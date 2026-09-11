"""Technical Gate admission, trusted completion, and REVISE routing."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sastsimi.agents.technical_gate import TechnicalCallRefs, TechnicalGateAgent
from sastsimi.contracts.actions import (
    ActionDecision,
    ActionRequest,
    ActionType,
    Decision,
    RequesterRole,
    UseStatus,
)
from sastsimi.contracts.dynamic import DynamicReproductionResult, PoCBundle
from sastsimi.contracts.gates import (
    CWELabel,
    TechnicalEvidenceReview,
    validate_cwe_evidence,
    validate_technical_gate,
    validate_true_dynamic,
)
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    VerificationAssignment,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef, reference
from sastsimi.contracts.verification import PlaybookApplication, VerificationResult
from sastsimi.contracts.work import WorkExecutionState, WorkStatus, WorkType
from sastsimi.ports.dto import Record
from sastsimi.ports.ready_work import ReadyWorkPort
from sastsimi.ports.verification_registration import VerificationRegistration
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation

from .cwe_service import GateCallRefs


@dataclass(frozen=True)
class TechnicalGateOutcome:
    review: TechnicalEvidenceReview
    completed_work: WorkExecutionState
    revision_work: WorkExecutionState | None


class ExactRecordStore(Protocol):
    def get_exact(self, ref: RecordRef) -> object: ...


class CurrentRecordQuery(Protocol):
    def current_records(self, analysis_id: str, kind: str) -> tuple[Record, ...]: ...


class ResultPublisher(Protocol):
    def complete(
        self,
        work: WorkExecutionState,
        identity: BudgetScopeRef,
        role: str,
        outputs: tuple[Record, ...],
        *,
        status: str = "SUCCEEDED",
        cause: str = "COMPLETED",
        error_ids: tuple[str, ...] = (),
        gap_ids: tuple[str, ...] = (),
        action_input_refs: tuple[RecordRef, ...] | None = None,
    ) -> WorkExecutionState: ...


class RevisionStarter(Protocol):
    def start_new_generation(
        self,
        *,
        technical_review_ref: StoredDataRef,
        hypothesis_ref: StoredDataRef,
        proposal_ref: StoredDataRef,
        policy_ref: StoredDataRef,
        playbook_ref: StoredDataRef,
        expected_process_ref: StoredDataRef,
        owner_identity_ref: StoredDataRef,
        requester_identity_ref: BudgetScopeRef,
        budget_binding_ref: StoredDataRef,
    ) -> VerificationRegistration: ...


class T10RevisionServices(Protocol):
    @property
    def revision(self) -> RevisionStarter: ...


class TechnicalGateService:
    """Review one exact current CWE/TRUE closure and route REVISE safely."""

    def __init__(
        self,
        *,
        agent: TechnicalGateAgent,
        publisher: ResultPublisher,
        records: ExactRecordStore,
        identity_ref: BudgetScopeRef,
        orchestration_identity_ref: BudgetScopeRef,
        t10_services: T10RevisionServices,
        ready_work: ReadyWorkPort,
    ) -> None:
        self._agent = agent
        self._publisher = publisher
        self._records = records
        self._identity_ref = identity_ref
        self._orchestration_identity_ref = orchestration_identity_ref
        self._t10 = t10_services
        self._ready = ready_work

    async def review(
        self,
        *,
        work: WorkExecutionState,
        process_ref: StoredDataRef,
        assignment_ref: StoredDataRef,
        verification_ref: StoredDataRef,
        dynamic_result_ref: StoredDataRef,
        poc_ref: StoredDataRef,
        cwe_label_ref: StoredDataRef,
        budget_binding_ref: StoredDataRef,
        call: GateCallRefs,
    ) -> TechnicalGateOutcome:
        self._require_running(work)
        required_inputs = (
            process_ref,
            assignment_ref,
            verification_ref,
            dynamic_result_ref,
            poc_ref,
            cwe_label_ref,
            budget_binding_ref,
        )
        if len(required_inputs) != len(set(required_inputs)) or not set(
            required_inputs
        ).issubset(work.input_refs):
            raise ValueError("STALE_RESULT: exact Technical inputs required")
        process = self._exact(process_ref, HypothesisProcessState)
        assignment = self._exact(assignment_ref, VerificationAssignment)
        verification = self._exact(verification_ref, VerificationResult)
        dynamic = self._exact(dynamic_result_ref, DynamicReproductionResult)
        poc = self._exact(poc_ref, PoCBundle)
        label = self._exact(cwe_label_ref, CWELabel)
        self._require_current(
            work, process, assignment_ref, assignment, verification_ref
        )
        validate_true_dynamic(verification, dynamic, poc)
        allowed_evidence = self._allowed_evidence(verification, dynamic, poc)
        validate_cwe_evidence(
            label, verification, process.verification_generation, allowed_evidence
        )
        required_context = (
            verification_ref,
            dynamic_result_ref,
            poc_ref,
            cwe_label_ref,
            process_ref,
            assignment_ref,
            *allowed_evidence,
        )
        self._require_call_authority(
            work, assignment, call, required_context=required_context
        )
        agent_outcome = await self._agent.review(
            work=work,
            verification_ref=verification_ref,
            cwe_label_ref=cwe_label_ref,
            required_context=required_context,
            call=TechnicalCallRefs(
                call.decision_ref, call.reservation_ref, call.call_spec_ref
            ),
        )
        validate_technical_gate(
            agent_outcome.review,
            verification,
            label,
            dynamic,
            poc,
            current_generation=process.verification_generation,
        )
        completed = self._publisher.complete(
            work,
            self._identity_ref,
            "TECHNICAL_GATE",
            (agent_outcome.review,),
            action_input_refs=self._save_inputs(work, call, agent_outcome.invocation),
        )
        if completed.status != WorkStatus.SUCCEEDED:
            raise ValueError("TECHNICAL_REVIEW_COMMIT_REQUIRED")
        revision_work = self.reconcile_revision(completed)
        return TechnicalGateOutcome(agent_outcome.review, completed, revision_work)

    def reconcile_revision(
        self, completed_work: WorkExecutionState
    ) -> WorkExecutionState | None:
        """Replay a committed REVISE handoff without recalling the provider.

        The committed TechnicalEvidenceReview and its exact work inputs are the
        durable handoff intent.  Registration and READY enqueue are idempotent,
        so recovery may safely call this method after a process crash.
        """
        if (
            completed_work.work_type != WorkType.TECHNICAL_GATE
            or completed_work.status != WorkStatus.SUCCEEDED
            or completed_work.active_attempt_id is not None
        ):
            raise ValueError("TECHNICAL_REVIEW_COMMIT_REQUIRED")
        review_ref = self._one(completed_work.output_refs, "technical_evidence_review")
        review = self._exact(review_ref, TechnicalEvidenceReview)
        if review.status != "REVISE":
            return None
        verification_ref = self._one(completed_work.input_refs, "verification_result")
        if review.verification_result_ref != verification_ref:
            raise ValueError("TECHNICAL_REVISE_CLOSURE_MISMATCH")
        verification = self._exact(verification_ref, VerificationResult)
        process_ref = self._one(completed_work.input_refs, "hypothesis_process_state")
        assignment_ref = self._one(completed_work.input_refs, "verification_assignment")
        assignment = self._exact(assignment_ref, VerificationAssignment)
        budget_binding_ref = self._one(
            completed_work.input_refs, "budget_profile_binding"
        )
        return self._start_revision(
            review=review,
            verification=verification,
            process_ref=process_ref,
            assignment=assignment,
            budget_binding_ref=budget_binding_ref,
        )

    def _start_revision(
        self,
        *,
        review: TechnicalEvidenceReview,
        verification: VerificationResult,
        process_ref: StoredDataRef,
        assignment: VerificationAssignment,
        budget_binding_ref: StoredDataRef,
    ) -> WorkExecutionState:
        review_ref = reference(review)
        if not isinstance(review_ref, StoredDataRef):
            raise ValueError("TECHNICAL_REVIEW_SCOPE_MISMATCH")
        application = self._exact(
            verification.playbook_application_ref, PlaybookApplication
        )
        registration = self._t10.revision.start_new_generation(
            technical_review_ref=review_ref,
            hypothesis_ref=application.hypothesis_ref,
            proposal_ref=application.proposal_ref,
            policy_ref=application.policy_ref,
            playbook_ref=application.playbook_ref,
            expected_process_ref=process_ref,
            owner_identity_ref=assignment.owner_identity_ref,
            requester_identity_ref=self._orchestration_identity_ref,
            budget_binding_ref=budget_binding_ref,
        )
        if registration.assignment_ref != reference(assignment):
            raise ValueError("TECHNICAL_REVISE_CLOSURE_MISMATCH")
        if registration.work.status == WorkStatus.PENDING:
            if registration.work.active_attempt_id is not None:
                raise ValueError("TECHNICAL_REVISE_CLOSURE_MISMATCH")
            ready = self._ready.enqueue_registered(
                registration.work,
                budget_binding_ref,
                self._orchestration_identity_ref,
                role="ORCHESTRATION",
            )
        else:
            ready = registration.work
        if ready.status not in {
            WorkStatus.READY,
            WorkStatus.RUNNING,
            WorkStatus.BLOCKED,
            WorkStatus.SUCCEEDED,
            WorkStatus.PARTIAL,
            WorkStatus.FAILED,
            WorkStatus.CANCELLED,
        }:
            raise ValueError("TECHNICAL_REVISE_READY_ONLY_REQUIRED")
        return ready

    @staticmethod
    def _one(refs: tuple[RecordRef, ...], kind: str) -> StoredDataRef:
        matches = tuple(
            ref
            for ref in refs
            if ref.data_kind == kind and isinstance(ref, StoredDataRef)
        )
        if len(matches) != 1:
            raise ValueError(f"TECHNICAL_REVISE_CLOSURE_MISMATCH: one {kind} required")
        return matches[0]

    def _require_call_authority(
        self,
        work: WorkExecutionState,
        assignment: VerificationAssignment,
        call: GateCallRefs,
        *,
        required_context: tuple[StoredDataRef, ...],
    ) -> None:
        decision = self._exact(call.decision_ref, ActionDecision)
        if not isinstance(decision.action_ref, StoredDataRef):
            raise ValueError("AUTHORITY_DENIED: invalid Technical Gate call")
        action = self._exact(decision.action_ref, ActionRequest)
        if (
            decision.decision != Decision.ALLOW
            or decision.use_status != UseStatus.UNUSED
            or action.action_type != ActionType.CALL_TECHNICAL_GATE
            or action.requested_by != RequesterRole.VERIFICATION
            or action.requester_identity_ref != assignment.owner_identity_ref
            or action.work_ref != reference(work)
            or action.llm_call_spec_ref != call.call_spec_ref
            or not set(required_context).issubset(action.input_refs)
        ):
            raise ValueError("AUTHORITY_DENIED: invalid Technical Gate call")

    @staticmethod
    def _allowed_evidence(
        verification: VerificationResult,
        dynamic: DynamicReproductionResult,
        poc: PoCBundle,
    ) -> tuple[StoredDataRef, ...]:
        candidates = (
            *(
                ref
                for claim in verification.supporting_evidence
                for ref in claim.evidence_refs
            ),
            *(
                ref
                for claim in verification.counter_evidence
                for ref in claim.evidence_refs
            ),
            *dynamic.observation_refs,
            *dynamic.hypothesis_evidence_refs,
            *dynamic.disproof_evidence_refs,
            *poc.evidence_refs,
        )
        return tuple(dict.fromkeys(candidates))

    @staticmethod
    def _require_running(work: WorkExecutionState) -> None:
        if (
            work.work_type != WorkType.TECHNICAL_GATE
            or work.status != WorkStatus.RUNNING
            or work.active_attempt_id is None
        ):
            raise ValueError("ATTEMPT_NOT_ACTIVE")

    @staticmethod
    def _require_current(
        work: WorkExecutionState,
        process: HypothesisProcessState,
        assignment_ref: StoredDataRef,
        assignment: VerificationAssignment,
        verification_ref: StoredDataRef,
    ) -> None:
        if (
            process.status != "TERMINAL"
            or process.verification_result_ref != verification_ref
            or process.verification_generation != work.work_generation
            or process.verification_assignment_ref != assignment_ref
            or assignment.status != "ACTIVE"
        ):
            raise ValueError("STALE_RESULT: current final Verification required")

    @staticmethod
    def _save_inputs(
        work: WorkExecutionState,
        call: GateCallRefs,
        invocation: PersistedLLMInvocation,
    ) -> tuple[RecordRef, ...]:
        refs: tuple[RecordRef, ...] = (
            *work.input_refs,
            call.decision_ref,
            call.reservation_ref,
            call.call_spec_ref,
            invocation.request.action_decision_ref,
            reference(invocation.request),
            reference(invocation.result),
            invocation.log_ref,
        )
        if invocation.result.parsed_output_ref is not None:
            refs = (*refs, invocation.result.parsed_output_ref)
        return tuple(dict.fromkeys(refs))

    def _exact[T](self, ref: StoredDataRef, model: type[T]) -> T:
        value = self._records.get_exact(ref)
        if not isinstance(value, model) or reference(value) != ref:  # type: ignore[arg-type]
            raise ValueError("RECORD_REVISION_MISMATCH")
        return value

    def _require_revision_successor(
        self,
        review_ref: StoredDataRef,
        review: TechnicalEvidenceReview,
        work: WorkExecutionState,
    ) -> None:
        verification = self._exact(review.verification_result_ref, VerificationResult)
        application = self._exact(
            verification.playbook_application_ref, PlaybookApplication
        )
        if (
            work.work_type != WorkType.VERIFICATION
            or work.subject_type.value != "HYPOTHESIS"
            or work.subject_id != review.meta.hypothesis_id
            or not isinstance(work.meta, RecordMeta)
            or work.meta.hypothesis_id != review.meta.hypothesis_id
            or work.work_generation != application.verification_generation + 1
            or work.input_refs.count(review_ref) != 1
        ):
            raise ValueError("TECHNICAL_REVISE_CLOSURE_MISMATCH")


class TechnicalRevisionReconciler:
    """Discover committed REVISE reviews and replay only missing handoffs."""

    def __init__(
        self, *, service: TechnicalGateService, current: CurrentRecordQuery
    ) -> None:
        self._service = service
        self._current = current

    def reconcile_pending(self, analysis_id: str) -> tuple[WorkExecutionState, ...]:
        works = tuple(
            record
            for record in self._current.current_records(
                analysis_id, "work_execution_state"
            )
            if isinstance(record, WorkExecutionState)
        )
        reconciled: list[WorkExecutionState] = []
        for completed in works:
            if (
                completed.work_type != WorkType.TECHNICAL_GATE
                or completed.status != WorkStatus.SUCCEEDED
            ):
                continue
            review_refs = tuple(
                ref
                for ref in completed.output_refs
                if ref.data_kind == "technical_evidence_review"
                and isinstance(ref, StoredDataRef)
            )
            if len(review_refs) != 1:
                continue
            review_ref = review_refs[0]
            review = self._service._exact(review_ref, TechnicalEvidenceReview)
            if review.status != "REVISE":
                continue
            successors = tuple(
                work
                for work in works
                if work.work_type == WorkType.VERIFICATION
                and review_ref in work.input_refs
            )
            if len(successors) > 1:
                raise ValueError("TECHNICAL_REVISE_DUPLICATE_SUCCESSOR")
            if successors:
                self._service._require_revision_successor(
                    review_ref, review, successors[0]
                )
                if successors[0].status != WorkStatus.PENDING:
                    reconciled.append(successors[0])
                    continue
            successor = self._service.reconcile_revision(completed)
            if successor is not None:
                reconciled.append(successor)
        return tuple(reconciled)


__all__ = [
    "TechnicalGateOutcome",
    "TechnicalGateService",
    "TechnicalRevisionReconciler",
]
