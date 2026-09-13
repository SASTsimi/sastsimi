"""Asynchronous, exact-generation Verification-to-dynamic handoff."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, cast

from sastsimi.chaining.work_handlers import require_claimed_context
from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    DynamicReproductionResult,
    DynamicReproductionState,
    SandboxProfile,
)
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    VulnerabilityHypothesis,
)
from sastsimi.contracts.llm import (
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    RecordRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.static import StaticFactBundle
from sastsimi.contracts.verification import (
    ConEvidenceResult,
    PlaybookApplication,
    ProEvidenceResult,
    VerificationInitialAssessment,
)
from sastsimi.contracts.work import WorkExecutionState, WorkStatus, WorkType
from sastsimi.ports.dto import WorkContext, WorkHandlerResult
from sastsimi.ports.dynamic_registration import DynamicRegistrationPort
from sastsimi.ports.llm_invocation import PersistedLLMInvocation
from sastsimi.ports.record_store import RecordStore
from sastsimi.ports.runtime_query import RuntimeQueryPort
from sastsimi.ports.verification_assembly import VerificationGenerationInputs
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.verification.completion import VerificationCompletionCoordinator
from sastsimi.verification.debate_service import AuthorizedLLMCall
from sastsimi.verification.service import VerificationService

from .production_llm_work_handlers import (
    ProductionCallPort,
    _verification_call_refs,
)

type BudgetScopeResolver = Callable[[str], BudgetScopeRef]
type SandboxProfileResolver = Callable[[WorkExecutionState], StoredDataRef]


class DynamicExecutor(Protocol):
    async def execute(
        self,
        *,
        work: WorkExecutionState,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
        authorizations: None,
    ) -> WorkHandlerResult: ...


type DynamicServicesResolver = Callable[[WorkExecutionState], DynamicExecutor]


@dataclass(frozen=True, slots=True)
class ProductionDynamicVerificationHandoff:
    """Publish one request, park its parent, and later synthesize exact output."""

    records: RecordStore
    queries: RuntimeQueryPort
    runner: WorkflowRunner
    verification: VerificationService
    completion: VerificationCompletionCoordinator
    calls: ProductionCallPort
    dynamic_registration: DynamicRegistrationPort
    verification_identity_ref: BudgetScopeRef
    budget_scope: BudgetScopeResolver
    sandbox_profile: SandboxProfileResolver

    async def complete_dynamic(
        self,
        *,
        context: WorkContext,
        generation: VerificationGenerationInputs,
        assessment_ref: StoredDataRef,
    ) -> WorkHandlerResult:
        """Create the exact request then atomically register, ready, and park."""
        require_claimed_context(context, WorkType.VERIFICATION)
        work = context.work
        process = self._process(work)
        assignment_ref = process.verification_assignment_ref
        if assignment_ref is None:
            raise ValueError("VERIFICATION_ASSIGNMENT_REQUIRED")
        profile_ref = self.sandbox_profile(work)
        profile = self._exact(profile_ref, SandboxProfile)
        if profile_ref != reference(profile):
            raise ValueError("SANDBOX_PROFILE_REVISION_MISMATCH")
        initial_refs = self._initial_source_refs(generation)
        call = self.calls.resolve(
            work=work,
            role="VERIFICATION",
            task_kind="CREATE_DYNAMIC_REQUEST",
            source_refs=(*initial_refs, assessment_ref, profile_ref),
        )
        outcome = await self.verification.create_dynamic_request_with_invocation(
            generation=generation,
            assessment_ref=assessment_ref,
            verification_assignment_ref=assignment_ref,
            sandbox_profile_ref=profile_ref,
            call=_verification_call_refs(call),
        )
        self.calls.settle(call, outcome.invocation)
        request_ref = self._publish_request(
            work, outcome.invocation, outcome.record, call
        )
        scope = self.budget_scope(str(work.meta.analysis_id))
        action = self.runner.action(
            work,
            self.verification_identity_ref,
            "VERIFICATION",
            "REQUEST_DYNAMIC_REPRO",
            dynamic_request_ref=request_ref,
            input_refs=(*initial_refs, assessment_ref, request_ref, profile_ref),
            reason="Run separate dynamic reproduction for this Verification generation",
        )
        reservation = self.runner.reserve(
            work, scope, action, self.runner.units(work_count=1)
        )
        decision_ref = self.runner.authorize(work, action, reservation)
        child = self.dynamic_registration.register_and_park(
            str(work.work_id), decision_ref, reference(reservation)
        )
        if child.status != WorkStatus.READY or child.input_refs != (request_ref,):
            raise ValueError("DYNAMIC_HANDOFF_COMMIT_MISMATCH")
        return WorkHandlerResult(())

    async def resume_dynamic(
        self,
        *,
        context: WorkContext,
        public_input_refs: tuple[StoredDataRef, ...],
    ) -> WorkHandlerResult | None:
        """Synthesize only a successful exact child; never rerun Pro or Con."""
        require_claimed_context(context, WorkType.VERIFICATION)
        work = context.work
        state = self._state(work)
        if state.status == "NOT_REQUESTED":
            return None
        if state.status not in {"SUCCEEDED", "PARTIAL"}:
            raise ValueError("DYNAMIC_PARENT_RESUME_NOT_READY")
        if state.dynamic_work_ref is None or state.dynamic_result_ref is None:
            raise ValueError("DYNAMIC_PARENT_RESUME_NOT_READY")
        child = self._exact(state.dynamic_work_ref, WorkExecutionState)
        result = self._exact(state.dynamic_result_ref, DynamicReproductionResult)
        request_ref = state.request_ref
        if request_ref is None:
            raise ValueError("DYNAMIC_PARENT_RESUME_NOT_READY")
        request = self._exact(request_ref, DynamicReproductionRequest)
        old_parent = (
            self._exact(child.parent_work_ref, WorkExecutionState)
            if isinstance(child.parent_work_ref, StoredDataRef)
            else None
        )
        if (
            old_parent is None
            or old_parent.work_id != work.work_id
            or old_parent.work_generation != work.work_generation
            or child.work_generation != work.work_generation
            or child.status != WorkStatus(state.status)
            or child.output_refs != (state.dynamic_result_ref,)
            or result.request_ref != request_ref
            or result.status != state.status
            or request.verification_generation != work.work_generation
        ):
            raise ValueError("STALE_DYNAMIC_RESULT")
        assessment = self._assessment(work)
        generation = self._generation(
            work,
            public_input_refs,
            assessment.pro_evidence_ref,
            assessment.con_evidence_ref,
        )
        initial_refs = self._initial_source_refs(generation)
        final_refs = (
            *initial_refs,
            reference(assessment),
            request_ref,
            state.dynamic_result_ref,
            *((result.poc_ref,) if result.poc_ref is not None else ()),
        )
        call = self.calls.resolve(
            work=work,
            role="VERIFICATION",
            task_kind="FINAL_VERDICT",
            source_refs=cast(tuple[StoredDataRef, ...], final_refs),
        )
        completed = await self.completion.complete_dynamic(
            generation=generation,
            assessment_ref=cast(StoredDataRef, reference(assessment)),
            dynamic_request_ref=request_ref,
            dynamic_result_ref=state.dynamic_result_ref,
            poc_ref=result.poc_ref,
            pro_ref=generation.pro_ref,
            con_ref=generation.con_ref,
            call=_verification_call_refs(call),
        )
        self.calls.settle(call, completed.outcome.invocation)
        return WorkHandlerResult(completed.completed_work.output_refs)

    def _publish_request(
        self,
        work: WorkExecutionState,
        invocation: PersistedLLMInvocation,
        request: DynamicReproductionRequest,
        call: AuthorizedLLMCall,
    ) -> StoredDataRef:
        invocation_refs = self._invocation_refs(invocation)
        decision_ref = call.decision_ref
        reservation_ref = call.reservation_ref
        call_spec_ref = call.call_spec_ref
        published = self.runner.publish_intermediate(
            work,
            self.verification_identity_ref,
            "VERIFICATION",
            (request,),
            action_input_refs=tuple(
                dict.fromkeys(
                    (
                        *work.input_refs,
                        decision_ref,
                        reservation_ref,
                        call_spec_ref,
                        *invocation_refs,
                    )
                )
            ),
        )
        expected = reference(request)
        if published != (expected,) or not isinstance(expected, StoredDataRef):
            raise ValueError("DYNAMIC_REQUEST_COMMIT_MISMATCH")
        return expected

    def _invocation_refs(
        self, invocation: PersistedLLMInvocation
    ) -> tuple[StoredDataRef, ...]:
        request_ref = reference(invocation.request)
        result_ref = reference(invocation.result)
        if not isinstance(request_ref, StoredDataRef) or not isinstance(
            result_ref, StoredDataRef
        ):
            raise ValueError("VERIFICATION_INVOCATION_PROVENANCE_MISMATCH")
        if (
            not isinstance(self.records.get_exact(request_ref), LLMInvocationRequest)
            or not isinstance(self.records.get_exact(result_ref), LLMInvocationResult)
            or not isinstance(
                self.records.get_exact(invocation.log_ref), LLMInvocationLog
            )
        ):
            raise ValueError("VERIFICATION_INVOCATION_PROVENANCE_MISMATCH")
        return request_ref, result_ref, invocation.log_ref

    def _generation(
        self,
        work: WorkExecutionState,
        public_refs: tuple[StoredDataRef, ...],
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
    ) -> VerificationGenerationInputs:
        hypothesis = self._one(
            public_refs, VulnerabilityHypothesis.KIND, VulnerabilityHypothesis
        )
        application = self._one(
            public_refs, PlaybookApplication.KIND, PlaybookApplication
        )
        evidence = self._one(public_refs, StaticFactBundle.KIND, StaticFactBundle)
        pro = self._exact(pro_ref, ProEvidenceResult)
        con = self._exact(con_ref, ConEvidenceResult)
        if (
            pro.debate_input_hash != con.debate_input_hash
            or application.verification_work_id != work.work_id
            or application.verification_generation != work.work_generation
        ):
            raise ValueError("STALE_DYNAMIC_RESULT")
        return VerificationGenerationInputs(
            work_id=work.work_id,
            generation=work.work_generation,
            hypothesis_ref=cast(StoredDataRef, reference(hypothesis)),
            policy_ref=self._ref_of_kind(public_refs, "playbook_policy"),
            playbook_ref=self._ref_of_kind(public_refs, "verification_playbook"),
            application_ref=cast(StoredDataRef, reference(application)),
            pro_ref=pro_ref,
            con_ref=con_ref,
            debate_input_hash=pro.debate_input_hash,
            evidence_ref=cast(StoredDataRef, reference(evidence)),
            location=hypothesis.target_locations[0],
            falsification_question_ids=tuple(
                str(item.question_id) for item in hypothesis.falsification_questions
            )
            + tuple(str(item.question_id) for item in application.questions),
            validation_ids=tuple(
                str(item.validation_id) for item in hypothesis.validation_checks
            ),
        )

    def _assessment(self, work: WorkExecutionState) -> VerificationInitialAssessment:
        candidates = tuple(
            item
            for item in self.queries.current_records(
                str(work.meta.analysis_id), VerificationInitialAssessment.KIND
            )
            if isinstance(item, VerificationInitialAssessment)
            and isinstance(item.meta, RecordMeta)
            and isinstance(work.meta, RecordMeta)
            and item.meta.hypothesis_id == work.meta.hypothesis_id
            and item.verification_work_id == work.work_id
            and item.verification_generation == work.work_generation
        )
        if len(candidates) != 1:
            raise ValueError("STALE_DYNAMIC_RESULT")
        return candidates[0]

    def _process(self, work: WorkExecutionState) -> HypothesisProcessState:
        candidates = tuple(
            item
            for item in self.queries.current_records(
                str(work.meta.analysis_id), HypothesisProcessState.KIND
            )
            if isinstance(item, HypothesisProcessState)
            and isinstance(item.meta, RecordMeta)
            and isinstance(work.meta, RecordMeta)
            and item.meta.hypothesis_id == work.meta.hypothesis_id
        )
        if (
            len(candidates) != 1
            or candidates[0].verification_generation != work.work_generation
            or candidates[0].verification_work_ref != reference(work)
        ):
            raise ValueError("STALE_DYNAMIC_RESULT")
        return candidates[0]

    def _state(self, work: WorkExecutionState) -> DynamicReproductionState:
        candidates = tuple(
            item
            for item in self.queries.current_records(
                str(work.meta.analysis_id), DynamicReproductionState.KIND
            )
            if isinstance(item, DynamicReproductionState)
            and isinstance(item.meta, RecordMeta)
            and isinstance(work.meta, RecordMeta)
            and item.meta.hypothesis_id == work.meta.hypothesis_id
            and item.verification_generation == work.work_generation
        )
        if len(candidates) != 1:
            raise ValueError("STALE_DYNAMIC_RESULT")
        return candidates[0]

    def _one[T](self, refs: tuple[StoredDataRef, ...], kind: str, model: type[T]) -> T:
        matching = tuple(ref for ref in refs if ref.data_kind == kind)
        if len(matching) != 1:
            raise ValueError("STALE_DYNAMIC_RESULT")
        return self._exact(matching[0], model)

    @staticmethod
    def _ref_of_kind(refs: tuple[StoredDataRef, ...], kind: str) -> StoredDataRef:
        matching = tuple(ref for ref in refs if ref.data_kind == kind)
        if len(matching) != 1:
            raise ValueError("STALE_DYNAMIC_RESULT")
        return matching[0]

    def _exact[T](self, ref: RecordRef, model: type[T]) -> T:
        value = self.records.get_exact(ref)
        if not isinstance(value, model) or reference(value) != ref:  # type: ignore[arg-type]
            raise ValueError("RECORD_REVISION_MISMATCH")
        return value

    @staticmethod
    def _initial_source_refs(
        generation: VerificationGenerationInputs,
    ) -> tuple[StoredDataRef, ...]:
        return (
            generation.hypothesis_ref,
            generation.policy_ref,
            generation.playbook_ref,
            generation.application_ref,
            generation.pro_ref,
            generation.con_ref,
            generation.evidence_ref,
        )


@dataclass(frozen=True, slots=True)
class DynamicParentResumeService:
    """CAS one successful child into the same parent's READY state."""

    records: RecordStore
    queries: RuntimeQueryPort
    runner: WorkflowRunner
    verification_identity_ref: BudgetScopeRef

    def reconcile_pending(self, analysis_id: str) -> tuple[WorkExecutionState, ...]:
        """Repair a crash after child commit without polling or rerunning T11."""
        resumed: list[WorkExecutionState] = []
        for work in self.runner.runtime.work.store.work_for_run(analysis_id):
            if work.work_type != WorkType.DYNAMIC_REPRO or work.status not in {
                WorkStatus.SUCCEEDED,
                WorkStatus.PARTIAL,
            }:
                continue
            if not isinstance(work.parent_work_ref, StoredDataRef):
                raise ValueError("DYNAMIC_PARENT_REQUIRED")
            historical_parent = self._exact(work.parent_work_ref, WorkExecutionState)
            current_parent = self.runner.runtime.work.get(
                str(historical_parent.work_id)
            )
            # Historical children from an older Technical REVISE generation,
            # and parents already settled by another recovery pass, are not
            # pending handoffs. An explicit late-result callback still fails
            # closed in ``resume``.
            if (
                current_parent.work_generation != work.work_generation
                or current_parent.status
                not in {WorkStatus.BLOCKED, WorkStatus.READY, WorkStatus.RUNNING}
            ):
                continue
            parent = self.resume(str(work.work_id))
            if parent.status == WorkStatus.READY and parent not in resumed:
                resumed.append(parent)
        return tuple(resumed)

    def resume(self, child_work_id: str) -> WorkExecutionState:
        child = self.runner.runtime.work.get(child_work_id)
        if not isinstance(child.parent_work_ref, StoredDataRef):
            raise ValueError("DYNAMIC_PARENT_REQUIRED")
        old_parent = self._exact(child.parent_work_ref, WorkExecutionState)
        parent = self.runner.runtime.work.get(str(old_parent.work_id))
        state = self._state(child)
        if (
            child.work_type != WorkType.DYNAMIC_REPRO
            or child.work_generation != old_parent.work_generation
            or parent.work_generation != child.work_generation
            or not isinstance(parent.meta, RecordMeta)
            or not isinstance(child.meta, RecordMeta)
            or parent.meta.hypothesis_id != child.meta.hypothesis_id
            or state.verification_generation != child.work_generation
            or state.dynamic_work_ref != reference(child)
        ):
            raise ValueError("STALE_DYNAMIC_RESULT")
        if child.status in {
            WorkStatus.BLOCKED,
            WorkStatus.FAILED,
            WorkStatus.CANCELLED,
        }:
            if (
                parent.status != WorkStatus.BLOCKED
                or parent.stop_reason != "WAITING_FOR_DYNAMIC_REPRO"
            ):
                raise ValueError("STALE_DYNAMIC_RESULT")
            return parent
        if child.status not in {WorkStatus.SUCCEEDED, WorkStatus.PARTIAL}:
            raise ValueError("DYNAMIC_CHILD_NOT_TERMINAL")
        if (
            state.status != child.status.value
            or state.dynamic_result_ref is None
            or child.output_refs != (state.dynamic_result_ref,)
        ):
            raise ValueError("STALE_DYNAMIC_RESULT")
        result = self._exact(state.dynamic_result_ref, DynamicReproductionResult)
        if result.status != state.status or result.request_ref != state.request_ref:
            raise ValueError("STALE_DYNAMIC_RESULT")
        if parent.status in {
            WorkStatus.READY,
            WorkStatus.RUNNING,
            WorkStatus.SUCCEEDED,
            WorkStatus.PARTIAL,
        }:
            return parent
        if (
            parent.status != WorkStatus.BLOCKED
            or parent.stop_reason != "WAITING_FOR_DYNAMIC_REPRO"
            or parent.waiting_for != ("DEPENDENCY",)
        ):
            raise ValueError("STALE_DYNAMIC_RESULT")
        action = self.runner.action(
            parent,
            self.verification_identity_ref,
            "VERIFICATION",
            "CHANGE_WORK_STATE",
            input_refs=(state.dynamic_result_ref,),
            reason="Exact dynamic child completed; resume final Verification synthesis",
        )
        decision = self.runner.authorize(parent, action)
        transition = self.runner.transition(parent, decision, "READY")
        return self.runner.runtime.work.make_ready(transition)

    def _state(self, child: WorkExecutionState) -> DynamicReproductionState:
        candidates = tuple(
            item
            for item in self.queries.current_records(
                str(child.meta.analysis_id), DynamicReproductionState.KIND
            )
            if isinstance(item, DynamicReproductionState)
            and isinstance(item.meta, RecordMeta)
            and isinstance(child.meta, RecordMeta)
            and item.meta.hypothesis_id == child.meta.hypothesis_id
            and item.verification_generation == child.work_generation
        )
        if len(candidates) != 1:
            raise ValueError("STALE_DYNAMIC_RESULT")
        return candidates[0]

    def _exact[T](self, ref: RecordRef, model: type[T]) -> T:
        value = self.records.get_exact(ref)
        if not isinstance(value, model) or reference(value) != ref:  # type: ignore[arg-type]
            raise ValueError("RECORD_REVISION_MISMATCH")
        return value


@dataclass(frozen=True, slots=True)
class DynamicReproductionWorkHandler:
    """Run only claimed T11 child work, then signal its parent without polling."""

    records: RecordStore
    services_for: DynamicServicesResolver
    parent_resume: DynamicParentResumeService

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        require_claimed_context(context, WorkType.DYNAMIC_REPRO)
        work = context.work
        if len(work.input_refs) != 1 or not isinstance(
            work.input_refs[0], StoredDataRef
        ):
            raise ValueError("DYNAMIC_REQUEST_INPUT_REQUIRED")
        request_ref = work.input_refs[0]
        request = self.records.get_exact(request_ref)
        if (
            not isinstance(request, DynamicReproductionRequest)
            or reference(request) != request_ref
            or request.verification_generation != work.work_generation
        ):
            raise ValueError("DYNAMIC_REQUEST_INPUT_REQUIRED")
        result = await self.services_for(work).execute(
            work=work,
            request=request,
            request_ref=request_ref,
            authorizations=None,
        )
        self.parent_resume.resume(str(work.work_id))
        return result


__all__ = [
    "DynamicParentResumeService",
    "DynamicReproductionWorkHandler",
    "ProductionDynamicVerificationHandoff",
]
