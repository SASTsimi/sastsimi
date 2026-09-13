"""Exact final-TRUE admission and atomic CWE work completion."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from sastsimi.agents.cwe_labeling import CWECallRefs, CWELabelingAgent
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
    validate_cwe_evidence,
    validate_true_dynamic,
)
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef, reference
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import WorkExecutionState, WorkStatus, WorkType
from sastsimi.ports.dto import Record
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation
from sastsimi.runtime.llm_invocation_provenance import llm_invocation_save_refs

GateCallRefs = CWECallRefs


@dataclass(frozen=True)
class CWELabelingOutcome:
    label: CWELabel
    completed_work: WorkExecutionState


class ExactRecordStore(Protocol):
    def get_exact(self, ref: RecordRef) -> object: ...


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


class CWELabelingService:
    """Create one current CWE revision without changing the TRUE verdict."""

    def __init__(
        self,
        *,
        agent: CWELabelingAgent,
        publisher: ResultPublisher,
        records: ExactRecordStore,
        identity_ref: BudgetScopeRef,
        taxonomy_version: str,
    ) -> None:
        self._agent = agent
        self._publisher = publisher
        self._records = records
        self._identity_ref = identity_ref
        self._taxonomy_version = taxonomy_version

    async def label(
        self,
        *,
        work: WorkExecutionState,
        process_ref: StoredDataRef,
        verification_ref: StoredDataRef,
        dynamic_result_ref: StoredDataRef,
        poc_ref: StoredDataRef,
        call: GateCallRefs,
    ) -> CWELabelingOutcome:
        self._require_running(work, WorkType.CWE_LABEL)
        self._require_inputs(
            work, (process_ref, verification_ref, dynamic_result_ref, poc_ref)
        )
        process = self._exact(process_ref, HypothesisProcessState)
        verification = self._exact(verification_ref, VerificationResult)
        dynamic = self._exact(dynamic_result_ref, DynamicReproductionResult)
        poc = self._exact(poc_ref, PoCBundle)
        self._require_current(work, process, verification_ref)
        validate_true_dynamic(verification, dynamic, poc)
        allowed_evidence = self._allowed_evidence(verification, dynamic, poc)
        required_context = (
            verification_ref,
            dynamic_result_ref,
            poc_ref,
            process_ref,
            *allowed_evidence,
        )
        self._require_call_authority(
            work,
            call,
            required_context=required_context,
        )
        agent_outcome = await self._agent.classify(
            work=work,
            verification_ref=verification_ref,
            verification_generation=process.verification_generation,
            taxonomy_version=self._taxonomy_version,
            allowed_evidence=allowed_evidence,
            required_context=required_context,
            requester_identity_ref=self._identity_ref,
            call=call,
        )
        validate_cwe_evidence(
            agent_outcome.label,
            verification,
            process.verification_generation,
            allowed_evidence,
        )
        completed = self._publisher.complete(
            work,
            self._identity_ref,
            "CWE_LABELING",
            (agent_outcome.label,),
            action_input_refs=self._save_inputs(work, call, agent_outcome.invocation),
        )
        if completed.status != WorkStatus.SUCCEEDED:
            raise ValueError("CWE_COMMIT_REQUIRED")
        return CWELabelingOutcome(agent_outcome.label, completed)

    def _require_call_authority(
        self,
        work: WorkExecutionState,
        call: GateCallRefs,
        *,
        required_context: tuple[StoredDataRef, ...],
    ) -> None:
        decision = self._exact(call.decision_ref, ActionDecision)
        if not isinstance(decision.action_ref, StoredDataRef):
            raise ValueError("AUTHORITY_DENIED: invalid CWE call")
        action = self._exact(decision.action_ref, ActionRequest)
        if (
            decision.decision != Decision.ALLOW
            or decision.use_status != UseStatus.UNUSED
            or action.action_type != ActionType.CALL_LLM
            or action.requested_by != RequesterRole.CWE_LABELING
            or action.requester_identity_ref != self._identity_ref
            or action.work_ref != reference(work)
            or action.llm_call_spec_ref != call.call_spec_ref
            or not set(required_context).issubset(action.input_refs)
        ):
            raise ValueError("AUTHORITY_DENIED: invalid CWE call")

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
    def _require_running(work: WorkExecutionState, kind: WorkType) -> None:
        if (
            work.work_type != kind
            or work.status != WorkStatus.RUNNING
            or work.active_attempt_id is None
        ):
            raise ValueError("ATTEMPT_NOT_ACTIVE")

    @staticmethod
    def _require_inputs(
        work: WorkExecutionState, refs: tuple[StoredDataRef, ...]
    ) -> None:
        if len(refs) != len(set(refs)) or not set(refs).issubset(work.input_refs):
            raise ValueError("STALE_RESULT: exact stage inputs required")

    @staticmethod
    def _require_current(
        work: WorkExecutionState,
        process: HypothesisProcessState,
        verification_ref: StoredDataRef,
    ) -> None:
        if (
            process.status != "TERMINAL"
            or process.verification_result_ref != verification_ref
            or process.verification_generation != work.work_generation
        ):
            raise ValueError("STALE_RESULT: current final Verification required")

    def _save_inputs(
        self,
        work: WorkExecutionState,
        call: GateCallRefs,
        invocation: PersistedLLMInvocation,
    ) -> tuple[RecordRef, ...]:
        return llm_invocation_save_refs(
            records=self._records,
            work=work,
            issued_decision_ref=call.decision_ref,
            reservation_ref=call.reservation_ref,
            call_spec_ref=call.call_spec_ref,
            invocation=invocation,
        )

    def _exact[T](self, ref: StoredDataRef, model: type[T]) -> T:
        value = self._records.get_exact(ref)
        if not isinstance(value, model) or reference(value) != ref:  # type: ignore[arg-type]
            raise ValueError("RECORD_REVISION_MISMATCH")
        return value


__all__ = ["CWELabelingOutcome", "CWELabelingService", "GateCallRefs"]
