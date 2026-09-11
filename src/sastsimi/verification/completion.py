"""Trusted completion boundary for an exact T11-backed Verification verdict."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from sastsimi.agents.verification import (
    VerificationAgentOutcome,
    VerificationCallRefs,
)
from sastsimi.contracts.actions import (
    ActionDecision,
    ActionRequest,
    ActionType,
    Decision,
    UseStatus,
    validate_decision_for_action,
    validate_decision_revision,
)
from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    DynamicReproductionResult,
)
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.ids import WorkId
from sastsimi.contracts.llm import LLMInvocationLog
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef, reference
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import WorkExecutionState, WorkStatus, WorkType
from sastsimi.ports.record_store import RecordStore
from sastsimi.ports.verification_assembly import VerificationGenerationInputs
from sastsimi.runtime.workflow_runner import WorkflowRunner

from .service import VerificationService

type WorkResolver = Callable[[WorkId], WorkExecutionState | None]
type CurrentProcessResolver = Callable[
    [DynamicReproductionRequest], HypothesisProcessState
]


@dataclass(frozen=True)
class VerificationCompletion:
    """The trusted proposal and the exact work revision that published it."""

    outcome: VerificationAgentOutcome[VerificationResult]
    completed_work: WorkExecutionState


class VerificationCompletionCoordinator:
    """Finalize and publish one exact current R7-to-R6 result chain."""

    def __init__(
        self,
        *,
        verification: VerificationService,
        runner: WorkflowRunner,
        records: RecordStore,
        work_resolver: WorkResolver,
        current_process: CurrentProcessResolver,
        verification_identity_ref: BudgetScopeRef,
    ) -> None:
        self._verification = verification
        self._runner = runner
        self._records = records
        self._work = work_resolver
        self._current_process = current_process
        self._identity = verification_identity_ref

    async def complete_dynamic(
        self,
        *,
        generation: VerificationGenerationInputs,
        assessment_ref: StoredDataRef,
        dynamic_request_ref: StoredDataRef,
        dynamic_result_ref: StoredDataRef,
        poc_ref: StoredDataRef | None,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
        call: VerificationCallRefs,
    ) -> VerificationCompletion:
        """Publish only a successful exact-current dynamic verdict closure."""
        request = self._exact(dynamic_request_ref, DynamicReproductionRequest)
        dynamic = self._exact(dynamic_result_ref, DynamicReproductionResult)
        if dynamic.status not in {"SUCCEEDED", "PARTIAL"}:
            raise ValueError("EXECUTION_FAILURE_IS_NOT_VERDICT")

        work = self._current_work(generation.work_id)
        self._require_current(work, generation, request, dynamic, poc_ref)
        outcome = await self._verification.finalize_with_dynamic_with_invocation(
            generation=generation,
            assessment_ref=assessment_ref,
            dynamic_request_ref=dynamic_request_ref,
            dynamic_result_ref=dynamic_result_ref,
            poc_ref=poc_ref,
            pro_ref=pro_ref,
            con_ref=con_ref,
            call=call,
        )
        invocation_refs = self._invocation_refs(outcome, call)

        # The LLM call may have taken long enough for the generation to change.
        # Re-resolve immediately before WorkflowRunner's authorized CAS completion.
        work = self._current_work(generation.work_id)
        self._require_current(work, generation, request, dynamic, poc_ref)
        output_ref = reference(outcome.record)
        staged_ref = self._records.stage_record(outcome.record)
        if not isinstance(output_ref, StoredDataRef) or staged_ref != output_ref:
            raise ValueError("DOMAIN_RECORD_STAGE_MISMATCH")

        action_input_refs = _unique_refs(
            (
                *work.input_refs,
                generation.hypothesis_ref,
                generation.policy_ref,
                generation.playbook_ref,
                generation.application_ref,
                generation.evidence_ref,
                assessment_ref,
                dynamic_request_ref,
                dynamic_result_ref,
                *((poc_ref,) if poc_ref is not None else ()),
                pro_ref,
                con_ref,
                call.decision_ref,
                call.reservation_ref,
                call.call_spec_ref,
                *invocation_refs,
            )
        )
        completed = self._runner.complete(
            work,
            self._identity,
            "VERIFICATION",
            (outcome.record,),
            action_input_refs=action_input_refs,
        )
        if (
            completed.status != WorkStatus.SUCCEEDED
            or completed.active_attempt_id is not None
            or completed.output_refs != (output_ref,)
        ):
            raise ValueError("VERIFICATION_COMPLETION_MISMATCH")
        return VerificationCompletion(outcome, completed)

    def _current_work(self, work_id: WorkId) -> WorkExecutionState:
        work = self._work(work_id)
        if work is None:
            raise ValueError("STALE_RESULT")
        return work

    def _require_current(
        self,
        work: WorkExecutionState,
        generation: VerificationGenerationInputs,
        request: DynamicReproductionRequest,
        dynamic: DynamicReproductionResult,
        poc_ref: StoredDataRef | None,
    ) -> None:
        process = self._current_process(request)
        work_ref = reference(work)
        if (
            not isinstance(work.meta, RecordMeta)
            or not isinstance(process.meta, RecordMeta)
            or not isinstance(work_ref, StoredDataRef)
            or work.work_id != generation.work_id
            or work.work_type != WorkType.VERIFICATION
            or work.status != WorkStatus.RUNNING
            or work.active_attempt_id is None
            or work.work_generation != generation.generation
            or process.status != "VERIFYING"
            or process.verification_generation != generation.generation
            or process.verification_work_ref != work_ref
            or process.verification_assignment_ref
            != request.verification_assignment_ref
            or request.verification_generation != generation.generation
            or request.hypothesis_ref != generation.hypothesis_ref
            or request.pro_evidence_ref != generation.pro_ref
            or request.con_evidence_ref != generation.con_ref
            or dynamic.request_ref != reference(request)
            or dynamic.poc_ref != poc_ref
            or (
                work.meta.analysis_id,
                work.meta.workspace_id,
                work.meta.commit_id,
                work.meta.hypothesis_id,
            )
            != (
                process.meta.analysis_id,
                process.meta.workspace_id,
                process.meta.commit_id,
                process.meta.hypothesis_id,
            )
            or (
                request.meta.analysis_id,
                request.meta.workspace_id,
                request.meta.commit_id,
                request.meta.hypothesis_id,
            )
            != (
                work.meta.analysis_id,
                work.meta.workspace_id,
                work.meta.commit_id,
                work.meta.hypothesis_id,
            )
        ):
            raise ValueError("STALE_RESULT")

    def _invocation_refs(
        self,
        outcome: VerificationAgentOutcome[VerificationResult],
        call: VerificationCallRefs,
    ) -> tuple[StoredDataRef, ...]:
        invocation = outcome.invocation
        request_ref = reference(invocation.request)
        result_ref = reference(invocation.result)
        if not isinstance(request_ref, StoredDataRef) or not isinstance(
            result_ref, StoredDataRef
        ):
            raise ValueError("VERIFICATION_INVOCATION_PROVENANCE_MISMATCH")
        persisted_request = self._records.get_exact(request_ref)
        persisted_result = self._records.get_exact(result_ref)
        persisted_log = self._records.get_exact(invocation.log_ref)
        parsed_output_ref = invocation.result.parsed_output_ref
        claimed_ref = invocation.request.action_decision_ref
        issued = self._records.get_exact(call.decision_ref)
        claimed = self._records.get_exact(claimed_ref)
        action = (
            self._records.get_exact(issued.action_ref)
            if isinstance(issued, ActionDecision)
            else None
        )
        if (
            persisted_request != invocation.request
            or persisted_result != invocation.result
            or not isinstance(persisted_log, LLMInvocationLog)
            or reference(persisted_log) != invocation.log_ref
            or not isinstance(issued, ActionDecision)
            or reference(issued) != call.decision_ref
            or issued.decision != Decision.ALLOW
            or issued.use_status != UseStatus.UNUSED
            or issued.outcome_refs
            or not isinstance(claimed, ActionDecision)
            or reference(claimed) != claimed_ref
            or claimed.decision != Decision.ALLOW
            or claimed.use_status != UseStatus.USED
            or claimed.outcome_refs
            or not isinstance(action, ActionRequest)
            or reference(action) != issued.action_ref
            or not isinstance(action.meta, RecordMeta)
            or not isinstance(issued.meta, RecordMeta)
            or not isinstance(claimed.meta, RecordMeta)
            or action.action_type != ActionType.CALL_LLM
            or action.llm_call_spec_ref != call.call_spec_ref
            or action.meta.attempt_id != invocation.request.meta.attempt_id
            or issued.meta.attempt_id != invocation.request.meta.attempt_id
            or claimed.meta.attempt_id != invocation.request.meta.attempt_id
            or invocation.request.call_spec_ref != call.call_spec_ref
            or invocation.request.agent_role != "VERIFICATION"
            or invocation.request.task_kind != "FINAL_VERDICT"
            or invocation.request.purpose != "PRODUCTION"
            or invocation.result.llm_call_id != invocation.request.llm_call_id
            or invocation.result.purpose != invocation.request.purpose
            or invocation.result.status != "SUCCEEDED"
            or parsed_output_ref is None
            or persisted_log.llm_call_id != invocation.request.llm_call_id
            or persisted_log.action_decision_ref != claimed_ref
            or persisted_log.call_spec_ref != call.call_spec_ref
            or persisted_log.agent_role != "VERIFICATION"
            or persisted_log.task_kind != "FINAL_VERDICT"
            or persisted_log.purpose != "PRODUCTION"
            or persisted_log.context_refs != invocation.request.context_refs
            or persisted_log.parsed_output_ref != parsed_output_ref
            or persisted_log.status != "SUCCEEDED"
        ):
            raise ValueError("VERIFICATION_INVOCATION_PROVENANCE_MISMATCH")
        try:
            validate_decision_for_action(issued, ActionType.CALL_LLM)
            validate_decision_for_action(claimed, ActionType.CALL_LLM)
            validate_decision_revision(issued, claimed)
        except ValueError as error:
            raise ValueError(
                "VERIFICATION_INVOCATION_PROVENANCE_MISMATCH"
            ) from error
        return (
            claimed_ref,
            request_ref,
            result_ref,
            invocation.log_ref,
            parsed_output_ref,
        )

    def _exact[T](self, ref: StoredDataRef, model: type[T]) -> T:
        value = self._records.get_exact(ref)
        if not isinstance(value, model) or reference(value) != ref:  # type: ignore[arg-type]
            raise ValueError("RECORD_REVISION_MISMATCH")
        return value


def _unique_refs(refs: tuple[RecordRef, ...]) -> tuple[RecordRef, ...]:
    return tuple(dict.fromkeys(refs))


__all__ = ["VerificationCompletion", "VerificationCompletionCoordinator"]
