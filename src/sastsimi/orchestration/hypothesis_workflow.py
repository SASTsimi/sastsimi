"""Trusted orchestration of one initial Hypothesis Agent invocation."""

from __future__ import annotations

from dataclasses import dataclass

from sastsimi.contracts.llm import (
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
)
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef, reference
from sastsimi.contracts.static import StaticFactBundle
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.llm_invocation import (
    HypothesisAgentOutcome,
    HypothesisProposalAgent,
)
from sastsimi.ports.record_store import RecordStore
from sastsimi.runtime.workflow_runner import WorkflowRunner


@dataclass(frozen=True)
class HypothesisWorkflowResult:
    """Invocation evidence and optional terminal work after safe finalization."""

    outcome: HypothesisAgentOutcome
    completed_work: WorkExecutionState | None


class HypothesisWorkflow:
    """Bind Agent proposals to their exact invocation before terminal storage."""

    def __init__(
        self,
        *,
        agent: HypothesisProposalAgent,
        runner: WorkflowRunner,
        records: RecordStore,
    ) -> None:
        self._agent = agent
        self._runner = runner
        self._records = records

    async def run(
        self,
        *,
        work: WorkExecutionState,
        orchestration_identity_ref: BudgetScopeRef,
        decision_ref: StoredDataRef,
        reservation_ref: RecordRef,
        call_spec_ref: StoredDataRef,
        static_bundle: StaticFactBundle,
        static_bundle_ref: StoredDataRef,
    ) -> HypothesisWorkflowResult:
        outcome = await self._agent.propose(
            work=work,
            decision_ref=decision_ref,
            reservation_ref=reservation_ref,
            call_spec_ref=call_spec_ref,
            static_bundle=static_bundle,
            static_bundle_ref=static_bundle_ref,
        )
        if outcome.invocation.result.status != "SUCCEEDED":
            if outcome.proposals:
                raise ValueError("HYPOTHESIS_FAILED_INVOCATION_HAS_OUTPUT")
            return HypothesisWorkflowResult(outcome, None)

        invocation_refs = self._require_persisted_invocation(outcome)
        completed = self._runner.complete(
            work,
            orchestration_identity_ref,
            "ORCHESTRATION",
            outcome.proposals,
            action_input_refs=(static_bundle_ref, *invocation_refs),
        )
        return HypothesisWorkflowResult(outcome, completed)

    def _require_persisted_invocation(
        self, outcome: HypothesisAgentOutcome
    ) -> tuple[StoredDataRef, ...]:
        invocation = outcome.invocation
        request_ref = reference(invocation.request)
        result_ref = reference(invocation.result)
        if not isinstance(request_ref, StoredDataRef) or not isinstance(
            result_ref, StoredDataRef
        ):
            raise ValueError("HYPOTHESIS_INVOCATION_PROVENANCE_MISMATCH")
        log = self._records.get_exact(invocation.log_ref)
        request = self._records.get_exact(request_ref)
        result = self._records.get_exact(result_ref)
        if (
            not isinstance(log, LLMInvocationLog)
            or not isinstance(request, LLMInvocationRequest)
            or not isinstance(result, LLMInvocationResult)
            or request != invocation.request
            or result != invocation.result
            or reference(log) != invocation.log_ref
            or log.status != "SUCCEEDED"
            or log.agent_role != "HYPOTHESIS"
            or log.task_kind != "GENERATE_INITIAL"
            or log.llm_call_id != request.llm_call_id
            or result.llm_call_id != request.llm_call_id
            or log.action_decision_ref != request.action_decision_ref
            or log.call_spec_ref != request.call_spec_ref
            or log.context_refs != request.context_refs
            or log.parsed_output_ref != result.parsed_output_ref
            or result.parsed_output_ref is None
        ):
            raise ValueError("HYPOTHESIS_INVOCATION_PROVENANCE_MISMATCH")
        return request_ref, result_ref, invocation.log_ref, result.parsed_output_ref


__all__ = ["HypothesisWorkflow", "HypothesisWorkflowResult"]
