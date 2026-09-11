"""Production-facing Rule Scope work result adapter."""

from __future__ import annotations

from typing import Protocol

from sastsimi.contracts.gates import RuleScopeImpactReview
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation
from sastsimi.runtime.workflow_runner import WorkflowRunner

from .rule_scope_service import (
    RuleScopeExecution,
    RuleScopeGateInputs,
    RuleScopeGateOutcome,
    RuleScopeGateService,
)


class CompletingRunner(Protocol):
    def complete(self, *args: object, **kwargs: object) -> object: ...


class WorkflowRuleScopePublisher:
    """Save with RULE_SCOPE_GATE identity; never with Verification identity."""

    def __init__(self, runner: WorkflowRunner) -> None:
        self._runner = runner

    def __call__(
        self,
        execution: RuleScopeExecution,
        review: RuleScopeImpactReview,
        invocation: PersistedLLMInvocation,
    ) -> StoredDataRef:
        if execution.gate_identity_ref is None:
            raise ValueError("RULE_SCOPE_GATE_IDENTITY_REQUIRED")
        completed = self._runner.complete(
            execution.work,
            execution.gate_identity_ref,
            "RULE_SCOPE_GATE",
            (review,),
            action_input_refs=self._save_inputs(execution, invocation),
        )
        output_ref = completed.output_refs[0]
        if not isinstance(output_ref, StoredDataRef):
            raise ValueError("RULE_SCOPE_REVIEW_COMMIT_MISMATCH")
        return output_ref

    @staticmethod
    def _save_inputs(
        execution: RuleScopeExecution,
        invocation: PersistedLLMInvocation,
    ) -> tuple[RecordRef, ...]:
        refs: tuple[RecordRef, ...] = (
            *execution.work.input_refs,
            execution.call.decision_ref,
            execution.call.reservation_ref,
            execution.call.call_spec_ref,
            invocation.request.action_decision_ref,
            reference(invocation.request),
            reference(invocation.result),
            invocation.log_ref,
        )
        if invocation.result.parsed_output_ref is not None:
            refs = (*refs, invocation.result.parsed_output_ref)
        return tuple(dict.fromkeys(refs))


class RuleScopeGateHandler:
    """Scheduler handler; the service itself preserves the no-work stop branch."""

    def __init__(self, service: RuleScopeGateService) -> None:
        self._service = service

    async def run(self, inputs: RuleScopeGateInputs) -> RuleScopeGateOutcome:
        return await self._service.review(inputs)


__all__ = ["RuleScopeGateHandler", "WorkflowRuleScopePublisher"]
