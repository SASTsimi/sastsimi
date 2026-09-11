"""Production-facing Rule Scope work result adapter."""

from __future__ import annotations

from typing import Protocol

from sastsimi.contracts.gates import RuleScopeImpactReview
from sastsimi.contracts.refs import StoredDataRef
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
        self, execution: RuleScopeExecution, review: RuleScopeImpactReview
    ) -> StoredDataRef:
        if execution.gate_identity_ref is None:
            raise ValueError("RULE_SCOPE_GATE_IDENTITY_REQUIRED")
        completed = self._runner.complete(
            execution.work,
            execution.gate_identity_ref,
            "RULE_SCOPE_GATE",
            (review,),
            action_input_refs=execution.work.input_refs,
        )
        output_ref = completed.output_refs[0]
        if not isinstance(output_ref, StoredDataRef):
            raise ValueError("RULE_SCOPE_REVIEW_COMMIT_MISMATCH")
        return output_ref


class RuleScopeGateHandler:
    """Scheduler handler; the service itself preserves the no-work stop branch."""

    def __init__(self, service: RuleScopeGateService) -> None:
        self._service = service

    async def run(self, inputs: RuleScopeGateInputs) -> RuleScopeGateOutcome:
        return await self._service.review(inputs)


__all__ = ["RuleScopeGateHandler", "WorkflowRuleScopePublisher"]
