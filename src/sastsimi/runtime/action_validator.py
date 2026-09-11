"""Trusted runtime authorization API; checks and claims commit in the port."""

from typing import Protocol, cast

from sastsimi.contracts.actions import ActionDecision, ActionRequest
from sastsimi.contracts.llm import (
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
)
from sastsimi.contracts.refs import RecordRef, StoredDataRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.runtime_store import ActionAuthorizationPort


class _DispatchInspectionPort(Protocol):
    def require_unresolved_dispatch(
        self,
        work_id: str,
        attempt_id: str,
        decision_ref: RecordRef,
        action_id: str,
    ) -> None: ...


class RuntimeValidator:
    def require_unresolved_dispatch(
        self,
        work_id: str,
        attempt_id: str,
        decision_ref: RecordRef,
        action_id: str,
    ) -> None:
        if not hasattr(self.authorization, "require_unresolved_dispatch"):
            raise ValueError("DISPATCH_INSPECTION_UNAVAILABLE")
        cast(_DispatchInspectionPort, self.authorization).require_unresolved_dispatch(
            work_id, attempt_id, decision_ref, action_id
        )

    def mark_dispatched(
        self,
        decision_ref: RecordRef,
        provider_request_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> None:
        self.authorization.mark_dispatched(
            decision_ref, provider_request_id, idempotency_key
        )

    def mark_returned(self, decision_ref: RecordRef) -> None:
        self.authorization.mark_returned(decision_ref)

    def __init__(self, authorization: ActionAuthorizationPort) -> None:
        self.authorization = authorization

    def authorize(
        self,
        action: ActionRequest,
        work: WorkExecutionState | None = None,
        reservation_ref: RecordRef | None = None,
    ) -> ActionDecision:
        return self.authorization.authorize(action, work, reservation_ref)

    def claim_external(
        self, work_id: str, decision_ref: RecordRef, reservation_ref: RecordRef | None
    ) -> RecordRef:
        return self.authorization.claim_external(work_id, decision_ref, reservation_ref)

    def record_invocation(
        self,
        request: LLMInvocationRequest,
        result: LLMInvocationResult,
        log: LLMInvocationLog,
    ) -> StoredDataRef:
        return self.authorization.record_invocation(request, result, log)
