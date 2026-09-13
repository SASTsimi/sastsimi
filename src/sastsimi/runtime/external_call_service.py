"""Commit authorization before even constructing an external-port awaitable."""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from sastsimi.contracts.refs import RecordRef
from sastsimi.ports.llm_invocation import ExternalDispatchState
from sastsimi.ports.runtime_store import ActionAuthorizationPort


@dataclass(frozen=True)
class ExternalOperationResult[T]:
    """Operation result plus whether the remote outcome is known."""

    value: T
    dispatch_state: ExternalDispatchState


class ExternalCallService:
    def __init__(self, authorization: ActionAuthorizationPort) -> None:
        self.authorization = authorization

    async def invoke[T](
        self,
        work_id: str,
        decision_ref: RecordRef,
        reservation_ref: RecordRef | None,
        operation: Callable[[], Awaitable[T]],
        *,
        provider_request_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> T:
        self.authorization.claim_external(work_id, decision_ref, reservation_ref)
        self.authorization.mark_dispatched(
            decision_ref, provider_request_id, idempotency_key
        )
        result = await operation()
        self.authorization.mark_returned(decision_ref)
        return result

    async def invoke_bound[T](
        self,
        work_id: str,
        decision_ref: RecordRef,
        reservation_ref: RecordRef | None,
        operation: Callable[[RecordRef], Awaitable[T]],
        *,
        provider_request_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> tuple[T, RecordRef]:
        claimed = self.authorization.claim_external(
            work_id, decision_ref, reservation_ref
        )
        self.authorization.mark_dispatched(
            decision_ref, provider_request_id, idempotency_key
        )
        result = await operation(claimed)
        self.authorization.mark_returned(decision_ref)
        return result, claimed

    async def invoke_bound_tracked[T](
        self,
        work_id: str,
        decision_ref: RecordRef,
        reservation_ref: RecordRef | None,
        operation: Callable[[RecordRef], Awaitable[ExternalOperationResult[T]]],
        *,
        provider_request_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> tuple[ExternalOperationResult[T], RecordRef]:
        """Keep an ambiguous remote dispatch open until explicit reconciliation."""
        claimed = self.authorization.claim_external(
            work_id, decision_ref, reservation_ref
        )
        self.authorization.mark_dispatched(
            decision_ref, provider_request_id, idempotency_key
        )
        result = await operation(claimed)
        if result.dispatch_state == "RETURNED":
            self.authorization.mark_returned(decision_ref)
        return result, claimed
