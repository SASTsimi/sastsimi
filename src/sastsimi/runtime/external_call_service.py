"""Commit authorization before even constructing an external-port awaitable."""

from collections.abc import Awaitable, Callable

from sastsimi.contracts.refs import RecordRef
from sastsimi.ports.runtime_store import ActionAuthorizationPort


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
