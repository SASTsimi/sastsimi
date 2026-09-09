"""Trusted runtime authorization API; checks and claims commit in the port."""

from sastsimi.contracts.actions import ActionDecision, ActionRequest
from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.runtime_store import ActionAuthorizationPort


class RuntimeValidator:
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
    ) -> None:
        self.authorization.claim_external(work_id, decision_ref, reservation_ref)
