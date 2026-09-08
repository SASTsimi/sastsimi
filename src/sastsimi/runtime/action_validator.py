"""Trusted runtime authorization API; checks and claims commit in the port."""

from sastsimi.contracts.refs import RecordRef
from sastsimi.ports.runtime_store import ActionAuthorizationPort


class RuntimeValidator:
    def __init__(self, authorization: ActionAuthorizationPort) -> None:
        self.authorization = authorization

    def claim_external(
        self, work_id: str, decision_ref: RecordRef, reservation_ref: RecordRef | None
    ) -> None:
        self.authorization.claim_external(work_id, decision_ref, reservation_ref)
