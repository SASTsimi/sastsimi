"""Runtime-owned dynamic request handoff."""

from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dynamic_registration import DynamicRegistrationPort


class DynamicRegistrationService:
    def __init__(self, store: DynamicRegistrationPort) -> None:
        self.store = store

    def register(
        self, work_id: str, decision_ref: RecordRef, reservation_ref: RecordRef
    ) -> WorkExecutionState:
        return self.store.register(work_id, decision_ref, reservation_ref)
