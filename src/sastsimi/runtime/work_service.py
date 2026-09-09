"""Runtime work API; the injected port owns each atomic state change."""

from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.work import StateTransition, WorkExecutionState
from sastsimi.ports.runtime_store import WorkStatePort


class WorkService:
    def __init__(self, store: WorkStatePort) -> None:
        self.store = store

    def get(self, work_id: str) -> WorkExecutionState:
        return self.store.get(work_id)

    def register(
        self,
        work: WorkExecutionState,
        decision_ref: RecordRef,
        reservation_ref: RecordRef | None,
    ) -> WorkExecutionState:
        return self.store.register(work, decision_ref, reservation_ref)

    def make_ready(self, transition: StateTransition) -> WorkExecutionState:
        return self.store.make_ready(transition)
