"""Runtime attempt API with no persistence implementation dependency."""

from datetime import datetime

from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.work import StateTransition, WorkAttempt, WorkExecutionState
from sastsimi.ports.runtime_store import AttemptPort


class AttemptService:
    def __init__(self, store: AttemptPort) -> None:
        self.store = store

    def start(
        self,
        transition: StateTransition,
        attempt: WorkAttempt,
        reservation_ref: RecordRef,
        worker_id: str,
        lease_expires_at: datetime,
    ) -> WorkExecutionState:
        return self.store.start(
            transition, attempt, reservation_ref, worker_id, lease_expires_at
        )
