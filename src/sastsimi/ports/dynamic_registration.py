"""A trusted handoff consumes the owning Verification request exactly once."""

from typing import Protocol

from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.work import WorkExecutionState


class DynamicRegistrationPort(Protocol):
    def register(
        self, work_id: str, decision_ref: RecordRef, reservation_ref: RecordRef
    ) -> WorkExecutionState: ...
