"""Task 6 transaction ports. SQL connections never cross these boundaries."""

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from sastsimi.contracts.budget import BudgetProfileBinding, ExecutionBudgetProfile
from sastsimi.contracts.refs import RecordRef, RunStoredDataRef, StoredDataRef
from sastsimi.contracts.work import StateTransition, WorkAttempt, WorkExecutionState


class WorkStatePort(Protocol):
    def get(self, work_id: str) -> WorkExecutionState: ...
    def register(
        self,
        work: WorkExecutionState,
        decision_ref: RecordRef,
        reservation_ref: RecordRef | None,
    ) -> WorkExecutionState: ...
    def make_ready(self, transition: StateTransition) -> WorkExecutionState: ...


class AttemptPort(Protocol):
    def start(
        self,
        transition: StateTransition,
        attempt: WorkAttempt,
        reservation_ref: RecordRef,
        worker_id: str,
        lease_expires_at: datetime,
    ) -> WorkExecutionState: ...


class ActionAuthorizationPort(Protocol):
    def claim_external(
        self, work_id: str, decision_ref: RecordRef, reservation_ref: RecordRef | None
    ) -> None: ...


class BudgetRegistryPort(Protocol):
    def pin_execution(self, profile: ExecutionBudgetProfile) -> RunStoredDataRef: ...
    def pin_binding(
        self, binding: BudgetProfileBinding, workspace_ref: RunStoredDataRef
    ) -> StoredDataRef: ...


@dataclass(frozen=True)
class RecoveryReport:
    checked_artifacts: int
    quarantined_artifacts: int
    blocked_work: int


class RecoveryPort(Protocol):
    def recover(self) -> RecoveryReport: ...
