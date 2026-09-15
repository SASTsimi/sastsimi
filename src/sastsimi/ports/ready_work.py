"""Port for registering downstream work without claiming or executing it."""

from typing import Protocol, runtime_checkable

from sastsimi.contracts.records import RecordMetadata
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef
from sastsimi.contracts.work import WorkExecutionState


@runtime_checkable
class ReadyWorkPort(Protocol):
    def enqueue(
        self,
        scope: BudgetScopeRef,
        metadata: RecordMetadata,
        work_type: str,
        subject_type: str,
        subject_id: str,
        identity: BudgetScopeRef,
        *,
        role: str = "ORCHESTRATION",
        generation: int = 1,
        inputs: tuple[RecordRef, ...] = (),
        parent: RecordRef | None = None,
        trigger_primitive_ref: RecordRef | None = None,
    ) -> WorkExecutionState: ...

    def enqueue_registered(
        self,
        registered: WorkExecutionState,
        scope: BudgetScopeRef,
        identity: BudgetScopeRef,
        *,
        role: str = "ORCHESTRATION",
    ) -> WorkExecutionState: ...

    def ensure_enqueue(
        self,
        scope: BudgetScopeRef,
        metadata: RecordMetadata,
        work_type: str,
        subject_type: str,
        subject_id: str,
        identity: BudgetScopeRef,
        *,
        stable_key: str,
        role: str = "ORCHESTRATION",
        generation: int = 1,
        inputs: tuple[RecordRef, ...] = (),
        parent: RecordRef | None = None,
        trigger_primitive_ref: RecordRef | None = None,
    ) -> WorkExecutionState: ...
