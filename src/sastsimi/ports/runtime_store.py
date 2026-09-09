"""Task 6 transaction ports. SQL connections never cross these boundaries."""

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from sastsimi.contracts.actions import ActionDecision, ActionRequest
from sastsimi.contracts.analysis import AnalysisRunState
from sastsimi.contracts.budget import BudgetProfileBinding, ExecutionBudgetProfile
from sastsimi.contracts.llm import (
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
)
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
    def mark_dispatched(
        self,
        decision_ref: RecordRef,
        provider_request_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> None: ...
    def mark_returned(self, decision_ref: RecordRef) -> None: ...
    def authorize(
        self,
        action: ActionRequest,
        work: WorkExecutionState | None = None,
        reservation_ref: RecordRef | None = None,
    ) -> ActionDecision: ...
    def claim_external(
        self, work_id: str, decision_ref: RecordRef, reservation_ref: RecordRef | None
    ) -> RecordRef: ...
    def record_invocation(
        self,
        request: LLMInvocationRequest,
        result: LLMInvocationResult,
        log: LLMInvocationLog,
        output_ref: StoredDataRef,
    ) -> StoredDataRef: ...


class BudgetRegistryPort(Protocol):
    def pin_execution(
        self, profile: ExecutionBudgetProfile, state: AnalysisRunState | None = None
    ) -> RunStoredDataRef: ...
    def current_state(self, analysis_id: str) -> AnalysisRunState: ...
    def pin_binding(
        self,
        binding: BudgetProfileBinding,
        workspace_ref: RunStoredDataRef,
        analysis_state_ref: RunStoredDataRef | None = None,
    ) -> StoredDataRef: ...


@dataclass(frozen=True)
class RecoveryReport:
    checked_artifacts: int
    quarantined_artifacts: int
    blocked_work: int


class RecoveryPort(Protocol):
    def recover(self) -> RecoveryReport: ...
