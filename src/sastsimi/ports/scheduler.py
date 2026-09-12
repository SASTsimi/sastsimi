"""Transport-only ports for production scheduling and durable run control."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.contracts.refs import RecordRef, RunStoredDataRef, StoredDataRef
from sastsimi.contracts.work import WorkAttempt, WorkExecutionState, WorkType

from .dto import WorkContext
from .work_handler import WorkHandler

type CancellationTargetKind = Literal["STATIC", "PROVIDER", "SANDBOX"]
type CancellationStatus = Literal["STOPPED", "ALREADY_TERMINAL", "UNRESOLVED"]
type RunDisposition = Literal["TERMINAL", "BLOCKED", "CANCELLED", "FAILED"]


@dataclass(frozen=True)
class CancellationTarget:
    """Exact persisted external target; callers cannot widen it with raw IDs."""

    target_kind: CancellationTargetKind
    work: WorkExecutionState
    attempt: WorkAttempt
    action_request_ref: RecordRef
    action_decision_ref: RecordRef
    call_spec_ref: StoredDataRef | None
    sandbox_resource_refs: tuple[StoredDataRef, ...]


@dataclass(frozen=True)
class CancellationObservation:
    target: CancellationTarget
    status: CancellationStatus
    reason_code: str | None


@dataclass(frozen=True)
class RunOutcome:
    analysis_id: str
    disposition: RunDisposition
    result_ref: RunStoredDataRef | None


@dataclass(frozen=True)
class AnalysisStatusView:
    analysis_id: str
    run_status: str
    work_counts: tuple[tuple[str, int], ...]
    cancel_requested: bool
    waiting_for: tuple[str, ...]
    result_ref: RunStoredDataRef | None


class SchedulerStorePort(Protocol):
    def ready_work(
        self, analysis_id: str, limit: int
    ) -> tuple[WorkExecutionState, ...]: ...

    def work_for_run(self, analysis_id: str) -> tuple[WorkExecutionState, ...]: ...

    def attempts_for_work(self, work_id: str) -> tuple[WorkAttempt, ...]: ...

    def try_claim_ready(
        self,
        analysis_id: str,
        work_id: str,
        expected_state_version: int,
        worker_id: str,
        lease_expires_at: datetime,
    ) -> WorkContext | None: ...

    def renew_lease(
        self,
        context: WorkContext,
        worker_id: str,
        lease_expires_at: datetime,
        elapsed_ms: int,
    ) -> WorkContext: ...


class RunControlPort(Protocol):
    def request_cancel(self, analysis_id: str, reason: str) -> None: ...

    def cancel_requested(self, analysis_id: str) -> bool: ...

    def mark_quiescent(self, analysis_id: str) -> None: ...

    def cancellation_targets(
        self, analysis_id: str
    ) -> tuple[CancellationTarget, ...]: ...


class ExternalCancellationPort(Protocol):
    async def cancel(self, target: CancellationTarget) -> CancellationObservation: ...


class HandlerRegistryPort(Protocol):
    def validate_complete(self, required: tuple[WorkType, ...]) -> None: ...

    def resolve(self, work_type: WorkType) -> WorkHandler: ...


class WorkSchedulerPort(Protocol):
    async def drain(self, analysis_id: str) -> RunOutcome: ...


class AnalysisApplicationPort(Protocol):
    async def run(self, request: AnalysisStartRequest) -> RunOutcome: ...

    def status(self, analysis_id: str) -> AnalysisStatusView: ...

    async def cancel(self, analysis_id: str) -> AnalysisStatusView: ...

    async def resume(self, analysis_id: str) -> RunOutcome: ...

    def result(self, analysis_id: str) -> AnalysisRunResult: ...


__all__ = [
    "AnalysisApplicationPort",
    "AnalysisStatusView",
    "CancellationObservation",
    "CancellationStatus",
    "CancellationTarget",
    "CancellationTargetKind",
    "ExternalCancellationPort",
    "HandlerRegistryPort",
    "RunControlPort",
    "RunDisposition",
    "RunOutcome",
    "SchedulerStorePort",
    "WorkSchedulerPort",
]
