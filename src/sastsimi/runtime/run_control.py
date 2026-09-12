"""Production run, status, cancel, resume, and exact-result application service."""

from __future__ import annotations

import asyncio
from collections import Counter
from typing import Protocol

from sastsimi.contracts.analysis import AnalysisRunState, AnalysisStartRequest
from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.contracts.refs import RecordRef, reference
from sastsimi.contracts.work import (
    WorkAttempt,
    WorkExecutionState,
)
from sastsimi.ports.runtime_store import RecoveryPort
from sastsimi.ports.scheduler import (
    AnalysisStatusView,
    RunControlPort,
    RunOutcome,
    SchedulerStorePort,
    WorkSchedulerPort,
)

from .cancellation_service import CancellationService


class RunInitializerPort(Protocol):
    """Create one production run and return its durable analysis ID."""

    def initialize(self, request: AnalysisStartRequest) -> str: ...


class AnalysisRunReader(Protocol):
    def current_state(self, analysis_id: str) -> AnalysisRunState: ...


class ExactRecordReader(Protocol):
    def get_exact(self, ref: RecordRef) -> object: ...


class BlockedWorkResumePort(Protocol):
    """Atomically revalidate and move exact BLOCKED works to READY.

    The storage implementation must re-read every work and prior attempt,
    unchanged input/config references, remaining budget, cancellation latch,
    and unresolved external-dispatch state in one transaction.  It returns all
    READY revisions only when every candidate passes; it never calls
    ``make_ready`` after a separate eligibility read or partially opens a run.
    """

    def resume_blocked(
        self,
        candidates: tuple[tuple[WorkExecutionState, WorkAttempt], ...],
    ) -> tuple[WorkExecutionState, ...]: ...


class ProductionRunControl:
    """Transport coordination only; handlers retain all domain-result authority."""

    def __init__(
        self,
        *,
        initializer: RunInitializerPort,
        scheduler: WorkSchedulerPort,
        scheduler_store: SchedulerStorePort,
        controls: RunControlPort,
        cancellation: CancellationService,
        recovery: RecoveryPort,
        runs: AnalysisRunReader,
        records: ExactRecordReader,
        resumer: BlockedWorkResumePort,
        shutdown_timeout_seconds: float = 5.0,
    ) -> None:
        if shutdown_timeout_seconds <= 0:
            raise ValueError("SHUTDOWN_TIMEOUT_INVALID")
        self._initializer = initializer
        self._scheduler = scheduler
        self._scheduler_store = scheduler_store
        self.controls = controls
        self._cancellation = cancellation
        self._recovery = recovery
        self._runs = runs
        self._records = records
        self._resumer = resumer
        self._shutdown_timeout_seconds = shutdown_timeout_seconds

    async def run(self, request: AnalysisStartRequest) -> RunOutcome:
        self._recovery.recover()
        analysis_id = self._initializer.initialize(request)
        return await self._drain_interrupt_safe(analysis_id)

    def status(self, analysis_id: str) -> AnalysisStatusView:
        state = self._runs.current_state(analysis_id)
        works = self._scheduler_store.work_for_run(analysis_id)
        counts = Counter(
            f"{item.work_type.value}:{item.status.value}" for item in works
        )
        cancel_requested = self.controls.cancel_requested(analysis_id)
        run_status: str = state.status
        if state.status == "RUNNING":
            active = any(item.status in {"READY", "RUNNING"} for item in works)
            blocked = any(item.status == "BLOCKED" for item in works)
            if cancel_requested:
                run_status = "CANCELLING"
            elif blocked and not active:
                run_status = "BLOCKED"
        waiting_for = tuple(
            sorted({reason.value for item in works for reason in item.waiting_for})
        )
        return AnalysisStatusView(
            analysis_id=analysis_id,
            run_status=run_status,
            work_counts=tuple(sorted(counts.items())),
            cancel_requested=cancel_requested,
            waiting_for=waiting_for,
            result_ref=state.analysis_result_ref,
        )

    async def cancel(self, analysis_id: str) -> AnalysisStatusView:
        await self._cancellation.request(analysis_id, "USER_REQUEST")
        return self.status(analysis_id)

    async def resume(self, analysis_id: str) -> RunOutcome:
        self._recovery.recover()
        state = self._runs.current_state(analysis_id)
        if state.status != "RUNNING" or self.controls.cancel_requested(analysis_id):
            raise ValueError("RUN_NOT_RESUMABLE")
        works = self._scheduler_store.work_for_run(analysis_id)
        if any(item.status in {"PENDING", "READY", "RUNNING"} for item in works):
            raise ValueError("RUN_NOT_QUIESCENT")
        blocked = tuple(item for item in works if item.status == "BLOCKED")
        if not blocked:
            raise ValueError("RUN_NOT_RESUMABLE")
        candidates: list[tuple[WorkExecutionState, WorkAttempt]] = []
        for item in blocked:
            attempts = self._scheduler_store.attempts_for_work(str(item.work_id))
            if not attempts:
                raise ValueError("RESUME_ATTEMPT_HISTORY_REQUIRED")
            previous = attempts[-1]
            if previous.status == "RUNNING" or previous.input_hash != item.input_hash:
                raise ValueError("RESUME_INPUT_CHANGED")
            candidates.append((item, previous))
        resumed = self._resumer.resume_blocked(tuple(candidates))
        if len(resumed) != len(candidates) or any(
            ready.status != "READY"
            or ready.work_id != blocked_item.work_id
            or ready.input_hash != blocked_item.input_hash
            for ready, (blocked_item, _previous) in zip(
                resumed, candidates, strict=True
            )
        ):
            raise ValueError("RESUME_RESULT_MISMATCH")
        return await self._drain_interrupt_safe(analysis_id)

    def result(self, analysis_id: str) -> AnalysisRunResult:
        state = self._runs.current_state(analysis_id)
        if state.status == "RUNNING" or state.analysis_result_ref is None:
            raise ValueError("RESULT_NOT_TERMINAL")
        result = self._records.get_exact(state.analysis_result_ref)
        if (
            not isinstance(result, AnalysisRunResult)
            or reference(result) != state.analysis_result_ref
            or str(result.meta.analysis_id) != analysis_id
            or result.status != state.status
        ):
            raise ValueError("ANALYSIS_RESULT_EXACT_REF_MISMATCH")
        return result

    async def _drain_interrupt_safe(self, analysis_id: str) -> RunOutcome:
        try:
            return await self._scheduler.drain(analysis_id)
        except (KeyboardInterrupt, asyncio.CancelledError):
            # Persist synchronously before any cancellation/drain await.  If the
            # bounded drain is interrupted again, restart still sees the latch.
            self.controls.request_cancel(analysis_id, "FOREGROUND_INTERRUPT")
            task = asyncio.create_task(self._cancellation.drain_latched(analysis_id))
            try:
                await asyncio.wait_for(
                    asyncio.shield(task), timeout=self._shutdown_timeout_seconds
                )
            except Exception:
                # External completion is uncertain; durable recovery owns the
                # next decision and must not redispatch the prior action.
                pass
            raise


__all__ = [
    "AnalysisRunReader",
    "BlockedWorkResumePort",
    "ExactRecordReader",
    "ProductionRunControl",
    "RunInitializerPort",
]
