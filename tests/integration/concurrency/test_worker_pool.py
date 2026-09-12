from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from sastsimi.contracts.ids import AnalysisId, AttemptId, WorkId
from sastsimi.contracts.records import RunMeta
from sastsimi.contracts.work import (
    AttemptStatus,
    WorkAttempt,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.ports.dto import WorkContext, WorkHandlerResult
from sastsimi.runtime.handler_registry import HandlerRegistry
from sastsimi.runtime.work_service import WorkService
from sastsimi.runtime.worker_pool import WorkerPool

NOW = datetime(2026, 9, 13, tzinfo=UTC)


class _Clock:
    def __init__(self) -> None:
        self.elapsed = 0

    def now(self) -> datetime:
        return NOW

    def monotonic_ms(self) -> int:
        self.elapsed += 1
        return self.elapsed


class _RunControl:
    def __init__(self) -> None:
        self.cancelled = False
        self.quiescent = False

    def request_cancel(self, analysis_id: str, reason: str) -> None:
        assert analysis_id == "analysis-1"
        assert reason
        self.cancelled = True

    def cancel_requested(self, analysis_id: str) -> bool:
        assert analysis_id == "analysis-1"
        return self.cancelled

    def mark_quiescent(self, analysis_id: str) -> None:
        assert analysis_id == "analysis-1"
        self.quiescent = True

    def cancellation_targets(self, analysis_id: str) -> tuple[()]:
        assert analysis_id == "analysis-1"
        return ()


def _work(work_id: str, work_type: WorkType) -> WorkExecutionState:
    return WorkExecutionState.model_construct(
        meta=RunMeta.model_construct(analysis_id=AnalysisId("analysis-1")),
        work_id=WorkId(work_id),
        work_type=work_type,
        status=WorkStatus.READY,
        state_version=2,
        active_attempt_id=None,
        input_hash="a" * 64,
        output_refs=(),
    )


class _Scheduler:
    """In-memory atomic boundary; handlers still own terminal publication."""

    def __init__(self, works: tuple[WorkExecutionState, ...], cap: int) -> None:
        self.works = {str(work.work_id): work for work in works}
        self.attempts: dict[str, list[WorkAttempt]] = {
            str(work.work_id): [] for work in works
        }
        self.cap = cap
        self.claims: list[tuple[WorkType, str]] = []
        self.current_running = 0
        self.max_running = 0
        self.handler_publications: list[str] = []
        self.failure_records: list[str] = []
        self.stale_on_renew: set[str] = set()

    def get(self, work_id: str) -> WorkExecutionState:
        return self.works[work_id]

    def ready_work(
        self, analysis_id: str, limit: int
    ) -> tuple[WorkExecutionState, ...]:
        assert analysis_id == "analysis-1"
        # Deliberately reverse storage order: the pool owns the stable selection.
        ready = sorted(
            (work for work in self.works.values() if work.status == WorkStatus.READY),
            key=lambda work: str(work.work_id),
            reverse=True,
        )
        return tuple(ready[:limit])

    def work_for_run(self, analysis_id: str) -> tuple[WorkExecutionState, ...]:
        assert analysis_id == "analysis-1"
        return tuple(self.works.values())

    def attempts_for_work(self, work_id: str) -> tuple[WorkAttempt, ...]:
        return tuple(self.attempts[work_id])

    def try_claim_ready(
        self,
        analysis_id: str,
        work_id: str,
        expected_state_version: int,
        worker_id: str,
        lease_expires_at: datetime,
    ) -> WorkContext | None:
        assert analysis_id == "analysis-1"
        assert worker_id
        assert lease_expires_at > NOW
        work = self.works[work_id]
        if (
            work.status != WorkStatus.READY
            or work.state_version != expected_state_version
            or self.current_running >= self.cap
        ):
            return None
        attempt_id = AttemptId(f"attempt-{work_id}-{len(self.claims) + 1}")
        running = work.model_copy(
            update={
                "status": WorkStatus.RUNNING,
                "state_version": work.state_version + 1,
                "active_attempt_id": attempt_id,
            }
        )
        attempt = WorkAttempt.model_construct(
            meta=work.meta,
            work_id=work.work_id,
            attempt_id=attempt_id,
            status=AttemptStatus.RUNNING,
            input_hash=work.input_hash,
            elapsed_ms=0,
        )
        self.works[work_id] = running
        self.attempts[work_id].append(attempt)
        self.claims.append((work.work_type, work_id))
        self.current_running += 1
        self.max_running = max(self.max_running, self.current_running)
        return WorkContext(running, attempt)

    def renew_lease(
        self,
        context: WorkContext,
        worker_id: str,
        lease_expires_at: datetime,
        elapsed_ms: int,
    ) -> WorkContext:
        assert worker_id
        assert lease_expires_at > NOW
        work_id = str(context.work.work_id)
        if work_id in self.stale_on_renew:
            self.stale_on_renew.remove(work_id)
            self.works[work_id] = context.work.model_copy(
                update={
                    "status": WorkStatus.SUCCEEDED,
                    "state_version": context.work.state_version + 1,
                    "active_attempt_id": None,
                    "output_refs": (),
                }
            )
            self.current_running -= 1
            raise ValueError("LEASE_NOT_ACTIVE")
        if self.works[work_id] != context.work:
            raise ValueError("LEASE_NOT_ACTIVE")
        renewed = WorkContext(
            context.work,
            context.attempt.model_copy(update={"elapsed_ms": elapsed_ms}),
        )
        self.attempts[work_id][-1] = renewed.attempt
        return renewed

    def complete(
        self, context: WorkContext, result: WorkHandlerResult
    ) -> WorkExecutionState:
        work_id = str(context.work.work_id)
        if self.works[work_id] != context.work:
            raise ValueError("ATTEMPT_NOT_ACTIVE")
        completed = context.work.model_copy(
            update={
                "status": WorkStatus.SUCCEEDED,
                "state_version": context.work.state_version + 1,
                "active_attempt_id": None,
                "output_refs": result.output_refs,
            }
        )
        self.works[work_id] = completed
        self.attempts[work_id][-1] = context.attempt.model_copy(
            update={
                "status": AttemptStatus.SUCCEEDED,
                "output_refs": result.output_refs,
            }
        )
        self.current_running -= 1
        self.handler_publications.append(work_id)
        return completed

    def record_handler_failure(
        self, context: WorkContext, reason_code: str
    ) -> WorkExecutionState:
        assert reason_code == "WORK_HANDLER_FAILED"
        work_id = str(context.work.work_id)
        if self.works[work_id] != context.work:
            raise ValueError("ATTEMPT_NOT_ACTIVE")
        blocked = context.work.model_copy(
            update={
                "status": WorkStatus.BLOCKED,
                "state_version": context.work.state_version + 1,
                "active_attempt_id": None,
                "output_refs": (),
            }
        )
        self.works[work_id] = blocked
        self.attempts[work_id][-1] = context.attempt.model_copy(
            update={"status": AttemptStatus.CANCELLED, "output_refs": ()}
        )
        self.current_running -= 1
        self.failure_records.append(work_id)
        return blocked


class _Handler:
    def __init__(
        self,
        store: _Scheduler,
        *,
        barrier: asyncio.Barrier | None = None,
        failures: frozenset[str] = frozenset(),
        wait_forever: frozenset[str] = frozenset(),
        unfinalized: frozenset[str] = frozenset(),
    ) -> None:
        self.store = store
        self.barrier = barrier
        self.failures = failures
        self.wait_forever = wait_forever
        self.unfinalized = unfinalized
        self.active = 0
        self.max_active = 0
        self.started = asyncio.Event()

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        work_id = str(context.work.work_id)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        self.started.set()
        try:
            if work_id in self.failures:
                raise RuntimeError("untrusted handler detail must not be persisted")
            if work_id in self.wait_forever:
                await asyncio.Event().wait()
            if self.barrier is not None:
                await self.barrier.wait()
            result = WorkHandlerResult(())
            if work_id in self.unfinalized:
                return result
            self.store.complete(context, result)
            return result
        finally:
            self.active -= 1


def _pool(
    store: _Scheduler,
    handler: _Handler,
    control: _RunControl,
    worker_id: str = "worker-1",
) -> WorkerPool:
    registry = HandlerRegistry({work_type: handler for work_type in WorkType})
    return WorkerPool(
        scheduler=store,
        run_control=control,
        registry=registry,
        works=WorkService(store, failure_recorder=store),
        clock=_Clock(),
        worker_id=worker_id,
        max_workers=4,
        lease_duration=timedelta(seconds=1),
        heartbeat_interval=0.005,
        poll_interval=0.005,
    )


@pytest.mark.asyncio
async def test_pool_runs_two_ready_work_items_concurrently_in_stable_order() -> None:
    store = _Scheduler(
        (
            _work("work-z", WorkType.STATIC_TOOL),
            _work("work-a", WorkType.DYNAMIC_REPRO),
        ),
        cap=2,
    )
    handler = _Handler(store, barrier=asyncio.Barrier(2))
    incomplete = HandlerRegistry({WorkType.STATIC_TOOL: handler})
    with pytest.raises(ValueError, match="WORK_HANDLER_REGISTRY_INCOMPLETE"):
        incomplete.validate_complete(tuple(WorkType))
    pool = _pool(store, handler, _RunControl())

    outcome = await pool.drain("analysis-1")

    assert outcome.disposition == "TERMINAL"
    assert handler.max_active == 2
    assert store.claims == [
        (WorkType.DYNAMIC_REPRO, "work-a"),
        (WorkType.STATIC_TOOL, "work-z"),
    ]
    assert set(store.handler_publications) == {"work-a", "work-z"}
    assert pool.active_task_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    ["duplicate", "zero", "one", "stale", "failure", "unfinalized", "cancel"],
)
async def test_pool_isolates_critical_claim_and_execution_failures(case: str) -> None:
    works = (
        (_work("work-a", WorkType.DYNAMIC_REPRO),)
        if case in {"duplicate", "zero", "stale", "cancel"}
        else (
            _work("work-a", WorkType.DYNAMIC_REPRO),
            _work("work-b", WorkType.STATIC_TOOL),
        )
    )
    store = _Scheduler(works, cap=0 if case == "zero" else 1)
    control = _RunControl()
    failures = frozenset({"work-a"}) if case == "failure" else frozenset()
    waits = frozenset({"work-a"}) if case == "cancel" else frozenset()
    unfinalized = (
        frozenset({"work-a"}) if case == "unfinalized" else frozenset()
    )
    handler = _Handler(
        store,
        failures=failures,
        wait_forever=waits,
        unfinalized=unfinalized,
    )
    first = _pool(store, handler, control, "worker-1")

    if case == "stale":
        store.stale_on_renew.add("work-a")
    if case == "duplicate":
        second = _pool(store, handler, control, "worker-2")
        outcomes = await asyncio.gather(
            first.drain("analysis-1"), second.drain("analysis-1")
        )
        assert {outcome.disposition for outcome in outcomes} == {"TERMINAL"}
        assert len(store.claims) == 1
    elif case == "cancel":
        drain = asyncio.create_task(first.drain("analysis-1"))
        await handler.started.wait()
        control.request_cancel("analysis-1", "USER_REQUEST")
        outcome = await asyncio.wait_for(drain, timeout=1)
        assert outcome.disposition == "CANCELLED"
        # Lane B owns durable exact-target cancellation; Lane A must not mark a
        # still-RUNNING persisted attempt quiescent merely because its local
        # asyncio task stopped.
        assert not control.quiescent
        assert store.handler_publications == []
    else:
        outcome = await asyncio.wait_for(first.drain("analysis-1"), timeout=1)
        assert outcome.disposition == (
            "BLOCKED"
            if case in {"zero", "failure", "unfinalized"}
            else "TERMINAL"
        )

    if case == "zero":
        assert store.claims == []
    if case == "one":
        assert [kind for kind, _ in store.claims] == [
            WorkType.DYNAMIC_REPRO,
            WorkType.STATIC_TOOL,
        ]
        assert store.max_running == handler.max_active == 1
    if case == "stale":
        assert store.handler_publications == []
    if case in {"failure", "unfinalized"}:
        assert store.failure_records == ["work-a"]
        assert store.handler_publications == ["work-b"]
        assert store.works["work-a"].status == WorkStatus.BLOCKED
        assert store.works["work-a"].output_refs == ()
    assert first.active_task_count == 0
