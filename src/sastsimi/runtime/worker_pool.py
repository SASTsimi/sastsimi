"""Bounded foreground scheduler over exact claimed work contexts."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from datetime import timedelta

from sastsimi.contracts.work import TERMINAL_WORK_STATUSES, WorkStatus, WorkType
from sastsimi.ports.clock import Clock
from sastsimi.ports.dto import WorkContext
from sastsimi.ports.scheduler import (
    HandlerRegistryPort,
    RunControlPort,
    RunOutcome,
    SchedulerStorePort,
)

from .lease_heartbeat import LeaseHeartbeat
from .work_service import HandlerDidNotFinalizeError, WorkService

_ALL_READY_WORK = 2_147_483_647


class WorkerPool:
    """Claim READY work atomically and isolate every handler task."""

    def __init__(
        self,
        *,
        scheduler: SchedulerStorePort,
        run_control: RunControlPort,
        registry: HandlerRegistryPort,
        works: WorkService,
        clock: Clock,
        worker_id: str,
        max_workers: int,
        lease_duration: timedelta,
        heartbeat_interval: float,
        poll_interval: float,
    ) -> None:
        if (
            not worker_id
            or max_workers <= 0
            or poll_interval <= 0
            or lease_duration <= timedelta(0)
            or heartbeat_interval <= 0
            or heartbeat_interval >= lease_duration.total_seconds()
        ):
            raise ValueError("WORKER_POOL_CONFIGURATION_INVALID")
        registry.validate_complete(tuple(WorkType))
        works.require_failure_recorder()
        self._scheduler = scheduler
        self._run_control = run_control
        self._registry = registry
        self._works = works
        self._clock = clock
        self._worker_id = worker_id
        self._max_workers = max_workers
        self._lease_duration = lease_duration
        self._heartbeat_interval = heartbeat_interval
        self._poll_interval = poll_interval
        self._tasks: set[asyncio.Task[None]] = set()

    @property
    def active_task_count(self) -> int:
        return len(self._tasks)

    async def drain(self, analysis_id: str) -> RunOutcome:
        if not analysis_id:
            raise ValueError("ANALYSIS_ID_REQUIRED")
        owned: set[asyncio.Task[None]] = set()
        try:
            while True:
                if self._run_control.cancel_requested(analysis_id):
                    await self._cancel_tasks(owned)
                    if all(
                        work.status != WorkStatus.RUNNING
                        for work in self._scheduler.work_for_run(analysis_id)
                    ):
                        self._run_control.mark_quiescent(analysis_id)
                    return RunOutcome(analysis_id, "CANCELLED", None)

                self._fill_available_slots(analysis_id, owned)
                if owned:
                    done, _ = await asyncio.wait(
                        owned,
                        timeout=self._poll_interval,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    self._collect(done, owned)
                    continue

                outcome = self._idle_outcome(analysis_id)
                if outcome is not None:
                    return outcome
                await asyncio.sleep(self._poll_interval)
        except asyncio.CancelledError:
            await self._cancel_tasks(owned)
            raise
        finally:
            self._tasks.difference_update(owned)

    async def shutdown(self) -> None:
        await self._cancel_tasks(set(self._tasks))

    def _fill_available_slots(
        self, analysis_id: str, owned: set[asyncio.Task[None]]
    ) -> None:
        while len(owned) < self._max_workers:
            candidates = sorted(
                self._scheduler.ready_work(analysis_id, _ALL_READY_WORK),
                key=lambda work: (work.work_type.value, str(work.work_id)),
            )
            claimed = False
            for candidate in candidates:
                if self._run_control.cancel_requested(analysis_id):
                    return
                context = self._scheduler.try_claim_ready(
                    analysis_id,
                    str(candidate.work_id),
                    candidate.state_version,
                    self._worker_id,
                    self._clock.now() + self._lease_duration,
                )
                if context is None:
                    continue
                task = asyncio.create_task(self._execute_claimed(context))
                owned.add(task)
                self._tasks.add(task)
                claimed = True
                break
            if not claimed:
                return

    async def _execute_claimed(self, context: WorkContext) -> None:
        analysis_id = str(context.work.meta.analysis_id)
        heartbeat = LeaseHeartbeat(
            scheduler=self._scheduler,
            run_control=self._run_control,
            clock=self._clock,
            context=context,
            worker_id=self._worker_id,
            lease_duration=self._lease_duration,
            interval=self._heartbeat_interval,
        )
        if heartbeat.pulse() != "ACTIVE":
            return

        handler = self._registry.resolve(context.work.work_type)
        handler_task = asyncio.create_task(handler.execute(context))
        heartbeat_task = asyncio.create_task(heartbeat.run())
        try:
            done, _ = await asyncio.wait(
                (handler_task, heartbeat_task),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if handler_task not in done:
                handler_task.cancel()
                with suppress(asyncio.CancelledError):
                    await handler_task
                return

            try:
                result = handler_task.result()
            except asyncio.CancelledError:
                return
            except Exception:
                heartbeat.stop()
                await heartbeat_task
                self._record_failure(context)
                return

            heartbeat.stop()
            await heartbeat_task
            if self._run_control.cancel_requested(analysis_id):
                return
            try:
                self._works.accept_handler_result(context, result)
            except HandlerDidNotFinalizeError:
                self._record_failure(context)
            except (LookupError, ValueError):
                # An exact later attempt/current revision owns any such result.
                return
        finally:
            heartbeat.stop()
            if not heartbeat_task.done():
                heartbeat_task.cancel()
            if not handler_task.done():
                handler_task.cancel()
            await asyncio.gather(
                handler_task, heartbeat_task, return_exceptions=True
            )

    def _record_failure(self, context: WorkContext) -> None:
        with suppress(LookupError, ValueError):
            self._works.record_handler_failure(context)

    def _idle_outcome(self, analysis_id: str) -> RunOutcome | None:
        work = self._scheduler.work_for_run(analysis_id)
        statuses = {item.status for item in work}
        if WorkStatus.RUNNING in statuses:
            return None
        if not work or WorkStatus.READY in statuses:
            return RunOutcome(analysis_id, "BLOCKED", None)
        if WorkStatus.BLOCKED in statuses or WorkStatus.PENDING in statuses:
            return RunOutcome(analysis_id, "BLOCKED", None)
        if WorkStatus.FAILED in statuses:
            return RunOutcome(analysis_id, "FAILED", None)
        if statuses and statuses <= TERMINAL_WORK_STATUSES:
            if statuses == {WorkStatus.CANCELLED}:
                return RunOutcome(analysis_id, "CANCELLED", None)
            return RunOutcome(analysis_id, "TERMINAL", None)
        return RunOutcome(analysis_id, "BLOCKED", None)

    def _collect(
        self,
        done: set[asyncio.Task[None]],
        owned: set[asyncio.Task[None]],
    ) -> None:
        for task in done:
            owned.discard(task)
            self._tasks.discard(task)
            with suppress(asyncio.CancelledError):
                task.result()

    async def _cancel_tasks(self, tasks: set[asyncio.Task[None]]) -> None:
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._tasks.difference_update(tasks)
        tasks.clear()


__all__ = ["WorkerPool"]
