"""Durable heartbeat for one exact claimed work attempt."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Literal

from sastsimi.ports.clock import Clock
from sastsimi.ports.dto import WorkContext
from sastsimi.ports.scheduler import RunControlPort, SchedulerStorePort

type HeartbeatStatus = Literal["ACTIVE", "STOPPED", "CANCELLED", "STALE"]


class LeaseHeartbeat:
    """Renew only the exact current attempt and stop on cancellation or staleness."""

    def __init__(
        self,
        *,
        scheduler: SchedulerStorePort,
        run_control: RunControlPort,
        clock: Clock,
        context: WorkContext,
        worker_id: str,
        lease_duration: timedelta,
        interval: float,
    ) -> None:
        if (
            not worker_id
            or lease_duration <= timedelta(0)
            or interval <= 0
            or interval >= lease_duration.total_seconds()
        ):
            raise ValueError("HEARTBEAT_CONFIGURATION_INVALID")
        self._scheduler = scheduler
        self._run_control = run_control
        self._clock = clock
        self._context = context
        self._worker_id = worker_id
        self._lease_duration = lease_duration
        self._interval = interval
        self._started_ms = clock.monotonic_ms()
        self._initial_elapsed_ms = context.attempt.elapsed_ms
        self._stopped = asyncio.Event()

    def pulse(self) -> HeartbeatStatus:
        analysis_id = str(self._context.work.meta.analysis_id)
        if self._run_control.cancel_requested(analysis_id):
            return "CANCELLED"
        elapsed_ms = self._initial_elapsed_ms + max(
            0, self._clock.monotonic_ms() - self._started_ms
        )
        try:
            self._context = self._scheduler.renew_lease(
                self._context,
                self._worker_id,
                self._clock.now() + self._lease_duration,
                elapsed_ms,
            )
        except (LookupError, ValueError):
            return "STALE"
        return "ACTIVE"

    async def run(self) -> HeartbeatStatus:
        while True:
            try:
                await asyncio.wait_for(self._stopped.wait(), timeout=self._interval)
            except TimeoutError:
                status = self.pulse()
                if status != "ACTIVE":
                    return status
            else:
                return "STOPPED"

    def stop(self) -> None:
        self._stopped.set()


__all__ = ["HeartbeatStatus", "LeaseHeartbeat"]
