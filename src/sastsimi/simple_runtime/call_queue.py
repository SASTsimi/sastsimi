"""One queue every agent request passes through.

Each stage used to hold its own ceiling, so a run with six hypotheses could
launch six times the configured number of children at once.  A request is
therefore submitted here instead of started directly: the queue admits them in
arrival order, keeps at most ``max_concurrent`` running, and leaves a minimum
gap between launches so a burst does not arrive as one spike.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from time import monotonic
from typing import TypeVar

T = TypeVar("T")


class CallQueue:
    """Admit agent requests in arrival order, bounded and spaced.

    Arrival order comes from ``asyncio.Semaphore``, which wakes the waiter
    that has been queued longest.  The spacing is the part that has to be
    written out: without it a freed slot is taken the same instant, so a run
    that finishes six stages together starts six children together.
    """

    def __init__(self, *, max_concurrent: int = 1, min_interval_ms: int = 0) -> None:
        self._max_concurrent = max(1, max_concurrent)
        self._min_interval = max(0, min_interval_ms) / 1000
        self._slots = asyncio.Semaphore(self._max_concurrent)
        self._turnstile = asyncio.Lock()
        self._next_launch = 0.0
        self._running = 0
        self.peak_running = 0

    @property
    def max_concurrent(self) -> int:
        return self._max_concurrent

    async def submit(self, run: Callable[[], Awaitable[T]]) -> T:
        """Run ``run`` once a slot is free, then release the slot."""

        await self._slots.acquire()
        try:
            await self._space_out()
            self._running += 1
            self.peak_running = max(self.peak_running, self._running)
            try:
                return await run()
            finally:
                self._running -= 1
        finally:
            self._slots.release()

    async def _space_out(self) -> None:
        if self._min_interval <= 0:
            return
        async with self._turnstile:
            now = monotonic()
            delay = self._next_launch - now
            if delay > 0:
                await asyncio.sleep(delay)
                now = monotonic()
            self._next_launch = now + self._min_interval
