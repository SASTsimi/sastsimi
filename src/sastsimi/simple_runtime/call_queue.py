"""One queue every agent request passes through.

Each stage used to hold its own ceiling, so a run with six hypotheses could
launch six times the configured number of children at once.  A request is
therefore submitted here instead of started directly: the queue admits them in
arrival order and keeps at most ``max_concurrent`` running.

Spacing launches apart was tried and removed: six large prompts refused at a
1.5 s gap exactly as often as with none, because the server limits what is in
flight, not how fast it arrives.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from typing import TypeVar

T = TypeVar("T")


class CallQueue:
    """Admit agent requests in arrival order, bounded.

    Arrival order comes from ``asyncio.Semaphore``, which wakes the waiter
    that has been queued longest.
    """

    def __init__(self, *, max_concurrent: int = 1) -> None:
        self._max_concurrent = max(1, max_concurrent)
        self._slots = asyncio.Semaphore(self._max_concurrent)
        self._running = 0
        self.peak_running = 0

    @property
    def max_concurrent(self) -> int:
        return self._max_concurrent

    @asynccontextmanager
    async def hold(self) -> AsyncIterator[None]:
        """Keep one slot for as long as a conversation's process is alive.

        A conversation's process exists between its turns too, so its slot is
        held for the whole conversation: otherwise twenty batches would start
        twenty client processes and wait on slots only to send.
        """

        async with self._slots:
            self._running += 1
            self.peak_running = max(self.peak_running, self._running)
            try:
                yield
            finally:
                self._running -= 1

    async def submit(self, run: Callable[[], Awaitable[T]]) -> T:
        """Run ``run`` once a slot is free, then release the slot."""

        async with self._slots:
            self._running += 1
            self.peak_running = max(self.peak_running, self._running)
            try:
                return await run()
            finally:
                self._running -= 1
