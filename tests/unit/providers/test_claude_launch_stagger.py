"""A child process launch waits for the previous one's stagger gap.

The official client races two children that start at the same instant to
refresh the same expired token, and the loser reports "another Claude Code
process is refreshing it".  Spacing launches clears it without serializing
the calls themselves.
"""

from __future__ import annotations

import asyncio

import pytest

from sastsimi.providers.claude_subscription import (
    _LAST_LAUNCH,
    _LAUNCH_STAGGER_SECONDS,
    _stagger_launch,
)


@pytest.fixture(autouse=True)
def _reset_launch_clock() -> None:
    _LAST_LAUNCH[0] = 0.0


@pytest.mark.asyncio
async def test_a_second_launch_waits_out_the_stagger_gap() -> None:
    clock = 100.0
    waited: list[float] = []

    def now() -> float:
        return clock

    async def sleep(seconds: float) -> None:
        nonlocal clock
        waited.append(seconds)
        clock += seconds

    import sastsimi.providers.claude_subscription as module

    original_monotonic = module.monotonic
    original_sleep = asyncio.sleep
    module.monotonic = now  # type: ignore[assignment]
    asyncio.sleep = sleep  # type: ignore[assignment]
    try:
        await _stagger_launch()
        await _stagger_launch()
    finally:
        module.monotonic = original_monotonic  # type: ignore[assignment]
        asyncio.sleep = original_sleep

    assert waited == [_LAUNCH_STAGGER_SECONDS]


@pytest.mark.asyncio
async def test_a_launch_after_the_gap_has_passed_does_not_wait() -> None:
    clock = 100.0

    def now() -> float:
        return clock

    async def sleep(seconds: float) -> None:
        raise AssertionError("should not wait once the gap has already passed")

    import sastsimi.providers.claude_subscription as module

    original_monotonic = module.monotonic
    original_sleep = asyncio.sleep
    module.monotonic = now  # type: ignore[assignment]
    asyncio.sleep = sleep  # type: ignore[assignment]
    try:
        await _stagger_launch()
        clock += _LAUNCH_STAGGER_SECONDS + 1
        await _stagger_launch()
    finally:
        module.monotonic = original_monotonic  # type: ignore[assignment]
        asyncio.sleep = original_sleep
