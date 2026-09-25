"""A burst refusal is waited out, not turned into a blocked stage.

The official client was measured returning ``api_error_status: 429`` with the
text "Server is temporarily limiting requests (not your usage limit)" when
several large prompts were sent at once.  That refusal clears on its own, so
the call is retried rather than failed.
"""

from __future__ import annotations

from typing import Any

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.providers.base import CodexProcessRequest, CodexProcessResult
from sastsimi.simple_runtime.call_queue import CallQueue
from sastsimi.simple_runtime.models import StageFailure
from sastsimi.simple_runtime.provider import SimpleClaudeClient

_ANSWER = b'{"answer":"ok"}'


def _ref() -> StoredDataRef:
    return StoredDataRef(
        stored_data_id="c" * 64,
        data_kind="artifact",
        content_hash="c" * 64,
        workspace_id="workspace-1",
        commit_id="a" * 40,
        record_id=None,
    )


class _Runner:
    """Returns each scripted status in turn."""

    def __init__(self, statuses: list[str]) -> None:
        self._statuses = statuses
        self.attempts = 0

    async def execute(self, request: CodexProcessRequest) -> CodexProcessResult:
        status = self._statuses[min(self.attempts, len(self._statuses) - 1)]
        self.attempts += 1
        message = _ANSWER if status == "SUCCEEDED" else None
        return CodexProcessResult(status, message, "session-1")  # type: ignore[arg-type]


def _client(
    runner: _Runner, waits: list[float], **overrides: Any
) -> SimpleClaudeClient:
    async def sleep(seconds: float) -> None:
        waits.append(seconds)

    return SimpleClaudeClient(
        runner=runner,  # type: ignore[arg-type]
        provider_profile_ref=_ref(),
        model="claude-sonnet-5",
        queue=CallQueue(max_concurrent=2),
        sleep=sleep,
        **overrides,
    )


async def _call(client: SimpleClaudeClient) -> Any:
    return await client.call(
        prompt=b"prompt",
        output_schema={
            "type": "object",
            "properties": {"answer": {"type": "string"}},
            "required": ["answer"],
        },
        timeout_ms=60_000,
    )


@pytest.mark.asyncio
async def test_a_burst_refusal_is_waited_out_and_the_answer_still_arrives() -> None:
    runner = _Runner(["RATE_LIMITED", "RATE_LIMITED", "SUCCEEDED"])
    waits: list[float] = []

    result = await _call(_client(runner, waits))

    assert not isinstance(result, StageFailure)
    assert result.value == {"answer": "ok"}
    assert runner.attempts == 3


@pytest.mark.asyncio
async def test_each_wait_is_longer_than_the_one_before() -> None:
    runner = _Runner(["RATE_LIMITED"])
    waits: list[float] = []

    await _call(_client(runner, waits))

    assert waits == sorted(waits)
    assert len(set(waits)) == len(waits)
    assert waits[0] > 0


@pytest.mark.asyncio
async def test_a_refusal_that_never_clears_gives_up_and_says_why() -> None:
    runner = _Runner(["RATE_LIMITED"])
    waits: list[float] = []

    result = await _call(_client(runner, waits, rate_limit_backoff_ms=(1, 2)))

    assert isinstance(result, StageFailure)
    # The stage must learn it was rate limited, not a bare FAILED.
    assert result.code == "RATE_LIMITED"
    assert runner.attempts == 3
    assert waits == [0.001, 0.002]


@pytest.mark.asyncio
async def test_a_call_that_succeeds_first_time_never_waits() -> None:
    runner = _Runner(["SUCCEEDED"])
    waits: list[float] = []

    result = await _call(_client(runner, waits))

    assert not isinstance(result, StageFailure)
    assert runner.attempts == 1
    assert waits == []


@pytest.mark.asyncio
async def test_a_failure_that_is_not_a_burst_refusal_is_not_retried() -> None:
    # An invalid output will be invalid again; only the transient refusal is
    # worth the wall clock of a retry.
    runner = _Runner(["INVALID_OUTPUT"])
    waits: list[float] = []

    result = await _call(_client(runner, waits))

    assert isinstance(result, StageFailure)
    assert runner.attempts == 1
    assert waits == []


class _WindowRunner:
    """Refuses with a window that reopens at a stated time, then succeeds."""

    def __init__(self, reopens_at: int | None, refusals: int = 1) -> None:
        self._reopens_at = reopens_at
        self._refusals = refusals
        self.attempts = 0

    async def execute(self, request: CodexProcessRequest) -> CodexProcessResult:
        self.attempts += 1
        if self.attempts <= self._refusals:
            return CodexProcessResult("RATE_LIMITED", None, None, self._reopens_at)
        return CodexProcessResult("SUCCEEDED", _ANSWER, "session-1")


def _windowed(runner: Any, waits: list[float], now: float) -> SimpleClaudeClient:
    async def sleep(seconds: float) -> None:
        waits.append(seconds)

    return SimpleClaudeClient(
        runner=runner,
        provider_profile_ref=_ref(),
        model="claude-sonnet-5",
        queue=CallQueue(max_concurrent=2),
        sleep=sleep,
        now=lambda: now,
    )


@pytest.mark.asyncio
async def test_a_window_is_waited_out_rather_than_retried_three_times() -> None:
    """Three short retries cannot outlast a window measured at five hours."""

    now = 1_000_000.0
    runner = _WindowRunner(reopens_at=int(now) + 2 * 60 * 60)
    waits: list[float] = []

    result = await _call(_windowed(runner, waits, now))

    assert not isinstance(result, StageFailure)
    assert runner.attempts == 2
    # Waited the stated remainder, not three seconds.
    assert waits == [2 * 60 * 60 + 5]


@pytest.mark.asyncio
async def test_a_window_that_already_reopened_is_retried_at_once() -> None:
    now = 1_000_000.0
    runner = _WindowRunner(reopens_at=int(now) - 30)
    waits: list[float] = []

    result = await _call(_windowed(runner, waits, now))

    assert not isinstance(result, StageFailure)
    assert waits == [0.0]


@pytest.mark.asyncio
async def test_a_wait_longer_than_any_real_window_is_not_waited_for() -> None:
    """Holding the run for a day would be worse than reporting it blocked."""

    now = 1_000_000.0
    runner = _WindowRunner(reopens_at=int(now) + 24 * 60 * 60, refusals=99)
    waits: list[float] = []

    result = await _call(_windowed(runner, waits, now))

    assert isinstance(result, StageFailure)
    assert result.code == "RATE_LIMITED"
    assert waits == []
    assert runner.attempts == 1


@pytest.mark.asyncio
async def test_a_burst_with_no_window_still_uses_the_short_ladder() -> None:
    now = 1_000_000.0
    runner = _WindowRunner(reopens_at=None, refusals=2)
    waits: list[float] = []

    result = await _call(_windowed(runner, waits, now))

    assert not isinstance(result, StageFailure)
    assert waits == [3.0, 12.0]
