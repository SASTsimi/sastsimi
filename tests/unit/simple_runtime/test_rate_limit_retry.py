from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from sastsimi.simple_runtime.models import StageFailure
from sastsimi.simple_runtime.provider import SimpleLLMCallResult, SimpleOpenAIClient
from tests.unit.simple_runtime.test_call_queue import _Client, _success, _wrapper


@pytest.mark.asyncio
async def test_rate_limit_and_transient_server_failures_retry_at_most_three(
    tmp_path: Path,
) -> None:
    sleeps: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)

    inner = _Client(
        [
            StageFailure(code="RATE_LIMITED", retryable=True, safe_message="retry"),
            StageFailure(code="FAILED", retryable=True, safe_message="retry"),
            _success(),
        ]
    )
    result = await _wrapper(
        tmp_path, inner, asyncio.Semaphore(1), sleep=fake_sleep
    ).call(
        prompt=b"safe",
        output_schema={},
        timeout_ms=10_000,
    )
    assert isinstance(result, SimpleLLMCallResult)
    assert inner.calls == 3
    assert sleeps[:2] == [0.5, 1.0]


@pytest.mark.asyncio
async def test_auth_and_model_failures_are_terminal_even_if_marked_retryable(
    tmp_path: Path,
) -> None:
    for code in ("AUTH_REQUIRED", "MODEL_UNAVAILABLE"):
        inner = _Client([StageFailure(code=code, retryable=True, safe_message="no")])
        result = await _wrapper(tmp_path, inner, asyncio.Semaphore(1)).call(
            prompt=b"safe",
            output_schema={},
            timeout_ms=1_000,
        )
        assert isinstance(result, StageFailure)
        assert result.retryable is False
        assert inner.calls == 1


@pytest.mark.asyncio
async def test_missing_openai_credential_is_terminal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SASTSIMI_TEST_OPENAI_KEY", raising=False)
    client = SimpleOpenAIClient(
        credential_ref="env:SASTSIMI_TEST_OPENAI_KEY",
        model="test-model",
    )
    result = await client.call(prompt=b"safe", output_schema={}, timeout_ms=1000)
    assert isinstance(result, StageFailure)
    assert result.code == "AUTH_REQUIRED"
    assert result.retryable is False
