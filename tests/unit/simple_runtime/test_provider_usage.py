from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import openai
import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.providers.base import CodexProcessResult
from sastsimi.simple_runtime.provider import (
    SimpleCodexClient,
    SimpleLLMCallResult,
    SimpleOpenAIClient,
)
from tests.contract.domain.fixtures import ref


@pytest.mark.asyncio
async def test_codex_client_preserves_runner_token_usage() -> None:
    class Runner:
        async def execute(self, _request: object) -> CodexProcessResult:
            return CodexProcessResult(
                "SUCCEEDED",
                b'{"ok":true}',
                "thread-1",
                input_tokens=12,
                output_tokens=5,
            )

    client = SimpleCodexClient(
        runner=Runner(),
        provider_profile_ref=StoredDataRef.model_validate(ref("provider_profile")),
        model="test-model",
    )

    result = await client.call(prompt=b"safe", output_schema={}, timeout_ms=1000)

    assert isinstance(result, SimpleLLMCallResult)
    assert (result.input_tokens, result.output_tokens) == (12, 5)
    assert result.cost_minor_units is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("usage", "expected"),
    [
        (SimpleNamespace(input_tokens=12, output_tokens=5, total_tokens=17), (12, 5)),
        (
            SimpleNamespace(input_tokens=12, output_tokens=5, total_tokens=99),
            (None, None),
        ),
    ],
)
async def test_openai_client_preserves_only_valid_response_token_usage(
    monkeypatch: pytest.MonkeyPatch,
    usage: object,
    expected: tuple[int | None, int | None],
) -> None:
    class Responses:
        async def create(self, **_kwargs: Any) -> object:
            return SimpleNamespace(output_text='{"ok":true}', usage=usage)

    class FakeOpenAI:
        def __init__(self, **_kwargs: Any) -> None:
            self.responses = Responses()

        async def __aenter__(self) -> FakeOpenAI:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

    monkeypatch.setenv("SASTSIMI_TEST_OPENAI_KEY", "test-key")
    monkeypatch.setattr(openai, "AsyncOpenAI", FakeOpenAI)
    client = SimpleOpenAIClient(
        credential_ref="env:SASTSIMI_TEST_OPENAI_KEY", model="test-model"
    )

    result = await client.call(prompt=b"safe", output_schema={}, timeout_ms=1000)

    assert isinstance(result, SimpleLLMCallResult)
    assert (result.input_tokens, result.output_tokens) == expected
    assert result.cost_minor_units is None
