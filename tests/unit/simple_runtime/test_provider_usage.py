from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import httpx
import openai
import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.providers.base import CodexProcessResult
from sastsimi.simple_runtime.models import StageFailure
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "body", "expected_code", "retryable"),
    [
        (
            400,
            {"code": "context_length_exceeded", "type": "invalid_request_error"},
            "CONTEXT_LIMIT_EXCEEDED",
            False,
        ),
        (
            400,
            {"code": "model_not_found", "type": "invalid_request_error"},
            "MODEL_OR_REQUEST_UNSUPPORTED",
            False,
        ),
        (
            401,
            {"code": "invalid_api_key", "type": "invalid_request_error"},
            "AUTH_REQUIRED",
            False,
        ),
        (
            429,
            {"code": "rate_limit_exceeded", "type": "rate_limit_error"},
            "RATE_LIMITED",
            True,
        ),
    ],
)
async def test_openai_http_errors_distinguish_context_from_model_and_auth(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    body: dict[str, str],
    expected_code: str,
    retryable: bool,
) -> None:
    response = httpx.Response(
        status, request=httpx.Request("POST", "https://api.openai.com/v1/responses")
    )
    error_type = {
        400: openai.BadRequestError,
        401: openai.AuthenticationError,
        429: openai.RateLimitError,
    }[status]
    error = error_type("SECRET_FROM_PROVIDER", response=response, body=body)

    class Responses:
        async def create(self, **_kwargs: Any) -> object:
            raise error

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

    assert isinstance(result, StageFailure)
    assert (result.code, result.retryable) == (expected_code, retryable)
    assert "SECRET_FROM_PROVIDER" not in result.safe_message
