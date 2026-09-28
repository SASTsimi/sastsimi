from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.cursor_provider import (
    CursorCLIRateLimitError,
    CursorModelCatalog,
    CursorProvider,
    OfficialCursorCLITransport,
)
from sastsimi.simple_runtime.models import CheckpointIdentity, StageFailure
from sastsimi.simple_runtime.provider import SimpleLLMCallResult


class RateLimitError(Exception):
    pass


class AuthenticationError(Exception):
    pass


class FakeTransport:
    def __init__(
        self, outcomes: list[str | BaseException], models: set[str] | None = None
    ):
        self.outcomes = outcomes
        self.models = models or {"available-model", "verification-model"}
        self.calls: list[tuple[str, str]] = []
        self.list_calls = 0

    async def list_models(self, api_key: str) -> set[str]:
        assert api_key in {"", "test-key"}
        self.list_calls += 1
        return self.models

    async def complete(
        self, *, api_key: str, model: str, prompt: str, timeout: float
    ) -> tuple[str, dict[str, int | float | None]]:
        assert api_key in {"", "test-key"}
        self.calls.append((model, prompt))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome, {"input_tokens": 12, "output_tokens": 3}


def provider(
    tmp_path: Path,
    transport: FakeTransport,
    *,
    max_retries: int = 2,
    allow_on_demand: bool = True,
    agent_models: Mapping[str, str] | None = None,
    use_cli_login: bool = False,
    model_catalog: CursorModelCatalog | None = None,
    budget_check: Callable[[], StageFailure | None] | None = None,
) -> CursorProvider:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    return CursorProvider(
        artifacts=SimpleArtifactRepository(tmp_path, identity),
        default_model="available-model",
        agent_models=agent_models or {},
        timeout_seconds=5,
        max_retries=max_retries,
        semaphore=asyncio.Semaphore(1),
        allow_on_demand=allow_on_demand,
        transport=transport,
        use_cli_login=use_cli_login,
        model_catalog=model_catalog,
        budget_check=budget_check,
    )


SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"verdict": {"type": "string", "enum": ["TRUE", "FALSE"]}},
    "required": ["verdict"],
    "additionalProperties": False,
}


async def call(client: CursorProvider) -> SimpleLLMCallResult | StageFailure:
    return await client.call(
        prompt=b"You are the Verification Agent.",
        output_schema=SCHEMA,
        timeout_ms=5_000,
        agent_name="verification_result",
    )


@pytest.mark.asyncio
async def test_valid_json_and_separate_raw_parsed_artifacts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("CURSOR_API_KEY", "test-key")
    fake = FakeTransport(['{"verdict":"TRUE"}'])
    client = provider(
        tmp_path, fake, agent_models={"verification_result": "verification-model"}
    )
    result = await call(client)
    assert isinstance(result, SimpleLLMCallResult)
    assert result.value == {"verdict": "TRUE"}
    assert result.model == "verification-model"
    assert result.raw_output_ref != result.parsed_output_ref
    assert result.input_tokens == 12
    assert result.on_demand_possible
    with sqlite3.connect(tmp_path / "db" / "sastsimi.sqlite3") as connection:
        attempt = connection.execute(
            "SELECT input_tokens, output_tokens, status, artifact_ref_json "
            "FROM simple_llm_attempts WHERE analysis_id = ?",
            ("analysis-1",),
        ).fetchone()
    assert attempt is not None
    assert attempt[:3] == (12, 3, "SUCCEEDED")
    assert "content_hash" in attempt[3]


@pytest.mark.asyncio
async def test_code_fence_is_unwrapped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("CURSOR_API_KEY", "test-key")
    result = await call(
        provider(tmp_path, FakeTransport(['```json\n{"verdict":"FALSE"}\n```']))
    )
    assert isinstance(result, SimpleLLMCallResult)
    assert result.value["verdict"] == "FALSE"


@pytest.mark.asyncio
async def test_invalid_json_and_schema_get_bounded_reprompt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("CURSOR_API_KEY", "test-key")
    fake = FakeTransport(["not json", '{"verdict":"MAYBE"}', '{"verdict":"TRUE"}'])
    result = await call(provider(tmp_path, fake))
    assert isinstance(result, SimpleLLMCallResult)
    assert len(fake.calls) == 3
    assert "validation" in fake.calls[1][1]
    assert '"required"' in fake.calls[1][1]


@pytest.mark.asyncio
async def test_invalid_output_exhaustion_is_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("CURSOR_API_KEY", "test-key")
    fake = FakeTransport(["not json", "still not json"])
    result = await call(provider(tmp_path, fake, max_retries=1))
    assert isinstance(result, StageFailure)
    assert result.code == "CURSOR_INVALID_OUTPUT"
    assert len(fake.calls) == 2
    with sqlite3.connect(tmp_path / "db" / "sastsimi.sqlite3") as connection:
        attempts = connection.execute(
            "SELECT COUNT(*) FROM simple_llm_attempts WHERE analysis_id = ?",
            ("analysis-1",),
        ).fetchone()
    assert attempts == (2,)


@pytest.mark.asyncio
async def test_rate_limit_retries_but_auth_does_not(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("CURSOR_API_KEY", "test-key")
    limited = FakeTransport([RateLimitError(), '{"verdict":"TRUE"}'])
    result = await call(provider(tmp_path, limited))
    assert isinstance(result, SimpleLLMCallResult)
    assert len(limited.calls) == 2
    auth = FakeTransport([AuthenticationError()])
    result = await call(provider(tmp_path, auth))
    assert isinstance(result, StageFailure)
    assert result.code == "CURSOR_AUTH_FAILED"
    assert len(auth.calls) == 1


@pytest.mark.asyncio
async def test_missing_model_and_on_demand_guard(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("CURSOR_API_KEY", "test-key")
    fake = FakeTransport([], models={"other-model"})
    result = await call(provider(tmp_path, fake))
    assert isinstance(result, StageFailure)
    assert result.code == "CURSOR_MODEL_UNAVAILABLE"
    assert not fake.calls
    result = await call(provider(tmp_path, fake, allow_on_demand=False))
    assert isinstance(result, StageFailure)
    assert result.code == "CURSOR_ON_DEMAND_CONTROL_UNAVAILABLE"


@pytest.mark.asyncio
async def test_cursor_budget_blocks_completion_before_charging(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("CURSOR_API_KEY", "test-key")
    fake = FakeTransport(['{"verdict":"TRUE"}'])
    blocked = StageFailure(
        code="LLM_COST_BUDGET_EXHAUSTED",
        retryable=False,
        safe_message="limit",
    )
    result = await call(provider(tmp_path, fake, budget_check=lambda: blocked))
    assert isinstance(result, StageFailure)
    assert result.code == "LLM_COST_BUDGET_EXHAUSTED"
    assert fake.calls == []


@pytest.mark.asyncio
async def test_timeout_is_bounded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("CURSOR_API_KEY", "test-key")
    fake = FakeTransport([TimeoutError()])
    result = await call(provider(tmp_path, fake, max_retries=0))
    assert isinstance(result, StageFailure)
    assert result.code == "CURSOR_TIMED_OUT"


@pytest.mark.asyncio
async def test_cli_login_needs_no_api_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("CURSOR_API_KEY", raising=False)
    result = await call(
        provider(
            tmp_path,
            FakeTransport(['{"verdict":"TRUE"}']),
            use_cli_login=True,
        )
    )
    assert isinstance(result, SimpleLLMCallResult)
    assert result.provider == "cursor-cli"


@pytest.mark.asyncio
async def test_model_catalog_is_shared_between_agents(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("CURSOR_API_KEY", "test-key")
    fake = FakeTransport(['{"verdict":"TRUE"}', '{"verdict":"FALSE"}'])
    catalog = CursorModelCatalog()
    assert isinstance(
        await call(provider(tmp_path, fake, model_catalog=catalog)),
        SimpleLLMCallResult,
    )
    assert isinstance(
        await call(provider(tmp_path, fake, model_catalog=catalog)),
        SimpleLLMCallResult,
    )
    assert fake.list_calls == 1


@pytest.mark.asyncio
async def test_cli_transport_parses_only_verified_catalog_and_json_envelope(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    native = tmp_path / "node.exe"
    native.write_bytes(b"test")
    (tmp_path / "index.js").write_bytes(b"test")
    calls: list[tuple[str, ...]] = []

    class Process:
        returncode = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            if len(calls) == 1:
                return b"Available models\nauto - Auto\ncomposer-2.5 - Composer\n", b""
            return (
                b'{"type":"result","subtype":"success","is_error":false,'
                b'"result":"{\\"verdict\\":\\"TRUE\\"}"}',
                b"",
            )

    async def fake_subprocess(*args: str, **kwargs: Any) -> Process:
        assert kwargs["cwd"] != str(tmp_path)
        assert "CURSOR_API_KEY" not in kwargs["env"]
        calls.append(args)
        return Process()

    monkeypatch.setenv("CURSOR_API_KEY", "must-not-leak")
    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_subprocess)
    transport = OfficialCursorCLITransport(str(native))
    assert await transport.list_models("") == {"auto", "composer-2.5"}
    raw, usage = await transport.complete(
        api_key="", model="composer-2.5", prompt="test prompt", timeout=5
    )
    assert raw == '{"verdict":"TRUE"}'
    assert usage == {}
    assert calls[1][:2] == (str(native), str(tmp_path / "index.js"))
    assert "--mode" in calls[1] and "ask" in calls[1]
    assert "--trust" in calls[1]


@pytest.mark.asyncio
async def test_cli_transport_classifies_rate_limit_without_leaking_stderr(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    native = tmp_path / "node.exe"
    native.write_bytes(b"test")
    (tmp_path / "index.js").write_bytes(b"test")

    class Process:
        returncode = 1

        async def communicate(self) -> tuple[bytes, bytes]:
            return b"", b"429 rate limit for account@example.test"

    async def fake_subprocess(*_args: str, **_kwargs: Any) -> Process:
        return Process()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_subprocess)
    with pytest.raises(CursorCLIRateLimitError):
        await OfficialCursorCLITransport(str(native)).list_models("")
