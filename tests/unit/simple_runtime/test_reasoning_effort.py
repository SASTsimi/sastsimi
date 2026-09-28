from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from sastsimi.config.user_config import SimpleToolBinding
from sastsimi.providers.base import CodexProcessRequest, CodexProcessResult
from sastsimi.providers.codex_subscription import CodexCliProcessRunner
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.claude_provider import OfficialClaudeCLITransport
from sastsimi.simple_runtime.cursor_provider import (
    CursorModelCapability,
    CursorProvider,
)
from sastsimi.simple_runtime.models import CheckpointIdentity, StageFailure
from sastsimi.simple_runtime.provider import (
    SimpleCodexClient,
    SimpleLLMCallResult,
    SimpleOpenAIClient,
)
from sastsimi.simple_runtime.reasoning import validate_reasoning_effort

SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"answer": {"type": "string"}},
    "required": ["answer"],
    "additionalProperties": False,
}


def test_unsupported_effort_nonretryable() -> None:
    assert (
        validate_reasoning_effort(
            "cursor-cli", "account-model", None, supported_levels=None
        )
        is None
    )
    failure = validate_reasoning_effort(
        "cursor-cli", "account-model", "high", supported_levels=None
    )
    assert isinstance(failure, StageFailure)
    assert failure.code == "REASONING_EFFORT_UNSUPPORTED"
    assert failure.retryable is False


class _Runner:
    def __init__(self) -> None:
        self.requests: list[CodexProcessRequest] = []

    async def execute(self, request: CodexProcessRequest) -> CodexProcessResult:
        self.requests.append(request)
        return CodexProcessResult(
            status="SUCCEEDED",
            final_message=b'{"answer":"yes"}',
            provider_session_id=None,
        )


@pytest.mark.asyncio
async def test_unset_effort_preserves_request(tmp_path: Path) -> None:
    from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
    from sastsimi.simple_runtime.models import CheckpointIdentity

    artifacts = SimpleArtifactRepository(
        tmp_path,
        CheckpointIdentity(
            analysis_id="analysis-1",
            workspace_id="workspace-1",
            commit_id="a" * 40,
            hypothesis_id="hypothesis-1",
        ),
    )
    runner = _Runner()
    client = SimpleCodexClient(
        runner=runner,
        provider_profile_ref=artifacts.put_json({"kind": "profile"}),
        model="gpt-test",
        artifacts=artifacts,
    )
    result = await client.call(
        prompt=b"secret prompt", output_schema=SCHEMA, timeout_ms=1000
    )
    assert isinstance(result, SimpleLLMCallResult)
    assert runner.requests[0].reasoning_effort is None


@pytest.mark.asyncio
async def test_codex_official_override(tmp_path: Path) -> None:
    from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
    from sastsimi.simple_runtime.models import CheckpointIdentity

    artifacts = SimpleArtifactRepository(
        tmp_path,
        CheckpointIdentity(
            analysis_id="analysis-1",
            workspace_id="workspace-1",
            commit_id="a" * 40,
            hypothesis_id="hypothesis-1",
        ),
    )
    runner = _Runner()
    client = SimpleCodexClient(
        runner=runner,
        provider_profile_ref=artifacts.put_json({"kind": "profile"}),
        model="gpt-test",
        artifacts=artifacts,
        reasoning_effort="medium",
        agent_reasoning_efforts={"verification_result": "high"},
    )
    result = await client.call(
        prompt=b"secret prompt",
        output_schema=SCHEMA,
        timeout_ms=1000,
        agent_name="verification_result",
    )
    assert isinstance(result, SimpleLLMCallResult)
    assert runner.requests[0].reasoning_effort == "high"


@pytest.mark.asyncio
async def test_codex_reasoning_cli_rejection_is_terminal(tmp_path: Path) -> None:
    class _RejectedRunner:
        def __init__(self) -> None:
            self.calls = 0

        async def execute(self, _request: CodexProcessRequest) -> CodexProcessResult:
            self.calls += 1
            return CodexProcessResult(
                status="FAILED", final_message=None, provider_session_id=None
            )

    artifacts = SimpleArtifactRepository(
        tmp_path,
        CheckpointIdentity(
            analysis_id="analysis-1",
            workspace_id="workspace-1",
            commit_id="a" * 40,
            hypothesis_id="hypothesis-1",
        ),
    )
    runner = _RejectedRunner()
    client = SimpleCodexClient(
        runner=runner,
        provider_profile_ref=artifacts.put_json({"kind": "profile"}),
        model="gpt-test",
        reasoning_effort="high",
    )
    failure = await client.call(
        prompt=b"secret prompt", output_schema=SCHEMA, timeout_ms=1000
    )
    assert isinstance(failure, StageFailure)
    assert failure.code == "CODEX_REASONING_REQUEST_FAILED"
    assert failure.retryable is False
    assert runner.calls == 1


@pytest.mark.asyncio
async def test_openai_responses_effort(monkeypatch: pytest.MonkeyPatch) -> None:
    import openai

    captured: dict[str, Any] = {}

    class _Responses:
        async def create(self, **kwargs: Any) -> Any:
            captured.update(kwargs)
            return type(
                "Response",
                (),
                {"output_text": json.dumps({"answer": "yes"}), "usage": None},
            )()

    class _Client:
        def __init__(self, **_kwargs: Any) -> None:
            self.responses = _Responses()

        async def __aenter__(self) -> _Client:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

    monkeypatch.setenv("SASTSIMI_TEST_OPENAI_KEY", "test-key")
    monkeypatch.setattr(openai, "AsyncOpenAI", _Client)
    client = SimpleOpenAIClient(
        credential_ref="env:SASTSIMI_TEST_OPENAI_KEY",
        model="gpt-test",
        reasoning_effort="medium",
        agent_reasoning_efforts={"verification_result": "high"},
    )
    result = await client.call(
        prompt=b"secret prompt",
        output_schema=SCHEMA,
        timeout_ms=1000,
        agent_name="verification_result",
    )
    assert isinstance(result, SimpleLLMCallResult)
    assert captured["reasoning"] == {"effort": "high"}
    assert "secret prompt" not in str(captured["reasoning"])


def test_codex_argv_uses_official_config_key(tmp_path: Path) -> None:
    runner = object.__new__(CodexCliProcessRunner)
    runner.executable = type("Executable", (), {"path": tmp_path / "codex.exe"})()
    request = CodexProcessRequest(
        invocation_id="invocation-1",
        provider_profile_ref=SimpleArtifactRepository(
            tmp_path,
            CheckpointIdentity(
                analysis_id="analysis-1",
                workspace_id="workspace-1",
                commit_id="a" * 40,
                hypothesis_id="hypothesis-1",
            ),
        ).put_json({"kind": "profile"}),
        model="gpt-test",
        prompt=b"secret prompt",
        output_schema=b"{}",
        timeout_ms=1000,
        reasoning_effort="high",
    )
    argv = runner.execution_argv(
        request, tmp_path, tmp_path / "schema.json", tmp_path / "out.json"
    )
    assert 'model_reasoning_effort="high"' in argv
    assert "secret prompt" not in " ".join(argv)


@pytest.mark.asyncio
async def test_claude_child_env(tmp_path: Path) -> None:
    captured: list[dict[str, str]] = []

    async def fake_runner(
        argv: tuple[str, ...],
        *,
        stdin: bytes | None,
        cwd: Path,
        env: Mapping[str, str],
        timeout: float,
    ) -> tuple[int, bytes, bytes]:
        captured.append(dict(env))
        if "--version" in argv:
            return 0, b"2.1.280 (Claude Code)\n", b""
        if "auth" in argv:
            return (
                0,
                b'{"loggedIn":true,"authMethod":"claude.ai","apiProvider":"firstParty","subscriptionType":"pro"}',
                b"",
            )
        from tests.unit.simple_runtime.test_claude_provider import _stream

        return 0, _stream("operator-model"), b""

    executable = tmp_path / "claude.exe"
    executable.write_bytes(b"fake executable")
    transport = OfficialClaudeCLITransport(
        SimpleToolBinding(
            executable_path=executable,
            version="2.1.280",
            executable_sha256=hashlib.sha256(b"fake executable").hexdigest(),
        ),
        tmp_path / "config",
        runner=fake_runner,
    )
    await transport.invoke(
        prompt=b"secret prompt",
        output_schema=SCHEMA,
        model="operator-model",
        timeout=10,
        reasoning_effort="high",
    )
    assert captured[-1]["CLAUDE_CODE_EFFORT_LEVEL"] == "high"
    assert "CLAUDE_CODE_EFFORT_LEVEL" not in captured[0]


@pytest.mark.asyncio
async def test_cursor_catalog_parameter(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class _Transport:
        def __init__(self) -> None:
            self.models: list[str | Mapping[str, Any]] = []

        async def list_models(self, _key: str) -> dict[str, CursorModelCapability]:
            return {
                "account-model": CursorModelCapability(
                    parameter_id="account-reasoning",
                    supported_levels=frozenset({"low", "high"}),
                )
            }

        async def complete(
            self,
            *,
            api_key: str,
            model: str | Mapping[str, Any],
            prompt: str,
            timeout: float,
        ) -> tuple[str, dict[str, int | float | None]]:
            self.models.append(model)
            return '{"answer":"yes"}', {}

    monkeypatch.setenv("CURSOR_API_KEY", "test-key")
    transport = _Transport()
    artifacts = SimpleArtifactRepository(
        tmp_path,
        CheckpointIdentity(
            analysis_id="analysis-1",
            workspace_id="workspace-1",
            commit_id="a" * 40,
            hypothesis_id="hypothesis-1",
        ),
    )
    client = CursorProvider(
        artifacts=artifacts,
        default_model="account-model",
        agent_models={},
        timeout_seconds=5,
        max_retries=0,
        semaphore=asyncio.Semaphore(1),
        allow_on_demand=True,
        transport=transport,
        reasoning_effort="high",
    )
    result = await client.call(
        prompt=b"secret prompt", output_schema=SCHEMA, timeout_ms=5000
    )
    assert isinstance(result, SimpleLLMCallResult)
    assert transport.models == [
        {
            "id": "account-model",
            "params": [{"id": "account-reasoning", "value": "high"}],
        }
    ]


@pytest.mark.asyncio
async def test_cursor_cli_rejects_effort(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    class _Transport:
        def __init__(self) -> None:
            self.called = False

        async def list_models(self, _key: str) -> set[str]:
            return {"account-model"}

        async def complete(
            self, **_kwargs: Any
        ) -> tuple[str, dict[str, int | float | None]]:
            self.called = True
            return '{"answer":"yes"}', {}

    monkeypatch.delenv("CURSOR_API_KEY", raising=False)
    transport = _Transport()
    artifacts = SimpleArtifactRepository(
        tmp_path,
        CheckpointIdentity(
            analysis_id="analysis-1",
            workspace_id="workspace-1",
            commit_id="a" * 40,
            hypothesis_id="hypothesis-1",
        ),
    )
    client = CursorProvider(
        artifacts=artifacts,
        default_model="account-model",
        agent_models={},
        timeout_seconds=5,
        max_retries=0,
        semaphore=asyncio.Semaphore(1),
        allow_on_demand=True,
        transport=transport,
        use_cli_login=True,
        reasoning_effort="high",
    )
    result = await client.call(
        prompt=b"secret prompt", output_schema=SCHEMA, timeout_ms=5000
    )
    assert isinstance(result, StageFailure)
    assert result.code == "REASONING_EFFORT_UNSUPPORTED"
    assert result.retryable is False
    assert transport.called is False
