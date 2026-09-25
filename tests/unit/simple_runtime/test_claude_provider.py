from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from sastsimi.config.user_config import SimpleToolBinding
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.claude_provider import (
    ClaudeBoundaryError,
    ClaudeCLIResponse,
    ClaudeProvider,
    ClaudeTransportError,
    OfficialClaudeCLITransport,
)
from sastsimi.simple_runtime.models import CheckpointIdentity, StageFailure
from sastsimi.simple_runtime.provider import SimpleLLMCallResult


def _binding(tmp_path: Path) -> SimpleToolBinding:
    executable = tmp_path / "claude.exe"
    executable.write_bytes(b"fake executable")
    return SimpleToolBinding(
        executable_path=executable,
        version="2.1.280",
        executable_sha256=hashlib.sha256(b"fake executable").hexdigest(),
    )


def _stream(model: str, *, tools: list[str] | None = None) -> bytes:
    events = [
        {
            "type": "system",
            "subtype": "init",
            "session_id": "session-1",
            "tools": ["StructuredOutput"] if tools is None else tools,
            "mcp_servers": [],
            "plugins": [],
            "slash_commands": [],
            "skills": [],
            "apiKeySource": "none",
            "permissionMode": "dontAsk",
            "model": model,
            "claude_code_version": "2.1.280",
            "agents": ["claude", "Explore", "general-purpose", "Plan"],
        },
        {
            "type": "result",
            "session_id": "session-1",
            "is_error": False,
            "permission_denials": [],
            "structured_output": {"answer": "yes"},
            "total_cost_usd": 0.01,
            "usage": {"input_tokens": 5, "output_tokens": 2},
        },
    ]
    return b"\n".join(json.dumps(event).encode() for event in events) + b"\n"


@pytest.mark.asyncio
async def test_claude_cli_uses_no_tools_and_stdin_only(tmp_path: Path) -> None:
    calls: list[tuple[tuple[str, ...], bytes | None, dict[str, str]]] = []

    async def fake_runner(
        argv: tuple[str, ...],
        *,
        stdin: bytes | None,
        cwd: Path,
        env: Mapping[str, str],
        timeout: float,
    ) -> tuple[int, bytes, bytes]:
        calls.append((argv, stdin, dict(env)))
        if "--version" in argv:
            return 0, b"2.1.280 (Claude Code)\n", b""
        if "auth" in argv:
            return (
                0,
                b'{"loggedIn":true,"authMethod":"claude.ai","apiProvider":"firstParty","subscriptionType":"pro"}',
                b"",
            )
        return 0, _stream("operator-model"), b""

    transport = OfficialClaudeCLITransport(
        _binding(tmp_path), tmp_path / "config", runner=fake_runner
    )
    response = await transport.invoke(
        prompt=b"secret prompt",
        output_schema={
            "type": "object",
            "required": ["answer"],
            "properties": {"answer": {"type": "string"}},
        },
        model="operator-model",
        timeout=10,
    )
    assert isinstance(response, ClaudeCLIResponse)
    assert response.value == {"answer": "yes"}
    assert response.cost_minor_units == 1.0
    assert response.input_tokens == 5
    argv, stdin, env = calls[-1]
    assert stdin == b"secret prompt"
    assert "secret prompt" not in " ".join(argv)
    assert argv[argv.index("--tools") + 1] == ""
    assert "--json-schema" in argv
    assert "ANTHROPIC_API_KEY" not in env
    assert "PATH" not in env
    assert len(calls) == 3


@pytest.mark.asyncio
async def test_claude_cli_rejects_tool_in_effective_init(tmp_path: Path) -> None:
    async def fake_runner(
        argv: tuple[str, ...],
        *,
        stdin: bytes | None,
        cwd: Path,
        env: Mapping[str, str],
        timeout: float,
    ) -> tuple[int, bytes, bytes]:
        if "--version" in argv:
            return 0, b"2.1.280 (Claude Code)\n", b""
        if "auth" in argv:
            return (
                0,
                b'{"loggedIn":true,"authMethod":"claude.ai","apiProvider":"firstParty","subscriptionType":"pro"}',
                b"",
            )
        return 0, _stream("operator-model", tools=["Read", "StructuredOutput"]), b""

    transport = OfficialClaudeCLITransport(
        _binding(tmp_path), tmp_path / "config", runner=fake_runner
    )
    with pytest.raises(ClaudeBoundaryError):
        await transport.invoke(
            prompt=b"hello",
            output_schema={"type": "object"},
            model="operator-model",
            timeout=10,
        )


class FakeTransport:
    def __init__(self, outcomes: list[ClaudeCLIResponse | Exception]) -> None:
        self.outcomes = outcomes
        self.calls: list[tuple[str, bytes]] = []

    async def invoke(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        model: str,
        timeout: float,
    ) -> ClaudeCLIResponse:
        self.calls.append((model, prompt))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


def _provider(
    tmp_path: Path, fake: FakeTransport, *, retries: int = 2
) -> ClaudeProvider:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    return ClaudeProvider(
        artifacts=SimpleArtifactRepository(tmp_path, identity),
        default_model="base-model",
        agent_models={"verification_result": "verification-model"},
        timeout_seconds=5,
        max_retries=retries,
        semaphore=asyncio.Semaphore(1),
        transport=fake,
    )


@pytest.mark.asyncio
async def test_claude_adapter_preserves_schema_model_and_distinct_artifacts(
    tmp_path: Path,
) -> None:
    fake = FakeTransport(
        [
            ClaudeCLIResponse(
                raw_output=b"raw stream",
                value={"verdict": "TRUE"},
                input_tokens=4,
                output_tokens=2,
            )
        ]
    )
    result = await _provider(tmp_path, fake).call(
        prompt=b"Verification Agent prompt",
        output_schema={
            "type": "object",
            "required": ["verdict"],
            "properties": {"verdict": {"type": "string", "enum": ["TRUE", "FALSE"]}},
            "additionalProperties": False,
        },
        timeout_ms=5_000,
        agent_name="verification_result",
    )
    assert isinstance(result, SimpleLLMCallResult)
    assert result.value == {"verdict": "TRUE"}
    assert result.model == "verification-model"
    assert result.raw_output_ref != result.parsed_output_ref
    assert fake.calls == [("verification-model", b"Verification Agent prompt")]
    assert result.input_tokens == 4


@pytest.mark.asyncio
async def test_claude_schema_mismatch_is_retried_then_fails(tmp_path: Path) -> None:
    fake = FakeTransport(
        [
            ClaudeCLIResponse(raw_output=b"first", value={"wrong": True}),
            ClaudeCLIResponse(raw_output=b"second", value={"wrong": True}),
        ]
    )
    result = await _provider(tmp_path, fake, retries=1).call(
        prompt=b"agent prompt",
        output_schema={
            "type": "object",
            "required": ["verdict"],
            "properties": {"verdict": {"type": "string"}},
        },
        timeout_ms=5_000,
        agent_name="verification_result",
    )
    assert isinstance(result, StageFailure)
    assert result.code == "CLAUDE_INVALID_OUTPUT"
    assert len(fake.calls) == 2
    assert b"$.verdict" in fake.calls[1][1]


@pytest.mark.asyncio
async def test_claude_auth_failure_is_not_retried(tmp_path: Path) -> None:
    fake = FakeTransport([ClaudeTransportError("CLAUDE_AUTH_REQUIRED")])
    result = await _provider(tmp_path, fake).call(
        prompt=b"hello", output_schema={"type": "object"}, timeout_ms=5_000
    )
    assert isinstance(result, StageFailure)
    assert result.code == "CLAUDE_AUTH_REQUIRED"
    assert len(fake.calls) == 1


@pytest.mark.asyncio
async def test_claude_rate_limit_retries_once_then_succeeds(tmp_path: Path) -> None:
    fake = FakeTransport(
        [
            ClaudeTransportError("CLAUDE_RATE_LIMITED", retryable=True),
            ClaudeCLIResponse(raw_output=b"response", value={"ok": True}),
        ]
    )
    result = await _provider(tmp_path, fake, retries=1).call(
        prompt=b"agent prompt",
        output_schema={
            "type": "object",
            "required": ["ok"],
            "properties": {"ok": {"type": "boolean"}},
        },
        timeout_ms=5_000,
    )
    assert isinstance(result, SimpleLLMCallResult)
    assert len(fake.calls) == 2
