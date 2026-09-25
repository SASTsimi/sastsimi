from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sastsimi.config.user_config import SimpleToolBinding
from sastsimi.simple_runtime.claude_provider import (
    ClaudeBoundaryError,
    ClaudeCLIResponse,
    OfficialClaudeCLITransport,
)


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
        },
    ]
    return b"\n".join(json.dumps(event).encode() for event in events) + b"\n"


@pytest.mark.asyncio
async def test_claude_cli_uses_no_tools_and_stdin_only(tmp_path: Path) -> None:
    calls: list[tuple[tuple[str, ...], bytes | None, dict[str, str]]] = []

    async def fake_runner(argv, *, stdin, cwd, env, timeout):
        calls.append((argv, stdin, env))
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
    async def fake_runner(argv, *, stdin, cwd, env, timeout):
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
