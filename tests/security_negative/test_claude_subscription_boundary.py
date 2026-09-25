from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from sastsimi.config.user_config import SimpleToolBinding
from sastsimi.simple_runtime.claude_provider import (
    ClaudeBoundaryError,
    OfficialClaudeCLITransport,
    _child_environment,
    _parse_stream,
    _subscription_status,
)


def _stream(
    *, model: str = "operator-model", extra: list[dict[str, object]] | None = None
) -> bytes:
    init: dict[str, object] = {
        "type": "system",
        "subtype": "init",
        "session_id": "one",
        "tools": ["StructuredOutput"],
        "mcp_servers": [],
        "plugins": [],
        "slash_commands": [],
        "skills": [],
        "apiKeySource": "none",
        "permissionMode": "dontAsk",
        "model": "operator-model",
        "claude_code_version": "2.1.280",
        "agents": ["claude", "Explore", "general-purpose", "Plan"],
    }
    terminal: dict[str, object] = {
        "type": "result",
        "session_id": "one",
        "is_error": False,
        "permission_denials": [],
        "structured_output": {"ok": True},
    }
    return (
        b"\n".join(
            json.dumps(item).encode() for item in [init, *(extra or []), terminal]
        )
        + b"\n"
    )


def test_minimal_environment_drops_api_credentials_and_project_settings(
    tmp_path: Path,
) -> None:
    result = _child_environment(
        tmp_path,
        {
            "ANTHROPIC_API_KEY": "secret",
            "HOME": "C:/untrusted",
            "PATH": "C:/untrusted",
            "CLAUDE_CODE_USE_BEDROCK": "1",
            "SYSTEMROOT": "C:/Windows",
        },
    )
    assert "ANTHROPIC_API_KEY" not in result
    assert "HOME" not in result
    assert "PATH" not in result
    assert "CLAUDE_CODE_USE_BEDROCK" not in result
    assert result["CLAUDE_CODE_MANAGED_SETTINGS_PATH"]
    assert result["SYSTEMROOT"] == "C:/Windows"


@pytest.mark.parametrize(
    "raw",
    [
        b'{"loggedIn":false,"authMethod":"claude.ai","apiProvider":"firstParty","subscriptionType":"pro"}',
        b'{"loggedIn":true,"authMethod":"api_key","apiProvider":"firstParty","subscriptionType":"pro"}',
        b'{"loggedIn":true,"authMethod":"claude.ai","apiProvider":"firstParty","subscriptionType":"pro","apiKeySource":"env"}',
        b'{"loggedIn":true,"loggedIn":true,"authMethod":"claude.ai","apiProvider":"firstParty","subscriptionType":"pro"}',
    ],
)
def test_subscription_status_rejects_api_or_ambiguous_identity(raw: bytes) -> None:
    assert _subscription_status(raw) is False


@pytest.mark.parametrize(
    "extra",
    [
        [
            {
                "type": "assistant",
                "session_id": "one",
                "message": {
                    "model": "operator-model",
                    "content": [{"type": "tool_use", "name": "Read", "id": "call-1"}],
                },
            }
        ],
        [{"type": "system", "session_id": "one", "subtype": "permission_denied"}],
        [
            {
                "type": "assistant",
                "session_id": "other",
                "message": {"model": "operator-model", "content": []},
            }
        ],
        [{"type": "user", "session_id": "one", "message": {"content": []}}],
        [
            {
                "type": "assistant",
                "session_id": "one",
                "message": {
                    "model": "<synthetic>",
                    "content": [{"type": "text", "text": "ok"}],
                },
            }
        ],
    ],
)
def test_event_stream_fails_closed_on_unsafe_events(
    extra: list[dict[str, object]],
) -> None:
    with pytest.raises(ClaudeBoundaryError):
        _parse_stream(_stream(extra=extra), "operator-model")


@pytest.mark.asyncio
async def test_executable_digest_is_rechecked_before_inference(tmp_path: Path) -> None:
    binary = tmp_path / "claude.exe"
    binary.write_bytes(b"first")
    binding = SimpleToolBinding(
        executable_path=binary,
        version="2.1.280",
        executable_sha256=hashlib.sha256(b"first").hexdigest(),
    )
    called = False

    async def fake_runner(
        argv: tuple[str, ...],
        *,
        stdin: bytes | None,
        cwd: Path,
        env: Mapping[str, str],
        timeout: float,
    ) -> tuple[int, bytes, bytes]:
        nonlocal called
        called = True
        return 0, b"", b""

    transport = OfficialClaudeCLITransport(binding, tmp_path, runner=fake_runner)
    binary.write_bytes(b"changed")
    with pytest.raises(ClaudeBoundaryError, match="CLAUDE_CLI_BINDING_CHANGED"):
        await transport.invoke(
            prompt=b"hello",
            output_schema={"type": "object"},
            model="operator-model",
            timeout=10,
        )
    assert called is False
