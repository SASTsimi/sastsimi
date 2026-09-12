"""Explicit opt-in smoke test for a locally authenticated official Codex CLI."""

import json
import os
from pathlib import Path

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.providers.base import CodexProcessRequest
from sastsimi.providers.codex_subscription import (
    ApprovedCodexExecutable,
    CodexCliProcessRunner,
)

_LIVE_ENABLED = os.environ.get("SASTSIMI_CODEX_LIVE") == "1"
pytestmark = pytest.mark.skipif(
    not _LIVE_ENABLED,
    reason="set SASTSIMI_CODEX_LIVE=1 for the credential-safe live probe",
)


@pytest.mark.asyncio
async def test_logged_in_chatgpt_session_can_return_one_structured_result() -> None:
    executable_value = os.environ.get("SASTSIMI_CODEX_LIVE_EXECUTABLE")
    executable_digest = os.environ.get("SASTSIMI_CODEX_LIVE_EXECUTABLE_SHA256")
    model = os.environ.get("SASTSIMI_CODEX_LIVE_MODEL")
    assert executable_value and executable_digest and model
    executable = Path(executable_value).resolve()
    codex_home = Path(
        os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))
    ).resolve()
    runner = CodexCliProcessRunner(
        executable=ApprovedCodexExecutable(
            path=executable,
            sha256=executable_digest.lower(),
        ),
        codex_home=codex_home,
    )
    schema = {
        "type": "object",
        "properties": {"status": {"type": "string", "const": "ok"}},
        "required": ["status"],
        "additionalProperties": False,
    }

    result = await runner.execute(
        CodexProcessRequest(
            invocation_id="codex-live-structured-probe",
            model=model,
            prompt=b'Return exactly one JSON object whose status field is "ok".',
            output_schema=canonical_bytes(schema),
            timeout_ms=120_000,
        )
    )

    assert result.status == "SUCCEEDED"
    assert result.final_message is not None
    assert json.loads(result.final_message) == {"status": "ok"}
    assert result.provider_session_id
