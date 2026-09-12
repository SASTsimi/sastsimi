"""Explicit opt-in smoke test for a locally authenticated official Codex CLI."""

import json
import os
from pathlib import Path
from typing import cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import (
    ClientExecutionProfile,
    Environment,
    ProviderProfile,
)
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.providers.base import CodexProcessRequest
from sastsimi.providers.codex_subscription import (
    ApprovedCodexExecutable,
    ApprovedCodexExecutionBinding,
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
    provider_profile_value = os.environ.get("SASTSIMI_CODEX_LIVE_PROVIDER_PROFILE_JSON")
    client_profile_value = os.environ.get(
        "SASTSIMI_CODEX_LIVE_CLIENT_EXECUTION_PROFILE_JSON"
    )
    runtime_environment = os.environ.get("SASTSIMI_CODEX_LIVE_ENVIRONMENT")
    assert (
        executable_value
        and executable_digest
        and provider_profile_value
        and client_profile_value
        and runtime_environment
    )
    assert runtime_environment in {
        "PERSONAL_LOCAL",
        "TEAM_LOCAL",
        "PRIVATE_CI",
        "SHARED_SERVER",
    }
    executable = Path(executable_value).resolve()
    provider_profile = ProviderProfile.model_validate_json(
        Path(provider_profile_value).read_bytes()
    )
    client_profile = ClientExecutionProfile.model_validate_json(
        Path(client_profile_value).read_bytes()
    )
    codex_home = Path(
        os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))
    ).resolve()
    runner = CodexCliProcessRunner(
        binding=ApprovedCodexExecutionBinding(
            provider_profile=provider_profile,
            client_execution_profile=client_profile,
            executable=ApprovedCodexExecutable(
                path=executable,
                sha256=executable_digest.lower(),
            ),
            codex_home=codex_home,
            runtime_environment=cast(Environment, runtime_environment),
        ),
    )
    schema = {
        "type": "object",
        "properties": {"status": {"type": "string", "const": "ok"}},
        "required": ["status"],
        "additionalProperties": False,
    }
    provider_profile_ref = reference(provider_profile)
    assert isinstance(provider_profile_ref, StoredDataRef)

    result = await runner.execute(
        CodexProcessRequest(
            invocation_id="codex-live-structured-probe",
            provider_profile_ref=provider_profile_ref,
            model=provider_profile.model,
            prompt=b'Return exactly one JSON object whose status field is "ok".',
            output_schema=canonical_bytes(schema),
            timeout_ms=120_000,
        )
    )

    assert result.status == "SUCCEEDED"
    assert result.final_message is not None
    assert json.loads(result.final_message) == {"status": "ok"}
    assert result.provider_session_id
