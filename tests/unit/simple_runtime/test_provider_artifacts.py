from __future__ import annotations

import json

import pytest

from sastsimi.providers.base import CodexProcessRequest, CodexProcessResult
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import CheckpointIdentity, StageFailure
from sastsimi.simple_runtime.provider import SimpleCodexClient, SimpleLLMCallResult


class _Runner:
    async def execute(self, _request: CodexProcessRequest) -> CodexProcessResult:
        return CodexProcessResult(
            status="SUCCEEDED",
            final_message=b'{"decision":"accept"}',
            provider_session_id=None,
        )


@pytest.mark.asyncio
async def test_codex_call_persists_redacted_request_and_response(tmp_path) -> None:
    artifacts = SimpleArtifactRepository(
        tmp_path,
        CheckpointIdentity(
            analysis_id="analysis-1",
            workspace_id="workspace-1",
            commit_id="commit-1",
            hypothesis_id="hypothesis-1",
        ),
    )
    profile = artifacts.put_json({"kind": "provider_profile"})
    client = SimpleCodexClient(
        runner=_Runner(),
        provider_profile_ref=profile,
        model="gpt-test",
        artifacts=artifacts,
    )

    result = await client.call(
        prompt=b"api_key=do-not-store",
        output_schema={
            "type": "object",
            "properties": {"decision": {"type": "string"}},
            "required": ["decision"],
            "additionalProperties": False,
        },
        timeout_ms=1000,
    )

    assert isinstance(result, SimpleLLMCallResult)
    assert not isinstance(result, StageFailure)
    assert result.request_ref is not None
    assert result.response_ref is not None
    request = json.loads(artifacts.read(result.request_ref))
    response = json.loads(artifacts.read(result.response_ref))
    assert request["prompt"] == "[REDACTED:CREDENTIAL]"
    assert request["template_revision"] == "simple-runtime-inline-v1"
    assert "do-not-store" not in json.dumps(request)
    assert response["response"] == {"decision": "accept"}
