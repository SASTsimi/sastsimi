from __future__ import annotations

import hashlib
import json
from pathlib import Path

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


class _ResultRunner:
    def __init__(self, result: CodexProcessResult) -> None:
        self.result = result

    async def execute(self, _request: CodexProcessRequest) -> CodexProcessResult:
        return self.result


@pytest.mark.asyncio
async def test_codex_call_persists_redacted_request_and_response(
    tmp_path: Path,
) -> None:
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("raw", "secret"),
    [
        (b'{"decision":"api_key=do-not-store","details":', "do-not-store"),
        (b'{"api_key": "SYNTHETIC_SECRET"', "SYNTHETIC_SECRET"),
    ],
)
async def test_malformed_codex_output_records_metadata_without_response_text(
    tmp_path: Path,
    raw: bytes,
    secret: str,
) -> None:
    artifacts = SimpleArtifactRepository(
        tmp_path,
        CheckpointIdentity(
            analysis_id="analysis-invalid",
            workspace_id="workspace-invalid",
            commit_id="commit-invalid",
            hypothesis_id=None,
        ),
    )
    profile = artifacts.put_json({"kind": "provider_profile"})
    client = SimpleCodexClient(
        runner=_ResultRunner(CodexProcessResult("SUCCEEDED", raw, None)),
        provider_profile_ref=profile,
        model="gpt-test",
        artifacts=artifacts,
    )

    result = await client.call(
        prompt=b"repo code and api_key=prompt-secret",
        output_schema={"type": "object"},
        timeout_ms=1000,
    )

    assert isinstance(result, StageFailure)
    assert result.code == "INVALID_OUTPUT"
    assert result.retryable
    assert len(result.evidence_refs) == 2
    request = json.loads(artifacts.read(result.evidence_refs[0]))
    diagnostic = json.loads(artifacts.read(result.evidence_refs[1]))
    assert request["kind"] == "simple_llm_request"
    assert diagnostic["kind"] == "simple_llm_invalid_output"
    assert diagnostic["category"] == "json_malformed"
    assert diagnostic["diagnostic_source"] == "final_message"
    assert diagnostic["diagnostic_sha256"] == hashlib.sha256(raw).hexdigest()
    assert diagnostic["request_ref"] == result.evidence_refs[0].model_dump(mode="json")
    assert "response_excerpt" not in diagnostic
    assert "response_excerpt_source" not in diagnostic
    assert secret not in json.dumps(diagnostic)
    assert "prompt-secret" not in json.dumps(diagnostic)


@pytest.mark.asyncio
async def test_codex_schema_mismatch_records_field_without_unredacted_output(
    tmp_path: Path,
) -> None:
    unlabelled_secret = "zephyr79-kiwi64-opal33"
    raw = b'{"decision":12,"details":"zephyr79-kiwi64-opal33","api_key":"do-not-store"}'
    artifacts = SimpleArtifactRepository(
        tmp_path,
        CheckpointIdentity(
            analysis_id="analysis-schema",
            workspace_id="workspace-schema",
            commit_id="commit-schema",
            hypothesis_id=None,
        ),
    )
    client = SimpleCodexClient(
        runner=_ResultRunner(CodexProcessResult("SUCCEEDED", raw, None)),
        provider_profile_ref=artifacts.put_json({"kind": "provider_profile"}),
        model="gpt-test",
        artifacts=artifacts,
    )

    result = await client.call(
        prompt=b"safe",
        output_schema={
            "type": "object",
            "properties": {"decision": {"type": "string"}},
            "required": ["decision"],
        },
        timeout_ms=1000,
    )

    assert isinstance(result, StageFailure)
    assert result.retryable
    assert result.invalid_field == "$.decision"
    diagnostic = json.loads(artifacts.read(result.evidence_refs[-1]))
    assert diagnostic["category"] == "schema_mismatch"
    assert diagnostic["diagnostic_source"] == "final_message"
    assert diagnostic["diagnostic_sha256"] == hashlib.sha256(raw).hexdigest()
    assert diagnostic["request_ref"] == result.evidence_refs[0].model_dump(mode="json")
    assert diagnostic["invalid_field"] == "$.decision"
    assert unlabelled_secret not in json.dumps(diagnostic)
    assert "response_excerpt" not in diagnostic
    assert "do-not-store" not in json.dumps(diagnostic)


@pytest.mark.asyncio
async def test_schema_mismatch_category_survives_unsafe_field_path(
    tmp_path: Path,
) -> None:
    artifacts = SimpleArtifactRepository(
        tmp_path,
        CheckpointIdentity(
            analysis_id="analysis-unsafe-field",
            workspace_id="workspace-unsafe-field",
            commit_id="commit-unsafe-field",
            hypothesis_id=None,
        ),
    )
    client = SimpleCodexClient(
        runner=_ResultRunner(CodexProcessResult("SUCCEEDED", b'{"foo-bar":12}', None)),
        provider_profile_ref=artifacts.put_json({"kind": "provider_profile"}),
        model="gpt-test",
        artifacts=artifacts,
    )

    result = await client.call(
        prompt=b"safe",
        output_schema={
            "type": "object",
            "properties": {"foo-bar": {"type": "string"}},
        },
        timeout_ms=1000,
    )

    assert isinstance(result, StageFailure)
    assert result.invalid_field is None
    diagnostic = json.loads(artifacts.read(result.evidence_refs[-1]))
    assert diagnostic["category"] == "schema_mismatch"
    assert diagnostic["invalid_field"] is None


@pytest.mark.asyncio
async def test_codex_extra_property_name_never_becomes_invalid_field(
    tmp_path: Path,
) -> None:
    unlabelled_secret = "zephyr79Kiwi64Opal33"
    raw = b'{"zephyr79Kiwi64Opal33":1}'
    artifacts = SimpleArtifactRepository(
        tmp_path,
        CheckpointIdentity(
            analysis_id="analysis-extra-key",
            workspace_id="workspace-extra-key",
            commit_id="commit-extra-key",
            hypothesis_id=None,
        ),
    )
    client = SimpleCodexClient(
        runner=_ResultRunner(CodexProcessResult("SUCCEEDED", raw, None)),
        provider_profile_ref=artifacts.put_json({"kind": "provider_profile"}),
        model="gpt-test",
        artifacts=artifacts,
    )

    result = await client.call(
        prompt=b"safe",
        output_schema={
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
        timeout_ms=1000,
    )

    assert isinstance(result, StageFailure)
    assert result.code == "INVALID_OUTPUT"
    diagnostic = json.loads(artifacts.read(result.evidence_refs[-1]))
    assert diagnostic["category"] == "schema_mismatch"
    assert diagnostic["diagnostic_sha256"] == hashlib.sha256(raw).hexdigest()
    assert unlabelled_secret not in json.dumps(diagnostic)
    assert diagnostic["invalid_field"] is None
    assert result.invalid_field is None


@pytest.mark.asyncio
async def test_runner_invalid_output_category_is_persisted_without_raw_message(
    tmp_path: Path,
) -> None:
    artifacts = SimpleArtifactRepository(
        tmp_path,
        CheckpointIdentity(
            analysis_id="analysis-process",
            workspace_id="workspace-process",
            commit_id="commit-process",
            hypothesis_id=None,
        ),
    )
    client = SimpleCodexClient(
        runner=_ResultRunner(
            CodexProcessResult(
                "INVALID_OUTPUT",
                None,
                None,
                invalid_output_category="event_stream_invalid",
                invalid_output_sha256="a" * 64,
                invalid_output_source="event_stream",
            )
        ),
        provider_profile_ref=artifacts.put_json({"kind": "provider_profile"}),
        model="gpt-test",
        artifacts=artifacts,
    )

    result = await client.call(prompt=b"safe", output_schema={}, timeout_ms=1000)

    assert isinstance(result, StageFailure)
    assert result.retryable
    assert len(result.evidence_refs) == 2
    diagnostic = json.loads(artifacts.read(result.evidence_refs[-1]))
    assert diagnostic["category"] == "event_stream_invalid"
    assert diagnostic["diagnostic_source"] == "event_stream"
    assert diagnostic["diagnostic_sha256"] == "a" * 64
    assert "response_excerpt" not in diagnostic
    assert "response_excerpt_source" not in diagnostic
