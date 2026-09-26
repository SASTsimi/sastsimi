from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.stages import ReporterStage
from sastsimi.simple_runtime.store import SimpleCheckpointStore


class _ReporterClient:
    async def call(self, **_kwargs: Any) -> SimpleLLMCallResult:
        value = {
            "title": "검증된 명령어 삽입 취약점",
            "summary": "검증되지 않은 입력으로 운영체제 명령을 실행할 수 있습니다.",
            "details": "입력값이 정제되지 않고 명령 실행 함수까지 전달됩니다.",
            "impact": "공격자가 서버 권한으로 임의 명령을 실행할 수 있습니다.",
            "limitations": ["로컬 격리 환경에서만 재현했습니다."],
            "review_items": ["실제 배포 설정에서 동일 경로를 확인해야 합니다."],
        }
        return SimpleLLMCallResult(
            value=value,
            prompt_digest=hashlib.sha256(b"prompt").hexdigest(),
            output_digest=hashlib.sha256(b"output").hexdigest(),
        )


def test_policy_lookup_is_empty_for_a_simple_runtime_database(tmp_path: Path) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")

    refs = SimpleArtifactRepository(tmp_path, identity).published_refs(
        frozenset({"program_policy_record"})
    )

    assert refs == ()


def _checkpoint(
    identity: CheckpointIdentity,
    stage: SimpleStage,
    *,
    outputs=(),
    attempt_id: str | None = None,
    validated_poc_ref=None,
    verdict=None,
    gate_decision=None,
) -> StageCheckpoint:
    return StageCheckpoint(
        identity=identity,
        stage=stage,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=outputs,
        attempt_id=attempt_id,
        validated_poc_ref=validated_poc_ref,
        verdict=verdict,
        gate_decision=gate_decision,
    )


@pytest.mark.asyncio
async def test_restricted_report_contains_exact_validated_poc_and_stable_name(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    script = b"#!/bin/sh\nset -eu\nprintf 'SUPPORTED: command executed\\n'\n"
    content_ref = artifacts.put_bytes(script, "text/x-shellscript")
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "content_ref": content_ref.model_dump(mode="json"),
            "attempt_id": "attempt-1",
        }
    )
    stdout_ref = artifacts.put_bytes(b"SUPPORTED: command executed\n", "text/plain")
    stderr_ref = artifacts.put_bytes(b"", "text/plain")
    execution_ref = artifacts.put_json(
        {
            "kind": "simple_poc_execution",
            "candidate_ref": candidate_ref.model_dump(mode="json"),
            "content_ref": content_ref.model_dump(mode="json"),
            "stdout_ref": stdout_ref.model_dump(mode="json"),
            "stderr_ref": stderr_ref.model_dump(mode="json"),
            "exit_code": 0,
            "timed_out": False,
            "attempt_id": "attempt-1",
        }
    )
    validated_ref = artifacts.put_json(
        {
            "kind": "simple_validated_poc",
            "candidate_ref": candidate_ref.model_dump(mode="json"),
            "content_ref": content_ref.model_dump(mode="json"),
            "execution_ref": execution_ref.model_dump(mode="json"),
            "attempt_id": "attempt-1",
        }
    )
    verification_ref = artifacts.put_json(
        {"result": {"rationale": "Same-attempt evidence supports the finding."}}
    )
    cwe_ref = artifacts.put_json(
        {"result": {"primary_cwe": "CWE-78", "rationale": "명령어 삽입"}}
    )
    technical_ref = artifacts.put_json(
        {"result": {"status": "ACCEPT", "rationale": "근거가 연결되었습니다."}}
    )
    scope_ref = artifacts.put_json(
        {
            "result": {
                "status": "DENY",
                "rationale": "공식 허용 범위를 확인하지 못했습니다.",
                "restrictions": ["외부 제출 금지"],
            }
        }
    )
    finding_ref = artifacts.put_json({"kind": "simple_finding"})
    prior = {
        SimpleStage.POC_CANDIDATE_DONE: _checkpoint(
            identity,
            SimpleStage.POC_CANDIDATE_DONE,
            outputs=(candidate_ref, content_ref),
            attempt_id="attempt-1",
        ),
        SimpleStage.POC_EXECUTION_DONE: _checkpoint(
            identity,
            SimpleStage.POC_EXECUTION_DONE,
            outputs=(execution_ref, validated_ref),
            attempt_id="attempt-1",
            validated_poc_ref=validated_ref,
        ),
        SimpleStage.VERIFICATION_FINAL_DONE: _checkpoint(
            identity,
            SimpleStage.VERIFICATION_FINAL_DONE,
            outputs=(verification_ref,),
            validated_poc_ref=validated_ref,
            verdict="TRUE",
        ),
        SimpleStage.CWE_DONE: _checkpoint(
            identity, SimpleStage.CWE_DONE, outputs=(cwe_ref,)
        ),
        SimpleStage.TECH_GATE_DONE: _checkpoint(
            identity,
            SimpleStage.TECH_GATE_DONE,
            outputs=(technical_ref,),
            gate_decision="ACCEPT",
        ),
        SimpleStage.SCOPE_GATE_DONE: _checkpoint(
            identity, SimpleStage.SCOPE_GATE_DONE, outputs=(scope_ref,)
        ),
        SimpleStage.FINDING_DONE: _checkpoint(
            identity,
            SimpleStage.FINDING_DONE,
            outputs=(finding_ref,),
            validated_poc_ref=validated_ref,
            verdict="TRUE",
        ),
    }
    current = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.REPORT_DONE,
        status=StageStatus.RUNNING,
        input_refs=(finding_ref,),
        input_hash=input_reference_hash((finding_ref,)),
        attempt_id="report-attempt",
    )

    result = await ReporterStage(_ReporterClient(), artifacts)(current, prior)  # type: ignore[arg-type]

    assert result.markdown_path is not None
    path = Path(result.markdown_path)
    markdown = path.read_text(encoding="utf-8")
    assert path.name == "F-001.md"
    for heading in ("### Summary", "### Details", "### PoC", "### Impact"):
        assert markdown.count(heading) == 1
    assert "CONFIRMED_RESTRICTED" in markdown
    assert "외부 제출·공개 금지" in markdown
    assert "validated PoC" in markdown
    assert "실행 명령" in markdown
    assert "실행 결과" in markdown
    assert script.decode().rstrip() in markdown
    assert "SUPPORTED: command executed" in markdown
    assert "입력값이 정제되지 않고 명령 실행 함수까지 전달됩니다." in markdown
    assert "Same-attempt evidence supports the finding." not in markdown


@pytest.mark.asyncio
async def test_report_rejects_missing_validated_poc(tmp_path: Path) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    finding_ref = artifacts.put_json({"kind": "simple_finding"})
    prior = {
        SimpleStage.FINDING_DONE: _checkpoint(
            identity,
            SimpleStage.FINDING_DONE,
            outputs=(finding_ref,),
            verdict="TRUE",
        )
    }
    current = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.REPORT_DONE,
        status=StageStatus.RUNNING,
        input_refs=(finding_ref,),
        input_hash=input_reference_hash((finding_ref,)),
    )

    with pytest.raises(ValueError, match="REPORT_VALIDATED_POC_MISSING"):
        await ReporterStage(_ReporterClient(), artifacts)(current, prior)  # type: ignore[arg-type]


# mypy: disable-error-code="arg-type,no-untyped-def,unused-ignore"
