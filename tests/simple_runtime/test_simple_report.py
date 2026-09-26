from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from sastsimi.composition.simple_runtime_composition import (
    PublicSimpleRuntimeApplication,
)
from sastsimi.config.user_config import SimpleExecutionProfile, UserConfig
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.scope_policy import validate_scope_decision
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
        stage_version=STAGE_VERSION[stage],
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
async def test_verified_policy_allow_report_shows_source_and_five_citations(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    repository_url = "https://github.com/acme/app"
    source_url = "https://api.github.com/repos/acme/app/contents/SECURITY.md?ref=main"
    policy_lines = (
        "# Security policy",
        "Security reports from any researcher are accepted.",
        "Repository app version 2.x is in scope.",
        "High-impact security vulnerabilities are eligible.",
        "Local proof-of-concept testing is permitted.",
        "Private reports are permitted.",
    )
    policy_body = "\n".join(policy_lines).encode()
    blob_sha = hashlib.sha1(
        b"blob " + str(len(policy_body)).encode() + b"\0" + policy_body
    ).hexdigest()
    body_ref = artifacts.put_bytes(policy_body, "text/markdown")
    snapshot = {
        "kind": "simple_policy_snapshot",
        "version": 1,
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "target_repository": repository_url,
        "status": "FOUND",
        "reason_code": "POLICY_FOUND",
        "source_kind": "github_contents_api",
        "owner": "acme",
        "repo": "app",
        "publisher": "acme/app",
        "source_url": source_url,
        "source_path": "SECURITY.md",
        "blob_sha": blob_sha,
        "etag": '"v1"',
        "content_type": "text/markdown",
        "checked_at": datetime(2026, 9, 26, tzinfo=UTC),
        "body_sha256": hashlib.sha256(policy_body).hexdigest(),
        "body_ref": body_ref.model_dump(mode="json"),
    }
    snapshot_ref = artifacts.put_json(snapshot)
    axes = ("rules", "asset_scope", "impact", "testing", "reporting")
    model_result = {
        "status": "ALLOW",
        "rationale": "The policy permits local testing and private reports.",
        "restrictions": [],
        "testing_restriction_compliance": "PASS",
        "axes": {
            axis: {
                "status": "PASS",
                "line": line_number,
                "quote": policy_lines[line_number - 1],
                "reason": "Explicit policy sentence",
            }
            for line_number, axis in enumerate(axes, start=2)
        },
    }
    gate_ref = artifacts.put_json(
        {
            "kind": "simple_rule_scope_gate",
            "policy_snapshot_ref": snapshot_ref.model_dump(mode="json"),
            "source_refs": [body_ref.model_dump(mode="json")],
            "model_result": model_result,
            "result": validate_scope_decision(
                snapshot, policy_body.decode(), model_result
            ),
            "attempt_id": "scope-attempt",
        }
    )
    script = b"#!/bin/sh\nprintf 'SUPPORTED: command executed\\n'\n"
    content_ref = artifacts.put_bytes(script, "text/x-shellscript")
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "content_ref": content_ref.model_dump(mode="json"),
            "attempt_id": "poc-attempt",
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
            "attempt_id": "poc-attempt",
        }
    )
    validated_ref = artifacts.put_json(
        {
            "kind": "simple_validated_poc",
            "candidate_ref": candidate_ref.model_dump(mode="json"),
            "content_ref": content_ref.model_dump(mode="json"),
            "execution_ref": execution_ref.model_dump(mode="json"),
            "attempt_id": "poc-attempt",
        }
    )
    cwe_ref = artifacts.put_json({"result": {"primary_cwe": "CWE-78"}})
    technical_ref = artifacts.put_json({"result": {"status": "ACCEPT"}})
    finding_ref = artifacts.put_json({"kind": "simple_finding"})
    prior = {
        SimpleStage.POC_CANDIDATE_DONE: _checkpoint(
            identity,
            SimpleStage.POC_CANDIDATE_DONE,
            outputs=(candidate_ref, content_ref),
            attempt_id="poc-attempt",
        ),
        SimpleStage.POC_EXECUTION_DONE: _checkpoint(
            identity,
            SimpleStage.POC_EXECUTION_DONE,
            outputs=(execution_ref, validated_ref),
            attempt_id="poc-attempt",
            validated_poc_ref=validated_ref,
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
        SimpleStage.SCOPE_GATE_DONE: StageCheckpoint(
            identity=identity,
            stage=SimpleStage.SCOPE_GATE_DONE,
            stage_version=STAGE_VERSION[SimpleStage.SCOPE_GATE_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=(snapshot_ref,),
            input_hash=input_reference_hash((snapshot_ref,)),
            output_refs=(gate_ref,),
            attempt_id="scope-attempt",
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

    result = await ReporterStage(
        _ReporterClient(),
        artifacts,
        policy_snapshot_ref=snapshot_ref,
        repository_url=repository_url,
    )(current, prior)  # type: ignore[arg-type]

    assert result.markdown_path is not None
    markdown = Path(result.markdown_path).read_text(encoding="utf-8")
    assert "- Rule Scope Gate: ALLOW" in markdown
    assert "- 외부 제출·공개 허용: 예" in markdown
    assert f"- 정책 출처: {source_url}" in markdown
    assert f"- 정책 개정: {blob_sha}" in markdown
    for line_number, axis in enumerate(axes, start=2):
        assert (
            f"- Scope {axis}: PASS · {line_number}행 · "
            f"{policy_lines[line_number - 1]} · Explicit policy sentence"
        ) in markdown


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


def test_public_report_and_export_restrict_legacy_unverified_allow(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    config = UserConfig(
        data_dir=data_dir,
        profile_path=tmp_path / "profile.toml",
        auth_mode="API_KEY",
        provider="openai",
        model="test-model",
        credential_ref="env:OPENAI_API_KEY",
        execution_profile="LIGHTWEIGHT",
        max_cost_minor_units=100,
        max_tokens=1000,
        max_elapsed_seconds=3600,
        docker_network="NONE",
        enabled_tools=(),
        detected_versions={},
        setup_ready=True,
    )
    profile = SimpleExecutionProfile(
        provider_profile_ref="test",
        provider="openai",
        model="test-model",
        auth_mode="API_KEY",
        credential_ref="env:OPENAI_API_KEY",
        data_dir=data_dir,
        workspace_root=data_dir / "workspaces",
        max_cost_minor_units=100,
        max_tokens=1000,
        max_elapsed_seconds=3600,
        docker_network="NONE",
        tools={},
    )
    application = PublicSimpleRuntimeApplication(config, profile)
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    AnalysisDisplayIdStore(store.database_path).get_or_allocate("analysis-1")
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id="analysis-1",
            display_analysis_id="A-001",
            workspace_id="workspace-1",
            commit_id="a" * 40,
            repository="https://github.com/acme/app",
            hypothesis_ids=("hypothesis-1",),
        )
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(data_dir, identity)
    finding_ref = artifacts.put_json({"kind": "simple_finding"})
    assert (
        FindingDisplayIdStore(store.database_path).get_or_allocate(
            "analysis-1", finding_ref
        )
        == "F-001"
    )
    technical_ref = artifacts.put_json(
        {"kind": "simple_technical_gate", "result": {"status": "ACCEPT"}}
    )
    scope_ref = artifacts.put_json({"result": {"status": "ALLOW"}})
    old_text = "# Legacy\n- 상태: CONFIRMED\n- 외부 제출·공개 허용: 예\n"
    markdown_ref = artifacts.put_bytes(old_text.encode(), "text/markdown")
    report_path = data_dir / "reports" / "analysis-1" / "F-001.md"
    report_path.parent.mkdir(parents=True)
    report_path.write_text(old_text, encoding="utf-8")
    for stage, outputs, inputs in (
        (SimpleStage.TECH_GATE_DONE, (technical_ref,), ()),
        (SimpleStage.SCOPE_GATE_DONE, (scope_ref,), ()),
        (SimpleStage.FINDING_DONE, (finding_ref,), ()),
        (
            SimpleStage.REPORT_DONE,
            (artifacts.put_json({"kind": "draft"}), markdown_ref),
            (finding_ref,),
        ),
    ):
        store.save_checkpoint(
            StageCheckpoint(
                identity=identity,
                stage=stage,
                stage_version=STAGE_VERSION[stage],
                status=StageStatus.SUCCEEDED,
                input_refs=inputs,
                input_hash=input_reference_hash(inputs),
                output_refs=outputs,
                gate_decision="ACCEPT" if stage is SimpleStage.TECH_GATE_DONE else None,
                markdown_path=str(report_path)
                if stage is SimpleStage.REPORT_DONE
                else None,
            )
        )

    shown = application.report("F-001")
    exported = application.export_report("F-001")

    assert "허용: 예" not in shown
    assert "제보 불가" in shown
    assert exported.endswith("F-001.restricted.md")
    assert (data_dir / exported).read_text(encoding="utf-8") == shown
    assert report_path.read_text(encoding="utf-8") == old_text


# mypy: disable-error-code="arg-type,no-untyped-def,unused-ignore"
