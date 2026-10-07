from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from sastsimi.composition.simple_runtime_composition import (
    PublicSimpleRuntimeApplication,
)
from sastsimi.config.user_config import SimpleExecutionProfile, UserConfig
from sastsimi.dashboard.query import DashboardNotFound, DashboardQuery
from sastsimi.interfaces.cli.simple_evaluation import _report_path_for_result
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.runner import SimpleRuntimeRunner, StageBlocked
from sastsimi.simple_runtime.scope_policy import validate_scope_decision
from sastsimi.simple_runtime.stages import ReporterStage
from sastsimi.simple_runtime.store import SimpleCheckpointStore


class _ReporterClient:
    def __init__(self) -> None:
        self.calls = 0
        self.last_schema: dict[str, Any] | None = None

    async def call(self, **_kwargs: Any) -> SimpleLLMCallResult:
        self.calls += 1
        self.last_schema = _kwargs["output_schema"]
        ko = {
            "title": "검증된 명령어 삽입 취약점",
            "summary": "검증되지 않은 입력으로 운영체제 명령을 실행할 수 있습니다.",
            "details": "입력값이 정제되지 않고 명령 실행 함수까지 전달됩니다.",
            "impact": "공격자가 서버 권한으로 임의 명령을 실행할 수 있습니다.",
            "recommendation": "입력을 검증하세요.",
            "limitations": ["로컬 격리 환경에서만 재현했습니다."],
            "review_items": ["실제 배포 설정에서 동일 경로를 확인해야 합니다."],
        }
        value = {
            "schema_version": 2,
            "en": {
                "title": "Confirmed command injection",
                "summary": "Untrusted input reaches a command execution path.",
                "details": "The tested flow reaches the command sink.",
                "impact": "An attacker could execute commands.",
                "recommendation": "Validate and constrain the input.",
                "limitations": ["Only an isolated environment was tested."],
                "review_items": ["Confirm affected deployed versions."],
            },
            "ko": ko,
            "citations": [],
        }
        return SimpleLLMCallResult(
            value=value,
            prompt_digest=hashlib.sha256(b"prompt").hexdigest(),
            output_digest=hashlib.sha256(b"output").hexdigest(),
        )


@pytest.mark.asyncio
async def test_invalid_report_prose_has_specific_retryable_failure(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    finding_ref = artifacts.put_json({"kind": "simple_finding"})
    poc_ref = artifacts.put_json({"kind": "simple_poc_execution"})

    class _InvalidReporterClient(_ReporterClient):
        async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
            result = await super().call(**kwargs)
            value = dict(result.value)
            en = dict(value["en"])
            en["limitations"] = ["Affected version 1.2.3 was not verified."]
            value["en"] = en
            return result.model_copy(update={"value": value})

    prior = {
        SimpleStage.FINDING_DONE: _checkpoint(
            identity, SimpleStage.FINDING_DONE, outputs=(finding_ref,), verdict="TRUE"
        ),
        SimpleStage.POC_EXECUTION_DONE: _checkpoint(
            identity, SimpleStage.POC_EXECUTION_DONE, outputs=(poc_ref,)
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

    with pytest.raises(StageBlocked) as caught:
        await ReporterStage(_InvalidReporterClient(), artifacts)._draft(
            current, prior, finding_ref
        )
    assert caught.value.failure.code == "REPORT_CONTENT_INVALID"
    assert caught.value.failure.retryable is True


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
    monkeypatch: pytest.MonkeyPatch,
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
    chain_ref = artifacts.put_json(
        {
            "kind": "simple_chaining_result",
            "analysis_id": identity.analysis_id,
            "source_hypothesis_id": identity.hypothesis_id,
            "considered_primitive_refs": [],
            "status": "NO_MATERIAL_CHILD",
            "children": [],
        }
    )
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
        SimpleStage.CHAINING_DONE: _checkpoint(
            identity, SimpleStage.CHAINING_DONE, outputs=(chain_ref,)
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
        stage_version=STAGE_VERSION[SimpleStage.REPORT_DONE],
        status=StageStatus.RUNNING,
        input_refs=(finding_ref,),
        input_hash=input_reference_hash((finding_ref,)),
        attempt_id="report-attempt",
    )

    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    client = _ReporterClient()

    def fail_publication(**_kwargs: Any) -> None:
        raise ValueError("BUNDLE_PUBLICATION_FAILED")

    with monkeypatch.context() as patched:
        patched.setattr(
            "sastsimi.simple_runtime.stages.publish_bundle", fail_publication
        )
        with pytest.raises(ValueError, match="BUNDLE_PUBLICATION_FAILED"):
            await ReporterStage(client, artifacts, store=store)(current, prior)
    assert client.calls == 1
    assert client.last_schema is not None
    assert client.last_schema["properties"]["citations"] == {
        "type": "array",
        "items": {"type": "string"},
    }
    assert STAGE_VERSION[SimpleStage.REPORT_DONE] == "4"
    retry = current.model_copy(update={"attempt_id": "report-attempt-2"})
    resumed_store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    coverage_ref = artifacts.put_json(
        {
            "kind": "simple_static_coverage_v1",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "fingerprint": "e" * 64,
            "expected_count": 2,
            "verified_count": 1,
            "gaps": [
                {"path": "other.py", "rule_id": "r1", "reason": "not_attempted_budget"}
            ],
            "unsupported_files": [
                {"path": "Dockerfile", "reason": "unsupported_language"}
            ],
            "engine_errors": [],
        }
    )
    resumed_store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id="A-001",
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="example/project",
            static_coverage_ref=coverage_ref,
            static_disposition="PARTIAL",
        )
    )
    predictable_temporary = (
        tmp_path / "reports" / identity.analysis_id / "F-001.md.next"
    )
    predictable_temporary.parent.mkdir(parents=True, exist_ok=True)
    predictable_temporary.write_bytes(b"must remain untouched")
    result = await ReporterStage(client, artifacts, store=resumed_store)(retry, prior)
    assert client.calls == 1
    assert predictable_temporary.read_bytes() == b"must remain untouched"

    assert result.markdown_path is not None
    path = Path(result.markdown_path)
    markdown = path.read_text(encoding="utf-8")
    assert path.name == "F-001.md"
    for heading in ("### Summary", "### Details", "### PoC", "### Impact"):
        assert markdown.count(heading) == 1
    assert "CONFIRMED_RESTRICTED" in markdown
    assert "비공개 제보 허가가 확인되지 않았습니다" in markdown
    assert "validated PoC" in markdown
    assert "실행 명령" in markdown
    assert "실행 결과" in markdown
    assert script.decode().rstrip() in markdown
    assert "SUPPORTED: command executed" in markdown
    assert "입력값이 정제되지 않고 명령 실행 함수까지 전달됩니다." in markdown
    assert "Same-attempt evidence supports the finding." not in markdown
    assert "PARTIAL" in markdown
    assert "1 / 2" in markdown
    assert "Finding 확인" in markdown
    assert coverage_ref.content_hash in markdown
    assert result.bundle_manifest_ref is not None
    assert result.bundle_archive_ref is not None
    bundle = path.with_suffix("")
    assert (bundle / "report_en.md").is_file()
    assert (bundle / "report_kr.md").is_file()
    assert (bundle / "poc.sh").read_bytes() == script
    assert (bundle / "evidence" / "provenance.json").is_file()
    assert (bundle / "bundle.zip").is_file()
    assert (
        b"## Affected products and tested version"
        in (bundle / "report_en.md").read_bytes()
    )
    original_legacy = path.read_bytes()

    # A completed report must be re-rendered when a later static retry fills
    # the remaining coverage gap, even if that FULL state predates this resume.
    for stage in HYPOTHESIS_STAGES:
        if stage is SimpleStage.REPORT_DONE:
            continue
        checkpoint = prior.get(stage) or _checkpoint(identity, stage)
        resumed_store.save_checkpoint(checkpoint)
    resumed_store.complete(retry, result)
    profile_ref = artifacts.put_json({"kind": "simple_repository_profile"})
    bundle_ref = artifacts.put_json({"kind": "simple_static_fact_bundle"})
    full_coverage_ref = artifacts.put_json(
        {
            "kind": "simple_static_coverage_v1",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "fingerprint": "e" * 64,
            "expected_count": 2,
            "verified_count": 2,
            "gaps": [],
            "unsupported_files": [],
            "engine_errors": [],
        }
    )
    resumed_store.save_analysis_run(
        resumed_store.require_analysis_run(identity.analysis_id).model_copy(
            update={
                "workspace_path": tmp_path / "workspaces" / identity.workspace_id,
                "repository_profile_ref": profile_ref,
                "static_bundle_ref": bundle_ref,
                "static_coverage_ref": full_coverage_ref,
                "static_disposition": "FULL",
                "hypothesis_ids": (identity.hypothesis_id,),
            }
        )
    )
    AnalysisDisplayIdStore(resumed_store.database_path).get_or_allocate(
        identity.analysis_id
    )
    with pytest.raises(DashboardNotFound, match="DASHBOARD_REPORT_NOT_FOUND"):
        DashboardQuery(tmp_path).report_path(identity.analysis_id, "F-001")

    class _UnusedBootstrap:
        async def run(self, *_args: Any) -> StaticBootstrapResult:
            raise AssertionError("completed static scan must not run again")

        async def propose(self, *_args: Any) -> None:
            raise AssertionError("completed hypothesis agents must not run again")

    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=resumed_store,
        static_bootstrap=_UnusedBootstrap(),
        hypothesis_bootstrap=_UnusedBootstrap(),
        runner_factory=lambda current_store, child, _static: SimpleRuntimeRunner(
            current_store,
            {
                SimpleStage.REPORT_DONE: ReporterStage(
                    client,
                    SimpleArtifactRepository(tmp_path, child),
                    store=current_store,
                )
            },
        ),
    )
    resumed = await application.resume("A-001")
    assert resumed.status == "COMPLETE", (resumed.current_stage, resumed.error_code)
    refreshed_report = resumed_store.require(identity, SimpleStage.REPORT_DONE)
    assert refreshed_report.report_ref == result.report_ref
    assert refreshed_report.bundle_manifest_ref != result.bundle_manifest_ref
    assert refreshed_report.markdown_path is not None
    refreshed_bundle = Path(refreshed_report.markdown_path).with_suffix("")
    assert refreshed_bundle != bundle
    assert "Static scan status: `FULL`" in (
        refreshed_bundle / "report_en.md"
    ).read_text(encoding="utf-8")
    assert "PARTIAL warning" not in (refreshed_bundle / "report_en.md").read_text(
        encoding="utf-8"
    )
    assert "정적 분석 상태: `FULL`" in (refreshed_bundle / "report_kr.md").read_text(
        encoding="utf-8"
    )
    assert "2 / 2" in Path(refreshed_report.markdown_path).read_text(encoding="utf-8")
    assert "PARTIAL" in (bundle / "report_en.md").read_text(encoding="utf-8")
    assert client.calls == 1
    assert DashboardQuery(tmp_path).report_path(identity.analysis_id, "F-001") == Path(
        refreshed_report.markdown_path
    )
    if os.name == "nt":
        # Simulate Windows installations where regular Win32 paths cannot be
        # resolved past the legacy limit. Both manifest and archive reads must
        # use the extended path, just as publication does.
        original_resolve = Path.resolve

        def require_extended_report_path(path: Path, *args: Any, **kwargs: Any) -> Path:
            if path.name in {"manifest.json", "bundle.zip"} and not str(
                path
            ).startswith("\\\\?\\"):
                raise OSError(206, "legacy report path limit")
            return original_resolve(path, *args, **kwargs)

        with monkeypatch.context() as patched:
            patched.setattr(Path, "resolve", require_extended_report_path)
            verified, _ = artifacts.verified_report_bundle(
                checkpoints={
                    stage: resumed_store.require(identity, stage)
                    for stage in HYPOTHESIS_STAGES
                },
                finding_ref=finding_ref,
                display_id="F-001",
                scope_status=json.loads(
                    (refreshed_bundle / "evidence" / "provenance.json").read_bytes()
                )["scope_status"],
                public_projection=lambda body: body,
            )
    else:
        verified, _ = artifacts.verified_report_bundle(
            checkpoints={
                stage: resumed_store.require(identity, stage)
                for stage in HYPOTHESIS_STAGES
            },
            finding_ref=finding_ref,
            display_id="F-001",
            scope_status=json.loads(
                (refreshed_bundle / "evidence" / "provenance.json").read_bytes()
            )["scope_status"],
            public_projection=lambda body: body,
        )
    assert verified.display_id == "F-001"
    public_config = UserConfig(
        data_dir=tmp_path,
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
    public_profile = SimpleExecutionProfile(
        provider_profile_ref="test",
        provider="openai",
        model="test-model",
        auth_mode="API_KEY",
        credential_ref="env:OPENAI_API_KEY",
        data_dir=tmp_path,
        workspace_root=tmp_path / "workspaces",
        max_cost_minor_units=100,
        max_tokens=1000,
        max_elapsed_seconds=3600,
        docker_network="NONE",
        tools={},
    )
    public_app = PublicSimpleRuntimeApplication(public_config, public_profile)
    with monkeypatch.context() as patched:
        patched.setattr(
            "sastsimi.composition.simple_runtime_composition.safe_public_report",
            lambda body, _review: body,
        )
        exported = public_app.export_report_bundle("F-001")
    assert exported == (
        f"reports/{identity.analysis_id}/{refreshed_bundle.name}/bundle.zip"
    )
    current_run = resumed_store.require_analysis_run(identity.analysis_id)
    resumed_store.save_analysis_run(
        current_run.model_copy(
            update={
                "static_coverage_ref": coverage_ref,
                "static_disposition": "PARTIAL",
            }
        )
    )
    with pytest.raises(LookupError, match="CURRENT_REPORT_STALE"):
        public_app.report("F-001")
    assert (
        _report_path_for_result(
            resumed_store,
            artifacts,
            identity,
            refreshed_report,
            policy_snapshot_ref=None,
            repository_url="example/project",
        )
        is None
    )
    resumed_store.save_analysis_run(current_run)
    assert (await application.resume("A-001")).status == "COMPLETE"
    assert client.calls == 1
    (refreshed_bundle / "manifest.json").write_bytes(b"tampered")
    assert (await application.resume("A-001")).status == "COMPLETE"
    with pytest.raises(ValueError, match="BUNDLE_MANIFEST_CHANGED"):
        artifacts.verified_report_bundle(
            checkpoints={
                stage: resumed_store.require(identity, stage)
                for stage in HYPOTHESIS_STAGES
            },
            finding_ref=finding_ref,
            display_id="F-001",
            scope_status="UNCERTAIN",
            public_projection=lambda body: body,
        )

    monkeypatch.setattr(
        "sastsimi.simple_runtime.stages.publish_bundle", fail_publication
    )
    with pytest.raises(ValueError, match="BUNDLE_PUBLICATION_FAILED"):
        await ReporterStage(client, artifacts, store=resumed_store)(retry, prior)
    assert client.calls == 1
    assert path.read_bytes() == original_legacy

    # A new Finding attempt is not a publication retry, even when its
    # content-addressed output reference happens to be identical.
    refreshed = dict(prior)
    refreshed[SimpleStage.FINDING_DONE] = prior[SimpleStage.FINDING_DONE].model_copy(
        update={"attempt_id": "finding-attempt-2"}
    )
    with pytest.raises(ValueError, match="BUNDLE_PUBLICATION_FAILED"):
        await ReporterStage(client, artifacts, store=resumed_store)(retry, refreshed)
    assert client.calls == 2


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
    script = b"#!/bin/sh\nprintf 'SUPPORTED: command executed\\n'\n"
    axes = ("rules", "asset_scope", "impact", "testing", "reporting")
    model_result = {
        "status": "ALLOW",
        "rationale": "The policy permits local testing and private reports.",
        "restrictions": [],
        "testing_restriction_compliance": "PASS",
        "testing_poc_quote": "printf 'SUPPORTED: command executed\\n'",
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
    verification_ref = artifacts.put_json(
        {
            "kind": "simple_verification_result",
            "source_refs": [
                validated_ref.model_dump(mode="json"),
                execution_ref.model_dump(mode="json"),
            ],
            "result": {"verdict": "TRUE"},
            "attempt_id": "verification-attempt",
        }
    )
    technical_ref = artifacts.put_json(
        {
            "kind": "simple_technical_gate",
            "source_refs": [
                validated_ref.model_dump(mode="json"),
                execution_ref.model_dump(mode="json"),
                verification_ref.model_dump(mode="json"),
            ],
            "result": {"status": "ACCEPT"},
            "attempt_id": "technical-attempt",
        }
    )
    gate_ref = artifacts.put_json(
        {
            "kind": "simple_rule_scope_gate",
            "policy_snapshot_ref": snapshot_ref.model_dump(mode="json"),
            "source_refs": [
                ref.model_dump(mode="json")
                for ref in (
                    body_ref,
                    content_ref,
                    validated_ref,
                    technical_ref,
                    execution_ref,
                    verification_ref,
                )
            ],
            "model_result": model_result,
            "result": validate_scope_decision(
                snapshot,
                policy_body.decode(),
                model_result,
                poc_evidence_text=script.decode(),
            ),
            "attempt_id": "scope-attempt",
        }
    )
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
    assert "- 비공개 제보 정책 조건: 예비 충족·사람 검토 필요" in markdown
    assert "- 외부 공개 허용: 확인되지 않음" in markdown
    assert "- 외부 제출·공개 허용: 예" not in markdown
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
