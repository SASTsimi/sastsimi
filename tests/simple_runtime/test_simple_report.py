from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.runner import StageFailed
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
            "title_en": "Verified command injection vulnerability",
            "summary_en": (
                "Unvalidated input reaches an OS command execution function."
            ),
            "details_en": "The input is passed unsanitized into a command "
            "execution call.",
            "impact_en": "An attacker can execute arbitrary commands with "
            "the server's privileges.",
            "limitations_en": ["Reproduced only in a local isolated environment."],
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
    )


def _reportable_prior(
    identity: CheckpointIdentity, artifacts: SimpleArtifactRepository
) -> tuple[dict[SimpleStage, StageCheckpoint], StoredDataRef]:
    """Build the prior stages a REPORT_DONE call needs, and the finding ref."""

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
            identity, SimpleStage.TECH_GATE_DONE, outputs=(technical_ref,)
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
    return prior, finding_ref


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
    prior, finding_ref = _reportable_prior(identity, artifacts)
    script = artifacts.read(prior[SimpleStage.POC_CANDIDATE_DONE].output_refs[1])
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
    assert "### Audit Trail" in markdown
    assert "Commit: `commit-1`" in markdown
    assert "Attempt: `report-attempt`" in markdown
    candidate_hash = prior[SimpleStage.POC_CANDIDATE_DONE].output_refs[0].content_hash
    assert f"PoC 후보 (attempt `attempt-1`): `{candidate_hash}`" in markdown

    submission_path = path.with_suffix(".submission.md")
    assert submission_path.is_file()
    submission = submission_path.read_text(encoding="utf-8")
    assert "# Verified command injection vulnerability" in submission
    assert "Internal only" in submission
    assert "### Affected / Environment" in submission
    assert "### AI Use & Human Verification" in submission
    assert "AI-assisted analysis: Yes" in submission
    assert "Manually verified by: <fill in" in submission
    assert "### Reproduction / Proof of Concept" in submission
    assert "### Disclosure" in submission
    assert "Reproduced only in a local isolated environment." in submission
    assert "상태:" not in submission
    assert "### Audit Trail" not in submission
    assert len(result.output_refs) == 3


class _LeakyReporterClient(_ReporterClient):
    async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
        result = await super().call(**kwargs)
        leaked = dict(result.value)
        leaked["details_en"] = leaked["details_en"] + " (operator: leak@example.com)"
        return SimpleLLMCallResult(
            value=leaked,
            prompt_digest=result.prompt_digest,
            output_digest=result.output_digest,
        )


@pytest.mark.asyncio
async def test_report_is_refused_when_it_names_the_operators_own_identity(
    tmp_path: Path,
) -> None:
    """A model that ignores its instructions still can't save the leak.

    healthchecks' actual Rule Scope Gate output once named the operator's
    email in a `restrictions` sentence; the prompt-level rule added afterward
    cannot be trusted alone, since the model is free to ignore it again.
    """

    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    prior, finding_ref = _reportable_prior(identity, artifacts)
    current = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.REPORT_DONE,
        status=StageStatus.RUNNING,
        input_refs=(finding_ref,),
        input_hash=input_reference_hash((finding_ref,)),
        attempt_id="report-attempt",
    )
    stage = ReporterStage(
        _LeakyReporterClient(),  # type: ignore[arg-type]
        artifacts,
        operator_identity=frozenset({"leak@example.com"}),
    )

    with pytest.raises(StageFailed) as excinfo:
        await stage(current, prior)
    assert excinfo.value.failure.code == "REPORT_SENSITIVE_CONTENT"


class _JargonLeakingReporterClient(_ReporterClient):
    async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
        result = await super().call(**kwargs)
        leaked = dict(result.value)
        leaked["details_en"] = (
            "The Pro agent confirmed this across two rounds. " + leaked["details_en"]
        )
        return SimpleLLMCallResult(
            value=leaked,
            prompt_digest=result.prompt_digest,
            output_digest=result.output_digest,
        )


@pytest.mark.asyncio
async def test_report_is_refused_when_it_names_this_pipelines_own_machinery(
    tmp_path: Path,
) -> None:
    # Observed on saleor: a submission report's Technical Details opened with
    # "The Pro agent confirmed..." despite being told not to - an instruction
    # the model is free to ignore, same as the operator's own identity.
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    prior, finding_ref = _reportable_prior(identity, artifacts)
    current = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.REPORT_DONE,
        status=StageStatus.RUNNING,
        input_refs=(finding_ref,),
        input_hash=input_reference_hash((finding_ref,)),
        attempt_id="report-attempt",
    )
    stage = ReporterStage(_JargonLeakingReporterClient(), artifacts)  # type: ignore[arg-type]

    with pytest.raises(StageFailed) as excinfo:
        await stage(current, prior)
    assert excinfo.value.failure.code == "REPORT_SENSITIVE_CONTENT"


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
