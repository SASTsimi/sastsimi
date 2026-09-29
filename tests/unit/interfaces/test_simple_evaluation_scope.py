"""Policy context and report visibility for the legacy simple-resume command."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.interfaces.cli import simple_evaluation
from sastsimi.providers.base import CodexProcessResult
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.runner import RunOutcome
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _checkpoint(
    identity: CheckpointIdentity,
    stage: SimpleStage,
    *,
    outputs: tuple[StoredDataRef, ...] = (),
    recipe_ref: StoredDataRef | None = None,
    image_digest: str | None = None,
    markdown_path: str | None = None,
) -> StageCheckpoint:
    return StageCheckpoint(
        identity=identity,
        stage=stage,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=outputs,
        recipe_ref=recipe_ref,
        image_digest=image_digest,
        markdown_path=markdown_path,
    )


@pytest.mark.parametrize(
    ("gate_status", "report_text", "file_text", "visible"),
    [
        (
            "ALLOW",
            "# Old report\n- 상태: CONFIRMED\n- 외부 제출·공개 허용: 예\n",
            "# Old report\n- 상태: CONFIRMED\n- 외부 제출·공개 허용: 예\n",
            False,
        ),
        (
            "UNCERTAIN",
            "# Restricted report\n- 상태: CONFIRMED_RESTRICTED\n"
            "- 외부 제출·공개 허용: 아니요\n",
            "# Restricted report\n- 상태: CONFIRMED_RESTRICTED\n"
            "- 외부 제출·공개 허용: 아니요\n",
            True,
        ),
        (
            "UNCERTAIN",
            "# Restricted report\n- 외부 제출·공개 허용: 아니요\n",
            "# Old report\n- 상태: CONFIRMED\n- 외부 제출·공개 허용: 예\n",
            False,
        ),
    ],
)
def test_result_path_does_not_advertise_unverified_allow_report(
    tmp_path: Path,
    gate_status: str,
    report_text: str,
    file_text: str,
    visible: bool,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    gate_ref = artifacts.put_json({"result": {"status": gate_status}})
    report_ref = artifacts.put_bytes(report_text.encode(), "text/markdown")
    report_path = tmp_path / "reports" / "analysis-1" / "F-001.md"
    report_path.parent.mkdir(parents=True)
    report_path.write_bytes(file_text.encode())
    store.save_checkpoint(
        _checkpoint(identity, SimpleStage.SCOPE_GATE_DONE, outputs=(gate_ref,))
    )
    report = _checkpoint(
        identity,
        SimpleStage.REPORT_DONE,
        outputs=(artifacts.put_json({"kind": "draft"}), report_ref),
        markdown_path=str(report_path),
    )

    result = simple_evaluation._report_path_for_result(
        store,
        artifacts,
        identity,
        report,
        policy_snapshot_ref=None,
        repository_url=None,
    )

    assert result == (str(report_path) if visible else None)
    if visible:
        outside_path = tmp_path / "other" / "F-001.md"
        outside_path.parent.mkdir()
        outside_path.write_bytes(report_text.encode())
        assert (
            simple_evaluation._report_path_for_result(
                store,
                artifacts,
                identity,
                report.model_copy(update={"markdown_path": str(outside_path)}),
                policy_snapshot_ref=None,
                repository_url=None,
            )
            is None
        )


@pytest.mark.asyncio
async def test_simple_resume_passes_saved_policy_context_to_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    policy_ref = artifacts.put_json({"kind": "simple_policy_snapshot"})
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id="A-001",
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="https://github.com/acme/app",
            policy_snapshot_ref=policy_ref,
            hypothesis_ids=(identity.hypothesis_id or "",),
        )
    )
    store.save_checkpoint(
        _checkpoint(
            identity,
            SimpleStage.POC_CANDIDATE_DONE,
            recipe_ref=artifacts.put_json({"kind": "recipe"}),
            image_digest="sha256:test",
        )
    )
    monkeypatch.setattr(
        simple_evaluation, "import_existing_analysis", lambda *_args: (identity,)
    )
    monkeypatch.setattr(
        simple_evaluation,
        "load_local_evaluation_profile",
        lambda _path: SimpleNamespace(codex=SimpleNamespace(model="test-model")),
    )
    monkeypatch.setattr(
        simple_evaluation,
        "build_local_codex_binding",
        lambda **_kwargs: SimpleNamespace(provider=object(), binding=object()),
    )
    monkeypatch.setattr(simple_evaluation, "reference", lambda _provider: policy_ref)
    monkeypatch.setattr(
        simple_evaluation, "CodexCliProcessRunner", lambda **_kwargs: object()
    )
    monkeypatch.setattr(
        simple_evaluation, "SimpleCodexClient", lambda **_kwargs: object()
    )
    monkeypatch.setattr(
        simple_evaluation, "build_simple_docker_adapter", lambda *_args: object()
    )
    monkeypatch.setattr(
        simple_evaluation,
        "SimpleLocalContainerFactory",
        lambda **_kwargs: object(),
    )

    received: list[tuple[object, object, object, bool]] = []

    class _Runner:
        def __init__(
            self,
            _store: SimpleCheckpointStore,
            handlers: dict[SimpleStage, Any],
            *,
            policy_snapshot_ref: StoredDataRef | None = None,
            codex_invalid_output_resume: bool = False,
        ) -> None:
            scope = handlers[SimpleStage.SCOPE_GATE_DONE]
            received.append(
                (
                    policy_snapshot_ref,
                    scope._policy_snapshot_ref,
                    scope._repository_url,
                    codex_invalid_output_resume,
                )
            )

        async def resume_hypothesis(self, _identity: CheckpointIdentity) -> RunOutcome:
            return RunOutcome(
                current_stage=SimpleStage.POC_CANDIDATE_DONE,
                status=StageStatus.BLOCKED,
            )

    monkeypatch.setattr(simple_evaluation, "SimpleRuntimeRunner", _Runner)

    await simple_evaluation.resume(
        data_dir=tmp_path,
        analysis_id=identity.analysis_id,
        profile_path=tmp_path / "profile.toml",
    )

    assert received == [(policy_ref, policy_ref, "https://github.com/acme/app", True)]


@pytest.mark.asyncio
async def test_simple_resume_writes_invalid_output_diagnostics_per_hypothesis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identities = tuple(
        CheckpointIdentity(
            analysis_id="analysis-1",
            workspace_id=f"workspace-{number}",
            commit_id=str(number) * 40,
            hypothesis_id=f"hypothesis-{number}",
        )
        for number in (1, 2)
    )
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    for identity in identities:
        artifacts = SimpleArtifactRepository(tmp_path, identity)
        store.save_checkpoint(
            _checkpoint(
                identity,
                SimpleStage.POC_CANDIDATE_DONE,
                recipe_ref=artifacts.put_json({"kind": "recipe"}),
                image_digest="sha256:test",
            )
        )
    provider_ref = SimpleArtifactRepository(tmp_path, identities[0]).put_json(
        {"kind": "provider"}
    )
    monkeypatch.setattr(
        simple_evaluation, "import_existing_analysis", lambda *_args: identities
    )
    monkeypatch.setattr(
        simple_evaluation,
        "load_local_evaluation_profile",
        lambda _path: SimpleNamespace(codex=SimpleNamespace(model="test-model")),
    )
    monkeypatch.setattr(
        simple_evaluation,
        "build_local_codex_binding",
        lambda **_kwargs: SimpleNamespace(provider=object(), binding=object()),
    )
    monkeypatch.setattr(simple_evaluation, "reference", lambda _provider: provider_ref)

    class _CodexRunner:
        async def execute(self, _request: object) -> CodexProcessResult:
            return CodexProcessResult(
                status="SUCCEEDED",
                final_message=b"{invalid-json",
                provider_session_id=None,
            )

    monkeypatch.setattr(
        simple_evaluation, "CodexCliProcessRunner", lambda **_kwargs: _CodexRunner()
    )
    monkeypatch.setattr(
        simple_evaluation, "build_simple_docker_adapter", lambda *_args: object()
    )
    monkeypatch.setattr(
        simple_evaluation,
        "SimpleLocalContainerFactory",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        simple_evaluation,
        "build_stage_handlers",
        lambda **kwargs: {"client": kwargs["client"]},
    )
    failures: dict[str, StageFailure] = {}

    class _Runner:
        def __init__(
            self,
            _store: SimpleCheckpointStore,
            handlers: dict[str, Any],
            *,
            policy_snapshot_ref: StoredDataRef | None = None,
            codex_invalid_output_resume: bool = False,
        ) -> None:
            assert codex_invalid_output_resume
            self.client = handlers["client"]

        async def resume_hypothesis(self, identity: CheckpointIdentity) -> RunOutcome:
            failure = await self.client.call(
                prompt=b"safe request",
                output_schema={"type": "object"},
                timeout_ms=1_000,
            )
            assert isinstance(failure, StageFailure)
            failures[identity.hypothesis_id or ""] = failure
            return RunOutcome(
                current_stage=SimpleStage.POC_CANDIDATE_DONE,
                status=StageStatus.BLOCKED,
                error_code=failure.code,
            )

    monkeypatch.setattr(simple_evaluation, "SimpleRuntimeRunner", _Runner)

    result = await simple_evaluation.resume(
        data_dir=tmp_path,
        analysis_id="analysis-1",
        profile_path=tmp_path / "profile.toml",
    )

    assert result["status"] == "BLOCKED"
    assert len(failures) == 2
    for identity in identities:
        failure = failures[identity.hypothesis_id or ""]
        assert failure.code == "INVALID_OUTPUT"
        assert len(failure.evidence_refs) == 2
        artifacts = SimpleArtifactRepository(tmp_path, identity)
        for ref in failure.evidence_refs:
            assert str(ref.workspace_id) == identity.workspace_id
            assert str(ref.commit_id) == identity.commit_id
            artifacts.read(ref)
        diagnostic = json.loads(artifacts.read(failure.evidence_refs[1]))
        assert diagnostic["kind"] == "simple_llm_invalid_output"
