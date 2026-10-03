"""Public simple-runtime reads must retract untrusted candidate child results."""

from __future__ import annotations

import hashlib
from datetime import timedelta
from pathlib import Path

import pytest

from sastsimi.composition.simple_runtime_composition import (
    PublicSimpleRuntimeApplication,
)
from sastsimi.config.user_config import SimpleExecutionProfile, UserConfig
from sastsimi.contracts.canonical_json import canonical_bytes
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
from sastsimi.simple_runtime.run_lease import analysis_run_lease
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _seed_public_candidate_report(
    tmp_path: Path,
) -> tuple[
    PublicSimpleRuntimeApplication,
    SimpleCheckpointStore,
    CheckpointIdentity,
    CheckpointIdentity,
]:
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
    root = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    child = root.model_copy(update={"hypothesis_id": "hypothesis-1"})
    assert (
        AnalysisDisplayIdStore(store.database_path).get_or_allocate(root.analysis_id)
        == "A-001"
    )
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=root.analysis_id,
            display_analysis_id="A-001",
            workspace_id=root.workspace_id,
            commit_id=root.commit_id,
            repository="https://example.invalid/repository.git",
            candidate_pipeline_version=2,
            hypothesis_ids=("hypothesis-1",),
        )
    )
    artifacts = SimpleArtifactRepository(data_dir, child)
    finding_ref = artifacts.put_json({"kind": "simple_finding"})
    assert (
        FindingDisplayIdStore(store.database_path).get_or_allocate(
            root.analysis_id, finding_ref
        )
        == "F-001"
    )
    gate_ref = artifacts.put_json(
        {"kind": "simple_technical_gate", "result": {"status": "ACCEPT"}}
    )
    script_ref = artifacts.put_bytes(b"#!/bin/sh\nprintf ok\n", "text/x-shellscript")
    validated_ref = artifacts.put_json({"kind": "simple_validated_poc"})
    report_ref = artifacts.put_bytes(b"# Existing report\n", "text/markdown")
    report_path = data_dir / "reports" / root.analysis_id / "F-001.md"
    report_path.parent.mkdir(parents=True)
    report_path.write_bytes(b"# Existing report\n")

    store.save_checkpoint(
        StageCheckpoint(
            identity=root,
            stage=SimpleStage.HYPOTHESIS_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
        )
    )
    for stage, outputs in (
        (
            SimpleStage.POC_CANDIDATE_DONE,
            (artifacts.put_json({"kind": "candidate"}), script_ref),
        ),
        (SimpleStage.POC_EXECUTION_DONE, (artifacts.put_json({"kind": "execution"}),)),
        (SimpleStage.TECH_GATE_DONE, (gate_ref,)),
        (SimpleStage.FINDING_DONE, (finding_ref,)),
    ):
        store.save_checkpoint(
            StageCheckpoint(
                identity=child,
                stage=stage,
                stage_version=STAGE_VERSION[stage],
                status=StageStatus.SUCCEEDED,
                input_refs=(),
                input_hash=input_reference_hash(()),
                output_refs=outputs,
                validated_poc_ref=(
                    validated_ref if stage is SimpleStage.POC_EXECUTION_DONE else None
                ),
                gate_decision="ACCEPT" if stage is SimpleStage.TECH_GATE_DONE else None,
                verdict="TRUE" if stage is SimpleStage.FINDING_DONE else None,
            )
        )
    store.save_checkpoint(
        StageCheckpoint(
            identity=child,
            stage=SimpleStage.REPORT_DONE,
            stage_version=STAGE_VERSION[SimpleStage.REPORT_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=(finding_ref,),
            input_hash=input_reference_hash((finding_ref,)),
            output_refs=(artifacts.put_json({"kind": "draft"}), report_ref),
            markdown_path=str(report_path),
        )
    )

    assert application.status("A-001")["finding_count"] == 1
    assert application.result("A-001")["findings"] == ["F-001"]
    assert "printf ok" in application.poc("F-001")
    assert "Existing report" in application.report("F-001")
    return application, store, root, child


def test_public_candidate_integrity_block_retracts_result_poc_and_report(
    tmp_path: Path,
) -> None:
    application, store, root, _child = _seed_public_candidate_report(tmp_path)

    checkpoint = store.require(root, SimpleStage.HYPOTHESIS_DONE)
    store.save_checkpoint(
        checkpoint.model_copy(
            update={
                "status": StageStatus.BLOCKED,
                "error_code": "HYPOTHESIS_EVIDENCE_INVALID",
                "retryable": False,
            }
        )
    )

    assert application.status("A-001")["finding_count"] == 0
    result = application.result("A-001")
    assert result["finding_count"] == 0
    assert result["findings"] == []
    for read in (
        application.poc,
        application.report,
        application.export_report,
        application.export_report_bundle,
    ):
        with pytest.raises(LookupError):
            read("F-001")


def test_inactive_unresolved_codex_call_retracts_saved_sibling_report(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    application, store, root, child = _seed_public_candidate_report(tmp_path)
    prior = store.list_checkpoints(root.analysis_id)
    assert store.begin_codex_call("orphan-call", root.analysis_id)

    assert application.status("A-001")["finding_count"] == 0
    assert application.result("A-001")["findings"] == []
    for read in (application.report, application.export_report):
        with pytest.raises(LookupError):
            read("F-001")
    assert store.list_checkpoints(root.analysis_id) == prior
    assert store.require(child, SimpleStage.REPORT_DONE).markdown_path is not None

    with monkeypatch.context() as patch:
        patch.setattr(
            "sastsimi.simple_runtime.report_currentness.analysis_run_lease_active",
            lambda *_args: None,
        )
        assert application.result("A-001")["findings"] == []

    with analysis_run_lease(tmp_path / "data", root.analysis_id):
        assert application.result("A-001")["findings"] == ["F-001"]
        assert "Existing report" in application.report("F-001")


def test_inactive_unconfirmed_cleanup_retracts_saved_sibling_report(
    tmp_path: Path,
) -> None:
    application, store, root, child = _seed_public_candidate_report(tmp_path)
    unrelated = child.model_copy(
        update={"workspace_id": "other-workspace", "hypothesis_id": "other-child"}
    )
    store.save_checkpoint(
        StageCheckpoint(
            identity=unrelated,
            stage=SimpleStage.PRO_CON_DONE,
            status=StageStatus.BLOCKED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            attempt_id="other-unclean-child",
            error_code="CODEX_PROCESS_CLEANUP_UNCONFIRMED",
            retryable=False,
        )
    )
    assert application.result("A-001")["findings"] == ["F-001"]

    store.save_checkpoint(
        StageCheckpoint(
            identity=child,
            stage=SimpleStage.PRO_CON_DONE,
            status=StageStatus.BLOCKED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            attempt_id="unclean-child",
            error_code="CODEX_PROCESS_CLEANUP_UNCONFIRMED",
            retryable=False,
        )
    )

    assert application.result("A-001")["findings"] == []
    with pytest.raises(LookupError):
        application.report("F-001")
    with analysis_run_lease(tmp_path / "data", root.analysis_id):
        assert application.result("A-001")["findings"] == ["F-001"]


def test_confirmed_cleanup_marker_does_not_retract_saved_report(
    tmp_path: Path,
) -> None:
    application, store, root, child = _seed_public_candidate_report(tmp_path)
    run = store.require_analysis_run(root.analysis_id)
    store.save_analysis_run(run.model_copy(update={"candidate_pipeline_version": 1}))
    blocked = StageCheckpoint(
        identity=child,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.BLOCKED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="confirmed-child",
        error_code="CODEX_PROCESS_CLEANUP_UNCONFIRMED",
        retryable=False,
    )
    store.save_checkpoint(blocked)
    assert application.result("A-001")["findings"] == []

    artifacts = SimpleArtifactRepository(tmp_path / "data", child)
    confirmation = artifacts.put_json(
        {
            "kind": "simple_codex_cleanup_confirmation",
            "analysis_id": root.analysis_id,
            "stage": blocked.stage.value,
            "attempt_id": blocked.attempt_id,
            "checkpoint_sha256": hashlib.sha256(canonical_bytes(blocked)).hexdigest(),
            "process_tree_stopped": True,
            "verification_method": "windows_process_inventory",
            "former_parent_pid": 12345,
            "observed_matching_process_count": 0,
            "observed_at": (blocked.updated_at + timedelta(seconds=1)).isoformat(),
        }
    )
    store.confirm_codex_cleanup(blocked, confirmation, artifacts)

    assert application.result("A-001")["findings"] == ["F-001"]
    assert "Existing report" in application.report("F-001")


def test_inactive_unmatched_root_codex_marker_retracts_saved_report(
    tmp_path: Path,
) -> None:
    application, store, root, child = _seed_public_candidate_report(tmp_path)
    checkpoint = store.require(root, SimpleStage.HYPOTHESIS_DONE)
    store.save_checkpoint(
        checkpoint.model_copy(
            update={
                "status": StageStatus.BLOCKED,
                "error_code": (
                    "CANDIDATE_CHILD_CODEX_STATE_PENDING:hypothesis-1:attempt-1"
                ),
                "retryable": False,
            }
        )
    )

    assert application.result("A-001")["findings"] == []
    with pytest.raises(LookupError):
        application.report("F-001")
    with analysis_run_lease(tmp_path / "data", root.analysis_id):
        assert application.result("A-001")["findings"] == ["F-001"]

    store.save_checkpoint(
        StageCheckpoint(
            identity=child,
            stage=SimpleStage.PRO_CON_DONE,
            status=StageStatus.BLOCKED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            attempt_id="attempt-1",
            error_code="CODEX_CALL_IN_FLIGHT_UNRESOLVED",
            retryable=False,
        )
    )
    assert application.result("A-001")["findings"] == ["F-001"]
