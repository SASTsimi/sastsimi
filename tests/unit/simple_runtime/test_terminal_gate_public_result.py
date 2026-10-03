"""Public CLI result and dashboard agree on a non-reportable Gate outcome."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sastsimi.composition.simple_runtime_composition import (
    PublicSimpleRuntimeApplication,
)
from sastsimi.config.user_config import (
    SimpleExecutionProfile,
    UserConfig,
    UserConfigStore,
)
from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.dashboard.query import DashboardQuery
from sastsimi.interfaces.cli.main import main
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
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
    terminal_initial_outcome,
    terminal_poc_outcome,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _ref(name: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(f"stored-{name}"),
        data_kind="test",
        content_hash=hashlib.sha256(name.encode()).hexdigest(),
        workspace_id=WorkspaceId("workspace-1"),
        commit_id=CommitId("a" * 40),
        record_id=None,
    )


@pytest.mark.parametrize("attempt_number", [1, 2, 3])
def test_terminal_poc_requires_exhausted_attempt(attempt_number: int) -> None:
    checkpoint = StageCheckpoint(
        identity=CheckpointIdentity(
            analysis_id="analysis-1",
            workspace_id="workspace-1",
            commit_id="a" * 40,
            hypothesis_id="hypothesis-1",
        ),
        stage=SimpleStage.POC_EXECUTION_DONE,
        stage_version=STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(_ref("execution"), _ref("interpretation")),
        attempt_number=attempt_number,
        verdict="HOLD",
    )

    assert terminal_poc_outcome(checkpoint) == (
        "INCONCLUSIVE" if attempt_number == 3 else None
    )


def test_terminal_poc_accepts_recorded_stop_only_with_explicit_provenance() -> None:
    checkpoint = StageCheckpoint(
        identity=CheckpointIdentity(
            analysis_id="analysis-1",
            workspace_id="workspace-1",
            commit_id="a" * 40,
            hypothesis_id="hypothesis-1",
        ),
        stage=SimpleStage.POC_EXECUTION_DONE,
        stage_version=STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(_ref("execution"), _ref("interpretation")),
        attempt_number=2,
        verdict="HOLD",
        poc_stop_decision_ref=_ref("stop-decision"),
    )

    assert terminal_poc_outcome(checkpoint) == "INCONCLUSIVE"
    assert (
        terminal_poc_outcome(
            checkpoint.model_copy(update={"validated_poc_ref": _ref("validated")})
        )
        is None
    )


def test_terminal_initial_requires_explicit_unmet_prerequisite_evidence() -> None:
    ref = _ref("unmet-external-prerequisite")
    checkpoint = StageCheckpoint(
        identity=CheckpointIdentity(
            analysis_id="analysis-1",
            workspace_id="workspace-1",
            commit_id="a" * 40,
            hypothesis_id="hypothesis-1",
        ),
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(ref,),
        verdict="HOLD",
        external_prerequisites_ref=ref,
    )

    assert terminal_initial_outcome(checkpoint) == "INCONCLUSIVE"
    assert (
        terminal_initial_outcome(
            checkpoint.model_copy(update={"external_prerequisites_ref": None})
        )
        is None
    )
    assert (
        terminal_initial_outcome(checkpoint.model_copy(update={"recipe_ref": ref}))
        is None
    )


@pytest.mark.parametrize(
    "invalidity", ("missing", "tampered", "wrong_attempt", "empty")
)
def test_initial_terminal_evidence_reader_rejects_invalid_artifact(
    tmp_path: Path,
    invalidity: str,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    ref = artifacts.put_json(
        {
            "kind": "simple_initial_verification",
            "attempt_id": "other-attempt"
            if invalidity == "wrong_attempt"
            else "attempt-1",
            "result": {
                "initial_assessment": "HOLD",
                "unmet_external_prerequisites": (
                    []
                    if invalidity == "empty"
                    else ["attacker control not established"]
                ),
            },
        }
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(ref,),
        attempt_id="attempt-1",
        verdict="HOLD",
        external_prerequisites_ref=ref,
    )

    path = artifacts.artifacts.path_for(ref.content_hash)
    if invalidity == "missing":
        path.unlink()
    elif invalidity == "tampered":
        path.write_bytes(b'{"kind":"tampered"}')
    with pytest.raises((OSError, ValueError)):
        artifacts.verified_terminal_initial_outcome(checkpoint)


def test_public_result_and_dashboard_agree_on_inconclusive_gate(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    data_dir = tmp_path / "data"
    config = UserConfig(
        data_dir=data_dir,
        profile_path=tmp_path / "profile.toml",
        auth_mode="API_KEY",
        provider="openai",
        model="configured-model",
        credential_ref="env:OPENAI_API_KEY",
        execution_profile="LIGHTWEIGHT",
        max_cost_minor_units=10_000,
        max_tokens=100_000,
        max_elapsed_seconds=3_600,
        docker_network="NONE",
        enabled_tools=(),
        detected_versions={},
        setup_ready=True,
    )
    profile = SimpleExecutionProfile(
        provider_profile_ref="local-openai",
        provider="openai",
        model="configured-model",
        auth_mode="API_KEY",
        credential_ref="env:OPENAI_API_KEY",
        data_dir=data_dir,
        workspace_root=data_dir / "workspaces",
        max_cost_minor_units=10_000,
        max_tokens=100_000,
        max_elapsed_seconds=3_600,
        docker_network="NONE",
        tools={},
    )
    config_store = UserConfigStore(tmp_path / "config.toml")
    config_store.save(config)
    application = PublicSimpleRuntimeApplication(config, profile)
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    assert (
        AnalysisDisplayIdStore(store.database_path).get_or_allocate("analysis-a")
        == "A-001"
    )
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id="analysis-a",
            display_analysis_id="A-001",
            workspace_id="workspace-1",
            commit_id="a" * 40,
            repository="https://example.invalid/repo.git",
            hypothesis_ids=("hypothesis-1",),
        )
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    gate_index = HYPOTHESIS_STAGES.index(SimpleStage.TECH_GATE_DONE)
    for stage in HYPOTHESIS_STAGES[: gate_index + 1]:
        store.save_checkpoint(
            StageCheckpoint(
                identity=identity,
                stage=stage,
                stage_version=STAGE_VERSION[stage],
                status=StageStatus.SUCCEEDED,
                input_refs=(),
                input_hash=input_reference_hash(()),
                output_refs=(_ref(stage.value),),
                verdict="TRUE"
                if stage is SimpleStage.VERIFICATION_FINAL_DONE
                else None,
                gate_decision="REVISE" if stage is SimpleStage.TECH_GATE_DONE else None,
                gate_revision_count=2,
            )
        )

    dashboard = DashboardQuery(data_dir).get_analysis("A-001")
    result = application.result("A-001")

    assert dashboard.status == result["status"] == "COMPLETE"
    assert dashboard.progress_percent == result["percent"] == 100
    assert dashboard.finding_count == result["finding_count"] == 0
    assert result["inconclusive_hypothesis_count"] == 1
    assert result["rejected_hypothesis_count"] == 0
    assert result["findings"] == []
    assert (
        main(
            ["result", "A-001", "--format", "json"],
            public_application=application,
            user_config_store=config_store,
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["data"]["status"] == "COMPLETE"
    assert payload["data"]["inconclusive_hypothesis_count"] == 1


def test_cli_status_and_dashboard_block_when_initial_evidence_disappears(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    config = UserConfig(
        data_dir=data_dir,
        profile_path=tmp_path / "profile.toml",
        auth_mode="API_KEY",
        provider="openai",
        model="configured-model",
        credential_ref="env:OPENAI_API_KEY",
        execution_profile="LIGHTWEIGHT",
        max_cost_minor_units=10_000,
        max_tokens=100_000,
        max_elapsed_seconds=3_600,
        docker_network="NONE",
        enabled_tools=(),
        detected_versions={},
        setup_ready=True,
    )
    profile = SimpleExecutionProfile(
        provider_profile_ref="local-openai",
        provider="openai",
        model="configured-model",
        auth_mode="API_KEY",
        credential_ref="env:OPENAI_API_KEY",
        data_dir=data_dir,
        workspace_root=data_dir / "workspaces",
        max_cost_minor_units=10_000,
        max_tokens=100_000,
        max_elapsed_seconds=3_600,
        docker_network="NONE",
        tools={},
    )
    store = SimpleCheckpointStore(
        data_dir / "db" / "sastsimi.sqlite3", artifact_data_dir=data_dir
    )
    display = AnalysisDisplayIdStore(store.database_path).get_or_allocate(
        "analysis-initial"
    )
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id="analysis-initial",
            display_analysis_id=display,
            workspace_id="workspace-1",
            commit_id="a" * 40,
            repository="https://example.invalid/repo.git",
            hypothesis_ids=("hypothesis-1",),
        )
    )
    root = CheckpointIdentity(
        analysis_id="analysis-initial",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    child = root.model_copy(update={"hypothesis_id": "hypothesis-1"})
    for identity, stages in (
        (root, (SimpleStage.STATIC_DONE, SimpleStage.HYPOTHESIS_DONE)),
        (child, (SimpleStage.PRO_CON_DONE,)),
    ):
        for stage in stages:
            store.save_checkpoint(
                StageCheckpoint(
                    identity=identity,
                    stage=stage,
                    stage_version=STAGE_VERSION[stage],
                    status=StageStatus.SUCCEEDED,
                    input_refs=(),
                    input_hash=input_reference_hash(()),
                    output_refs=(_ref(stage.value),),
                )
            )
    artifacts = SimpleArtifactRepository(data_dir, child)
    ref = artifacts.put_json(
        {
            "kind": "simple_initial_verification",
            "attempt_id": "initial-attempt",
            "result": {
                "initial_assessment": "HOLD",
                "unmet_external_prerequisites": ["attacker control unproven"],
            },
        }
    )
    store.save_checkpoint(
        StageCheckpoint(
            identity=child,
            stage=SimpleStage.VERIFICATION_INITIAL_DONE,
            stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(ref,),
            attempt_id="initial-attempt",
            verdict="HOLD",
            external_prerequisites_ref=ref,
        )
    )
    application = PublicSimpleRuntimeApplication(config, profile)
    assert application.status(display)["status"] == "COMPLETE"
    assert DashboardQuery(data_dir).get_analysis(display).status == "COMPLETE"

    artifacts.artifacts.path_for(ref.content_hash).unlink()

    cli_status = application.status(display)
    dashboard = DashboardQuery(data_dir).get_analysis(display)
    assert cli_status["status"] == dashboard.status == "BLOCKED"
    assert cli_status["error_code"] == "INITIAL_VERIFICATION_EVIDENCE_INVALID"
    assert dashboard.error_code == "INITIAL_VERIFICATION_EVIDENCE_INVALID"
    assert cli_status["inconclusive_hypothesis_count"] == 0


def test_dashboard_shows_completed_inconclusive_poc_without_finding(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(
        data_dir / "db" / "sastsimi.sqlite3", artifact_data_dir=data_dir
    )
    display = AnalysisDisplayIdStore(store.database_path).get_or_allocate(
        "analysis-poc"
    )
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id="analysis-poc",
            display_analysis_id=display,
            workspace_id="workspace-1",
            commit_id="a" * 40,
            repository="https://example.invalid/repo.git",
            hypothesis_ids=("hypothesis-poc",),
        )
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-poc",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-poc",
    )
    artifacts = SimpleArtifactRepository(data_dir, identity)
    attempt_id = "poc-attempt-3"
    execution_ref = artifacts.put_json(
        {
            "kind": "simple_poc_execution",
            "attempt_id": attempt_id,
            "timed_out": False,
            "exit_code": 0,
        }
    )
    interpretation_ref = artifacts.put_json(
        {
            "kind": "simple_dynamic_interpretation",
            "execution_ref": execution_ref.model_dump(mode="json"),
            "result": {"outcome": "INCONCLUSIVE"},
        }
    )
    for stage in (
        SimpleStage.PRO_CON_DONE,
        SimpleStage.VERIFICATION_INITIAL_DONE,
        SimpleStage.POC_CANDIDATE_DONE,
        SimpleStage.POC_EXECUTION_DONE,
    ):
        store.save_checkpoint(
            StageCheckpoint(
                identity=identity,
                stage=stage,
                stage_version=STAGE_VERSION[stage],
                status=StageStatus.SUCCEEDED,
                input_refs=(),
                input_hash=input_reference_hash(()),
                output_refs=(execution_ref, interpretation_ref)
                if stage is SimpleStage.POC_EXECUTION_DONE
                else (_ref(stage.value),),
                verdict="HOLD" if stage is SimpleStage.POC_EXECUTION_DONE else None,
                attempt_number=3,
                attempt_id=(
                    attempt_id if stage is SimpleStage.POC_EXECUTION_DONE else None
                ),
            )
        )

    dashboard = DashboardQuery(data_dir).get_analysis(display)

    assert dashboard.status == "COMPLETE"
    assert dashboard.progress_percent == 100
    assert dashboard.finding_count == 0
    assert dashboard.hypotheses[0].disposition == "INCONCLUSIVE"
    assert dashboard.hypotheses[0].validated_poc is False
