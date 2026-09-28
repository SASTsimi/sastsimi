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
from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
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


def test_dashboard_shows_completed_inconclusive_poc_without_finding(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
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
                output_refs=(_ref(stage.value), _ref("interpretation"))
                if stage is SimpleStage.POC_EXECUTION_DONE
                else (_ref(stage.value),),
                verdict="HOLD" if stage is SimpleStage.POC_EXECUTION_DONE else None,
                attempt_number=3,
            )
        )

    dashboard = DashboardQuery(data_dir).get_analysis(display)

    assert dashboard.status == "COMPLETE"
    assert dashboard.progress_percent == 100
    assert dashboard.finding_count == 0
    assert dashboard.hypotheses[0].disposition == "INCONCLUSIVE"
    assert dashboard.hypotheses[0].validated_poc is False
