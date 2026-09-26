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
