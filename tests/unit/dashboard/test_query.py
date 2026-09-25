from __future__ import annotations

import hashlib
from datetime import UTC, datetime

import pytest

from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.dashboard.query import DashboardNotFound, DashboardQuery
from sastsimi.observability.agent_activity import ActivityKind, AgentActivityEvent
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore


def ref(name: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(f"stored-{name}"),
        data_kind="finding",
        content_hash=hashlib.sha256(name.encode()).hexdigest(),
        workspace_id=WorkspaceId("workspace-1"),
        commit_id=CommitId("commit-1"),
        record_id=None,
    )


def seed(data_dir) -> None:
    database = data_dir / "db" / "sastsimi.sqlite3"
    store = SimpleCheckpointStore(database)
    assert AnalysisDisplayIdStore(database).get_or_allocate("analysis-a") == "A-001"
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id="analysis-a",
            display_analysis_id="A-001",
            workspace_id="workspace-1",
            commit_id="commit-1",
            repository="https://example.invalid/repository.git",
            hypothesis_ids=("hypothesis-1",),
            parent_hypothesis_ids={"hypothesis-1": ("parent-1", "parent-2")},
            chain_depths={"hypothesis-1": 1},
        )
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    inputs: tuple[StoredDataRef, ...] = ()
    for stage in (
        SimpleStage.PRO_CON_DONE,
        SimpleStage.VERIFICATION_INITIAL_DONE,
        SimpleStage.POC_CANDIDATE_DONE,
    ):
        output = ref(stage.value.lower())
        store.save_success(
            StageCheckpoint(
                identity=identity,
                stage=stage,
                status=StageStatus.PENDING,
                input_refs=inputs,
                input_hash=input_reference_hash(inputs),
            ),
            outputs=(output,),
        )
        inputs = (output,)
    AgentActivityStore(database).append(
        AgentActivityEvent(
            event_id="event-1",
            analysis_id="analysis-a",
            workspace_id="workspace-1",
            commit_id="commit-1",
            hypothesis_id="hypothesis-1",
            stage="PRO_CON_DONE",
            agent_role="Pro·Con Agents",
            attempt_id="attempt-1",
            sequence=1,
            kind=ActivityKind.EVIDENCE_RECORDED,
            status="SUCCEEDED",
            summary_ko="찬성·반대 근거를 저장했습니다.",
            started_at=datetime.now(UTC),
        )
    )
    finding = ref("finding")
    assert (
        FindingDisplayIdStore(database).get_or_allocate("analysis-a", finding)
        == "F-001"
    )
    report = data_dir / "reports" / "analysis-a" / "F-001.md"
    report.parent.mkdir(parents=True)
    report.write_text("# report", encoding="utf-8")


def test_query_projects_current_progress_without_cross_analysis_data(tmp_path) -> None:
    seed(tmp_path)
    detail = DashboardQuery(tmp_path).get_analysis("analysis-a")

    assert detail.analysis_id == "analysis-a"
    assert detail.completed_count == 3
    assert all(item.analysis_id == "analysis-a" for item in detail.hypotheses)
    assert "C:\\" not in detail.model_dump_json()
    assert detail.reports[0].display_id == "F-001"
    assert detail.reports[0].english_available is False
    assert detail.display_analysis_id == "A-001"
    assert detail.progress_percent < 100
    assert detail.hypotheses[0].parent_hypothesis_ids == ("parent-1", "parent-2")
    assert DashboardQuery(tmp_path).get_analysis("A-001").analysis_id == "analysis-a"
    assert DashboardQuery(tmp_path).list_events("analysis-a")[0].agent_role == (
        "Pro·Con Agents"
    )
    assert DashboardQuery(tmp_path).list_events(
        "analysis-a", after_event_id="event-1"
    ) == ()


def test_failure_guidance_maps_common_recovery_actions() -> None:
    assert "인증" in (DashboardQuery._failure_guidance("PROVIDER_AUTH_FAILED") or "")
    assert "Docker" in (DashboardQuery._failure_guidance("SANDBOX_FAILED") or "")
    assert "CodeQL" in (DashboardQuery._failure_guidance("CODEQL_QUERY_FAILED") or "")
    assert DashboardQuery._failure_guidance(None) is None


def test_report_path_rejects_traversal_and_unknown_report(tmp_path) -> None:
    seed(tmp_path)
    query = DashboardQuery(tmp_path)

    with pytest.raises(DashboardNotFound):
        query.report_path("analysis-a", "../F-001")
    with pytest.raises(DashboardNotFound):
        query.report_path("analysis-a", "F-999")
    assert query.report_path("analysis-a", "F-001").name == "F-001.md"


# mypy: disable-error-code="no-untyped-def"
