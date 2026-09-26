from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.dashboard.query import DashboardNotFound, DashboardQuery
from sastsimi.observability.agent_activity import ActivityKind, AgentActivityEvent
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore
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
    for attempt_number, stage in enumerate(
        (
            SimpleStage.PRO_CON_DONE,
            SimpleStage.VERIFICATION_INITIAL_DONE,
            SimpleStage.POC_CANDIDATE_DONE,
        ),
        start=1,
    ):
        output = ref(stage.value.lower())
        store.save_success(
            StageCheckpoint(
                identity=identity,
                stage=stage,
                status=StageStatus.PENDING,
                input_refs=inputs,
                input_hash=input_reference_hash(inputs),
                attempt_number=attempt_number,
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
    assert detail.reports == ()
    assert detail.display_analysis_id == "A-001"
    assert detail.progress_percent < 100
    assert detail.hypotheses[0].parent_hypothesis_ids == ("parent-1", "parent-2")
    assert detail.hypotheses[0].attempt_number == 3
    assert detail.hypotheses[0].attempt_limit == 3
    assert DashboardQuery(tmp_path).get_analysis("A-001").analysis_id == "analysis-a"
    assert DashboardQuery(tmp_path).list_events("analysis-a")[0].agent_role == (
        "Pro·Con Agents"
    )


def test_report_path_rejects_traversal_and_unknown_report(tmp_path) -> None:
    seed(tmp_path)
    query = DashboardQuery(tmp_path)

    with pytest.raises(DashboardNotFound):
        query.report_path("analysis-a", "../F-001")
    with pytest.raises(DashboardNotFound):
        query.report_path("analysis-a", "F-999")
    with pytest.raises(DashboardNotFound):
        query.report_path("analysis-a", "F-001")


def test_stale_report_without_current_gate_accept_is_not_exposed(tmp_path) -> None:
    seed(tmp_path)
    query = DashboardQuery(tmp_path)

    assert query.get_analysis("analysis-a").reports == ()
    with pytest.raises(DashboardNotFound):
        query.report_path("analysis-a", "F-001")


def test_current_accepted_report_remains_accessible(tmp_path) -> None:
    seed(tmp_path)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    gate_ref = artifacts.put_json(
        {"kind": "simple_technical_gate", "result": {"status": "ACCEPT"}}
    )
    finding_ref = ref("finding")
    report_path = tmp_path / "reports" / "analysis-a" / "F-001.md"
    for stage, outputs in (
        (SimpleStage.TECH_GATE_DONE, (gate_ref,)),
        (SimpleStage.FINDING_DONE, (finding_ref,)),
        (
            SimpleStage.REPORT_DONE,
            (
                artifacts.put_json({"kind": "draft"}),
                artifacts.put_bytes(b"# report", "text/markdown"),
            ),
        ),
    ):
        inputs = (finding_ref,) if stage is SimpleStage.REPORT_DONE else ()
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

    query = DashboardQuery(tmp_path)
    detail = query.get_analysis("analysis-a")

    assert detail.reports[0].display_id == "F-001"
    assert query.report_path("analysis-a", "F-001") == report_path


def test_claude_usage_shows_unknown_cost_and_generic_on_demand_warning(
    tmp_path,
) -> None:
    seed(tmp_path)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    run = store.require_analysis_run("analysis-a")
    store.save_analysis_run(
        run.model_copy(
            update={
                "llm_provider": "claude",
                "on_demand_possible": True,
            }
        )
    )
    store.record_llm_attempt(
        attempt_id="claude-attempt",
        analysis_id="analysis-a",
        agent="hypothesis",
        model="operator-model",
        attempt_number=1,
        status="SUCCEEDED",
        elapsed_ms=100,
        input_tokens=12,
        output_tokens=3,
        cost_cents=None,
        artifact_ref=ref("attempt"),
    )

    detail = DashboardQuery(tmp_path).get_analysis("analysis-a")

    assert detail.on_demand_possible is True
    assert detail.llm_attempt_count == 1
    assert detail.llm_input_tokens == 12
    assert detail.llm_unknown_cost_calls == 1
    assert detail.llm_cost_minor_units is None
    script = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "sastsimi"
        / "dashboard"
        / "static"
        / "app.js"
    )
    assert "추가 사용량 과금 가능" in script.read_text(encoding="utf-8")
    assert "Cursor 추가 사용량 과금 가능" not in script.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("decision", "revisions", "expected_disposition"),
    [("REJECT", 0, "REJECT"), ("REVISE", 2, "INCONCLUSIVE")],
)
def test_terminal_gate_projects_complete_without_report_or_resume_hint(
    tmp_path: Path, decision: str, revisions: int, expected_disposition: str
) -> None:
    database = tmp_path / "db" / "sastsimi.sqlite3"
    store = SimpleCheckpointStore(database)
    AnalysisDisplayIdStore(database).get_or_allocate("analysis-a")
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id="analysis-a",
            display_analysis_id="A-001",
            workspace_id="workspace-1",
            commit_id="commit-1",
            repository="https://example.invalid/repository.git",
            hypothesis_ids=("hypothesis-1",),
        )
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
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
                output_refs=(ref(stage.value),),
                verdict="TRUE"
                if stage is SimpleStage.VERIFICATION_FINAL_DONE
                else None,
                gate_decision=decision if stage is SimpleStage.TECH_GATE_DONE else None,
                gate_revision_count=revisions,
            )
        )

    detail = DashboardQuery(tmp_path).get_analysis("A-001")

    assert detail.status == "COMPLETE"
    assert detail.progress_percent == 100
    assert detail.finding_count == 0
    assert detail.reports == ()
    assert detail.inconclusive_hypothesis_count == (decision == "REVISE")
    assert detail.rejected_hypothesis_count == (decision == "REJECT")
    assert detail.hypotheses[0].status == "COMPLETE"
    assert detail.hypotheses[0].disposition == expected_disposition
    assert detail.hypotheses[0].resume_available is False
    assert detail.hypotheses[0].error_code is None


# mypy: disable-error-code="no-untyped-def"
