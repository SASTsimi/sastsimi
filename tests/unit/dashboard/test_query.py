from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from unittest.mock import patch

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import CommitId, RecordId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.dashboard.query import (
    DashboardIncomplete,
    DashboardNotFound,
    DashboardQuery,
)
from sastsimi.observability.agent_activity import ActivityKind, AgentActivityEvent
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.reporting.bundle_files import PublishedBundle, parse_bundle_manifest
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attack_surfaces import AttackSurface, SurfaceIndex
from sastsimi.simple_runtime.candidates import normalize_candidate_page
from sastsimi.simple_runtime.finding_flow import FlowAnchor
from sastsimi.simple_runtime.finding_groups import (
    VerifiedFindingMember,
    group_verified_findings,
)
from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
    STAGE_VERSION,
    CandidateTerminal,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.run_lease import analysis_run_lease
from sastsimi.simple_runtime.scope_policy import validate_scope_decision
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.support.current_bundle import attach_current_bundle


def ref(name: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(f"stored-{name}"),
        data_kind="finding",
        content_hash=hashlib.sha256(name.encode()).hexdigest(),
        workspace_id=WorkspaceId("workspace-1"),
        commit_id=CommitId("commit-1"),
        record_id=RecordId("record-finding") if name == "finding" else None,
    )


def test_public_artifact_reader_never_loads_unbounded_cas(tmp_path: Path) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    repository = SimpleArtifactRepository(tmp_path, identity)
    artifact_ref = repository.put_json({"kind": "example"})
    with patch.object(repository, "read", side_effect=AssertionError("unbounded")):
        media, raw, parsed = DashboardQuery(tmp_path)._safe_ref_bytes(
            repository, artifact_ref
        )
    assert media == "application/json"
    assert parsed == {"kind": "example"}
    assert raw == b'{"kind":"example"}'


@pytest.mark.parametrize(
    "body, media_type",
    (
        (b"# Report\nfile:///C:/Users/alice/private/repo\n", "text/markdown"),
        (b'{"repository":"file:///C:/Users/alice/private/repo"}', "application/json"),
        (
            json.dumps({"payload": r'{"uri":"file\u003a///private/repo"}'}).encode(),
            "application/json",
        ),
        (
            json.dumps({"payload": '{"uri":"file:///private/repo"}'}).encode(),
            "application/json",
        ),
    ),
)
def test_public_artifact_reader_redacts_legacy_local_file_urls(
    tmp_path: Path, body: bytes, media_type: str
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    repository = SimpleArtifactRepository(tmp_path, identity)
    artifact_ref = repository.put_bytes(body, media_type)

    _, projected, parsed = DashboardQuery(tmp_path)._safe_ref_bytes(
        repository, artifact_ref
    )
    assert b"file:" not in projected.lower()
    assert b"[REDACTED:LOCAL_FILE_URL]" in projected
    if isinstance(parsed, dict) and "payload" in parsed:
        assert json.loads(parsed["payload"])["uri"] == "[REDACTED:LOCAL_FILE_URL]"


def test_local_policy_snapshot_keeps_projection_complete(tmp_path: Path) -> None:
    seed(tmp_path)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    run = store.require_analysis_run("analysis-a")
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    repository = SimpleArtifactRepository(tmp_path, identity)
    snapshot_ref = repository.put_json(
        {
            "kind": "simple_policy_snapshot",
            "target_repository": "file:///C:/Users/alice/private/repo",
        }
    )
    projected_run = run.model_copy(update={"repository_profile_ref": snapshot_ref})

    _, contents, _, _, _, omitted = DashboardQuery(tmp_path)._artifact_projection(
        "analysis-a", [], projected_run
    )

    assert omitted == 0
    assert snapshot_ref.content_hash in contents
    assert b"file:" not in contents[snapshot_ref.content_hash][2].lower()


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
        store.save_checkpoint(
            StageCheckpoint(
                identity=identity,
                stage=stage,
                status=StageStatus.SUCCEEDED,
                input_refs=inputs,
                input_hash=input_reference_hash(inputs),
                output_refs=(output,),
                attempt_number=attempt_number,
                updated_at=datetime(2026, 1, 1, tzinfo=UTC)
                + timedelta(seconds=attempt_number),
            ),
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


def test_public_analysis_repository_hides_local_file_url(tmp_path: Path) -> None:
    seed(tmp_path)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    run = store.require_analysis_run("analysis-a")
    store.save_analysis_run(
        run.model_copy(update={"repository": "file:///C:/Users/alice/private/repo"})
    )

    query = DashboardQuery(tmp_path)
    assert query.get_analysis("analysis-a").repository == "[REDACTED:LOCAL_FILE_URL]"
    assert query.list_analyses()[0].repository == "[REDACTED:LOCAL_FILE_URL]"


def test_public_scope_review_redacts_nested_local_url(tmp_path: Path) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    review = {
        "status": "UNCERTAIN",
        "policy_source": {"collection_status": "file:///private/status"},
        "checks": ["file:///private/reason"],
        "axes": {"reporting": {"reason": "file:///private/model-reason"}},
    }

    with patch("sastsimi.dashboard.query.project_scope_review", return_value=review):
        public = DashboardQuery(tmp_path)._scope_review(identity, None, None)

    assert "file:" not in json.dumps(public).lower()
    assert "[REDACTED:LOCAL_FILE_URL]" in json.dumps(public)


def test_public_events_and_logs_redact_local_urls_without_breaking_json(
    tmp_path: Path,
) -> None:
    seed(tmp_path)
    activity = AgentActivityStore(tmp_path / "db" / "sastsimi.sqlite3")
    activity.append(
        AgentActivityEvent(
            event_id="event-local-url",
            analysis_id="analysis-a",
            workspace_id="workspace-1",
            commit_id="commit-1",
            hypothesis_id=None,
            stage="PRO_CON_DONE",
            agent_role="Pro·Con Agents",
            attempt_id="attempt-local-url",
            sequence=2,
            kind=ActivityKind.EVIDENCE_RECORDED,
            status="SUCCEEDED",
            summary_ko="file:///private/repo",
            provider="file:///private/provider",
            model="file:///private/model",
            started_at=datetime.now(UTC),
        )
    )
    logs = tmp_path / "logs" / "analysis-a.log"
    logs.parent.mkdir(parents=True, exist_ok=True)
    logs.write_text(
        json.dumps({"summary_ko": "file:///private/repo", "status": "RUNNING"}) + "\n",
        encoding="utf-8",
    )

    query = DashboardQuery(tmp_path)
    assert "file:" not in query.list_events("analysis-a")[-1].summary_ko.lower()
    assert (
        "file:"
        not in json.dumps(
            query.get_analysis("analysis-a").model_dump(mode="json")
        ).lower()
    )
    rows = [json.loads(line) for line in query.logs_bytes("analysis-a").splitlines()]
    assert len(rows) == 1
    assert rows[0]["status"] == "RUNNING"
    assert "file:" not in rows[0]["summary_ko"].lower()


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


def test_dashboard_summary_paths_do_not_materialize_report_bundles(
    tmp_path: Path,
) -> None:
    seed(tmp_path)
    query = DashboardQuery(tmp_path)

    with patch.object(
        query, "_reports", side_effect=AssertionError("report bundles loaded")
    ):
        listed = query.list_analyses()
        shell = query.get_analysis_shell("A-001")

    assert len(listed) == 1
    assert listed[0].analysis_id == "analysis-a"
    assert shell.analysis_id == "analysis-a"


def test_dashboard_stale_warning_requires_no_active_run_lease(tmp_path: Path) -> None:
    seed(tmp_path)
    query = DashboardQuery(tmp_path)

    idle = query.get_analysis("A-001")
    assert idle.status == "RUNNING"
    assert idle.stale is True

    with analysis_run_lease(tmp_path, "analysis-a"):
        active = query.get_analysis("A-001")
        assert active.status == "RUNNING"
        assert active.stale is False
        assert query.list_analyses()[0].stale is False


def test_dashboard_marks_unleased_candidate_run_interrupted_without_rewriting_it(
    tmp_path: Path,
) -> None:
    seed(tmp_path)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    run = store.require_analysis_run("analysis-a")
    store.save_analysis_run(run.model_copy(update={"candidate_pipeline_version": 1}))
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    store.mark_running(identity, SimpleStage.STATIC_DONE, (), attempt_id="static-1")
    query = DashboardQuery(tmp_path)

    idle = query.get_analysis("A-001")
    assert idle.status == "PAUSED"
    assert idle.error_code == "INTERRUPTED_RESUME_REQUIRED"
    assert idle.resume_action == "RESUME_INTERRUPTED"
    assert query.list_analyses()[0].status == "PAUSED"
    with analysis_run_lease(tmp_path, "analysis-a"):
        assert query.get_analysis("A-001").status == "RUNNING"
    checkpoint = store.get(identity, SimpleStage.STATIC_DONE)
    assert checkpoint is not None
    assert checkpoint.status is StageStatus.RUNNING


def test_dashboard_prioritizes_unresolved_codex_call_over_interrupted_resume(
    tmp_path: Path,
) -> None:
    seed(tmp_path)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    run = store.require_analysis_run("analysis-a")
    store.save_analysis_run(run.model_copy(update={"candidate_pipeline_version": 1}))
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    store.mark_running(identity, SimpleStage.STATIC_DONE, (), attempt_id="static-1")
    assert store.begin_codex_call("unresolved-call", "analysis-a")

    query = DashboardQuery(tmp_path)
    with analysis_run_lease(tmp_path, "analysis-a"):
        active = query.get_analysis("A-001")
        assert active.status == "RUNNING"
        assert active.error_code != "CODEX_CALL_IN_FLIGHT_UNRESOLVED"
        assert query.list_analyses()[0].status == "RUNNING"

    detail = query.get_analysis("A-001")

    assert detail.status == "BLOCKED"
    assert detail.error_code == "CODEX_CALL_IN_FLIGHT_UNRESOLVED"
    assert detail.resume_action == "MANUAL_CODEX_CLEANUP_REVIEW"
    assert query.list_analyses()[0].status == "BLOCKED"


def test_dashboard_requires_review_for_unconfirmed_codex_cleanup(
    tmp_path: Path,
) -> None:
    seed(tmp_path)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    run = store.require_analysis_run("analysis-a")
    store.save_analysis_run(run.model_copy(update={"candidate_pipeline_version": 1}))
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    running = store.mark_running(
        identity, SimpleStage.STATIC_DONE, (), attempt_id="static-1"
    )
    store.save_checkpoint(
        running.model_copy(
            update={
                "status": StageStatus.BLOCKED,
                "error_code": "CODEX_PROCESS_CLEANUP_UNCONFIRMED",
                "retryable": False,
            }
        )
    )

    detail = DashboardQuery(tmp_path).get_analysis("A-001")
    assert detail.status == "BLOCKED"
    assert detail.error_code == "CODEX_PROCESS_CLEANUP_UNCONFIRMED"
    assert detail.resume_action == "MANUAL_CODEX_CLEANUP_REVIEW"


def test_dashboard_shows_resume_only_after_exact_codex_cleanup_confirmation(
    tmp_path: Path,
) -> None:
    seed(tmp_path)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    run = store.require_analysis_run("analysis-a")
    store.save_analysis_run(run.model_copy(update={"candidate_pipeline_version": 1}))
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    running = store.mark_running(
        identity, SimpleStage.STATIC_DONE, (), attempt_id="static-1"
    )
    blocked = running.model_copy(
        update={
            "status": StageStatus.BLOCKED,
            "error_code": "CODEX_PROCESS_CLEANUP_UNCONFIRMED",
            "retryable": False,
        }
    )
    store.save_checkpoint(blocked)
    call_id = "confirmed-call"
    assert store.begin_codex_call(call_id, identity.analysis_id)
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    confirmation = artifacts.put_json(
        {
            "kind": "simple_codex_cleanup_confirmation",
            "analysis_id": identity.analysis_id,
            "stage": blocked.stage.value,
            "attempt_id": blocked.attempt_id,
            "checkpoint_sha256": hashlib.sha256(canonical_bytes(blocked)).hexdigest(),
            "call_id": call_id,
            "process_tree_stopped": True,
            "verification_method": "windows_process_inventory",
            "former_parent_pid": 12345,
            "observed_matching_process_count": 0,
            "observed_at": (blocked.updated_at + timedelta(seconds=1)).isoformat(),
        }
    )
    query = DashboardQuery(tmp_path)
    assert query.get_analysis("A-001").resume_action == "MANUAL_CODEX_CLEANUP_REVIEW"
    store.confirm_codex_cleanup(blocked, confirmation, artifacts)

    with analysis_run_lease(tmp_path, identity.analysis_id):
        assert query.get_analysis("A-001").resume_action != "RESUME_INTERRUPTED"
    resumed = query.get_analysis("A-001")
    assert resumed.status == "PAUSED"
    assert resumed.error_code == "INTERRUPTED_RESUME_REQUIRED"
    assert resumed.resume_action == "RESUME_INTERRUPTED"
    assert query.list_analyses()[0].resume_action == "RESUME_INTERRUPTED"


def test_dashboard_complete_requires_matching_candidate_terminal_marker(
    tmp_path: Path,
) -> None:
    seed(tmp_path)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    run = store.require_analysis_run("analysis-a")
    root = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    bundle_ref = SimpleArtifactRepository(tmp_path, root).put_json(
        {"kind": "simple_static_fact_bundle"}
    )
    for stage in (SimpleStage.STATIC_DONE, SimpleStage.HYPOTHESIS_DONE):
        store.save_checkpoint(
            StageCheckpoint(
                identity=root,
                stage=stage,
                status=StageStatus.SUCCEEDED,
                input_refs=(),
                input_hash=input_reference_hash(()),
            )
        )
    store.save_checkpoint(
        StageCheckpoint(
            identity=root.model_copy(update={"hypothesis_id": "hypothesis-1"}),
            stage=SimpleStage.VERIFICATION_FINAL_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            verdict="FALSE",
        )
    )
    terminal = CandidateTerminal(
        status="COMPLETE",
        bundle_hash=bundle_ref.content_hash,
        scope_fingerprint="scope-1",
        decision_counts={},
        deep_counts={},
        hypothesis_count=1,
    )
    store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_pipeline_version": 1,
                "candidate_scope_fingerprint": "scope-1",
                "static_bundle_ref": bundle_ref,
                "candidate_terminal": terminal,
            }
        )
    )

    query = DashboardQuery(tmp_path)
    assert query.get_analysis("A-001").status == "COMPLETE"
    assert query.list_analyses()[0].status == "COMPLETE"


def _static_identity() -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )


def _attach_static_coverage(
    tmp_path: Path,
    *,
    blocked: bool,
    corrupt: bool = False,
    limitations_only: bool = False,
    scope_metadata: dict[str, object] | None = None,
):
    identity = _static_identity()
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    gaps = [
        {
            "path": f"src/file-{index}.ts",
            "rule_id": "rule.js",
            "reason": "parse_or_scan_error",
        }
        for index in range(105)
    ]
    coverage_ref = artifacts.put_json(
        {
            "kind": "simple_static_coverage_v1",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "fingerprint": "f" * 64,
            "expected_count": 5 if limitations_only else 110,
            "verified_count": 5,
            "gaps": [] if limitations_only else gaps,
            "unsupported": []
            if limitations_only
            else [
                {"extension": ".go", "file_count": 3},
                {"extension": "", "file_count": 1},
            ],
            "unsupported_files": []
            if limitations_only
            else [
                {"path": "tools/launcher", "reason": "unsupported_extension"},
                {"path": "src/driver.go", "reason": "unsupported_extension"},
            ],
            "ast_parse_error_count": 2,
            "ast_oversize_count": 1 if limitations_only else 0,
            "ast_truncated": True,
            "codeql_configured": True,
            "codeql_executed": not blocked,
            "codeql_scope": "python_only",
            "codeql_error": "CODEQL_ANALYZE_FAILED" if limitations_only else None,
            "engine_errors": ["SEMGREP_EXECUTION_FAILED"] if limitations_only else [],
            **(scope_metadata or {}),
        }
    )
    bundle_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "static_coverage_ref": coverage_ref.model_dump(mode="json"),
        }
    )
    if corrupt:
        artifacts.artifacts.path_for(coverage_ref.content_hash).write_bytes(b"corrupt")
    refs = (
        (coverage_ref, bundle_ref)
        if blocked
        else (artifacts.put_json({"kind": "simple_repository_profile"}), bundle_ref)
    )
    SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3").save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.STATIC_DONE,
            status=StageStatus.BLOCKED if blocked else StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=refs,
            error_code="STATIC_COVERAGE_INCOMPLETE" if blocked else None,
            retryable=False,
        )
    )
    return coverage_ref


@pytest.mark.parametrize("blocked", [False, True])
def test_static_coverage_summary_shows_bounded_relative_gaps(
    tmp_path: Path,
    blocked: bool,
) -> None:
    seed(tmp_path)
    _attach_static_coverage(tmp_path, blocked=blocked)
    detail = DashboardQuery(tmp_path).get_analysis("analysis-a")
    assert detail.static_coverage_expected == 110
    assert detail.static_coverage_verified == 5
    assert detail.static_coverage_gap_count == 105
    assert len(detail.static_coverage_gap_preview) == 100
    assert detail.static_coverage_gap_preview[0] == {
        "path": "src/file-0.ts",
        "rule_id": "rule.js",
        "reason": "parse_or_scan_error",
    }
    assert "C:\\" not in detail.model_dump_json()
    assert detail.static_coverage_unsupported == ((".go", 3), ("", 1))
    assert detail.static_coverage_unsupported_count == 2
    assert detail.static_coverage_reason_counts == {
        "ast_parse_errors": 2,
        "parse_or_scan_error": 105,
        "unsupported_extension": 2,
    }
    assert detail.static_ast_parse_error_count == 2
    assert detail.static_ast_truncated is True
    assert detail.static_codeql_configured is True
    assert detail.static_codeql_executed is (not blocked)
    assert detail.static_codeql_scope == "python_only"


def test_partial_without_gaps_exposes_engine_limitation_reasons(tmp_path: Path) -> None:
    seed(tmp_path)
    coverage_ref = _attach_static_coverage(
        tmp_path, blocked=False, limitations_only=True
    )
    query = DashboardQuery(tmp_path)
    run = query._simple_run("analysis-a")
    assert run is not None
    SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3").save_analysis_run(
        run.model_copy(
            update={
                "static_disposition": "PARTIAL",
                "static_coverage_ref": coverage_ref,
            }
        )
    )

    detail = query.get_analysis("analysis-a")
    assert detail.static_disposition == "PARTIAL"
    assert detail.static_coverage_gap_count == 0
    assert detail.static_coverage_unsupported_count == 0
    assert detail.static_coverage_reason_counts == {
        "SEMGREP_EXECUTION_FAILED": 1,
        "ast_oversize_files": 1,
        "ast_parse_errors": 2,
        "codeql_error": 1,
    }


def test_unavailable_python_paths_are_separate_from_pair_gaps_and_pageable(
    tmp_path: Path,
) -> None:
    seed(tmp_path)
    coverage_ref = _attach_static_coverage(
        tmp_path,
        blocked=False,
        limitations_only=True,
        scope_metadata={
            "unavailable_paths": [
                {"path": "src/a.py", "reason": "OPENGREP_EXECUTION_FAILED"},
                {"path": "src/b.py", "reason": "OPENGREP_EXECUTION_FAILED"},
            ]
        },
    )
    query = DashboardQuery(tmp_path)
    run = query._simple_run("analysis-a")
    assert run is not None
    SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3").save_analysis_run(
        run.model_copy(
            update={
                "static_disposition": "PARTIAL",
                "static_coverage_ref": coverage_ref,
            }
        )
    )

    detail = query.get_analysis("A-001")
    assert detail.static_disposition == "PARTIAL"
    assert detail.static_coverage_gap_count == 0
    assert detail.static_coverage_unsupported_count == 0
    assert detail.static_unavailable_file_count == 2
    assert detail.static_unavailable_reason_counts == {"OPENGREP_EXECUTION_FAILED": 2}
    assert detail.static_unavailable_file_preview[0] == {
        "path": "src/a.py",
        "reason": "OPENGREP_EXECUTION_FAILED",
    }
    page = query.get_static_coverage_page(
        "A-001", kind="unavailable", offset=1, limit=1
    )
    assert page.total == 2
    assert page.items == ({"path": "src/b.py", "reason": "OPENGREP_EXECUTION_FAILED"},)
    assert page.coverage_digest == coverage_ref.content_hash


def test_static_coverage_pages_include_full_ledger_and_bounded_limits(
    tmp_path: Path,
) -> None:
    seed(tmp_path)
    coverage_ref = _attach_static_coverage(tmp_path, blocked=False)
    query = DashboardQuery(tmp_path)

    gaps = query.get_static_coverage_page("A-001", kind="gaps", offset=100, limit=20)
    assert gaps.total == gaps.total_items == 105
    assert gaps.page == 6
    assert gaps.page_size == 20
    assert gaps.total_pages == 6
    assert gaps.has_previous is True
    assert gaps.has_next is False
    assert len(gaps.items) == 5
    assert gaps.items[0] == {
        "path": "src/file-100.ts",
        "rule_id": "rule.js",
        "reason": "parse_or_scan_error",
    }
    assert gaps.coverage_digest == coverage_ref.content_hash

    unsupported = query.get_static_coverage_page(
        "analysis-a", kind="unsupported", offset=0, limit=1
    )
    assert unsupported.total == 2
    assert unsupported.items == (
        {"path": "tools/launcher", "reason": "unsupported_extension"},
    )
    with pytest.raises(ValueError):
        query.get_static_coverage_page("analysis-a", kind="gaps", offset=0, limit=101)


def test_dashboard_candidate_counts_are_scope_bound_and_not_duplicated(
    tmp_path: Path,
) -> None:
    seed(tmp_path)
    query = DashboardQuery(tmp_path)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    run = store.require_analysis_run("analysis-a")
    store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_pipeline_version": 1,
                "candidate_scope_fingerprint": "scope-1",
            }
        )
    )
    identity = _static_identity()
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    hits = [
        {
            "check_id": "python.eval",
            "path": "pkg/item.py",
            "start": {"line": index + 1},
            "end": {"line": index + 1},
            "extra": {"message": f"candidate {index}"},
        }
        for index in range(3)
    ]
    ref = artifacts.put_json({"results": hits})
    candidates = normalize_candidate_page(
        identity, "scope-1", "opengrep", ref, tuple(hits), 0
    )
    store.upsert_candidate_page(identity, "scope-1", ref, 0, 3, candidates)
    store.save_candidate_decision(
        identity, "scope-1", candidates[0].candidate_id, "INCLUDE", "input reachable"
    )
    store.save_candidate_deep_status(
        identity, "scope-1", candidates[0].candidate_id, "RUNNING"
    )
    store.save_candidate_decision(
        identity, "scope-1", candidates[1].candidate_id, "EXCLUDE", "test-only call"
    )

    detail = query.get_analysis("analysis-a")
    summary = query.list_analyses()[0]
    assert detail.candidate_total_count == summary.candidate_total_count == 3
    assert detail.candidate_decision_counts == {
        "PENDING": 1,
        "INCLUDE": 1,
        "EXCLUDE": 1,
        "UNDECIDED": 0,
        "ERROR": 0,
    }
    assert detail.deep_analysis_running_count == 1
    assert query.get_analysis("analysis-a").candidate_total_count == 3

    store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_pipeline_version": 2,
                "candidate_scope_fingerprint": "scope-1",
            }
        )
    )
    v2 = query.get_analysis("analysis-a")
    assert v2.candidate_total_count == 3
    assert v2.percentage_kind == "known_checkpoint_fraction"
    assert v2.phase_counts["triage"] == {"completed": 2, "known": 3}

    store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_pipeline_version": 1,
                "candidate_scope_fingerprint": "different-scope",
            }
        )
    )
    assert query.get_analysis("analysis-a").candidate_total_count == 0


def test_v2_dashboard_does_not_complete_a_partially_recorded_surface(
    tmp_path: Path,
) -> None:
    seed(tmp_path)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    run = store.require_analysis_run("analysis-a")
    identity = _static_identity()
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    bundle_ref = artifacts.put_json({"kind": "simple_static_fact_bundle"})
    surfaces = tuple(
        AttackSurface(
            surface_id=f"surface-{index}",
            type="AUTHORIZATION",
            path=f"pkg/item_{index}.py",
            symbol="check_access" + "x" * (1024 * 1024)
            if index == 0
            else "check_access",
            line=index + 1,
            linked_candidate_ids=(),
            evidence_refs=(),
            detector="AST",
        )
        for index in range(2)
    )
    index = SurfaceIndex(
        scope_fingerprint="scope-1",
        static_bundle_hash=bundle_ref.content_hash,
        ast_manifest_hash="ast-hash",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        candidate_inventory_hash="inventory-hash",
        candidate_count=0,
        surfaces=surfaces,
        static_gaps=(),
    )
    index_ref = artifacts.put_json(index.to_json())
    store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_pipeline_version": 2,
                "candidate_scope_fingerprint": "scope-1",
                "static_bundle_ref": bundle_ref,
            }
        )
    )
    store.save_attack_surface_index(
        identity,
        "scope-1",
        static_bundle_hash=bundle_ref.content_hash,
        ast_manifest_hash="ast-hash",
        candidate_inventory_hash="inventory-hash",
        candidate_count=0,
        index_ref=index_ref,
    )
    for context_id in ("part-1", "part-2"):
        result_ref = artifacts.put_json(
            {
                "kind": "simple_surface_hypothesis_result_v1",
                "context_id": context_id,
            }
        )
        store.commit_surface_exploration(
            identity,
            "scope-1",
            "surface-0",
            context_id,
            static_bundle_hash=bundle_ref.content_hash,
            index_hash=index_ref.content_hash,
            context_hash=context_id,
            source_sha256=None,
            status="NO_HYPOTHESIS",
            result_ref=result_ref,
            registrations=(),
        )
        partial = DashboardQuery(tmp_path).get_analysis("analysis-a")
        assert partial.phase_counts["surface"] == {
            "recorded_contexts": 1 if context_id == "part-1" else 2,
            "recorded_surfaces": 1,
            "completed": 0,
            "total": 2,
        }

    query = DashboardQuery(tmp_path)
    detail = query.get_analysis("analysis-a")
    assert detail.phase_counts["surface"] == {
        "recorded_contexts": 2,
        "recorded_surfaces": 1,
        "completed": 0,
        "total": 2,
    }
    assert query.list_analyses()[0].phase_counts["surface"] == {
        "recorded_contexts": 2,
        "recorded_surfaces": 1,
        "completed": 0,
        "total": 2,
    }

    coverage_ref = artifacts.put_json(
        {
            **index.to_json(),
            "kind": "simple_attack_surface_coverage_v1",
            "surfaces": [
                {**surfaces[0].to_json(), "coverage_status": "COVERED"},
                surfaces[1].to_json(),
            ],
            "complete": False,
        }
    )
    missing_coverage_ref = index_ref.model_copy(update={"content_hash": "0" * 64})
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.HYPOTHESIS_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(index_ref, coverage_ref, missing_coverage_ref),
        )
    )
    terminal = CandidateTerminal(
        status="PARTIAL",
        bundle_hash=bundle_ref.content_hash,
        scope_fingerprint="scope-1",
        decision_counts={},
        deep_counts={},
        hypothesis_count=1,
        surface_index_hash=index_ref.content_hash,
        surface_coverage_hash=coverage_ref.content_hash,
        surface_counts={"COVERED": 1, "UNCOVERED": 1, "INSUFFICIENT": 0},
        producer_finished=True,
    )
    store.save_analysis_run(
        store.require_analysis_run("analysis-a").model_copy(
            update={"candidate_terminal": terminal}
        )
    )
    verified = query.get_analysis("analysis-a")
    assert verified.phase_counts["surface"]["completed"] == 1
    assert verified.phase_counts["surface"]["covered"] == 1
    assert verified.phase_counts["surface"]["uncovered"] == 1

    store.save_analysis_run(
        store.require_analysis_run("analysis-a").model_copy(
            update={
                "candidate_terminal": terminal.model_copy(
                    update={"surface_coverage_hash": "0" * 64}
                )
            }
        )
    )
    unverified = query.get_analysis("analysis-a")
    assert unverified.phase_counts["surface"] == {
        "recorded_contexts": 2,
        "recorded_surfaces": 1,
        "completed": 0,
        "total": 2,
    }


def test_dashboard_shows_test_exclusions_and_python_only_scope(
    tmp_path: Path,
) -> None:
    seed(tmp_path)
    _attach_static_coverage(
        tmp_path,
        blocked=False,
        scope_metadata={
            "excluded_test_files": [
                {"path": "tests/test_api.py", "reason": "test-directory:tests"}
            ],
            "out_of_scope_product_files": [
                {"path": "web/app.ts", "reason": "non_python_product_source"}
            ],
        },
    )
    query = DashboardQuery(tmp_path)
    detail = query.get_analysis("analysis-a")

    assert detail.static_excluded_test_file_count == 1
    assert detail.static_excluded_test_file_preview == (
        {"path": "tests/test_api.py", "reason": "test-directory:tests"},
    )
    assert detail.static_out_of_scope_product_count == 1
    assert detail.static_out_of_scope_product_preview == (
        {"path": "web/app.ts", "reason": "non_python_product_source"},
    )
    assert (
        query.get_static_coverage_page(
            "A-001", kind="excluded_tests", offset=0, limit=10
        ).items[0]["path"]
        == "tests/test_api.py"
    )
    assert (
        query.get_static_coverage_page(
            "A-001", kind="out_of_scope", offset=0, limit=10
        ).items[0]["path"]
        == "web/app.ts"
    )


@pytest.mark.parametrize("unsafe_path", [r"C:\secret.py", r"tests\test_api.py"])
def test_dashboard_rejects_unsafe_exclusion_path(
    tmp_path: Path, unsafe_path: str
) -> None:
    seed(tmp_path)
    _attach_static_coverage(
        tmp_path,
        blocked=False,
        scope_metadata={
            "excluded_test_files": [
                {"path": unsafe_path, "reason": "test-directory:tests"}
            ]
        },
    )
    query = DashboardQuery(tmp_path)
    assert query.get_analysis("analysis-a").static_coverage_expected is None
    with pytest.raises(DashboardNotFound):
        query.get_static_coverage_page(
            "analysis-a", kind="excluded_tests", offset=0, limit=10
        )


def test_corrupt_static_coverage_has_no_paginated_ledger(tmp_path: Path) -> None:
    seed(tmp_path)
    _attach_static_coverage(tmp_path, blocked=True, corrupt=True)
    with pytest.raises(DashboardNotFound):
        DashboardQuery(tmp_path).get_static_coverage_page(
            "analysis-a", kind="gaps", offset=0, limit=20
        )


def test_partial_run_disposition_and_coverage_ref_are_projected(tmp_path: Path) -> None:
    seed(tmp_path)
    coverage_ref = _attach_static_coverage(tmp_path, blocked=False)
    query = DashboardQuery(tmp_path)
    run = query._simple_run("analysis-a")
    assert run is not None
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    store.save_analysis_run(
        run.model_copy(
            update={
                "static_disposition": "PARTIAL",
                "static_coverage_ref": coverage_ref,
            }
        )
    )

    detail = query.get_analysis("analysis-a")
    assert detail.static_disposition == "PARTIAL"
    assert detail.static_coverage_digest == coverage_ref.content_hash
    assert query.list_analyses()[0].static_disposition == "PARTIAL"

    store.save_analysis_run(
        run.model_copy(
            update={
                "static_disposition": "PARTIAL",
                "static_coverage_ref": ref("wrong"),
            }
        )
    )
    assert query.get_analysis("analysis-a").static_coverage_expected is None
    with pytest.raises(DashboardNotFound):
        query.get_static_coverage_page("analysis-a", kind="gaps", offset=0, limit=10)


def test_terminal_partial_analysis_has_a_finished_at(tmp_path: Path) -> None:
    seed(tmp_path)
    coverage_ref = _attach_static_coverage(tmp_path, blocked=False)
    database = tmp_path / "db" / "sastsimi.sqlite3"
    store = SimpleCheckpointStore(database)
    run = DashboardQuery(tmp_path)._simple_run("analysis-a")
    assert run is not None
    store.save_analysis_run(
        run.model_copy(
            update={
                "static_disposition": "PARTIAL",
                "static_coverage_ref": coverage_ref,
            }
        )
    )
    root = _static_identity()
    hypothesis = root.model_copy(update={"hypothesis_id": "hypothesis-1"})
    for index, stage in enumerate(
        (SimpleStage.HYPOTHESIS_DONE, *HYPOTHESIS_STAGES), start=1
    ):
        identity = root if stage is SimpleStage.HYPOTHESIS_DONE else hypothesis
        store.save_checkpoint(
            StageCheckpoint(
                identity=identity,
                stage=stage,
                status=StageStatus.SUCCEEDED,
                input_refs=(),
                input_hash=input_reference_hash(()),
                output_refs=(ref(f"terminal-{index}"),),
                attempt_number=100 + index,
                attempt_id=f"terminal-{index}",
                updated_at=datetime(2026, 1, 2, tzinfo=UTC) + timedelta(seconds=index),
            )
        )

    detail = DashboardQuery(tmp_path).get_analysis("analysis-a")
    assert detail.status == "PARTIAL"
    assert detail.finished_at == detail.last_updated_at
    assert detail.started_at is not None
    assert detail.finished_at is not None
    assert detail.elapsed_ms == int(
        (detail.finished_at - detail.started_at).total_seconds() * 1000
    )


def test_corrupt_static_coverage_is_unavailable_not_complete(tmp_path: Path) -> None:
    seed(tmp_path)
    _attach_static_coverage(tmp_path, blocked=True, corrupt=True)
    detail = DashboardQuery(tmp_path).get_analysis("analysis-a")
    assert detail.static_coverage_expected is None
    assert detail.static_coverage_verified is None
    assert detail.static_coverage_gap_count is None
    assert detail.static_coverage_gap_preview == ()


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
    assert detail.reports[0].english_available is False
    assert detail.reports[0].english_view_url is None
    assert detail.reports[0].english_download_url is None
    assert detail.finding_group_count is None
    assert detail.finding_groups == ()
    assert query.report_path("analysis-a", "F-001") == report_path


def _two_current_reports(
    tmp_path: Path, *, attach_bundles: bool = False
) -> tuple[DashboardQuery, StoredDataRef]:
    test_current_accepted_report_remains_accessible(tmp_path)
    database = tmp_path / "db" / "sastsimi.sqlite3"
    store = SimpleCheckpointStore(database)
    run = store.require_analysis_run("analysis-a")
    store.save_analysis_run(
        run.model_copy(update={"hypothesis_ids": (*run.hypothesis_ids, "hypothesis-2")})
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-2",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    finding_ref = artifacts.put_json({"kind": "simple_finding", "id": 2})
    display_id = FindingDisplayIdStore(database).get_or_allocate(
        "analysis-a", finding_ref
    )
    assert display_id == "F-002"
    gate_ref = artifacts.put_json(
        {"kind": "simple_technical_gate", "result": {"status": "ACCEPT"}}
    )
    report_path = tmp_path / "reports" / "analysis-a" / "F-002.md"
    report_path.write_text("# second report", encoding="utf-8")
    for stage, outputs, inputs in (
        (SimpleStage.TECH_GATE_DONE, (gate_ref,), ()),
        (SimpleStage.FINDING_DONE, (finding_ref,), ()),
        (
            SimpleStage.REPORT_DONE,
            (
                artifacts.put_json({"kind": "simple_report_draft"}),
                artifacts.put_bytes(b"# second report", "text/markdown"),
            ),
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
    if attach_bundles:
        first_identity = identity.model_copy(update={"hypothesis_id": "hypothesis-1"})
        attach_current_bundle(tmp_path, first_identity, ref("finding"), "F-001")
        attach_current_bundle(
            tmp_path,
            identity,
            finding_ref,
            "F-002",
            stdout=b"second-proof\n",
        )
    return DashboardQuery(tmp_path), finding_ref


def _export_group_members(*, proven: bool) -> tuple[VerifiedFindingMember, ...]:
    anchor = (
        FlowAnchor(
            route="/ping",
            function="ping",
            source_file="app.py",
            source_line=7,
            source_access="request.args",
            source_key="target",
            def_use_nodes=("target@7",),
            sink_file="app.py",
            sink_line=8,
            sink_callee="os.system",
            sink_argument=0,
            branch_nodes=(),
            cwe="CWE-78",
        )
        if proven
        else None
    )
    return tuple(
        VerifiedFindingMember(
            analysis_id="analysis-a",
            workspace_id="workspace-1",
            commit_id="commit-1",
            display_id=display_id,
            finding_ref=ref(f"export-{display_id}"),
            hypothesis_id=f"hypothesis-{index}",
            validated_poc_ref=ref(f"poc-{display_id}"),
            proposal_ref=ref(f"proposal-{display_id}"),
            cwe_ref=ref(f"cwe-{display_id}"),
            candidate_ids=(),
            candidate_origins=(),
            scope_status="UNCERTAIN",
            anchor=anchor,
            undetermined_reason=None if proven else "FLOW_NOT_RESOLVED",
        )
        for index, display_id in enumerate(("F-001", "F-002"), start=1)
    )


def test_default_bundle_exports_only_proven_group_representative_and_mapping(
    tmp_path: Path,
) -> None:
    query, finding_ref = _two_current_reports(tmp_path, attach_bundles=True)
    grouped = group_verified_findings(_export_group_members(proven=True))
    with patch(
        "sastsimi.dashboard.query.current_report_groups",
        return_value=grouped,
    ):
        detail = query.get_analysis("analysis-a")
        members = query.bundle_members("analysis-a", artifact_ids=frozenset())
        selected = query.bundle_members(
            "analysis-a",
            artifact_ids=frozenset(),
            report_ids=frozenset({"F-002"}),
        )
    assert tuple(report.display_id for report in detail.reports) == ("F-001", "F-002")
    assert detail.finding_group_count == 1
    manifest = json.loads(members["manifest.json"])
    assert [report["display_id"] for report in manifest["reports"]] == [
        "F-001",
        "F-002",
    ]
    assert any(
        artifact["artifact_id"] == finding_ref.content_hash
        for artifact in manifest["artifacts"]
    )
    assert "reports/F-001.md" in members
    assert "reports/F-002.md" not in members
    assert members["reports/originals/F-002/report_kr.md"] == (
        "# 한국어 보고서\n".encode()
    )
    assert members["reports/originals/F-002/report_en.md"] == b"# English report\n"
    assert members["reports/originals/F-002/poc.sh"].startswith(b"#!/bin/sh")
    assert members["reports/originals/F-002/evidence/stdout.txt"] == (b"second-proof\n")
    assert "reports/originals/F-002/evidence/provenance.json" in members
    mapping = json.loads(members["reports/export-selection.json"])
    assert mapping["mode"] == "PROVEN_FLOW_DEDUP"
    assert mapping["groups"] == [
        {
            "group_id": grouped.groups[0].group_id,
            "representative_id": "F-001",
            "member_ids": ["F-001", "F-002"],
            "original_paths": {"F-002": "reports/originals/F-002/"},
        }
    ]
    assert "reports/F-002.md" in selected
    assert "reports/F-001.md" not in selected
    assert "reports/export-selection.json" not in selected
    assert "reports/F-002/poc.sh" in selected
    assert "reports/originals/F-002/poc.sh" not in selected
    assert query.report_content("analysis-a", "F-002") == b"# second report"


def test_default_bundle_preserves_legacy_nonrepresentative_report(
    tmp_path: Path,
) -> None:
    query, _ = _two_current_reports(tmp_path)
    grouped = group_verified_findings(_export_group_members(proven=True))
    with patch(
        "sastsimi.dashboard.query.current_report_groups",
        return_value=grouped,
    ):
        members = query.bundle_members("analysis-a", artifact_ids=frozenset())
    assert "reports/F-002.md" not in members
    assert members["reports/originals/F-002/report_kr.md"] == b"# second report"


def test_default_bundle_rejects_corrupt_nonrepresentative_attachment(
    tmp_path: Path,
) -> None:
    query, _ = _two_current_reports(tmp_path, attach_bundles=True)
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-2",
    )
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    archive_ref = store.require(identity, SimpleStage.REPORT_DONE).bundle_archive_ref
    assert archive_ref is not None
    archive_path = (
        tmp_path
        / "artifacts"
        / "sha256"
        / archive_ref.content_hash[:2]
        / archive_ref.content_hash[2:]
    )
    archive_path.write_bytes(b"corrupted archive")
    grouped = group_verified_findings(_export_group_members(proven=True))
    with patch(
        "sastsimi.dashboard.query.current_report_groups",
        return_value=grouped,
    ):
        with pytest.raises(
            DashboardIncomplete, match="DASHBOARD_REPORT_BUNDLE_UNAVAILABLE"
        ):
            query.bundle_members("analysis-a", artifact_ids=frozenset())
        explicit = query.bundle_members(
            "analysis-a",
            artifact_ids=frozenset(),
            report_ids=frozenset({"F-001"}),
        )
    assert "reports/F-001.md" in explicit
    assert "reports/originals/F-002/report_kr.md" not in explicit


def test_default_bundle_keeps_undetermined_and_incomplete_groups_raw(
    tmp_path: Path,
) -> None:
    query, _ = _two_current_reports(tmp_path)
    complete_but_unknown = group_verified_findings(_export_group_members(proven=False))
    incomplete = group_verified_findings(_export_group_members(proven=True)[:1])
    for projection in (complete_but_unknown, incomplete):
        with patch(
            "sastsimi.dashboard.query.current_report_groups",
            return_value=projection,
        ):
            members = query.bundle_members("analysis-a", artifact_ids=frozenset())
        assert "reports/F-001.md" in members
        assert "reports/F-002.md" in members
        assert "reports/export-selection.json" not in members


def _attach_bundle(tmp_path: Path) -> tuple[CheckpointIdentity, PublishedBundle]:
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    return identity, attach_current_bundle(tmp_path, identity, ref("finding"), "F-001")


def test_dashboard_hides_raw_report_draft_and_response(
    tmp_path: Path,
) -> None:
    test_current_accepted_report_remains_accessible(tmp_path)
    identity, _ = _attach_bundle(tmp_path)
    database = tmp_path / "db" / "sastsimi.sqlite3"
    store = SimpleCheckpointStore(database)
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    draft = artifacts.put_json(
        {
            "kind": "simple_report_draft",
            "result": {"en": {"details": "file:relative/private-source"}},
        }
    )
    response = artifacts.put_json(
        {
            "kind": "simple_llm_response",
            "response": {"en": {"details": "file:relative/private-source"}},
        }
    )
    report = store.require(identity, SimpleStage.REPORT_DONE)
    store.save_checkpoint(
        report.model_copy(
            update={
                "output_refs": (draft, report.output_refs[1]),
                "report_ref": draft,
            }
        )
    )
    AgentActivityStore(database).append(
        AgentActivityEvent(
            event_id="current-report-draft",
            analysis_id=identity.analysis_id,
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            hypothesis_id=identity.hypothesis_id,
            stage=SimpleStage.REPORT_DONE.value,
            agent_role="Reporter Agent",
            attempt_id="current-report-draft",
            sequence=1,
            kind=ActivityKind.DECISION_RECORDED,
            status="SUCCEEDED",
            summary_ko="Report generated",
            output_refs=(draft, report.output_refs[1]),
            tool_result_refs=(response,),
            started_at=datetime.now(UTC),
        )
    )

    query = DashboardQuery(tmp_path)
    assert query.report_content(identity.analysis_id, "F-001") == b"# report"
    markdown_bytes = query.artifact_bytes(
        identity.analysis_id, report.output_refs[1].content_hash
    )[2]
    assert markdown_bytes == b"# report"
    for hidden in (draft, response):
        with pytest.raises(DashboardNotFound):
            query.artifact_content(identity.analysis_id, hidden.content_hash)
        with pytest.raises(DashboardNotFound):
            query.artifact_bytes(identity.analysis_id, hidden.content_hash)


@pytest.mark.parametrize("block_kind", ["root_invalid", "unresolved_call"])
def test_integrity_block_hides_historical_activity_report_refs(
    tmp_path: Path,
    block_kind: str,
) -> None:
    test_current_accepted_report_remains_accessible(tmp_path)
    identity, _ = _attach_bundle(tmp_path)
    database = tmp_path / "db" / "sastsimi.sqlite3"
    store = SimpleCheckpointStore(database)
    run = store.require_analysis_run(identity.analysis_id)
    store.save_analysis_run(run.model_copy(update={"candidate_pipeline_version": 2}))
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    old_finding = artifacts.put_json({"kind": "simple_finding", "old": True})
    old_draft = artifacts.put_json({"kind": "simple_report_draft", "old": True})
    old_report = artifacts.put_bytes(b"# historical report", "text/markdown")
    old_response = artifacts.put_json(
        {"kind": "simple_llm_response", "report": "historical draft"}
    )
    ordinary = artifacts.put_json({"kind": "ordinary_evidence", "valid": True})
    carrier = artifacts.put_json(
        {
            "kind": "ordinary_evidence",
            "nested": {"report_ref": old_report.model_dump(mode="json")},
        }
    )
    activity = AgentActivityStore(database)
    for sequence, stage, outputs, tool_results in (
        (1, SimpleStage.FINDING_DONE, (old_finding,), ()),
        (2, SimpleStage.REPORT_DONE, (old_draft, old_report), (old_response,)),
        (3, SimpleStage.PRO_CON_DONE, (ordinary, carrier), ()),
    ):
        activity.append(
            AgentActivityEvent(
                event_id=f"historical-activity-{sequence}",
                analysis_id=identity.analysis_id,
                workspace_id=identity.workspace_id,
                commit_id=identity.commit_id,
                hypothesis_id=identity.hypothesis_id,
                stage=stage.value,
                agent_role="Agent",
                attempt_id="historical-activity",
                sequence=sequence,
                kind=ActivityKind.EVIDENCE_RECORDED,
                status="SUCCEEDED",
                summary_ko="Historical activity",
                output_refs=outputs,
                tool_result_refs=tool_results,
                started_at=datetime.now(UTC),
            )
        )
    query = DashboardQuery(tmp_path)
    finding_content = query.artifact_content(
        identity.analysis_id, old_finding.content_hash
    )
    assert finding_content.kind == "simple_finding"
    assert query.artifact_bytes(identity.analysis_id, old_report.content_hash)[2] == (
        b"# historical report"
    )

    if block_kind == "unresolved_call":
        assert store.begin_codex_call("orphan-call", identity.analysis_id)
    else:
        root = identity.model_copy(update={"hypothesis_id": None})
        store.save_checkpoint(
            StageCheckpoint(
                identity=root,
                stage=SimpleStage.HYPOTHESIS_DONE,
                status=StageStatus.BLOCKED,
                input_refs=(),
                input_hash=input_reference_hash(()),
                error_code="HYPOTHESIS_EVIDENCE_INVALID",
                retryable=False,
            )
        )

    assert any(
        event.event_id == "historical-activity-2"
        for event in query.list_events(identity.analysis_id)
    )
    assert query.artifact_content(identity.analysis_id, ordinary.content_hash).kind == (
        "ordinary_evidence"
    )
    assert query.artifact_content(identity.analysis_id, carrier.content_hash).kind == (
        "ordinary_evidence"
    )
    for hidden in (old_finding, old_draft, old_report, old_response):
        with pytest.raises(DashboardNotFound):
            query.artifact_content(identity.analysis_id, hidden.content_hash)
        with pytest.raises(DashboardNotFound):
            query.artifact_bytes(identity.analysis_id, hidden.content_hash)


@pytest.mark.parametrize("status", [StageStatus.BLOCKED, StageStatus.FAILED])
def test_candidate_hypothesis_integrity_failure_retracts_current_report(
    tmp_path: Path, status: StageStatus
) -> None:
    test_current_accepted_report_remains_accessible(tmp_path)
    identity, _ = _attach_bundle(tmp_path)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    run = store.require_analysis_run(identity.analysis_id)
    store.save_analysis_run(run.model_copy(update={"candidate_pipeline_version": 2}))
    finding = store.require(identity, SimpleStage.FINDING_DONE)
    store.save_checkpoint(finding.model_copy(update={"verdict": "TRUE"}))
    report = store.require(identity, SimpleStage.REPORT_DONE)
    query = DashboardQuery(tmp_path)
    assert query.report_path(identity.analysis_id, "F-001").is_file()
    before = query.get_analysis(identity.analysis_id)
    assert before.finding_count == 1
    assert before.hypotheses[0].validated_poc is True

    root = identity.model_copy(update={"hypothesis_id": None})
    store.save_checkpoint(
        StageCheckpoint(
            identity=root,
            stage=SimpleStage.HYPOTHESIS_DONE,
            status=status,
            input_refs=(),
            input_hash=input_reference_hash(()),
            error_code="HYPOTHESIS_EVIDENCE_INVALID",
            retryable=False,
        )
    )

    detail = query.get_analysis(identity.analysis_id)
    assert detail.finding_count == 0
    assert detail.reports == ()
    assert detail.hypotheses[0].verdict is None
    assert detail.hypotheses[0].validated_poc is False
    assert query.list_analyses()[0].finding_count == 0
    with pytest.raises(DashboardNotFound):
        query.report_path(identity.analysis_id, "F-001")
    with pytest.raises(DashboardNotFound):
        query.report_content(identity.analysis_id, "F-001")
    with pytest.raises(DashboardNotFound):
        query.report_attachment(identity.analysis_id, "F-001", "bundle.zip")
    with pytest.raises(DashboardNotFound):
        query.artifact_content(identity.analysis_id, report.output_refs[1].content_hash)
    with pytest.raises(DashboardNotFound):
        query.bundle_members(
            identity.analysis_id,
            artifact_ids=frozenset(),
            report_ids=frozenset({"F-001"}),
        )
    assert not any(
        name.startswith("reports/")
        for name in query.bundle_members(identity.analysis_id, artifact_ids=frozenset())
    )


def test_inactive_unresolved_codex_call_retracts_current_dashboard_report(
    tmp_path: Path,
) -> None:
    test_current_accepted_report_remains_accessible(tmp_path)
    identity, _ = _attach_bundle(tmp_path)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    run = store.require_analysis_run(identity.analysis_id)
    store.save_analysis_run(run.model_copy(update={"candidate_pipeline_version": 2}))
    finding = store.require(identity, SimpleStage.FINDING_DONE)
    store.save_checkpoint(finding.model_copy(update={"verdict": "TRUE"}))
    report = store.require(identity, SimpleStage.REPORT_DONE)
    assert store.begin_codex_call("orphan-call", identity.analysis_id)

    query = DashboardQuery(tmp_path)
    detail = query.get_analysis(identity.analysis_id)
    assert detail.status == "BLOCKED"
    assert detail.finding_count == 0
    assert detail.reports == ()
    assert detail.hypotheses[0].verdict is None
    assert detail.hypotheses[0].validated_poc is False
    assert query.list_analyses()[0].finding_count == 0
    with pytest.raises(DashboardNotFound):
        query.report_path(identity.analysis_id, "F-001")
    with pytest.raises(DashboardNotFound):
        query.report_content(identity.analysis_id, "F-001")
    for hidden in (finding.output_refs[0], report.output_refs[1]):
        with pytest.raises(DashboardNotFound):
            query.artifact_content(identity.analysis_id, hidden.content_hash)
    with pytest.raises(DashboardNotFound):
        query.bundle_members(
            identity.analysis_id,
            artifact_ids=frozenset(),
            report_ids=frozenset({"F-001"}),
        )

    with analysis_run_lease(tmp_path, identity.analysis_id):
        active = query.get_analysis(identity.analysis_id)
        assert tuple(item.display_id for item in active.reports) == ("F-001",)
        assert active.finding_count == 1
        assert query.report_content(identity.analysis_id, "F-001") == b"# report"


@pytest.mark.parametrize("block_kind", ["root_invalid", "unresolved_call"])
def test_report_currentness_block_hides_confirmed_dashboard_kpis(
    tmp_path: Path, block_kind: str
) -> None:
    test_current_accepted_report_remains_accessible(tmp_path)
    identity, _ = _attach_bundle(tmp_path)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    run = store.require_analysis_run(identity.analysis_id)
    store.save_analysis_run(run.model_copy(update={"candidate_pipeline_version": 2}))
    finding = store.require(identity, SimpleStage.FINDING_DONE)
    store.save_checkpoint(finding.model_copy(update={"verdict": "TRUE"}))
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.VERIFICATION_FINAL_DONE,
            stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_FINAL_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            verdict="TRUE",
        )
    )

    query = DashboardQuery(tmp_path)
    before = query.get_analysis(identity.analysis_id)
    before_shell = query.get_analysis_shell(identity.analysis_id)
    assert before.confirmed_finding_count == 1
    assert before_shell.kpis.confirmed_findings == 1
    assert before_shell.validated_poc_count == 1

    if block_kind == "unresolved_call":
        assert store.begin_codex_call("orphan-call", identity.analysis_id)
    else:
        root = identity.model_copy(update={"hypothesis_id": None})
        store.save_checkpoint(
            StageCheckpoint(
                identity=root,
                stage=SimpleStage.HYPOTHESIS_DONE,
                status=StageStatus.BLOCKED,
                input_refs=(),
                input_hash=input_reference_hash(()),
                error_code="HYPOTHESIS_EVIDENCE_INVALID",
                retryable=False,
            )
        )

    detail = query.get_analysis(identity.analysis_id)
    shell = query.get_analysis_shell(identity.analysis_id)
    assert detail.finding_count == 0
    assert detail.reports == ()
    assert detail.confirmed_finding_count == 0
    assert shell.kpis.confirmed_findings == 0
    assert shell.validated_poc_count == 0


@pytest.mark.parametrize(
    ("candidate_version", "error_code"),
    [
        (2, "CANDIDATE_CHILD_ERROR:OTHER_CHILD_BLOCKED"),
        (None, "HYPOTHESIS_EVIDENCE_INVALID"),
    ],
)
def test_other_root_failures_keep_previously_verified_report(
    tmp_path: Path, candidate_version: int | None, error_code: str
) -> None:
    test_current_accepted_report_remains_accessible(tmp_path)
    identity, _ = _attach_bundle(tmp_path)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    run = store.require_analysis_run(identity.analysis_id)
    store.save_analysis_run(
        run.model_copy(update={"candidate_pipeline_version": candidate_version})
    )
    root = identity.model_copy(update={"hypothesis_id": None})
    store.save_checkpoint(
        StageCheckpoint(
            identity=root,
            stage=SimpleStage.HYPOTHESIS_DONE,
            status=StageStatus.BLOCKED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            error_code=error_code,
            retryable=False,
        )
    )

    query = DashboardQuery(tmp_path)
    assert query.report_path(identity.analysis_id, "F-001").is_file()
    reports = query.get_analysis(identity.analysis_id).reports
    assert tuple(item.display_id for item in reports) == ("F-001",)


def test_current_bundle_lists_only_verified_attachment_urls(tmp_path) -> None:
    test_current_accepted_report_remains_accessible(tmp_path)
    _attach_bundle(tmp_path)
    query = DashboardQuery(tmp_path)
    report = query.get_analysis("analysis-a").reports[0]

    assert report.attachment_urls["report_en.md"].endswith("/files/report_en.md")
    assert report.english_available is True
    assert report.english_view_url is None
    assert report.english_download_url == report.attachment_urls["report_en.md"]
    assert report.attachment_urls["bundle.zip"].endswith("/bundle.zip")
    assert query.report_attachment("analysis-a", "F-001", "poc.sh")[0] == (
        b"#!/bin/sh\nprintf ok\n"
    )
    assert query.report_attachment("analysis-a", "F-001", "bundle.zip")[1] == (
        "application/zip"
    )
    for invalid in ("../poc.sh", "manifest.json", "other.txt", "evidence/../../poc.sh"):
        with pytest.raises(DashboardNotFound):
            query.report_attachment("analysis-a", "F-001", invalid)


def test_historical_process_local_poc_bundle_is_not_verified_or_downloadable(
    tmp_path: Path,
) -> None:
    test_current_accepted_report_remains_accessible(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    attach_current_bundle(
        tmp_path,
        identity,
        ref("finding"),
        "F-001",
        poc=b"""#!/bin/sh
python3 - <<'PY'
import pickle
class LocalFixture:
    pass
client = app.test_client()
payload = pickle.dumps(LocalFixture())
client.set_cookie('value', payload)
client.get('/cookie')
PY
""",
    )
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    checkpoints = {
        stage: store.require(identity, stage)
        for stage in (
            SimpleStage.POC_CANDIDATE_DONE,
            SimpleStage.POC_EXECUTION_DONE,
            SimpleStage.TECH_GATE_DONE,
            SimpleStage.SCOPE_GATE_DONE,
            SimpleStage.FINDING_DONE,
            SimpleStage.REPORT_DONE,
        )
    }
    with pytest.raises(ValueError, match="BUNDLE_POC_SOURCE_UNVERIFIED"):
        artifacts.verified_report_bundle(
            checkpoints=checkpoints,
            finding_ref=ref("finding"),
            display_id="F-001",
            scope_status="UNCERTAIN",
            public_projection=lambda body: body,
        )

    query = DashboardQuery(tmp_path)
    assert query.get_analysis(identity.analysis_id).reports == ()
    report_ref = checkpoints[SimpleStage.REPORT_DONE].output_refs[1]
    with pytest.raises(DashboardNotFound):
        query.artifact_bytes(identity.analysis_id, report_ref.content_hash)
    for path in ("poc.sh", "bundle.zip"):
        with pytest.raises(DashboardNotFound):
            query.report_attachment(identity.analysis_id, "F-001", path)


def test_legacy_bundle_with_local_file_url_is_not_downloadable(tmp_path: Path) -> None:
    test_current_accepted_report_remains_accessible(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    attach_current_bundle(
        tmp_path,
        identity,
        ref("finding"),
        "F-001",
        report_en=b"# Report\n- Repository: file:///repository/private/repo\n",
        report_kr="# 보고서\n- 저장소: file:///repository/private/repo\n".encode(),
    )

    query = DashboardQuery(tmp_path)
    for name in ("report_en.md", "report_kr.md", "poc.sh", "bundle.zip"):
        with pytest.raises(DashboardNotFound):
            query.report_attachment("analysis-a", "F-001", name)


def test_legacy_bundle_with_provenance_only_local_file_url_is_not_downloadable(
    tmp_path: Path,
) -> None:
    test_current_accepted_report_remains_accessible(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    attach_current_bundle(
        tmp_path,
        identity,
        ref("finding"),
        "F-001",
        provenance_origin="file:///repository/private/repo",
    )

    query = DashboardQuery(tmp_path)
    for name in ("evidence/provenance.json", "poc.sh", "bundle.zip"):
        with pytest.raises(DashboardNotFound):
            query.report_attachment("analysis-a", "F-001", name)


def test_sandbox_only_file_url_in_verified_shell_poc_remains_downloadable(
    tmp_path: Path,
) -> None:
    test_current_accepted_report_remains_accessible(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    safe_poc = b"#!/bin/sh\nprintf file:///tmp/sastsimi-poc-candidate\n"
    attach_current_bundle(tmp_path, identity, ref("finding"), "F-001", poc=safe_poc)

    body, _ = DashboardQuery(tmp_path).report_attachment(
        "analysis-a", "F-001", "poc.sh"
    )

    assert body == safe_poc


def test_sandbox_file_url_in_execution_stdout_keeps_verified_bundle(
    tmp_path: Path,
) -> None:
    test_current_accepted_report_remains_accessible(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    uri = b"file:///tmp/sastsimi-poc-candidate"
    attach_current_bundle(
        tmp_path,
        identity,
        ref("finding"),
        "F-001",
        poc=b"#!/bin/sh\nprintf " + uri + b"\n",
        stdout=uri + b"\n",
    )

    body, _ = DashboardQuery(tmp_path).report_attachment(
        "analysis-a", "F-001", "bundle.zip"
    )

    assert body


def test_host_file_url_in_shell_poc_is_rejected(tmp_path: Path) -> None:
    test_current_accepted_report_remains_accessible(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    unsafe_poc = b"#!/bin/sh\nprintf file:///C:/Users/alice/private/repo\n"
    with pytest.raises(ValueError, match="BUNDLE_FILE_UNSAFE"):
        attach_current_bundle(
            tmp_path, identity, ref("finding"), "F-001", poc=unsafe_poc
        )


def test_bundle_rejects_poc_without_current_execution_closure(tmp_path) -> None:
    test_current_accepted_report_remains_accessible(tmp_path)
    identity, _ = _attach_bundle(tmp_path)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    unrelated = SimpleArtifactRepository(tmp_path, identity).put_bytes(
        b"#!/bin/sh\nprintf different\n", "text/x-shellscript"
    )
    store.save_checkpoint(
        candidate.model_copy(
            update={
                "output_refs": (candidate.output_refs[0], unrelated),
            }
        )
    )
    with pytest.raises(DashboardNotFound):
        DashboardQuery(tmp_path).report_attachment("analysis-a", "F-001", "poc.sh")


def test_bundle_download_fails_for_missing_manifest_and_legacy_allow(tmp_path) -> None:
    test_current_accepted_report_remains_accessible(tmp_path)
    query = DashboardQuery(tmp_path)
    with pytest.raises(DashboardNotFound):
        query.report_attachment("analysis-a", "F-001", "poc.sh")

    identity, _ = _attach_bundle(tmp_path)
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    scope_ref = artifacts.put_json({"result": {"status": "ALLOW"}})
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.SCOPE_GATE_DONE,
            stage_version=STAGE_VERSION[SimpleStage.SCOPE_GATE_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(scope_ref,),
        )
    )
    with pytest.raises(DashboardNotFound):
        query.report_attachment("analysis-a", "F-001", "poc.sh")


def test_bundle_download_rejects_tampered_cas_and_stale_finding(tmp_path) -> None:
    test_current_accepted_report_remains_accessible(tmp_path)
    identity, bundle = _attach_bundle(tmp_path)
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    manifest = parse_bundle_manifest(
        artifacts.read(bundle.manifest_ref), finding_ref=ref("finding")
    )
    poc_ref = next(
        item.artifact_ref for item in manifest.files if item.path == "poc.sh"
    )
    query = DashboardQuery(tmp_path)
    assert query.report_attachment("analysis-a", "F-001", "poc.sh")[0]
    artifacts.artifacts.path_for(poc_ref.content_hash).write_bytes(b"tampered")
    with pytest.raises(DashboardNotFound):
        query.report_attachment("analysis-a", "F-001", "poc.sh")
    with pytest.raises(DashboardNotFound):
        query.report_attachment("analysis-a", "F-001", "bundle.zip")

    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    report = store.require(identity, SimpleStage.REPORT_DONE)
    stale_input = ref("unrelated")
    store.save_checkpoint(
        report.model_copy(
            update={
                "input_refs": (stale_input,),
                "input_hash": input_reference_hash((stale_input,)),
            }
        )
    )
    with pytest.raises(DashboardNotFound):
        query.report_attachment("analysis-a", "F-001", "report_en.md")


def test_dashboard_does_not_treat_legacy_allow_as_report_permission(tmp_path) -> None:
    seed(tmp_path)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    scope_ref = artifacts.put_json({"result": {"status": "ALLOW"}})
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.SCOPE_GATE_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(scope_ref,),
        )
    )

    hypothesis = DashboardQuery(tmp_path).get_analysis("analysis-a").hypotheses[0]

    assert hypothesis.scope_status == "UNCERTAIN"
    assert hypothesis.scope_collection_status == "UNVERIFIED"
    assert hypothesis.external_disclosure_allowed is False
    assert "POLICY" in " ".join(hypothesis.scope_reasons)


def test_dashboard_shows_verified_allow_source_and_all_citations(tmp_path) -> None:
    seed(tmp_path)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    lines = (
        "# Security policy",
        "Researchers may report vulnerabilities.",
        "The app release is in scope.",
        "High impact vulnerabilities are eligible.",
        "Local proof-of-concept testing is permitted.",
        "Private reports are accepted.",
    )
    body = "\n".join(lines).encode()
    body_ref = artifacts.put_bytes(body, "text/markdown")
    blob_sha = hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body)
    snapshot = {
        "kind": "simple_policy_snapshot",
        "version": 1,
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "target_repository": "https://github.com/acme/app",
        "status": "FOUND",
        "reason_code": "POLICY_FOUND",
        "source_kind": "github_contents_api",
        "owner": "acme",
        "repo": "app",
        "publisher": "acme/app",
        "source_url": "https://api.github.com/repos/acme/app/contents/SECURITY.md?ref=main",
        "source_path": "SECURITY.md",
        "blob_sha": blob_sha.hexdigest(),
        "content_type": "text/markdown",
        "checked_at": datetime.now(UTC),
        "body_sha256": hashlib.sha256(body).hexdigest(),
        "body_ref": body_ref.model_dump(mode="json"),
    }
    snapshot_ref = artifacts.put_json(snapshot)
    names = ("rules", "asset_scope", "impact", "testing", "reporting")
    model_result = {
        "rationale": "All five conditions are explicitly stated.",
        "restrictions": [],
        "testing_restriction_compliance": "PASS",
        "testing_poc_quote": "printf 'LOCAL_POC_METHOD_MARKER\\n'",
        "axes": {
            name: {
                "status": "PASS",
                "line": index,
                "quote": lines[index - 1],
                "reason": "Applies to the local test",
            }
            for index, name in enumerate(names, start=2)
        },
    }
    script = b"#!/bin/sh\nprintf 'LOCAL_POC_METHOD_MARKER\\n'\n"
    content_ref = artifacts.put_bytes(script, "text/x-shellscript")
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "content_ref": content_ref.model_dump(mode="json"),
            "attempt_id": "candidate-attempt",
        }
    )
    execution_ref = artifacts.put_json(
        {
            "kind": "simple_poc_execution",
            "candidate_ref": candidate_ref.model_dump(mode="json"),
            "content_ref": content_ref.model_dump(mode="json"),
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
    decision = validate_scope_decision(
        snapshot, body.decode(), model_result, poc_evidence_text=script.decode()
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
            "result": decision,
            "attempt_id": "scope-attempt",
        }
    )
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.SCOPE_GATE_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(snapshot_ref,),
            input_hash=input_reference_hash((snapshot_ref,)),
            output_refs=(gate_ref,),
            attempt_id="scope-attempt",
        )
    )
    run = store.require_analysis_run("analysis-a")
    store.save_analysis_run(
        run.model_copy(
            update={
                "repository": "https://github.com/acme/app",
                "policy_snapshot_ref": snapshot_ref,
            }
        )
    )

    hypothesis = DashboardQuery(tmp_path).get_analysis("analysis-a").hypotheses[0]

    assert hypothesis.scope_status == "ALLOW"
    assert hypothesis.scope_collection_status == "FOUND"
    assert hypothesis.scope_source_url == snapshot["source_url"]
    assert hypothesis.scope_source_revision == snapshot["blob_sha"]
    assert hypothesis.private_reporting_policy_passed is True
    assert hypothesis.external_disclosure_allowed is False
    assert set(hypothesis.scope_axes) == set(names)
    assert all(axis["quote"] for axis in hypothesis.scope_axes.values())


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


def test_unknown_codex_token_usage_is_explicit_in_dashboard(tmp_path) -> None:
    seed(tmp_path)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    store.record_llm_attempt(
        attempt_id="unverified-codex-call",
        analysis_id="analysis-a",
        agent="hypothesis",
        model="operator-model",
        attempt_number=1,
        status="CODEX_USAGE_UNAVAILABLE",
        elapsed_ms=0,
        input_tokens=None,
        output_tokens=None,
        cost_cents=None,
        artifact_ref=ref("unverified-codex-usage"),
    )

    detail = DashboardQuery(tmp_path).get_analysis("analysis-a")

    assert detail.llm_attempt_count == 1
    assert detail.llm_input_tokens == 0
    assert detail.llm_output_tokens == 0
    assert detail.llm_unknown_token_calls == 1
    script = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "sastsimi"
        / "dashboard"
        / "static"
        / "app.js"
    )
    assert "토큰 미확인 호출" in script.read_text(encoding="utf-8")
    assert "Cursor 추가 사용량 과금 가능" not in script.read_text(encoding="utf-8")


def test_in_flight_codex_call_without_attempt_is_visible_as_possible_usage(
    tmp_path: Path,
) -> None:
    seed(tmp_path)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    assert store.begin_codex_call("unrecorded-call", "analysis-a")

    detail = DashboardQuery(tmp_path).get_analysis("analysis-a")
    assert detail.llm_attempt_count == 1
    assert detail.llm_unknown_token_calls == 1
    assert detail.llm_unknown_cost_calls == 1
    assert detail.llm_unrecorded_in_flight_codex_calls == 1
    script = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "sastsimi"
        / "dashboard"
        / "static"
        / "app.js"
    )
    assert "진행·종료 미확인 Codex 호출" in script.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    ("decision", "revisions", "expected_disposition"),
    [("REJECT", 0, "REJECT"), ("REVISE", 2, "INCONCLUSIVE")],
)
def test_terminal_gate_projects_complete_without_report_or_resume_hint(
    tmp_path: Path,
    decision: Literal["REJECT", "REVISE"],
    revisions: int,
    expected_disposition: str,
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


@pytest.mark.parametrize(
    "stage",
    (SimpleStage.VERIFICATION_INITIAL_DONE, SimpleStage.POC_EXECUTION_DONE),
)
def test_status_cells_keep_verified_terminal_hold_complete(
    tmp_path: Path, stage: SimpleStage
) -> None:
    database = tmp_path / "db" / "sastsimi.sqlite3"
    store = SimpleCheckpointStore(database, artifact_data_dir=tmp_path)
    display = AnalysisDisplayIdStore(database).get_or_allocate("analysis-a")
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id="analysis-a",
            display_analysis_id=display,
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
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    attempt_id = "terminal-attempt"
    external_prerequisites_ref: StoredDataRef | None = None
    output_refs: tuple[StoredDataRef, ...]
    attempt_number = 1
    if stage is SimpleStage.VERIFICATION_INITIAL_DONE:
        external_prerequisites_ref = artifacts.put_json(
            {
                "kind": "simple_initial_verification",
                "attempt_id": attempt_id,
                "result": {
                    "initial_assessment": "HOLD",
                    "unmet_external_prerequisites": ["attacker control unproven"],
                },
            }
        )
        output_refs = (external_prerequisites_ref,)
    else:
        attempt_number = 3
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
        output_refs = (execution_ref, interpretation_ref)
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=stage,
            stage_version=STAGE_VERSION[stage],
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=output_refs,
            attempt_number=attempt_number,
            attempt_id=attempt_id,
            verdict="HOLD",
            external_prerequisites_ref=external_prerequisites_ref,
        )
    )

    cells = DashboardQuery(tmp_path).list_status_cells(display).items

    assert [(cell.id, cell.status) for cell in cells] == [("hypothesis-1", "COMPLETE")]


# mypy: disable-error-code="no-untyped-def"
