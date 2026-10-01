from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from unittest.mock import patch

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import CommitId, RecordId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.dashboard.query import DashboardNotFound, DashboardQuery
from sastsimi.observability.agent_activity import ActivityKind, AgentActivityEvent
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.reporting.bundle_files import PublishedBundle, parse_bundle_manifest
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.candidates import normalize_candidate_page
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
    assert gaps.total == 105
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
                "candidate_pipeline_version": 1,
                "candidate_scope_fingerprint": "different-scope",
            }
        )
    )
    assert query.get_analysis("analysis-a").candidate_total_count == 0


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
    assert query.report_path("analysis-a", "F-001") == report_path


def _attach_bundle(tmp_path: Path) -> tuple[CheckpointIdentity, PublishedBundle]:
    identity = CheckpointIdentity(
        analysis_id="analysis-a",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    return identity, attach_current_bundle(tmp_path, identity, ref("finding"), "F-001")


def test_current_bundle_lists_only_verified_attachment_urls(tmp_path) -> None:
    test_current_accepted_report_remains_accessible(tmp_path)
    _attach_bundle(tmp_path)
    query = DashboardQuery(tmp_path)
    report = query.get_analysis("analysis-a").reports[0]

    assert report.attachment_urls["report_en.md"].endswith("/files/report_en.md")
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


# mypy: disable-error-code="no-untyped-def"
