from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

import pytest

from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.progress.models import ProgressSnapshot
from sastsimi.progress.projector import ProgressProjector
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
    STAGE_VERSION,
    CandidateTerminal,
    CheckpointIdentity,
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
        commit_id=CommitId("commit-1"),
        record_id=None,
    )


def _save(
    store: SimpleCheckpointStore,
    identity: CheckpointIdentity,
    stage: SimpleStage,
    *,
    status: StageStatus = StageStatus.SUCCEEDED,
    verdict: Literal["TRUE", "FALSE", "HOLD"] | None = None,
    attempt_number: int = 0,
    attempt_id: str | None = None,
    error_code: str | None = None,
    gate_decision: Literal["ACCEPT", "REVISE", "REJECT"] | None = None,
    gate_revision_count: int = 0,
    output_refs: tuple[StoredDataRef, ...] | None = None,
) -> None:
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=stage,
        stage_version=STAGE_VERSION[stage],
        status=status,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(
            output_refs
            if output_refs is not None
            else (_ref(f"{identity.hypothesis_id}-{stage.value}"),)
            if status is StageStatus.SUCCEEDED
            else ()
        ),
        verdict=verdict,
        attempt_number=attempt_number,
        attempt_id=attempt_id,
        error_code=error_code,
        gate_decision=gate_decision,
        gate_revision_count=gate_revision_count,
    )
    store.save_checkpoint(checkpoint)


def test_progress_counts_known_work_and_only_complete_reaches_100(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    analysis = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    hypothesis = analysis.model_copy(update={"hypothesis_id": "hypothesis-1"})
    _save(store, analysis, SimpleStage.STATIC_DONE)
    _save(store, analysis, SimpleStage.HYPOTHESIS_DONE)
    _save(store, hypothesis, SimpleStage.PRO_CON_DONE)

    running = ProgressProjector(store).snapshot("analysis-1")

    assert running.completed_units == 3
    assert running.known_units == 2 + len(HYPOTHESIS_STAGES)
    assert running.percent < 100
    assert running.status == "RUNNING"
    assert running.candidate_total_count is None
    assert running.attempt_number == 1
    assert running.attempt_limit == 3

    for stage in HYPOTHESIS_STAGES[1:]:
        _save(
            store,
            hypothesis,
            stage,
            verdict=("TRUE" if stage is SimpleStage.VERIFICATION_FINAL_DONE else None),
        )

    complete = ProgressProjector(store).snapshot("analysis-1")
    assert complete.status == "COMPLETE"
    assert complete.percent == 100


def test_unmet_external_prerequisite_counts_as_inconclusive_terminal(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    analysis = CheckpointIdentity(
        analysis_id="external-prerequisite-analysis",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    hypothesis = analysis.model_copy(update={"hypothesis_id": "hypothesis-1"})
    _save(store, analysis, SimpleStage.STATIC_DONE)
    _save(store, analysis, SimpleStage.HYPOTHESIS_DONE)
    _save(store, hypothesis, SimpleStage.PRO_CON_DONE)
    data_dir = tmp_path / "data"
    artifacts = SimpleArtifactRepository(data_dir, hypothesis)
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
            identity=hypothesis,
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

    snapshot = ProgressProjector(store, artifact_data_dir=data_dir).snapshot(
        "external-prerequisite-analysis"
    )

    assert snapshot.status == "COMPLETE"
    assert snapshot.percent == 100
    assert snapshot.inconclusive_hypothesis_count == 1
    assert snapshot.finding_count == 0
    artifacts.artifacts.path_for(ref.content_hash).unlink()
    corrupted = ProgressProjector(store, artifact_data_dir=data_dir).snapshot(
        "external-prerequisite-analysis"
    )
    assert corrupted.status == "BLOCKED"
    assert corrupted.error_code == "INITIAL_VERIFICATION_EVIDENCE_INVALID"
    assert corrupted.inconclusive_hypothesis_count == 0


def test_candidate_progress_counts_decisions_and_deep_work_separately(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="candidate-analysis",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    _save(store, identity, SimpleStage.STATIC_DONE)
    _save(store, identity, SimpleStage.HYPOTHESIS_DONE)

    snapshot = ProgressProjector(store).snapshot(
        "candidate-analysis",
        candidate_pipeline_version=1,
        candidate_counts={
            "INCLUDE": 2,
            "EXCLUDE": 1,
            "UNDECIDED": 1,
            "PENDING": 1,
            "ERROR": 0,
        },
        candidate_deep_counts={"RUNNING": 1, "COMPLETE": 1, "PENDING": 1},
    )

    assert snapshot.candidate_total_count == 5
    assert snapshot.candidate_decision_counts["UNDECIDED"] == 1
    assert snapshot.deep_analysis_running_count == 1
    assert snapshot.deep_analysis_completed_count == 1
    assert snapshot.deep_analysis_pending_count == 1
    assert snapshot.status == "RUNNING"
    assert snapshot.completed_units == 7
    assert snapshot.known_units == 10
    assert snapshot.percent == 70


@pytest.mark.parametrize(
    ("candidate_version", "root_status", "root_error", "finding_count"),
    [
        (2, StageStatus.BLOCKED, "HYPOTHESIS_EVIDENCE_INVALID", 0),
        (2, StageStatus.FAILED, "HYPOTHESIS_EVIDENCE_INVALID", 0),
        (2, StageStatus.BLOCKED, "CANDIDATE_CHILD_ERROR:OTHER_CHILD_BLOCKED", 1),
        (0, StageStatus.BLOCKED, "HYPOTHESIS_EVIDENCE_INVALID", 1),
    ],
)
def test_root_provenance_failure_retracts_candidate_finding_count(
    tmp_path: Path,
    candidate_version: int,
    root_status: StageStatus,
    root_error: str,
    finding_count: int,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    root = CheckpointIdentity(
        analysis_id="candidate-finding",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    child = root.model_copy(update={"hypothesis_id": "hypothesis-1"})
    _save(store, root, SimpleStage.STATIC_DONE)
    _save(
        store,
        root,
        SimpleStage.HYPOTHESIS_DONE,
        status=root_status,
        error_code=root_error,
    )
    _save(store, child, SimpleStage.FINDING_DONE, verdict="TRUE")

    snapshot = ProgressProjector(store).snapshot(
        root.analysis_id, candidate_pipeline_version=candidate_version
    )

    assert snapshot.finding_count == finding_count


def test_v2_inconclusive_candidate_does_not_hide_blocked_stage(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="inconclusive-candidate",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    _save(store, identity, SimpleStage.STATIC_DONE)
    _save(
        store,
        identity,
        SimpleStage.HYPOTHESIS_DONE,
        status=StageStatus.BLOCKED,
        error_code="HYPOTHESIS_SURFACE_OUTPUT_INVALID",
    )

    snapshot = ProgressProjector(store).snapshot(
        "inconclusive-candidate",
        candidate_pipeline_version=2,
        candidate_counts={"INCLUDE": 1},
        candidate_deep_counts={"INCONCLUSIVE": 1},
    )

    assert snapshot.status == "BLOCKED"
    assert snapshot.error_code == "HYPOTHESIS_SURFACE_OUTPUT_INVALID"
    assert snapshot.deep_analysis_completed_count == 1
    assert snapshot.phase_counts["candidate_deep"] == {"completed": 1, "known": 1}


def test_v2_root_child_block_displays_actual_failed_hypothesis(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="blocked-child",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    child = identity.model_copy(update={"hypothesis_id": "hypothesis-1"})
    _save(store, identity, SimpleStage.STATIC_DONE)
    _save(
        store,
        child,
        SimpleStage.POC_EXECUTION_DONE,
        status=StageStatus.BLOCKED,
        error_code="POC_EXECUTION_FAILED",
        attempt_id="attempt-1",
    )
    _save(
        store,
        identity,
        SimpleStage.HYPOTHESIS_DONE,
        status=StageStatus.BLOCKED,
        error_code="CANDIDATE_CHILD_ERROR_BOUND:POC_EXECUTION_FAILED:hypothesis-1:attempt-1",
    )

    snapshot = ProgressProjector(store).snapshot(
        identity.analysis_id, candidate_pipeline_version=2
    )

    assert snapshot.status == "BLOCKED"
    assert snapshot.current_stage == SimpleStage.POC_EXECUTION_DONE.value
    assert snapshot.current_hypothesis_id == "hypothesis-1"
    assert snapshot.error_code == "POC_EXECUTION_FAILED"


def test_v2_direct_root_error_is_not_misattributed_to_old_child(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="direct-root-error",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    child = identity.model_copy(update={"hypothesis_id": "old-hypothesis"})
    _save(store, identity, SimpleStage.STATIC_DONE)
    _save(
        store,
        child,
        SimpleStage.POC_EXECUTION_DONE,
        status=StageStatus.BLOCKED,
        error_code="INVALID_OUTPUT",
    )
    _save(
        store,
        identity,
        SimpleStage.HYPOTHESIS_DONE,
        status=StageStatus.BLOCKED,
        error_code="INVALID_OUTPUT",
    )

    snapshot = ProgressProjector(store).snapshot(
        identity.analysis_id, candidate_pipeline_version=2
    )

    assert snapshot.status == "BLOCKED"
    assert snapshot.current_stage == SimpleStage.HYPOTHESIS_DONE.value
    assert snapshot.current_hypothesis_id is None
    assert snapshot.error_code == "INVALID_OUTPUT"


def test_v2_child_marker_preserves_colon_in_error_code(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="colon-child-error",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    child = identity.model_copy(update={"hypothesis_id": "hypothesis-1"})
    _save(store, identity, SimpleStage.STATIC_DONE)
    _save(
        store,
        child,
        SimpleStage.PRO_CON_DONE,
        status=StageStatus.BLOCKED,
        error_code="REQUIRED_TOOL_MISSING:FOO",
        attempt_id="attempt-1",
    )
    _save(
        store,
        identity,
        SimpleStage.HYPOTHESIS_DONE,
        status=StageStatus.BLOCKED,
        error_code="CANDIDATE_CHILD_ERROR_BOUND:REQUIRED_TOOL_MISSING:FOO:hypothesis-1:attempt-1",
    )

    snapshot = ProgressProjector(store).snapshot(
        identity.analysis_id, candidate_pipeline_version=2
    )

    assert snapshot.error_code == "REQUIRED_TOOL_MISSING:FOO"
    assert snapshot.current_hypothesis_id == "hypothesis-1"


def test_v2_unbound_child_marker_preserves_full_colon_error(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="unbound-colon-error",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    _save(store, identity, SimpleStage.STATIC_DONE)
    _save(
        store,
        identity,
        SimpleStage.HYPOTHESIS_DONE,
        status=StageStatus.BLOCKED,
        error_code="CANDIDATE_CHILD_ERROR:ENV_ERROR:A:B",
    )

    snapshot = ProgressProjector(store).snapshot(
        identity.analysis_id, candidate_pipeline_version=2
    )

    assert snapshot.error_code == "ENV_ERROR:A:B"
    assert snapshot.current_hypothesis_id is None


def test_v2_missing_codex_child_remains_manual_cleanup_block(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="missing-codex-child",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    _save(store, identity, SimpleStage.STATIC_DONE)
    old_child = identity.model_copy(update={"hypothesis_id": "old-hypothesis"})
    _save(
        store,
        old_child,
        SimpleStage.PRO_CON_DONE,
        status=StageStatus.BLOCKED,
        error_code="CODEX_PROCESS_CLEANUP_UNCONFIRMED",
    )
    _save(
        store,
        identity,
        SimpleStage.HYPOTHESIS_DONE,
        status=StageStatus.BLOCKED,
        error_code="CANDIDATE_CHILD_CODEX_STATE_PENDING",
    )

    snapshot = ProgressProjector(store).snapshot(
        identity.analysis_id, candidate_pipeline_version=2
    )

    assert snapshot.status == "BLOCKED"
    assert snapshot.error_code == "CODEX_PROCESS_CLEANUP_UNCONFIRMED"
    assert snapshot.current_hypothesis_id is None


def test_v2_progress_is_phase_counted_and_replay_stable(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="v2-progress",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    _save(store, identity, SimpleStage.STATIC_DONE)
    _save(store, identity, SimpleStage.HYPOTHESIS_DONE)
    _save(
        store,
        identity.model_copy(update={"hypothesis_id": "hypothesis-1"}),
        SimpleStage.POC_EXECUTION_DONE,
    )

    def snapshot() -> ProgressSnapshot:
        return ProgressProjector(store).snapshot(
            "v2-progress",
            candidate_pipeline_version=2,
            candidate_counts={"INCLUDE": 1, "EXCLUDE": 1, "PENDING": 1},
            candidate_deep_counts={"COMPLETE": 1},
            registered_hypothesis_count=1,
            surface_counts={"CONTEXT_RECORDS": 1, "TOTAL": 2},
        )

    first = snapshot()
    assert first.percentage_kind == "known_checkpoint_fraction"
    assert first.phase_counts == {
        "static": {"completed": 1, "known": 1},
        "triage": {"completed": 2, "known": 3},
        "candidate_deep": {"completed": 1, "known": 1},
        "verification": {"completed": 0, "known": 1},
        "poc": {"attempted": 1, "completed": 1},
        "surface": {"recorded_contexts": 1, "completed": 0, "total": 2},
    }
    assert first.percent < 100
    assert snapshot() == first


def test_v2_partial_surface_context_has_no_surface_completion_credit(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="v2-partial-surface",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    _save(store, identity, SimpleStage.STATIC_DONE)
    _save(store, identity, SimpleStage.HYPOTHESIS_DONE)

    snapshot = ProgressProjector(store).snapshot(
        "v2-partial-surface",
        candidate_pipeline_version=2,
        candidate_counts={},
        candidate_deep_counts={},
        surface_counts={"TOTAL": 1, "CONTEXT_RECORDS": 2, "CONTEXT_SURFACES": 1},
    )

    assert snapshot.phase_counts["surface"] == {
        "recorded_contexts": 2,
        "recorded_surfaces": 1,
        "completed": 0,
        "total": 1,
    }
    assert snapshot.completed_units == 2
    assert snapshot.known_units == 3
    assert snapshot.status == "RUNNING"


def test_v2_does_not_accept_v1_terminal_without_surface_proof(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="v2-no-surface-proof",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    _save(store, identity, SimpleStage.STATIC_DONE)
    _save(store, identity, SimpleStage.HYPOTHESIS_DONE)

    snapshot = ProgressProjector(store).snapshot(
        "v2-no-surface-proof",
        candidate_pipeline_version=2,
        candidate_counts={},
        candidate_deep_counts={},
        candidate_terminal=CandidateTerminal(
            status="COMPLETE",
            bundle_hash="a" * 64,
            scope_fingerprint="scope-1",
            decision_counts={},
            deep_counts={},
            hypothesis_count=0,
        ),
        candidate_bundle_hash="a" * 64,
        candidate_scope_fingerprint="scope-1",
    )

    assert snapshot.status == "RUNNING"
    assert snapshot.percent < 100


@pytest.mark.parametrize(
    ("terminal_status", "coverage_counts"),
    [
        ("COMPLETE", {"COVERED": 1, "UNCOVERED": 0, "INSUFFICIENT": 0}),
        ("PARTIAL", {"COVERED": 0, "UNCOVERED": 1, "INSUFFICIENT": 0}),
    ],
)
def test_v2_terminal_uses_exact_surface_proof_and_partial_status(
    tmp_path: Path,
    terminal_status: Literal["COMPLETE", "PARTIAL"],
    coverage_counts: dict[str, int],
) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="v2-terminal",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    _save(store, identity, SimpleStage.STATIC_DONE)
    _save(
        store,
        identity,
        SimpleStage.HYPOTHESIS_DONE,
        output_refs=(
            _ref("surface-index").model_copy(update={"content_hash": "b" * 64}),
            _ref("surface-coverage").model_copy(update={"content_hash": "c" * 64}),
        ),
    )
    terminal = CandidateTerminal(
        status=terminal_status,
        bundle_hash="a" * 64,
        scope_fingerprint="scope-1",
        decision_counts={},
        deep_counts={},
        hypothesis_count=0,
        surface_index_hash="b" * 64,
        surface_coverage_hash="c" * 64,
        surface_counts=coverage_counts,
        producer_finished=True,
        pending_child_count=0,
    )

    snapshot = ProgressProjector(store).snapshot(
        "v2-terminal",
        candidate_pipeline_version=2,
        candidate_counts={},
        candidate_deep_counts={},
        candidate_terminal=terminal,
        candidate_bundle_hash="a" * 64,
        candidate_scope_fingerprint="scope-1",
        surface_counts={"TOTAL": 1, "CONTEXT_RECORDS": 0, **coverage_counts},
        surface_index_hash="b" * 64,
    )

    assert snapshot.status == terminal_status
    assert snapshot.phase_counts["surface"]["completed"] == coverage_counts["COVERED"]
    assert snapshot.phase_counts["surface"]["uncovered"] == coverage_counts["UNCOVERED"]
    if terminal_status == "COMPLETE":
        assert snapshot.percent == 100
    else:
        assert snapshot.percent < 100

    unbound = ProgressProjector(store).snapshot(
        "v2-terminal",
        candidate_pipeline_version=2,
        candidate_counts={},
        candidate_deep_counts={},
        candidate_terminal=terminal.model_copy(
            update={"surface_coverage_hash": "d" * 64}
        ),
        candidate_bundle_hash="a" * 64,
        candidate_scope_fingerprint="scope-1",
        surface_counts={"TOTAL": 1, "CONTEXT_RECORDS": 0, **coverage_counts},
        surface_index_hash="b" * 64,
    )
    assert unbound.status == "RUNNING"

    unverified_counts = ProgressProjector(store).snapshot(
        "v2-terminal",
        candidate_pipeline_version=2,
        candidate_counts={},
        candidate_deep_counts={},
        candidate_terminal=terminal,
        candidate_bundle_hash="a" * 64,
        candidate_scope_fingerprint="scope-1",
        surface_counts={"TOTAL": 1, "CONTEXT_RECORDS": 0},
        surface_index_hash="b" * 64,
    )
    assert unverified_counts.status == "RUNNING"


def test_registered_hypotheses_without_checkpoints_expand_progress_denominator(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="registered-analysis",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    _save(store, identity, SimpleStage.STATIC_DONE)
    _save(store, identity, SimpleStage.HYPOTHESIS_DONE)

    snapshot = ProgressProjector(store).snapshot(
        "registered-analysis",
        candidate_pipeline_version=1,
        candidate_counts={},
        candidate_deep_counts={},
        registered_hypothesis_count=2,
    )

    assert snapshot.hypothesis_count == 2
    assert snapshot.known_units == 2 + 2 * len(HYPOTHESIS_STAGES)
    assert snapshot.completed_units == 2
    assert snapshot.status == "RUNNING"


def test_candidate_error_blocks_but_is_not_undecided(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="candidate-error",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    _save(store, identity, SimpleStage.STATIC_DONE)
    _save(store, identity, SimpleStage.HYPOTHESIS_DONE)

    snapshot = ProgressProjector(store).snapshot(
        "candidate-error",
        candidate_pipeline_version=1,
        candidate_counts={
            "INCLUDE": 0,
            "EXCLUDE": 0,
            "UNDECIDED": 0,
            "PENDING": 0,
            "ERROR": 1,
        },
        candidate_deep_counts={},
    )

    assert snapshot.status == "BLOCKED"
    assert snapshot.candidate_decision_counts["ERROR"] == 1
    assert snapshot.candidate_decision_counts["UNDECIDED"] == 0
    assert snapshot.percent < 100


def test_candidate_pipeline_can_complete_with_zero_candidates(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="candidate-empty",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    _save(store, identity, SimpleStage.STATIC_DONE)
    _save(store, identity, SimpleStage.HYPOTHESIS_DONE)

    unfinalized = ProgressProjector(store).snapshot(
        "candidate-empty",
        candidate_pipeline_version=1,
        candidate_counts={},
        candidate_deep_counts={},
    )
    assert unfinalized.status == "RUNNING"

    snapshot = ProgressProjector(store).snapshot(
        "candidate-empty",
        candidate_pipeline_version=1,
        candidate_counts={},
        candidate_deep_counts={},
        candidate_terminal=CandidateTerminal(
            status="COMPLETE",
            bundle_hash="a" * 64,
            scope_fingerprint="scope-1",
            decision_counts={},
            deep_counts={},
            hypothesis_count=0,
        ),
        candidate_bundle_hash="a" * 64,
        candidate_scope_fingerprint="scope-1",
    )

    assert snapshot.status == "COMPLETE"
    assert snapshot.percent == 100


def test_candidate_free_hypothesis_hold_waits_for_chaining(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    analysis = CheckpointIdentity(
        analysis_id="candidate-hold",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    hypothesis = analysis.model_copy(update={"hypothesis_id": "free-hypothesis"})
    _save(store, analysis, SimpleStage.STATIC_DONE)
    _save(store, analysis, SimpleStage.HYPOTHESIS_DONE)
    final_index = HYPOTHESIS_STAGES.index(SimpleStage.VERIFICATION_FINAL_DONE)
    for stage in HYPOTHESIS_STAGES[: final_index + 1]:
        _save(
            store,
            hypothesis,
            stage,
            verdict="HOLD" if stage is SimpleStage.VERIFICATION_FINAL_DONE else None,
        )

    unfinished = ProgressProjector(store).snapshot(
        "candidate-hold",
        candidate_pipeline_version=1,
        candidate_counts={},
        candidate_deep_counts={},
    )
    assert unfinished.status == "RUNNING"
    assert unfinished.percent < 100

    _save(store, hypothesis, SimpleStage.CHAINING_DONE)
    unfinalized = ProgressProjector(store).snapshot(
        "candidate-hold",
        candidate_pipeline_version=1,
        candidate_counts={},
        candidate_deep_counts={},
    )
    assert unfinalized.status == "RUNNING"
    assert unfinalized.percent < 100

    finished = ProgressProjector(store).snapshot(
        "candidate-hold",
        candidate_pipeline_version=1,
        candidate_counts={},
        candidate_deep_counts={},
        candidate_terminal=CandidateTerminal(
            status="COMPLETE",
            bundle_hash="a" * 64,
            scope_fingerprint="scope-1",
            decision_counts={},
            deep_counts={},
            hypothesis_count=1,
        ),
        candidate_bundle_hash="a" * 64,
        candidate_scope_fingerprint="scope-1",
    )
    assert finished.status == "COMPLETE"
    assert finished.percent == 100


@pytest.mark.parametrize(
    "error_code",
    [
        "LLM_TOKEN_BUDGET_EXHAUSTED",
        "LLM_COST_BUDGET_EXHAUSTED",
        "LLM_ELAPSED_BUDGET_EXHAUSTED",
        "LLM_TOKEN_USAGE_UNAVAILABLE",
        "LLM_COST_USAGE_UNAVAILABLE",
    ],
)
@pytest.mark.parametrize("failure_status", [StageStatus.BLOCKED, StageStatus.FAILED])
def test_budget_exhaustion_is_paused_not_blocked(
    tmp_path: Path, error_code: str, failure_status: StageStatus
) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="budget-analysis",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    _save(store, identity, SimpleStage.STATIC_DONE)
    _save(
        store,
        identity,
        SimpleStage.HYPOTHESIS_DONE,
        status=failure_status,
        error_code=error_code,
    )

    snapshot = ProgressProjector(store).snapshot(
        "budget-analysis",
        candidate_pipeline_version=1,
        candidate_counts={},
        candidate_deep_counts={},
    )

    assert snapshot.status == "PAUSED"
    assert snapshot.error_code == error_code
    assert snapshot.resume_action == (
        "CHECK_USAGE_TELEMETRY"
        if error_code.endswith("USAGE_UNAVAILABLE")
        else "INCREASE_BUDGET_AND_RESUME"
    )


def test_partial_static_scope_never_projects_complete_or_full_coverage(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    analysis = CheckpointIdentity(
        analysis_id="analysis-partial",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    hypothesis = analysis.model_copy(update={"hypothesis_id": "hypothesis-1"})
    _save(store, analysis, SimpleStage.STATIC_DONE)
    _save(store, analysis, SimpleStage.HYPOTHESIS_DONE)
    for stage in HYPOTHESIS_STAGES:
        _save(
            store,
            hypothesis,
            stage,
            verdict="TRUE" if stage is SimpleStage.VERIFICATION_FINAL_DONE else None,
        )

    snapshot = ProgressProjector(store).snapshot(
        "analysis-partial", static_disposition="PARTIAL"
    )

    assert snapshot.status == "PARTIAL"
    assert snapshot.percent < 100


def test_false_is_terminal_without_becoming_a_failed_analysis(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    final_index = HYPOTHESIS_STAGES.index(SimpleStage.VERIFICATION_FINAL_DONE)
    for stage in HYPOTHESIS_STAGES[: final_index + 1]:
        _save(
            store,
            identity,
            stage,
            verdict="FALSE" if stage is SimpleStage.VERIFICATION_FINAL_DONE else None,
        )

    snapshot = ProgressProjector(store).snapshot("analysis-1")

    assert snapshot.status == "COMPLETE"
    assert snapshot.percent == 100
    assert snapshot.skipped_units > 0


def test_executed_inconclusive_poc_is_complete_but_not_reportable(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(
        tmp_path / "db" / "sastsimi.sqlite3", artifact_data_dir=tmp_path
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    attempt_id = "terminal-poc-attempt-3"
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
    ):
        _save(store, identity, stage)
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.POC_EXECUTION_DONE,
            stage_version=STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(execution_ref, interpretation_ref),
            verdict="HOLD",
            attempt_number=3,
            attempt_id=attempt_id,
        )
    )

    snapshot = ProgressProjector(store, artifact_data_dir=tmp_path).snapshot(
        "analysis-1"
    )

    assert snapshot.status == "COMPLETE"
    assert snapshot.percent == 100
    assert snapshot.inconclusive_hypothesis_count == 1
    assert snapshot.rejected_hypothesis_count == 0
    assert snapshot.skipped_units == len(HYPOTHESIS_STAGES) - 4


def test_new_child_expands_denominator_without_losing_progress(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    parent = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="parent",
    )
    _save(store, parent, SimpleStage.PRO_CON_DONE)
    before = ProgressProjector(store).snapshot("analysis-1")

    child = parent.model_copy(update={"hypothesis_id": "child"})
    _save(store, child, SimpleStage.PRO_CON_DONE, status=StageStatus.PENDING)
    after = ProgressProjector(store).snapshot("analysis-1")

    assert after.completed_units == before.completed_units
    assert after.known_units > before.known_units
    assert after.percent <= before.percent
    assert after.denominator_change_reason == "NEW_HYPOTHESIS_REGISTERED"


def test_blocked_and_failed_stages_are_not_counted_complete(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    _save(store, identity, SimpleStage.PRO_CON_DONE, status=StageStatus.BLOCKED)
    blocked = ProgressProjector(store).snapshot("analysis-1")
    assert blocked.completed_units == 0
    assert blocked.status == "BLOCKED"

    _save(store, identity, SimpleStage.PRO_CON_DONE, status=StageStatus.FAILED)
    failed = ProgressProjector(store).snapshot("analysis-1")
    assert failed.completed_units == 0
    assert failed.status == "FAILED"


def test_progress_projects_the_current_recovery_attempt(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    _save(
        store,
        identity,
        SimpleStage.POC_EXECUTION_DONE,
        status=StageStatus.BLOCKED,
        attempt_number=2,
    )

    snapshot = ProgressProjector(store).snapshot("analysis-1")

    assert snapshot.attempt_number == 2
    assert snapshot.attempt_limit == 3


def test_running_hypothesis_takes_priority_over_earlier_blocked_one(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    blocked = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-a",
    )
    running = blocked.model_copy(update={"hypothesis_id": "hypothesis-b"})
    _save(
        store,
        blocked,
        SimpleStage.POC_EXECUTION_DONE,
        status=StageStatus.BLOCKED,
        error_code="RECOVERY_EXHAUSTED",
    )
    _save(store, running, SimpleStage.PRO_CON_DONE, status=StageStatus.RUNNING)

    snapshot = ProgressProjector(store).snapshot("analysis-1")

    assert snapshot.status == "RUNNING"
    assert snapshot.current_hypothesis_id == "hypothesis-b"
    assert snapshot.current_stage == SimpleStage.PRO_CON_DONE.value
    assert snapshot.error_code is None


def test_failed_hypothesis_takes_priority_over_blocked_one(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    blocked = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-a",
    )
    failed = blocked.model_copy(update={"hypothesis_id": "hypothesis-b"})
    _save(
        store,
        blocked,
        SimpleStage.POC_EXECUTION_DONE,
        status=StageStatus.BLOCKED,
        error_code="RECOVERY_EXHAUSTED",
    )
    _save(
        store,
        failed,
        SimpleStage.PRO_CON_DONE,
        status=StageStatus.FAILED,
        error_code="TEST_FAILURE",
    )

    snapshot = ProgressProjector(store).snapshot("analysis-1")

    assert snapshot.status == "FAILED"
    assert snapshot.current_hypothesis_id == "hypothesis-b"
    assert snapshot.error_code == "TEST_FAILURE"


@pytest.mark.parametrize(("decision", "revisions"), [("REJECT", 0), ("REVISE", 2)])
def test_terminal_gate_decision_completes_without_a_report(
    tmp_path: Path, decision: Literal["REJECT", "REVISE"], revisions: int
) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    gate_index = HYPOTHESIS_STAGES.index(SimpleStage.TECH_GATE_DONE)
    for stage in HYPOTHESIS_STAGES[: gate_index + 1]:
        _save(
            store,
            identity,
            stage,
            verdict="TRUE" if stage is SimpleStage.VERIFICATION_FINAL_DONE else None,
            gate_decision=decision if stage is SimpleStage.TECH_GATE_DONE else None,
            gate_revision_count=revisions,
        )

    snapshot = ProgressProjector(store).snapshot("analysis-1")

    assert snapshot.status == "COMPLETE"
    assert snapshot.percent == 100
    assert snapshot.completed_units == gate_index + 1
    assert snapshot.skipped_units == len(HYPOTHESIS_STAGES) - gate_index - 1
    assert snapshot.error_code is None
    assert store.get(identity, SimpleStage.FINDING_DONE) is None
    assert store.get(identity, SimpleStage.REPORT_DONE) is None


def test_terminal_gate_does_not_hide_operationally_blocked_sibling(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    rejected = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="rejected",
    )
    blocked = rejected.model_copy(update={"hypothesis_id": "blocked"})
    for stage in HYPOTHESIS_STAGES[
        : HYPOTHESIS_STAGES.index(SimpleStage.TECH_GATE_DONE) + 1
    ]:
        _save(
            store,
            rejected,
            stage,
            gate_decision="REJECT" if stage is SimpleStage.TECH_GATE_DONE else None,
        )
    _save(
        store,
        blocked,
        SimpleStage.POC_EXECUTION_DONE,
        status=StageStatus.BLOCKED,
        error_code="DOCKER_BUILD_FAILED",
    )

    snapshot = ProgressProjector(store).snapshot("analysis-1")

    assert snapshot.status == "BLOCKED"
    assert snapshot.percent < 100
    assert snapshot.current_hypothesis_id == "blocked"
    assert snapshot.error_code == "DOCKER_BUILD_FAILED"
