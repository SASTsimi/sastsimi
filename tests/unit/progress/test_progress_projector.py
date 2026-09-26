from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

import pytest

from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.progress.projector import ProgressProjector
from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
    STAGE_VERSION,
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
    error_code: str | None = None,
    gate_decision: Literal["ACCEPT", "REVISE", "REJECT"] | None = None,
    gate_revision_count: int = 0,
) -> None:
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=stage,
        stage_version=STAGE_VERSION[stage],
        status=status,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(_ref(f"{identity.hypothesis_id}-{stage.value}"),)
        if status is StageStatus.SUCCEEDED
        else (),
        verdict=verdict,
        attempt_number=attempt_number,
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
