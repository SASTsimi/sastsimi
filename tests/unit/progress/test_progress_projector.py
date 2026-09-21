from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Literal

from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.progress.projector import ProgressProjector
from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
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
) -> None:
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=stage,
        status=status,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(_ref(f"{identity.hypothesis_id}-{stage.value}"),)
        if status is StageStatus.SUCCEEDED
        else (),
        verdict=verdict,
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
