"""A stale Final checkpoint cannot be hidden by a later terminal stage."""

from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.simple_runtime.application import SimpleAnalysisApplication
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore


@pytest.mark.parametrize(
    "terminal_stage",
    [SimpleStage.REPORT_DONE, SimpleStage.TECH_GATE_DONE],
)
def test_stale_final_is_incomplete_even_with_current_downstream_stage(
    tmp_path: Path, terminal_stage: SimpleStage
) -> None:
    root = CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    child = root.model_copy(update={"hypothesis_id": "hypothesis"})
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    store.upsert_hypothesis(root, "hypothesis")
    for stage in (SimpleStage.VERIFICATION_FINAL_DONE, terminal_stage):
        store.save_checkpoint(
            StageCheckpoint(
                identity=child,
                stage=stage,
                stage_version=(
                    "2"
                    if stage is SimpleStage.VERIFICATION_FINAL_DONE
                    else STAGE_VERSION[stage]
                ),
                status=StageStatus.SUCCEEDED,
                input_refs=(),
                input_hash=input_reference_hash(()),
                verdict="TRUE"
                if stage is SimpleStage.VERIFICATION_FINAL_DONE
                else None,
                gate_decision="REJECT" if stage is SimpleStage.TECH_GATE_DONE else None,
            )
        )

    assert store.list_incomplete_hypotheses(root, limit=1) == ("hypothesis",)
    app = object.__new__(SimpleAnalysisApplication)
    app._store = store
    assert not app._candidate_hypothesis_terminal(root, "hypothesis")
