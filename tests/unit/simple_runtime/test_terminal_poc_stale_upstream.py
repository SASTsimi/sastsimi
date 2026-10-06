"""Preserve a verified terminal PoC when an upstream stage version changes."""

from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.simple_runtime.application import SimpleAnalysisApplication
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.runner import SimpleRuntimeRunner
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _saved_terminal_poc(
    tmp_path: Path, *, valid_interpretation: bool = True
) -> tuple[
    SimpleCheckpointStore,
    SimpleArtifactRepository,
    CheckpointIdentity,
    CheckpointIdentity,
    StageCheckpoint,
]:
    root = CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    child = root.model_copy(update={"hypothesis_id": "hypothesis"})
    artifacts = SimpleArtifactRepository(tmp_path, child)
    store = SimpleCheckpointStore(
        tmp_path / "sastsimi.sqlite3", artifact_data_dir=tmp_path
    )
    store.upsert_hypothesis(root, "hypothesis")
    for stage in (SimpleStage.PRO_CON_DONE, SimpleStage.VERIFICATION_INITIAL_DONE):
        prior_ref = artifacts.put_json({"kind": stage.value})
        store.save_checkpoint(
            StageCheckpoint(
                identity=child,
                stage=stage,
                stage_version=STAGE_VERSION[stage],
                status=StageStatus.SUCCEEDED,
                input_refs=(),
                input_hash=input_reference_hash(()),
                output_refs=(prior_ref,),
                attempt_id="attempt-3",
                verdict="TRUE"
                if stage is SimpleStage.VERIFICATION_INITIAL_DONE
                else None,
            )
        )
    candidate_ref = artifacts.put_json({"kind": "simple_poc_candidate"})
    candidate = StageCheckpoint(
        identity=child,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        stage_version="2",
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(candidate_ref,),
        attempt_id="attempt-3",
    )
    store.save_checkpoint(candidate)
    execution_ref = artifacts.put_json(
        {
            "kind": "simple_poc_execution",
            "attempt_id": "attempt-3",
            "timed_out": False,
            "exit_code": 0,
        }
    )
    interpretation_ref = artifacts.put_json(
        {
            "kind": "simple_dynamic_interpretation",
            "execution_ref": (
                execution_ref.model_dump(mode="json")
                if valid_interpretation
                else candidate_ref.model_dump(mode="json")
            ),
            "result": {"outcome": "INCONCLUSIVE"},
        }
    )
    poc = StageCheckpoint(
        identity=child,
        stage=SimpleStage.POC_EXECUTION_DONE,
        stage_version=STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=(candidate_ref,),
        input_hash=input_reference_hash((candidate_ref,)),
        output_refs=(execution_ref, interpretation_ref),
        attempt_id="attempt-3",
        attempt_number=3,
        verdict="HOLD",
    )
    store.save_checkpoint(poc)
    return store, artifacts, root, child, poc


@pytest.mark.asyncio
async def test_runner_preserves_verified_terminal_poc_with_stale_candidate(
    tmp_path: Path,
) -> None:
    store, artifacts, _root, child, poc = _saved_terminal_poc(tmp_path)
    assert artifacts.verified_terminal_poc_outcome(poc) == "INCONCLUSIVE"

    outcome = await SimpleRuntimeRunner(
        store, {}, cleanup_artifacts=artifacts
    ).resume_hypothesis(child)

    assert outcome.status is StageStatus.SUCCEEDED
    assert outcome.current_stage is SimpleStage.POC_EXECUTION_DONE
    assert store.get(child, SimpleStage.POC_EXECUTION_DONE) == poc
    assert store.get(child, SimpleStage.POC_CANDIDATE_DONE) is not None


def test_candidate_queue_accepts_verified_terminal_poc_with_stale_candidate(
    tmp_path: Path,
) -> None:
    store, _artifacts, root, _child, _poc = _saved_terminal_poc(tmp_path)
    app = object.__new__(SimpleAnalysisApplication)
    app._store = store

    assert store.list_incomplete_hypotheses(root, limit=1) == ()
    assert app._candidate_hypothesis_terminal(root, "hypothesis")


def test_stale_downstream_remains_incomplete_after_terminal_poc(
    tmp_path: Path,
) -> None:
    store, artifacts, root, child, _poc = _saved_terminal_poc(tmp_path)
    final_ref = artifacts.put_json({"kind": "stale_final"})
    store.save_checkpoint(
        StageCheckpoint(
            identity=child,
            stage=SimpleStage.VERIFICATION_FINAL_DONE,
            stage_version="2",
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(final_ref,),
        )
    )
    app = object.__new__(SimpleAnalysisApplication)
    app._store = store

    assert store.list_incomplete_hypotheses(root, limit=1) == ("hypothesis",)
    assert not app._candidate_hypothesis_terminal(root, "hypothesis")


@pytest.mark.asyncio
async def test_invalid_terminal_poc_evidence_blocks_without_erasing_it(
    tmp_path: Path,
) -> None:
    store, artifacts, root, child, poc = _saved_terminal_poc(
        tmp_path, valid_interpretation=False
    )
    app = object.__new__(SimpleAnalysisApplication)
    app._store = store
    assert store.list_incomplete_hypotheses(root, limit=1) == ("hypothesis",)
    assert not app._candidate_hypothesis_terminal(root, "hypothesis")

    outcome = await SimpleRuntimeRunner(
        store, {}, cleanup_artifacts=artifacts
    ).resume_hypothesis(child)

    assert outcome.status is StageStatus.BLOCKED
    assert outcome.error_code == "POC_TERMINAL_EVIDENCE_INVALID"
    blocked = store.get(child, SimpleStage.POC_EXECUTION_DONE)
    assert blocked is not None
    assert blocked.output_refs == poc.output_refs
    assert store.get(child, SimpleStage.POC_CANDIDATE_DONE) is not None


@pytest.mark.asyncio
async def test_terminal_poc_without_artifact_reader_blocks_without_replay(
    tmp_path: Path,
) -> None:
    store, _artifacts, _root, child, poc = _saved_terminal_poc(tmp_path)

    outcome = await SimpleRuntimeRunner(store, {}).resume_hypothesis(child)

    assert outcome.status is StageStatus.BLOCKED
    assert outcome.error_code == "POC_TERMINAL_EVIDENCE_INVALID"
    assert store.get(child, SimpleStage.POC_EXECUTION_DONE) == poc
