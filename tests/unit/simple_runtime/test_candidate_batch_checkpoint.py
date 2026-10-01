"""Versioned candidate producer checkpoints are atomic and replayable."""

from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.application import HypothesisSeed
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from tests.unit.simple_runtime.test_candidate_batches import _fixture


def _pending(
    identity: CheckpointIdentity, seed: HypothesisSeed, context_ref: StoredDataRef
) -> StageCheckpoint:
    child = identity.model_copy(update={"hypothesis_id": seed.hypothesis_id})
    inputs = (seed.proposal_ref, context_ref)
    return StageCheckpoint(
        identity=child,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.PENDING,
        input_refs=inputs,
        input_hash=input_reference_hash(inputs),
    )


def test_v2_candidate_outcome_and_all_seed_links_commit_atomically(
    tmp_path: Path,
) -> None:
    store, identity, artifacts, _, _, candidate_ids = _fixture(tmp_path, count=1)
    context_ref = artifacts.put_json({"kind": "context"})
    result_ref = artifacts.put_json({"kind": "result"})
    seeds = tuple(
        HypothesisSeed(
            hypothesis_id=f"hypothesis-{index}",
            proposal_ref=artifacts.put_json(
                {"kind": "simple_hypothesis_proposal", "index": index}
            ),
        )
        for index in range(2)
    )
    registrations = tuple(
        (seed.hypothesis_id, seed.proposal_ref, _pending(identity, seed, context_ref))
        for seed in seeds
    )
    first = store.commit_candidate_batch_outcome(
        identity,
        "scope-batch",
        candidate_ids[0],
        batch_id="batch-1",
        static_bundle_hash="a" * 64,
        source_sha256="b" * 64,
        context_hash=context_ref.content_hash,
        status="HYPOTHESES",
        result_ref=result_ref,
        registrations=registrations,
    )
    second = store.commit_candidate_batch_outcome(
        identity,
        "scope-batch",
        candidate_ids[0],
        batch_id="batch-1",
        static_bundle_hash="a" * 64,
        source_sha256="b" * 64,
        context_hash=context_ref.content_hash,
        status="HYPOTHESES",
        result_ref=result_ref,
        registrations=registrations,
    )
    assert first is True
    assert second is False
    assert store.list_candidate_hypothesis_ids(
        identity, "scope-batch", candidate_ids[0]
    ) == tuple(seed.hypothesis_id for seed in seeds)
    for seed in seeds:
        child = identity.model_copy(update={"hypothesis_id": seed.hypothesis_id})
        assert (
            store.require(child, SimpleStage.PRO_CON_DONE).status is StageStatus.PENDING
        )
    progress = store.list_candidate_batch_outcomes(identity, "scope-batch")
    assert tuple(progress) == candidate_ids
    assert progress[candidate_ids[0]].result_ref == result_ref
    assert store.list_candidates(identity, "scope-batch")[0].deep_status == "RUNNING"


def test_v2_outcome_transaction_rolls_back_invalid_second_seed(tmp_path: Path) -> None:
    store, identity, artifacts, _, _, candidate_ids = _fixture(tmp_path, count=1)
    context_ref = artifacts.put_json({"kind": "context"})
    result_ref = artifacts.put_json({"kind": "result"})
    good = HypothesisSeed(
        hypothesis_id="hypothesis-good",
        proposal_ref=artifacts.put_json({"kind": "good"}),
    )
    bad = HypothesisSeed(
        hypothesis_id="hypothesis-bad",
        proposal_ref=artifacts.put_json({"kind": "bad"}),
    )
    wrong_checkpoint = _pending(identity, good, context_ref)
    with pytest.raises(ValueError):
        store.commit_candidate_batch_outcome(
            identity,
            "scope-batch",
            candidate_ids[0],
            batch_id="batch-1",
            static_bundle_hash="a" * 64,
            source_sha256="b" * 64,
            context_hash=context_ref.content_hash,
            status="HYPOTHESES",
            result_ref=result_ref,
            registrations=(
                (
                    good.hypothesis_id,
                    good.proposal_ref,
                    _pending(identity, good, context_ref),
                ),
                (bad.hypothesis_id, bad.proposal_ref, wrong_checkpoint),
            ),
        )
    assert store.list_candidate_batch_outcomes(identity, "scope-batch") == {}
    assert store.hypothesis_count(identity) == 0
    assert store.list_candidates(identity, "scope-batch")[0].deep_status == "PENDING"


def test_v1_free_page_marker_is_unchanged_by_v2_batch_marker(tmp_path: Path) -> None:
    store, identity, artifacts, _, _, _ = _fixture(tmp_path, count=1)
    legacy = artifacts.put_json({"kind": "legacy-page"})
    store.save_survey_progress(
        identity.analysis_id,
        "a" * 64,
        "__candidate_free_page_00000000__",
        legacy,
    )
    marker = artifacts.put_json({"kind": "v2-batch"})
    store.save_candidate_batch_progress(identity, "scope-batch", "batch-1", marker)
    assert store.list_candidate_batch_progress(identity, "scope-batch") == {
        "batch-1": marker
    }
    assert store.survey_progress(identity.analysis_id, "a" * 64) == {
        "__candidate_free_page_00000000__": legacy
    }
