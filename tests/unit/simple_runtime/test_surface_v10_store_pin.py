"""A v10 successor pins one complete v9 snapshot without rewriting it."""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CandidateTerminal,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_enrichment_v10 import (
    v9_progress_snapshot_hash,
)
from tests.unit.simple_runtime.test_surface_v8_store_pin import _v9_pin_case


def test_v10_run_model_preserves_v9_ref(tmp_path: Path) -> None:
    _store, identity, run, v9_ref, _ = _v9_pin_case(tmp_path)
    assert run.candidate_terminal is not None
    successor_ref = SimpleArtifactRepository(tmp_path / "data", identity).put_json(
        {"kind": "simple_surface_enrichment_plan_v10"}
    )
    successor = run.model_copy(
        update={
            "surface_enrichment_v9_plan_ref": v9_ref,
            "surface_enrichment_v10_plan_ref": successor_ref,
            "candidate_terminal": run.candidate_terminal.model_copy(
                update={"surface_proof_version": 8}
            ),
        }
    )

    restored = SimpleAnalysisRun.model_validate_json(successor.model_dump_json())

    assert restored.surface_enrichment_v9_plan_ref == v9_ref
    assert restored.surface_enrichment_v10_plan_ref == successor_ref
    assert restored.candidate_terminal is not None
    assert restored.candidate_terminal.surface_proof_version == 8


def test_v10_model_rejects_unpinned_predecessor(tmp_path: Path) -> None:
    _store, identity, run, _v9_ref, _ = _v9_pin_case(tmp_path)
    successor_ref = SimpleArtifactRepository(tmp_path / "data", identity).put_json(
        {"kind": "simple_surface_enrichment_plan_v10"}
    )

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V10_STATE_UNBOUND"):
        SimpleAnalysisRun.model_validate_json(
            run.model_copy(
                update={"surface_enrichment_v10_plan_ref": successor_ref}
            ).model_dump_json()
        )


def test_v10_snapshot_hash_rejects_incomplete_v9_review(tmp_path: Path) -> None:
    store, identity, parent, v9_ref, prior_hash = _v9_pin_case(tmp_path)
    assert store.pin_surface_enrichment_v9_plan(parent, v9_ref, prior_hash)
    plan = json.loads(
        SimpleArtifactRepository(tmp_path / "data", identity).read(v9_ref)
    )
    progress = store.list_surface_exploration_progress(identity, "scope-v8")

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V10_PROGRESS_INCOMPLETE"):
        v9_progress_snapshot_hash(plan, progress)


def test_v10_snapshot_hash_rejects_a001_shaped_nine_of_thirty_six(
    tmp_path: Path,
) -> None:
    store, _artifacts, identity, parent, _plan_ref, _plan, v9_plan = _completed_parent(
        tmp_path
    )
    assert parent.candidate_scope_fingerprint is not None
    original = v9_plan["expected_parts"][0]
    expected_parts = [
        {
            **original,
            "surface_id": f"surface-{number:02d}",
            "context_id": f"context-{number:02d}",
        }
        for number in range(36)
    ]
    rows = store.list_surface_exploration_progress(
        identity, parent.candidate_scope_fingerprint
    )
    first = next(row for row in rows.values() if row.proposal_version == 9)
    nine = {
        (part["surface_id"], part["context_id"]): replace(
            first,
            surface_id=part["surface_id"],
            context_id=part["context_id"],
        )
        for part in expected_parts[:9]
    }

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V10_PROGRESS_INCOMPLETE"):
        v9_progress_snapshot_hash({**v9_plan, "expected_parts": expected_parts}, nine)


def _completed_parent(
    tmp_path: Path,
) -> tuple[
    SimpleCheckpointStore,
    SimpleArtifactRepository,
    CheckpointIdentity,
    SimpleAnalysisRun,
    StoredDataRef,
    dict[str, object],
    dict[str, Any],
]:
    store, identity, parent, v9_ref, prior_hash = _v9_pin_case(tmp_path)
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    assert store.pin_surface_enrichment_v9_plan(parent, v9_ref, prior_hash)
    prior = store.require_analysis_run(identity.analysis_id)
    assert prior.candidate_terminal is not None
    assert prior.candidate_scope_fingerprint is not None
    root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
    assert root is not None
    v9_plan = json.loads(artifacts.read(v9_ref))
    expected = v9_plan["expected_parts"][0]
    result_ref = artifacts.put_json(
        {"kind": "simple_surface_hypothesis_result_v9", "status": "NO_HYPOTHESIS"}
    )
    assert store.commit_surface_exploration(
        identity,
        prior.candidate_scope_fingerprint,
        expected["surface_id"],
        expected["context_id"],
        static_bundle_hash=prior.candidate_terminal.bundle_hash,
        index_hash=root.output_refs[0].content_hash,
        context_hash=expected["context_hash"],
        source_sha256=expected["context_part"]["source_sha256"],
        status="NO_HYPOTHESIS",
        result_ref=result_ref,
        registrations=(),
        proposal_version=9,
    )
    coverage_ref = artifacts.put_json(
        {
            "kind": "simple_attack_surface_coverage_v7",
            "scope_fingerprint": prior.candidate_scope_fingerprint,
            "static_bundle_hash": prior.candidate_terminal.bundle_hash,
            "index_hash": root.output_refs[0].content_hash,
            "v9_plan_ref": v9_ref.model_dump(mode="json"),
            "missing_v9_parts": [],
            "surfaces": [
                {"surface_id": "surface-v8", "coverage_status": "INSUFFICIENT"}
            ],
            "complete": False,
        }
    )
    v9_root = root.model_copy(
        update={"output_refs": (root.output_refs[0], coverage_ref)}
    )
    store.save_checkpoint(v9_root)
    terminal = prior.candidate_terminal.model_copy(
        update={
            "surface_proof_version": 7,
            "surface_coverage_hash": coverage_ref.content_hash,
            "surface_counts": {"COVERED": 0, "UNCOVERED": 0, "INSUFFICIENT": 1},
            "producer_finished": True,
        }
    )
    run = prior.model_copy(update={"candidate_terminal": terminal})
    store.save_analysis_run(run)
    progress = store.list_surface_exploration_progress(
        identity, prior.candidate_scope_fingerprint
    )
    progress_hash = v9_progress_snapshot_hash(v9_plan, progress)
    plan: dict[str, object] = {
        "kind": "simple_surface_enrichment_plan_v10",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope_fingerprint": prior.candidate_scope_fingerprint,
        "static_bundle_hash": terminal.bundle_hash,
        "index_hash": root.output_refs[0].content_hash,
        "v9_plan_ref": v9_ref.model_dump(mode="json"),
        "v9_coverage_ref": coverage_ref.model_dump(mode="json"),
        "v9_terminal": terminal.model_dump(mode="json"),
        "v9_root": v9_root.model_dump(mode="json"),
        "v9_progress_hash": progress_hash,
        "proofs": [{"surface_id": "surface-v8", "proof_hash": "a" * 64}],
    }
    plan_ref = artifacts.put_json(plan)
    return store, artifacts, identity, run, plan_ref, plan, v9_plan


def test_v10_pin_rejects_unfinished_v9_parent(tmp_path: Path) -> None:
    store, identity, parent, v9_ref, prior_hash = _v9_pin_case(tmp_path)
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    assert store.pin_surface_enrichment_v9_plan(parent, v9_ref, prior_hash)
    unfinished = store.require_analysis_run(identity.analysis_id)
    plan_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v10"})

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V10_PIN_INVALID"):
        store.pin_surface_enrichment_v10_plan(unfinished, plan_ref)


def test_v10_pin_is_idempotent_and_keeps_v9_root(tmp_path: Path) -> None:
    store, _artifacts, identity, parent, plan_ref, _plan, _v9_plan = _completed_parent(
        tmp_path
    )
    previous_root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)

    assert store.pin_surface_enrichment_v10_plan(parent, plan_ref)
    saved = store.require_analysis_run(identity.analysis_id)
    assert saved.surface_enrichment_v10_plan_ref == plan_ref
    assert saved.surface_enrichment_v9_plan_ref == parent.surface_enrichment_v9_plan_ref
    assert saved.candidate_terminal == parent.candidate_terminal
    assert store.get(identity, SimpleStage.HYPOTHESIS_DONE) == previous_root
    assert not store.pin_surface_enrichment_v10_plan(parent, plan_ref)


def test_v10_pin_rejects_changed_predecessor_root(tmp_path: Path) -> None:
    store, artifacts, identity, parent, plan_ref, _plan, _v9_plan = _completed_parent(
        tmp_path
    )
    root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
    assert root is not None
    forged_coverage = artifacts.put_json({"kind": "changed"})
    store.save_checkpoint(
        root.model_copy(update={"output_refs": (root.output_refs[0], forged_coverage)})
    )

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V10_PIN_STALE"):
        store.pin_surface_enrichment_v10_plan(parent, plan_ref)


def test_v10_pin_rejects_changed_predecessor_progress(tmp_path: Path) -> None:
    store, artifacts, identity, parent, plan_ref, _plan, _v9_plan = _completed_parent(
        tmp_path
    )
    result_ref = artifacts.put_json(
        {"kind": "simple_surface_hypothesis_result_v9", "status": "NO_HYPOTHESIS"}
    )
    root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
    assert root is not None
    assert parent.candidate_terminal is not None
    # A new row cannot be smuggled in after the parent snapshot was pinned.
    with store._connect() as connection:
        connection.execute(
            "INSERT INTO simple_surface_exploration_progress "
            "(analysis_id, workspace_id, commit_id, scope_fingerprint, "
            "surface_id, context_id, static_bundle_hash, index_hash, "
            "context_hash, source_sha256, status, proposal_version, "
            "result_ref_json, registrations_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                identity.analysis_id,
                identity.workspace_id,
                identity.commit_id,
                parent.candidate_scope_fingerprint,
                "extra",
                "extra-context",
                parent.candidate_terminal.bundle_hash,
                root.output_refs[0].content_hash,
                "e" * 64,
                "f" * 64,
                "NO_HYPOTHESIS",
                9,
                result_ref.model_dump_json(),
                "[]",
            ),
        )

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V10_PIN_STALE"):
        store.pin_surface_enrichment_v10_plan(parent, plan_ref)


def _successor_result(
    tmp_path: Path,
) -> tuple[
    SimpleCheckpointStore,
    SimpleArtifactRepository,
    CheckpointIdentity,
    SimpleAnalysisRun,
    StoredDataRef,
    StoredDataRef,
    CandidateTerminal,
    dict[str, object],
]:
    store, artifacts, identity, parent, plan_ref, plan, _ = _completed_parent(tmp_path)
    assert store.pin_surface_enrichment_v10_plan(parent, plan_ref)
    pinned = store.require_analysis_run(identity.analysis_id)
    root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
    assert root is not None and pinned.candidate_terminal is not None
    assert parent.candidate_terminal is not None
    coverage_ref = artifacts.put_json(
        {
            "kind": "simple_attack_surface_coverage_v8",
            "scope_fingerprint": parent.candidate_scope_fingerprint,
            "static_bundle_hash": parent.candidate_terminal.bundle_hash,
            "index_hash": root.output_refs[0].content_hash,
            "v9_coverage_hash": root.output_refs[1].content_hash,
            "v10_plan_ref": plan_ref.model_dump(mode="json"),
            "surfaces": [{"surface_id": "surface-v8", "coverage_status": "COVERED"}],
            "pending_candidate_count": 0,
            "pending_child_count": 0,
            "complete": True,
        }
    )
    terminal = pinned.candidate_terminal.model_copy(
        update={
            "surface_proof_version": 8,
            "surface_coverage_hash": coverage_ref.content_hash,
            "surface_counts": {"COVERED": 1, "UNCOVERED": 0, "INSUFFICIENT": 0},
            "status": "COMPLETE",
        }
    )
    return store, artifacts, identity, pinned, plan_ref, coverage_ref, terminal, plan


def test_v10_promotion_replaces_root_and_terminal_atomically(tmp_path: Path) -> None:
    store, _artifacts, identity, pinned, plan_ref, coverage_ref, terminal, _ = (
        _successor_result(tmp_path)
    )
    old_root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)

    assert store.promote_surface_enrichment_v10_coverage(
        pinned, plan_ref, coverage_ref, terminal
    )
    saved = store.require_analysis_run(identity.analysis_id)
    root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
    assert root is not None and old_root is not None
    assert root.output_refs == (old_root.output_refs[0], coverage_ref)
    assert saved.candidate_terminal == terminal
    assert saved.surface_enrichment_v10_plan_ref == plan_ref
    assert saved.surface_enrichment_v9_plan_ref == pinned.surface_enrichment_v9_plan_ref
    assert not store.promote_surface_enrichment_v10_coverage(
        pinned, plan_ref, coverage_ref, terminal
    )


def test_v10_promotion_rejects_tampered_coverage_without_state_change(
    tmp_path: Path,
) -> None:
    store, artifacts, identity, pinned, plan_ref, _coverage_ref, terminal, _ = (
        _successor_result(tmp_path)
    )
    forged = artifacts.put_json(
        {"kind": "simple_attack_surface_coverage_v8", "complete": True}
    )
    original_run = store.require_analysis_run(identity.analysis_id)
    original_root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V10_RESULT_INVALID"):
        store.promote_surface_enrichment_v10_coverage(
            pinned,
            plan_ref,
            forged,
            terminal.model_copy(update={"surface_coverage_hash": forged.content_hash}),
        )
    assert store.require_analysis_run(identity.analysis_id) == original_run
    assert store.get(identity, SimpleStage.HYPOTHESIS_DONE) == original_root


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("decision_counts", {"FORGED": 1}),
        ("deep_counts", {"FORGED": 1}),
        ("hypothesis_count", 99),
        ("chaining_pool_fingerprint", "f" * 64),
        ("chaining_batch_count", 99),
    ),
)
def test_v10_promotion_rejects_changed_inherited_terminal_field(
    tmp_path: Path, field: str, value: object
) -> None:
    """The V10 CAS may change only the fields produced by successor coverage."""

    store, _artifacts, identity, pinned, plan_ref, coverage_ref, terminal, _ = (
        _successor_result(tmp_path)
    )
    assert getattr(terminal, field) != value
    original_run = store.require_analysis_run(identity.analysis_id)
    original_root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
    forged = terminal.model_copy(update={field: value})

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V10_RESULT_INVALID"):
        store.promote_surface_enrichment_v10_coverage(
            pinned, plan_ref, coverage_ref, forged
        )
    assert store.require_analysis_run(identity.analysis_id) == original_run
    assert store.get(identity, SimpleStage.HYPOTHESIS_DONE) == original_root
