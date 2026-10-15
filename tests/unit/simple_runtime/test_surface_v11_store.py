"""The V11 successor must pin atomically without rewriting old child records."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.attack_surfaces import AttackSurface, SurfaceIndex
from sastsimi.simple_runtime.models import (
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import V11PromotionReaders
from sastsimi.simple_runtime.surface_child_evidence_v11 import (
    collect_child_hold_targets_v11,
)
from sastsimi.simple_runtime.surface_coverage_v8 import (
    SurfaceCoverageV8,
    SurfaceProofV8,
)
from sastsimi.simple_runtime.surface_coverage_v9 import (
    ChildDispositionV11,
    SurfaceCoverageV9,
    evaluate_surface_coverage_v9,
)
from sastsimi.simple_runtime.surface_enrichment_v10_bindings import (
    v9_progress_snapshot_hash,
)
from sastsimi.simple_runtime.surface_enrichment_v11 import (
    prepare_surface_enrichment_v11,
)
from tests.unit.simple_runtime.test_surface_v10_store_pin import _successor_result


def _readers() -> V11PromotionReaders:
    from sastsimi.simple_runtime.surface_child_evidence_v11 import (
        collect_child_hold_targets_v11 as collect_targets,
    )
    from sastsimi.simple_runtime.surface_coverage_v8_read import (
        verified_saved_coverage_v8,
    )
    from sastsimi.simple_runtime.surface_coverage_v9 import (
        evaluate_surface_coverage_v9 as evaluate_coverage,
    )
    from sastsimi.simple_runtime.surface_coverage_v9_read import (
        verified_child_dispositions_v11,
    )
    from sastsimi.simple_runtime.surface_enrichment_v11 import (
        prepare_surface_enrichment_v11 as prepare_plan,
    )

    return V11PromotionReaders(
        collect_child_hold_targets_v11=collect_targets,
        verified_saved_coverage_v8=verified_saved_coverage_v8,
        evaluate_surface_coverage_v9=evaluate_coverage,
        verified_child_dispositions_v11=verified_child_dispositions_v11,
        prepare_surface_enrichment_v11=prepare_plan,
    )


def _v11_case(tmp_path: Path, *, with_hold: bool = False):  # type: ignore[no-untyped-def]
    (
        store,
        artifacts,
        identity,
        pinned,
        v10_plan_ref,
        coverage_ref,
        terminal,
        v10_plan,
    ) = _successor_result(tmp_path)
    assert store.promote_surface_enrichment_v10_coverage(
        pinned, v10_plan_ref, coverage_ref, terminal
    )
    run = store.require_analysis_run(identity.analysis_id)
    root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
    assert root is not None
    targets = []
    if with_hold:
        child = identity.model_copy(update={"hypothesis_id": "child"})
        checkpoint = StageCheckpoint(
            identity=child,
            stage=SimpleStage.VERIFICATION_INITIAL_DONE,
            stage_version="1",
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(),
            attempt_id="old-attempt",
            verdict="HOLD",
        )
        store.save_checkpoint(checkpoint)
        targets.append(
            {
                "hypothesis_id": "child",
                "stage": checkpoint.stage.value,
                "surface_ids": ["surface-v8"],
                "checkpoint_hash": hashlib.sha256(
                    canonical_bytes(checkpoint)
                ).hexdigest(),
            }
        )
    plan = {
        "kind": "simple_surface_enrichment_plan_v11",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope_fingerprint": run.candidate_scope_fingerprint,
        "static_bundle_hash": terminal.bundle_hash,
        "index_hash": terminal.surface_index_hash,
        "v10_plan_ref": v10_plan_ref.model_dump(mode="json"),
        "v10_coverage_ref": coverage_ref.model_dump(mode="json"),
        "v10_terminal": terminal.model_dump(mode="json"),
        "v10_root": root.model_dump(mode="json"),
        "v9_progress_hash": v10_plan["v9_progress_hash"],
        "child_snapshot_hash": "f" * 64,
        "targets": targets,
    }
    plan_ref = artifacts.put_json(plan)
    return store, identity, run, root, plan_ref


def test_v11_pin_suspends_old_complete_and_is_idempotent(tmp_path: Path) -> None:
    store, identity, run, old_root, plan_ref = _v11_case(tmp_path)
    assert run.candidate_terminal is not None
    assert run.candidate_terminal.status == "COMPLETE"

    assert store.pin_surface_enrichment_v11_plan(run, plan_ref)

    saved = store.require_analysis_run(identity.analysis_id)
    assert saved.surface_enrichment_v11_plan_ref == plan_ref
    assert saved.surface_enrichment_status == "RUNNING"
    assert saved.candidate_terminal is not None
    assert saved.candidate_terminal.status == "PARTIAL"
    assert store.get(identity, SimpleStage.HYPOTHESIS_DONE) == old_root
    assert not store.pin_surface_enrichment_v11_plan(run, plan_ref)


def test_v11_pin_rejects_forged_plan_without_state_change(tmp_path: Path) -> None:
    store, identity, run, root, _plan_ref = _v11_case(tmp_path)
    artifacts = __import__(
        "sastsimi.simple_runtime.artifacts", fromlist=["SimpleArtifactRepository"]
    ).SimpleArtifactRepository(tmp_path / "data", identity)
    forged = artifacts.put_json(
        {"kind": "simple_surface_enrichment_plan_v11", "targets": []}
    )
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V11_PIN_INVALID"):
        store.pin_surface_enrichment_v11_plan(run, forged)
    assert store.require_analysis_run(identity.analysis_id) == run
    assert store.get(identity, SimpleStage.HYPOTHESIS_DONE) == root


def test_v11_child_attempt_is_claimed_once_and_saved_separately(tmp_path: Path) -> None:
    store, identity, run, old_root, plan_ref = _v11_case(tmp_path, with_hold=True)
    assert store.pin_surface_enrichment_v11_plan(run, plan_ref)
    scope = run.candidate_scope_fingerprint
    assert scope is not None
    progress = store.list_surface_child_revalidation_v11(identity, scope, plan_ref)
    key = ("child", SimpleStage.VERIFICATION_INITIAL_DONE)
    assert progress[key].status == "PENDING"
    old_hash = progress[key].checkpoint_hash
    attempt_id = uuid4().hex

    assert store.claim_surface_child_revalidation_v11(
        identity, scope, plan_ref, "child", key[1], old_hash, attempt_id
    )
    assert not store.claim_surface_child_revalidation_v11(
        identity, scope, plan_ref, "child", key[1], old_hash, uuid4().hex
    )
    result_ref = (
        __import__(
            "sastsimi.simple_runtime.artifacts", fromlist=["SimpleArtifactRepository"]
        )
        .SimpleArtifactRepository(tmp_path / "data", identity)
        .put_json(
            {
                "kind": "simple_surface_child_revalidation_result_v11",
                "plan_ref": plan_ref.model_dump(mode="json"),
                "hypothesis_id": "child",
                "stage": key[1].value,
                "checkpoint_hash": old_hash,
                "status": "STILL_HOLD",
                "reason_code": "EXTERNAL_PREREQUISITE_UNPROVEN",
                "evidence_refs": [],
            }
        )
    )
    assert store.finish_surface_child_revalidation_v11(
        identity,
        scope,
        plan_ref,
        "child",
        key[1],
        old_hash,
        attempt_id,
        "STILL_HOLD",
        "EXTERNAL_PREREQUISITE_UNPROVEN",
        result_ref,
    )
    saved = store.list_surface_child_revalidation_v11(identity, scope, plan_ref)
    assert saved[key].status == "STILL_HOLD"
    assert saved[key].result_ref == result_ref
    assert store.get(identity, SimpleStage.HYPOTHESIS_DONE) == old_root


def test_v11_claim_rejects_old_checkpoint_changed_after_pin(tmp_path: Path) -> None:
    store, identity, run, _root, plan_ref = _v11_case(tmp_path, with_hold=True)
    assert store.pin_surface_enrichment_v11_plan(run, plan_ref)
    scope = run.candidate_scope_fingerprint
    assert scope is not None
    stage = SimpleStage.VERIFICATION_INITIAL_DONE
    key = ("child", stage)
    old_hash = store.list_surface_child_revalidation_v11(identity, scope, plan_ref)[
        key
    ].checkpoint_hash
    child = identity.model_copy(update={"hypothesis_id": "child"})
    old = store.get(child, stage)
    assert old is not None
    store.save_checkpoint(old.model_copy(update={"attempt_number": 2}))

    with pytest.raises(ValueError, match="SURFACE_CHILD_V11_CLAIM_STALE"):
        store.claim_surface_child_revalidation_v11(
            identity, scope, plan_ref, "child", stage, old_hash, uuid4().hex
        )


def test_v11_blocked_preflight_with_only_pending_children_can_resume(
    tmp_path: Path,
) -> None:
    store, identity, run, root, plan_ref = _v11_case(tmp_path, with_hold=True)
    assert store.pin_surface_enrichment_v11_plan(run, plan_ref)
    pinned = store.require_analysis_run(identity.analysis_id)
    blocked = pinned.model_copy(
        update={
            "surface_enrichment_status": "BLOCKED",
            "surface_enrichment_error_code": "SURFACE_ENRICHMENT_V11_REPLAY_INVALID",
        }
    )
    store.save_analysis_run(blocked)
    assert store.resume_surface_enrichment_v11_if_safe(blocked, plan_ref)
    resumed = store.require_analysis_run(identity.analysis_id)
    assert resumed.surface_enrichment_status == "RUNNING"
    assert resumed.surface_enrichment_error_code is None
    assert store.get(identity, SimpleStage.HYPOTHESIS_DONE) == root


def test_v11_blocked_in_flight_child_cannot_resume_without_cleanup_proof(
    tmp_path: Path,
) -> None:
    store, identity, run, _root, plan_ref = _v11_case(tmp_path, with_hold=True)
    assert store.pin_surface_enrichment_v11_plan(run, plan_ref)
    pinned = store.require_analysis_run(identity.analysis_id)
    scope = run.candidate_scope_fingerprint
    assert scope is not None
    progress = store.list_surface_child_revalidation_v11(identity, scope, plan_ref)
    key = ("child", SimpleStage.VERIFICATION_INITIAL_DONE)
    assert store.claim_surface_child_revalidation_v11(
        identity,
        scope,
        plan_ref,
        "child",
        key[1],
        progress[key].checkpoint_hash,
        uuid4().hex,
    )
    blocked = pinned.model_copy(
        update={
            "surface_enrichment_status": "BLOCKED",
            "surface_enrichment_error_code": "SURFACE_CHILD_V11_ATTEMPT_IN_FLIGHT",
        }
    )
    store.save_analysis_run(blocked)
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V11_RESUME_UNSAFE"):
        store.resume_surface_enrichment_v11_if_safe(blocked, plan_ref)
    assert store.require_analysis_run(identity.analysis_id) == blocked


def _promotion_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, with_hold: bool
) -> tuple[Any, ...]:
    """Real CAS/ledger fixture; only the deep V10 replay is isolated."""

    store, artifacts, identity, pinned, v10_plan_ref, old_ref, old_terminal, _ = (
        _successor_result(tmp_path)
    )
    assert store.promote_surface_enrichment_v10_coverage(
        pinned, v10_plan_ref, old_ref, old_terminal
    )
    run = store.require_analysis_run(identity.analysis_id)
    root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
    assert run.candidate_terminal is not None and root is not None
    index = SurfaceIndex(
        scope_fingerprint="scope-v8",
        static_bundle_hash=run.candidate_terminal.bundle_hash,
        ast_manifest_hash="a" * 64,
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        candidate_inventory_hash="b" * 64,
        candidate_count=0,
        surfaces=(
            AttackSurface(
                surface_id="surface-v8",
                type="SQL_EXECUTION",
                path="app.py",
                symbol="run",
                line=4,
                linked_candidate_ids=("candidate-1",),
                evidence_refs=(),
                detector="fixture",
            ),
        ),
        static_gaps=(),
    )
    index_ref = artifacts.put_json(index.to_json())
    assert run.surface_enrichment_v9_plan_ref is not None
    v9_plan = json.loads(artifacts.read(run.surface_enrichment_v9_plan_ref))
    v9_progress = store.list_surface_exploration_progress(
        identity, index.scope_fingerprint
    )
    v10_plan = {
        "v9_plan_ref": run.surface_enrichment_v9_plan_ref.model_dump(mode="json"),
        "v9_progress_hash": v9_progress_snapshot_hash(v9_plan, v9_progress),
    }
    successor_plan_ref = artifacts.put_json(v10_plan)
    parent = SurfaceCoverageV8(
        scope_fingerprint=index.scope_fingerprint,
        static_bundle_hash=index.static_bundle_hash,
        ast_manifest_hash=index.ast_manifest_hash,
        candidate_inventory_hash=index.candidate_inventory_hash,
        candidate_count=0,
        index_hash=index_ref.content_hash,
        v9_coverage_hash="d" * 64,
        v10_plan_ref=successor_plan_ref,
        raw_static_gaps=(),
        effective_python_gaps=(),
        missing_v9_parts=(),
        surfaces=(
            SurfaceProofV8(
                surface_id="surface-v8",
                path="app.py",
                line=4,
                coverage_status="COVERED",
                prior_v7_status="INSUFFICIENT",
                proof_kind="ROUTE_BOUND",
                verified_roles=(),
                unresolved_reason_codes=(),
                reviewed_path_ids=(),
                reviewed_context_ids=(),
                completed_inconclusive_children=(),
                route_proof_hash="e" * 64,
                external_scope_limit=None,
            ),
        ),
        pending_candidate_count=0,
        pending_child_count=0,
        remaining_route_gap_events=(),
    )
    parent_ref = artifacts.put_json(parent.to_json())
    predecessor = run.candidate_terminal.model_copy(
        update={
            "surface_index_hash": index_ref.content_hash,
            "surface_coverage_hash": parent_ref.content_hash,
            "surface_counts": {"COVERED": 1, "UNCOVERED": 0, "INSUFFICIENT": 0},
        }
    )
    predecessor_root = root.model_copy(update={"output_refs": (index_ref, parent_ref)})
    store.save_checkpoint(predecessor_root)
    store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_terminal": predecessor,
                "surface_enrichment_v10_plan_ref": successor_plan_ref,
            }
        )
    )
    if with_hold:
        child = identity.model_copy(update={"hypothesis_id": "child"})
        old = StageCheckpoint(
            identity=child,
            stage=SimpleStage.VERIFICATION_INITIAL_DONE,
            stage_version="1",
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(),
            attempt_id="historical-child",
            verdict="HOLD",
        )
        store.save_checkpoint(old)
        with store._connect() as connection:
            connection.execute(
                "INSERT INTO simple_candidate_hypothesis_links "
                "(analysis_id, workspace_id, commit_id, scope_fingerprint, "
                "candidate_id, hypothesis_id) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    identity.analysis_id,
                    identity.workspace_id,
                    identity.commit_id,
                    index.scope_fingerprint,
                    "candidate-1",
                    "child",
                ),
            )
    progress = store.list_surface_exploration_progress(
        identity, index.scope_fingerprint
    )
    targets, snapshot_hash = collect_child_hold_targets_v11(
        identity, index, progress, store
    )
    plan = prepare_surface_enrichment_v11(
        identity,
        parent,
        successor_plan_ref,
        parent_ref,
        predecessor,
        predecessor_root,
        targets,
        snapshot_hash,
        cast(str, v10_plan["v9_progress_hash"]),
    )
    plan_ref = artifacts.put_json(plan)
    current = store.require_analysis_run(identity.analysis_id)
    assert store.pin_surface_enrichment_v11_plan(current, plan_ref)
    pinned_v11 = store.require_analysis_run(identity.analysis_id)
    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_coverage_v8_read.verified_saved_coverage_v8",
        lambda *_args, **_kwargs: parent,
    )
    return store, artifacts, identity, pinned_v11, plan_ref, parent, targets


def test_v11_promotion_keeps_still_hold_partial_and_is_atomic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, artifacts, identity, pinned, plan_ref, parent, targets = _promotion_case(
        tmp_path, monkeypatch, with_hold=True
    )
    target = targets[0]
    scope = parent.scope_fingerprint
    attempt_id = uuid4().hex
    assert store.claim_surface_child_revalidation_v11(
        identity,
        scope,
        plan_ref,
        target.hypothesis_id,
        target.stage,
        target.checkpoint_hash,
        attempt_id,
    )
    result_ref = artifacts.put_json(
        {
            "kind": "simple_surface_child_revalidation_result_v11",
            "plan_ref": plan_ref.model_dump(mode="json"),
            "hypothesis_id": target.hypothesis_id,
            "stage": target.stage.value,
            "checkpoint_hash": target.checkpoint_hash,
            "attempt_id": attempt_id,
            "status": "STILL_HOLD",
            "reason_code": "EXTERNAL_PREREQUISITE_UNPROVEN",
            "evidence_refs": [],
        }
    )
    assert store.finish_surface_child_revalidation_v11(
        identity,
        scope,
        plan_ref,
        target.hypothesis_id,
        target.stage,
        target.checkpoint_hash,
        attempt_id,
        "STILL_HOLD",
        "EXTERNAL_PREREQUISITE_UNPROVEN",
        result_ref,
    )
    coverage = evaluate_surface_coverage_v9(
        parent,
        targets,
        {
            (target.hypothesis_id, target.stage): ChildDispositionV11(
                checkpoint_hash=target.checkpoint_hash,
                status="STILL_HOLD",
                reason_code="EXTERNAL_PREREQUISITE_UNPROVEN",
                evidence_hash=None,
            )
        },
        current_pending_child_count=0,
    )
    assert not coverage.complete
    coverage_ref = artifacts.put_json(coverage.to_json())
    assert pinned.candidate_terminal is not None
    predecessor = json.loads(artifacts.read(plan_ref))["v10_terminal"]
    expected_terminal = pinned.candidate_terminal.model_validate(
        predecessor
    ).model_copy(
        update={
            "status": "PARTIAL",
            "surface_coverage_hash": coverage_ref.content_hash,
            "surface_counts": {"COVERED": 0, "UNCOVERED": 0, "INSUFFICIENT": 1},
            "surface_proof_version": 9,
            "pending_child_count": 0,
        }
    )
    prior_root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
    assert store.promote_surface_enrichment_v11_coverage(
        pinned, plan_ref, coverage_ref, expected_terminal, readers=_readers()
    )
    saved = store.require_analysis_run(identity.analysis_id)
    current_root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
    assert saved.candidate_terminal == expected_terminal
    assert saved.surface_enrichment_status == "PARTIAL"
    assert current_root is not None and prior_root is not None
    assert current_root.output_refs == (prior_root.output_refs[0], coverage_ref)
    assert not store.promote_surface_enrichment_v11_coverage(
        pinned, plan_ref, coverage_ref, expected_terminal, readers=_readers()
    )


def test_v11_promotion_rejects_false_complete_with_pending_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, artifacts, identity, pinned, plan_ref, parent, targets = _promotion_case(
        tmp_path, monkeypatch, with_hold=True
    )
    coverage = evaluate_surface_coverage_v9(parent, targets, {})
    coverage_ref = artifacts.put_json(coverage.to_json())
    assert pinned.candidate_terminal is not None
    forged_terminal = pinned.candidate_terminal.model_copy(
        update={
            "status": "COMPLETE",
            "surface_proof_version": 9,
            "surface_coverage_hash": coverage_ref.content_hash,
            "surface_counts": {"COVERED": 0, "UNCOVERED": 0, "INSUFFICIENT": 1},
        }
    )
    old_root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V11_RESULT_INVALID"):
        store.promote_surface_enrichment_v11_coverage(
            pinned, plan_ref, coverage_ref, forged_terminal, readers=_readers()
        )
    assert store.require_analysis_run(identity.analysis_id) == pinned
    assert store.get(identity, SimpleStage.HYPOTHESIS_DONE) == old_root


def test_v11_promotion_rejects_missing_reader_bundle_before_any_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, artifacts, identity, pinned, plan_ref, parent, targets = _promotion_case(
        tmp_path, monkeypatch, with_hold=False
    )
    coverage = evaluate_surface_coverage_v9(
        parent, targets, {}, current_pending_child_count=0
    )
    coverage_ref = artifacts.put_json(coverage.to_json())
    assert pinned.candidate_terminal is not None
    predecessor = json.loads(artifacts.read(plan_ref))["v10_terminal"]
    terminal = pinned.candidate_terminal.model_validate(predecessor).model_copy(
        update={
            "status": "COMPLETE",
            "surface_coverage_hash": coverage_ref.content_hash,
            "surface_counts": {"COVERED": 1, "UNCOVERED": 0, "INSUFFICIENT": 0},
            "surface_proof_version": 9,
            "pending_child_count": 0,
        }
    )
    old_root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V11_READERS_INVALID"):
        store.promote_surface_enrichment_v11_coverage(
            pinned, plan_ref, coverage_ref, terminal, readers=None
        )
    assert store.require_analysis_run(identity.analysis_id) == pinned
    assert store.get(identity, SimpleStage.HYPOTHESIS_DONE) == old_root


def test_v11_promotion_replays_v10_without_holding_sqlite_write_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, artifacts, identity, pinned, plan_ref, parent, targets = _promotion_case(
        tmp_path, monkeypatch, with_hold=False
    )
    assert not targets
    coverage = evaluate_surface_coverage_v9(
        parent, targets, {}, current_pending_child_count=0
    )
    assert coverage.complete
    coverage_ref = artifacts.put_json(coverage.to_json())
    assert pinned.candidate_terminal is not None
    predecessor = json.loads(artifacts.read(plan_ref))["v10_terminal"]
    terminal = pinned.candidate_terminal.model_validate(predecessor).model_copy(
        update={
            "status": "COMPLETE",
            "surface_coverage_hash": coverage_ref.content_hash,
            "surface_counts": {"COVERED": 1, "UNCOVERED": 0, "INSUFFICIENT": 0},
            "surface_proof_version": 9,
            "pending_child_count": 0,
        }
    )

    def read_parent(*_args: object, **_kwargs: object) -> SurfaceCoverageV8:
        # A second writer must not hit the store's five-second busy timeout
        # while source/graph replay is running.
        with store._connect() as peer:
            peer.execute("BEGIN IMMEDIATE")
            peer.rollback()
        return cast(SurfaceCoverageV8, parent)

    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_coverage_v8_read.verified_saved_coverage_v8",
        read_parent,
    )
    assert store.promote_surface_enrichment_v11_coverage(
        pinned, plan_ref, coverage_ref, terminal, readers=_readers()
    )
    saved = store.require_analysis_run(identity.analysis_id)
    assert saved.candidate_terminal == terminal


def test_v11_promotion_rejects_new_hold_after_unlocked_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, artifacts, identity, pinned, plan_ref, parent, targets = _promotion_case(
        tmp_path, monkeypatch, with_hold=False
    )
    assert not targets and pinned.candidate_terminal is not None
    coverage = evaluate_surface_coverage_v9(
        parent, targets, {}, current_pending_child_count=0
    )
    coverage_ref = artifacts.put_json(coverage.to_json())
    predecessor = json.loads(artifacts.read(plan_ref))["v10_terminal"]
    forged_complete = pinned.candidate_terminal.model_validate(predecessor).model_copy(
        update={
            "status": "COMPLETE",
            "surface_coverage_hash": coverage_ref.content_hash,
            "surface_counts": {"COVERED": 1, "UNCOVERED": 0, "INSUFFICIENT": 0},
            "surface_proof_version": 9,
            "pending_child_count": 0,
        }
    )
    old_root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
    original_evaluate = evaluate_surface_coverage_v9
    raced = False

    def insert_new_hold(*args: object, **kwargs: object) -> SurfaceCoverageV9:
        nonlocal raced
        result = cast(Callable[..., SurfaceCoverageV9], original_evaluate)(
            *args, **kwargs
        )
        if not raced:
            raced = True
            child = identity.model_copy(update={"hypothesis_id": "late-child"})
            store.save_checkpoint(
                StageCheckpoint(
                    identity=child,
                    stage=SimpleStage.VERIFICATION_INITIAL_DONE,
                    stage_version="1",
                    status=StageStatus.SUCCEEDED,
                    input_refs=(),
                    input_hash=input_reference_hash(()),
                    output_refs=(),
                    verdict="HOLD",
                )
            )
            with store._connect() as connection:
                connection.execute(
                    "INSERT INTO simple_candidate_hypothesis_links "
                    "(analysis_id, workspace_id, commit_id, scope_fingerprint, "
                    "candidate_id, hypothesis_id) VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        identity.analysis_id,
                        identity.workspace_id,
                        identity.commit_id,
                        parent.scope_fingerprint,
                        "candidate-1",
                        "late-child",
                    ),
                )
        return result

    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_coverage_v9.evaluate_surface_coverage_v9",
        insert_new_hold,
    )
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V11_RESULT_INVALID"):
        store.promote_surface_enrichment_v11_coverage(
            pinned, plan_ref, coverage_ref, forged_complete, readers=_readers()
        )
    assert raced
    assert store.require_analysis_run(identity.analysis_id) == pinned
    assert store.get(identity, SimpleStage.HYPOTHESIS_DONE) == old_root
