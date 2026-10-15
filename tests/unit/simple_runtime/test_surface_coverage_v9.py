"""Child HOLD obligations are independent of inherited surface coverage."""

from __future__ import annotations

from dataclasses import replace

from sastsimi.simple_runtime.models import CheckpointIdentity, SimpleStage
from sastsimi.simple_runtime.surface_child_evidence_v11 import ChildHoldTargetV11
from sastsimi.simple_runtime.surface_coverage_v2 import _ref
from sastsimi.simple_runtime.surface_coverage_v8 import (
    SurfaceCoverageV8,
    SurfaceProofV8,
)
from sastsimi.simple_runtime.surface_coverage_v9 import (
    ChildDispositionV11,
    evaluate_surface_coverage_v9,
)


def _parent(*, old_reason: str | None = None) -> SurfaceCoverageV8:
    identity = CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    reasons = (old_reason,) if old_reason else ()
    return SurfaceCoverageV8(
        scope_fingerprint="s" * 64,
        static_bundle_hash="b" * 64,
        ast_manifest_hash="m" * 64,
        candidate_inventory_hash="c" * 64,
        candidate_count=0,
        index_hash="i" * 64,
        v9_coverage_hash="7" * 64,
        v10_plan_ref=_ref(identity, "1" * 64),
        raw_static_gaps=(),
        effective_python_gaps=(),
        missing_v9_parts=(),
        surfaces=(
            SurfaceProofV8(
                surface_id="route",
                path="app.py",
                line=1,
                coverage_status="INSUFFICIENT" if reasons else "COVERED",
                prior_v7_status="INSUFFICIENT",
                proof_kind="CONNECTED_PATHS",
                verified_roles=(),
                unresolved_reason_codes=reasons,
                reviewed_path_ids=(),
                reviewed_context_ids=(),
                completed_inconclusive_children=(),
                route_proof_hash="9" * 64,
                external_scope_limit=None,
            ),
        ),
        pending_candidate_count=0,
        pending_child_count=0,
        remaining_route_gap_events=(),
    )


def _target() -> ChildHoldTargetV11:
    return ChildHoldTargetV11(
        hypothesis_id="h1",
        stage=SimpleStage.POC_EXECUTION_DONE,
        surface_ids=("route",),
        checkpoint_hash="e" * 64,
    )


def test_covered_parent_with_unresolved_child_is_not_complete() -> None:
    parent = _parent()
    assert parent.complete

    result = evaluate_surface_coverage_v9(parent, (_target(),), {})

    assert not result.complete
    assert result.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "CHILD_HOLD" in result.surfaces[0].unresolved_reason_codes
    assert result.pending_child_revalidation_count == 1


def test_verified_child_does_not_erase_unrelated_route_gap() -> None:
    parent = _parent(old_reason="ROUTE_DOWNSTREAM_UNVERIFIED")
    target = _target()
    result = evaluate_surface_coverage_v9(
        parent,
        (target,),
        {
            (target.hypothesis_id, target.stage): ChildDispositionV11(
                checkpoint_hash=target.checkpoint_hash,
                status="RESOLVED",
                reason_code="VERIFIED_POC_INCONCLUSIVE",
                evidence_hash="f" * 64,
            )
        },
    )

    assert not result.complete
    assert result.surfaces[0].unresolved_reason_codes == (
        "ROUTE_DOWNSTREAM_UNVERIFIED",
    )
    assert result.resolved_child_revalidation_count == 1


def test_two_linked_children_need_two_resolutions() -> None:
    parent = _parent()
    first = _target()
    second = ChildHoldTargetV11(
        hypothesis_id="h2",
        stage=SimpleStage.POC_EXECUTION_DONE,
        surface_ids=("route",),
        checkpoint_hash="d" * 64,
    )
    dispositions = {
        (first.hypothesis_id, first.stage): ChildDispositionV11(
            checkpoint_hash=first.checkpoint_hash,
            status="RESOLVED",
            reason_code="VERIFIED_POC_INCONCLUSIVE",
            evidence_hash="f" * 64,
        ),
    }

    pending = evaluate_surface_coverage_v9(parent, (first, second), dispositions)
    assert not pending.complete
    assert pending.resolved_child_revalidation_count == 1
    assert pending.pending_child_revalidation_count == 1

    dispositions[(second.hypothesis_id, second.stage)] = ChildDispositionV11(
        checkpoint_hash=second.checkpoint_hash,
        status="RESOLVED",
        reason_code="VERIFIED_POC_INCONCLUSIVE",
        evidence_hash="c" * 64,
    )
    done = evaluate_surface_coverage_v9(parent, (first, second), dispositions)
    assert done.complete
    assert done.surfaces[0].coverage_status == "COVERED"


def test_wrong_checkpoint_hash_never_resolves_child() -> None:
    target = _target()
    result = evaluate_surface_coverage_v9(
        _parent(),
        (target,),
        {
            (target.hypothesis_id, target.stage): ChildDispositionV11(
                checkpoint_hash="0" * 64,
                status="RESOLVED",
                reason_code="VERIFIED_POC_INCONCLUSIVE",
                evidence_hash="f" * 64,
            )
        },
    )

    assert not result.complete
    assert result.error_child_revalidation_count == 1


def test_final_true_without_downstream_gates_is_not_resolved() -> None:
    target = ChildHoldTargetV11(
        hypothesis_id="h1",
        stage=SimpleStage.VERIFICATION_FINAL_DONE,
        surface_ids=("route",),
        checkpoint_hash="e" * 64,
    )
    result = evaluate_surface_coverage_v9(
        _parent(),
        (target,),
        {
            (target.hypothesis_id, target.stage): ChildDispositionV11(
                checkpoint_hash=target.checkpoint_hash,
                status="RESOLVED",
                reason_code="VERIFIED_FINAL_TRUE",
                evidence_hash="f" * 64,
            )
        },
    )
    assert not result.complete
    assert result.error_child_revalidation_count == 1


def test_historical_pending_count_is_not_permanently_inherited() -> None:
    """The current independently recounted set supersedes a stale V10 count."""

    parent = replace(_parent(), pending_child_count=2)

    result = evaluate_surface_coverage_v9(parent, (), {}, current_pending_child_count=0)

    assert result.pending_child_count == 0
    assert result.complete
