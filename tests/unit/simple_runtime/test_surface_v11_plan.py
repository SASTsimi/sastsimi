"""A V11 child plan binds the exact V10 certificate and historical children."""

from __future__ import annotations

from dataclasses import replace

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.models import (
    CandidateTerminal,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.surface_child_evidence_v11 import ChildHoldTargetV11
from sastsimi.simple_runtime.surface_coverage_v2 import _ref
from sastsimi.simple_runtime.surface_coverage_v8 import SurfaceCoverageV8
from sastsimi.simple_runtime.surface_enrichment_v9 import _digest
from sastsimi.simple_runtime.surface_enrichment_v11 import (
    prepare_surface_enrichment_v11,
)
from tests.unit.simple_runtime.test_surface_coverage_v9 import _parent


def _inputs() -> tuple[
    CheckpointIdentity,
    SurfaceCoverageV8,
    StoredDataRef,
    StoredDataRef,
    CandidateTerminal,
    StageCheckpoint,
    ChildHoldTargetV11,
]:
    identity = CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    plan_ref = _ref(identity, "e" * 64)
    parent = replace(_parent(), index_hash="1" * 64, v10_plan_ref=plan_ref)
    index_ref = _ref(identity, parent.index_hash)
    coverage_ref = _ref(identity, _digest(parent.to_json()))
    root = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.HYPOTHESIS_DONE,
        status=StageStatus.SUCCEEDED,
        stage_version="1",
        attempt_number=1,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(index_ref, coverage_ref),
        attempt_id="root-attempt",
    )
    terminal = CandidateTerminal(
        status="COMPLETE",
        bundle_hash="c" * 64,
        scope_fingerprint=parent.scope_fingerprint,
        decision_counts={},
        deep_counts={},
        hypothesis_count=0,
        surface_index_hash=parent.index_hash,
        surface_coverage_hash=coverage_ref.content_hash,
        surface_proof_version=8,
        producer_finished=True,
        surface_counts={"COVERED": 1},
    )
    target = ChildHoldTargetV11(
        hypothesis_id="h1",
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        surface_ids=("route",),
        checkpoint_hash="d" * 64,
    )
    return identity, parent, plan_ref, coverage_ref, terminal, root, target


def test_v11_plan_freezes_parent_and_child_snapshot() -> None:
    identity, parent, plan_ref, coverage_ref, terminal, root, target = _inputs()
    plan = prepare_surface_enrichment_v11(
        identity,
        parent,
        plan_ref,
        coverage_ref,
        terminal,
        root,
        (target,),
        "f" * 64,
        "0" * 64,
    )
    assert plan["kind"] == "simple_surface_enrichment_plan_v11"
    assert plan["v10_terminal"] == terminal.model_dump(mode="json")
    assert plan["v10_root"] == root.model_dump(mode="json")
    assert plan["child_snapshot_hash"] == "f" * 64
    assert plan["targets"] == [
        {
            "hypothesis_id": "h1",
            "stage": target.stage.value,
            "surface_ids": ["route"],
            "checkpoint_hash": "d" * 64,
        }
    ]


def test_v11_plan_rejects_duplicate_or_unbound_child() -> None:
    identity, parent, plan_ref, coverage_ref, terminal, root, target = _inputs()
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V11_CHILD_INVALID"):
        prepare_surface_enrichment_v11(
            identity,
            parent,
            plan_ref,
            coverage_ref,
            terminal,
            root,
            (target, target),
            "f" * 64,
            "0" * 64,
        )
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V11_PARENT_INVALID"):
        prepare_surface_enrichment_v11(
            identity,
            parent,
            plan_ref,
            coverage_ref,
            terminal,
            root.model_copy(update={"output_refs": ()}),
            (target,),
            "f" * 64,
            "0" * 64,
        )
