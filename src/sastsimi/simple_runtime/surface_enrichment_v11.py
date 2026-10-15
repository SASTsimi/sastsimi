"""Immutable V11 plan for rechecking historical child HOLDs.

The plan is provenance, not a verdict. In particular, a listed target remains
unresolved until an independent reader verifies its later result artifact.
"""

from __future__ import annotations

import re

from sastsimi.contracts.refs import StoredDataRef

from .models import (
    CandidateTerminal,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from .surface_child_evidence_v11 import ChildHoldTargetV11
from .surface_coverage_v8 import SurfaceCoverageV8
from .surface_enrichment_v9 import _digest

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_HOLD_STAGES = frozenset(
    {
        SimpleStage.VERIFICATION_INITIAL_DONE,
        SimpleStage.POC_EXECUTION_DONE,
        SimpleStage.VERIFICATION_FINAL_DONE,
    }
)


def prepare_surface_enrichment_v11(
    identity: CheckpointIdentity,
    parent: SurfaceCoverageV8,
    v10_plan_ref: StoredDataRef,
    v10_coverage_ref: StoredDataRef,
    v10_terminal: CandidateTerminal,
    v10_root: StageCheckpoint,
    targets: tuple[ChildHoldTargetV11, ...],
    child_snapshot_hash: str,
    v9_progress_hash: str,
) -> dict[str, object]:
    """Bind every linked old HOLD to one exact replayable V10 predecessor."""

    if (
        identity.hypothesis_id is not None
        or v10_terminal.surface_proof_version != 8
        or not v10_terminal.producer_finished
        or v10_terminal.scope_fingerprint != parent.scope_fingerprint
        or v10_terminal.surface_index_hash != parent.index_hash
        or v10_terminal.surface_coverage_hash != v10_coverage_ref.content_hash
        or parent.v10_plan_ref != v10_plan_ref
        or _digest(parent.to_json()) != v10_coverage_ref.content_hash
        or v10_root.identity != identity
        or v10_root.stage is not SimpleStage.HYPOTHESIS_DONE
        or v10_root.status is not StageStatus.SUCCEEDED
        or v10_root.input_hash != input_reference_hash(v10_root.input_refs)
        or len(v10_root.output_refs) != 2
        or v10_root.output_refs[0].content_hash != parent.index_hash
        or v10_root.output_refs[1] != v10_coverage_ref
        or str(v10_plan_ref.workspace_id) != identity.workspace_id
        or str(v10_plan_ref.commit_id) != identity.commit_id
        or str(v10_coverage_ref.workspace_id) != identity.workspace_id
        or str(v10_coverage_ref.commit_id) != identity.commit_id
        or _HASH.fullmatch(v9_progress_hash) is None
        or _HASH.fullmatch(child_snapshot_hash) is None
    ):
        raise ValueError("SURFACE_ENRICHMENT_V11_PARENT_INVALID")
    surface_ids = {surface.surface_id for surface in parent.surfaces}
    keys = [(target.hypothesis_id, target.stage) for target in targets]
    if len(keys) != len(set(keys)) or any(
        not target.hypothesis_id
        or target.stage not in _HOLD_STAGES
        or not target.surface_ids
        or len(target.surface_ids) != len(set(target.surface_ids))
        or not set(target.surface_ids) <= surface_ids
        or _HASH.fullmatch(target.checkpoint_hash) is None
        for target in targets
    ):
        raise ValueError("SURFACE_ENRICHMENT_V11_CHILD_INVALID")
    return {
        "kind": "simple_surface_enrichment_plan_v11",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope_fingerprint": parent.scope_fingerprint,
        "static_bundle_hash": parent.static_bundle_hash,
        "index_hash": parent.index_hash,
        "ast_manifest_hash": parent.ast_manifest_hash,
        "candidate_inventory_hash": parent.candidate_inventory_hash,
        "v10_plan_ref": v10_plan_ref.model_dump(mode="json"),
        "v10_coverage_ref": v10_coverage_ref.model_dump(mode="json"),
        "v10_terminal": v10_terminal.model_dump(mode="json"),
        "v10_root": v10_root.model_dump(mode="json"),
        "v9_progress_hash": v9_progress_hash,
        "child_snapshot_hash": child_snapshot_hash,
        "targets": [
            {
                "hypothesis_id": target.hypothesis_id,
                "stage": target.stage.value,
                "surface_ids": list(target.surface_ids),
                "checkpoint_hash": target.checkpoint_hash,
            }
            for target in targets
        ],
    }
