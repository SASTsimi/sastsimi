"""Immutable successor plan bound to a replayable v9 surface terminal.

The plan stores provenance, not a revised v9 verdict. Saved v9 artifacts and
review parts remain unchanged; a separate evaluator may use new route proofs.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import TYPE_CHECKING

from sastsimi.contracts.refs import StoredDataRef

from .attack_surfaces import SurfaceIndex, surface_review_contract
from .models import (
    CandidateTerminal,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from .surface_enrichment_v9 import _bound, _digest
from .surface_enrichment_v10_bindings import (
    v9_progress_snapshot_hash as v9_progress_snapshot_hash,
)
from .surface_route_boundary_v10 import RouteBoundaryProofV10, _dischargeable_event

if TYPE_CHECKING:
    from .surface_coverage_v7 import SurfaceCoverageV7

_HASH = re.compile(r"[0-9a-f]{64}\Z")
_BOUNDARIES = frozenset(
    {"NONE", "PYTHON_RESPONSE", "LITERAL_TEMPLATE", "PINNED_PYTHON_SINK"}
)


def _proofs_match_index(
    index: SurfaceIndex, proofs: Mapping[str, RouteBoundaryProofV10]
) -> bool:
    ids = [surface.surface_id for surface in index.surfaces]
    sources = dict(index.ast_source_hashes)
    if (
        index.index_version != 2
        or not index.ast_source_hashes
        or len(sources) != len(index.ast_source_hashes)
        or len(ids) != len(set(ids))
        or set(proofs) != set(ids)
    ):
        return False
    for surface in index.surfaces:
        proof = proofs.get(surface.surface_id)
        if (
            not isinstance(proof, RouteBoundaryProofV10)
            or proof.surface_id != surface.surface_id
            or proof.source_hashes != index.ast_source_hashes
            or proof.boundary_kind not in _BOUNDARIES
            or proof.external_scope_limit
            != (
                "TEMPLATE_CONTENT_NOT_ANALYZED"
                if proof.boundary_kind == "LITERAL_TEMPLATE"
                else None
            )
            or proof.boundary_kind != "NONE"
            and not proof.resolved_edges
            or any(
                edge.get("source_sha256") not in sources.values()
                for edge in proof.resolved_edges
            )
            or proof.boundary_kind == "PINNED_PYTHON_SINK"
            and any(
                edge.get("sink_surface_id")
                not in {
                    row.surface_id
                    for row in index.surfaces
                    if surface_review_contract(row.type) == "SINK"
                }
                for edge in proof.resolved_edges
            )
            or any(
                not _dischargeable_event(event, surface, proof.boundary_kind)
                or event.get("proof_kind")
                != (
                    "PINNED_LINEAR_PYTHON_RESPONSE"
                    if proof.boundary_kind == "PYTHON_RESPONSE"
                    else "PINNED_LITERAL_TEMPLATE_HANDOFF"
                    if proof.boundary_kind == "LITERAL_TEMPLATE"
                    else "PINNED_PYTHON_SINK_CALL"
                )
                for event in proof.discharged_gap_events
            )
            or len(
                {
                    (event.get("reason"), event.get("event_ordinal"))
                    for event in proof.discharged_gap_events
                }
            )
            != len(proof.discharged_gap_events)
        ):
            return False
    return True


def prepare_surface_enrichment_v10(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    parent_v7: SurfaceCoverageV7,
    v9_plan_ref: StoredDataRef,
    v9_coverage_ref: StoredDataRef,
    v9_terminal: CandidateTerminal,
    v9_progress_hash: str,
    proofs: Mapping[str, RouteBoundaryProofV10],
    *,
    v9_root: StageCheckpoint,
) -> dict[str, object]:
    """Build a content-addressable plan without modifying any v9 record."""

    if (
        identity.hypothesis_id is not None
        or identity.workspace_id != index.workspace_id
        or identity.commit_id != index.commit_id
        or not isinstance(v9_progress_hash, str)
        or _HASH.fullmatch(v9_progress_hash) is None
        or not isinstance(v9_terminal, CandidateTerminal)
        or v9_terminal.surface_proof_version != 7
        or not v9_terminal.producer_finished
        or v9_terminal.status == "COMPLETE"
        and not parent_v7.complete
        or v9_terminal.bundle_hash != index.static_bundle_hash
        or v9_terminal.scope_fingerprint != index.scope_fingerprint
        or v9_terminal.surface_index_hash != _digest(index.to_json())
        or v9_terminal.surface_coverage_hash != v9_coverage_ref.content_hash
        or v9_root.identity != identity
        or v9_root.stage is not SimpleStage.HYPOTHESIS_DONE
        or v9_root.status is not StageStatus.SUCCEEDED
        or v9_root.input_hash != input_reference_hash(v9_root.input_refs)
        or len(v9_root.output_refs) != 2
        or v9_root.output_refs[0].content_hash != _digest(index.to_json())
        or v9_root.output_refs[1] != v9_coverage_ref
        or v9_plan_ref.data_kind != "artifact"
        or v9_plan_ref.record_id is not None
        or str(v9_plan_ref.workspace_id) != identity.workspace_id
        or str(v9_plan_ref.commit_id) != identity.commit_id
        or str(v9_plan_ref.stored_data_id) != v9_plan_ref.content_hash
        or _HASH.fullmatch(v9_plan_ref.content_hash) is None
        or v9_coverage_ref.data_kind != "artifact"
        or v9_coverage_ref.record_id is not None
        or str(v9_coverage_ref.workspace_id) != identity.workspace_id
        or str(v9_coverage_ref.commit_id) != identity.commit_id
        or str(v9_coverage_ref.stored_data_id) != v9_coverage_ref.content_hash
        or _HASH.fullmatch(v9_coverage_ref.content_hash) is None
    ):
        raise ValueError("SURFACE_ENRICHMENT_V10_PARENT_INVALID")
    validate_surface_enrichment_v10_parent(
        identity, index, parent_v7, v9_plan_ref, v9_coverage_ref
    )
    if not _proofs_match_index(index, proofs):
        raise ValueError("SURFACE_ENRICHMENT_V10_PROOF_INVALID")
    return {
        "kind": "simple_surface_enrichment_plan_v10",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope_fingerprint": index.scope_fingerprint,
        "static_bundle_hash": index.static_bundle_hash,
        "ast_manifest_hash": index.ast_manifest_hash,
        "candidate_inventory_hash": index.candidate_inventory_hash,
        "candidate_count": index.candidate_count,
        "index_hash": _digest(index.to_json()),
        "ast_source_hashes": [
            {"path": path, "source_sha256": source_sha256}
            for path, source_sha256 in index.ast_source_hashes
        ],
        "v9_plan_ref": v9_plan_ref.model_dump(mode="json"),
        "v9_coverage_ref": v9_coverage_ref.model_dump(mode="json"),
        "v9_terminal": v9_terminal.model_dump(mode="json"),
        "v9_root": v9_root.model_dump(mode="json"),
        "v9_progress_hash": v9_progress_hash,
        "proofs": [
            {
                "surface_id": surface.surface_id,
                "proof_hash": _digest(proofs[surface.surface_id].to_json()),
            }
            for surface in index.surfaces
        ],
    }


def validate_surface_enrichment_v10_parent(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    parent: SurfaceCoverageV7,
    v9_plan_ref: StoredDataRef,
    v9_coverage_ref: StoredDataRef,
) -> None:
    """Reject an incomplete or mismatched v9 certificate before promotion."""

    if (
        not _bound(v9_coverage_ref, identity, parent.to_json())
        or parent.v9_plan_ref != v9_plan_ref
        or parent.missing_v9_parts
        or parent.scope_fingerprint != index.scope_fingerprint
        or parent.static_bundle_hash != index.static_bundle_hash
        or parent.ast_manifest_hash != index.ast_manifest_hash
        or parent.candidate_inventory_hash != index.candidate_inventory_hash
        or parent.candidate_count != index.candidate_count
        or parent.index_hash != _digest(index.to_json())
        or len(parent.surfaces) != len(index.surfaces)
        or any(
            (row.surface_id, row.path, row.line)
            != (surface.surface_id, surface.path, surface.line)
            for row, surface in zip(parent.surfaces, index.surfaces, strict=True)
        )
    ):
        raise ValueError("SURFACE_ENRICHMENT_V10_PARENT_INVALID")
