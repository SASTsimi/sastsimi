"""Pure, additive planning for one source-bound successor surface review.

The caller must first verify the saved v3 certificate and persist the returned
plan under an exact compare-and-set. This module never reads or changes saved
progress, checkpoints, or artifacts.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from functools import partial
from typing import cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .attack_surfaces import AttackSurface, SurfaceIndex
from .models import CheckpointIdentity
from .surface_contexts import SurfaceContextOverflow
from .surface_coverage_v3 import SurfaceCoverageV3, SurfaceProofV3
from .surface_enrichment_v5 import (
    _MAX_PART_BYTES,
    _READER_REVISION,
    _graph_items,
    _part_payload,
    _sha,
)
from .surface_evidence_validation_v5 import validate_v5_context

_GRAPH_SEMANTICS_REVISION = "v5-source-bound-3"


@dataclass(frozen=True, slots=True)
class V6Part:
    payload: dict[str, object]
    surface_id: str
    context_id: str
    context_hash: str
    part_index: int
    part_count: int
    source_sha256: str | None


def _artifact_ref_matches(
    ref: StoredDataRef, identity: CheckpointIdentity, digest: str
) -> bool:
    return (
        str(ref.workspace_id) == identity.workspace_id
        and str(ref.commit_id) == identity.commit_id
        and ref.data_kind == "artifact"
        and ref.record_id is None
        and str(ref.stored_data_id) == ref.content_hash == digest
    )


def _valid_parent(
    identity: CheckpointIdentity,
    scope: str,
    index: SurfaceIndex,
    index_ref: StoredDataRef,
    prior_v3_ref: StoredDataRef,
    prior_v3: SurfaceCoverageV3,
    prior_v5_plan_ref: StoredDataRef,
    prior_v5_plan: Mapping[str, object],
) -> None:
    invalid = "SURFACE_ENRICHMENT_V6_PARENT_INVALID"
    index_hash = _sha(index.to_json())
    if (
        not scope
        or identity.hypothesis_id is not None
        or index.index_version != 2
        or index.workspace_id != identity.workspace_id
        or index.commit_id != identity.commit_id
        or not _artifact_ref_matches(index_ref, identity, index_hash)
        or not _artifact_ref_matches(prior_v3_ref, identity, _sha(prior_v3.to_json()))
        or not _artifact_ref_matches(prior_v5_plan_ref, identity, _sha(prior_v5_plan))
        or prior_v3.v5_plan_ref != prior_v5_plan_ref
        or prior_v3.scope_fingerprint != index.scope_fingerprint
        or prior_v3.static_bundle_hash != index.static_bundle_hash
        or prior_v3.ast_manifest_hash != index.ast_manifest_hash
        or prior_v3.candidate_inventory_hash != index.candidate_inventory_hash
        or prior_v3.candidate_count != index.candidate_count
        or prior_v3.index_hash != index_hash
        or prior_v3.pending_candidate_count != 0
        or prior_v3.pending_child_count != 0
        or len(prior_v3.surfaces) != len(index.surfaces)
        or any(
            proof.surface_id != surface.surface_id
            or proof.path != surface.path
            or proof.line != surface.line
            or (proof.coverage_status == "COVERED")
            == bool(proof.unresolved_reason_codes)
            for surface, proof in zip(index.surfaces, prior_v3.surfaces, strict=True)
        )
        or prior_v5_plan.get("kind") != "simple_surface_enrichment_plan_v5"
        or prior_v5_plan.get("analysis_id") != identity.analysis_id
        or prior_v5_plan.get("workspace_id") != identity.workspace_id
        or prior_v5_plan.get("commit_id") != identity.commit_id
        or prior_v5_plan.get("scope") != scope
        or prior_v5_plan.get("scope_fingerprint") != index.scope_fingerprint
        or prior_v5_plan.get("static_bundle_hash") != index.static_bundle_hash
        or prior_v5_plan.get("ast_manifest_hash") != index.ast_manifest_hash
        or prior_v5_plan.get("candidate_inventory_hash")
        != index.candidate_inventory_hash
        or prior_v5_plan.get("index_ref") != index_ref.model_dump(mode="json")
        or prior_v5_plan.get("index_hash") != index_hash
        or prior_v5_plan.get("v2_coverage_ref")
        != prior_v3.prior_v2_ref.model_dump(mode="json")
        or prior_v5_plan.get("v2_coverage_hash") != prior_v3.prior_v2_ref.content_hash
        or prior_v5_plan.get("original_coverage_ref")
        != prior_v3.original_coverage_ref.model_dump(mode="json")
        or prior_v5_plan.get("scope_certificate_ref")
        != prior_v3.scope_certificate_ref.model_dump(mode="json")
        or prior_v5_plan.get("reader_revision") != _READER_REVISION
        or not isinstance(prior_v5_plan.get("plan_binding_hash"), str)
        or not isinstance(prior_v5_plan.get("targets"), list)
        or not isinstance(prior_v5_plan.get("expected_parts"), list)
    ):
        raise ValueError(invalid)
    try:
        v4_ref = StoredDataRef.model_validate(prior_v5_plan["v4_plan_ref"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(invalid) from error
    if (
        not _artifact_ref_matches(
            v4_ref, identity, cast(str, prior_v5_plan.get("v4_plan_hash"))
        )
        or not _artifact_ref_matches(
            prior_v3.prior_v2_ref,
            identity,
            prior_v3.prior_v2_ref.content_hash,
        )
        or not _artifact_ref_matches(
            prior_v3.original_coverage_ref,
            identity,
            prior_v3.original_coverage_ref.content_hash,
        )
        or not _artifact_ref_matches(
            prior_v3.scope_certificate_ref,
            identity,
            prior_v3.scope_certificate_ref.content_hash,
        )
    ):
        raise ValueError(invalid)
    old_targets = prior_v5_plan["target_surface_ids"]
    old_parts = prior_v5_plan["expected_parts"]
    old_children = prior_v5_plan.get("child_checkpoint_hashes")
    if (
        not isinstance(old_targets, list)
        or old_targets
        != [
            proof.surface_id
            for proof in prior_v3.surfaces
            if proof.prior_v2_status == "INSUFFICIENT"
        ]
        or not isinstance(old_parts, list)
        or any(
            not isinstance(row, dict)
            or not isinstance(row.get("context_id"), str)
            or not row["context_id"]
            for row in old_parts
        )
        or not isinstance(old_children, dict)
        or any(
            not isinstance(key, str)
            or not key
            or not isinstance(value, str)
            or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)
            for key, value in old_children.items()
        )
    ):
        raise ValueError(invalid)


def _context_payload(
    *,
    identity: CheckpointIdentity,
    scope: str,
    index: SurfaceIndex,
    index_hash: str,
    surface: AttackSurface,
    source_sha256: str | None,
    graph_hash: str,
    binding_hash: str,
    prior_proof: SurfaceProofV3,
    prior_v3_ref: StoredDataRef,
    prior_v5_plan_ref: StoredDataRef,
    prior_v5_plan: Mapping[str, object],
    child_hash: str,
    items: list[dict[str, object]],
    part_index: int,
    part_count: int,
    unavailable_count: int,
) -> dict[str, object]:
    payload = _part_payload(
        identity=identity,
        scope=scope,
        index=index,
        index_hash=index_hash,
        surface=surface,
        source_sha256=source_sha256,
        graph_hash=graph_hash,
        plan_binding_hash=binding_hash,
        parent_progress_hash=_sha(prior_proof.to_json()),
        prior_reasons=list(prior_proof.unresolved_reason_codes),
        v4_plan_hash=cast(str, prior_v5_plan["v4_plan_hash"]),
        v2_coverage_hash=cast(str, prior_v5_plan["v2_coverage_hash"]),
        child_checkpoint_hash=child_hash,
        items=items,
        part_index=part_index,
        part_count=part_count,
        unavailable_count=unavailable_count,
    )
    payload.update(
        prior_v3_coverage_hash=prior_v3_ref.content_hash,
        prior_v5_plan_hash=prior_v5_plan_ref.content_hash,
        graph_semantics_revision=_GRAPH_SEMANTICS_REVISION,
    )
    return payload


def prepare_surface_enrichment_v6(
    identity: CheckpointIdentity,
    scope: str,
    index: SurfaceIndex,
    index_ref: StoredDataRef,
    prior_v3_ref: StoredDataRef,
    prior_v3: SurfaceCoverageV3,
    prior_v5_plan_ref: StoredDataRef,
    prior_v5_plan: Mapping[str, object],
    graphs: Mapping[str, Mapping[str, object]],
    *,
    required_graph_revision: str,
) -> tuple[dict[str, object], tuple[V6Part, ...]]:
    """Build an immutable successor for only saved-v3 insufficient surfaces."""

    _valid_parent(
        identity,
        scope,
        index,
        index_ref,
        prior_v3_ref,
        prior_v3,
        prior_v5_plan_ref,
        prior_v5_plan,
    )
    if required_graph_revision != _GRAPH_SEMANTICS_REVISION:
        raise ValueError("SURFACE_ENRICHMENT_V6_GRAPH_REVISION_INVALID")
    targets = tuple(
        (surface, proof)
        for surface, proof in zip(index.surfaces, prior_v3.surfaces, strict=True)
        if proof.coverage_status == "INSUFFICIENT"
    )
    if not targets or set(graphs) != {surface.surface_id for surface, _ in targets}:
        raise ValueError("SURFACE_ENRICHMENT_V6_TARGET_SET_INVALID")
    index_hash = index_ref.content_hash
    source_hashes = dict(index.ast_source_hashes)
    selected: list[
        tuple[AttackSurface, SurfaceProofV3, list[dict[str, object]], str]
    ] = []
    binding_targets: list[dict[str, object]] = []
    for surface, proof in targets:
        graph = graphs[surface.surface_id]
        if graph.get("proof_semantics_revision") != required_graph_revision:
            raise ValueError("SURFACE_ENRICHMENT_V6_GRAPH_REVISION_INVALID")
        try:
            items, graph_hash = _graph_items(graph, surface, index, index_hash)
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("SURFACE_ENRICHMENT_V6_GRAPH_INVALID") from error
        selected.append((surface, proof, items, graph_hash))
        binding_targets.append(
            {
                "surface_id": surface.surface_id,
                "graph_hash": graph_hash,
                "prior_v3_proof_hash": _sha(proof.to_json()),
                "prior_reasons": list(proof.unresolved_reason_codes),
                "item_digests": [_sha(item) for item in items],
            }
        )
    child_hashes = cast(dict[str, str], prior_v5_plan["child_checkpoint_hashes"])
    binding: dict[str, object] = {
        "kind": "simple_surface_enrichment_binding_v6",
        "reader_revision": _READER_REVISION,
        "graph_semantics_revision": required_graph_revision,
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope": scope,
        "scope_fingerprint": index.scope_fingerprint,
        "static_bundle_hash": index.static_bundle_hash,
        "ast_manifest_hash": index.ast_manifest_hash,
        "candidate_inventory_hash": index.candidate_inventory_hash,
        "index_ref": index_ref.model_dump(mode="json"),
        "index_hash": index_hash,
        "prior_v3_coverage_ref": prior_v3_ref.model_dump(mode="json"),
        "prior_v3_coverage_hash": prior_v3_ref.content_hash,
        "prior_v5_plan_ref": prior_v5_plan_ref.model_dump(mode="json"),
        "prior_v5_plan_hash": prior_v5_plan_ref.content_hash,
        "v4_plan_ref": prior_v5_plan["v4_plan_ref"],
        "v4_plan_hash": prior_v5_plan["v4_plan_hash"],
        "v2_coverage_ref": prior_v5_plan["v2_coverage_ref"],
        "v2_coverage_hash": prior_v5_plan["v2_coverage_hash"],
        "original_coverage_ref": prior_v5_plan["original_coverage_ref"],
        "scope_certificate_ref": prior_v5_plan["scope_certificate_ref"],
        "child_checkpoint_hashes": dict(sorted(child_hashes.items())),
        "targets": binding_targets,
    }
    binding_hash = _sha(binding)
    child_hash = _sha(binding["child_checkpoint_hashes"])
    parts: list[V6Part] = []
    target_rows: list[dict[str, object]] = []
    expected_parts: list[dict[str, object]] = []
    old_ids = {
        row["context_id"]
        for row in cast(list[dict[str, object]], prior_v5_plan["expected_parts"])
    }
    for surface, proof, items, graph_hash in selected:
        source_sha256 = source_hashes.get(surface.path)

        payload = partial(
            _context_payload,
            identity=identity,
            scope=scope,
            index=index,
            index_hash=index_hash,
            surface=surface,
            source_sha256=source_sha256,
            graph_hash=graph_hash,
            binding_hash=binding_hash,
            prior_proof=proof,
            prior_v3_ref=prior_v3_ref,
            prior_v5_plan_ref=prior_v5_plan_ref,
            prior_v5_plan=prior_v5_plan,
            child_hash=child_hash,
        )

        upper = max(1, len(items) + 1)
        if (
            len(
                canonical_bytes(
                    payload(
                        items=[],
                        part_index=upper,
                        part_count=upper,
                        unavailable_count=upper,
                    )
                )
            )
            > _MAX_PART_BYTES
        ):
            raise SurfaceContextOverflow(surface.surface_id)
        available: list[dict[str, object]] = []
        unavailable: list[dict[str, object]] = []
        for item in items:
            if (
                len(
                    canonical_bytes(
                        payload(
                            items=[item],
                            part_index=upper,
                            part_count=upper,
                            unavailable_count=upper,
                        )
                    )
                )
                > _MAX_PART_BYTES
            ):
                unavailable.append(
                    {
                        "category": item["category"],
                        "ordinal": item["ordinal"],
                        "item_hash": _sha(item),
                        "reason": "ATOMIC_ITEM_TOO_LARGE",
                    }
                )
            else:
                available.append(item)
        chunks: list[list[dict[str, object]]] = []
        current: list[dict[str, object]] = []
        for item in available:
            proposed = [*current, item]
            if (
                len(
                    canonical_bytes(
                        payload(
                            items=proposed,
                            part_index=upper,
                            part_count=upper,
                            unavailable_count=upper,
                        )
                    )
                )
                > _MAX_PART_BYTES
            ):
                if not current:
                    raise SurfaceContextOverflow(surface.surface_id)
                chunks.append(current)
                current = [item]
            else:
                current = proposed
        if current or not chunks:
            chunks.append(current)
        target_rows.append(
            {
                "surface_id": surface.surface_id,
                "graph_hash": graph_hash,
                "prior_v3_proof_hash": _sha(proof.to_json()),
                "parent_progress_hash": _sha(proof.to_json()),
                "prior_reasons": list(proof.unresolved_reason_codes),
                "item_count": len(items),
                "available_item_count": len(available),
                "unavailable_items": unavailable,
                "source_sha256": source_sha256,
                "part_count": len(chunks),
            }
        )
        for ordinal, chunk in enumerate(chunks):
            record = payload(
                items=chunk,
                part_index=ordinal,
                part_count=len(chunks),
                unavailable_count=len(unavailable),
            )
            encoded = canonical_bytes(record)
            if len(encoded) > _MAX_PART_BYTES:
                raise SurfaceContextOverflow(surface.surface_id)
            context_hash = hashlib.sha256(encoded).hexdigest()
            context_id = _sha(
                {
                    "kind": "simple_surface_context_id_v5",
                    "plan_binding_hash": binding_hash,
                    "surface_id": surface.surface_id,
                    "part_index": ordinal,
                    "context_hash": context_hash,
                }
            )
            if context_id in old_ids:
                raise ValueError("SURFACE_ENRICHMENT_V6_CONTEXT_COLLISION")
            try:
                validate_v5_context(
                    {
                        "context_payload": record,
                        "graph_payload": graphs[surface.surface_id],
                        "context_hash": context_hash,
                        "context_id": context_id,
                    }
                )
            except (KeyError, TypeError, ValueError) as error:
                raise ValueError("SURFACE_ENRICHMENT_V6_GRAPH_INVALID") from error
            parts.append(
                V6Part(
                    payload=record,
                    surface_id=surface.surface_id,
                    context_id=context_id,
                    context_hash=context_hash,
                    part_index=ordinal,
                    part_count=len(chunks),
                    source_sha256=source_sha256,
                )
            )
            expected_parts.append(
                {
                    "surface_id": surface.surface_id,
                    "context_id": context_id,
                    "context_hash": context_hash,
                    "part_index": ordinal,
                    "part_count": len(chunks),
                    "source_sha256": source_sha256,
                }
            )
    plan = {
        **binding,
        "kind": "simple_surface_enrichment_plan_v6",
        "plan_binding_hash": binding_hash,
        "target_surface_ids": [surface.surface_id for surface, _ in targets],
        "targets": target_rows,
        "expected_parts": expected_parts,
    }
    return plan, tuple(parts)
