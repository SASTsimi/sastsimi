"""Immutable v7 review plan over exact saved v6 coverage and progress.

This module is pure. The caller validates stored evidence and performs the
transactional compare-and-swap before using any returned part.
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
from .surface_coverage_v4 import SurfaceCoverageV4, SurfaceProofV4
from .surface_enrichment_v5 import (
    _MAX_PART_BYTES,
    _READER_REVISION,
    _graph_items,
    _part_payload,
    _sha,
)
from .surface_enrichment_v7_bindings import (
    SurfaceProgressRow,
    missing_v6_part_set,
    prior_progress_snapshot_hash,
)

_GRAPH_SEMANTICS_REVISION = "v5-source-bound-4"


@dataclass(frozen=True, slots=True)
class V7Part:
    payload: dict[str, object]
    surface_id: str
    context_id: str
    context_hash: str
    part_index: int
    part_count: int
    source_sha256: str | None


def _bound(ref: StoredDataRef, identity: CheckpointIdentity, digest: str) -> bool:
    return (
        str(ref.workspace_id) == identity.workspace_id
        and str(ref.commit_id) == identity.commit_id
        and ref.data_kind == "artifact"
        and ref.record_id is None
        and str(ref.stored_data_id) == ref.content_hash == digest
    )


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
    proof_hash: str,
    prior_reasons: list[str],
    prior_v4_ref: StoredDataRef,
    prior_v6_plan_ref: StoredDataRef,
    prior_v6_plan: Mapping[str, object],
    progress_hash: str,
    child_hash: str,
    review_mode: str,
    target_path_id: str | None,
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
        parent_progress_hash=proof_hash,
        prior_reasons=prior_reasons,
        v4_plan_hash=cast(str, prior_v6_plan["v4_plan_hash"]),
        v2_coverage_hash=cast(str, prior_v6_plan["v2_coverage_hash"]),
        child_checkpoint_hash=child_hash,
        items=items,
        part_index=part_index,
        part_count=part_count,
        unavailable_count=unavailable_count,
    )
    payload.update(
        kind="simple_surface_context_v7",
        prior_v3_coverage_hash=prior_v6_plan["prior_v3_coverage_hash"],
        prior_v5_plan_hash=prior_v6_plan["prior_v5_plan_hash"],
        prior_v6_plan_hash=prior_v6_plan_ref.content_hash,
        prior_v4_coverage_hash=prior_v4_ref.content_hash,
        prior_progress_hash=progress_hash,
        graph_semantics_revision=_GRAPH_SEMANTICS_REVISION,
        review_mode=review_mode,
        target_path_id=target_path_id,
    )
    return payload


def _path_support(
    items: list[dict[str, object]], surface: AttackSurface
) -> list[tuple[str | None, list[dict[str, object]], list[dict[str, object]]]]:
    """One pinned path and its source support per review part.

    Other paths never enter a part. Related source lines are kept together so
    parsing/dispatch context is not silently lost to global byte chunking.
    """

    paths = [item for item in items if item["category"] == "paths"]
    selected: list[
        tuple[str | None, list[dict[str, object]], list[dict[str, object]]]
    ] = []
    for path_item in paths:
        path = cast(dict[str, object], path_item["value"])
        steps = path.get("steps")
        if not isinstance(steps, list) or any(
            not isinstance(step, dict) for step in steps
        ):
            raise ValueError("SURFACE_ENRICHMENT_V7_GRAPH_INVALID")
        if not any(step.get("role") == "ROUTE_ENTRY" for step in steps) or not any(
            step.get("role") == "SINK"
            and step.get("path") == surface.path
            and step.get("line") == surface.line
            for step in steps
        ):
            continue
        path_id = path.get("path_id")
        edge_ids = path.get("edge_ids")
        if (
            not isinstance(path_id, str)
            or not path_id
            or not isinstance(edge_ids, list)
            or any(not isinstance(edge_id, str) for edge_id in edge_ids)
        ):
            raise ValueError("SURFACE_ENRICHMENT_V7_GRAPH_INVALID")
        node_ids = {step.get("node_id") for step in steps}
        linked_files = {step.get("path") for step in steps}
        if any(not isinstance(value, str) for value in node_ids | linked_files):
            raise ValueError("SURFACE_ENRICHMENT_V7_GRAPH_INVALID")
        support = [
            item
            for item in items
            if item["category"] == "paths"
            and item["ordinal"] == path_item["ordinal"]
            or item["category"] == "nodes"
            and cast(dict[str, object], item["value"]).get("node_id") in node_ids
            or item["category"] == "edges"
            and cast(dict[str, object], item["value"]).get("edge_id") in edge_ids
            or item["category"] in {"source_files", "source_lines"}
            and cast(dict[str, object], item["value"]).get("path") in linked_files
        ]
        optional = [
            item
            for item in items
            if item["category"] == "ast_facts"
            and cast(dict[str, object], item["value"]).get("path") in linked_files
            or item["category"] == "operational_routes"
            and (
                cast(dict[str, object], item["value"]).get("target_path")
                in linked_files
                or cast(dict[str, object], item["value"]).get("parser_path")
                in linked_files
            )
            or item["category"] == "gaps"
            and cast(dict[str, object], item["value"]).get("path") in linked_files
        ]
        selected.append((path_id, support, optional))
    return selected or [(None, [], [])]


def prepare_surface_enrichment_v7(
    identity: CheckpointIdentity,
    scope: str,
    index: SurfaceIndex,
    index_ref: StoredDataRef,
    prior_v6_plan_ref: StoredDataRef,
    prior_v6_plan: Mapping[str, object],
    prior_v4_ref: StoredDataRef,
    prior_v4: SurfaceCoverageV4,
    prior_progress: Mapping[tuple[str, str], SurfaceProgressRow],
    graphs: Mapping[str, Mapping[str, object]],
    *,
    required_graph_revision: str,
) -> tuple[dict[str, object], tuple[V7Part, ...]]:
    """Build a deterministic rev4 recertification overlay for every indexed row."""

    invalid = "SURFACE_ENRICHMENT_V7_PARENT_INVALID"
    index_hash = _sha(index.to_json())
    if (
        not scope
        or identity.hypothesis_id is not None
        or index.index_version != 2
        or index.workspace_id != identity.workspace_id
        or index.commit_id != identity.commit_id
        or not _bound(index_ref, identity, index_hash)
        or not _bound(prior_v6_plan_ref, identity, _sha(prior_v6_plan))
        or not _bound(prior_v4_ref, identity, _sha(prior_v4.to_json()))
        or prior_v4.v6_plan_ref != prior_v6_plan_ref
        or prior_v4.scope_fingerprint != index.scope_fingerprint
        or prior_v4.static_bundle_hash != index.static_bundle_hash
        or prior_v4.ast_manifest_hash != index.ast_manifest_hash
        or prior_v4.candidate_inventory_hash != index.candidate_inventory_hash
        or prior_v4.candidate_count != index.candidate_count
        or prior_v4.index_hash != index_hash
        or len(prior_v4.surfaces) != len(index.surfaces)
        or any(
            proof.surface_id != surface.surface_id
            or proof.path != surface.path
            or proof.line != surface.line
            for surface, proof in zip(index.surfaces, prior_v4.surfaces, strict=True)
        )
        or prior_v6_plan.get("kind") != "simple_surface_enrichment_plan_v6"
        or prior_v6_plan.get("analysis_id") != identity.analysis_id
        or prior_v6_plan.get("workspace_id") != identity.workspace_id
        or prior_v6_plan.get("commit_id") != identity.commit_id
        or prior_v6_plan.get("scope") != scope
        or prior_v6_plan.get("scope_fingerprint") != index.scope_fingerprint
        or prior_v6_plan.get("index_ref") != index_ref.model_dump(mode="json")
        or prior_v6_plan.get("index_hash") != index_hash
        or prior_v6_plan.get("static_bundle_hash") != index.static_bundle_hash
        or prior_v6_plan.get("ast_manifest_hash") != index.ast_manifest_hash
        or not isinstance(prior_v6_plan.get("child_checkpoint_hashes"), dict)
    ):
        raise ValueError(invalid)
    if required_graph_revision != _GRAPH_SEMANTICS_REVISION:
        raise ValueError("SURFACE_ENRICHMENT_V7_GRAPH_REVISION_INVALID")
    progress_hash = prior_progress_snapshot_hash(prior_progress)
    missing = missing_v6_part_set(prior_v6_plan, prior_progress)
    completed_hypotheses = {
        row.surface_id for row in prior_progress.values() if row.status == "HYPOTHESES"
    }
    targets = tuple(
        (surface, proof)
        for surface, proof in zip(index.surfaces, prior_v4.surfaces, strict=True)
    )
    if set(graphs) != {surface.surface_id for surface, _ in targets}:
        raise ValueError("SURFACE_ENRICHMENT_V7_TARGET_SET_INVALID")
    source_hashes = dict(index.ast_source_hashes)
    selected: list[
        tuple[AttackSurface, SurfaceProofV4, list[dict[str, object]], str, str]
    ] = []
    target_bindings: list[dict[str, object]] = []
    for surface, proof in targets:
        # A prior child is bound to a surface, not to an equivalent rev4
        # input-to-sink path. Preserve it, but independently review new paths.
        review_mode = "STANDARD"
        graph = graphs[surface.surface_id]
        if graph.get("proof_semantics_revision") != required_graph_revision:
            raise ValueError("SURFACE_ENRICHMENT_V7_GRAPH_REVISION_INVALID")
        try:
            items, graph_hash = _graph_items(graph, surface, index, index_hash)
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("SURFACE_ENRICHMENT_V7_GRAPH_INVALID") from error
        selected.append((surface, proof, items, graph_hash, review_mode))
        target_bindings.append(
            {
                "surface_id": surface.surface_id,
                "graph_hash": graph_hash,
                "prior_v4_proof_hash": _sha(proof.to_json()),
                "prior_reasons": list(proof.unresolved_reason_codes),
                "review_mode": review_mode,
                "item_digests": [_sha(item) for item in items],
            }
        )
    child_hashes = cast(dict[str, str], prior_v6_plan["child_checkpoint_hashes"])
    binding: dict[str, object] = {
        "kind": "simple_surface_enrichment_binding_v7",
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
        "prior_v6_plan_ref": prior_v6_plan_ref.model_dump(mode="json"),
        "prior_v6_plan_hash": prior_v6_plan_ref.content_hash,
        "prior_v4_coverage_ref": prior_v4_ref.model_dump(mode="json"),
        "prior_v4_coverage_hash": prior_v4_ref.content_hash,
        "prior_progress_hash": progress_hash,
        "missing_v6_parts": missing,
        "existing_hypothesis_surface_ids": sorted(completed_hypotheses),
        "v4_plan_ref": prior_v6_plan["v4_plan_ref"],
        "v4_plan_hash": prior_v6_plan["v4_plan_hash"],
        "v2_coverage_ref": prior_v6_plan["v2_coverage_ref"],
        "v2_coverage_hash": prior_v6_plan["v2_coverage_hash"],
        "original_coverage_ref": prior_v6_plan["original_coverage_ref"],
        "scope_certificate_ref": prior_v6_plan["scope_certificate_ref"],
        "child_checkpoint_hashes": dict(sorted(child_hashes.items())),
        "targets": target_bindings,
    }
    binding_hash = _sha(binding)
    child_hash = _sha(binding["child_checkpoint_hashes"])
    parts: list[V7Part] = []
    target_rows: list[dict[str, object]] = []
    expected_parts: list[dict[str, object]] = []
    old_ids = {
        row["context_id"]
        for row in cast(list[dict[str, object]], prior_v6_plan["expected_parts"])
    }
    for surface, proof, items, graph_hash, review_mode in selected:
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
            proof_hash=_sha(proof.to_json()),
            prior_reasons=list(proof.unresolved_reason_codes),
            prior_v4_ref=prior_v4_ref,
            prior_v6_plan_ref=prior_v6_plan_ref,
            prior_v6_plan=prior_v6_plan,
            progress_hash=progress_hash,
            child_hash=child_hash,
            review_mode=review_mode,
        )
        specs = _path_support(items, surface)
        part_count = len(specs)
        chunks: list[tuple[str | None, list[dict[str, object]], int]] = []
        unavailable: list[dict[str, object]] = []
        for ordinal, (path_id, support, optional) in enumerate(specs):
            record = payload(
                target_path_id=path_id,
                items=support,
                part_index=ordinal,
                part_count=part_count,
                unavailable_count=0,
            )
            if len(canonical_bytes(record)) > _MAX_PART_BYTES:
                if path_id is None:
                    raise SurfaceContextOverflow(surface.surface_id)
                unavailable.append(
                    {
                        "target_path_id": path_id,
                        "reason": "ATOMIC_PATH_SUPPORT_TOO_LARGE",
                        "path_hash": _sha(support),
                    }
                )
                chunks.append((path_id, [], 1))
                continue
            visible = list(support)
            for item in optional:
                proposed = [*visible, item]
                if (
                    len(
                        canonical_bytes(
                            payload(
                                target_path_id=path_id,
                                items=proposed,
                                part_index=ordinal,
                                part_count=part_count,
                                unavailable_count=0,
                            )
                        )
                    )
                    <= _MAX_PART_BYTES
                ):
                    visible = proposed
            chunks.append((path_id, visible, 0))
        target_rows.append(
            {
                "surface_id": surface.surface_id,
                "graph_hash": graph_hash,
                "prior_v4_proof_hash": _sha(proof.to_json()),
                "parent_progress_hash": _sha(proof.to_json()),
                "prior_reasons": list(proof.unresolved_reason_codes),
                "review_mode": review_mode,
                "item_count": len(items),
                "available_item_count": sum(len(chunk) for _, chunk, _ in chunks),
                "unavailable_items": unavailable,
                "source_sha256": source_sha256,
                "part_count": part_count,
            }
        )
        for ordinal, (path_id, chunk, unavailable_count) in enumerate(chunks):
            record = payload(
                target_path_id=path_id,
                items=chunk,
                part_index=ordinal,
                part_count=part_count,
                unavailable_count=unavailable_count,
            )
            encoded = canonical_bytes(record)
            if len(encoded) > _MAX_PART_BYTES:
                raise SurfaceContextOverflow(surface.surface_id)
            context_hash = hashlib.sha256(encoded).hexdigest()
            context_id = _sha(
                {
                    "kind": "simple_surface_context_id_v7",
                    "plan_binding_hash": binding_hash,
                    "surface_id": surface.surface_id,
                    "part_index": ordinal,
                    "context_hash": context_hash,
                }
            )
            if context_id in old_ids:
                raise ValueError("SURFACE_ENRICHMENT_V7_CONTEXT_COLLISION")
            parts.append(
                V7Part(
                    record,
                    surface.surface_id,
                    context_id,
                    context_hash,
                    ordinal,
                    part_count,
                    source_sha256,
                )
            )
            expected_parts.append(
                {
                    "surface_id": surface.surface_id,
                    "context_id": context_id,
                    "context_hash": context_hash,
                    "part_index": ordinal,
                    "part_count": part_count,
                    "target_path_id": path_id,
                    "source_sha256": source_sha256,
                }
            )
    plan = {
        **binding,
        "kind": "simple_surface_enrichment_plan_v7",
        "plan_binding_hash": binding_hash,
        "target_surface_ids": [surface.surface_id for surface, _ in targets],
        "targets": target_rows,
        "expected_parts": expected_parts,
    }
    return plan, tuple(parts)
