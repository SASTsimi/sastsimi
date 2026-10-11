"""Immutable, bounded planning for source-bound v5 surface review.

This module only computes a plan. Persistence must compare-and-set its canonical
bytes before starting a review, and subsequent resumes must read that saved plan.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from functools import partial
from typing import cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .attack_surfaces import AttackSurface, SurfaceIndex
from .models import CheckpointIdentity
from .store import SurfaceExplorationProgressRecord
from .surface_contexts import SurfaceContextOverflow
from .surface_coverage_v2 import SurfaceCoverageV2

_MAX_PART_BYTES = 64 * 1024
_GRAPH_CATEGORIES = (
    "source_files",
    "source_lines",
    "ast_facts",
    "nodes",
    "edges",
    "paths",
    "gaps",
    "operational_routes",
)
_OPERATIONAL_FIELDS = frozenset(
    {
        "route",
        "module_path",
        "class_symbol",
        "config_path",
        "config_sha256",
        "parser_path",
        "parser_sha256",
        "parser_sites",
        "target_path",
        "target_sha256",
        "launcher_path",
        "launcher_sha256",
    }
)
_READER_REVISION = "source-bound-v5-1"


@dataclass(frozen=True, slots=True)
class V5Part:
    payload: dict[str, object]
    surface_id: str
    context_id: str
    context_hash: str
    part_index: int
    part_count: int
    source_sha256: str | None


def _sha(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _ref_matches(ref: StoredDataRef, identity: CheckpointIdentity) -> bool:
    return (
        str(ref.workspace_id) == identity.workspace_id
        and str(ref.commit_id) == identity.commit_id
    )


def _prior_rows(
    surface_id: str,
    progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord],
    index: SurfaceIndex,
    index_hash: str,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for key, record in sorted(progress.items()):
        if key != (record.surface_id, record.context_id):
            raise ValueError("SURFACE_ENRICHMENT_V5_PARENT_KEY_INVALID")
        if record.proposal_version not in {1, 2, 3, 4}:
            raise ValueError("SURFACE_ENRICHMENT_V5_PARENT_VERSION_INVALID")
        if record.surface_id != surface_id:
            continue
        if (
            record.static_bundle_hash != index.static_bundle_hash
            or record.index_hash != index_hash
            or str(record.result_ref.workspace_id) != index.workspace_id
            or str(record.result_ref.commit_id) != index.commit_id
            or record.source_sha256
            not in {
                None,
                dict(index.ast_source_hashes).get(
                    next(s.path for s in index.surfaces if s.surface_id == surface_id)
                ),
            }
        ):
            raise ValueError("SURFACE_ENRICHMENT_V5_PARENT_SCOPE_INVALID")
        rows.append(
            {
                "proposal_version": record.proposal_version,
                "context_id": record.context_id,
                "context_hash": record.context_hash,
                "source_sha256": record.source_sha256,
                "status": record.status,
                "result_ref": record.result_ref.model_dump(mode="json"),
                "result_hash": record.result_ref.content_hash,
                "hypothesis_ids": list(record.hypothesis_ids),
            }
        )
    return sorted(
        rows,
        key=lambda row: (cast(int, row["proposal_version"]), str(row["context_id"])),
    )


def _graph_items(
    graph: Mapping[str, object],
    surface: AttackSurface,
    index: SurfaceIndex,
    index_hash: str,
) -> tuple[list[dict[str, object]], str]:
    if (
        graph.get("kind") != "simple_surface_evidence_graph_v5"
        or graph.get("anchor")
        != {
            "surface_id": surface.surface_id,
            "path": surface.path,
            "line": surface.line,
        }
        or graph.get("scope_fingerprint") != index.scope_fingerprint
        or graph.get("index_hash") != index_hash
        or graph.get("ast_manifest_hash") != index.ast_manifest_hash
    ):
        raise ValueError("SURFACE_ENRICHMENT_V5_GRAPH_SCOPE_INVALID")
    source_hashes = dict(index.ast_source_hashes)
    files = graph.get("source_files")
    if not isinstance(files, list):
        raise ValueError("SURFACE_ENRICHMENT_V5_GRAPH_INVALID")
    for file in files:
        if (
            not isinstance(file, dict)
            or not isinstance(file.get("path"), str)
            or file.get("source_sha256") != source_hashes.get(file["path"])
        ):
            raise ValueError("SURFACE_ENRICHMENT_V5_GRAPH_SOURCE_INVALID")
    items: list[dict[str, object]] = []
    for category in _GRAPH_CATEGORIES:
        rows = graph.get(category)
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError("SURFACE_ENRICHMENT_V5_GRAPH_INVALID")
        for ordinal, row in enumerate(rows):
            if category == "operational_routes":
                if set(row) != _OPERATIONAL_FIELDS:
                    raise ValueError(
                        "SURFACE_ENRICHMENT_V5_CONFIG_ANSWER_KEY_FORBIDDEN"
                    )
                if row.get("target_sha256") != source_hashes.get(
                    row.get("target_path")
                ) or row.get("parser_sha256") != source_hashes.get(
                    row.get("parser_path")
                ):
                    raise ValueError("SURFACE_ENRICHMENT_V5_GRAPH_SOURCE_INVALID")
            items.append(
                {
                    "category": category,
                    "ordinal": ordinal,
                    "value": deepcopy(row),
                }
            )
    return items, _sha(graph)


def _part_payload(
    *,
    identity: CheckpointIdentity,
    scope: str,
    index: SurfaceIndex,
    index_hash: str,
    surface: AttackSurface,
    source_sha256: str | None,
    graph_hash: str,
    plan_binding_hash: str,
    parent_progress_hash: str,
    prior_reasons: list[str],
    v4_plan_hash: str,
    v2_coverage_hash: str,
    child_checkpoint_hash: str,
    items: list[dict[str, object]],
    part_index: int,
    part_count: int,
    unavailable_count: int,
) -> dict[str, object]:
    return {
        "kind": "simple_surface_context_v5",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope": scope,
        "scope_fingerprint": index.scope_fingerprint,
        "static_bundle_hash": index.static_bundle_hash,
        "ast_manifest_hash": index.ast_manifest_hash,
        "surface_index_hash": index_hash,
        "surface_id": surface.surface_id,
        "surface_type": surface.type,
        "path": surface.path,
        "line": surface.line,
        "source_sha256": source_sha256,
        "source_unavailable_reason": None,
        "graph_hash": graph_hash,
        "parent_progress_hash": parent_progress_hash,
        "prior_reasons": prior_reasons,
        "v4_plan_hash": v4_plan_hash,
        "v2_coverage_hash": v2_coverage_hash,
        "child_checkpoint_hash": child_checkpoint_hash,
        "plan_binding_hash": plan_binding_hash,
        "reader_revision": _READER_REVISION,
        "part_index": part_index,
        "part_count": part_count,
        "unavailable_item_count": unavailable_count,
        "items": items,
    }


def prepare_surface_enrichment_v5(
    identity: CheckpointIdentity,
    scope: str,
    index: SurfaceIndex,
    index_ref: StoredDataRef,
    v4_plan_ref: StoredDataRef,
    v2_coverage_ref: StoredDataRef,
    current_coverage: SurfaceCoverageV2,
    prior_progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord],
    graphs: Mapping[str, Mapping[str, object]],
    *,
    v4_plan: Mapping[str, object],
    child_checkpoint_hashes: Mapping[str, str],
) -> tuple[dict[str, object], tuple[V5Part, ...]]:
    """Target current insufficient surfaces, pinning all prior evidence exactly."""

    index_hash = _sha(index.to_json())
    if (
        not scope
        or identity.hypothesis_id is not None
        or index.index_version != 2
        or index.workspace_id != identity.workspace_id
        or index.commit_id != identity.commit_id
        or not _ref_matches(index_ref, identity)
        or index_ref.content_hash != index_hash
        or current_coverage.to_json().get("kind") != "simple_attack_surface_coverage_v2"
        or current_coverage.scope_fingerprint != index.scope_fingerprint
        or current_coverage.static_bundle_hash != index.static_bundle_hash
        or current_coverage.ast_manifest_hash != index.ast_manifest_hash
        or current_coverage.candidate_inventory_hash != index.candidate_inventory_hash
        or current_coverage.candidate_count != index.candidate_count
        or current_coverage.index_hash != index_hash
        or len(current_coverage.surfaces) != len(index.surfaces)
        or any(
            proof.surface_id != surface.surface_id
            or proof.path != surface.path
            or proof.line != surface.line
            for surface, proof in zip(
                index.surfaces, current_coverage.surfaces, strict=True
            )
        )
        or not _ref_matches(v2_coverage_ref, identity)
        or v2_coverage_ref.content_hash != _sha(current_coverage.to_json())
    ):
        raise ValueError("SURFACE_ENRICHMENT_V5_SCOPE_INVALID")
    static_ref_object = v4_plan.get("static_bundle_ref")
    expected_parts_object = v4_plan.get("expected_parts")
    if (
        not _ref_matches(v4_plan_ref, identity)
        or v4_plan_ref.content_hash != _sha(v4_plan)
        or v4_plan.get("kind") != "simple_surface_enrichment_plan_v4"
        or v4_plan.get("analysis_id") != identity.analysis_id
        or v4_plan.get("workspace_id") != identity.workspace_id
        or v4_plan.get("commit_id") != identity.commit_id
        or v4_plan.get("scope_fingerprint") != index.scope_fingerprint
        or v4_plan.get("index_hash") != index_hash
        or v4_plan.get("index_ref") != index_ref.model_dump(mode="json")
        or v4_plan.get("ast_manifest_hash") != index.ast_manifest_hash
        or v4_plan.get("candidate_inventory_hash") != index.candidate_inventory_hash
        or not isinstance(static_ref_object, dict)
        or static_ref_object.get("content_hash") != index.static_bundle_hash
        or not isinstance(expected_parts_object, list)
    ):
        raise ValueError("SURFACE_ENRICHMENT_V5_V4_PLAN_INVALID")
    for child_id, digest in child_checkpoint_hashes.items():
        if (
            not child_id
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
        ):
            raise ValueError("SURFACE_ENRICHMENT_V5_CHILD_BINDING_INVALID")
    expected_v4: dict[tuple[str, str], dict[str, object]] = {}
    for item in expected_parts_object:
        if not isinstance(item, dict):
            raise ValueError("SURFACE_ENRICHMENT_V5_V4_PLAN_INVALID")
        surface_id = item.get("surface_id")
        context_id = item.get("context_id")
        if (
            not isinstance(surface_id, str)
            or not surface_id
            or not isinstance(context_id, str)
            or not context_id
            or (surface_id, context_id) in expected_v4
        ):
            raise ValueError("SURFACE_ENRICHMENT_V5_V4_PLAN_INVALID")
        expected_v4[(surface_id, context_id)] = item
    actual_v4 = {
        (row.surface_id, row.context_id): row
        for row in prior_progress.values()
        if row.proposal_version == 4
    }
    if set(expected_v4) != set(actual_v4):
        raise ValueError("SURFACE_ENRICHMENT_V5_V4_PROGRESS_INCOMPLETE")
    for key, expected in expected_v4.items():
        actual = actual_v4[key]
        if (
            expected.get("context_hash") != actual.context_hash
            or expected.get("source_sha256") != actual.source_sha256
            or actual.status
            not in {
                "HYPOTHESES",
                "NO_HYPOTHESIS",
                "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
            }
        ):
            raise ValueError("SURFACE_ENRICHMENT_V5_V4_PROGRESS_INVALID")
    targets = tuple(
        surface
        for surface, proof in zip(
            index.surfaces, current_coverage.surfaces, strict=True
        )
        if proof.coverage_status == "INSUFFICIENT"
    )
    if set(graphs) != {surface.surface_id for surface in targets}:
        raise ValueError("SURFACE_ENRICHMENT_V5_GRAPH_SET_INVALID")
    proof_by_id = {proof.surface_id: proof for proof in current_coverage.surfaces}
    selected: list[
        tuple[
            AttackSurface,
            list[dict[str, object]],
            str,
            list[dict[str, object]],
            list[str],
        ]
    ] = []
    binding_targets: list[dict[str, object]] = []
    for surface in targets:
        parents = _prior_rows(surface.surface_id, prior_progress, index, index_hash)
        items, graph_hash = _graph_items(
            graphs[surface.surface_id], surface, index, index_hash
        )
        reasons = list(proof_by_id[surface.surface_id].unresolved_reason_codes)
        selected.append((surface, items, graph_hash, parents, reasons))
        binding_targets.append(
            {
                "surface_id": surface.surface_id,
                "graph_hash": graph_hash,
                "prior_progress": parents,
                "prior_reasons": reasons,
                "item_digests": [_sha(item) for item in items],
            }
        )
    binding: dict[str, object] = {
        "kind": "simple_surface_enrichment_binding_v5",
        "reader_revision": _READER_REVISION,
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
        "v4_plan_ref": v4_plan_ref.model_dump(mode="json"),
        "v4_plan_hash": v4_plan_ref.content_hash,
        "v2_coverage_ref": v2_coverage_ref.model_dump(mode="json"),
        "v2_coverage_hash": v2_coverage_ref.content_hash,
        "original_coverage_ref": current_coverage.original_coverage_ref.model_dump(
            mode="json"
        ),
        "scope_certificate_ref": current_coverage.scope_certificate_ref.model_dump(
            mode="json"
        ),
        "child_checkpoint_hashes": dict(sorted(child_checkpoint_hashes.items())),
        "targets": binding_targets,
    }
    binding_hash = _sha(binding)
    result: list[V5Part] = []
    target_rows: list[dict[str, object]] = []
    expected_parts: list[dict[str, object]] = []
    source_hashes = dict(index.ast_source_hashes)
    child_hash = _sha(binding["child_checkpoint_hashes"])
    for surface, items, graph_hash, parents, reasons in selected:
        source_sha256 = source_hashes.get(surface.path)
        parent_hash = _sha(parents)
        payload = partial(
            _part_payload,
            identity=identity,
            scope=scope,
            index=index,
            index_hash=index_hash,
            surface=surface,
            source_sha256=source_sha256,
            graph_hash=graph_hash,
            plan_binding_hash=binding_hash,
            parent_progress_hash=parent_hash,
            prior_reasons=reasons,
            v4_plan_hash=v4_plan_ref.content_hash,
            v2_coverage_hash=v2_coverage_ref.content_hash,
            child_checkpoint_hash=child_hash,
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
                "prior_progress": parents,
                "parent_progress_hash": parent_hash,
                "prior_reasons": reasons,
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
            result.append(
                V5Part(
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
        "kind": "simple_surface_enrichment_plan_v5",
        "plan_binding_hash": binding_hash,
        "target_surface_ids": [surface.surface_id for surface in targets],
        "targets": target_rows,
        "expected_parts": expected_parts,
    }
    return plan, tuple(result)
