"""Pure, deterministic planning of source-bound v4 surface review parts.

The plan is immutable input to persistence and replay; this module performs no
database or artifact writes and never silently truncates a source/graph item.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass, replace
from functools import partial
from typing import cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .attack_surfaces import AttackSurface, SurfaceCoverage, SurfaceIndex
from .models import CheckpointIdentity
from .store import SurfaceExplorationProgressRecord
from .surface_contexts import SurfaceContextOverflow

_MAX_PART_BYTES = 64 * 1024
_GRAPH_CATEGORIES = (
    "source_files",
    "source_lines",
    "ast_facts",
    "nodes",
    "edges",
    "paths",
    "gaps",
)
_READER_REVISION = "source-bound-v4-1"


@dataclass(frozen=True, slots=True)
class V4Part:
    payload: dict[str, object]
    surface_id: str
    context_id: str
    context_hash: str
    part_index: int
    part_count: int
    source_sha256: str | None


def read_saved_coverage_v1(
    artifacts: SimpleArtifactRepository,
    index: SurfaceIndex,
    coverage_ref: StoredDataRef,
) -> SurfaceCoverage:
    """Read the *original* saved v1 proof, rejecting changed surface identities."""

    invalid = "SURFACE_ENRICHMENT_COVERAGE_INVALID"
    try:
        raw = json.loads(artifacts.read(coverage_ref))
        if (
            not isinstance(raw, dict)
            or raw.get("kind") != "simple_attack_surface_coverage_v1"
            or not isinstance(raw.get("surfaces"), list)
            or len(raw["surfaces"]) != len(index.surfaces)
        ):
            raise ValueError(invalid)
        reviewed: list[AttackSurface] = []
        for original, row in zip(index.surfaces, raw["surfaces"], strict=True):
            if (
                not isinstance(row, dict)
                or row.get("coverage_status")
                not in {"COVERED", "UNCOVERED", "INSUFFICIENT"}
                or not isinstance(row.get("review_evidence_refs"), list)
            ):
                raise ValueError(invalid)
            refs = tuple(
                StoredDataRef.model_validate(value)
                for value in row["review_evidence_refs"]
            )
            candidate = replace(
                original,
                coverage_status=row["coverage_status"],
                review_evidence_refs=refs,
            )
            if candidate.to_json() != row:
                raise ValueError(invalid)
            reviewed.append(candidate)
        coverage = SurfaceCoverage(
            scope_fingerprint=index.scope_fingerprint,
            static_bundle_hash=index.static_bundle_hash,
            ast_manifest_hash=index.ast_manifest_hash,
            candidate_inventory_hash=index.candidate_inventory_hash,
            candidate_count=index.candidate_count,
            surfaces=tuple(reviewed),
            static_gaps=index.static_gaps,
        )
        if coverage.to_json() != raw:
            raise ValueError(invalid)
        return coverage
    except (OSError, TypeError, ValueError, KeyError) as error:
        raise ValueError(invalid) from error


def _sha(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _same_surface(left: AttackSurface, right: AttackSurface) -> bool:
    return (
        left.surface_id,
        left.type,
        left.path,
        left.symbol,
        left.line,
        left.linked_candidate_ids,
        left.evidence_refs,
        left.detector,
        left.flow_identity,
    ) == (
        right.surface_id,
        right.type,
        right.path,
        right.symbol,
        right.line,
        right.linked_candidate_ids,
        right.evidence_refs,
        right.detector,
        right.flow_identity,
    )


def _parent_rows(
    surface_id: str,
    progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord],
    index: SurfaceIndex,
    index_hash: str,
) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for key, record in sorted(progress.items()):
        if key != (record.surface_id, record.context_id):
            raise ValueError("SURFACE_ENRICHMENT_PARENT_KEY_INVALID")
        if record.surface_id != surface_id or record.proposal_version == 4:
            continue
        if (
            record.proposal_version not in {1, 2, 3}
            or record.static_bundle_hash != index.static_bundle_hash
            or record.index_hash != index_hash
            or str(record.result_ref.workspace_id) != index.workspace_id
            or str(record.result_ref.commit_id) != index.commit_id
        ):
            raise ValueError("SURFACE_ENRICHMENT_PARENT_SCOPE_INVALID")
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
        graph.get("kind") != "simple_surface_evidence_graph_v4"
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
        raise ValueError("SURFACE_ENRICHMENT_GRAPH_SCOPE_INVALID")
    source_hashes = dict(index.ast_source_hashes)
    files = graph.get("source_files")
    if not isinstance(files, list):
        raise ValueError("SURFACE_ENRICHMENT_GRAPH_INVALID")
    for file in files:
        if (
            not isinstance(file, dict)
            or not isinstance(file.get("path"), str)
            or file.get("source_sha256") != source_hashes.get(file["path"])
        ):
            raise ValueError("SURFACE_ENRICHMENT_GRAPH_SOURCE_INVALID")
    items: list[dict[str, object]] = []
    for category in _GRAPH_CATEGORIES:
        rows = graph.get(category)
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError("SURFACE_ENRICHMENT_GRAPH_INVALID")
        for ordinal, row in enumerate(rows):
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
    certificate_hash: str,
    surface: AttackSurface,
    graph_hash: str,
    plan_binding_hash: str,
    parent_hash: str,
    source_sha256: str | None,
    items: list[dict[str, object]],
    part_index: int,
    part_count: int,
    unavailable_count: int,
) -> dict[str, object]:
    return {
        "kind": "simple_surface_context_v4",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope": scope,
        "scope_fingerprint": index.scope_fingerprint,
        "static_bundle_hash": index.static_bundle_hash,
        "ast_manifest_hash": index.ast_manifest_hash,
        "surface_index_hash": index_hash,
        "scope_certificate_hash": certificate_hash,
        "surface_id": surface.surface_id,
        "surface_type": surface.type,
        "path": surface.path,
        "line": surface.line,
        "source_sha256": source_sha256,
        "graph_hash": graph_hash,
        "parent_progress_hash": parent_hash,
        "plan_binding_hash": plan_binding_hash,
        "reader_revision": _READER_REVISION,
        "part_index": part_index,
        "part_count": part_count,
        "unavailable_item_count": unavailable_count,
        "items": items,
    }


def prepare_surface_enrichment_v4(
    identity: CheckpointIdentity,
    scope: str,
    static_bundle_ref: StoredDataRef,
    index: SurfaceIndex,
    index_ref: StoredDataRef,
    certificate: Mapping[str, object],
    prior_coverage: SurfaceCoverage,
    prior_progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord],
    graphs: Mapping[str, Mapping[str, object]],
    *,
    prior_coverage_ref: StoredDataRef | None = None,
) -> tuple[dict[str, object], tuple[V4Part, ...]]:
    """Plan exactly the saved insufficient surfaces, with bounded prompt parts."""

    index_hash = _sha(index.to_json())
    if (
        not scope
        or identity.hypothesis_id is not None
        or index.index_version != 2
        or index.workspace_id != identity.workspace_id
        or index.commit_id != identity.commit_id
        or str(index_ref.workspace_id) != identity.workspace_id
        or str(index_ref.commit_id) != identity.commit_id
        or index_ref.content_hash != index_hash
        or str(static_bundle_ref.workspace_id) != identity.workspace_id
        or str(static_bundle_ref.commit_id) != identity.commit_id
        or static_bundle_ref.content_hash != index.static_bundle_hash
        or prior_coverage.scope_fingerprint != index.scope_fingerprint
        or prior_coverage.static_bundle_hash != index.static_bundle_hash
        or prior_coverage.ast_manifest_hash != index.ast_manifest_hash
        or prior_coverage.candidate_inventory_hash != index.candidate_inventory_hash
        or prior_coverage.candidate_count != index.candidate_count
        or prior_coverage.static_gaps != index.static_gaps
        or len(prior_coverage.surfaces) != len(index.surfaces)
        or any(
            not _same_surface(original, reviewed)
            for original, reviewed in zip(
                index.surfaces, prior_coverage.surfaces, strict=True
            )
        )
        or certificate.get("kind") != "simple_python_scope_recertification_v1"
        or certificate.get("analysis_id") != identity.analysis_id
        or certificate.get("workspace_id") != identity.workspace_id
        or certificate.get("commit_id") != identity.commit_id
        or certificate.get("scope_fingerprint") != index.scope_fingerprint
        or certificate.get("index_hash") != index_hash
        or certificate.get("raw_static_gaps") != index.to_json()["static_gaps"]
    ):
        raise ValueError("SURFACE_ENRICHMENT_SCOPE_INVALID")
    if prior_coverage_ref is not None and (
        str(prior_coverage_ref.workspace_id) != identity.workspace_id
        or str(prior_coverage_ref.commit_id) != identity.commit_id
        or prior_coverage_ref.content_hash != _sha(prior_coverage.to_json())
    ):
        raise ValueError("SURFACE_ENRICHMENT_COVERAGE_REF_INVALID")
    targets = tuple(
        surface
        for original, surface in zip(
            index.surfaces, prior_coverage.surfaces, strict=True
        )
        if surface.coverage_status == "INSUFFICIENT"
    )
    if set(graphs) != {surface.surface_id for surface in targets}:
        raise ValueError("SURFACE_ENRICHMENT_GRAPH_SET_INVALID")
    source_hashes = dict(index.ast_source_hashes)
    certificate_hash = _sha(certificate)
    bound_targets: list[dict[str, object]] = []
    selected: list[
        tuple[AttackSurface, list[dict[str, object]], str, list[dict[str, object]]]
    ] = []
    for surface in targets:
        parents = _parent_rows(surface.surface_id, prior_progress, index, index_hash)
        items, graph_hash = _graph_items(
            graphs[surface.surface_id], surface, index, index_hash
        )
        bound_targets.append(
            {
                "surface_id": surface.surface_id,
                "graph_hash": graph_hash,
                "prior_progress": parents,
                "item_digests": [_sha(item) for item in items],
            }
        )
        selected.append((surface, items, graph_hash, parents))
    binding = {
        "kind": "simple_surface_enrichment_binding_v4",
        "reader_revision": _READER_REVISION,
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope": scope,
        "scope_fingerprint": index.scope_fingerprint,
        "static_bundle_ref": static_bundle_ref.model_dump(mode="json"),
        "index_ref": index_ref.model_dump(mode="json"),
        "index_hash": index_hash,
        "ast_manifest_hash": index.ast_manifest_hash,
        "candidate_inventory_hash": index.candidate_inventory_hash,
        "certificate_hash": certificate_hash,
        "prior_coverage_hash": _sha(prior_coverage.to_json()),
        "original_coverage_ref": (
            prior_coverage_ref.model_dump(mode="json")
            if prior_coverage_ref is not None
            else None
        ),
        "targets": bound_targets,
    }
    plan_binding_hash = _sha(binding)
    target_rows: list[dict[str, object]] = []
    expected_parts: list[dict[str, object]] = []
    result: list[V4Part] = []
    for surface, items, graph_hash, parents in selected:
        source_sha256 = source_hashes.get(surface.path)
        parent_hash = _sha(parents)
        upper = max(1, len(items) + 1)

        payload = partial(
            _part_payload,
            identity=identity,
            scope=scope,
            index=index,
            index_hash=index_hash,
            certificate_hash=certificate_hash,
            surface=surface,
            graph_hash=graph_hash,
            plan_binding_hash=plan_binding_hash,
            parent_hash=parent_hash,
            source_sha256=source_sha256,
        )

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
                    "kind": "simple_surface_context_id_v4",
                    "plan_binding_hash": plan_binding_hash,
                    "surface_id": surface.surface_id,
                    "part_index": ordinal,
                    "context_hash": context_hash,
                }
            )
            part = V4Part(
                payload=record,
                surface_id=surface.surface_id,
                context_id=context_id,
                context_hash=context_hash,
                part_index=ordinal,
                part_count=len(chunks),
                source_sha256=source_sha256,
            )
            result.append(part)
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
    plan: dict[str, object] = {
        **binding,
        "kind": "simple_surface_enrichment_plan_v4",
        "plan_binding_hash": plan_binding_hash,
        "target_surface_ids": [surface.surface_id for surface in targets],
        "targets": target_rows,
        "expected_parts": expected_parts,
    }
    return plan, tuple(result)
