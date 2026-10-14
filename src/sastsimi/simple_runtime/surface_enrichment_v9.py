"""Pure v9 source-review plan over an immutable v8 surface certificate.

The plan is an inventory, not a coverage verdict. Every source part remains
individually reviewable, and saved plans can be reconstructed for replay.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.prompt_redaction import redact_untrusted_text_preserving_lines
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .attack_surfaces import AttackSurface, SurfaceIndex
from .candidates import StaticCandidate
from .models import CheckpointIdentity
from .surface_applicability_v9 import (
    AnalyzerApplicabilityV9,
    validate_analyzer_applicability,
)
from .surface_coverage_v6 import SurfaceCoverageV6
from .surface_evidence_graph_v4 import _raw_source
from .surface_intrinsic_proof_v9 import IntrinsicProofV9, validate_intrinsic_proof
from .surface_path_proof_v9 import (
    ContextPartV9,
    PathCertificateV9,
    validate_path_certificate,
)

_HASH = re.compile(r"[0-9a-f]{64}\Z")
RoleV9 = Literal["ENTRY", "TRUST_BOUNDARY", "ANCHOR"]
ReviewStatusV9 = Literal[
    "HYPOTHESES", "NO_HYPOTHESIS", "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
]


@dataclass(frozen=True, slots=True)
class V9Part:
    payload: dict[str, object]
    surface_id: str
    context_id: str
    context_hash: str
    part_id: str
    part_index: int
    part_count: int
    source_sha256: str


@dataclass(frozen=True, slots=True)
class V9RoleCitation:
    """One Agent citation to an exact role on one graph path."""

    path_id: str
    role: RoleV9
    location: str
    source_sha256: str
    edge_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class V9ReviewedPart:
    """A response already checked against source by the caller's validator.

    Construction alone does not validate a model reply. Coverage independently
    checks this value against the recomputed plan and path graph.
    """

    surface_id: str
    context_id: str
    context_hash: str
    part_id: str
    source_sha256: str
    content_sha256: str
    status: ReviewStatusV9
    reviewed_path_ids: tuple[str, ...]
    role_citations: tuple[V9RoleCitation, ...]
    review_complete: bool | None = None


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _bound(ref: StoredDataRef, identity: CheckpointIdentity, value: object) -> bool:
    digest = _digest(value)
    return (
        ref.data_kind == "artifact"
        and ref.record_id is None
        and str(ref.workspace_id) == identity.workspace_id
        and str(ref.commit_id) == identity.commit_id
        and str(ref.stored_data_id) == ref.content_hash == digest
    )


def _parent_valid(
    identity: CheckpointIdentity,
    scope: str,
    index: SurfaceIndex,
    index_ref: StoredDataRef,
    prior_v8_plan_ref: StoredDataRef,
    prior_v8_plan: Mapping[str, object],
    prior_v8_coverage_ref: StoredDataRef,
    prior_v8_coverage: SurfaceCoverageV6,
    prior_v8_progress_hash: str,
) -> bool:
    index_hash = _digest(index.to_json())
    parent = prior_v8_coverage
    return (
        bool(scope)
        and identity.hypothesis_id is None
        and index.index_version == 2
        and index.workspace_id == identity.workspace_id
        and index.commit_id == identity.commit_id
        and isinstance(prior_v8_progress_hash, str)
        and _HASH.fullmatch(prior_v8_progress_hash) is not None
        and _bound(index_ref, identity, index.to_json())
        and _bound(prior_v8_plan_ref, identity, prior_v8_plan)
        and _bound(prior_v8_coverage_ref, identity, parent.to_json())
        and prior_v8_plan.get("kind") == "simple_surface_enrichment_plan_v8"
        and prior_v8_plan.get("analysis_id") == identity.analysis_id
        and prior_v8_plan.get("workspace_id") == identity.workspace_id
        and prior_v8_plan.get("commit_id") == identity.commit_id
        and prior_v8_plan.get("scope") == scope
        and prior_v8_plan.get("scope_fingerprint") == index.scope_fingerprint
        and prior_v8_plan.get("static_bundle_hash") == index.static_bundle_hash
        and prior_v8_plan.get("ast_manifest_hash") == index.ast_manifest_hash
        and prior_v8_plan.get("candidate_inventory_hash")
        == index.candidate_inventory_hash
        and prior_v8_plan.get("candidate_count") == index.candidate_count
        and prior_v8_plan.get("index_hash") == index_hash
        and prior_v8_plan.get("index_ref") == index_ref.model_dump(mode="json")
        and parent.v8_plan_ref == prior_v8_plan_ref
        and parent.scope_fingerprint == index.scope_fingerprint
        and parent.static_bundle_hash == index.static_bundle_hash
        and parent.ast_manifest_hash == index.ast_manifest_hash
        and parent.candidate_inventory_hash == index.candidate_inventory_hash
        and parent.candidate_count == index.candidate_count
        and parent.index_hash == index_hash
        and len(parent.surfaces) == len(index.surfaces)
        and all(
            (old.surface_id, old.path, old.line)
            == (surface.surface_id, surface.path, surface.line)
            for surface, old in zip(index.surfaces, parent.surfaces, strict=True)
        )
    )


def _source_excerpt(index: SurfaceIndex, part: ContextPartV9, workspace: Path) -> str:
    source_hashes = dict(index.ast_source_hashes)
    if source_hashes.get(part.path) != part.source_sha256:
        raise ValueError("SURFACE_ENRICHMENT_V9_SOURCE_INVALID")
    raw = _raw_source(workspace, part.path, part.source_sha256)
    source_lines = raw.decode("utf-8").splitlines()
    if not 1 <= part.start_line <= part.end_line <= len(source_lines):
        raise ValueError("SURFACE_ENRICHMENT_V9_SOURCE_INVALID")
    content = "\n".join(source_lines[part.start_line - 1 : part.end_line])
    if hashlib.sha256(content.encode("utf-8")).hexdigest() != part.content_sha256:
        raise ValueError("SURFACE_ENRICHMENT_V9_SOURCE_INVALID")
    redacted = redact_untrusted_text_preserving_lines(raw).data.decode("utf-8")
    redacted_lines = redacted.splitlines()
    if len(redacted_lines) != len(source_lines):
        raise ValueError("SURFACE_ENRICHMENT_V9_SOURCE_INVALID")
    excerpt = "\n".join(redacted_lines[part.start_line - 1 : part.end_line])
    if len(excerpt.encode("utf-8")) > 16 * 1024:
        raise ValueError("SURFACE_ENRICHMENT_V9_CONTEXT_LIMIT")
    return excerpt


def _role_directory(
    graph: Mapping[str, object],
    surface: AttackSurface,
    part: ContextPartV9,
    certificate: PathCertificateV9 | None = None,
) -> list[dict[str, object]]:
    paths = graph.get("paths")
    edges = graph.get("edges")
    if not isinstance(paths, list) or not isinstance(edges, list):
        raise ValueError("SURFACE_ENRICHMENT_V9_GRAPH_INVALID")
    edge_map = {edge.get("edge_id"): edge for edge in edges if isinstance(edge, dict)}
    downstream = (
        {path.path_id: path for path in certificate.downstream_paths}
        if certificate is not None
        else {}
    )
    directory: list[dict[str, object]] = []
    for path_id in part.path_ids:
        derived = downstream.get(path_id)
        if derived is not None:
            steps: list[object] = [step.to_json() for step in derived.steps]
            path_edges: list[object] = list(derived.edge_ids)
        else:
            matches = [
                path
                for path in paths
                if isinstance(path, dict) and path.get("path_id") == path_id
            ]
            if len(matches) != 1 or not isinstance(matches[0].get("steps"), list):
                raise ValueError("SURFACE_ENRICHMENT_V9_GRAPH_INVALID")
            path = matches[0]
            raw_edges = path.get("edge_ids")
            if not isinstance(raw_edges, list):
                raise ValueError("SURFACE_ENRICHMENT_V9_GRAPH_INVALID")
            path_edges = cast(list[object], raw_edges)
            steps = cast(list[object], path["steps"])
        for ordinal, step in enumerate(steps):
            if not isinstance(step, dict):
                raise ValueError("SURFACE_ENRICHMENT_V9_GRAPH_INVALID")
            line = step.get("line")
            if (
                step.get("path") != part.path
                or type(line) is not int
                or not part.start_line <= line <= part.end_line
            ):
                continue
            roles: list[RoleV9] = []
            if step.get("role") == "ROUTE_ENTRY":
                roles.append("ENTRY")
            if step.get("role") == "REQUEST_CONTEXT":
                roles.append("TRUST_BOUNDARY")
            if (step.get("path"), line) == (surface.path, surface.line):
                roles.append("ANCHOR")
            if not roles:
                continue
            node_id = step.get("node_id")
            incident = (
                [
                    edge_id
                    for edge_id in path_edges[max(0, ordinal - 1) : ordinal + 1]
                    if isinstance(edge_id, str)
                ]
                if derived is not None
                else [
                    edge_id
                    for edge_id in path_edges
                    if isinstance(edge_id, str)
                    and isinstance(edge_map.get(edge_id), dict)
                    and node_id
                    in {
                        edge_map[edge_id].get("from_node_id"),
                        edge_map[edge_id].get("to_node_id"),
                    }
                ]
            )
            for role in roles:
                directory.append(
                    {
                        "path_id": path_id,
                        "role": role,
                        "location": f"{part.path}:{line}",
                        "source_sha256": part.source_sha256,
                        "edge_ids": incident,
                    }
                )
    return directory


def prepare_surface_enrichment_v9(
    identity: CheckpointIdentity,
    scope: str,
    index: SurfaceIndex,
    index_ref: StoredDataRef,
    prior_v8_plan_ref: StoredDataRef,
    prior_v8_plan: Mapping[str, object],
    prior_v8_coverage_ref: StoredDataRef,
    prior_v8_coverage: SurfaceCoverageV6,
    prior_v8_progress_hash: str,
    applicability: AnalyzerApplicabilityV9,
    intrinsic_proofs: Mapping[str, IntrinsicProofV9],
    path_certificates: Mapping[str, PathCertificateV9],
    graphs: Mapping[str, Mapping[str, object]],
    workspace: Path,
    *,
    candidates: Mapping[str, StaticCandidate] | None = None,
    artifacts: SimpleArtifactRepository | None = None,
) -> tuple[dict[str, object], tuple[V9Part, ...]]:
    """Recompute all supplied proofs and pin their exact bounded review parts."""

    if not _parent_valid(
        identity,
        scope,
        index,
        index_ref,
        prior_v8_plan_ref,
        prior_v8_plan,
        prior_v8_coverage_ref,
        prior_v8_coverage,
        prior_v8_progress_hash,
    ):
        raise ValueError("SURFACE_ENRICHMENT_V9_PARENT_INVALID")
    surface_ids = {surface.surface_id for surface in index.surfaces}
    if (
        len(surface_ids) != len(index.surfaces)
        or set(graphs) != surface_ids
        or not set(intrinsic_proofs) <= surface_ids
        or not set(path_certificates) <= surface_ids
        or not validate_analyzer_applicability(index, applicability, workspace)
    ):
        raise ValueError("SURFACE_ENRICHMENT_V9_PROOF_INVALID")
    targets: list[dict[str, object]] = []
    for surface in index.surfaces:
        graph = graphs[surface.surface_id]
        intrinsic = intrinsic_proofs.get(surface.surface_id)
        path = path_certificates.get(surface.surface_id)
        if (
            intrinsic is not None
            and not validate_intrinsic_proof(
                index,
                surface,
                workspace,
                graph,
                intrinsic,
                candidates=candidates,
                artifacts=artifacts,
            )
        ) or (
            path is not None
            and not validate_path_certificate(
                index, surface, graph, applicability, workspace, path
            )
        ):
            raise ValueError("SURFACE_ENRICHMENT_V9_PROOF_INVALID")
        targets.append(
            {
                "surface_id": surface.surface_id,
                "surface_type": surface.type,
                "path": surface.path,
                "line": surface.line,
                "graph_hash": _digest(graph),
                "intrinsic_type": intrinsic.proof_type if intrinsic else None,
                "intrinsic_hash": _digest(intrinsic.to_json()) if intrinsic else None,
                "path_certificate_hash": _digest(path.to_json()) if path else None,
                "path_ids": list(path.path_ids) if path else [],
                "unresolved_path_ids": list(path.unresolved_path_ids) if path else [],
                "unresolved_gap_codes": list(path.unresolved_gap_codes) if path else [],
                "source_complete": bool(path and path.source_complete),
            }
        )
    binding: dict[str, object] = {
        "kind": "simple_surface_enrichment_binding_v9",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope": scope,
        "scope_fingerprint": index.scope_fingerprint,
        "static_bundle_hash": index.static_bundle_hash,
        "ast_manifest_hash": index.ast_manifest_hash,
        "candidate_inventory_hash": index.candidate_inventory_hash,
        "candidate_count": index.candidate_count,
        "index_ref": index_ref.model_dump(mode="json"),
        "index_hash": index_ref.content_hash,
        "prior_v8_plan_ref": prior_v8_plan_ref.model_dump(mode="json"),
        "prior_v8_coverage_ref": prior_v8_coverage_ref.model_dump(mode="json"),
        "prior_v8_progress_hash": prior_v8_progress_hash,
        "applicability_hash": _digest(applicability.to_json()),
        "targets": targets,
    }
    binding_hash = _digest(binding)
    parts: list[V9Part] = []
    expected: list[dict[str, object]] = []
    for surface in index.surfaces:
        certificate = path_certificates.get(surface.surface_id)
        if certificate is None:
            continue
        contexts = certificate.context_parts
        graph = graphs[surface.surface_id]
        target = next(row for row in targets if row["surface_id"] == surface.surface_id)
        for index_in_surface, context in enumerate(contexts):
            payload: dict[str, object] = {
                "kind": "simple_surface_context_v9",
                "analysis_id": identity.analysis_id,
                "workspace_id": identity.workspace_id,
                "commit_id": identity.commit_id,
                "scope": scope,
                "scope_fingerprint": index.scope_fingerprint,
                "static_bundle_hash": index.static_bundle_hash,
                "ast_manifest_hash": index.ast_manifest_hash,
                "surface_index_hash": index_ref.content_hash,
                "prior_v8_plan_hash": prior_v8_plan_ref.content_hash,
                "prior_v8_coverage_hash": prior_v8_coverage_ref.content_hash,
                "prior_v8_progress_hash": prior_v8_progress_hash,
                "plan_binding_hash": binding_hash,
                "surface_id": surface.surface_id,
                "surface_type": surface.type,
                "path": surface.path,
                "line": surface.line,
                "graph_hash": target["graph_hash"],
                "path_certificate_hash": target["path_certificate_hash"],
                "context_part": context.to_json(),
                "part_index": index_in_surface,
                "part_count": len(contexts),
                "source_excerpt": _source_excerpt(index, context, workspace),
                "role_directory": _role_directory(graph, surface, context, certificate),
            }
            context_hash = _digest(payload)
            context_id = _digest(
                {
                    "kind": "simple_surface_context_id_v9",
                    "plan_binding_hash": binding_hash,
                    "surface_id": surface.surface_id,
                    "part_id": context.part_id,
                    "context_hash": context_hash,
                }
            )
            parts.append(
                V9Part(
                    payload=payload,
                    surface_id=surface.surface_id,
                    context_id=context_id,
                    context_hash=context_hash,
                    part_id=context.part_id,
                    part_index=index_in_surface,
                    part_count=len(contexts),
                    source_sha256=context.source_sha256,
                )
            )
            expected.append(
                {
                    "surface_id": surface.surface_id,
                    "context_id": context_id,
                    "context_hash": context_hash,
                    "part_id": context.part_id,
                    "part_index": index_in_surface,
                    "part_count": len(contexts),
                    "context_part": context.to_json(),
                    "graph_hash": target["graph_hash"],
                    "path_certificate_hash": target["path_certificate_hash"],
                }
            )
    if len({part.context_id for part in parts}) != len(parts):
        raise ValueError("SURFACE_ENRICHMENT_V9_PART_DUPLICATE")
    plan = dict(binding)
    plan.update(
        kind="simple_surface_enrichment_plan_v9",
        plan_binding_hash=binding_hash,
        expected_parts=expected,
    )
    return plan, tuple(parts)
