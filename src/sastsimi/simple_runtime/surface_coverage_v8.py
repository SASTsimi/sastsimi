"""Conservative successor coverage for source-bound Python route proofs."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from sastsimi.contracts.refs import StoredDataRef

from .attack_surfaces import SurfaceIndex
from .surface_enrichment_v9 import _digest
from .surface_enrichment_v10 import _proofs_match_index
from .surface_route_boundary_v10 import RouteBoundaryProofV10

if TYPE_CHECKING:
    from .surface_coverage_v7 import SurfaceCoverageV7

CoverageStatusV8 = Literal["COVERED", "UNCOVERED", "INSUFFICIENT"]
_SOURCE_PATH_REASONS = frozenset(
    {
        "SURFACE_SOURCE_UNAVAILABLE",
        "UNREVIEWED_RELEVANT_PATH",
        "CONNECTED_ROLE_PROOF_MISSING",
        "LOCAL_ONLY_ATTACK_PATH_UNVERIFIED",
        "INHERITED_GRAPH_SEMANTICS_UNVERIFIED",
        "SURFACE_EVIDENCE_INSUFFICIENT",
    }
)
_TEMPLATE_SOURCE_REASONS = (
    _SOURCE_PATH_REASONS - {"SURFACE_EVIDENCE_INSUFFICIENT"}
) | {"CONNECTED_PATH_CERTIFICATE_MISSING"}
_REQUIRED_ROLES = frozenset({"ENTRY", "TRUST_BOUNDARY", "ANCHOR"})
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _reviewed_v9_paths(
    index: SurfaceIndex,
    surface_path: str,
    surface_line: int,
    roles: tuple[dict[str, object], ...],
    reviewed_context_ids: tuple[str, ...],
    proof: RouteBoundaryProofV10,
) -> bool:
    """Join completed v9 role citations to every exact route-proof path."""

    expected = set(proof.expected_v9_path_ids)
    if (
        not expected
        or len(expected) != len(proof.expected_v9_path_ids)
        or expected != set(proof.resolved_v9_path_ids)
        or len(expected) != len(proof.resolved_v9_path_ids)
        or not set(proof.unresolved_v9_path_ids) <= expected
        or type(proof.expected_v9_part_count) is not int
        or proof.expected_v9_part_count < 1
        or len(reviewed_context_ids) != proof.expected_v9_part_count
        or len(set(reviewed_context_ids)) != proof.expected_v9_part_count
    ):
        return False
    source_hash = dict(index.ast_source_hashes).get(surface_path)
    if source_hash is None:
        return False
    edges_by_path: dict[str, set[str]] = defaultdict(set)
    for edge in proof.resolved_edges:
        path_id = edge.get("path_id")
        edge_id = edge.get("edge_id")
        if (
            not isinstance(path_id, str)
            or path_id not in expected
            or not isinstance(edge_id, str)
            or not edge_id
            or edge.get("source_sha256") != source_hash
        ):
            return False
        edges_by_path[path_id].add(edge_id)
    if set(edges_by_path) != expected:
        return False
    seen_roles: dict[str, set[str]] = defaultdict(set)
    for citation in roles:
        path_id = citation.get("path_id")
        role = citation.get("role")
        location = citation.get("location")
        edge_ids = citation.get("edge_ids")
        if not (
            isinstance(path_id, str)
            and path_id in expected
            and isinstance(role, str)
            and role in _REQUIRED_ROLES
            and isinstance(location, str)
            and location.startswith(f"{surface_path}:")
            and location.removeprefix(f"{surface_path}:").isdigit()
            and citation.get("source_sha256") == source_hash
            and citation.get("context_id") in reviewed_context_ids
            and isinstance(edge_ids, list)
            and edge_ids
            and all(
                isinstance(edge_id, str) and edge_id in edges_by_path[path_id]
                for edge_id in edge_ids
            )
            and (role != "ANCHOR" or location == f"{surface_path}:{surface_line}")
        ):
            continue
        seen_roles[path_id].add(role)
    return all(_REQUIRED_ROLES <= seen_roles[path_id] for path_id in expected)


def _pinned_literal_template(
    index: SurfaceIndex,
    surface_id: str,
    surface_path: str,
    surface_line: int,
    proof: RouteBoundaryProofV10,
) -> bool:
    """A pathless v9 route can close at one pinned Python→template handoff."""

    if (
        proof.boundary_kind != "LITERAL_TEMPLATE"
        or proof.expected_v9_path_ids
        or proof.unresolved_v9_path_ids
        or proof.resolved_v9_path_ids
        or proof.expected_v9_part_count != 0
        or proof.external_scope_limit != "TEMPLATE_CONTENT_NOT_ANALYZED"
        or len(proof.resolved_edges) != 1
    ):
        return False
    edge = proof.resolved_edges[0]
    to_line = edge.get("to_line")
    template_path = edge.get("template_path")
    template_hash = edge.get("template_sha256")
    template_parts = template_path.split("/") if isinstance(template_path, str) else []
    return bool(
        edge.get("path_id") == f"python-template:{surface_id}"
        and edge.get("from_line") == surface_line
        and isinstance(to_line, int)
        and not isinstance(to_line, bool)
        and to_line >= surface_line
        and edge.get("source_sha256") == dict(index.ast_source_hashes).get(surface_path)
        and isinstance(template_path, str)
        and "\\" not in template_path
        and ":" not in template_parts[0]
        and "templates" in template_parts[:-1]
        and all(part not in {"", ".", ".."} for part in template_parts)
        and isinstance(template_hash, str)
        and _SHA256.fullmatch(template_hash)
    )


@dataclass(frozen=True, slots=True)
class SurfaceProofV8:
    surface_id: str
    path: str
    line: int
    coverage_status: CoverageStatusV8
    prior_v7_status: CoverageStatusV8
    proof_kind: str
    verified_roles: tuple[dict[str, object], ...]
    unresolved_reason_codes: tuple[str, ...]
    reviewed_path_ids: tuple[str, ...]
    reviewed_context_ids: tuple[str, ...]
    completed_inconclusive_children: tuple[dict[str, object], ...]
    route_proof_hash: str
    external_scope_limit: str | None

    def to_json(self) -> dict[str, object]:
        return {
            "surface_id": self.surface_id,
            "path": self.path,
            "line": self.line,
            "coverage_status": self.coverage_status,
            "prior_v7_status": self.prior_v7_status,
            "proof_kind": self.proof_kind,
            "verified_roles": list(self.verified_roles),
            "unresolved_reason_codes": list(self.unresolved_reason_codes),
            "reviewed_path_ids": list(self.reviewed_path_ids),
            "reviewed_context_ids": list(self.reviewed_context_ids),
            "completed_inconclusive_children": list(
                self.completed_inconclusive_children
            ),
            "route_proof_hash": self.route_proof_hash,
            "external_scope_limit": self.external_scope_limit,
        }


@dataclass(frozen=True, slots=True)
class SurfaceCoverageV8:
    scope_fingerprint: str
    static_bundle_hash: str
    ast_manifest_hash: str
    candidate_inventory_hash: str
    candidate_count: int
    index_hash: str
    v9_coverage_hash: str
    v10_plan_ref: StoredDataRef
    raw_static_gaps: tuple[dict[str, object], ...]
    effective_python_gaps: tuple[dict[str, object], ...]
    missing_v9_parts: tuple[dict[str, str], ...]
    surfaces: tuple[SurfaceProofV8, ...]
    pending_candidate_count: int
    pending_child_count: int
    remaining_route_gap_events: tuple[dict[str, object], ...]

    @property
    def complete(self) -> bool:
        return (
            bool(self.surfaces)
            and not self.effective_python_gaps
            and not self.remaining_route_gap_events
            and not self.missing_v9_parts
            and self.pending_candidate_count == 0
            and self.pending_child_count == 0
            and all(row.coverage_status == "COVERED" for row in self.surfaces)
        )

    def to_json(self) -> dict[str, object]:
        return {
            "kind": "simple_attack_surface_coverage_v8",
            "scope_fingerprint": self.scope_fingerprint,
            "static_bundle_hash": self.static_bundle_hash,
            "ast_manifest_hash": self.ast_manifest_hash,
            "candidate_inventory_hash": self.candidate_inventory_hash,
            "candidate_count": self.candidate_count,
            "index_hash": self.index_hash,
            "v9_coverage_hash": self.v9_coverage_hash,
            "v10_plan_ref": self.v10_plan_ref.model_dump(mode="json"),
            "raw_static_gaps": list(self.raw_static_gaps),
            "effective_python_gaps": list(self.effective_python_gaps),
            "missing_v9_parts": list(self.missing_v9_parts),
            "surfaces": [row.to_json() for row in self.surfaces],
            "pending_candidate_count": self.pending_candidate_count,
            "pending_child_count": self.pending_child_count,
            "remaining_route_gap_events": list(self.remaining_route_gap_events),
            "complete": self.complete,
        }


def evaluate_surface_coverage_v8(
    index: SurfaceIndex,
    parent: SurfaceCoverageV7,
    plan_ref: StoredDataRef,
    proofs: Mapping[str, RouteBoundaryProofV10],
    *,
    pending_candidate_count: int,
    pending_child_count: int,
) -> SurfaceCoverageV8:
    """Carry forward all unproved reasons; never infer missing gaps are absent."""

    if (
        type(pending_candidate_count) is not int
        or pending_candidate_count < 0
        or type(pending_child_count) is not int
        or pending_child_count < 0
        or plan_ref.data_kind != "artifact"
        or plan_ref.record_id is not None
        or str(plan_ref.workspace_id) != index.workspace_id
        or str(plan_ref.commit_id) != index.commit_id
        or str(plan_ref.stored_data_id) != plan_ref.content_hash
        or not _proofs_match_index(index, proofs)
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
        raise ValueError("SURFACE_COVERAGE_V8_PARENT_INVALID")
    rows: list[SurfaceProofV8] = []
    for surface, old in zip(index.surfaces, parent.surfaces, strict=True):
        proof = proofs[surface.surface_id]
        reasons = set(old.unresolved_reason_codes)
        reviewed_paths = _reviewed_v9_paths(
            index,
            surface.path,
            surface.line,
            old.verified_roles,
            old.reviewed_context_ids,
            proof,
        )
        literal_template = _pinned_literal_template(
            index, surface.surface_id, surface.path, surface.line, proof
        ) and not (old.reviewed_context_ids or old.reviewed_path_ids)
        closed_boundary = (
            surface.type == "REQUEST_ENTRY"
            and old.coverage_status == "INSUFFICIENT"
            and proof.boundary_kind
            in {"PYTHON_RESPONSE", "LITERAL_TEMPLATE", "PINNED_PYTHON_SINK"}
            and proof.resolved_edges
            and not proof.unresolved_reasons
            and not proof.remaining_gap_events
            and not parent.missing_v9_parts
            and (
                literal_template
                if proof.boundary_kind == "LITERAL_TEMPLATE"
                else reviewed_paths
            )
            and not max(parent.pending_candidate_count, pending_candidate_count)
            and not max(parent.pending_child_count, pending_child_count)
        )
        route_promoted = closed_boundary and "ROUTE_DOWNSTREAM_UNVERIFIED" in reasons
        if route_promoted:
            reasons.discard("ROUTE_DOWNSTREAM_UNVERIFIED")
        source_reasons_discharged = closed_boundary and bool(
            reasons
            & (_TEMPLATE_SOURCE_REASONS if literal_template else _SOURCE_PATH_REASONS)
        )
        if source_reasons_discharged:
            reasons.difference_update(
                _TEMPLATE_SOURCE_REASONS if literal_template else _SOURCE_PATH_REASONS
            )
        graph_gap_discharged = (
            closed_boundary
            and "UNRESOLVED_RELEVANT_GRAPH_GAP" in reasons
            and bool(proof.discharged_gap_events)
            and not proof.remaining_gap_events
        )
        if graph_gap_discharged:
            reasons.remove("UNRESOLVED_RELEVANT_GRAPH_GAP")
            for event in proof.discharged_gap_events:
                reason = event.get("reason")
                if isinstance(reason, str):
                    reasons.discard(reason)
        if (
            surface.type == "REQUEST_ENTRY"
            and old.coverage_status != "COVERED"
            and proof.remaining_gap_events
        ):
            reasons.add("UNRESOLVED_RELEVANT_GRAPH_GAP")
        if old.coverage_status != "COVERED":
            if parent.effective_python_gaps:
                reasons.add("STATIC_COVERAGE_GAP")
            if max(parent.pending_candidate_count, pending_candidate_count):
                reasons.add("CANDIDATE_PENDING")
            if max(parent.pending_child_count, pending_child_count):
                reasons.add("CHILD_PENDING")
            if surface.type == "REQUEST_ENTRY":
                # Optional successor failures cannot demote an independent
                # v7 COVERED row; global gaps still prevent total completion.
                reasons.update(proof.unresolved_reasons)
        status: CoverageStatusV8 = (
            "INSUFFICIENT"
            if reasons
            else "COVERED"
            if route_promoted or graph_gap_discharged or source_reasons_discharged
            else old.coverage_status
        )
        rows.append(
            SurfaceProofV8(
                surface_id=surface.surface_id,
                path=surface.path,
                line=surface.line,
                coverage_status=status,
                prior_v7_status=old.coverage_status,
                proof_kind=proof.boundary_kind
                if proof.boundary_kind != "NONE"
                else old.proof_kind,
                verified_roles=old.verified_roles,
                unresolved_reason_codes=tuple(sorted(reasons)),
                reviewed_path_ids=(
                    tuple(
                        sorted(
                            set(old.reviewed_path_ids) | set(proof.resolved_v9_path_ids)
                        )
                    )
                    if closed_boundary and reviewed_paths
                    else old.reviewed_path_ids
                ),
                reviewed_context_ids=old.reviewed_context_ids,
                completed_inconclusive_children=old.completed_inconclusive_children,
                route_proof_hash=_digest(proof.to_json()),
                external_scope_limit=proof.external_scope_limit,
            )
        )
    return SurfaceCoverageV8(
        scope_fingerprint=index.scope_fingerprint,
        static_bundle_hash=index.static_bundle_hash,
        ast_manifest_hash=index.ast_manifest_hash,
        candidate_inventory_hash=index.candidate_inventory_hash,
        candidate_count=index.candidate_count,
        index_hash=_digest(index.to_json()),
        v9_coverage_hash=_digest(parent.to_json()),
        v10_plan_ref=plan_ref,
        raw_static_gaps=parent.raw_static_gaps,
        effective_python_gaps=parent.effective_python_gaps,
        missing_v9_parts=parent.missing_v9_parts,
        surfaces=tuple(rows),
        pending_candidate_count=max(
            parent.pending_candidate_count, pending_candidate_count
        ),
        pending_child_count=max(parent.pending_child_count, pending_child_count),
        remaining_route_gap_events=tuple(
            {**event, "surface_id": surface.surface_id}
            for surface in index.surfaces
            if surface.type == "REQUEST_ENTRY"
            for event in proofs[surface.surface_id].remaining_gap_events
        ),
    )
