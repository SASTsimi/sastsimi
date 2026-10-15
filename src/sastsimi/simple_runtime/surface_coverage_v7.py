"""Conservative v9 successor coverage over an unchanged v8 certificate."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .attack_surfaces import AttackSurface, SurfaceIndex
from .candidates import StaticCandidate
from .models import CheckpointIdentity
from .store import SimpleCheckpointStore, SurfaceExplorationProgressRecord
from .surface_applicability_v9 import AnalyzerApplicabilityV9
from .surface_coverage_v2 import _child_reasons, _related_child_ids
from .surface_coverage_v5 import _completed_inconclusive_child
from .surface_coverage_v6 import SurfaceCoverageV6
from .surface_enrichment_v9 import (
    V9Part,
    V9ReviewedPart,
    _bound,
    _digest,
    prepare_surface_enrichment_v9,
)
from .surface_intrinsic_proof_v9 import IntrinsicProofV9
from .surface_path_proof_v9 import PathCertificateV9

CoverageStatusV7 = Literal["COVERED", "UNCOVERED", "INSUFFICIENT"]
_EVIDENCE_REASONS = frozenset(
    {
        "CONNECTED_ROLE_PROOF_MISSING",
        "LOCAL_ONLY_ATTACK_PATH_UNVERIFIED",
        "SURFACE_EVIDENCE_INSUFFICIENT",
        "SURFACE_SOURCE_UNAVAILABLE",
        "SURFACE_PART_PENDING",
        "UNREVIEWED_RELEVANT_PATH",
        "UNRESOLVED_RELEVANT_GRAPH_GAP",
        "INHERITED_GRAPH_SEMANTICS_UNVERIFIED",
    }
)
_REQUIRED_ROLES = frozenset({"ENTRY", "TRUST_BOUNDARY", "ANCHOR"})
_CHILD_REASONS = frozenset({"CHILD_HOLD", "CHILD_PENDING", "CHILD_STALE"})


@dataclass(frozen=True, slots=True)
class SurfaceProofV7:
    surface_id: str
    path: str
    line: int
    coverage_status: CoverageStatusV7
    prior_v6_status: CoverageStatusV7
    proof_kind: Literal["FIXED_SQL_LITERAL", "CONNECTED_PATHS", "NONE"]
    review_classification: str | None
    verified_roles: tuple[dict[str, object], ...]
    evidence_refs: tuple[StoredDataRef, ...]
    unresolved_reason_codes: tuple[str, ...]
    completed_inconclusive_children: tuple[dict[str, object], ...]
    reviewed_path_ids: tuple[str, ...]
    reviewed_context_ids: tuple[str, ...]
    intrinsic_proof_hash: str | None
    path_certificate_hash: str | None

    def to_json(self) -> dict[str, object]:
        return {
            "surface_id": self.surface_id,
            "path": self.path,
            "line": self.line,
            "coverage_status": self.coverage_status,
            "prior_v6_status": self.prior_v6_status,
            "proof_kind": self.proof_kind,
            "review_classification": self.review_classification,
            "verified_roles": list(self.verified_roles),
            "evidence_refs": [
                ref.model_dump(mode="json") for ref in self.evidence_refs
            ],
            "unresolved_reason_codes": list(self.unresolved_reason_codes),
            "completed_inconclusive_children": list(
                self.completed_inconclusive_children
            ),
            "reviewed_path_ids": list(self.reviewed_path_ids),
            "reviewed_context_ids": list(self.reviewed_context_ids),
            "intrinsic_proof_hash": self.intrinsic_proof_hash,
            "path_certificate_hash": self.path_certificate_hash,
        }


@dataclass(frozen=True, slots=True)
class SurfaceCoverageV7:
    scope_fingerprint: str
    static_bundle_hash: str
    ast_manifest_hash: str
    candidate_inventory_hash: str
    candidate_count: int
    index_hash: str
    original_coverage_ref: StoredDataRef
    scope_certificate_ref: StoredDataRef
    prior_v6_ref: StoredDataRef
    v9_plan_ref: StoredDataRef
    prior_v8_progress_hash: str
    applicability_hash: str
    raw_static_gaps: tuple[dict[str, object], ...]
    effective_python_gaps: tuple[dict[str, object], ...]
    missing_v9_parts: tuple[dict[str, str], ...]
    surfaces: tuple[SurfaceProofV7, ...]
    pending_candidate_count: int
    pending_child_count: int

    @property
    def complete(self) -> bool:
        return (
            not self.effective_python_gaps
            and not self.missing_v9_parts
            and self.pending_candidate_count == 0
            and self.pending_child_count == 0
            and bool(self.surfaces)
            and all(row.coverage_status == "COVERED" for row in self.surfaces)
        )

    def to_json(self) -> dict[str, object]:
        return {
            "kind": "simple_attack_surface_coverage_v7",
            "scope_fingerprint": self.scope_fingerprint,
            "static_bundle_hash": self.static_bundle_hash,
            "ast_manifest_hash": self.ast_manifest_hash,
            "candidate_inventory_hash": self.candidate_inventory_hash,
            "candidate_count": self.candidate_count,
            "index_hash": self.index_hash,
            "original_coverage_ref": self.original_coverage_ref.model_dump(mode="json"),
            "scope_certificate_ref": self.scope_certificate_ref.model_dump(mode="json"),
            "prior_v6_ref": self.prior_v6_ref.model_dump(mode="json"),
            "v9_plan_ref": self.v9_plan_ref.model_dump(mode="json"),
            "prior_v8_progress_hash": self.prior_v8_progress_hash,
            "applicability_hash": self.applicability_hash,
            "raw_static_gaps": list(self.raw_static_gaps),
            "effective_python_gaps": list(self.effective_python_gaps),
            "missing_v9_parts": list(self.missing_v9_parts),
            "surfaces": [row.to_json() for row in self.surfaces],
            "pending_candidate_count": self.pending_candidate_count,
            "pending_child_count": self.pending_child_count,
            "complete": self.complete,
        }


def _review_roles(
    part: V9Part, reviewed: V9ReviewedPart
) -> tuple[dict[str, object], ...]:
    context = part.payload["context_part"]
    directory = part.payload["role_directory"]
    if (
        not isinstance(context, dict)
        or not isinstance(directory, list)
        or reviewed.surface_id != part.surface_id
        or reviewed.context_id != part.context_id
        or reviewed.context_hash != part.context_hash
        or reviewed.part_id != part.part_id
        or reviewed.source_sha256 != context.get("source_sha256")
        or reviewed.content_sha256 != context.get("content_sha256")
        or reviewed.status
        not in {
            "HYPOTHESES",
            "NO_HYPOTHESIS",
            "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
        }
        or len(reviewed.reviewed_path_ids) != len(set(reviewed.reviewed_path_ids))
    ):
        raise ValueError("SURFACE_COVERAGE_V7_REVIEW_INVALID")
    expected_path_ids = context.get("path_ids")
    if (
        not isinstance(expected_path_ids, list)
        or not set(reviewed.reviewed_path_ids) <= set(expected_path_ids)
        or reviewed.status == "NO_HYPOTHESIS"
        and set(reviewed.reviewed_path_ids) != set(expected_path_ids)
    ):
        raise ValueError("SURFACE_COVERAGE_V7_REVIEW_INVALID")
    allowed = {
        (
            row.get("path_id"),
            row.get("role"),
            row.get("location"),
            row.get("source_sha256"),
            tuple(row.get("edge_ids", ())),
        )
        for row in directory
        if isinstance(row, dict) and isinstance(row.get("edge_ids"), list)
    }
    citations: list[dict[str, object]] = []
    seen: set[tuple[object, ...]] = set()
    for citation in reviewed.role_citations:
        if citation.path_id not in reviewed.reviewed_path_ids:
            raise ValueError("SURFACE_COVERAGE_V7_REVIEW_INVALID")
        signature = (
            citation.path_id,
            citation.role,
            citation.location,
            citation.source_sha256,
            citation.edge_ids,
        )
        if signature not in allowed or signature in seen:
            raise ValueError("SURFACE_COVERAGE_V7_REVIEW_INVALID")
        seen.add(signature)
        citations.append(
            {
                "path_id": citation.path_id,
                "role": citation.role,
                "location": citation.location,
                "source_sha256": citation.source_sha256,
                "edge_ids": list(citation.edge_ids),
                "context_id": reviewed.context_id,
            }
        )
    return tuple(citations)


def _connected_review(
    surface_id: str,
    certificate: PathCertificateV9 | None,
    parts: tuple[V9Part, ...],
    completed_parts: Mapping[tuple[str, str], V9ReviewedPart],
) -> tuple[bool, set[str], list[dict[str, object]], tuple[str, ...], tuple[str, ...]]:
    reasons: set[str] = set()
    roles: list[dict[str, object]] = []
    reviewed_context_ids: list[str] = []
    complete_paths: list[str] = []
    if certificate is None:
        return False, {"CONNECTED_PATH_CERTIFICATE_MISSING"}, roles, (), ()
    if not certificate.path_ids:
        reasons.add("CONNECTED_PATH_CERTIFICATE_MISSING")
    if certificate.unresolved_path_ids:
        reasons.add("UNREVIEWED_RELEVANT_PATH")
    if certificate.unresolved_gap_codes:
        reasons.add("UNRESOLVED_RELEVANT_GRAPH_GAP")
        reasons.update(certificate.unresolved_gap_codes)
    if not certificate.source_complete:
        reasons.add("SURFACE_SOURCE_UNAVAILABLE")
    seen_roles: dict[str, set[str]] = defaultdict(set)
    reviewed_by_path: dict[str, set[str]] = defaultdict(set)
    for part in parts:
        reviewed = completed_parts.get((surface_id, part.context_id))
        if reviewed is None:
            reasons.add("SURFACE_PART_PENDING")
            continue
        citations = _review_roles(part, reviewed)
        if reviewed.status == "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS":
            reasons.add("SURFACE_EVIDENCE_INSUFFICIENT")
            continue
        context = cast(dict[str, object], part.payload["context_part"])
        directory = cast(list[dict[str, object]], part.payload["role_directory"])
        available = cast(list[str], context["path_ids"])
        cited_signatures = {
            (
                row["path_id"],
                row["role"],
                row["location"],
                row["source_sha256"],
                tuple(cast(list[str], row["edge_ids"])),
            )
            for row in citations
        }
        expected_signatures = {
            (
                row["path_id"],
                row["role"],
                row["location"],
                row["source_sha256"],
                tuple(cast(list[str], row["edge_ids"])),
            )
            for row in directory
            if row["path_id"] in reviewed.reviewed_path_ids
        }
        complete = (
            set(reviewed.reviewed_path_ids) == set(available)
            and expected_signatures <= cited_signatures
        )
        if (
            reviewed.review_complete is not None
            and reviewed.review_complete != complete
        ):
            raise ValueError("SURFACE_COVERAGE_V7_REVIEW_INVALID")
        reviewed_context_ids.append(part.context_id)
        for path_id in reviewed.reviewed_path_ids:
            if {
                signature
                for signature in expected_signatures
                if signature[0] == path_id
            } <= {
                signature for signature in cited_signatures if signature[0] == path_id
            }:
                reviewed_by_path[path_id].add(part.part_id)
            else:
                reasons.add("SURFACE_EVIDENCE_INSUFFICIENT")
        roles.extend(citations)
        for citation in citations:
            seen_roles[cast(str, citation["path_id"])].add(cast(str, citation["role"]))
    parts_by_path: dict[str, set[str]] = defaultdict(set)
    for part in parts:
        context = cast(dict[str, object], part.payload["context_part"])
        for path_id in cast(list[str], context["path_ids"]):
            parts_by_path[path_id].add(part.part_id)
    for path_id in certificate.path_ids:
        if (
            path_id in certificate.unresolved_path_ids
            or not parts_by_path[path_id]
            or reviewed_by_path[path_id] != parts_by_path[path_id]
            or not _REQUIRED_ROLES <= seen_roles[path_id]
        ):
            reasons.add("UNREVIEWED_RELEVANT_PATH")
        else:
            complete_paths.append(path_id)
    ready = (
        certificate.source_complete
        and not certificate.unresolved_path_ids
        and not certificate.unresolved_gap_codes
        and bool(certificate.path_ids)
        and len(complete_paths) == len(certificate.path_ids)
        and not reasons
    )
    return (
        ready,
        reasons,
        roles,
        tuple(complete_paths),
        tuple(reviewed_context_ids),
    )


def _route_downstream_reviewed(
    surface: AttackSurface,
    certificate: PathCertificateV9 | None,
    graph: Mapping[str, object],
) -> bool:
    """A route anchor is not itself a downstream sink proof."""

    if (
        certificate is None
        or not certificate.source_complete
        or certificate.graph_hash != _digest(graph)
        or not certificate.downstream_paths
        or set(certificate.path_ids)
        != {path.path_id for path in certificate.downstream_paths}
    ):
        return False
    for path in certificate.downstream_paths:
        steps = path.steps
        if not steps:
            return False
        entry = next(
            (i for i, step in enumerate(steps) if step.role == "ROUTE_ENTRY"), None
        )
        sink = steps[-1]
        if (
            entry is None
            or path.sink_surface_id == surface.surface_id
            or sink.role != "SINK"
            or (sink.path, sink.line) == (surface.path, surface.line)
            or not any(
                (step.path, step.line) == (surface.path, surface.line)
                for step in steps[:-1]
            )
            or not any(step.role == "REQUEST_CONTEXT" for step in steps[entry + 1 : -1])
            or len(path.edge_ids) != len(steps) - 1
        ):
            return False
    return True


def evaluate_surface_coverage_v7(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    index_ref: StoredDataRef,
    prior_v8_plan_ref: StoredDataRef,
    prior_v8_plan: Mapping[str, object],
    prior_v8_coverage_ref: StoredDataRef,
    parent_v6: SurfaceCoverageV6,
    v9_plan_ref: StoredDataRef,
    v9_plan: Mapping[str, object],
    prior_v8_progress_hash: str,
    applicability: AnalyzerApplicabilityV9,
    intrinsic_proofs: Mapping[str, IntrinsicProofV9],
    path_certificates: Mapping[str, PathCertificateV9],
    graphs: Mapping[str, Mapping[str, object]],
    completed_parts: Mapping[tuple[str, str], V9ReviewedPart],
    workspace: Path,
    *,
    pending_candidate_count: int,
    pending_child_count: int,
    candidates: Mapping[str, StaticCandidate] | None = None,
    artifacts: SimpleArtifactRepository | None = None,
    progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord] | None = None,
    store: SimpleCheckpointStore | None = None,
) -> SurfaceCoverageV7:
    """Promote only exact SQL calls or fully reviewed connected path sets."""

    if (
        type(pending_candidate_count) is not int
        or pending_candidate_count < 0
        or type(pending_child_count) is not int
        or pending_child_count < 0
        or not _bound(v9_plan_ref, identity, v9_plan)
        or prior_v8_progress_hash != v9_plan.get("prior_v8_progress_hash")
    ):
        raise ValueError("SURFACE_COVERAGE_V7_PLAN_INVALID")
    try:
        reconstructed, all_parts = prepare_surface_enrichment_v9(
            identity,
            cast(str, v9_plan["scope"]),
            index,
            index_ref,
            prior_v8_plan_ref,
            prior_v8_plan,
            prior_v8_coverage_ref,
            parent_v6,
            prior_v8_progress_hash,
            applicability,
            intrinsic_proofs,
            path_certificates,
            graphs,
            workspace,
            candidates=candidates,
            artifacts=artifacts,
        )
    except (KeyError, OSError, TypeError, ValueError, UnicodeError) as error:
        raise ValueError("SURFACE_COVERAGE_V7_PLAN_INVALID") from error
    if reconstructed != v9_plan:
        raise ValueError("SURFACE_COVERAGE_V7_PLAN_INVALID")
    expected = {(part.surface_id, part.context_id) for part in all_parts}
    if not set(completed_parts) <= expected or any(
        not isinstance(reviewed, V9ReviewedPart)
        for reviewed in completed_parts.values()
    ):
        raise ValueError("SURFACE_COVERAGE_V7_PROGRESS_INVALID")
    if (
        (progress is None) != (store is None)
        or progress is not None
        and artifacts is None
    ):
        raise ValueError("SURFACE_COVERAGE_V7_CHILD_EVIDENCE_MISSING")
    for key, reviewed in completed_parts.items():
        if reviewed.status != "HYPOTHESES":
            continue
        row = progress.get(key) if progress is not None else None
        if (
            row is None
            or row.proposal_version != 9
            or row.status != "HYPOTHESES"
            or not row.hypothesis_ids
        ):
            raise ValueError("SURFACE_COVERAGE_V7_CHILD_EVIDENCE_MISSING")
    by_surface: dict[str, tuple[V9Part, ...]] = {
        surface.surface_id: tuple(
            part for part in all_parts if part.surface_id == surface.surface_id
        )
        for surface in index.surfaces
    }
    missing = tuple(
        {"surface_id": part.surface_id, "context_id": part.context_id}
        for part in all_parts
        if (part.surface_id, part.context_id) not in completed_parts
    )
    proofs: list[SurfaceProofV7] = []
    for surface, old in zip(index.surfaces, parent_v6.surfaces, strict=True):
        reasons = set(old.unresolved_reason_codes)
        roles = list(old.verified_roles)
        completed_children = list(old.completed_inconclusive_children)
        source_complete, path_reasons, checked_roles, reviewed_paths, reviewed_ids = (
            _connected_review(
                surface.surface_id,
                path_certificates.get(surface.surface_id),
                by_surface[surface.surface_id],
                completed_parts,
            )
        )
        roles.extend(checked_roles)
        intrinsic = intrinsic_proofs.get(surface.surface_id)
        exact_sql = bool(
            intrinsic
            and intrinsic.proof_type == "FIXED_SQL_LITERAL"
            and surface.type == "SQL_EXECUTION"
        )
        proof_kind: Literal["FIXED_SQL_LITERAL", "CONNECTED_PATHS", "NONE"] = (
            "FIXED_SQL_LITERAL"
            if exact_sql
            else "CONNECTED_PATHS"
            if source_complete
            else "NONE"
        )
        if progress is not None and store is not None and artifacts is not None:
            related = _related_child_ids(
                identity, surface, progress, store, index.scope_fingerprint
            )
            historical_ids = {
                child_id
                for row in progress.values()
                if row.surface_id == surface.surface_id and row.proposal_version <= 8
                for child_id in row.hypothesis_ids
            }
            if historical_ids and historical_ids.issubset(related):
                reasons.difference_update(_CHILD_REASONS)
            for child_id in sorted(related):
                child_reasons = _child_reasons(identity, child_id, store, artifacts)
                if child_reasons == ("CHILD_HOLD",) and source_complete:
                    completed = _completed_inconclusive_child(
                        identity, child_id, store, artifacts
                    )
                    if completed is not None:
                        if completed not in completed_children:
                            completed_children.append(completed)
                        continue
                reasons.update(child_reasons)
            if "CHILD_ERROR" in reasons:
                raise ValueError("SURFACE_COVERAGE_V7_CHILD_FAILED")
        if old.coverage_status == "INSUFFICIENT":
            if exact_sql or source_complete:
                reasons.difference_update(_EVIDENCE_REASONS)
            if surface.type == "REQUEST_ENTRY" and not _route_downstream_reviewed(
                surface,
                path_certificates.get(surface.surface_id),
                graphs[surface.surface_id],
            ):
                reasons.add("ROUTE_DOWNSTREAM_UNVERIFIED")
            if not exact_sql:
                reasons.update(path_reasons)
            if parent_v6.effective_python_gaps or index.static_gaps:
                reasons.add("STATIC_COVERAGE_GAP")
            if max(parent_v6.pending_candidate_count, pending_candidate_count):
                reasons.add("CANDIDATE_PENDING")
            if max(parent_v6.pending_child_count, pending_child_count):
                reasons.add("CHILD_PENDING")
            status: CoverageStatusV7 = "COVERED" if not reasons else "INSUFFICIENT"
        else:
            # A new child can make an inherited covered row insufficient.
            status = (
                "INSUFFICIENT"
                if old.coverage_status == "COVERED" and reasons
                else old.coverage_status
            )
        proofs.append(
            SurfaceProofV7(
                surface_id=surface.surface_id,
                path=surface.path,
                line=surface.line,
                coverage_status=status,
                prior_v6_status=old.coverage_status,
                proof_kind=proof_kind,
                review_classification=old.review_classification,
                verified_roles=tuple(roles),
                evidence_refs=old.evidence_refs,
                unresolved_reason_codes=tuple(sorted(reasons)),
                completed_inconclusive_children=tuple(completed_children),
                reviewed_path_ids=reviewed_paths,
                reviewed_context_ids=reviewed_ids,
                intrinsic_proof_hash=_digest(intrinsic.to_json())
                if intrinsic
                else None,
                path_certificate_hash=(
                    _digest(path_certificates[surface.surface_id].to_json())
                    if surface.surface_id in path_certificates
                    else None
                ),
            )
        )
    return SurfaceCoverageV7(
        scope_fingerprint=index.scope_fingerprint,
        static_bundle_hash=index.static_bundle_hash,
        ast_manifest_hash=index.ast_manifest_hash,
        candidate_inventory_hash=index.candidate_inventory_hash,
        candidate_count=index.candidate_count,
        index_hash=index_ref.content_hash,
        original_coverage_ref=parent_v6.original_coverage_ref,
        scope_certificate_ref=parent_v6.scope_certificate_ref,
        prior_v6_ref=prior_v8_coverage_ref,
        v9_plan_ref=v9_plan_ref,
        prior_v8_progress_hash=prior_v8_progress_hash,
        applicability_hash=_digest(applicability.to_json()),
        raw_static_gaps=parent_v6.raw_static_gaps,
        effective_python_gaps=parent_v6.effective_python_gaps,
        missing_v9_parts=missing,
        surfaces=tuple(proofs),
        pending_candidate_count=max(
            parent_v6.pending_candidate_count, pending_candidate_count
        ),
        pending_child_count=max(parent_v6.pending_child_count, pending_child_count),
    )
