"""Role-aware v8 coverage over an immutable v7 parent certificate.

The old certificate is frozen after the v8 plan is pinned. Recomputing its
global pending-child count would incorrectly include new v8 children.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .attack_surfaces import SurfaceIndex, surface_review_contract
from .models import CheckpointIdentity, SimpleStage, StageStatus
from .store import SimpleCheckpointStore, SurfaceExplorationProgressRecord
from .surface_coverage_v2 import _child_reasons, _ref, _related_child_ids
from .surface_coverage_v3 import _bound_ref, _read_object
from .surface_coverage_v5 import (
    SurfaceCoverageV5,
    _completed_inconclusive_child,
    _pending_counts,
)
from .surface_coverage_v5 import (
    _frozen_parent_v5_from_json as _frozen_parent_v5_from_json,
)
from .surface_coverage_v5 import read_frozen_parent_v5 as read_frozen_parent_v5
from .surface_enrichment_v8 import (
    V8ValidatedResponse,
    prepare_surface_enrichment_v8,
    validate_v8_response,
)
from .surface_enrichment_v8_bindings import (
    missing_v7_part_set,
    prior_v7_progress_snapshot_hash,
)

_MAX_OBJECT = 8 * 1024 * 1024
_SUPERSEDED_REASONS = frozenset(
    {
        "CONNECTED_ROLE_PROOF_MISSING",
        "SURFACE_EVIDENCE_INSUFFICIENT",
        "SURFACE_SOURCE_UNAVAILABLE",
        "SURFACE_PART_PENDING",
        "UNREVIEWED_RELEVANT_PATH",
        "UNRESOLVED_RELEVANT_GRAPH_GAP",
        "INHERITED_GRAPH_SEMANTICS_UNVERIFIED",
    }
)
_CHILD_REASONS = frozenset({"CHILD_HOLD", "CHILD_PENDING", "CHILD_STALE"})


@dataclass(frozen=True, slots=True)
class SurfaceProofV6:
    surface_id: str
    path: str
    line: int
    coverage_status: Literal["COVERED", "UNCOVERED", "INSUFFICIENT"]
    prior_v5_status: Literal["COVERED", "UNCOVERED", "INSUFFICIENT"]
    review_classification: str | None
    verified_roles: tuple[dict[str, object], ...]
    evidence_refs: tuple[StoredDataRef, ...]
    unresolved_reason_codes: tuple[str, ...]
    completed_inconclusive_children: tuple[dict[str, object], ...]

    def to_json(self) -> dict[str, object]:
        result: dict[str, object] = {
            "surface_id": self.surface_id,
            "path": self.path,
            "line": self.line,
            "coverage_status": self.coverage_status,
            "prior_v5_status": self.prior_v5_status,
            "review_classification": self.review_classification,
            "verified_roles": list(self.verified_roles),
            "evidence_refs": [
                ref.model_dump(mode="json") for ref in self.evidence_refs
            ],
            "unresolved_reason_codes": list(self.unresolved_reason_codes),
        }
        if self.completed_inconclusive_children:
            result["completed_inconclusive_children"] = list(
                self.completed_inconclusive_children
            )
        return result


@dataclass(frozen=True, slots=True)
class SurfaceCoverageV6:
    scope_fingerprint: str
    static_bundle_hash: str
    ast_manifest_hash: str
    candidate_inventory_hash: str
    candidate_count: int
    index_hash: str
    original_coverage_ref: StoredDataRef
    scope_certificate_ref: StoredDataRef
    prior_v5_ref: StoredDataRef
    prior_v7_plan_ref: StoredDataRef
    v8_plan_ref: StoredDataRef
    prior_progress_hash: str
    missing_v7_parts: tuple[dict[str, str], ...]
    raw_static_gaps: tuple[dict[str, object], ...]
    effective_python_gaps: tuple[dict[str, object], ...]
    surfaces: tuple[SurfaceProofV6, ...]
    pending_candidate_count: int
    pending_child_count: int

    @property
    def complete(self) -> bool:
        return (
            not self.effective_python_gaps
            and not self.missing_v7_parts
            and self.pending_candidate_count == 0
            and self.pending_child_count == 0
            and bool(self.surfaces)
            and all(row.coverage_status == "COVERED" for row in self.surfaces)
        )

    def to_json(self) -> dict[str, object]:
        return {
            "kind": "simple_attack_surface_coverage_v6",
            "scope_fingerprint": self.scope_fingerprint,
            "static_bundle_hash": self.static_bundle_hash,
            "ast_manifest_hash": self.ast_manifest_hash,
            "candidate_inventory_hash": self.candidate_inventory_hash,
            "candidate_count": self.candidate_count,
            "index_hash": self.index_hash,
            "original_coverage_ref": self.original_coverage_ref.model_dump(mode="json"),
            "scope_certificate_ref": self.scope_certificate_ref.model_dump(mode="json"),
            "scope_certificate_hash": self.scope_certificate_ref.content_hash,
            "prior_v5_ref": self.prior_v5_ref.model_dump(mode="json"),
            "prior_v7_plan_ref": self.prior_v7_plan_ref.model_dump(mode="json"),
            "v8_plan_ref": self.v8_plan_ref.model_dump(mode="json"),
            "prior_progress_hash": self.prior_progress_hash,
            "missing_v7_parts": list(self.missing_v7_parts),
            "raw_static_gaps": list(self.raw_static_gaps),
            "effective_python_gaps": list(self.effective_python_gaps),
            "surfaces": [row.to_json() for row in self.surfaces],
            "pending_candidate_count": self.pending_candidate_count,
            "pending_child_count": self.pending_child_count,
            "complete": self.complete,
        }


def surface_coverage_v6_from_json(value: object) -> SurfaceCoverageV6:
    """Read an immutable v8 certificate without reinterpreting successor rows.

    This parser authenticates the canonical saved shape. Its caller must still
    bind the content-addressed ref and the v8 progress snapshot before use.
    """

    invalid = "SURFACE_COVERAGE_V6_SAVED_INVALID"
    try:
        if (
            not isinstance(value, dict)
            or value.get("kind") != "simple_attack_surface_coverage_v6"
        ):
            raise ValueError(invalid)
        raw_surfaces = value["surfaces"]
        if not isinstance(raw_surfaces, list) or not raw_surfaces:
            raise ValueError(invalid)
        surfaces: list[SurfaceProofV6] = []
        for raw in raw_surfaces:
            if not isinstance(raw, dict):
                raise ValueError(invalid)
            if raw["coverage_status"] not in {
                "COVERED",
                "UNCOVERED",
                "INSUFFICIENT",
            } or raw["prior_v5_status"] not in {"COVERED", "UNCOVERED", "INSUFFICIENT"}:
                raise ValueError(invalid)
            surfaces.append(
                SurfaceProofV6(
                    surface_id=raw["surface_id"],
                    path=raw["path"],
                    line=raw["line"],
                    coverage_status=raw["coverage_status"],
                    prior_v5_status=raw["prior_v5_status"],
                    review_classification=raw["review_classification"],
                    verified_roles=tuple(raw["verified_roles"]),
                    evidence_refs=tuple(
                        StoredDataRef.model_validate(ref)
                        for ref in raw["evidence_refs"]
                    ),
                    unresolved_reason_codes=tuple(raw["unresolved_reason_codes"]),
                    completed_inconclusive_children=tuple(
                        raw.get("completed_inconclusive_children", ())
                    ),
                )
            )
        if any(
            type(value[key]) is not int or value[key] < 0
            for key in (
                "candidate_count",
                "pending_candidate_count",
                "pending_child_count",
            )
        ):
            raise ValueError(invalid)
        coverage = SurfaceCoverageV6(
            scope_fingerprint=value["scope_fingerprint"],
            static_bundle_hash=value["static_bundle_hash"],
            ast_manifest_hash=value["ast_manifest_hash"],
            candidate_inventory_hash=value["candidate_inventory_hash"],
            candidate_count=value["candidate_count"],
            index_hash=value["index_hash"],
            original_coverage_ref=StoredDataRef.model_validate(
                value["original_coverage_ref"]
            ),
            scope_certificate_ref=StoredDataRef.model_validate(
                value["scope_certificate_ref"]
            ),
            prior_v5_ref=StoredDataRef.model_validate(value["prior_v5_ref"]),
            prior_v7_plan_ref=StoredDataRef.model_validate(value["prior_v7_plan_ref"]),
            v8_plan_ref=StoredDataRef.model_validate(value["v8_plan_ref"]),
            prior_progress_hash=value["prior_progress_hash"],
            missing_v7_parts=tuple(value["missing_v7_parts"]),
            raw_static_gaps=tuple(value["raw_static_gaps"]),
            effective_python_gaps=tuple(value["effective_python_gaps"]),
            surfaces=tuple(surfaces),
            pending_candidate_count=value["pending_candidate_count"],
            pending_child_count=value["pending_child_count"],
        )
        if coverage.to_json() != value:
            raise ValueError(invalid)
        return coverage
    except (KeyError, TypeError, ValueError, UnicodeError) as error:
        raise ValueError(invalid) from error


def _relevant_anchor_path_ids(
    graph: Mapping[str, object], surface_path: str, surface_line: int
) -> set[str]:
    """Retain each distinct entry-to-anchor alternative, even if unreviewable."""

    paths = graph.get("paths")
    if not isinstance(paths, list):
        raise ValueError("SURFACE_COVERAGE_V6_GRAPH_PATHS_INVALID")
    relevant: set[str] = set()
    for path in paths:
        if not isinstance(path, dict) or not isinstance(path.get("path_id"), str):
            raise ValueError("SURFACE_COVERAGE_V6_GRAPH_PATHS_INVALID")
        steps = path.get("steps")
        if not isinstance(steps, list) or any(not isinstance(s, dict) for s in steps):
            raise ValueError("SURFACE_COVERAGE_V6_GRAPH_PATHS_INVALID")
        if any(step.get("role") == "ROUTE_ENTRY" for step in steps) and any(
            (step.get("path"), step.get("line")) == (surface_path, surface_line)
            for step in steps
        ):
            relevant.add(path["path_id"])
    return relevant


def _target_reasons(
    inherited: set[str],
    *,
    relevant_paths: set[str],
    verified_paths: set[str],
    all_parts_present: bool,
    unavailable_items: bool,
    local_reviewed: bool,
    child_reasons: set[str],
) -> set[str]:
    """Only a complete exact route can supersede earlier graph uncertainty."""

    reasons = set(inherited)
    route_complete = (
        all_parts_present
        and not unavailable_items
        and bool(relevant_paths)
        and relevant_paths == verified_paths
    )
    if route_complete:
        reasons.difference_update(_SUPERSEDED_REASONS)
    else:
        if not all_parts_present:
            reasons.add("SURFACE_PART_PENDING")
        if unavailable_items:
            reasons.add("SURFACE_SOURCE_UNAVAILABLE")
        if relevant_paths.difference(verified_paths):
            reasons.add("UNREVIEWED_RELEVANT_PATH")
        if not verified_paths or not relevant_paths.issuperset(verified_paths):
            reasons.add(
                "LOCAL_ONLY_ATTACK_PATH_UNVERIFIED"
                if local_reviewed and not verified_paths
                else "CONNECTED_ROLE_PROOF_MISSING"
            )
    reasons.update(child_reasons)
    return reasons


def _usable_v8_path_id(checked: V8ValidatedResponse) -> str | None:
    """An insufficient outcome is not a completed role review."""

    return (
        checked.verified_path_id
        if checked.status in {"HYPOTHESES", "NO_HYPOTHESIS"}
        and checked.proof_level == "CONNECTED"
        else None
    )


def _validated_v8_part(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    index_ref: StoredDataRef,
    plan: Mapping[str, object],
    target: Mapping[str, object],
    expected: Mapping[str, object],
    row: SurfaceExplorationProgressRecord,
    artifacts: SimpleArtifactRepository,
) -> tuple[V8ValidatedResponse, tuple[StoredDataRef, ...]]:
    invalid = "SURFACE_COVERAGE_V6_PROGRESS_INVALID"
    try:
        if (
            row.proposal_version != 8
            or row.surface_id != expected.get("surface_id")
            or row.context_id != expected.get("context_id")
            or row.context_hash != expected.get("context_hash")
            or row.source_sha256 != expected.get("source_sha256")
            or row.static_bundle_hash != index.static_bundle_hash
            or row.index_hash != index_ref.content_hash
            or row.status
            not in {
                "HYPOTHESES",
                "NO_HYPOTHESIS",
                "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
            }
            or not _bound_ref(row.result_ref, identity)
        ):
            raise ValueError("progress mismatch")
        context_ref = _ref(identity, row.context_hash)
        graph_ref = _ref(identity, cast(str, target["graph_hash"]))
        context = _read_object(artifacts, context_ref, 64 * 1024)
        graph = _read_object(artifacts, graph_ref, _MAX_OBJECT)
        result = _read_object(artifacts, row.result_ref, 1024 * 1024)
        if (
            context.get("kind") != "simple_surface_context_v8"
            or context.get("analysis_id") != identity.analysis_id
            or context.get("workspace_id") != identity.workspace_id
            or context.get("commit_id") != identity.commit_id
            or context.get("scope") != plan.get("scope")
            or context.get("scope_fingerprint") != index.scope_fingerprint
            or context.get("static_bundle_hash") != index.static_bundle_hash
            or context.get("ast_manifest_hash") != index.ast_manifest_hash
            or context.get("surface_index_hash") != index_ref.content_hash
            or context.get("surface_id") != row.surface_id
            or context.get("graph_hash") != graph_ref.content_hash
            or context.get("graph_semantics_revision") != "v5-source-bound-5"
            or context.get("plan_binding_hash") != plan.get("plan_binding_hash")
            or context.get("prior_v7_plan_hash") != plan.get("prior_v7_plan_hash")
            or context.get("prior_v5_coverage_hash")
            != plan.get("prior_v5_coverage_hash")
            or context.get("prior_progress_hash") != plan.get("prior_progress_hash")
            or context.get("parent_progress_hash") != target.get("prior_v5_proof_hash")
            or context.get("anchor_contract") != expected.get("anchor_contract")
            or context.get("review_path_kind") != expected.get("review_path_kind")
            or context.get("target_path_id") != expected.get("target_path_id")
            or context.get("part_index") != expected.get("part_index")
            or context.get("part_count") != expected.get("part_count")
            or context.get("source_sha256") != expected.get("source_sha256")
            or result.get("kind") != "simple_surface_hypothesis_result_v8"
            or result.get("analysis_id") != identity.analysis_id
            or result.get("surface_id") != row.surface_id
            or result.get("context_id") != row.context_id
            or result.get("context_hash") != row.context_hash
            or result.get("part_index") != expected.get("part_index")
            or result.get("part_count") != expected.get("part_count")
            or result.get("static_bundle_hash") != index.static_bundle_hash
            or result.get("graph_ref") != graph_ref.model_dump(mode="json")
            or result.get("graph_hash") != graph_ref.content_hash
            or result.get("status") != row.status
            or result.get("validation_status") != "VALID"
            or result.get("seed_ids") != list(row.hypothesis_ids)
            or not isinstance(result.get("response"), dict)
        ):
            raise ValueError("context or result mismatch")
        checked = validate_v8_response(
            {
                "context_payload": context,
                "graph_payload": graph,
                "context_hash": row.context_hash,
                "context_id": row.context_id,
            },
            cast(dict[str, object], result["response"]),
        )
        derived_ids = [
            "hypothesis-"
            + hashlib.sha256(
                row.surface_id.encode("utf-8")
                + row.context_id.encode("utf-8")
                + canonical_bytes(proposal)
            ).hexdigest()[:32]
            for proposal, _ in checked.qualified
        ]
        if (
            checked.status != row.status
            or checked.reason != result.get("reason")
            or list(checked.verified_roles) != result.get("verified_roles")
            or sorted(checked.reviewed_parts) != result.get("reviewed_parts")
            or list(checked.evidence_locations) != result.get("evidence_locations")
            or checked.verified_path_id != result.get("verified_path_id")
            or checked.proof_level != result.get("proof_level")
            or derived_ids != result.get("seed_ids")
            or (row.status == "HYPOTHESES") != bool(derived_ids)
        ):
            raise ValueError("response attestation mismatch")
        return checked, (context_ref, graph_ref, row.result_ref)
    except (
        KeyError,
        IndexError,
        OSError,
        TypeError,
        ValueError,
        UnicodeError,
    ) as error:
        raise ValueError(invalid) from error


def evaluate_surface_coverage_v6(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    index_ref: StoredDataRef,
    parent_v5_ref: StoredDataRef,
    parent_v5: SurfaceCoverageV5,
    v7_plan_ref: StoredDataRef,
    v7_plan: Mapping[str, object],
    v8_plan_ref: StoredDataRef,
    v8_plan: Mapping[str, object],
    progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord],
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
) -> SurfaceCoverageV6:
    """Certify role-aware route coverage without changing the old v7 proof."""

    invalid = "SURFACE_COVERAGE_V6_PLAN_INVALID"
    try:
        if identity != artifacts.identity or identity.hypothesis_id is not None:
            raise ValueError("identity mismatch")
        for ref, value in (
            (index_ref, index.to_json()),
            (parent_v5_ref, parent_v5.to_json()),
            (v7_plan_ref, v7_plan),
            (v8_plan_ref, v8_plan),
        ):
            if (
                not _bound_ref(ref, identity)
                or _read_object(artifacts, ref, _MAX_OBJECT) != value
            ):
                raise ValueError("parent or plan changed")
        old_progress = {
            key: row for key, row in progress.items() if row.proposal_version <= 7
        }
        if (
            prior_v7_progress_snapshot_hash(old_progress)
            != v8_plan.get("prior_progress_hash")
            or missing_v7_part_set(v7_plan, old_progress)
            != v8_plan.get("missing_v7_parts")
            or v8_plan.get("missing_v7_parts") != []
            or v8_plan.get("prior_v7_plan_ref") != v7_plan_ref.model_dump(mode="json")
            or v8_plan.get("prior_v5_coverage_ref")
            != parent_v5_ref.model_dump(mode="json")
            or v8_plan.get("index_ref") != index_ref.model_dump(mode="json")
        ):
            raise ValueError("prior snapshot changed")
        raw_targets = v8_plan.get("targets")
        raw_parts = v8_plan.get("expected_parts")
        if (
            not isinstance(raw_targets, list)
            or not isinstance(raw_parts, list)
            or any(not isinstance(value, dict) for value in raw_targets + raw_parts)
        ):
            raise ValueError("v8 plan malformed")
        targets = cast(list[dict[str, object]], raw_targets)
        parts = cast(list[dict[str, object]], raw_parts)
        target_map = {cast(str, row["surface_id"]): row for row in targets}
        if len(target_map) != len(targets):
            raise ValueError("duplicate targets")
        graphs = {
            surface_id: _read_object(
                artifacts, _ref(identity, cast(str, row["graph_hash"])), _MAX_OBJECT
            )
            for surface_id, row in target_map.items()
        }
        reconstructed, _ = prepare_surface_enrichment_v8(
            identity,
            cast(str, v8_plan["scope"]),
            index,
            index_ref,
            v7_plan_ref,
            v7_plan,
            parent_v5_ref,
            parent_v5,
            old_progress,
            graphs,
            required_graph_revision="v5-source-bound-5",
        )
        if reconstructed != v8_plan:
            raise ValueError("v8 plan changed")
        expected = {
            (cast(str, part["surface_id"]), cast(str, part["context_id"])): part
            for part in parts
        }
        if len(expected) != len(parts) or any(
            key != (row.surface_id, row.context_id) for key, row in progress.items()
        ):
            raise ValueError("part key changed")
        v8_rows = {
            key: row for key, row in progress.items() if row.proposal_version == 8
        }
        if any(key not in expected for key in v8_rows) or any(
            row.proposal_version > 8 for row in progress.values()
        ):
            raise ValueError("extra progress")
        if len(parent_v5.surfaces) != len(index.surfaces):
            raise ValueError("parent surface set changed")
        proofs: list[SurfaceProofV6] = []
        for surface, old in zip(index.surfaces, parent_v5.surfaces, strict=True):
            if (old.surface_id, old.path, old.line) != (
                surface.surface_id,
                surface.path,
                surface.line,
            ):
                raise ValueError("parent surface changed")
            reasons = set(old.unresolved_reason_codes)
            roles = list(old.verified_roles)
            refs = list(old.evidence_refs)
            classification = old.review_classification
            completed = list(old.completed_inconclusive_children)
            contract = surface_review_contract(surface.type)
            if contract in {"SOURCE", "CONTROL"}:
                target = target_map[surface.surface_id]
                surface_parts = [
                    part for part in parts if part["surface_id"] == surface.surface_id
                ]
                all_present = all(
                    (surface.surface_id, cast(str, part["context_id"])) in v8_rows
                    for part in surface_parts
                )
                verified_paths: set[str] = set()
                local_reviewed = False
                for part in surface_parts:
                    row = v8_rows.get(
                        (surface.surface_id, cast(str, part["context_id"]))
                    )
                    if row is None:
                        continue
                    checked, checked_refs = _validated_v8_part(
                        identity,
                        index,
                        index_ref,
                        v8_plan,
                        target,
                        part,
                        row,
                        artifacts,
                    )
                    roles.extend(checked.verified_roles)
                    refs.extend(checked_refs)
                    classification = checked.status
                    if (path_id := _usable_v8_path_id(checked)) is not None:
                        verified_paths.add(path_id)
                    elif checked.proof_level == "LOCAL_ONLY":
                        local_reviewed = True
                relevant_paths = _relevant_anchor_path_ids(
                    graphs[surface.surface_id], surface.path, surface.line
                )
                child_codes: set[str] = set()
                related = _related_child_ids(
                    identity, surface, progress, store, index.scope_fingerprint
                )
                old_child_ids = {
                    child_id
                    for row in old_progress.values()
                    if row.surface_id == surface.surface_id
                    for child_id in row.hypothesis_ids
                }
                if old_child_ids and old_child_ids.issubset(related):
                    reasons.difference_update(_CHILD_REASONS)
                for child_id in sorted(related):
                    child_reasons = _child_reasons(identity, child_id, store, artifacts)
                    if child_reasons == ("CHILD_HOLD",) and (
                        all_present
                        and relevant_paths == verified_paths
                        and bool(relevant_paths)
                        and not target.get("unavailable_items")
                    ):
                        done = _completed_inconclusive_child(
                            identity, child_id, store, artifacts
                        )
                        if done is not None:
                            if done not in completed:
                                completed.append(done)
                            continue
                    child_codes.update(child_reasons)
                if "CHILD_ERROR" in child_codes:
                    raise ValueError("child failed")
                reasons = _target_reasons(
                    reasons,
                    relevant_paths=relevant_paths,
                    verified_paths=verified_paths,
                    all_parts_present=all_present,
                    unavailable_items=bool(target.get("unavailable_items")),
                    local_reviewed=local_reviewed,
                    child_reasons=child_codes,
                )
                status: Literal["COVERED", "UNCOVERED", "INSUFFICIENT"] = (
                    "COVERED" if not reasons else "INSUFFICIENT"
                )
            else:
                if contract == "UNKNOWN":
                    reasons.add("UNKNOWN_SURFACE_ROLE_UNVERIFIED")
                status = old.coverage_status if not reasons else "INSUFFICIENT"
            proofs.append(
                SurfaceProofV6(
                    surface_id=old.surface_id,
                    path=old.path,
                    line=old.line,
                    coverage_status=status,
                    prior_v5_status=old.coverage_status,
                    review_classification=classification,
                    verified_roles=tuple(roles),
                    evidence_refs=tuple(dict.fromkeys(refs)),
                    unresolved_reason_codes=tuple(sorted(reasons)),
                    completed_inconclusive_children=tuple(completed),
                )
            )
        pending_candidates, pending_children = _pending_counts(identity, index, store)
        return SurfaceCoverageV6(
            scope_fingerprint=parent_v5.scope_fingerprint,
            static_bundle_hash=parent_v5.static_bundle_hash,
            ast_manifest_hash=parent_v5.ast_manifest_hash,
            candidate_inventory_hash=parent_v5.candidate_inventory_hash,
            candidate_count=parent_v5.candidate_count,
            index_hash=parent_v5.index_hash,
            original_coverage_ref=parent_v5.original_coverage_ref,
            scope_certificate_ref=parent_v5.scope_certificate_ref,
            prior_v5_ref=parent_v5_ref,
            prior_v7_plan_ref=v7_plan_ref,
            v8_plan_ref=v8_plan_ref,
            prior_progress_hash=cast(str, v8_plan["prior_progress_hash"]),
            missing_v7_parts=tuple(
                cast(list[dict[str, str]], v8_plan["missing_v7_parts"])
            ),
            raw_static_gaps=parent_v5.raw_static_gaps,
            effective_python_gaps=parent_v5.effective_python_gaps,
            surfaces=tuple(proofs),
            pending_candidate_count=pending_candidates,
            pending_child_count=pending_children,
        )
    except (
        KeyError,
        IndexError,
        OSError,
        TypeError,
        ValueError,
        UnicodeError,
    ) as error:
        raise ValueError(invalid) from error


def verified_saved_coverage_v6(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    coverage_ref: StoredDataRef,
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
) -> SurfaceCoverageV6:
    """Recompute and compare the saved proof with the bound v8 terminal."""

    invalid = "SURFACE_COVERAGE_V6_VERIFIED_INVALID"
    try:
        run = store.require_analysis_run(identity.analysis_id)
        terminal = run.candidate_terminal
        v8_ref = run.surface_enrichment_v8_plan_ref
        v7_ref = run.surface_enrichment_v7_plan_ref
        root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
        if (
            terminal is None
            or terminal.surface_proof_version != 6
            or terminal.surface_coverage_hash != coverage_ref.content_hash
            or v8_ref is None
            or v7_ref is None
            or root is None
            or root.status is not StageStatus.SUCCEEDED
            or len(root.output_refs) != 2
            or root.output_refs[1] != coverage_ref
        ):
            raise ValueError("v8 terminal unbound")
        plan = _read_object(artifacts, v8_ref, _MAX_OBJECT)
        prior_plan = _read_object(artifacts, v7_ref, _MAX_OBJECT)
        index_ref = StoredDataRef.model_validate(plan["index_ref"])
        parent_ref = StoredDataRef.model_validate(plan["prior_v5_coverage_ref"])
        progress = store.list_surface_exploration_progress(
            identity, index.scope_fingerprint
        )
        parent = read_frozen_parent_v5(
            identity, index, parent_ref, v7_ref, prior_plan, progress, store, artifacts
        )
        current = evaluate_surface_coverage_v6(
            identity,
            index,
            index_ref,
            parent_ref,
            parent,
            v7_ref,
            prior_plan,
            v8_ref,
            plan,
            progress,
            store,
            artifacts,
        )
        counts = {
            status: sum(row.coverage_status == status for row in current.surfaces)
            for status in ("COVERED", "UNCOVERED", "INSUFFICIENT")
        }
        if (
            _read_object(artifacts, coverage_ref, _MAX_OBJECT) != current.to_json()
            or terminal.status != ("COMPLETE" if current.complete else "PARTIAL")
            or terminal.surface_counts != counts
            or terminal.pending_child_count != current.pending_child_count
            or terminal.scope_certificate_hash
            != current.scope_certificate_ref.content_hash
            or terminal.surface_index_hash != current.index_hash
            or root.output_refs[0] != index_ref
        ):
            raise ValueError("v8 terminal differs from proof")
        return current
    except (
        KeyError,
        IndexError,
        OSError,
        TypeError,
        ValueError,
        UnicodeError,
    ) as error:
        raise ValueError(invalid) from error
