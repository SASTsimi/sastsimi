"""Additive coverage certificate over an immutable v3 proof and v6 review.

This reader never reinterprets old v5 graphs. New coverage comes only from
fresh, source-bound v6 result parts and the current verified child outcome.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .attack_surfaces import SurfaceIndex
from .models import CheckpointIdentity
from .store import SimpleCheckpointStore, SurfaceExplorationProgressRecord
from .surface_coverage_v2 import _child_reasons, _ref, _related_child_ids
from .surface_coverage_v3 import (
    SurfaceCoverageV3,
    _bound_ref,
    _read_object,
    _validated_v5_part,
    read_saved_coverage_v3,
)
from .surface_enrichment_v5 import _prior_rows
from .surface_enrichment_v6 import prepare_surface_enrichment_v6
from .surface_evidence_validation_v5 import validate_v5_response

_GRAPH_REVISION = "v5-source-bound-3"
_GRAPH_REASONS = frozenset(
    {
        "CONNECTED_ROLE_PROOF_MISSING",
        "SURFACE_EVIDENCE_INSUFFICIENT",
        "SURFACE_SOURCE_UNAVAILABLE",
        "SURFACE_PART_PENDING",
    }
)
_CHILD_REASONS = frozenset({"CHILD_HOLD"})
_MAX_OBJECT = 8 * 1024 * 1024


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class SurfaceProofV4:
    surface_id: str
    path: str
    line: int
    coverage_status: Literal["COVERED", "UNCOVERED", "INSUFFICIENT"]
    prior_v3_status: Literal["COVERED", "UNCOVERED", "INSUFFICIENT"]
    review_classification: str | None
    verified_roles: tuple[dict[str, object], ...]
    evidence_refs: tuple[StoredDataRef, ...]
    unresolved_reason_codes: tuple[str, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "surface_id": self.surface_id,
            "path": self.path,
            "line": self.line,
            "coverage_status": self.coverage_status,
            "prior_v3_status": self.prior_v3_status,
            "review_classification": self.review_classification,
            "verified_roles": list(self.verified_roles),
            "evidence_refs": [
                ref.model_dump(mode="json") for ref in self.evidence_refs
            ],
            "unresolved_reason_codes": list(self.unresolved_reason_codes),
        }


@dataclass(frozen=True, slots=True)
class SurfaceCoverageV4:
    scope_fingerprint: str
    static_bundle_hash: str
    ast_manifest_hash: str
    candidate_inventory_hash: str
    candidate_count: int
    index_hash: str
    original_coverage_ref: StoredDataRef
    scope_certificate_ref: StoredDataRef
    prior_v2_ref: StoredDataRef
    prior_v3_ref: StoredDataRef
    prior_v5_plan_ref: StoredDataRef
    v6_plan_ref: StoredDataRef
    raw_static_gaps: tuple[dict[str, object], ...]
    effective_python_gaps: tuple[dict[str, object], ...]
    surfaces: tuple[SurfaceProofV4, ...]
    pending_candidate_count: int
    pending_child_count: int

    @property
    def complete(self) -> bool:
        return (
            not self.effective_python_gaps
            and self.pending_candidate_count == 0
            and self.pending_child_count == 0
            and bool(self.surfaces)
            and all(row.coverage_status == "COVERED" for row in self.surfaces)
        )

    def to_json(self) -> dict[str, object]:
        return {
            "kind": "simple_attack_surface_coverage_v4",
            "scope_fingerprint": self.scope_fingerprint,
            "static_bundle_hash": self.static_bundle_hash,
            "ast_manifest_hash": self.ast_manifest_hash,
            "candidate_inventory_hash": self.candidate_inventory_hash,
            "candidate_count": self.candidate_count,
            "index_hash": self.index_hash,
            "original_coverage_ref": self.original_coverage_ref.model_dump(mode="json"),
            "scope_certificate_ref": self.scope_certificate_ref.model_dump(mode="json"),
            "scope_certificate_hash": self.scope_certificate_ref.content_hash,
            "prior_v2_ref": self.prior_v2_ref.model_dump(mode="json"),
            "prior_v3_ref": self.prior_v3_ref.model_dump(mode="json"),
            "prior_v5_plan_ref": self.prior_v5_plan_ref.model_dump(mode="json"),
            "v6_plan_ref": self.v6_plan_ref.model_dump(mode="json"),
            "raw_static_gaps": list(self.raw_static_gaps),
            "effective_python_gaps": list(self.effective_python_gaps),
            "surfaces": [row.to_json() for row in self.surfaces],
            "pending_candidate_count": self.pending_candidate_count,
            "pending_child_count": self.pending_child_count,
            "complete": self.complete,
        }


def _saved_prior(
    artifacts: SimpleArtifactRepository,
    index: SurfaceIndex,
    prior_v3_ref: StoredDataRef,
    prior_v5_plan_ref: StoredDataRef,
) -> SurfaceCoverageV3:
    plan = _read_object(artifacts, prior_v5_plan_ref, _MAX_OBJECT)
    prior_v2_ref = StoredDataRef.model_validate(plan["v2_coverage_ref"])
    return read_saved_coverage_v3(
        artifacts,
        index,
        prior_v3_ref,
        prior_v2_ref=prior_v2_ref,
        v5_plan_ref=prior_v5_plan_ref,
    )


def read_saved_coverage_v4(
    artifacts: SimpleArtifactRepository,
    index: SurfaceIndex,
    coverage_ref: StoredDataRef,
    *,
    prior_v3_ref: StoredDataRef,
    prior_v5_plan_ref: StoredDataRef,
    v6_plan_ref: StoredDataRef,
) -> SurfaceCoverageV4:
    """Read exact successor bytes against caller-pinned predecessor refs."""

    invalid = "SURFACE_COVERAGE_V4_SAVED_INVALID"
    try:
        identity = artifacts.identity
        if not all(
            _bound_ref(ref, identity)
            for ref in (coverage_ref, prior_v3_ref, prior_v5_plan_ref, v6_plan_ref)
        ):
            raise ValueError("unbound v4 refs")
        prior = _saved_prior(artifacts, index, prior_v3_ref, prior_v5_plan_ref)
        plan = _read_object(artifacts, v6_plan_ref, _MAX_OBJECT)
        saved = _read_object(artifacts, coverage_ref, _MAX_OBJECT)
        index_ref = StoredDataRef.model_validate(plan["index_ref"])
        if (
            not _bound_ref(index_ref, identity)
            or _read_object(artifacts, index_ref, _MAX_OBJECT) != index.to_json()
        ):
            raise ValueError("unbound successor index")
        old_plan = _read_object(artifacts, prior_v5_plan_ref, _MAX_OBJECT)
        raw_targets = plan.get("targets")
        raw_parts = plan.get("expected_parts")
        if (
            not isinstance(raw_targets, list)
            or any(not isinstance(row, dict) for row in raw_targets)
            or not isinstance(raw_parts, list)
            or any(not isinstance(row, dict) for row in raw_parts)
        ):
            raise ValueError("invalid successor rows")
        target_rows = cast(list[dict[str, object]], raw_targets)
        part_rows = cast(list[dict[str, object]], raw_parts)
        target_map = {cast(str, row["surface_id"]): row for row in target_rows}
        graphs = {
            surface_id: _read_object(
                artifacts,
                _ref(identity, cast(str, row["graph_hash"])),
                _MAX_OBJECT,
            )
            for surface_id, row in target_map.items()
        }
        reconstructed, _ = prepare_surface_enrichment_v6(
            identity,
            cast(str, plan["scope"]),
            index,
            index_ref,
            prior_v3_ref,
            prior,
            prior_v5_plan_ref,
            old_plan,
            graphs,
            required_graph_revision=_GRAPH_REVISION,
        )
        if reconstructed != plan:
            raise ValueError("successor plan differs from reconstruction")
        targets = [
            row.surface_id
            for row in prior.surfaces
            if row.coverage_status == "INSUFFICIENT"
        ]
        if (
            plan.get("kind") != "simple_surface_enrichment_plan_v6"
            or plan.get("analysis_id") != identity.analysis_id
            or plan.get("workspace_id") != identity.workspace_id
            or plan.get("commit_id") != identity.commit_id
            or plan.get("graph_semantics_revision") != _GRAPH_REVISION
            or plan.get("index_hash") != prior.index_hash
            or plan.get("prior_v3_coverage_ref") != prior_v3_ref.model_dump(mode="json")
            or plan.get("prior_v3_coverage_hash") != prior_v3_ref.content_hash
            or plan.get("prior_v5_plan_ref")
            != prior_v5_plan_ref.model_dump(mode="json")
            or plan.get("prior_v5_plan_hash") != prior_v5_plan_ref.content_hash
            or plan.get("target_surface_ids") != targets
            or saved.get("kind") != "simple_attack_surface_coverage_v4"
            or saved.get("scope_fingerprint") != prior.scope_fingerprint
            or saved.get("static_bundle_hash") != prior.static_bundle_hash
            or saved.get("ast_manifest_hash") != prior.ast_manifest_hash
            or saved.get("candidate_inventory_hash") != prior.candidate_inventory_hash
            or saved.get("candidate_count") != prior.candidate_count
            or saved.get("index_hash") != prior.index_hash
            or saved.get("original_coverage_ref")
            != prior.original_coverage_ref.model_dump(mode="json")
            or saved.get("scope_certificate_ref")
            != prior.scope_certificate_ref.model_dump(mode="json")
            or saved.get("scope_certificate_hash")
            != prior.scope_certificate_ref.content_hash
            or saved.get("prior_v2_ref") != prior.prior_v2_ref.model_dump(mode="json")
            or saved.get("prior_v3_ref") != prior_v3_ref.model_dump(mode="json")
            or saved.get("prior_v5_plan_ref")
            != prior_v5_plan_ref.model_dump(mode="json")
            or saved.get("v6_plan_ref") != v6_plan_ref.model_dump(mode="json")
            or saved.get("raw_static_gaps") != list(prior.raw_static_gaps)
            or saved.get("effective_python_gaps") != list(prior.effective_python_gaps)
            or type(saved.get("pending_candidate_count")) is not int
            or type(saved.get("pending_child_count")) is not int
            or cast(int, saved["pending_candidate_count"]) < 0
            or cast(int, saved["pending_child_count"]) < 0
        ):
            raise ValueError("unbound v4 coverage header")
        rows = saved.get("surfaces")
        if not isinstance(rows, list) or len(rows) != len(index.surfaces):
            raise ValueError("invalid v4 surface count")
        proofs: list[SurfaceProofV4] = []
        for surface, old, raw in zip(index.surfaces, prior.surfaces, rows, strict=True):
            if (
                not isinstance(raw, dict)
                or set(raw)
                != {
                    "surface_id",
                    "path",
                    "line",
                    "coverage_status",
                    "prior_v3_status",
                    "review_classification",
                    "verified_roles",
                    "evidence_refs",
                    "unresolved_reason_codes",
                }
                or raw.get("surface_id") != surface.surface_id
                or raw.get("path") != surface.path
                or raw.get("line") != surface.line
                or raw.get("prior_v3_status") != old.coverage_status
                or raw.get("coverage_status")
                not in {"COVERED", "UNCOVERED", "INSUFFICIENT"}
                or raw.get("review_classification")
                not in {
                    None,
                    "HYPOTHESES",
                    "NO_HYPOTHESIS",
                    "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
                }
                or not isinstance(raw.get("verified_roles"), list)
                or any(not isinstance(role, dict) for role in raw["verified_roles"])
                or not isinstance(raw.get("evidence_refs"), list)
                or not isinstance(raw.get("unresolved_reason_codes"), list)
            ):
                raise ValueError("invalid v4 surface")
            reasons = raw["unresolved_reason_codes"]
            if (
                any(
                    not isinstance(reason, str)
                    or not reason
                    or len(reason) > 128
                    or any(ord(char) < 32 for char in reason)
                    for reason in reasons
                )
                or len(set(reasons)) != len(reasons)
                or (raw["coverage_status"] == "COVERED") == bool(reasons)
                or not set(old.unresolved_reason_codes)
                .difference(_GRAPH_REASONS | _CHILD_REASONS)
                .issubset(reasons)
            ):
                raise ValueError("invalid v4 reasons")
            refs = tuple(
                StoredDataRef.model_validate(value) for value in raw["evidence_refs"]
            )
            if (
                len(set(refs)) != len(refs)
                or any(not _bound_ref(ref, identity) for ref in refs)
                or not set(old.evidence_refs).issubset(refs)
                or any(role not in raw["verified_roles"] for role in old.verified_roles)
            ):
                raise ValueError("invalid v4 evidence")
            for ref in refs:
                artifacts.read_bounded(ref, _MAX_OBJECT)
            if old.coverage_status != "INSUFFICIENT":
                if (
                    raw["coverage_status"] != old.coverage_status
                    or raw["review_classification"] != old.review_classification
                    or raw["verified_roles"] != list(old.verified_roles)
                    or refs != old.evidence_refs
                    or reasons != list(old.unresolved_reason_codes)
                ):
                    raise ValueError("non-target v3 row changed")
            elif raw["coverage_status"] == "UNCOVERED":
                raise ValueError("insufficient v3 row became uncovered")
            if (
                old.coverage_status == "INSUFFICIENT"
                and raw["coverage_status"] == "COVERED"
            ):
                selected = [
                    item for item in part_rows if item["surface_id"] == old.surface_id
                ]
                if not selected:
                    raise ValueError("covered v4 row lacks successor parts")
                connected = False
                for item in selected:
                    context_ref = _ref(identity, cast(str, item["context_hash"]))
                    if context_ref not in refs:
                        raise ValueError("covered v4 row lacks successor context")
                    candidates: list[tuple[StoredDataRef, dict[str, object]]] = []
                    for ref in refs:
                        if ref in old.evidence_refs:
                            continue
                        try:
                            result = _read_object(artifacts, ref, 1024 * 1024)
                        except (OSError, ValueError, UnicodeError):
                            continue
                        if (
                            result.get("kind") == "simple_surface_hypothesis_result_v6"
                            and result.get("context_id") == item["context_id"]
                        ):
                            candidates.append((ref, result))
                    if len(candidates) != 1:
                        raise ValueError("covered v4 row lacks exact successor result")
                    result_ref, result = candidates[0]
                    seeds = result.get("seed_ids")
                    if not isinstance(seeds, list) or any(
                        not isinstance(seed, str) for seed in seeds
                    ):
                        raise ValueError("invalid successor seed IDs")
                    record = SurfaceExplorationProgressRecord(
                        surface_id=old.surface_id,
                        context_id=cast(str, item["context_id"]),
                        static_bundle_hash=index.static_bundle_hash,
                        index_hash=index_ref.content_hash,
                        context_hash=cast(str, item["context_hash"]),
                        source_sha256=cast(str | None, item["source_sha256"]),
                        status=cast(str, result["status"]),
                        result_ref=result_ref,
                        hypothesis_ids=tuple(cast(list[str], seeds)),
                        proposal_version=6,
                    )
                    _, required_refs, path_id, _ = _validated_v6_part(
                        identity,
                        index,
                        index_ref.content_hash,
                        plan,
                        target_map[old.surface_id],
                        item,
                        record,
                        artifacts,
                    )
                    if not set(required_refs).issubset(refs):
                        raise ValueError("successor evidence refs missing")
                    connected |= path_id is not None
                if not connected:
                    raise ValueError("covered v4 row lacks connected source proof")
            proofs.append(
                SurfaceProofV4(
                    surface_id=surface.surface_id,
                    path=surface.path,
                    line=surface.line,
                    coverage_status=cast(
                        Literal["COVERED", "UNCOVERED", "INSUFFICIENT"],
                        raw["coverage_status"],
                    ),
                    prior_v3_status=old.coverage_status,
                    review_classification=cast(
                        str | None, raw["review_classification"]
                    ),
                    verified_roles=tuple(
                        cast(list[dict[str, object]], raw["verified_roles"])
                    ),
                    evidence_refs=refs,
                    unresolved_reason_codes=tuple(cast(list[str], reasons)),
                )
            )
        coverage = SurfaceCoverageV4(
            scope_fingerprint=prior.scope_fingerprint,
            static_bundle_hash=prior.static_bundle_hash,
            ast_manifest_hash=prior.ast_manifest_hash,
            candidate_inventory_hash=prior.candidate_inventory_hash,
            candidate_count=prior.candidate_count,
            index_hash=prior.index_hash,
            original_coverage_ref=prior.original_coverage_ref,
            scope_certificate_ref=prior.scope_certificate_ref,
            prior_v2_ref=prior.prior_v2_ref,
            prior_v3_ref=prior_v3_ref,
            prior_v5_plan_ref=prior_v5_plan_ref,
            v6_plan_ref=v6_plan_ref,
            raw_static_gaps=prior.raw_static_gaps,
            effective_python_gaps=prior.effective_python_gaps,
            surfaces=tuple(proofs),
            pending_candidate_count=cast(int, saved["pending_candidate_count"]),
            pending_child_count=cast(int, saved["pending_child_count"]),
        )
        if saved != coverage.to_json():
            raise ValueError("saved v4 payload is not exact")
        return coverage
    except (
        KeyError,
        IndexError,
        OSError,
        TypeError,
        ValueError,
        UnicodeError,
    ) as error:
        raise ValueError(invalid) from error


def _validated_v6_part(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    index_hash: str,
    plan: Mapping[str, object],
    target: Mapping[str, object],
    expected: Mapping[str, object],
    record: SurfaceExplorationProgressRecord,
    artifacts: SimpleArtifactRepository,
) -> tuple[tuple[dict[str, object], ...], tuple[StoredDataRef, ...], str | None, str]:
    invalid = "SURFACE_COVERAGE_V4_PROGRESS_INVALID"
    surface_id = cast(str, expected["surface_id"])
    surface = next(row for row in index.surfaces if row.surface_id == surface_id)
    if (
        record.proposal_version != 6
        or record.surface_id != surface_id
        or record.context_id != expected.get("context_id")
        or record.context_hash != expected.get("context_hash")
        or record.static_bundle_hash != index.static_bundle_hash
        or record.index_hash != index_hash
        or record.source_sha256 != expected.get("source_sha256")
        or record.status
        not in {
            "HYPOTHESES",
            "NO_HYPOTHESIS",
            "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
        }
        or not _bound_ref(record.result_ref, identity)
    ):
        raise ValueError(invalid)
    context_ref = _ref(identity, record.context_hash)
    context = _read_object(artifacts, context_ref, 64 * 1024)
    if (
        context.get("kind") != "simple_surface_context_v5"
        or context.get("analysis_id") != identity.analysis_id
        or context.get("workspace_id") != identity.workspace_id
        or context.get("commit_id") != identity.commit_id
        or context.get("scope") != plan.get("scope")
        or context.get("scope_fingerprint") != index.scope_fingerprint
        or context.get("static_bundle_hash") != index.static_bundle_hash
        or context.get("ast_manifest_hash") != index.ast_manifest_hash
        or context.get("surface_index_hash") != index_hash
        or context.get("surface_id") != surface_id
        or context.get("path") != surface.path
        or context.get("line") != surface.line
        or context.get("source_sha256") != expected.get("source_sha256")
        or context.get("graph_hash") != target.get("graph_hash")
        or context.get("graph_semantics_revision") != _GRAPH_REVISION
        or context.get("plan_binding_hash") != plan.get("plan_binding_hash")
        or context.get("parent_progress_hash") != target.get("parent_progress_hash")
        or context.get("prior_reasons") != target.get("prior_reasons")
        or context.get("prior_v3_coverage_hash") != plan.get("prior_v3_coverage_hash")
        or context.get("prior_v5_plan_hash") != plan.get("prior_v5_plan_hash")
        or context.get("v4_plan_hash") != plan.get("v4_plan_hash")
        or context.get("v2_coverage_hash") != plan.get("v2_coverage_hash")
        or context.get("child_checkpoint_hash")
        != _digest(plan.get("child_checkpoint_hashes"))
        or context.get("part_index") != expected.get("part_index")
        or context.get("part_count") != expected.get("part_count")
        or context.get("unavailable_item_count")
        != len(cast(list[object], target.get("unavailable_items", [])))
    ):
        raise ValueError(invalid)
    graph_ref = _ref(identity, cast(str, target["graph_hash"]))
    graph = _read_object(artifacts, graph_ref, _MAX_OBJECT)
    result = _read_object(artifacts, record.result_ref, 1024 * 1024)
    if (
        result.get("kind") != "simple_surface_hypothesis_result_v6"
        or result.get("analysis_id") != identity.analysis_id
        or result.get("surface_id") != surface_id
        or result.get("context_id") != record.context_id
        or result.get("context_hash") != record.context_hash
        or result.get("part_index") != expected.get("part_index")
        or result.get("part_count") != expected.get("part_count")
        or result.get("static_bundle_hash") != index.static_bundle_hash
        or result.get("graph_ref") != graph_ref.model_dump(mode="json")
        or result.get("graph_hash") != graph_ref.content_hash
        or result.get("status") != record.status
        or result.get("validation_status") != "VALID"
        or result.get("seed_ids") != list(record.hypothesis_ids)
        or not isinstance(result.get("response"), dict)
    ):
        raise ValueError(invalid)
    checked = validate_v5_response(
        {
            "context_payload": context,
            "graph_payload": graph,
            "context_hash": record.context_hash,
            "context_id": record.context_id,
        },
        cast(dict[str, object], result["response"]),
    )
    derived_ids = [
        "hypothesis-"
        + hashlib.sha256(
            surface_id.encode("utf-8")
            + record.context_id.encode("utf-8")
            + canonical_bytes(proposal)
        ).hexdigest()[:32]
        for proposal, _ in checked.qualified
    ]
    if (
        checked.status != record.status
        or checked.reason != result.get("reason")
        or list(checked.verified_roles) != result.get("verified_roles")
        or sorted(checked.reviewed_parts) != result.get("reviewed_parts")
        or list(checked.evidence_locations) != result.get("evidence_locations")
        or checked.verified_path_id != result.get("verified_path_id")
        or derived_ids != result.get("seed_ids")
        or (record.status == "HYPOTHESES") != bool(derived_ids)
    ):
        raise ValueError(invalid)
    usable_path = (
        checked.verified_path_id
        if checked.status in {"HYPOTHESES", "NO_HYPOTHESIS"}
        and graph.get("proof_semantics_revision") == _GRAPH_REVISION
        and not target.get("unavailable_items")
        and context.get("unavailable_item_count") == 0
        else None
    )
    return (
        checked.verified_roles,
        (context_ref, graph_ref, record.result_ref),
        usable_path,
        checked.status,
    )


def _validated_old_rows(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    prior: SurfaceCoverageV3,
    old_plan: Mapping[str, object],
    progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord],
    artifacts: SimpleArtifactRepository,
) -> dict[str, set[str]]:
    """A successor cannot hide or relabel an old reviewed v5 part."""

    targets = old_plan.get("targets")
    parts = old_plan.get("expected_parts")
    if not isinstance(targets, list) or not isinstance(parts, list):
        raise ValueError("invalid predecessor plan")
    target_map = {
        cast(str, row["surface_id"]): row for row in targets if isinstance(row, dict)
    }
    expected: dict[tuple[str, str], dict[str, object]] = {}
    for raw in parts:
        if not isinstance(raw, dict):
            raise ValueError("invalid predecessor part")
        key = (cast(str, raw["surface_id"]), cast(str, raw["context_id"]))
        if key in expected:
            raise ValueError("duplicate predecessor part")
        expected[key] = raw
    proofs = {row.surface_id: row for row in prior.surfaces}
    child_ids: dict[str, set[str]] = {}
    for key, raw in expected.items():
        row = progress.get(key)
        context_ref = _ref(identity, cast(str, raw["context_hash"]))
        prior_refs = proofs[key[0]].evidence_refs
        if row is None:
            if context_ref in prior_refs:
                raise ValueError("reviewed predecessor part disappeared")
            continue
        if row.proposal_version != 5 or context_ref not in prior_refs:
            raise ValueError("new or changed predecessor part")
        target = target_map[key[0]]
        _, refs, _, _ = _validated_v5_part(
            identity,
            index,
            prior.index_hash,
            old_plan,
            key[0],
            target,
            raw,
            row,
            artifacts,
        )
        if not set(refs).issubset(prior_refs):
            raise ValueError("predecessor evidence regressed")
        child_ids.setdefault(key[0], set()).update(row.hypothesis_ids)
    if any(
        row.proposal_version == 5 and key not in expected
        for key, row in progress.items()
    ):
        raise ValueError("extra predecessor part")
    return child_ids


def _validated_pre_v5_rows(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    prior: SurfaceCoverageV3,
    old_plan: Mapping[str, object],
    progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord],
    artifacts: SimpleArtifactRepository,
) -> dict[str, set[str]]:
    """Rebind old child links to the exact rows pinned by the v5 parent."""

    targets = old_plan.get("targets")
    if not isinstance(targets, list) or any(
        not isinstance(row, dict) for row in targets
    ):
        raise ValueError("invalid predecessor targets")
    target_map = {
        cast(str, row["surface_id"]): row
        for row in targets
        if isinstance(row.get("surface_id"), str)
    }
    if len(target_map) != len(targets):
        raise ValueError("duplicate predecessor target")
    old_progress = {
        key: row
        for key, row in progress.items()
        if row.proposal_version in {1, 2, 3, 4}
    }
    children: dict[str, set[str]] = {}
    for proof in prior.surfaces:
        if proof.coverage_status != "INSUFFICIENT":
            continue
        target = target_map.get(proof.surface_id)
        if target is None or not isinstance(target.get("prior_progress"), list):
            raise ValueError("missing pinned predecessor progress")
        pinned = target["prior_progress"]
        current = _prior_rows(proof.surface_id, old_progress, index, prior.index_hash)
        if current != pinned:
            raise ValueError("predecessor progress changed")
        ids: set[str] = set()
        for row in current:
            ref = StoredDataRef.model_validate(row["result_ref"])
            if not _bound_ref(ref, identity):
                raise ValueError("unbound predecessor result")
            artifacts.read(ref)
            artifacts.read(_ref(identity, cast(str, row["context_hash"])))
            ids.update(cast(list[str], row["hypothesis_ids"]))
        children[proof.surface_id] = ids
    return children


def validate_surface_plan_v6(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    prior_v3_ref: StoredDataRef,
    prior_v3: SurfaceCoverageV3,
    prior_v5_plan_ref: StoredDataRef,
    v6_plan_ref: StoredDataRef,
    plan_v6: Mapping[str, object],
    progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord],
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
) -> None:
    """Preflight immutable plan/progress before the child drain runs."""

    _evaluate_surface_coverage_v4(
        identity,
        index,
        prior_v3_ref,
        prior_v3,
        prior_v5_plan_ref,
        v6_plan_ref,
        plan_v6,
        progress,
        store,
        artifacts,
        plan_only=True,
    )


def evaluate_surface_coverage_v4(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    prior_v3_ref: StoredDataRef,
    prior_v3: SurfaceCoverageV3,
    prior_v5_plan_ref: StoredDataRef,
    v6_plan_ref: StoredDataRef,
    plan_v6: Mapping[str, object],
    progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord],
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
) -> SurfaceCoverageV4:
    """Certify only the v6 delta over exact saved v3 bytes."""

    coverage = _evaluate_surface_coverage_v4(
        identity,
        index,
        prior_v3_ref,
        prior_v3,
        prior_v5_plan_ref,
        v6_plan_ref,
        plan_v6,
        progress,
        store,
        artifacts,
        plan_only=False,
    )
    if coverage is None:
        raise ValueError("SURFACE_COVERAGE_V4_PLAN_INVALID")
    return coverage


def _evaluate_surface_coverage_v4(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    prior_v3_ref: StoredDataRef,
    prior_v3: SurfaceCoverageV3,
    prior_v5_plan_ref: StoredDataRef,
    v6_plan_ref: StoredDataRef,
    plan_v6: Mapping[str, object],
    progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord],
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
    *,
    plan_only: bool,
) -> SurfaceCoverageV4 | None:
    invalid = "SURFACE_COVERAGE_V4_PLAN_INVALID"
    try:
        if identity != artifacts.identity or identity.hypothesis_id is not None:
            raise ValueError("identity mismatch")
        run = store.require_analysis_run(identity.analysis_id)
        terminal = run.candidate_terminal
        index_ref = StoredDataRef.model_validate(plan_v6["index_ref"])
        if (
            terminal is None
            or terminal.surface_proof_version not in {3, 4}
            or run.workspace_id != identity.workspace_id
            or run.commit_id != identity.commit_id
            or run.surface_enrichment_v5_plan_ref != prior_v5_plan_ref
            or run.surface_enrichment_v6_plan_ref != v6_plan_ref
            or not all(
                _bound_ref(ref, identity)
                for ref in (index_ref, prior_v3_ref, prior_v5_plan_ref, v6_plan_ref)
            )
            or _read_object(artifacts, index_ref, _MAX_OBJECT) != index.to_json()
            or _read_object(artifacts, v6_plan_ref, _MAX_OBJECT) != plan_v6
            or _saved_prior(artifacts, index, prior_v3_ref, prior_v5_plan_ref)
            != prior_v3
            or plan_v6.get("kind") != "simple_surface_enrichment_plan_v6"
            or plan_v6.get("graph_semantics_revision") != _GRAPH_REVISION
            or plan_v6.get("index_hash") != index_ref.content_hash
            or plan_v6.get("prior_v3_coverage_ref")
            != prior_v3_ref.model_dump(mode="json")
            or plan_v6.get("prior_v3_coverage_hash") != prior_v3_ref.content_hash
            or plan_v6.get("prior_v5_plan_ref")
            != prior_v5_plan_ref.model_dump(mode="json")
            or plan_v6.get("prior_v5_plan_hash") != prior_v5_plan_ref.content_hash
            or terminal.bundle_hash != index.static_bundle_hash
            or terminal.scope_fingerprint != index.scope_fingerprint
            or terminal.surface_index_hash != index_ref.content_hash
            or terminal.scope_certificate_hash
            != prior_v3.scope_certificate_ref.content_hash
            or terminal.surface_proof_version == 3
            and terminal.surface_coverage_hash != prior_v3_ref.content_hash
            or run.python_scope_certificate_ref != prior_v3.scope_certificate_ref
            or run.static_bundle_ref is None
            or run.static_bundle_ref.content_hash != index.static_bundle_hash
        ):
            raise ValueError("unbound successor plan or prior")
        old_plan = _read_object(artifacts, prior_v5_plan_ref, _MAX_OBJECT)
        target_ids = [
            row.surface_id
            for row in prior_v3.surfaces
            if row.coverage_status == "INSUFFICIENT"
        ]
        raw_targets = plan_v6.get("targets")
        raw_parts = plan_v6.get("expected_parts")
        if (
            not target_ids
            or plan_v6.get("target_surface_ids") != target_ids
            or not isinstance(raw_targets, list)
            or not isinstance(raw_parts, list)
            or any(not isinstance(row, dict) for row in raw_targets)
            or any(not isinstance(row, dict) for row in raw_parts)
            or [row.get("surface_id") for row in raw_targets] != target_ids
        ):
            raise ValueError("invalid successor target list")
        targets = cast(list[dict[str, object]], raw_targets)
        parts = cast(list[dict[str, object]], raw_parts)
        target_map = {cast(str, row["surface_id"]): row for row in targets}
        graphs: dict[str, dict[str, object]] = {}
        for surface_id in target_ids:
            graph_hash = target_map[surface_id].get("graph_hash")
            if not isinstance(graph_hash, str) or len(graph_hash) != 64:
                raise ValueError("invalid successor graph hash")
            graphs[surface_id] = _read_object(
                artifacts, _ref(identity, graph_hash), _MAX_OBJECT
            )
        reconstructed, _ = prepare_surface_enrichment_v6(
            identity,
            cast(str, plan_v6["scope"]),
            index,
            index_ref,
            prior_v3_ref,
            prior_v3,
            prior_v5_plan_ref,
            old_plan,
            graphs,
            required_graph_revision=_GRAPH_REVISION,
        )
        if reconstructed != plan_v6:
            raise ValueError("saved successor plan differs from reconstruction")
        expected: dict[tuple[str, str], dict[str, object]] = {}
        for part in parts:
            key = (cast(str, part["surface_id"]), cast(str, part["context_id"]))
            if key in expected or key[0] not in target_map:
                raise ValueError("duplicate or unbound successor part")
            expected[key] = part
        if any(
            key != (row.surface_id, row.context_id) for key, row in progress.items()
        ):
            raise ValueError("malformed progress key")
        if any(
            row.proposal_version == 6
            and key not in expected
            or row.proposal_version > 6
            for key, row in progress.items()
        ):
            raise ValueError("extra unbound successor progress")
        pinned_children = _validated_pre_v5_rows(
            identity, index, prior_v3, old_plan, progress, artifacts
        )
        validated_v5_children = _validated_old_rows(
            identity, index, prior_v3, old_plan, progress, artifacts
        )
        for surface_id, ids in validated_v5_children.items():
            pinned_children.setdefault(surface_id, set()).update(ids)
        successor_rows = {
            key: row for key, row in progress.items() if row.proposal_version == 6
        }
        proofs: list[SurfaceProofV4] = []
        for surface, old in zip(index.surfaces, prior_v3.surfaces, strict=True):
            if old.surface_id not in target_map:
                proofs.append(
                    SurfaceProofV4(
                        surface_id=old.surface_id,
                        path=old.path,
                        line=old.line,
                        coverage_status=old.coverage_status,
                        prior_v3_status=old.coverage_status,
                        review_classification=old.review_classification,
                        verified_roles=old.verified_roles,
                        evidence_refs=old.evidence_refs,
                        unresolved_reason_codes=old.unresolved_reason_codes,
                    )
                )
                continue
            target = target_map[old.surface_id]
            surface_parts = [
                part for part in parts if part["surface_id"] == old.surface_id
            ]
            reasons = set(old.unresolved_reason_codes)
            roles = list(old.verified_roles)
            refs = list(old.evidence_refs)
            classification = old.review_classification
            connected = False
            all_present = all(
                (old.surface_id, cast(str, part["context_id"])) in successor_rows
                for part in surface_parts
            )
            for part in surface_parts:
                row = successor_rows.get(
                    (old.surface_id, cast(str, part["context_id"]))
                )
                if row is None:
                    reasons.add("SURFACE_PART_PENDING")
                    continue
                verified, part_refs, path_id, classification = _validated_v6_part(
                    identity,
                    index,
                    index_ref.content_hash,
                    plan_v6,
                    target,
                    part,
                    row,
                    artifacts,
                )
                roles.extend(verified)
                refs.extend(part_refs)
                connected |= path_id is not None
            if all_present and connected:
                reasons.difference_update(_GRAPH_REASONS)
            elif all_present:
                reasons.add("CONNECTED_ROLE_PROOF_MISSING")
            if target.get("unavailable_items"):
                reasons.add("SURFACE_SOURCE_UNAVAILABLE")
            if plan_only:
                continue
            related = _related_child_ids(
                identity, surface, progress, store, index.scope_fingerprint
            )
            old_child_ids = pinned_children.get(old.surface_id, set())
            can_clear_old_hold = (
                "CHILD_HOLD" not in old.unresolved_reason_codes
                or bool(old_child_ids)
                and not surface.linked_candidate_ids
                and old_child_ids.issubset(related)
            )
            if related and can_clear_old_hold:
                reasons.difference_update(_CHILD_REASONS)
            for child_id in related:
                reasons.update(_child_reasons(identity, child_id, store, artifacts))
            if "CHILD_ERROR" in reasons:
                raise ValueError("successor child error")
            status: Literal["COVERED", "UNCOVERED", "INSUFFICIENT"] = (
                "COVERED" if not reasons else "INSUFFICIENT"
            )
            proofs.append(
                SurfaceProofV4(
                    surface_id=old.surface_id,
                    path=old.path,
                    line=old.line,
                    coverage_status=status,
                    prior_v3_status=old.coverage_status,
                    review_classification=classification,
                    verified_roles=tuple(roles),
                    evidence_refs=tuple(dict.fromkeys(refs)),
                    unresolved_reason_codes=tuple(sorted(reasons)),
                )
            )
        if plan_only:
            return None
        counts = store.candidate_counts(identity, index.scope_fingerprint)
        deep = store.candidate_deep_counts(identity, index.scope_fingerprint)
        pending_candidates = (
            counts.get("PENDING", 0)
            + counts.get("ERROR", 0)
            + sum(deep.get(status, 0) for status in ("PENDING", "RUNNING", "ERROR"))
            + (0 if terminal.producer_finished else 1)
        )
        pending_children = 0
        after_id: str | None = None
        while True:
            page = store.list_incomplete_hypotheses(
                identity, after_id=after_id, limit=100
            )
            if not page:
                break
            if (
                len(page) > 100
                or tuple(sorted(set(page))) != page
                or after_id is not None
                and page[0] <= after_id
            ):
                raise ValueError("invalid successor pending child page")
            pending_children += len(page)
            if len(page) < 100:
                break
            after_id = page[-1]
        coverage = SurfaceCoverageV4(
            scope_fingerprint=prior_v3.scope_fingerprint,
            static_bundle_hash=prior_v3.static_bundle_hash,
            ast_manifest_hash=prior_v3.ast_manifest_hash,
            candidate_inventory_hash=prior_v3.candidate_inventory_hash,
            candidate_count=prior_v3.candidate_count,
            index_hash=prior_v3.index_hash,
            original_coverage_ref=prior_v3.original_coverage_ref,
            scope_certificate_ref=prior_v3.scope_certificate_ref,
            prior_v2_ref=prior_v3.prior_v2_ref,
            prior_v3_ref=prior_v3_ref,
            prior_v5_plan_ref=prior_v5_plan_ref,
            v6_plan_ref=v6_plan_ref,
            raw_static_gaps=prior_v3.raw_static_gaps,
            effective_python_gaps=prior_v3.effective_python_gaps,
            surfaces=tuple(proofs),
            pending_candidate_count=pending_candidates,
            pending_child_count=pending_children,
        )
        return coverage
    except (
        KeyError,
        IndexError,
        OSError,
        TypeError,
        ValueError,
        UnicodeError,
    ) as error:
        raise ValueError(invalid) from error


def verified_saved_coverage_v4(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    coverage_ref: StoredDataRef,
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
) -> SurfaceCoverageV4:
    """Compare saved terminal bytes to current v6 progress and child state."""

    invalid = "SURFACE_COVERAGE_V4_VERIFIED_INVALID"
    try:
        if identity != artifacts.identity or identity.hypothesis_id is not None:
            raise ValueError("identity mismatch")
        run = store.require_analysis_run(identity.analysis_id)
        terminal = run.candidate_terminal
        plan_ref = run.surface_enrichment_v6_plan_ref
        if (
            terminal is None
            or terminal.surface_proof_version != 4
            or terminal.surface_coverage_hash != coverage_ref.content_hash
            or plan_ref is None
            or not _bound_ref(plan_ref, identity)
        ):
            raise ValueError("v4 terminal missing or unbound")
        plan = _read_object(artifacts, plan_ref, _MAX_OBJECT)
        prior_v3_ref = StoredDataRef.model_validate(plan["prior_v3_coverage_ref"])
        prior_v5_plan_ref = StoredDataRef.model_validate(plan["prior_v5_plan_ref"])
        saved = read_saved_coverage_v4(
            artifacts,
            index,
            coverage_ref,
            prior_v3_ref=prior_v3_ref,
            prior_v5_plan_ref=prior_v5_plan_ref,
            v6_plan_ref=plan_ref,
        )
        counts = {
            status: sum(row.coverage_status == status for row in saved.surfaces)
            for status in ("COVERED", "UNCOVERED", "INSUFFICIENT")
        }
        if (
            terminal.status != ("COMPLETE" if saved.complete else "PARTIAL")
            or terminal.surface_counts != counts
            or terminal.pending_child_count != saved.pending_child_count
            or terminal.scope_certificate_hash
            != saved.scope_certificate_ref.content_hash
            or terminal.surface_index_hash != saved.index_hash
        ):
            raise ValueError("v4 terminal counts differ from proof")
        prior = _saved_prior(artifacts, index, prior_v3_ref, prior_v5_plan_ref)
        progress = store.list_surface_exploration_progress(
            identity, index.scope_fingerprint
        )
        current = evaluate_surface_coverage_v4(
            identity,
            index,
            prior_v3_ref,
            prior,
            prior_v5_plan_ref,
            plan_ref,
            plan,
            progress,
            store,
            artifacts,
        )
        if current != saved:
            raise ValueError("saved v4 certificate differs from current proof")
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
