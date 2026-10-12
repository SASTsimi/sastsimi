"""Additive v3 coverage proof over an exact saved v2 certificate and v5 review."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .attack_surfaces import SurfaceIndex
from .models import CheckpointIdentity
from .store import SimpleCheckpointStore, SurfaceExplorationProgressRecord
from .surface_coverage_v2 import (
    SurfaceCoverageV2,
    SurfaceProofV2,
    _child_reasons,
    _ref,
    _related_child_ids,
)
from .surface_enrichment_v5 import (
    _graph_items,
    _prior_rows,
    prepare_surface_enrichment_v5,
)
from .surface_evidence_validation_v5 import validate_v5_response

_V2_INVALID = "SURFACE_COVERAGE_V2_SAVED_INVALID"
_REPLACEABLE_GRAPH_REASONS = frozenset(
    {
        "CONNECTED_ROLE_PROOF_MISSING",
        "SURFACE_EVIDENCE_INSUFFICIENT",
        "SURFACE_SOURCE_UNAVAILABLE",
        "SURFACE_PART_PENDING",
    }
)
_REPLACEABLE_CHILD_REASONS = frozenset({"CHILD_HOLD"})


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _bound_ref(ref: StoredDataRef, identity: CheckpointIdentity) -> bool:
    return (
        ref.data_kind == "artifact"
        and ref.record_id is None
        and str(ref.stored_data_id) == ref.content_hash
        and str(ref.workspace_id) == identity.workspace_id
        and str(ref.commit_id) == identity.commit_id
    )


def _read_object(
    artifacts: SimpleArtifactRepository, ref: StoredDataRef, maximum: int
) -> dict[str, object]:
    raw = artifacts.read_bounded(ref, maximum)
    value = json.loads(raw)
    if (
        not isinstance(value, dict)
        or raw != canonical_bytes(value)
        or _digest(value) != ref.content_hash
    ):
        raise ValueError("noncanonical or unbound coverage object")
    return cast(dict[str, object], value)


def read_saved_coverage_v2(
    artifacts: SimpleArtifactRepository,
    index: SurfaceIndex,
    coverage_ref: StoredDataRef,
) -> SurfaceCoverageV2:
    """Read the saved v2 bytes exactly; never run the mutable v2 evaluator."""

    identity = artifacts.identity
    try:
        if (
            identity.hypothesis_id is not None
            or index.index_version != 2
            or index.workspace_id != identity.workspace_id
            or index.commit_id != identity.commit_id
            or not _bound_ref(coverage_ref, identity)
        ):
            raise ValueError("invalid v2 coverage scope")
        saved = _read_object(artifacts, coverage_ref, 8 * 1024 * 1024)
        if (
            saved.get("kind") != "simple_attack_surface_coverage_v2"
            or saved.get("scope_fingerprint") != index.scope_fingerprint
            or saved.get("static_bundle_hash") != index.static_bundle_hash
            or saved.get("ast_manifest_hash") != index.ast_manifest_hash
            or saved.get("candidate_inventory_hash") != index.candidate_inventory_hash
            or saved.get("candidate_count") != index.candidate_count
            or saved.get("index_hash") != _digest(index.to_json())
            or saved.get("raw_static_gaps") != index.to_json()["static_gaps"]
            or type(saved.get("pending_candidate_count")) is not int
            or cast(int, saved["pending_candidate_count"]) < 0
            or type(saved.get("pending_child_count")) is not int
            or cast(int, saved["pending_child_count"]) < 0
        ):
            raise ValueError("invalid saved v2 coverage header")
        original_ref = StoredDataRef.model_validate(saved["original_coverage_ref"])
        certificate_ref = StoredDataRef.model_validate(saved["scope_certificate_ref"])
        if (
            not _bound_ref(original_ref, identity)
            or not _bound_ref(certificate_ref, identity)
            or saved.get("scope_certificate_hash") != certificate_ref.content_hash
        ):
            raise ValueError("invalid saved v2 references")
        original = _read_object(artifacts, original_ref, 8 * 1024 * 1024)
        certificate = _read_object(artifacts, certificate_ref, 8 * 1024 * 1024)
        index_ref = StoredDataRef.model_validate(certificate["index_ref"])
        static_ref = StoredDataRef.model_validate(certificate["coverage_ref"])
        if (
            not _bound_ref(index_ref, identity)
            or not _bound_ref(static_ref, identity)
            or index_ref.content_hash != _digest(index.to_json())
            or _read_object(artifacts, index_ref, 8 * 1024 * 1024) != index.to_json()
            or certificate.get("kind") != "simple_python_scope_recertification_v1"
            or certificate.get("analysis_id") != identity.analysis_id
            or certificate.get("workspace_id") != identity.workspace_id
            or certificate.get("commit_id") != identity.commit_id
            or certificate.get("scope_fingerprint") != index.scope_fingerprint
            or certificate.get("index_hash") != index_ref.content_hash
            or certificate.get("raw_static_gaps") != index.to_json()["static_gaps"]
            or certificate.get("effective_static_gaps")
            != saved.get("effective_python_gaps")
            or original.get("kind") != "simple_attack_surface_coverage_v1"
            or original.get("scope_fingerprint") != index.scope_fingerprint
            or original.get("static_bundle_hash") != index.static_bundle_hash
            or original.get("ast_manifest_hash") != index.ast_manifest_hash
            or original.get("candidate_inventory_hash")
            != index.candidate_inventory_hash
            or original.get("candidate_count") != index.candidate_count
            or original.get("static_gaps") != index.to_json()["static_gaps"]
        ):
            raise ValueError("invalid saved v2 source certificates")
        static_coverage = _read_object(artifacts, static_ref, 8 * 1024 * 1024)
        if certificate.get("raw_coverage_gaps") != static_coverage.get(
            "gaps"
        ) or certificate.get("raw_out_of_scope_product_files") != static_coverage.get(
            "out_of_scope_product_files"
        ):
            raise ValueError("invalid saved v2 static coverage")
        original_rows = original.get("surfaces")
        rows = saved.get("surfaces")
        effective = saved.get("effective_python_gaps")
        if (
            not isinstance(original_rows, list)
            or len(original_rows) != len(index.surfaces)
            or not isinstance(rows, list)
            or len(rows) != len(index.surfaces)
            or not isinstance(effective, list)
            or any(
                not isinstance(gap, dict)
                or set(gap) != {"path", "rule_id", "reason", "engine"}
                or any(not isinstance(value, str) for value in gap.values())
                for gap in effective
            )
        ):
            raise ValueError("invalid saved v2 surface list")
        proofs: list[SurfaceProofV2] = []
        for surface, raw, original_row in zip(
            index.surfaces, rows, original_rows, strict=True
        ):
            if (
                not isinstance(raw, dict)
                or set(raw)
                != {
                    "surface_id",
                    "path",
                    "line",
                    "coverage_status",
                    "verified_roles",
                    "evidence_refs",
                    "unresolved_reason_codes",
                }
                or not isinstance(original_row, dict)
                or original_row.get("surface_id") != surface.surface_id
                or original_row.get("path") != surface.path
                or original_row.get("line") != surface.line
                or raw.get("surface_id") != surface.surface_id
                or raw.get("path") != surface.path
                or raw.get("line") != surface.line
                or raw.get("coverage_status")
                not in {"COVERED", "UNCOVERED", "INSUFFICIENT"}
                or not isinstance(raw.get("verified_roles"), list)
                or any(not isinstance(role, dict) for role in raw["verified_roles"])
                or not isinstance(raw.get("evidence_refs"), list)
                or not isinstance(raw.get("unresolved_reason_codes"), list)
            ):
                raise ValueError("invalid saved v2 surface")
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
            ):
                raise ValueError("invalid saved v2 reasons")
            refs = tuple(
                StoredDataRef.model_validate(value) for value in raw["evidence_refs"]
            )
            if len(set(refs)) != len(refs) or any(
                not _bound_ref(ref, identity) for ref in refs
            ):
                raise ValueError("invalid saved v2 evidence refs")
            for ref in refs:
                artifacts.read_bounded(ref, 8 * 1024 * 1024)
            if raw["coverage_status"] == "COVERED" and not refs:
                raise ValueError("covered v2 surface lacks evidence")
            proofs.append(
                SurfaceProofV2(
                    surface_id=surface.surface_id,
                    path=surface.path,
                    line=surface.line,
                    coverage_status=cast(
                        Literal["COVERED", "UNCOVERED", "INSUFFICIENT"],
                        raw["coverage_status"],
                    ),
                    verified_roles=tuple(
                        cast(list[dict[str, object]], raw["verified_roles"])
                    ),
                    evidence_refs=refs,
                    unresolved_reason_codes=tuple(cast(list[str], reasons)),
                )
            )
        proof = SurfaceCoverageV2(
            scope_fingerprint=index.scope_fingerprint,
            static_bundle_hash=index.static_bundle_hash,
            ast_manifest_hash=index.ast_manifest_hash,
            candidate_inventory_hash=index.candidate_inventory_hash,
            candidate_count=index.candidate_count,
            index_hash=index_ref.content_hash,
            original_coverage_ref=original_ref,
            scope_certificate_ref=certificate_ref,
            raw_static_gaps=tuple(
                cast(list[dict[str, object]], saved["raw_static_gaps"])
            ),
            effective_python_gaps=tuple(cast(list[dict[str, object]], effective)),
            surfaces=tuple(proofs),
            pending_candidate_count=cast(int, saved["pending_candidate_count"]),
            pending_child_count=cast(int, saved["pending_child_count"]),
        )
        if saved != proof.to_json() or saved.get("complete") is not proof.complete:
            raise ValueError("saved v2 payload is not exact")
        return proof
    except (
        KeyError,
        IndexError,
        OSError,
        TypeError,
        ValueError,
        UnicodeError,
    ) as error:
        raise ValueError(_V2_INVALID) from error


@dataclass(frozen=True, slots=True)
class SurfaceProofV3:
    surface_id: str
    path: str
    line: int
    coverage_status: Literal["COVERED", "UNCOVERED", "INSUFFICIENT"]
    prior_v2_status: Literal["COVERED", "UNCOVERED", "INSUFFICIENT"]
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
            "prior_v2_status": self.prior_v2_status,
            "review_classification": self.review_classification,
            "verified_roles": list(self.verified_roles),
            "evidence_refs": [
                ref.model_dump(mode="json") for ref in self.evidence_refs
            ],
            "unresolved_reason_codes": list(self.unresolved_reason_codes),
        }


@dataclass(frozen=True, slots=True)
class SurfaceCoverageV3:
    scope_fingerprint: str
    static_bundle_hash: str
    ast_manifest_hash: str
    candidate_inventory_hash: str
    candidate_count: int
    index_hash: str
    original_coverage_ref: StoredDataRef
    scope_certificate_ref: StoredDataRef
    prior_v2_ref: StoredDataRef
    v5_plan_ref: StoredDataRef
    raw_static_gaps: tuple[dict[str, object], ...]
    effective_python_gaps: tuple[dict[str, object], ...]
    surfaces: tuple[SurfaceProofV3, ...]
    pending_candidate_count: int
    pending_child_count: int

    @property
    def complete(self) -> bool:
        return (
            not self.effective_python_gaps
            and self.pending_candidate_count == 0
            and self.pending_child_count == 0
            and bool(self.surfaces)
            and all(surface.coverage_status == "COVERED" for surface in self.surfaces)
        )

    def to_json(self) -> dict[str, object]:
        return {
            "kind": "simple_attack_surface_coverage_v3",
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
            "v5_plan_ref": self.v5_plan_ref.model_dump(mode="json"),
            "raw_static_gaps": list(self.raw_static_gaps),
            "effective_python_gaps": list(self.effective_python_gaps),
            "surfaces": [surface.to_json() for surface in self.surfaces],
            "pending_candidate_count": self.pending_candidate_count,
            "pending_child_count": self.pending_child_count,
            "complete": self.complete,
        }


def read_saved_coverage_v3(
    artifacts: SimpleArtifactRepository,
    index: SurfaceIndex,
    coverage_ref: StoredDataRef,
    *,
    prior_v2_ref: StoredDataRef,
    v5_plan_ref: StoredDataRef,
) -> SurfaceCoverageV3:
    """Read an exact v3 certificate against caller-pinned v2 and v5 refs."""

    invalid = "SURFACE_COVERAGE_V3_SAVED_INVALID"
    identity = artifacts.identity
    try:
        if not all(
            _bound_ref(ref, identity)
            for ref in (coverage_ref, prior_v2_ref, v5_plan_ref)
        ):
            raise ValueError("unbound v3 certificate refs")
        prior = read_saved_coverage_v2(artifacts, index, prior_v2_ref)
        plan = _read_object(artifacts, v5_plan_ref, 8 * 1024 * 1024)
        saved = _read_object(artifacts, coverage_ref, 8 * 1024 * 1024)
        if (
            plan.get("kind") != "simple_surface_enrichment_plan_v5"
            or plan.get("analysis_id") != identity.analysis_id
            or plan.get("workspace_id") != identity.workspace_id
            or plan.get("commit_id") != identity.commit_id
            or plan.get("index_hash") != prior.index_hash
            or plan.get("v2_coverage_ref") != prior_v2_ref.model_dump(mode="json")
            or plan.get("v2_coverage_hash") != prior_v2_ref.content_hash
            or saved.get("kind") != "simple_attack_surface_coverage_v3"
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
            or saved.get("prior_v2_ref") != prior_v2_ref.model_dump(mode="json")
            or saved.get("v5_plan_ref") != v5_plan_ref.model_dump(mode="json")
            or saved.get("raw_static_gaps") != list(prior.raw_static_gaps)
            or saved.get("effective_python_gaps") != list(prior.effective_python_gaps)
            or type(saved.get("pending_candidate_count")) is not int
            or cast(int, saved["pending_candidate_count"]) < 0
            or type(saved.get("pending_child_count")) is not int
            or cast(int, saved["pending_child_count"]) < 0
        ):
            raise ValueError("unbound v3 coverage header")
        rows = saved.get("surfaces")
        if not isinstance(rows, list) or len(rows) != len(index.surfaces):
            raise ValueError("invalid v3 surface count")
        proofs: list[SurfaceProofV3] = []
        for surface, old, raw in zip(index.surfaces, prior.surfaces, rows, strict=True):
            if (
                not isinstance(raw, dict)
                or set(raw)
                != {
                    "surface_id",
                    "path",
                    "line",
                    "coverage_status",
                    "prior_v2_status",
                    "review_classification",
                    "verified_roles",
                    "evidence_refs",
                    "unresolved_reason_codes",
                }
                or raw.get("surface_id") != surface.surface_id
                or raw.get("path") != surface.path
                or raw.get("line") != surface.line
                or raw.get("prior_v2_status") != old.coverage_status
                or raw.get("coverage_status")
                not in {"COVERED", "UNCOVERED", "INSUFFICIENT"}
                or old.coverage_status == "COVERED"
                and raw.get("coverage_status") != "COVERED"
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
                raise ValueError("invalid v3 surface")
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
                .difference(_REPLACEABLE_GRAPH_REASONS | _REPLACEABLE_CHILD_REASONS)
                .issubset(reasons)
            ):
                raise ValueError("invalid v3 reasons")
            refs = tuple(
                StoredDataRef.model_validate(value) for value in raw["evidence_refs"]
            )
            if (
                len(set(refs)) != len(refs)
                or any(not _bound_ref(ref, identity) for ref in refs)
                or not set(old.evidence_refs).issubset(refs)
                or any(role not in raw["verified_roles"] for role in old.verified_roles)
            ):
                raise ValueError("invalid v3 evidence")
            for ref in refs:
                artifacts.read_bounded(ref, 8 * 1024 * 1024)
            proofs.append(
                SurfaceProofV3(
                    surface_id=surface.surface_id,
                    path=surface.path,
                    line=surface.line,
                    coverage_status=cast(
                        Literal["COVERED", "UNCOVERED", "INSUFFICIENT"],
                        raw["coverage_status"],
                    ),
                    prior_v2_status=old.coverage_status,
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
        coverage = SurfaceCoverageV3(
            scope_fingerprint=prior.scope_fingerprint,
            static_bundle_hash=prior.static_bundle_hash,
            ast_manifest_hash=prior.ast_manifest_hash,
            candidate_inventory_hash=prior.candidate_inventory_hash,
            candidate_count=prior.candidate_count,
            index_hash=prior.index_hash,
            original_coverage_ref=prior.original_coverage_ref,
            scope_certificate_ref=prior.scope_certificate_ref,
            prior_v2_ref=prior_v2_ref,
            v5_plan_ref=v5_plan_ref,
            raw_static_gaps=prior.raw_static_gaps,
            effective_python_gaps=prior.effective_python_gaps,
            surfaces=tuple(proofs),
            pending_candidate_count=cast(int, saved["pending_candidate_count"]),
            pending_child_count=cast(int, saved["pending_child_count"]),
        )
        if saved != coverage.to_json():
            raise ValueError("saved v3 payload is not exact")
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


def _validated_v5_part(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    index_hash: str,
    plan: Mapping[str, object],
    surface_id: str,
    target: Mapping[str, object],
    expected: Mapping[str, object],
    record: SurfaceExplorationProgressRecord,
    artifacts: SimpleArtifactRepository,
) -> tuple[tuple[dict[str, object], ...], tuple[StoredDataRef, ...], str | None, str]:
    invalid = "SURFACE_COVERAGE_V3_PROGRESS_INVALID"
    surface = next(item for item in index.surfaces if item.surface_id == surface_id)
    if (
        record.proposal_version != 5
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
        or context.get("scope_fingerprint") != index.scope_fingerprint
        or context.get("static_bundle_hash") != index.static_bundle_hash
        or context.get("ast_manifest_hash") != index.ast_manifest_hash
        or context.get("surface_index_hash") != index_hash
        or context.get("surface_id") != surface_id
        or context.get("path") != surface.path
        or context.get("line") != surface.line
        or context.get("source_sha256") != expected.get("source_sha256")
        or context.get("graph_hash") != target.get("graph_hash")
        or context.get("plan_binding_hash") != plan.get("plan_binding_hash")
        or context.get("parent_progress_hash") != target.get("parent_progress_hash")
        or context.get("prior_reasons") != target.get("prior_reasons")
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
    graph = _read_object(artifacts, graph_ref, 8 * 1024 * 1024)
    result = _read_object(artifacts, record.result_ref, 1024 * 1024)
    if (
        result.get("kind") != "simple_surface_hypothesis_result_v5"
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
    derived_seed_ids = [
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
        or result.get("seed_ids") != derived_seed_ids
        or (record.status == "HYPOTHESES") != bool(derived_seed_ids)
    ):
        raise ValueError(invalid)
    usable_path = (
        checked.verified_path_id
        if checked.status in {"HYPOTHESES", "NO_HYPOTHESIS"}
        # Older saved graphs were built before import/launcher semantics were
        # tightened. Preserve their review record, never promote their path
        # assertions into new terminal coverage.
        and graph.get("proof_semantics_revision") == "v5-source-bound-2"
        and not graph.get("gaps")
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


def validate_surface_plan_v5(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    prior_v2: SurfaceCoverageV2,
    plan_v5: Mapping[str, object],
    progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord],
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
) -> None:
    """Validate the saved v5 plan and parts before LLM work.

    Do not reject recoverable child errors before the child drain runs.
    """

    _evaluate_surface_coverage_v3(
        identity,
        index,
        prior_v2,
        plan_v5,
        progress,
        store,
        artifacts,
        plan_only=True,
    )


def evaluate_surface_coverage_v3(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    prior_v2: SurfaceCoverageV2,
    plan_v5: Mapping[str, object],
    progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord],
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
) -> SurfaceCoverageV3:
    """Certify only v5 deltas over exact saved v2 bytes; never re-evaluate v2."""

    coverage = _evaluate_surface_coverage_v3(
        identity,
        index,
        prior_v2,
        plan_v5,
        progress,
        store,
        artifacts,
        plan_only=False,
    )
    if coverage is None:
        raise ValueError("SURFACE_COVERAGE_V3_PLAN_INVALID")
    return coverage


def _evaluate_surface_coverage_v3(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    prior_v2: SurfaceCoverageV2,
    plan_v5: Mapping[str, object],
    progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord],
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
    *,
    plan_only: bool,
) -> SurfaceCoverageV3 | None:
    """Share exact plan/part validation; only certification checks child state."""

    invalid = "SURFACE_COVERAGE_V3_PLAN_INVALID"
    if identity != artifacts.identity or identity.hypothesis_id is not None:
        raise ValueError(invalid)
    run = store.require_analysis_run(identity.analysis_id)
    plan_ref = run.surface_enrichment_v5_plan_ref
    try:
        prior_ref = StoredDataRef.model_validate(plan_v5["v2_coverage_ref"])
        v4_ref = StoredDataRef.model_validate(plan_v5["v4_plan_ref"])
        index_ref = StoredDataRef.model_validate(plan_v5["index_ref"])
        if (
            plan_ref is None
            or not all(
                _bound_ref(ref, identity)
                for ref in (plan_ref, prior_ref, v4_ref, index_ref)
            )
            or _read_object(artifacts, plan_ref, 8 * 1024 * 1024) != plan_v5
            or _read_object(artifacts, index_ref, 8 * 1024 * 1024) != index.to_json()
            or read_saved_coverage_v2(artifacts, index, prior_ref) != prior_v2
            or plan_v5.get("kind") != "simple_surface_enrichment_plan_v5"
            or plan_v5.get("analysis_id") != identity.analysis_id
            or plan_v5.get("workspace_id") != identity.workspace_id
            or plan_v5.get("commit_id") != identity.commit_id
            or plan_v5.get("scope_fingerprint") != index.scope_fingerprint
            or plan_v5.get("static_bundle_hash") != index.static_bundle_hash
            or plan_v5.get("ast_manifest_hash") != index.ast_manifest_hash
            or plan_v5.get("candidate_inventory_hash") != index.candidate_inventory_hash
            or plan_v5.get("index_hash") != index_ref.content_hash
            or plan_v5.get("v2_coverage_hash") != prior_ref.content_hash
            or plan_v5.get("v4_plan_hash") != v4_ref.content_hash
            or plan_v5.get("original_coverage_ref")
            != prior_v2.original_coverage_ref.model_dump(mode="json")
            or plan_v5.get("scope_certificate_ref")
            != prior_v2.scope_certificate_ref.model_dump(mode="json")
            or run.workspace_id != identity.workspace_id
            or run.commit_id != identity.commit_id
            or run.surface_enrichment_plan_ref != v4_ref
            or run.python_scope_certificate_ref != prior_v2.scope_certificate_ref
            or run.static_bundle_ref is None
            or run.static_bundle_ref.content_hash != index.static_bundle_hash
            or run.candidate_terminal is None
            or run.candidate_terminal.status not in {"PARTIAL", "COMPLETE"}
            or run.candidate_terminal.bundle_hash != index.static_bundle_hash
            or run.candidate_terminal.scope_fingerprint != index.scope_fingerprint
            or run.candidate_terminal.surface_index_hash != index_ref.content_hash
            or run.candidate_terminal.surface_proof_version not in {2, 3}
            or run.candidate_terminal.scope_certificate_hash
            != prior_v2.scope_certificate_ref.content_hash
            or run.candidate_terminal.surface_proof_version == 2
            and run.candidate_terminal.surface_coverage_hash != prior_ref.content_hash
        ):
            raise ValueError("unbound v3 plan or prior")
        terminal = run.candidate_terminal
        if terminal is None:
            raise ValueError("missing v3 candidate terminal")
        saved_v3: SurfaceCoverageV3 | None = None
        if terminal.surface_proof_version == 3:
            saved_hash = terminal.surface_coverage_hash
            if (
                not isinstance(saved_hash, str)
                or len(saved_hash) != 64
                or any(char not in "0123456789abcdef" for char in saved_hash)
            ):
                raise ValueError("invalid saved v3 terminal hash")
            saved_v3 = read_saved_coverage_v3(
                artifacts,
                index,
                _ref(identity, saved_hash),
                prior_v2_ref=prior_ref,
                v5_plan_ref=plan_ref,
            )
            if (terminal.status == "COMPLETE") != saved_v3.complete:
                raise ValueError("saved v3 terminal status differs from proof")
        v4_plan = _read_object(artifacts, v4_ref, 8 * 1024 * 1024)
        if (
            v4_plan.get("kind") != "simple_surface_enrichment_plan_v4"
            or v4_plan.get("index_hash") != index_ref.content_hash
            or v4_plan.get("analysis_id") != identity.analysis_id
        ):
            raise ValueError("unbound v4 parent plan")
        target_ids = [
            proof.surface_id
            for proof in prior_v2.surfaces
            if proof.coverage_status == "INSUFFICIENT"
        ]
        targets = plan_v5.get("targets")
        parts = plan_v5.get("expected_parts")
        if (
            plan_v5.get("target_surface_ids") != target_ids
            or not isinstance(targets, list)
            or [
                row.get("surface_id") if isinstance(row, dict) else None
                for row in targets
            ]
            != target_ids
            or not isinstance(parts, list)
            or any(not isinstance(part, dict) for part in parts)
        ):
            raise ValueError("invalid v5 target list")
        target_map = {str(row["surface_id"]): row for row in targets}
        binding_targets: list[dict[str, object]] = []
        graphs: dict[str, dict[str, object]] = {}
        indexed = {surface.surface_id: surface for surface in index.surfaces}
        for surface_id in target_ids:
            target = target_map[surface_id]
            graph_hash = target.get("graph_hash")
            if not isinstance(graph_hash, str) or len(graph_hash) != 64:
                raise ValueError("invalid v5 graph hash")
            graph = _read_object(artifacts, _ref(identity, graph_hash), 8 * 1024 * 1024)
            graphs[surface_id] = graph
            items, verified_hash = _graph_items(
                graph, indexed[surface_id], index, index_ref.content_hash
            )
            if verified_hash != graph_hash or target.get("item_count") != len(items):
                raise ValueError("unbound v5 graph")
            binding_targets.append(
                {
                    "surface_id": surface_id,
                    "graph_hash": graph_hash,
                    "prior_progress": target.get("prior_progress"),
                    "prior_reasons": target.get("prior_reasons"),
                    "item_digests": [_digest(item) for item in items],
                }
            )
        binding = {
            key: value
            for key, value in plan_v5.items()
            if key
            not in {
                "kind",
                "plan_binding_hash",
                "target_surface_ids",
                "targets",
                "expected_parts",
            }
        }
        binding["kind"] = "simple_surface_enrichment_binding_v5"
        binding["targets"] = binding_targets
        if _digest(binding) != plan_v5.get("plan_binding_hash"):
            raise ValueError("unbound v5 plan binding")
        part_map: dict[tuple[str, str], dict[str, object]] = {}
        for part in parts:
            key = (part.get("surface_id"), part.get("context_id"))
            if (
                not isinstance(key[0], str)
                or not isinstance(key[1], str)
                or key in part_map
                or key[0] not in target_map
            ):
                raise ValueError("invalid v5 part")
            part_map[cast(tuple[str, str], key)] = part
        if any(
            key != (row.surface_id, row.context_id) for key, row in progress.items()
        ) or any(
            key not in part_map
            for key, row in progress.items()
            if row.proposal_version == 5
        ):
            raise ValueError("unbound v5 progress")
        prior_progress = {
            key: row for key, row in progress.items() if row.proposal_version < 5
        }
        child_hashes = plan_v5.get("child_checkpoint_hashes")
        scope = plan_v5.get("scope")
        if (
            not isinstance(scope, str)
            or not isinstance(child_hashes, dict)
            or any(
                not isinstance(key, str) or not isinstance(value, str)
                for key, value in child_hashes.items()
            )
        ):
            raise ValueError("invalid pinned v5 child scope")
        reconstructed_plan, _ = prepare_surface_enrichment_v5(
            identity,
            scope,
            index,
            index_ref,
            v4_ref,
            prior_ref,
            prior_v2,
            prior_progress,
            graphs,
            v4_plan=v4_plan,
            child_checkpoint_hashes=cast(dict[str, str], child_hashes),
        )
        if reconstructed_plan != plan_v5:
            raise ValueError("saved v5 plan differs from pinned reconstruction")
        for proof in prior_v2.surfaces:
            if proof.surface_id not in target_map:
                continue
            target = target_map[proof.surface_id]
            parents = _prior_rows(
                proof.surface_id, prior_progress, index, index_ref.content_hash
            )
            surface_parts = [
                part for part in parts if part["surface_id"] == proof.surface_id
            ]
            if (
                target.get("prior_progress") != parents
                or target.get("parent_progress_hash") != _digest(parents)
                or target.get("prior_reasons") != list(proof.unresolved_reason_codes)
                or not surface_parts
                or target.get("part_count") != len(surface_parts)
                or {part["part_index"] for part in surface_parts}
                != set(range(len(surface_parts)))
                or any(
                    part.get("part_count") != len(surface_parts)
                    for part in surface_parts
                )
            ):
                raise ValueError("unbound v5 parent progress")
        v5_rows = {
            key: row for key, row in progress.items() if row.proposal_version == 5
        }
        if saved_v3 is not None:
            saved_rows = {row.surface_id: row for row in saved_v3.surfaces}
            for part in parts:
                key = (cast(str, part["surface_id"]), cast(str, part["context_id"]))
                if key in v5_rows:
                    continue
                saved_row = saved_rows[key[0]]
                context_ref = _ref(identity, cast(str, part["context_hash"]))
                if (
                    "SURFACE_PART_PENDING" not in saved_row.unresolved_reason_codes
                    or context_ref in saved_row.evidence_refs
                ):
                    raise ValueError("saved v3 reviewed part is missing")
        proofs: list[SurfaceProofV3] = []
        for surface, prior in zip(index.surfaces, prior_v2.surfaces, strict=True):
            reasons = set(prior.unresolved_reason_codes)
            roles = list(prior.verified_roles)
            refs = list(prior.evidence_refs)
            classification: str | None = None
            if prior.surface_id in target_map:
                target = target_map[prior.surface_id]
                surface_parts = [
                    part for part in parts if part["surface_id"] == prior.surface_id
                ]
                all_present = all(
                    (prior.surface_id, cast(str, part["context_id"])) in v5_rows
                    for part in surface_parts
                )
                connected = False
                for part in surface_parts:
                    key = (prior.surface_id, cast(str, part["context_id"]))
                    row = v5_rows.get(key)
                    if row is None:
                        reasons.add("SURFACE_PART_PENDING")
                        continue
                    verified, part_refs, path_id, review_status = _validated_v5_part(
                        identity,
                        index,
                        index_ref.content_hash,
                        plan_v5,
                        prior.surface_id,
                        target,
                        part,
                        row,
                        artifacts,
                    )
                    roles.extend(verified)
                    refs.extend(part_refs)
                    classification = review_status
                    connected |= path_id is not None
                if all_present and connected:
                    reasons.difference_update(_REPLACEABLE_GRAPH_REASONS)
                elif all_present:
                    reasons.add("CONNECTED_ROLE_PROOF_MISSING")
                if target.get("unavailable_items"):
                    reasons.add("SURFACE_SOURCE_UNAVAILABLE")
            if plan_only:
                continue
            related_children = _related_child_ids(
                identity, surface, progress, store, index.scope_fingerprint
            )
            if related_children:
                # The old HOLD is replaceable only by the current, verified
                # state of every still-linked child, never by the v5 review.
                reasons.difference_update(_REPLACEABLE_CHILD_REASONS)
            for child_id in related_children:
                reasons.update(_child_reasons(identity, child_id, store, artifacts))
            if "CHILD_ERROR" in reasons:
                raise ValueError("SURFACE_COVERAGE_V3_CHILD_ERROR")
            coverage_status: Literal["COVERED", "UNCOVERED", "INSUFFICIENT"] = (
                "COVERED"
                if not reasons
                else "UNCOVERED"
                if prior.coverage_status == "UNCOVERED"
                else "INSUFFICIENT"
            )
            proofs.append(
                SurfaceProofV3(
                    surface_id=prior.surface_id,
                    path=prior.path,
                    line=prior.line,
                    coverage_status=coverage_status,
                    prior_v2_status=prior.coverage_status,
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
                raise ValueError("invalid v3 pending child page")
            pending_children += len(page)
            if len(page) < 100:
                break
            after_id = page[-1]
        coverage = SurfaceCoverageV3(
            scope_fingerprint=index.scope_fingerprint,
            static_bundle_hash=index.static_bundle_hash,
            ast_manifest_hash=index.ast_manifest_hash,
            candidate_inventory_hash=index.candidate_inventory_hash,
            candidate_count=index.candidate_count,
            index_hash=index_ref.content_hash,
            original_coverage_ref=prior_v2.original_coverage_ref,
            scope_certificate_ref=prior_v2.scope_certificate_ref,
            prior_v2_ref=prior_ref,
            v5_plan_ref=plan_ref,
            raw_static_gaps=prior_v2.raw_static_gaps,
            effective_python_gaps=prior_v2.effective_python_gaps,
            surfaces=tuple(proofs),
            pending_candidate_count=pending_candidates,
            pending_child_count=pending_children,
        )
        if saved_v3 is not None:
            if terminal.status == "COMPLETE" and coverage != saved_v3:
                raise ValueError("completed v3 proof changed")
            for saved_row, current_row in zip(
                saved_v3.surfaces, coverage.surfaces, strict=True
            ):
                if (
                    saved_row.coverage_status == "COVERED"
                    and current_row.coverage_status != "COVERED"
                    or any(
                        role not in current_row.verified_roles
                        for role in saved_row.verified_roles
                    )
                    or not set(saved_row.evidence_refs).issubset(
                        current_row.evidence_refs
                    )
                ):
                    raise ValueError("saved v3 proof regressed")
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


def verified_saved_coverage_v3(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    coverage_ref: StoredDataRef,
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
) -> SurfaceCoverageV3:
    """Verify terminal v3 bytes against current source-bound progress and children."""

    invalid = "SURFACE_COVERAGE_V3_VERIFIED_INVALID"
    try:
        if identity != artifacts.identity or identity.hypothesis_id is not None:
            raise ValueError("v3 identity mismatch")
        run = store.require_analysis_run(identity.analysis_id)
        terminal = run.candidate_terminal
        plan_ref = run.surface_enrichment_v5_plan_ref
        if (
            terminal is None
            or terminal.surface_proof_version != 3
            or terminal.surface_coverage_hash != coverage_ref.content_hash
            or plan_ref is None
            or not _bound_ref(plan_ref, identity)
        ):
            raise ValueError("v3 terminal missing or unbound")
        plan = _read_object(artifacts, plan_ref, 8 * 1024 * 1024)
        prior_ref = StoredDataRef.model_validate(plan["v2_coverage_ref"])
        saved = read_saved_coverage_v3(
            artifacts,
            index,
            coverage_ref,
            prior_v2_ref=prior_ref,
            v5_plan_ref=plan_ref,
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
            raise ValueError("v3 terminal counts differ from saved certificate")
        prior = read_saved_coverage_v2(artifacts, index, prior_ref)
        progress = store.list_surface_exploration_progress(
            identity, index.scope_fingerprint
        )
        current = evaluate_surface_coverage_v3(
            identity, index, prior, plan, progress, store, artifacts
        )
        if current != saved:
            raise ValueError("saved v3 certificate differs from current proof")
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
