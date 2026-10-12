"""Additive, exact-scope attack-surface proof for a saved v4 repair.

This reader makes no writes and never changes the original v1 coverage. A
surface review proves coverage of an indexed location, not a vulnerability.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal, cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.python_coverage_scope import (
    out_of_scope_limits_python_coverage,
)
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .attack_surfaces import AttackSurface, SurfaceCoverage, SurfaceIndex
from .models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageStatus,
    terminal_gate_outcome,
)
from .store import SimpleCheckpointStore, SurfaceExplorationProgressRecord
from .surface_contexts import SurfaceContext
from .surface_enrichment_v4 import _parent_rows, _same_surface
from .surface_evidence_validation_v4 import (
    validate_v4_context_payload,
    validate_v4_response,
)

_ROLES = frozenset({"ENTRY", "SENSITIVE_OPERATION", "TRUST_BOUNDARY"})
_VALID_STATUSES = frozenset(
    {"HYPOTHESES", "NO_HYPOTHESIS", "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"}
)
_VALID_COVERAGE_STATUSES = frozenset({"COVERED", "UNCOVERED", "INSUFFICIENT"})


def _digest(payload: object) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def _ref(identity: CheckpointIdentity, digest: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(digest),
        data_kind="artifact",
        content_hash=digest,
        workspace_id=WorkspaceId(identity.workspace_id),
        commit_id=CommitId(identity.commit_id),
        record_id=None,
    )


def _read_object(
    artifacts: SimpleArtifactRepository, ref: StoredDataRef
) -> dict[str, object]:
    try:
        value = json.loads(artifacts.read(ref))
    except (OSError, UnicodeError, ValueError) as error:
        raise ValueError("SURFACE_COVERAGE_V2_ARTIFACT_INVALID") from error
    if not isinstance(value, dict):
        raise ValueError("SURFACE_COVERAGE_V2_ARTIFACT_INVALID")
    return cast(dict[str, object], value)


@dataclass(frozen=True, slots=True)
class SurfaceProofV2:
    surface_id: str
    path: str
    line: int
    coverage_status: Literal["COVERED", "UNCOVERED", "INSUFFICIENT"]
    verified_roles: tuple[dict[str, object], ...]
    evidence_refs: tuple[StoredDataRef, ...]
    unresolved_reason_codes: tuple[str, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "surface_id": self.surface_id,
            "path": self.path,
            "line": self.line,
            "coverage_status": self.coverage_status,
            "verified_roles": list(self.verified_roles),
            "evidence_refs": [
                ref.model_dump(mode="json") for ref in self.evidence_refs
            ],
            "unresolved_reason_codes": list(self.unresolved_reason_codes),
        }


@dataclass(frozen=True, slots=True)
class SurfaceCoverageV2:
    scope_fingerprint: str
    static_bundle_hash: str
    ast_manifest_hash: str
    candidate_inventory_hash: str
    candidate_count: int
    index_hash: str
    original_coverage_ref: StoredDataRef
    scope_certificate_ref: StoredDataRef
    raw_static_gaps: tuple[dict[str, object], ...]
    effective_python_gaps: tuple[dict[str, object], ...]
    surfaces: tuple[SurfaceProofV2, ...]
    pending_candidate_count: int
    pending_child_count: int

    @property
    def complete(self) -> bool:
        return (
            not self.effective_python_gaps
            and self.pending_candidate_count == 0
            and self.pending_child_count == 0
            and all(surface.coverage_status == "COVERED" for surface in self.surfaces)
        )

    def to_json(self) -> dict[str, object]:
        return {
            "kind": "simple_attack_surface_coverage_v2",
            "scope_fingerprint": self.scope_fingerprint,
            "static_bundle_hash": self.static_bundle_hash,
            "ast_manifest_hash": self.ast_manifest_hash,
            "candidate_inventory_hash": self.candidate_inventory_hash,
            "candidate_count": self.candidate_count,
            "index_hash": self.index_hash,
            "original_coverage_ref": self.original_coverage_ref.model_dump(mode="json"),
            "scope_certificate_ref": self.scope_certificate_ref.model_dump(mode="json"),
            "scope_certificate_hash": self.scope_certificate_ref.content_hash,
            "raw_static_gaps": list(self.raw_static_gaps),
            "effective_python_gaps": list(self.effective_python_gaps),
            "surfaces": [surface.to_json() for surface in self.surfaces],
            "pending_candidate_count": self.pending_candidate_count,
            "pending_child_count": self.pending_child_count,
            "complete": self.complete,
        }


def _scope_refs(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    index_ref: StoredDataRef,
    base: SurfaceCoverage,
    plan: Mapping[str, object],
    certificate: Mapping[str, object],
    artifacts: SimpleArtifactRepository,
) -> tuple[StoredDataRef, StoredDataRef, tuple[dict[str, object], ...]]:
    invalid = "SURFACE_COVERAGE_V2_SCOPE_INVALID"
    if (
        identity.hypothesis_id is not None
        or index.index_version != 2
        or index.workspace_id != identity.workspace_id
        or index.commit_id != identity.commit_id
        or str(index_ref.workspace_id) != identity.workspace_id
        or str(index_ref.commit_id) != identity.commit_id
        or index_ref.content_hash != _digest(index.to_json())
        or _read_object(artifacts, index_ref) != index.to_json()
        or base.scope_fingerprint != index.scope_fingerprint
        or base.static_bundle_hash != index.static_bundle_hash
        or base.ast_manifest_hash != index.ast_manifest_hash
        or base.candidate_inventory_hash != index.candidate_inventory_hash
        or base.candidate_count != index.candidate_count
        or base.static_gaps != index.static_gaps
        or len(base.surfaces) != len(index.surfaces)
        or any(
            not _same_surface(original, reviewed)
            for original, reviewed in zip(index.surfaces, base.surfaces, strict=True)
        )
        or plan.get("kind") != "simple_surface_enrichment_plan_v4"
        or plan.get("analysis_id") != identity.analysis_id
        or plan.get("workspace_id") != identity.workspace_id
        or plan.get("commit_id") != identity.commit_id
        or plan.get("scope_fingerprint") != index.scope_fingerprint
        or plan.get("index_hash") != index_ref.content_hash
        or plan.get("index_ref") != index_ref.model_dump(mode="json")
        or plan.get("static_bundle_ref") is None
        or plan.get("prior_coverage_hash") != _digest(base.to_json())
        or certificate.get("kind") != "simple_python_scope_recertification_v1"
        or certificate.get("analysis_id") != identity.analysis_id
        or certificate.get("workspace_id") != identity.workspace_id
        or certificate.get("commit_id") != identity.commit_id
        or certificate.get("scope_fingerprint") != index.scope_fingerprint
        or certificate.get("index_hash") != index_ref.content_hash
        or certificate.get("index_ref") != index_ref.model_dump(mode="json")
        or certificate.get("raw_static_gaps") != index.to_json()["static_gaps"]
        or plan.get("certificate_hash") != _digest(certificate)
    ):
        raise ValueError(invalid)
    try:
        original_ref = StoredDataRef.model_validate(plan["original_coverage_ref"])
        certificate_ref = _ref(identity, cast(str, plan["certificate_hash"]))
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(invalid) from error
    if (
        original_ref.content_hash != _digest(base.to_json())
        or str(original_ref.workspace_id) != identity.workspace_id
        or str(original_ref.commit_id) != identity.commit_id
        or _read_object(artifacts, original_ref) != base.to_json()
        or _read_object(artifacts, certificate_ref) != certificate
    ):
        raise ValueError(invalid)
    effective = certificate.get("effective_static_gaps")
    raw_coverage = certificate.get("raw_coverage_gaps")
    raw_exclusions = certificate.get("raw_out_of_scope_product_files")
    decisions = certificate.get("file_decisions")
    static_coverage_ref_value = certificate.get("coverage_ref")
    if (
        not isinstance(effective, list)
        or any(
            not isinstance(gap, dict)
            or set(gap) != {"path", "rule_id", "reason", "engine"}
            or any(not isinstance(value, str) for value in gap.values())
            for gap in effective
        )
        or not isinstance(raw_coverage, list)
        or not isinstance(raw_exclusions, list)
        or not isinstance(decisions, list)
    ):
        raise ValueError(invalid)
    try:
        static_coverage_ref = StoredDataRef.model_validate(static_coverage_ref_value)
        static_coverage = _read_object(artifacts, static_coverage_ref)
    except (TypeError, ValueError) as error:
        raise ValueError(invalid) from error
    if (
        str(static_coverage_ref.workspace_id) != identity.workspace_id
        or str(static_coverage_ref.commit_id) != identity.commit_id
        or raw_coverage != static_coverage.get("gaps")
        or raw_exclusions != static_coverage.get("out_of_scope_product_files")
    ):
        raise ValueError(invalid)
    effective_keys = {
        (row["path"], row["rule_id"], row["reason"], row["engine"]) for row in effective
    }
    if len(effective_keys) != len(effective):
        raise ValueError(invalid)
    decision_rows: dict[tuple[str, str], Mapping[str, object]] = {}
    for row in decisions:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("path"), str)
            or not isinstance(row.get("reason"), str)
            or (row["path"], row["reason"]) in decision_rows
        ):
            raise ValueError(invalid)
        decision_rows[(row["path"], row["reason"])] = row
    exclusions = {
        (row.get("path"), row.get("reason"))
        for row in raw_exclusions
        if isinstance(row, dict)
    }
    if len(exclusions) != len(raw_exclusions):
        raise ValueError(invalid)
    raw_index_gaps = cast(list[dict[str, object]], index.to_json()["static_gaps"])
    for raw in raw_index_gaps:
        if not isinstance(raw, dict):
            raise ValueError(invalid)
        key = (
            raw["path"],
            raw["rule_id"],
            raw["reason"],
            raw["engine"],
        )
        if key in effective_keys:
            continue
        decision = decision_rows.get((cast(str, raw["path"]), cast(str, raw["reason"])))
        if (
            key[1] != "STATIC_SCOPE"
            or key[3] != "STATIC"
            or (raw["path"], raw["reason"]) not in exclusions
            or decision is None
            or decision.get("decision") != "OUT_OF_SCOPE"
            or decision.get("verification") != "PINNED_MATCH"
            or not isinstance(decision.get("source_sha256"), str)
            or len(cast(str, decision["source_sha256"])) != 64
            or out_of_scope_limits_python_coverage(
                cast(str, raw["path"]), cast(str, raw["reason"])
            )
        ):
            raise ValueError(invalid)
    for raw in raw_coverage:
        if not isinstance(raw, dict) or not all(
            isinstance(raw.get(field), str) for field in ("path", "rule_id", "reason")
        ):
            raise ValueError(invalid)
        if any(
            key[:3] == (raw["path"], raw["rule_id"], raw["reason"])
            for key in effective_keys
        ):
            continue
        decision = decision_rows.get((cast(str, raw["path"]), cast(str, raw["reason"])))
        if (
            raw["rule_id"] != "STATIC_SCOPE"
            or (raw["path"], raw["reason"]) not in exclusions
            or decision is None
            or decision.get("decision") != "OUT_OF_SCOPE"
            or decision.get("verification") != "PINNED_MATCH"
            or out_of_scope_limits_python_coverage(
                cast(str, raw["path"]), cast(str, raw["reason"])
            )
        ):
            raise ValueError(invalid)
    for path, reason in exclusions:
        if not isinstance(path, str) or not isinstance(reason, str):
            raise ValueError(invalid)
        if (path, "STATIC_SCOPE", reason, "STATIC") in effective_keys:
            continue
        decision = decision_rows.get((path, reason))
        if (
            decision is None
            or decision.get("decision") != "OUT_OF_SCOPE"
            or decision.get("verification") != "PINNED_MATCH"
            or not isinstance(decision.get("source_sha256"), str)
            or len(cast(str, decision["source_sha256"])) != 64
            or out_of_scope_limits_python_coverage(path, reason)
        ):
            raise ValueError(invalid)
    return (
        original_ref,
        certificate_ref,
        tuple(cast(list[dict[str, object]], effective)),
    )


def _related_child_ids(
    identity: CheckpointIdentity,
    surface: AttackSurface,
    progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord],
    store: SimpleCheckpointStore,
    scope: str,
) -> set[str]:
    ids = {
        hypothesis_id
        for row in progress.values()
        if row.surface_id == surface.surface_id
        for hypothesis_id in row.hypothesis_ids
    }
    for candidate_id in surface.linked_candidate_ids:
        after: str | None = None
        while True:
            page = store.list_candidate_hypothesis_ids(
                identity, scope, candidate_id, after_id=after, limit=64
            )
            ids.update(page)
            if len(page) < 64:
                break
            after = page[-1]
    return ids


def _child_reasons(
    identity: CheckpointIdentity,
    hypothesis_id: str,
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
) -> tuple[str, ...]:
    child = identity.model_copy(update={"hypothesis_id": hypothesis_id})
    checkpoints = {
        stage: checkpoint
        for stage in SimpleStage
        if (checkpoint := store.get(child, stage)) is not None
    }
    if not checkpoints:
        return ("CHILD_PENDING",)
    if any(
        checkpoint.status in {StageStatus.BLOCKED, StageStatus.FAILED}
        for checkpoint in checkpoints.values()
    ):
        return ("CHILD_ERROR",)
    for checkpoint in checkpoints.values():
        if checkpoint.status is StageStatus.SUCCEEDED:
            for ref in checkpoint.output_refs:
                try:
                    artifacts.read(ref)
                except (OSError, TypeError, ValueError):
                    return ("CHILD_ERROR",)
    for checkpoint in checkpoints.values():
        if checkpoint.status is not StageStatus.SUCCEEDED:
            return ("CHILD_PENDING",)
        if checkpoint.stage_version != STAGE_VERSION[checkpoint.stage]:
            return ("CHILD_STALE",)
    if any(checkpoint.verdict == "HOLD" for checkpoint in checkpoints.values()):
        return ("CHILD_HOLD",)
    final = checkpoints.get(SimpleStage.VERIFICATION_FINAL_DONE)
    gate = checkpoints.get(SimpleStage.TECH_GATE_DONE)
    report = checkpoints.get(SimpleStage.REPORT_DONE)
    if (
        final is not None
        and final.verdict == "FALSE"
        or terminal_gate_outcome(gate) is not None
        or report is not None
    ):
        return ()
    return ("CHILD_PENDING",)


def _validated_part(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    index_ref: StoredDataRef,
    surface: AttackSurface,
    expected: Mapping[str, object],
    target: Mapping[str, object],
    record: SurfaceExplorationProgressRecord,
    plan: Mapping[str, object],
    certificate_ref: StoredDataRef,
    artifacts: SimpleArtifactRepository,
) -> tuple[tuple[dict[str, object], ...], tuple[StoredDataRef, ...], bool]:
    invalid = "SURFACE_COVERAGE_V2_PROGRESS_INVALID"
    if (
        record.proposal_version != 4
        or record.surface_id != surface.surface_id
        or record.context_id != expected.get("context_id")
        or record.context_hash != expected.get("context_hash")
        or record.static_bundle_hash != index.static_bundle_hash
        or record.index_hash != index_ref.content_hash
        or record.source_sha256 != expected.get("source_sha256")
        or record.status not in _VALID_STATUSES
        or str(record.result_ref.workspace_id) != identity.workspace_id
        or str(record.result_ref.commit_id) != identity.commit_id
    ):
        raise ValueError(invalid)
    context_ref = _ref(identity, record.context_hash)
    context_payload = _read_object(artifacts, context_ref)
    if (
        context_payload.get("analysis_id") != identity.analysis_id
        or context_payload.get("workspace_id") != identity.workspace_id
        or context_payload.get("commit_id") != identity.commit_id
        or context_payload.get("scope_fingerprint") != index.scope_fingerprint
        or context_payload.get("scope_certificate_hash") != certificate_ref.content_hash
        or context_payload.get("surface_index_hash") != index_ref.content_hash
        or context_payload.get("plan_binding_hash") != plan.get("plan_binding_hash")
        or context_payload.get("graph_hash") != target.get("graph_hash")
        or context_payload.get("path") != surface.path
        or context_payload.get("line") != surface.line
    ):
        raise ValueError(invalid)
    part_index = context_payload.get("part_index")
    part_count = context_payload.get("part_count")
    if (
        type(part_index) is not int
        or type(part_count) is not int
        or part_index != expected.get("part_index")
        or part_count != expected.get("part_count")
    ):
        raise ValueError(invalid)
    context = SurfaceContext(
        surface_id=surface.surface_id,
        context_id=record.context_id,
        context_hash=record.context_hash,
        context_ref=context_ref,
        part_index=part_index,
        part_count=part_count,
        prompt_bytes=len(canonical_bytes(context_payload)),
        source_sha256=record.source_sha256,
        source_unavailable_reason=None,
        ast_unavailable_reason=None,
        omitted_source_line_count=0,
        omitted_ast_fact_count=0,
    )
    validate_v4_context_payload(context, context_payload, index.static_bundle_hash)
    result = _read_object(artifacts, record.result_ref)
    try:
        graph_ref = StoredDataRef.model_validate(result["graph_ref"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(invalid) from error
    if (
        graph_ref.content_hash != target.get("graph_hash")
        or result.get("graph_hash") != graph_ref.content_hash
        or str(graph_ref.workspace_id) != identity.workspace_id
        or str(graph_ref.commit_id) != identity.commit_id
    ):
        raise ValueError(invalid)
    graph = _read_object(artifacts, graph_ref)
    if (
        result.get("kind") != "simple_surface_hypothesis_result_v4"
        or result.get("analysis_id") != identity.analysis_id
        or result.get("surface_id") != surface.surface_id
        or result.get("context_id") != record.context_id
        or result.get("context_hash") != record.context_hash
        or result.get("part_index") != part_index
        or result.get("part_count") != part_count
        or result.get("static_bundle_hash") != index.static_bundle_hash
        or result.get("status") != record.status
        or result.get("validation_status") != "VALID"
        or result.get("seed_ids") != list(record.hypothesis_ids)
    ):
        raise ValueError(invalid)
    checked = validate_v4_response(
        result.get("response"), context, context_payload, graph
    )
    if (
        checked.status != record.status
        or result.get("verified_roles") != list(checked.verified_roles)
        or result.get("reviewed_parts") != sorted(checked.reviewed_parts)
        or result.get("evidence_locations") != list(checked.evidence_locations)
    ):
        raise ValueError(invalid)
    complete_part = (
        context_payload.get("unavailable_item_count") == 0
        and not graph.get("gaps")
        and not target.get("unavailable_items")
    )
    return (
        checked.verified_roles,
        (context_ref, graph_ref, record.result_ref),
        complete_part,
    )


def _check_prior_v2_proof(
    saved: Mapping[str, object], current: Mapping[str, object], status: str
) -> None:
    """Permit only monotonic PARTIAL recertification on the same pinned scope."""

    invalid = "SURFACE_COVERAGE_V2_TERMINAL_INVALID"
    if (
        set(saved) != set(current)
        or type(saved.get("complete")) is not bool
        or saved["complete"] != (status == "COMPLETE")
        or any(
            type(saved.get(key)) is not int or cast(int, saved[key]) < 0
            for key in ("pending_candidate_count", "pending_child_count")
        )
    ):
        raise ValueError(invalid)
    unchanged = set(current) - {
        "surfaces",
        "pending_candidate_count",
        "pending_child_count",
        "complete",
    }
    if any(saved.get(key) != current[key] for key in unchanged):
        raise ValueError(invalid)
    old_surfaces = saved.get("surfaces")
    new_surfaces = current["surfaces"]
    if (
        not isinstance(old_surfaces, list)
        or not isinstance(new_surfaces, list)
        or len(old_surfaces) != len(new_surfaces)
    ):
        raise ValueError(invalid)
    for old, new in zip(old_surfaces, new_surfaces, strict=True):
        if not isinstance(old, dict) or not isinstance(new, dict):
            raise ValueError(invalid)
        if (
            set(old) != set(new)
            or any(old.get(key) != new[key] for key in ("surface_id", "path", "line"))
            or old.get("coverage_status") not in _VALID_COVERAGE_STATUSES
            or not isinstance(old.get("unresolved_reason_codes"), list)
            or old.get("coverage_status") == "COVERED"
            and new["coverage_status"] != "COVERED"
        ):
            raise ValueError(invalid)
        for key in ("verified_roles", "evidence_refs"):
            prior_items = old.get(key)
            current_items = new[key]
            if (
                not isinstance(prior_items, list)
                or not isinstance(current_items, list)
                or any(item not in current_items for item in prior_items)
            ):
                raise ValueError(invalid)


def evaluate_surface_coverage_v2(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    index_ref: StoredDataRef,
    base_coverage: SurfaceCoverage,
    plan: Mapping[str, object],
    certificate: Mapping[str, object],
    progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord],
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
) -> SurfaceCoverageV2:
    """Certify completed v4 parts without changing any v1 record or CAS object."""

    original_ref, certificate_ref, effective = _scope_refs(
        identity, index, index_ref, base_coverage, plan, certificate, artifacts
    )
    invalid = "SURFACE_COVERAGE_V2_PLAN_INVALID"
    targets = plan.get("targets")
    target_ids = plan.get("target_surface_ids")
    parts = plan.get("expected_parts")
    if (
        not isinstance(targets, list)
        or not isinstance(target_ids, list)
        or not isinstance(parts, list)
        or any(not isinstance(row, dict) for row in (*targets, *parts))
        or target_ids
        != [
            surface.surface_id
            for surface in base_coverage.surfaces
            if surface.coverage_status == "INSUFFICIENT"
        ]
        or [row.get("surface_id") for row in targets] != target_ids
    ):
        raise ValueError(invalid)
    target_by_id = {cast(str, row["surface_id"]): row for row in targets}
    expected: dict[tuple[str, str], dict[str, object]] = {}
    for row in parts:
        key = (row.get("surface_id"), row.get("context_id"))
        if (
            not isinstance(key[0], str)
            or not isinstance(key[1], str)
            or key in expected
            or key[0] not in target_by_id
        ):
            raise ValueError(invalid)
        expected[cast(tuple[str, str], key)] = row
    if any(
        key != (row.surface_id, row.context_id)
        or row.surface_id not in {surface.surface_id for surface in index.surfaces}
        for key, row in progress.items()
    ) or any(
        key not in expected
        for key, row in progress.items()
        if row.proposal_version == 4
    ):
        raise ValueError("SURFACE_COVERAGE_V2_PROGRESS_INVALID")
    run = store.require_analysis_run(identity.analysis_id)
    terminal = run.candidate_terminal
    plan_ref = run.surface_enrichment_plan_ref
    if (
        run.workspace_id != identity.workspace_id
        or run.commit_id != identity.commit_id
        or run.static_bundle_ref is None
        or run.static_bundle_ref.model_dump(mode="json")
        != plan.get("static_bundle_ref")
        or run.static_bundle_ref.content_hash != index.static_bundle_hash
        or run.static_coverage_ref is None
        or run.static_coverage_ref.model_dump(mode="json")
        != certificate.get("coverage_ref")
        or plan_ref is None
        or plan_ref.content_hash != _digest(plan)
        or _read_object(artifacts, plan_ref) != plan
        or run.python_scope_certificate_ref != certificate_ref
        or terminal is None
        or terminal.surface_index_hash != index_ref.content_hash
        or terminal.bundle_hash != index.static_bundle_hash
        or terminal.scope_fingerprint != index.scope_fingerprint
    ):
        raise ValueError("SURFACE_COVERAGE_V2_TERMINAL_INVALID")
    if terminal.surface_proof_version == 1:
        if terminal.surface_coverage_hash != original_ref.content_hash:
            raise ValueError("SURFACE_COVERAGE_V2_TERMINAL_INVALID")
    elif terminal.surface_proof_version == 2:
        if terminal.scope_certificate_hash != certificate_ref.content_hash:
            raise ValueError("SURFACE_COVERAGE_V2_TERMINAL_INVALID")
    else:
        raise ValueError("SURFACE_COVERAGE_V2_TERMINAL_INVALID")
    for record in progress.values():
        if record.proposal_version == 4:
            continue
        if (
            record.proposal_version not in {1, 2, 3}
            or record.static_bundle_hash != index.static_bundle_hash
            or record.index_hash != index_ref.content_hash
        ):
            raise ValueError("SURFACE_COVERAGE_V2_PROGRESS_INVALID")
        try:
            artifacts.read(record.result_ref)
            artifacts.read(_ref(identity, record.context_hash))
        except (OSError, ValueError) as error:
            raise ValueError("SURFACE_COVERAGE_V2_PROGRESS_INVALID") from error
    counts = store.candidate_counts(identity, index.scope_fingerprint)
    deep = store.candidate_deep_counts(identity, index.scope_fingerprint)
    pending_candidates = (
        counts.get("PENDING", 0)
        + counts.get("ERROR", 0)
        + sum(deep.get(status, 0) for status in ("PENDING", "RUNNING", "ERROR"))
        + (0 if terminal.producer_finished else 1)
    )
    global_pending_children = 0
    after_id: str | None = None
    while True:
        page = store.list_incomplete_hypotheses(identity, after_id=after_id, limit=100)
        if not page:
            break
        if (
            len(page) > 100
            or tuple(sorted(set(page))) != page
            or after_id is not None
            and page[0] <= after_id
        ):
            raise ValueError("SURFACE_COVERAGE_V2_PENDING_QUERY_INVALID")
        global_pending_children += len(page)
        if len(page) < 100:
            break
        after_id = page[-1]
    pending_children = global_pending_children
    proofs: list[SurfaceProofV2] = []
    for surface, old in zip(index.surfaces, base_coverage.surfaces, strict=True):
        reasons: set[str] = set()
        refs: list[StoredDataRef] = []
        verified: list[dict[str, object]] = []
        if old.coverage_status == "COVERED":
            if not old.review_evidence_refs:
                raise ValueError("SURFACE_COVERAGE_V2_PRIOR_PROOF_INVALID")
            for ref in old.review_evidence_refs:
                artifacts.read(ref)
                refs.append(ref)
        elif old.coverage_status == "INSUFFICIENT":
            target = target_by_id[surface.surface_id]
            parents = _parent_rows(
                surface.surface_id, progress, index, index_ref.content_hash
            )
            if target.get("prior_progress") != parents:
                raise ValueError(invalid)
            surface_parts = [
                row for row in parts if row["surface_id"] == surface.surface_id
            ]
            if not surface_parts or len(surface_parts) != target.get("part_count"):
                raise ValueError(invalid)
            graph_hash = target.get("graph_hash")
            if not isinstance(graph_hash, str):
                raise ValueError(invalid)
            for expected_part in surface_parts:
                key = (
                    cast(str, expected_part["surface_id"]),
                    cast(str, expected_part["context_id"]),
                )
                row = progress.get(key)
                if row is None:
                    reasons.add("SURFACE_PART_PENDING")
                    continue
                roles, part_refs, part_complete = _validated_part(
                    identity,
                    index,
                    index_ref,
                    surface,
                    expected_part,
                    target,
                    row,
                    plan,
                    certificate_ref,
                    artifacts,
                )
                verified.extend(roles)
                refs.extend(part_refs)
                if not part_complete:
                    reasons.add("SURFACE_EVIDENCE_INSUFFICIENT")
            if target.get("unavailable_items"):
                reasons.add("SURFACE_SOURCE_UNAVAILABLE")
            grouped: dict[str, dict[str, dict[str, object]]] = {}
            for role in verified:
                path_id, part_name = role["graph_path_id"], role["part"]
                if isinstance(path_id, str) and isinstance(part_name, str):
                    grouped.setdefault(path_id, {})[part_name] = role
            anchor = f"{surface.path}:{surface.line}"
            connected = any(
                set(path_roles) >= _ROLES
                and any(role["location"] == anchor for role in path_roles.values())
                and len(
                    {
                        role["location"]
                        for role in path_roles.values()
                        if isinstance(role.get("location"), str)
                    }
                )
                == 3
                for path_roles in grouped.values()
            )
            if not connected:
                reasons.add("CONNECTED_ROLE_PROOF_MISSING")
        else:
            reasons.add("PRIOR_SURFACE_UNCOVERED")
        related = _related_child_ids(
            identity, surface, progress, store, index.scope_fingerprint
        )
        for hypothesis_id in related:
            reasons.update(_child_reasons(identity, hypothesis_id, store, artifacts))
        if "CHILD_ERROR" in reasons:
            raise ValueError("SURFACE_COVERAGE_V2_CHILD_ERROR")
        if reasons:
            status: Literal["COVERED", "UNCOVERED", "INSUFFICIENT"] = (
                "UNCOVERED" if old.coverage_status == "UNCOVERED" else "INSUFFICIENT"
            )
        else:
            status = "COVERED"
        proofs.append(
            SurfaceProofV2(
                surface_id=surface.surface_id,
                path=surface.path,
                line=surface.line,
                coverage_status=status,
                verified_roles=tuple(verified),
                evidence_refs=tuple(dict.fromkeys(refs)),
                unresolved_reason_codes=tuple(sorted(reasons)),
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
            cast(list[dict[str, object]], index.to_json()["static_gaps"])
        ),
        effective_python_gaps=effective,
        surfaces=tuple(proofs),
        pending_candidate_count=pending_candidates,
        pending_child_count=pending_children,
    )
    if terminal.surface_proof_version == 2:
        if terminal.surface_coverage_hash is None:
            raise ValueError("SURFACE_COVERAGE_V2_TERMINAL_INVALID")
        saved = _read_object(artifacts, _ref(identity, terminal.surface_coverage_hash))
        fresh = proof.to_json()
        if terminal.status not in {"PARTIAL", "COMPLETE"}:
            raise ValueError("SURFACE_COVERAGE_V2_TERMINAL_INVALID")
        _check_prior_v2_proof(saved, fresh, terminal.status)
        if terminal.status == "COMPLETE" and saved != fresh:
            raise ValueError("SURFACE_COVERAGE_V2_TERMINAL_INVALID")
    return proof
