"""Conservative v7 coverage over an immutable saved v6 certificate."""

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
from .models import (
    HYPOTHESIS_STAGES,
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageStatus,
)
from .store import SimpleCheckpointStore, SurfaceExplorationProgressRecord
from .surface_coverage_v2 import _child_reasons, _ref, _related_child_ids
from .surface_coverage_v3 import _bound_ref, _read_object
from .surface_coverage_v4 import SurfaceCoverageV4, read_saved_coverage_v4
from .surface_enrichment_v7 import prepare_surface_enrichment_v7
from .surface_enrichment_v7_bindings import (
    missing_v6_part_set,
    prior_progress_snapshot_hash,
)
from .surface_enrichment_v8_bindings import missing_v7_part_set
from .surface_evidence_validation_v5 import validate_v7_response

_MAX_OBJECT = 8 * 1024 * 1024
_GRAPH_REASONS = frozenset(
    {
        "CONNECTED_ROLE_PROOF_MISSING",
        "SURFACE_EVIDENCE_INSUFFICIENT",
        "SURFACE_SOURCE_UNAVAILABLE",
        "SURFACE_PART_PENDING",
    }
)
_CHILD_REASONS = frozenset({"CHILD_HOLD", "CHILD_PENDING", "CHILD_STALE"})


@dataclass(frozen=True, slots=True)
class SurfaceProofV5:
    surface_id: str
    path: str
    line: int
    coverage_status: Literal["COVERED", "UNCOVERED", "INSUFFICIENT"]
    prior_v4_status: Literal["COVERED", "UNCOVERED", "INSUFFICIENT"]
    review_classification: str | None
    verified_roles: tuple[dict[str, object], ...]
    evidence_refs: tuple[StoredDataRef, ...]
    unresolved_reason_codes: tuple[str, ...]
    completed_inconclusive_children: tuple[dict[str, object], ...]

    def to_json(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "surface_id": self.surface_id,
            "path": self.path,
            "line": self.line,
            "coverage_status": self.coverage_status,
            "prior_v4_status": self.prior_v4_status,
            "review_classification": self.review_classification,
            "verified_roles": list(self.verified_roles),
            "evidence_refs": [
                ref.model_dump(mode="json") for ref in self.evidence_refs
            ],
            "unresolved_reason_codes": list(self.unresolved_reason_codes),
        }
        if self.completed_inconclusive_children:
            payload["completed_inconclusive_children"] = list(
                self.completed_inconclusive_children
            )
        return payload


@dataclass(frozen=True, slots=True)
class SurfaceCoverageV5:
    scope_fingerprint: str
    static_bundle_hash: str
    ast_manifest_hash: str
    candidate_inventory_hash: str
    candidate_count: int
    index_hash: str
    original_coverage_ref: StoredDataRef
    scope_certificate_ref: StoredDataRef
    prior_v4_ref: StoredDataRef
    prior_v6_plan_ref: StoredDataRef
    v7_plan_ref: StoredDataRef
    prior_progress_hash: str
    missing_v6_parts: tuple[dict[str, str], ...]
    raw_static_gaps: tuple[dict[str, object], ...]
    effective_python_gaps: tuple[dict[str, object], ...]
    surfaces: tuple[SurfaceProofV5, ...]
    pending_candidate_count: int
    pending_child_count: int

    @property
    def complete(self) -> bool:
        return (
            not self.effective_python_gaps
            and not self.missing_v6_parts
            and self.pending_candidate_count == 0
            and self.pending_child_count == 0
            and bool(self.surfaces)
            and all(row.coverage_status == "COVERED" for row in self.surfaces)
        )

    def to_json(self) -> dict[str, object]:
        return {
            "kind": "simple_attack_surface_coverage_v5",
            "scope_fingerprint": self.scope_fingerprint,
            "static_bundle_hash": self.static_bundle_hash,
            "ast_manifest_hash": self.ast_manifest_hash,
            "candidate_inventory_hash": self.candidate_inventory_hash,
            "candidate_count": self.candidate_count,
            "index_hash": self.index_hash,
            "original_coverage_ref": self.original_coverage_ref.model_dump(mode="json"),
            "scope_certificate_ref": self.scope_certificate_ref.model_dump(mode="json"),
            "scope_certificate_hash": self.scope_certificate_ref.content_hash,
            "prior_v4_ref": self.prior_v4_ref.model_dump(mode="json"),
            "prior_v6_plan_ref": self.prior_v6_plan_ref.model_dump(mode="json"),
            "v7_plan_ref": self.v7_plan_ref.model_dump(mode="json"),
            "prior_progress_hash": self.prior_progress_hash,
            "missing_v6_parts": list(self.missing_v6_parts),
            "raw_static_gaps": list(self.raw_static_gaps),
            "effective_python_gaps": list(self.effective_python_gaps),
            "surfaces": [row.to_json() for row in self.surfaces],
            "pending_candidate_count": self.pending_candidate_count,
            "pending_child_count": self.pending_child_count,
            "complete": self.complete,
        }


def _validated_v7_part(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    index_ref: StoredDataRef,
    plan: Mapping[str, object],
    target: Mapping[str, object],
    expected: Mapping[str, object],
    row: SurfaceExplorationProgressRecord,
    artifacts: SimpleArtifactRepository,
) -> tuple[tuple[dict[str, object], ...], tuple[StoredDataRef, ...], str | None, str]:
    invalid = "SURFACE_COVERAGE_V5_PROGRESS_INVALID"
    surface_id = expected.get("surface_id")
    if (
        row.proposal_version != 7
        or row.surface_id != surface_id
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
        raise ValueError(invalid)
    context_ref = _ref(identity, row.context_hash)
    graph_ref = _ref(identity, cast(str, target["graph_hash"]))
    context = _read_object(artifacts, context_ref, 64 * 1024)
    graph = _read_object(artifacts, graph_ref, _MAX_OBJECT)
    result = _read_object(artifacts, row.result_ref, 1024 * 1024)
    if (
        context.get("kind") != "simple_surface_context_v7"
        or context.get("analysis_id") != identity.analysis_id
        or context.get("workspace_id") != identity.workspace_id
        or context.get("commit_id") != identity.commit_id
        or context.get("scope") != plan.get("scope")
        or context.get("scope_fingerprint") != index.scope_fingerprint
        or context.get("static_bundle_hash") != index.static_bundle_hash
        or context.get("ast_manifest_hash") != index.ast_manifest_hash
        or context.get("surface_index_hash") != index_ref.content_hash
        or context.get("surface_id") != surface_id
        or context.get("graph_hash") != target.get("graph_hash")
        or context.get("graph_semantics_revision") != "v5-source-bound-4"
        or context.get("plan_binding_hash") != plan.get("plan_binding_hash")
        or context.get("parent_progress_hash") != target.get("parent_progress_hash")
        or context.get("prior_reasons") != target.get("prior_reasons")
        or context.get("prior_v6_plan_hash") != plan.get("prior_v6_plan_hash")
        or context.get("prior_v4_coverage_hash") != plan.get("prior_v4_coverage_hash")
        or context.get("prior_progress_hash") != plan.get("prior_progress_hash")
        or context.get("review_mode") != target.get("review_mode")
        or context.get("part_index") != expected.get("part_index")
        or context.get("part_count") != expected.get("part_count")
        or context.get("target_path_id") != expected.get("target_path_id")
        or context.get("source_sha256") != expected.get("source_sha256")
        or context.get("unavailable_item_count")
        != sum(
            item.get("target_path_id") == expected.get("target_path_id")
            for item in cast(
                list[dict[str, object]], target.get("unavailable_items", [])
            )
        )
        or result.get("kind") != "simple_surface_hypothesis_result_v7"
        or result.get("analysis_id") != identity.analysis_id
        or result.get("surface_id") != surface_id
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
        or target.get("review_mode") != "STANDARD"
    ):
        raise ValueError(invalid)
    checked = validate_v7_response(
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
            surface_id.encode("utf-8")
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
        or derived_ids != result.get("seed_ids")
        or (row.status == "HYPOTHESES") != bool(derived_ids)
    ):
        raise ValueError(invalid)
    usable_path = (
        checked.verified_path_id
        if checked.status in {"HYPOTHESES", "NO_HYPOTHESIS"}
        and graph.get("proof_semantics_revision") == "v5-source-bound-4"
        and context.get("unavailable_item_count") == 0
        else None
    )
    return (
        checked.verified_roles,
        (context_ref, graph_ref, row.result_ref),
        usable_path,
        checked.status,
    )


def _pending_counts(
    identity: CheckpointIdentity, index: SurfaceIndex, store: SimpleCheckpointStore
) -> tuple[int, int]:
    run = store.require_analysis_run(identity.analysis_id)
    terminal = run.candidate_terminal
    counts = store.candidate_counts(identity, index.scope_fingerprint)
    deep = store.candidate_deep_counts(identity, index.scope_fingerprint)
    candidates = (
        counts.get("PENDING", 0)
        + counts.get("ERROR", 0)
        + sum(deep.get(status, 0) for status in ("PENDING", "RUNNING", "ERROR"))
        + (0 if terminal is not None and terminal.producer_finished else 1)
    )
    children = 0
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
            raise ValueError("SURFACE_COVERAGE_V5_CHILD_PAGE_INVALID")
        children += len(page)
        if len(page) < 100:
            break
        after_id = page[-1]
    return candidates, children


def _relevant_sink_path_ids(
    graph: Mapping[str, object], surface_path: str, surface_line: int
) -> set[str]:
    """Find operational alternatives to the exact indexed sink, not raw graph gaps."""

    raw_paths = graph.get("paths")
    if not isinstance(raw_paths, list):
        raise ValueError("SURFACE_COVERAGE_V5_GRAPH_PATHS_INVALID")
    relevant: set[str] = set()
    for raw_path in raw_paths:
        if not isinstance(raw_path, dict) or not isinstance(
            raw_path.get("path_id"), str
        ):
            raise ValueError("SURFACE_COVERAGE_V5_GRAPH_PATHS_INVALID")
        steps = raw_path.get("steps")
        if not isinstance(steps, list) or any(
            not isinstance(step, dict) for step in steps
        ):
            raise ValueError("SURFACE_COVERAGE_V5_GRAPH_PATHS_INVALID")
        if any(step.get("role") == "ROUTE_ENTRY" for step in steps) and any(
            step.get("role") == "SINK"
            and step.get("path") == surface_path
            and step.get("line") == surface_line
            for step in steps
        ):
            relevant.add(raw_path["path_id"])
    return relevant


def _has_unresolved_relevant_graph_gap(
    graph: Mapping[str, object], surface_path: str, relevant_path_ids: set[str]
) -> bool:
    """Treat unmaterialized gaps on the sink or its known route as unresolved."""

    paths = cast(list[dict[str, object]], graph["paths"])
    linked_files = {surface_path}
    for path in paths:
        if path["path_id"] in relevant_path_ids:
            linked_files.update(
                cast(str, step["path"])
                for step in cast(list[dict[str, object]], path["steps"])
            )
    raw_gaps = graph.get("gaps")
    if not isinstance(raw_gaps, list):
        raise ValueError("SURFACE_COVERAGE_V5_GRAPH_GAPS_INVALID")
    for gap in raw_gaps:
        if not isinstance(gap, dict):
            raise ValueError("SURFACE_COVERAGE_V5_GRAPH_GAPS_INVALID")
        gap_path = gap.get("path")
        if gap_path is None or gap_path in linked_files:
            return True
        if not isinstance(gap_path, str):
            raise ValueError("SURFACE_COVERAGE_V5_GRAPH_GAPS_INVALID")
    return False


def _completed_inconclusive_child(
    identity: CheckpointIdentity,
    hypothesis_id: str,
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
) -> dict[str, object] | None:
    """Bind a terminal inconclusive outcome to its unchanged checkpoint and CAS.

    An initial free-text prerequisite cannot distinguish an unproven attack
    precondition from an execution-environment failure. Only a terminal PoC
    whose preceding checkpoints and exact input chain survived is admissible.
    """

    child = identity.model_copy(update={"hypothesis_id": hypothesis_id})
    child_artifacts = SimpleArtifactRepository(
        artifacts.data_dir, child, create_dirs=False
    )
    checkpoints = {
        stage: checkpoint
        for stage in HYPOTHESIS_STAGES
        if (checkpoint := store.get(child, stage)) is not None
    }
    hold = [
        checkpoint
        for checkpoint in checkpoints.values()
        if checkpoint.verdict == "HOLD"
    ]
    if len(hold) != 1:
        return None
    terminal = hold[0]
    if terminal.stage is not SimpleStage.POC_EXECUTION_DONE or any(
        checkpoint.status is not StageStatus.SUCCEEDED
        or checkpoint.stage_version != STAGE_VERSION[checkpoint.stage]
        or checkpoint.identity != child
        or HYPOTHESIS_STAGES.index(stage) > HYPOTHESIS_STAGES.index(terminal.stage)
        for stage, checkpoint in checkpoints.items()
    ):
        return None
    required_stages = (
        SimpleStage.PRO_CON_DONE,
        SimpleStage.VERIFICATION_INITIAL_DONE,
        SimpleStage.POC_CANDIDATE_DONE,
        SimpleStage.POC_EXECUTION_DONE,
    )
    if any(stage not in checkpoints for stage in required_stages):
        return None
    registered_ref = store.registered_hypothesis_ref(identity, hypothesis_id)
    pro_con_inputs = checkpoints[SimpleStage.PRO_CON_DONE].input_refs
    if (
        registered_ref is None
        or not pro_con_inputs
        or pro_con_inputs[0] != registered_ref
    ):
        return None
    for previous_stage, following_stage in zip(
        required_stages, required_stages[1:], strict=False
    ):
        previous = checkpoints[previous_stage]
        following = checkpoints[following_stage]
        if not previous.output_refs or (
            following.input_refs[: len(previous.output_refs)] != previous.output_refs
        ):
            return None
    candidate = checkpoints[SimpleStage.POC_CANDIDATE_DONE]
    if len(candidate.output_refs) < 2:
        return None
    candidate_ref, content_ref = candidate.output_refs[:2]
    try:
        proposal = json.loads(child_artifacts.read_prompt_proposal(registered_ref))
        if (
            proposal.get("analysis_id") != identity.analysis_id
            or proposal.get("hypothesis_id") != hypothesis_id
        ):
            return None
        candidate_data = json.loads(
            child_artifacts.read_bounded(candidate_ref, _MAX_OBJECT)
        )
        execution_data = json.loads(
            child_artifacts.read_bounded(terminal.output_refs[0], _MAX_OBJECT)
        )
        if (
            not isinstance(candidate_data, dict)
            or candidate_data.get("kind") != "simple_poc_candidate"
            or not isinstance(execution_data, dict)
            or execution_data.get("kind") != "simple_poc_execution"
        ):
            raise ValueError("SURFACE_COVERAGE_V5_CHILD_EVIDENCE_INVALID")
        if (
            candidate_data.get("content_ref") != content_ref.model_dump(mode="json")
            or execution_data.get("candidate_ref")
            != candidate_ref.model_dump(mode="json")
            or execution_data.get("content_ref") != content_ref.model_dump(mode="json")
        ):
            return None
        if child_artifacts.verified_terminal_poc_outcome(terminal) != "INCONCLUSIVE":
            raise ValueError("SURFACE_COVERAGE_V5_CHILD_EVIDENCE_INVALID")
    except (OSError, ValueError, TypeError, UnicodeError, IndexError) as error:
        raise ValueError("SURFACE_COVERAGE_V5_CHILD_EVIDENCE_INVALID") from error
    for checkpoint in checkpoints.values():
        for ref in checkpoint.output_refs:
            child_artifacts.read(ref)
    return {
        "hypothesis_id": hypothesis_id,
        "stage": terminal.stage.value,
        "checkpoint_sha256": hashlib.sha256(canonical_bytes(terminal)).hexdigest(),
        "output_refs": [ref.model_dump(mode="json") for ref in terminal.output_refs],
    }


def evaluate_surface_coverage_v5(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    index_ref: StoredDataRef,
    prior_v4_ref: StoredDataRef,
    prior_v4: SurfaceCoverageV4,
    prior_v6_plan_ref: StoredDataRef,
    prior_v6_plan: Mapping[str, object],
    v7_plan_ref: StoredDataRef,
    v7_plan: Mapping[str, object],
    progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord],
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
) -> SurfaceCoverageV5:
    """Certify only source-bound v7 parts against one pinned parent snapshot."""

    invalid = "SURFACE_COVERAGE_V5_PLAN_INVALID"
    try:
        if identity != artifacts.identity or identity.hypothesis_id is not None:
            raise ValueError("identity mismatch")
        for ref, value in (
            (index_ref, index.to_json()),
            (prior_v4_ref, prior_v4.to_json()),
            (prior_v6_plan_ref, prior_v6_plan),
            (v7_plan_ref, v7_plan),
        ):
            if (
                not _bound_ref(ref, identity)
                or _read_object(artifacts, ref, _MAX_OBJECT) != value
            ):
                raise ValueError("unbound parent or plan")
        old_progress = {
            key: row for key, row in progress.items() if row.proposal_version <= 6
        }
        if (
            prior_progress_snapshot_hash(old_progress)
            != v7_plan.get("prior_progress_hash")
            or missing_v6_part_set(prior_v6_plan, old_progress)
            != v7_plan.get("missing_v6_parts")
            or v7_plan.get("prior_v4_coverage_ref")
            != prior_v4_ref.model_dump(mode="json")
            or v7_plan.get("prior_v6_plan_ref")
            != prior_v6_plan_ref.model_dump(mode="json")
            or v7_plan.get("index_ref") != index_ref.model_dump(mode="json")
        ):
            raise ValueError("parent snapshot changed")
        raw_targets = v7_plan.get("targets")
        raw_parts = v7_plan.get("expected_parts")
        if (
            not isinstance(raw_targets, list)
            or any(not isinstance(row, dict) for row in raw_targets)
            or not isinstance(raw_parts, list)
            or any(not isinstance(row, dict) for row in raw_parts)
        ):
            raise ValueError("invalid v7 rows")
        targets = cast(list[dict[str, object]], raw_targets)
        parts = cast(list[dict[str, object]], raw_parts)
        target_map = {cast(str, row["surface_id"]): row for row in targets}
        if len(target_map) != len(targets):
            raise ValueError("duplicate v7 target")
        graphs = {
            surface_id: _read_object(
                artifacts, _ref(identity, cast(str, target["graph_hash"])), _MAX_OBJECT
            )
            for surface_id, target in target_map.items()
        }
        reconstructed, _ = prepare_surface_enrichment_v7(
            identity,
            cast(str, v7_plan["scope"]),
            index,
            index_ref,
            prior_v6_plan_ref,
            prior_v6_plan,
            prior_v4_ref,
            prior_v4,
            old_progress,
            graphs,
            required_graph_revision="v5-source-bound-4",
        )
        if reconstructed != v7_plan:
            raise ValueError("v7 plan changed")
        expected: dict[tuple[str, str], dict[str, object]] = {}
        for part in parts:
            key = (cast(str, part["surface_id"]), cast(str, part["context_id"]))
            if key in expected or key[0] not in target_map:
                raise ValueError("duplicate or unbound v7 part")
            expected[key] = part
        if any(
            key != (row.surface_id, row.context_id) for key, row in progress.items()
        ):
            raise ValueError("malformed progress key")
        v7_rows = {
            key: row for key, row in progress.items() if row.proposal_version == 7
        }
        if any(key not in expected for key in v7_rows) or any(
            row.proposal_version > 7 for row in progress.values()
        ):
            raise ValueError("extra v7 progress")
        missing_surfaces = {
            row["surface_id"]
            for row in cast(list[dict[str, str]], v7_plan["missing_v6_parts"])
        }
        proofs: list[SurfaceProofV5] = []
        for surface, old in zip(index.surfaces, prior_v4.surfaces, strict=True):
            reasons = set(old.unresolved_reason_codes)
            roles = list(old.verified_roles)
            refs = list(old.evidence_refs)
            classification = old.review_classification
            all_relevant_paths_verified = False
            if old.surface_id in target_map:
                target = target_map[old.surface_id]
                surface_parts = [
                    part for part in parts if part["surface_id"] == old.surface_id
                ]
                claimed_path_ids: set[str] = set()
                all_present = all(
                    (old.surface_id, cast(str, part["context_id"])) in v7_rows
                    for part in surface_parts
                )
                for part in surface_parts:
                    row = v7_rows.get((old.surface_id, cast(str, part["context_id"])))
                    if row is None:
                        reasons.add("SURFACE_PART_PENDING")
                        continue
                    checked_roles, checked_refs, path_id, part_classification = (
                        _validated_v7_part(
                            identity,
                            index,
                            index_ref,
                            v7_plan,
                            target,
                            part,
                            row,
                            artifacts,
                        )
                    )
                    roles.extend(checked_roles)
                    refs.extend(checked_refs)
                    classification = part_classification
                    if path_id is not None:
                        claimed_path_ids.add(path_id)
                relevant_path_ids = _relevant_sink_path_ids(
                    graphs[old.surface_id], surface.path, surface.line
                )
                unreviewed_path_ids = relevant_path_ids.difference(claimed_path_ids)
                if unreviewed_path_ids:
                    reasons.add("UNREVIEWED_RELEVANT_PATH")
                if _has_unresolved_relevant_graph_gap(
                    graphs[old.surface_id], surface.path, relevant_path_ids
                ):
                    reasons.add("UNRESOLVED_RELEVANT_GRAPH_GAP")
                if old.surface_id in missing_surfaces:
                    reasons.add("PRIOR_V6_PART_MISSING")
                    reasons.add("SURFACE_PART_PENDING")
                elif (
                    all_present
                    and claimed_path_ids
                    and not target.get("unavailable_items")
                ):
                    reasons.difference_update(_GRAPH_REASONS)
                elif all_present:
                    reasons.add("CONNECTED_ROLE_PROOF_MISSING")
                if target.get("unavailable_items"):
                    reasons.add("SURFACE_SOURCE_UNAVAILABLE")
                all_relevant_paths_verified = (
                    all_present
                    and bool(relevant_path_ids)
                    and relevant_path_ids.issubset(claimed_path_ids)
                    and not target.get("unavailable_items")
                    and old.surface_id not in missing_surfaces
                    and not _has_unresolved_relevant_graph_gap(
                        graphs[old.surface_id], surface.path, relevant_path_ids
                    )
                    and not reasons.difference(_CHILD_REASONS)
                )
            elif old.coverage_status == "COVERED":
                # The immutable v4 row used older route semantics. It remains
                # provenance, not a v7 all-path certificate.
                reasons.add("INHERITED_GRAPH_SEMANTICS_UNVERIFIED")
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
                # The old rows are hash-pinned above. Replace historical
                # CHILD_* only with the current state of those same IDs.
                reasons.difference_update(_CHILD_REASONS)
            completed_inconclusive_children: list[dict[str, object]] = []
            for child_id in sorted(related):
                child_reasons = _child_reasons(identity, child_id, store, artifacts)
                if child_reasons == ("CHILD_HOLD",) and all_relevant_paths_verified:
                    completed = _completed_inconclusive_child(
                        identity, child_id, store, artifacts
                    )
                    if completed is not None:
                        completed_inconclusive_children.append(completed)
                        continue
                reasons.update(child_reasons)
            if "CHILD_ERROR" in reasons:
                raise ValueError("v7 child error")
            status: Literal["COVERED", "UNCOVERED", "INSUFFICIENT"] = (
                "COVERED"
                if not reasons
                else "UNCOVERED"
                if old.coverage_status == "UNCOVERED"
                else "INSUFFICIENT"
            )
            proofs.append(
                SurfaceProofV5(
                    surface_id=old.surface_id,
                    path=old.path,
                    line=old.line,
                    coverage_status=status,
                    prior_v4_status=old.coverage_status,
                    review_classification=classification,
                    verified_roles=tuple(roles),
                    evidence_refs=tuple(dict.fromkeys(refs)),
                    unresolved_reason_codes=tuple(sorted(reasons)),
                    completed_inconclusive_children=tuple(
                        completed_inconclusive_children
                    ),
                )
            )
        pending_candidates, pending_children = _pending_counts(identity, index, store)
        return SurfaceCoverageV5(
            scope_fingerprint=prior_v4.scope_fingerprint,
            static_bundle_hash=prior_v4.static_bundle_hash,
            ast_manifest_hash=prior_v4.ast_manifest_hash,
            candidate_inventory_hash=prior_v4.candidate_inventory_hash,
            candidate_count=prior_v4.candidate_count,
            index_hash=prior_v4.index_hash,
            original_coverage_ref=prior_v4.original_coverage_ref,
            scope_certificate_ref=prior_v4.scope_certificate_ref,
            prior_v4_ref=prior_v4_ref,
            prior_v6_plan_ref=prior_v6_plan_ref,
            v7_plan_ref=v7_plan_ref,
            prior_progress_hash=cast(str, v7_plan["prior_progress_hash"]),
            missing_v6_parts=tuple(
                cast(list[dict[str, str]], v7_plan["missing_v6_parts"])
            ),
            raw_static_gaps=prior_v4.raw_static_gaps,
            effective_python_gaps=prior_v4.effective_python_gaps,
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


def _frozen_parent_v5_from_json(raw: Mapping[str, object]) -> SurfaceCoverageV5:
    """Parse old saved bytes exactly, without consulting mutable child counts."""

    if (
        raw.get("kind") != "simple_attack_surface_coverage_v5"
        or any(
            not isinstance(raw.get(field), str)
            for field in (
                "scope_fingerprint",
                "static_bundle_hash",
                "ast_manifest_hash",
                "candidate_inventory_hash",
                "index_hash",
                "prior_progress_hash",
            )
        )
        or any(
            type(raw.get(field)) is not int or cast(int, raw[field]) < 0
            for field in (
                "candidate_count",
                "pending_candidate_count",
                "pending_child_count",
            )
        )
    ):
        raise ValueError("SURFACE_COVERAGE_V6_PARENT_INVALID")
    for field in (
        "missing_v6_parts",
        "raw_static_gaps",
        "effective_python_gaps",
    ):
        value = raw.get(field)
        if not isinstance(value, list) or any(
            not isinstance(row, dict) for row in value
        ):
            raise ValueError("SURFACE_COVERAGE_V6_PARENT_INVALID")
    raw_rows = raw.get("surfaces")
    if not isinstance(raw_rows, list):
        raise ValueError("SURFACE_COVERAGE_V6_PARENT_INVALID")
    proofs: list[SurfaceProofV5] = []
    for row in raw_rows:
        if not isinstance(row, dict):
            raise ValueError("SURFACE_COVERAGE_V6_PARENT_INVALID")
        if row.get("coverage_status") not in {
            "COVERED",
            "UNCOVERED",
            "INSUFFICIENT",
        } or row.get("prior_v4_status") not in {"COVERED", "UNCOVERED", "INSUFFICIENT"}:
            raise ValueError("SURFACE_COVERAGE_V6_PARENT_INVALID")
        if (
            not isinstance(row.get("surface_id"), str)
            or not isinstance(row.get("path"), str)
            or type(row.get("line")) is not int
            or row["line"] < 1
            or row.get("review_classification") is not None
            and not isinstance(row.get("review_classification"), str)
        ):
            raise ValueError("SURFACE_COVERAGE_V6_PARENT_INVALID")
        for field in ("verified_roles", "evidence_refs", "unresolved_reason_codes"):
            if not isinstance(row.get(field), list):
                raise ValueError("SURFACE_COVERAGE_V6_PARENT_INVALID")
        if (
            any(not isinstance(role, dict) for role in row["verified_roles"])
            or any(
                not isinstance(reason, str) for reason in row["unresolved_reason_codes"]
            )
            or not isinstance(row.get("completed_inconclusive_children", []), list)
            or any(
                not isinstance(item, dict)
                for item in row.get("completed_inconclusive_children", [])
            )
        ):
            raise ValueError("SURFACE_COVERAGE_V6_PARENT_INVALID")
        proofs.append(
            SurfaceProofV5(
                surface_id=cast(str, row["surface_id"]),
                path=cast(str, row["path"]),
                line=cast(int, row["line"]),
                coverage_status=cast(
                    Literal["COVERED", "UNCOVERED", "INSUFFICIENT"],
                    row["coverage_status"],
                ),
                prior_v4_status=cast(
                    Literal["COVERED", "UNCOVERED", "INSUFFICIENT"],
                    row["prior_v4_status"],
                ),
                review_classification=cast(str | None, row["review_classification"]),
                verified_roles=tuple(
                    cast(list[dict[str, object]], row["verified_roles"])
                ),
                evidence_refs=tuple(
                    StoredDataRef.model_validate(value)
                    for value in cast(list[object], row["evidence_refs"])
                ),
                unresolved_reason_codes=tuple(
                    cast(list[str], row["unresolved_reason_codes"])
                ),
                completed_inconclusive_children=tuple(
                    cast(
                        list[dict[str, object]],
                        row.get("completed_inconclusive_children", []),
                    )
                ),
            )
        )
    parent = SurfaceCoverageV5(
        scope_fingerprint=cast(str, raw["scope_fingerprint"]),
        static_bundle_hash=cast(str, raw["static_bundle_hash"]),
        ast_manifest_hash=cast(str, raw["ast_manifest_hash"]),
        candidate_inventory_hash=cast(str, raw["candidate_inventory_hash"]),
        candidate_count=cast(int, raw["candidate_count"]),
        index_hash=cast(str, raw["index_hash"]),
        original_coverage_ref=StoredDataRef.model_validate(
            raw["original_coverage_ref"]
        ),
        scope_certificate_ref=StoredDataRef.model_validate(
            raw["scope_certificate_ref"]
        ),
        prior_v4_ref=StoredDataRef.model_validate(raw["prior_v4_ref"]),
        prior_v6_plan_ref=StoredDataRef.model_validate(raw["prior_v6_plan_ref"]),
        v7_plan_ref=StoredDataRef.model_validate(raw["v7_plan_ref"]),
        prior_progress_hash=cast(str, raw["prior_progress_hash"]),
        missing_v6_parts=tuple(cast(list[dict[str, str]], raw["missing_v6_parts"])),
        raw_static_gaps=tuple(cast(list[dict[str, object]], raw["raw_static_gaps"])),
        effective_python_gaps=tuple(
            cast(list[dict[str, object]], raw["effective_python_gaps"])
        ),
        surfaces=tuple(proofs),
        pending_candidate_count=cast(int, raw["pending_candidate_count"]),
        pending_child_count=cast(int, raw["pending_child_count"]),
    )
    if parent.to_json() != raw:
        raise ValueError("SURFACE_COVERAGE_V6_PARENT_INVALID")
    return parent


def read_frozen_parent_v5(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    parent_ref: StoredDataRef,
    v7_plan_ref: StoredDataRef,
    v7_plan: Mapping[str, object],
    progress: Mapping[tuple[str, str], SurfaceExplorationProgressRecord],
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
) -> SurfaceCoverageV5:
    """Read the pinned v5 proof without counting newly registered v8 work."""

    invalid = "SURFACE_COVERAGE_V6_PARENT_INVALID"
    try:
        if not _bound_ref(parent_ref, identity) or not _bound_ref(
            v7_plan_ref, identity
        ):
            raise ValueError("parent reference unbound")
        if _read_object(artifacts, v7_plan_ref, _MAX_OBJECT) != v7_plan:
            raise ValueError("v7 plan changed")
        parent = _frozen_parent_v5_from_json(
            _read_object(artifacts, parent_ref, _MAX_OBJECT)
        )
        if (
            parent.v7_plan_ref != v7_plan_ref
            or parent.scope_fingerprint != index.scope_fingerprint
            or parent.static_bundle_hash != index.static_bundle_hash
            or parent.ast_manifest_hash != index.ast_manifest_hash
            or parent.candidate_inventory_hash != index.candidate_inventory_hash
            or parent.candidate_count != index.candidate_count
            or parent.index_hash
            != hashlib.sha256(canonical_bytes(index.to_json())).hexdigest()
            or parent.prior_progress_hash != v7_plan.get("prior_progress_hash")
            or v7_plan.get("prior_v4_coverage_ref")
            != parent.prior_v4_ref.model_dump(mode="json")
            or v7_plan.get("prior_v6_plan_ref")
            != parent.prior_v6_plan_ref.model_dump(mode="json")
            or len(parent.surfaces) != len(index.surfaces)
            or any(
                (old.surface_id, old.path, old.line)
                != (surface.surface_id, surface.path, surface.line)
                for old, surface in zip(parent.surfaces, index.surfaces, strict=True)
            )
        ):
            raise ValueError("parent scope changed")
        old_progress = {
            key: row for key, row in progress.items() if row.proposal_version <= 7
        }
        prior_progress = {
            key: row for key, row in old_progress.items() if row.proposal_version <= 6
        }
        if missing_v7_part_set(v7_plan, old_progress) or prior_progress_snapshot_hash(
            prior_progress
        ) != v7_plan.get("prior_progress_hash"):
            raise ValueError("missing v7 part")
        for row in old_progress.values():
            for ref in (row.result_ref, _ref(identity, row.context_hash)):
                if not _bound_ref(ref, identity):
                    raise ValueError("old progress reference unbound")
                artifacts.read(ref)
        targets = v7_plan.get("targets")
        parts = v7_plan.get("expected_parts")
        if not isinstance(targets, list) or not isinstance(parts, list):
            raise ValueError("v7 plan malformed")
        by_surface = {
            row["surface_id"]: row for row in targets if isinstance(row, dict)
        }
        if len(by_surface) != len(targets):
            raise ValueError("v7 target duplicate")
        index_ref = StoredDataRef.model_validate(v7_plan["index_ref"])
        for part in parts:
            if not isinstance(part, dict):
                raise ValueError("v7 part malformed")
            key = (cast(str, part["surface_id"]), cast(str, part["context_id"]))
            _validated_v7_part(
                identity,
                index,
                index_ref,
                v7_plan,
                by_surface[key[0]],
                part,
                old_progress[key],
                artifacts,
            )
        for proof in parent.surfaces:
            for ref in proof.evidence_refs:
                if not _bound_ref(ref, identity):
                    raise ValueError("parent evidence unbound")
                artifacts.read(ref)
            for completed in proof.completed_inconclusive_children:
                child_id = completed.get("hypothesis_id")
                if not isinstance(child_id, str) or (
                    _completed_inconclusive_child(identity, child_id, store, artifacts)
                    != completed
                ):
                    raise ValueError("old completed child changed")
        pinned_children = v7_plan.get("child_checkpoint_hashes")
        if not isinstance(pinned_children, dict):
            raise ValueError("old child lineage missing")
        checkpoint_rows: dict[str, list[dict[str, object]]] = {
            child_id: [] for child_id in pinned_children
        }
        for checkpoint in store.list_checkpoints(identity.analysis_id):
            child_id = checkpoint.identity.hypothesis_id
            if child_id in checkpoint_rows:
                for ref in (
                    *checkpoint.input_refs,
                    *checkpoint.output_refs,
                    *checkpoint.recovery_decision_refs,
                ):
                    artifacts.read(ref)
                checkpoint_rows[child_id].append(checkpoint.model_dump(mode="json"))
        for child_id, digest in pinned_children.items():
            rows = checkpoint_rows[child_id]
            if (
                not rows
                or not isinstance(digest, str)
                or hashlib.sha256(
                    canonical_bytes(sorted(rows, key=lambda row: str(row["stage"])))
                ).hexdigest()
                != digest
            ):
                raise ValueError("old child checkpoint changed")
        return parent
    except (
        KeyError,
        IndexError,
        OSError,
        TypeError,
        ValueError,
        UnicodeError,
    ) as error:
        raise ValueError(invalid) from error


def verified_saved_coverage_v5(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    coverage_ref: StoredDataRef,
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
) -> SurfaceCoverageV5:
    """Recompute saved v7 coverage from exact current progress and child state."""

    invalid = "SURFACE_COVERAGE_V5_VERIFIED_INVALID"
    try:
        run = store.require_analysis_run(identity.analysis_id)
        terminal = run.candidate_terminal
        plan_ref = run.surface_enrichment_v7_plan_ref
        root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
        if (
            terminal is None
            or terminal.surface_proof_version != 5
            or terminal.surface_coverage_hash != coverage_ref.content_hash
            or plan_ref is None
            or root is None
            or root.status is not StageStatus.SUCCEEDED
            or len(root.output_refs) != 2
            or root.output_refs[1] != coverage_ref
        ):
            raise ValueError("v7 terminal unbound")
        plan = _read_object(artifacts, plan_ref, _MAX_OBJECT)
        index_ref = StoredDataRef.model_validate(plan["index_ref"])
        parent_ref = StoredDataRef.model_validate(plan["prior_v4_coverage_ref"])
        v6_ref = StoredDataRef.model_validate(plan["prior_v6_plan_ref"])
        v6_plan = _read_object(artifacts, v6_ref, _MAX_OBJECT)
        v3_ref = StoredDataRef.model_validate(v6_plan["prior_v3_coverage_ref"])
        v5_ref = StoredDataRef.model_validate(v6_plan["prior_v5_plan_ref"])
        parent = read_saved_coverage_v4(
            artifacts,
            index,
            parent_ref,
            prior_v3_ref=v3_ref,
            prior_v5_plan_ref=v5_ref,
            v6_plan_ref=v6_ref,
        )
        progress = store.list_surface_exploration_progress(
            identity, index.scope_fingerprint
        )
        if run.surface_enrichment_v8_plan_ref is not None:
            # A later review may register new children and rows. Its immutable
            # predecessor is checked against the pinned v7 lineage, not a
            # recomputation using the successor's current child universe.
            current = read_frozen_parent_v5(
                identity,
                index,
                coverage_ref,
                plan_ref,
                plan,
                progress,
                store,
                artifacts,
            )
        else:
            if any(row.proposal_version > 7 for row in progress.values()):
                raise ValueError("unbound successor progress")
            current = evaluate_surface_coverage_v5(
                identity,
                index,
                index_ref,
                parent_ref,
                parent,
                v6_ref,
                v6_plan,
                plan_ref,
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
            raise ValueError("v7 terminal differs from proof")
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
