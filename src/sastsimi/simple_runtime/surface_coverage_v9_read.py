"""Independent replay of a saved V11 child-evidence successor certificate.

The live terminal and progress rows are claims. No child resolution is counted
until its exact predecessor, saved CAS result and runtime lineage are replayed.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
from collections.abc import Mapping
from typing import cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .attack_surfaces import SurfaceIndex
from .models import (
    STAGE_VERSION,
    CandidateTerminal,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
)
from .store import ChildRevalidationProgressRecordV11, SimpleCheckpointStore
from .surface_child_evidence_v11 import (
    ChildHoldTargetV11,
    collect_child_hold_targets_v11,
    recount_incomplete_hypotheses_v11,
)
from .surface_coverage_v5 import _completed_inconclusive_child
from .surface_coverage_v8_read import verified_saved_coverage_v8
from .surface_coverage_v9 import (
    ChildDispositionV11,
    ChildStatusV11,
    SurfaceCoverageV9,
    evaluate_surface_coverage_v9,
)
from .surface_enrichment_v9 import _digest
from .surface_enrichment_v10_bindings import v9_progress_snapshot_hash
from .surface_enrichment_v11 import prepare_surface_enrichment_v11

_MAX_OBJECT = 16 * 1024 * 1024


def _object(
    artifacts: SimpleArtifactRepository, ref: StoredDataRef
) -> dict[str, object]:
    payload = json.loads(artifacts.read_bounded(ref, _MAX_OBJECT))
    if not isinstance(payload, dict):
        raise ValueError("SURFACE_COVERAGE_V9_OBJECT_INVALID")
    return payload


def _verified_supported_final_true(
    identity: CheckpointIdentity,
    old: StageCheckpoint,
    plan_ref: StoredDataRef,
    record: ChildRevalidationProgressRecordV11,
    result: dict[str, object],
    evidence_refs: tuple[StoredDataRef, ...],
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
) -> bool:
    """Check the old supported PoC and the new exact final-verification CAS."""

    if (
        old.stage is not SimpleStage.VERIFICATION_FINAL_DONE
        or old.verdict != "HOLD"
        or not old.output_refs
        or result.get("new_checkpoint") is None
    ):
        return False
    child = old.identity
    child_artifacts = SimpleArtifactRepository(
        artifacts.data_dir, child, create_dirs=False
    )
    try:
        fresh = StageCheckpoint.model_validate_json(
            json.dumps(result["new_checkpoint"])
        )
        candidate = store.require(child, SimpleStage.POC_CANDIDATE_DONE)
        dynamic = store.require(child, SimpleStage.POC_EXECUTION_DONE)
        pro_con = store.require(child, SimpleStage.PRO_CON_DONE)
        initial = store.require(child, SimpleStage.VERIFICATION_INITIAL_DONE)
        registered = store.registered_hypothesis_ref(
            identity, child.hypothesis_id or ""
        )
        if (
            fresh.identity != child
            or fresh.stage is not SimpleStage.VERIFICATION_FINAL_DONE
            or fresh.stage_version != STAGE_VERSION[fresh.stage]
            or fresh.status is not StageStatus.SUCCEEDED
            or fresh.attempt_id != record.attempt_id
            or fresh.verdict != "TRUE"
            or len(fresh.output_refs) != 1
            or old.stage_version != STAGE_VERSION[old.stage]
            or pro_con.status is not StageStatus.SUCCEEDED
            or initial.status is not StageStatus.SUCCEEDED
            or initial.verdict == "HOLD"
            or candidate.status is not StageStatus.SUCCEEDED
            or candidate.stage_version != STAGE_VERSION[candidate.stage]
            or dynamic.status is not StageStatus.SUCCEEDED
            or dynamic.stage_version != STAGE_VERSION[dynamic.stage]
            or not pro_con.input_refs
            or pro_con.input_refs[0] != registered
            or not pro_con.output_refs
            or initial.input_refs[: len(pro_con.output_refs)] != pro_con.output_refs
            or not initial.output_refs
            or candidate.input_refs[: len(initial.output_refs)] != initial.output_refs
            or len(candidate.output_refs) < 2
            or dynamic.input_refs[:2] != candidate.output_refs[:2]
            or len(dynamic.output_refs) != 4
            or dynamic.validated_poc_ref != dynamic.output_refs[2]
            or old.input_refs[: len(dynamic.output_refs)] != dynamic.output_refs
            or fresh.validated_poc_ref != dynamic.validated_poc_ref
            or not {*old.output_refs, *dynamic.output_refs, plan_ref}.issubset(
                fresh.input_refs
            )
            or not {
                *old.output_refs,
                *dynamic.output_refs,
                *fresh.output_refs,
            }.issubset(evidence_refs)
        ):
            return False
        candidate_ref, content_ref = candidate.output_refs[:2]
        execution_ref, interpretation_ref, validated_ref, cleanup_ref = (
            dynamic.output_refs
        )
        candidate_data = _object(child_artifacts, candidate_ref)
        execution = _object(child_artifacts, execution_ref)
        interpretation = _object(child_artifacts, interpretation_ref)
        validated = _object(child_artifacts, validated_ref)
        cleanup = _object(child_artifacts, cleanup_ref)
        final_output = _object(child_artifacts, fresh.output_refs[0])
        child_artifacts.read_bounded(content_ref, _MAX_OBJECT)
        child_artifacts.read_prompt_proposal(registered)
        for checkpoint in (pro_con, initial, candidate, dynamic, old):
            for ref in checkpoint.output_refs:
                child_artifacts.read_bounded(ref, _MAX_OBJECT)
        outcome = interpretation.get("result")
        assessment = final_output.get("result")
        source_refs = final_output.get("source_refs")
        expected_source_refs = {
            ref.model_dump(mode="json")["content_hash"]
            for ref in (*old.output_refs, execution_ref, validated_ref)
        }
        supplied_source_hashes = (
            {StoredDataRef.model_validate(item).content_hash for item in source_refs}
            if isinstance(source_refs, list)
            else set()
        )
        return (
            candidate_data.get("kind") == "simple_poc_candidate"
            and candidate_data.get("content_ref") == content_ref.model_dump(mode="json")
            and execution.get("kind") == "simple_poc_execution"
            and execution.get("candidate_ref") == candidate_ref.model_dump(mode="json")
            and execution.get("content_ref") == content_ref.model_dump(mode="json")
            and execution.get("attempt_id") == dynamic.attempt_id
            and execution.get("timed_out") is False
            and type(execution.get("exit_code")) is int
            and execution.get("exit_code") == 0
            and interpretation.get("kind") == "simple_dynamic_interpretation"
            and interpretation.get("execution_ref")
            == execution_ref.model_dump(mode="json")
            and isinstance(outcome, dict)
            and outcome.get("outcome") == "SUPPORTED"
            and validated.get("kind") == "simple_validated_poc"
            and validated.get("candidate_ref") == candidate_ref.model_dump(mode="json")
            and validated.get("content_ref") == content_ref.model_dump(mode="json")
            and validated.get("execution_ref") == execution_ref.model_dump(mode="json")
            and validated.get("interpretation_ref")
            == interpretation_ref.model_dump(mode="json")
            and validated.get("attempt_id") == dynamic.attempt_id
            and cleanup.get("kind") == "simple_container_cleanup"
            and cleanup.get("attempt_id") == dynamic.attempt_id
            and cleanup.get("status") == "REMOVED"
            and final_output.get("kind") == "simple_verification_result"
            and final_output.get("attempt_id") == fresh.attempt_id
            and isinstance(assessment, dict)
            and assessment.get("verdict") == "TRUE"
            and assessment.get("unresolved_conditions") == []
            and expected_source_refs <= supplied_source_hashes
        )
    except (KeyError, LookupError, OSError, TypeError, ValueError, UnicodeError):
        return False


def verified_child_dispositions_v11(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    plan_ref: StoredDataRef,
    targets: tuple[ChildHoldTargetV11, ...],
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
) -> Mapping[tuple[str, SimpleStage], ChildDispositionV11]:
    """Replay each saved child result before V11 promotion or read.

    An absent or in-flight row stays PENDING. A RESOLVED row is never accepted
    from a string label alone: its exact old checkpoint and its branch-specific
    runtime/evidence chain must still verify.
    """

    invalid = "SURFACE_CHILD_V11_VERIFIED_INVALID"
    try:
        if identity.hypothesis_id is not None or identity != artifacts.identity:
            raise ValueError("root identity invalid")
        keys = [(target.hypothesis_id, target.stage) for target in targets]
        surface_ids = {row.surface_id for row in index.surfaces}
        if len(keys) != len(set(keys)) or any(
            not target.surface_ids or not set(target.surface_ids) <= surface_ids
            for target in targets
        ):
            raise ValueError("target set invalid")
        plan = _object(artifacts, plan_ref)
        if (
            plan.get("kind") != "simple_surface_enrichment_plan_v11"
            or plan.get("analysis_id") != identity.analysis_id
            or plan.get("workspace_id") != identity.workspace_id
            or plan.get("commit_id") != identity.commit_id
            or plan.get("scope_fingerprint") != index.scope_fingerprint
            or plan.get("index_hash") != _digest(index.to_json())
            or plan.get("targets")
            != [
                {
                    "hypothesis_id": target.hypothesis_id,
                    "stage": target.stage.value,
                    "surface_ids": list(target.surface_ids),
                    "checkpoint_hash": target.checkpoint_hash,
                }
                for target in targets
            ]
        ):
            raise ValueError("plan target set unbound")
        rows = store.list_surface_child_revalidation_v11(
            identity, index.scope_fingerprint, plan_ref
        )
        if not set(rows) <= set(keys):
            raise ValueError("unplanned progress row")
        verified: dict[tuple[str, SimpleStage], ChildDispositionV11] = {}
        for target in targets:
            key = (target.hypothesis_id, target.stage)
            child = identity.model_copy(update={"hypothesis_id": target.hypothesis_id})
            old = store.get(child, target.stage)
            if (
                old is None
                or old.identity != child
                or old.stage is not target.stage
                or old.status is not StageStatus.SUCCEEDED
                or old.verdict != "HOLD"
                or hashlib.sha256(canonical_bytes(old)).hexdigest()
                != target.checkpoint_hash
            ):
                raise ValueError("old HOLD checkpoint changed")
            record = rows.get(key)
            if record is None:
                continue
            if (
                not isinstance(record, ChildRevalidationProgressRecordV11)
                or (record.hypothesis_id, record.stage) != key
                or record.checkpoint_hash != target.checkpoint_hash
                or record.status
                not in {"PENDING", "RUNNING", "RESOLVED", "STILL_HOLD", "ERROR"}
            ):
                raise ValueError("progress row changed")
            if record.status in {"PENDING", "RUNNING"}:
                if record.result_ref is not None or record.reason_code is not None:
                    raise ValueError("in-flight result invalid")
                verified[key] = ChildDispositionV11(
                    checkpoint_hash=target.checkpoint_hash,
                    status="PENDING",
                    reason_code=(
                        "REVALIDATION_IN_FLIGHT"
                        if record.status == "RUNNING"
                        else "REVALIDATION_NOT_RUN"
                    ),
                    evidence_hash=None,
                )
                continue
            if (
                record.result_ref is None
                or not record.reason_code
                or not record.attempt_id
            ):
                raise ValueError("result record incomplete")
            result = _object(artifacts, record.result_ref)
            if (
                result.get("kind") != "simple_surface_child_revalidation_result_v11"
                or result.get("plan_ref") != plan_ref.model_dump(mode="json")
                or result.get("hypothesis_id") != target.hypothesis_id
                or result.get("stage") != target.stage.value
                or result.get("checkpoint_hash") != target.checkpoint_hash
                or result.get("status") != record.status
                or result.get("reason_code") != record.reason_code
                or result.get("attempt_id") != record.attempt_id
                or not isinstance(result.get("evidence_refs"), list)
            ):
                raise ValueError("result artifact unbound")
            evidence_refs = tuple(
                StoredDataRef.model_validate(value)
                for value in cast(list[object], result["evidence_refs"])
            )
            child_artifacts = SimpleArtifactRepository(
                artifacts.data_dir, child, create_dirs=False
            )
            for ref in evidence_refs:
                child_artifacts.read_bounded(ref, _MAX_OBJECT)
            if record.status == "RESOLVED":
                if (
                    target.stage is SimpleStage.POC_EXECUTION_DONE
                    and record.reason_code == "VERIFIED_POC_INCONCLUSIVE"
                ):
                    lineage = _completed_inconclusive_child(
                        identity, target.hypothesis_id, store, artifacts
                    )
                    if (
                        lineage is None
                        or lineage.get("checkpoint_sha256") != target.checkpoint_hash
                        or evidence_refs != old.output_refs
                        or result.get("new_checkpoint") is not None
                    ):
                        raise ValueError("PoC inconclusive lineage unverified")
                else:
                    # Final TRUE is not terminal for the analysis. It still
                    # requires finding, tech/scope gates and report lineage.
                    raise ValueError("unproved resolved or downstream reason")
                verified[key] = ChildDispositionV11(
                    checkpoint_hash=target.checkpoint_hash,
                    status="RESOLVED",
                    reason_code=record.reason_code,
                    evidence_hash=record.result_ref.content_hash,
                )
            elif record.status in {"STILL_HOLD", "ERROR"}:
                if result.get("new_checkpoint") is not None:
                    raise ValueError("nonterminal result carries checkpoint")
                verified[key] = ChildDispositionV11(
                    checkpoint_hash=target.checkpoint_hash,
                    status=cast(ChildStatusV11, record.status),
                    reason_code=record.reason_code,
                    evidence_hash=None,
                )
        return verified
    except (
        KeyError,
        LookupError,
        OSError,
        TypeError,
        ValueError,
        UnicodeError,
    ) as error:
        raise ValueError(invalid) from error


def verified_saved_coverage_v9(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    coverage_ref: StoredDataRef,
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
) -> SurfaceCoverageV9:
    """Return only exactly replayed V11 coverage, else fail closed."""

    invalid = "SURFACE_COVERAGE_V9_VERIFIED_INVALID"
    try:
        run = store.require_analysis_run(identity.analysis_id)
        terminal = run.candidate_terminal
        plan_ref = run.surface_enrichment_v11_plan_ref
        root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
        if (
            identity.hypothesis_id is not None
            or identity != artifacts.identity
            or identity.workspace_id != run.workspace_id
            or identity.commit_id != run.commit_id
            or terminal is None
            or terminal.surface_proof_version != 9
            or not terminal.producer_finished
            or terminal.surface_coverage_hash != coverage_ref.content_hash
            or terminal.surface_index_hash is None
            or terminal.bundle_hash != index.static_bundle_hash
            or terminal.scope_fingerprint != index.scope_fingerprint
            or run.candidate_scope_fingerprint != index.scope_fingerprint
            or plan_ref is None
            or run.surface_enrichment_v10_plan_ref is None
            or root is None
            or root.identity != identity
            or root.stage is not SimpleStage.HYPOTHESIS_DONE
            or root.status is not StageStatus.SUCCEEDED
            or len(root.output_refs) != 2
            or root.output_refs[1] != coverage_ref
            or root.output_refs[0].content_hash != terminal.surface_index_hash
        ):
            raise ValueError("v11 terminal unbound")
        plan = _object(artifacts, plan_ref)
        parent_plan_ref = StoredDataRef.model_validate(plan["v10_plan_ref"])
        parent_ref = StoredDataRef.model_validate(plan["v10_coverage_ref"])
        predecessor_terminal = CandidateTerminal.model_validate_json(
            json.dumps(plan["v10_terminal"])
        )
        predecessor_root = StageCheckpoint.model_validate_json(
            json.dumps(plan["v10_root"])
        )
        if (
            parent_plan_ref != run.surface_enrichment_v10_plan_ref
            or predecessor_terminal.surface_coverage_hash != parent_ref.content_hash
            or predecessor_terminal.surface_index_hash
            != root.output_refs[0].content_hash
            or predecessor_terminal.scope_certificate_hash
            != terminal.scope_certificate_hash
            or predecessor_root.output_refs != (root.output_refs[0], parent_ref)
            or root
            != predecessor_root.model_copy(
                update={
                    "output_refs": root.output_refs,
                    "updated_at": root.updated_at,
                }
            )
        ):
            raise ValueError("v11 predecessor unbound")
        parent = verified_saved_coverage_v8(
            identity,
            index,
            parent_ref,
            store,
            artifacts,
            predecessor_terminal=predecessor_terminal,
            predecessor_root=predecessor_root,
        )
        progress = store.list_surface_exploration_progress(
            identity, index.scope_fingerprint
        )
        v10_plan = _object(artifacts, parent_plan_ref)
        v9_plan_ref = StoredDataRef.model_validate(v10_plan["v9_plan_ref"])
        v9_plan = _object(artifacts, v9_plan_ref)
        progress_hash = v9_progress_snapshot_hash(v9_plan, progress)
        targets, child_snapshot_hash = collect_child_hold_targets_v11(
            identity, index, progress, store
        )
        expected_plan = prepare_surface_enrichment_v11(
            identity,
            parent,
            parent_plan_ref,
            parent_ref,
            predecessor_terminal,
            predecessor_root,
            targets,
            child_snapshot_hash,
            progress_hash,
        )
        if plan != expected_plan:
            raise ValueError("v11 plan changed")
        dispositions = verified_child_dispositions_v11(
            identity, index, plan_ref, targets, store, artifacts
        )
        current = evaluate_surface_coverage_v9(
            parent,
            targets,
            dispositions,
            current_pending_child_count=recount_incomplete_hypotheses_v11(
                identity, store
            ),
        )
        counts = {
            status: sum(row.coverage_status == status for row in current.surfaces)
            for status in ("COVERED", "UNCOVERED", "INSUFFICIENT")
        }
        expected_terminal = predecessor_terminal.model_copy(
            update={
                "status": (
                    "COMPLETE"
                    if current.complete and run.static_disposition == "FULL"
                    else "PARTIAL"
                ),
                "surface_coverage_hash": coverage_ref.content_hash,
                "surface_counts": counts,
                "surface_proof_version": 9,
                "pending_child_count": current.pending_child_count,
            }
        )
        if (
            _object(artifacts, coverage_ref) != current.to_json()
            or terminal != expected_terminal
        ):
            raise ValueError("v11 terminal differs from proof")
        return current
    except (
        KeyError,
        LookupError,
        OSError,
        TypeError,
        ValueError,
        UnicodeError,
        subprocess.CalledProcessError,
    ) as error:
        raise ValueError(invalid) from error
