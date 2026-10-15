"""Independent V11 revalidation of historical child HOLD outcomes."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Callable, Mapping
from typing import Any, Literal
from uuid import uuid4

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .attack_surfaces import SurfaceIndex
from .models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from .poc_currentness import poc_source_current
from .runner import SimpleStageHandler, StageBlocked, StageFailed
from .store import SimpleCheckpointStore
from .surface_child_evidence_v11 import ChildHoldTargetV11
from .surface_coverage_v5 import _completed_inconclusive_child

_MAX_CAS_BYTES = 16 * 1024 * 1024
_SUPPORTED_STAGES = frozenset(
    {
        SimpleStage.VERIFICATION_INITIAL_DONE,
        SimpleStage.POC_EXECUTION_DONE,
        SimpleStage.VERIFICATION_FINAL_DONE,
    }
)


def _object(artifacts: SimpleArtifactRepository, ref: StoredDataRef) -> dict[str, Any]:
    value = json.loads(artifacts.read_bounded(ref, _MAX_CAS_BYTES))
    if not isinstance(value, dict):
        raise ValueError("SURFACE_CHILD_V11_ARTIFACT_INVALID")
    return value


def _route_context_ref(
    artifacts: SimpleArtifactRepository,
    index: SurfaceIndex,
    target: ChildHoldTargetV11,
    plan_ref: StoredDataRef,
    parent_coverage_ref: StoredDataRef,
    route_proof_refs: Mapping[str, StoredDataRef],
) -> StoredDataRef:
    rows: list[dict[str, Any]] = []
    indexed_ids = {surface.surface_id for surface in index.surfaces}
    for surface_id in target.surface_ids:
        if surface_id not in indexed_ids:
            raise ValueError("SURFACE_CHILD_V11_ROUTE_UNBOUND")
        coverage_ref = route_proof_refs.get(surface_id)
        if coverage_ref is None or coverage_ref != parent_coverage_ref:
            raise ValueError("SURFACE_CHILD_V11_ROUTE_UNBOUND")
        coverage = _object(artifacts, coverage_ref)
        surfaces = coverage.get("surfaces")
        if (
            coverage.get("kind") != "simple_attack_surface_coverage_v8"
            or coverage.get("scope_fingerprint") != index.scope_fingerprint
            or coverage.get("index_hash")
            != hashlib.sha256(canonical_bytes(index.to_json())).hexdigest()
            or not isinstance(surfaces, list)
        ):
            raise ValueError("SURFACE_CHILD_V11_ROUTE_UNBOUND")
        matches = [
            row
            for row in surfaces
            if isinstance(row, dict) and row.get("surface_id") == surface_id
        ]
        if len(matches) != 1:
            raise ValueError("SURFACE_CHILD_V11_ROUTE_UNBOUND")
        rows.append(
            {
                "coverage_ref": coverage_ref.model_dump(mode="json"),
                "surface": matches[0],
            }
        )
    context = {
        "kind": "simple_surface_child_route_context_v11",
        "plan_ref": plan_ref.model_dump(mode="json"),
        "hypothesis_id": target.hypothesis_id,
        "stage": target.stage.value,
        "checkpoint_hash": target.checkpoint_hash,
        "surfaces": rows,
    }
    # Never truncate a route proof before giving it to Verification Agent.
    if len(canonical_bytes(context)) > 128 * 1024:
        raise ValueError("SURFACE_CHILD_V11_ROUTE_CONTEXT_TOO_LARGE")
    return artifacts.put_json(context)


def _supported_prior_poc(
    old: StageCheckpoint,
    prior: Mapping[SimpleStage, StageCheckpoint],
    artifacts: SimpleArtifactRepository,
) -> bool:
    candidate = prior.get(SimpleStage.POC_CANDIDATE_DONE)
    dynamic = prior.get(SimpleStage.POC_EXECUTION_DONE)
    if (
        candidate is None
        or dynamic is None
        or candidate.identity != old.identity
        or dynamic.identity != old.identity
        or candidate.status is not StageStatus.SUCCEEDED
        or dynamic.status is not StageStatus.SUCCEEDED
        or candidate.stage_version != STAGE_VERSION[candidate.stage]
        or dynamic.stage_version != STAGE_VERSION[dynamic.stage]
        or len(candidate.output_refs) < 2
        or len(dynamic.output_refs) != 4
        or dynamic.validated_poc_ref != dynamic.output_refs[2]
        or old.input_refs[: len(dynamic.output_refs)] != dynamic.output_refs
        or not poc_source_current(candidate, read_content=artifacts.read_bounded)
    ):
        return False
    candidate_ref, content_ref = candidate.output_refs[:2]
    execution_ref, interpretation_ref, validated_ref, cleanup_ref = dynamic.output_refs
    try:
        candidate_data = _object(artifacts, candidate_ref)
        execution = _object(artifacts, execution_ref)
        interpretation = _object(artifacts, interpretation_ref)
        validated = _object(artifacts, validated_ref)
        cleanup = _object(artifacts, cleanup_ref)
        for ref in (*candidate.output_refs, *dynamic.output_refs):
            artifacts.read_bounded(ref, _MAX_CAS_BYTES)
        return bool(
            candidate_data.get("kind") == "simple_poc_candidate"
            and candidate_data.get("content_ref") == content_ref.model_dump(mode="json")
            and candidate_data.get("attempt_id") == candidate.attempt_id
            and execution.get("kind") == "simple_poc_execution"
            and execution.get("candidate_ref") == candidate_ref.model_dump(mode="json")
            and execution.get("content_ref") == content_ref.model_dump(mode="json")
            and execution.get("attempt_id") == dynamic.attempt_id
            and execution.get("exit_code") == 0
            and execution.get("timed_out") is False
            and interpretation.get("kind") == "simple_dynamic_interpretation"
            and interpretation.get("execution_ref")
            == execution_ref.model_dump(mode="json")
            and isinstance(interpretation.get("result"), dict)
            and interpretation["result"].get("outcome") == "SUPPORTED"
            and validated.get("kind") == "simple_validated_poc"
            and validated.get("candidate_ref") == candidate_ref.model_dump(mode="json")
            and validated.get("content_ref") == content_ref.model_dump(mode="json")
            and validated.get("execution_ref") == execution_ref.model_dump(mode="json")
            and validated.get("interpretation_ref")
            == interpretation_ref.model_dump(mode="json")
            and validated.get("attempt_id") == dynamic.attempt_id
            and cleanup.get("kind") == "simple_container_cleanup"
            and cleanup.get("status") == "REMOVED"
            and cleanup.get("attempt_id") == dynamic.attempt_id
        )
    except (OSError, TypeError, ValueError, UnicodeError):
        return False


def _synthetic_checkpoint(
    old: StageCheckpoint,
    plan_ref: StoredDataRef,
    route_ref: StoredDataRef,
    attempt_id: str,
    prior: Mapping[SimpleStage, StageCheckpoint],
) -> StageCheckpoint:
    dynamic = prior.get(SimpleStage.POC_EXECUTION_DONE)
    dynamic_refs = (
        dynamic.output_refs
        if old.stage is SimpleStage.VERIFICATION_FINAL_DONE and dynamic is not None
        else ()
    )
    validated_ref = (
        (dynamic.validated_poc_ref,)
        if dynamic_refs
        and dynamic is not None
        and dynamic.validated_poc_ref is not None
        else ()
    )
    inputs = tuple(
        dict.fromkeys(
            (*old.output_refs, plan_ref, route_ref, *dynamic_refs, *validated_ref)
        )
    )
    return StageCheckpoint(
        identity=old.identity,
        stage=old.stage,
        stage_version=STAGE_VERSION[old.stage],
        status=StageStatus.RUNNING,
        input_refs=inputs,
        input_hash=input_reference_hash(inputs),
        attempt_id=attempt_id,
        attempt_number=old.attempt_number + 1,
        recipe_ref=old.recipe_ref,
        image_digest=old.image_digest,
    )


def _final_true_result(
    checkpoint: StageCheckpoint,
    result: StageResult,
    old: StageCheckpoint,
    prior: Mapping[SimpleStage, StageCheckpoint],
    artifacts: SimpleArtifactRepository,
) -> tuple[
    Literal["STILL_HOLD"],
    str,
    tuple[StoredDataRef, ...],
    StageCheckpoint | None,
]:
    dynamic = prior.get(SimpleStage.POC_EXECUTION_DONE)
    if dynamic is None or not _supported_prior_poc(old, prior, artifacts):
        return "STILL_HOLD", "SUPPORTED_POC_UNVERIFIED", result.output_refs, None
    if result.verdict != "TRUE":
        return (
            "STILL_HOLD",
            "NEGATIVE_PROOF_REQUIRED"
            if result.verdict == "FALSE"
            else "FINAL_CONDITION_UNRESOLVED",
            result.output_refs,
            None,
        )
    if (
        result.validated_poc_ref != dynamic.validated_poc_ref
        or len(result.output_refs) != 1
    ):
        return "STILL_HOLD", "FINAL_TRUE_UNVERIFIED", result.output_refs, None
    output = _object(artifacts, result.output_refs[0])
    response = output.get("result")
    included = output.get("source_refs")
    must_include = (*old.output_refs, dynamic.output_refs[0], dynamic.validated_poc_ref)
    if (
        output.get("kind") != "simple_verification_result"
        or output.get("attempt_id") != checkpoint.attempt_id
        or not isinstance(response, dict)
        or response.get("verdict") != "TRUE"
        or response.get("unresolved_conditions") != []
        or not isinstance(included, list)
        or any(
            ref.model_dump(mode="json") not in included
            for ref in must_include
            if ref is not None
        )
    ):
        return "STILL_HOLD", "FINAL_TRUE_UNVERIFIED", result.output_refs, None
    evidence = tuple(
        dict.fromkeys((*old.output_refs, *dynamic.output_refs, *result.output_refs))
    )
    # A fresh TRUE assessment is not a finished hypothesis. The technical
    # gate, scope gate, finding and report have not run under this successor.
    # Keep the old HOLD and the new assessment as separate evidence only.
    return "STILL_HOLD", "DOWNSTREAM_GATES_REQUIRED", evidence, None


async def revalidate_child_holds_v11(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    targets: tuple[ChildHoldTargetV11, ...],
    plan_ref: StoredDataRef,
    route_proof_refs: Mapping[str, StoredDataRef],
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
    handlers_for_child: Callable[
        [CheckpointIdentity], Mapping[SimpleStage, SimpleStageHandler]
    ],
) -> None:
    """Attempt each pinned HOLD once without mutating its original stage row."""

    if (
        identity.hypothesis_id is not None
        or artifacts.identity != identity
        or index.workspace_id != identity.workspace_id
        or index.commit_id != identity.commit_id
        or len({(target.hypothesis_id, target.stage) for target in targets})
        != len(targets)
    ):
        raise ValueError("SURFACE_CHILD_V11_IDENTITY_INVALID")
    plan = _object(artifacts, plan_ref)
    try:
        parent_coverage_ref = StoredDataRef.model_validate(plan["v10_coverage_ref"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("SURFACE_CHILD_V11_PLAN_INVALID") from error
    expected_targets = [
        {
            "hypothesis_id": target.hypothesis_id,
            "stage": target.stage.value,
            "surface_ids": list(target.surface_ids),
            "checkpoint_hash": target.checkpoint_hash,
        }
        for target in targets
    ]
    saved_targets = plan.get("targets")
    if (
        plan.get("kind") != "simple_surface_enrichment_plan_v11"
        or plan.get("analysis_id") != identity.analysis_id
        or plan.get("workspace_id") != identity.workspace_id
        or plan.get("commit_id") != identity.commit_id
        or plan.get("scope_fingerprint") != index.scope_fingerprint
        or plan.get("index_hash")
        != hashlib.sha256(canonical_bytes(index.to_json())).hexdigest()
        or saved_targets != expected_targets
    ):
        raise ValueError("SURFACE_CHILD_V11_PLAN_INVALID")
    progress = store.list_surface_child_revalidation_v11(
        identity, index.scope_fingerprint, plan_ref
    )
    if set(progress) != {(target.hypothesis_id, target.stage) for target in targets}:
        raise ValueError("SURFACE_CHILD_V11_PROGRESS_SET_INVALID")
    for target in targets:
        if target.stage not in _SUPPORTED_STAGES:
            raise ValueError("SURFACE_CHILD_V11_STAGE_INVALID")
        key = (target.hypothesis_id, target.stage)
        row = progress[key]
        if row.checkpoint_hash != target.checkpoint_hash:
            raise ValueError("SURFACE_CHILD_V11_PROGRESS_STALE")
        if row.status != "PENDING":
            continue  # RUNNING is deliberately not retried without cleanup proof.
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
            raise ValueError("SURFACE_CHILD_V11_CHECKPOINT_STALE")
        for ref in old.output_refs:
            artifacts.read_bounded(ref, _MAX_CAS_BYTES)
        route_ref = _route_context_ref(
            artifacts,
            index,
            target,
            plan_ref,
            parent_coverage_ref,
            route_proof_refs,
        )
        attempt_id = uuid4().hex
        if not store.claim_surface_child_revalidation_v11(
            identity,
            index.scope_fingerprint,
            plan_ref,
            target.hypothesis_id,
            target.stage,
            target.checkpoint_hash,
            attempt_id,
        ):
            continue
        status: Literal["RESOLVED", "STILL_HOLD", "ERROR"] = "STILL_HOLD"
        reason_code = "EVIDENCE_INSUFFICIENT"
        evidence_refs: tuple[StoredDataRef, ...] = ()
        new_checkpoint: StageCheckpoint | None = None
        error_code: str | None = None
        try:
            prior = store.prior(child, target.stage)
            if target.stage is SimpleStage.POC_EXECUTION_DONE:
                verified = _completed_inconclusive_child(
                    identity, target.hypothesis_id, store, artifacts
                )
                if (
                    verified is not None
                    and verified.get("checkpoint_sha256") == target.checkpoint_hash
                    and verified.get("output_refs")
                    == [ref.model_dump(mode="json") for ref in old.output_refs]
                ):
                    status, reason_code = "RESOLVED", "VERIFIED_POC_INCONCLUSIVE"
                    evidence_refs = old.output_refs
                else:
                    reason_code = "POC_LINEAGE_UNVERIFIED"
            elif target.stage is SimpleStage.VERIFICATION_INITIAL_DONE:
                # A new initial opinion alone cannot complete its PoC, final
                # verification, gates or report. Preserve the existing HOLD
                # without spending another provider call on an unusable result.
                reason_code = "DOWNSTREAM_POC_REQUIRED"
                evidence_refs = old.output_refs
            elif (
                target.stage is SimpleStage.VERIFICATION_FINAL_DONE
                and not _supported_prior_poc(old, prior, artifacts)
            ):
                reason_code = "SUPPORTED_POC_UNVERIFIED"
            else:
                handler = handlers_for_child(child).get(target.stage)
                if handler is None:
                    status, reason_code = "ERROR", "STAGE_HANDLER_MISSING"
                else:
                    checkpoint = _synthetic_checkpoint(
                        old, plan_ref, route_ref, attempt_id, prior
                    )
                    result = await handler(checkpoint, prior)
                    status, reason_code, evidence_refs, new_checkpoint = (
                        _final_true_result(checkpoint, result, old, prior, artifacts)
                    )
        except asyncio.CancelledError:
            # Cancellation can race with an LLM child process. Its claimed
            # RUNNING row must remain until exact cleanup can be proven.
            raise
        except (StageBlocked, StageFailed) as error:
            status, reason_code = "ERROR", "AGENT_EXECUTION_FAILED"
            error_code = "AGENT_EXECUTION_FAILED"
            evidence_refs = error.failure.evidence_refs
        except (OSError, TypeError, ValueError, UnicodeError):
            status, reason_code = "ERROR", "CHILD_EVIDENCE_INVALID"
            error_code = "CHILD_EVIDENCE_INVALID"
        except Exception:
            # Unexpected handler/factory exceptions may contain local paths,
            # prompt text or credentials. Persist only a fixed code.
            status, reason_code = "ERROR", "AGENT_EXECUTION_FAILED"
            error_code = "AGENT_EXECUTION_FAILED"
        result_ref = artifacts.put_json(
            {
                "kind": "simple_surface_child_revalidation_result_v11",
                "plan_ref": plan_ref.model_dump(mode="json"),
                "hypothesis_id": target.hypothesis_id,
                "stage": target.stage.value,
                "checkpoint_hash": target.checkpoint_hash,
                "status": status,
                "reason_code": reason_code,
                "attempt_id": attempt_id,
                "evidence_refs": [ref.model_dump(mode="json") for ref in evidence_refs],
                "new_checkpoint": (
                    new_checkpoint.model_dump(mode="json")
                    if new_checkpoint is not None
                    else None
                ),
                "error_code": error_code,
            }
        )
        if not store.finish_surface_child_revalidation_v11(
            identity,
            index.scope_fingerprint,
            plan_ref,
            target.hypothesis_id,
            target.stage,
            target.checkpoint_hash,
            attempt_id,
            status,
            reason_code,
            result_ref,
        ):
            raise ValueError("SURFACE_CHILD_V11_FINISH_STALE")
