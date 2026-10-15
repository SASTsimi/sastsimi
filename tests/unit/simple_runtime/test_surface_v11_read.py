"""V11 must independently replay the exact frozen V10 predecessor."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any, TypedDict, cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attack_surfaces import SurfaceIndex
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CandidateTerminal,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import (
    ChildRevalidationProgressRecordV11,
    SimpleCheckpointStore,
    SurfaceExplorationProgressRecord,
)
from sastsimi.simple_runtime.surface_child_evidence_v11 import (
    ChildHoldTargetV11,
    collect_child_hold_targets_v11,
)
from sastsimi.simple_runtime.surface_coverage_v8 import SurfaceCoverageV8
from sastsimi.simple_runtime.surface_coverage_v8_read import (
    verified_saved_coverage_v8,
)
from sastsimi.simple_runtime.surface_coverage_v9 import (
    SurfaceCoverageV9,
    evaluate_surface_coverage_v9,
)
from sastsimi.simple_runtime.surface_enrichment_v9 import _digest
from sastsimi.simple_runtime.surface_enrichment_v11 import (
    prepare_surface_enrichment_v11,
)
from tests.unit.simple_runtime.test_surface_v7_inconclusive_completion import (
    _case_with_terminal_poc_hold,
)
from tests.unit.simple_runtime.test_surface_v10_read import _saved_v10_case


class _V11Case(TypedDict):
    identity: CheckpointIdentity
    index: SurfaceIndex
    store: Any  # The predecessor test fixture has dynamically replaced methods.
    artifacts: SimpleArtifactRepository
    workspace: Path
    coverage: SurfaceCoverageV8
    coverage_ref: StoredDataRef
    terminal: CandidateTerminal
    counts: dict[str, int]
    progress: dict[tuple[str, str], SurfaceExplorationProgressRecord]
    v10_terminal: CandidateTerminal
    v10_root: StageCheckpoint
    v11_plan_ref: StoredDataRef
    v11_coverage: SurfaceCoverageV9
    v11_coverage_ref: StoredDataRef
    v11_terminal: CandidateTerminal


class _PocCase(TypedDict):
    case: Any  # The older test fixture has an anonymous dynamic case object.
    child: CheckpointIdentity
    original: StageCheckpoint
    plan_ref: StoredDataRef
    result: dict[str, Any]
    record: ChildRevalidationProgressRecordV11


class _FinalCase(TypedDict):
    case: Any
    child: CheckpointIdentity
    old_final: StageCheckpoint
    poc: StageCheckpoint
    plan_ref: StoredDataRef
    result: dict[str, Any]
    record: ChildRevalidationProgressRecordV11


def test_v10_replay_accepts_paired_frozen_predecessor_after_v11_promotion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Changing only the live V10 terminal/root must not erase its proof."""

    case = _saved_v10_case(tmp_path, monkeypatch)
    store = case["store"]
    frozen_terminal = store.run.candidate_terminal
    frozen_root = store.get()
    assert frozen_terminal is not None
    newer_ref = case["artifacts"].put_json({"successor": True})
    store.run = store.run.model_copy(
        update={
            "candidate_terminal": frozen_terminal.model_copy(
                update={
                    "surface_proof_version": 9,
                    "surface_coverage_hash": newer_ref.content_hash,
                }
            )
        }
    )
    store.get = lambda *_args: frozen_root.model_copy(
        update={"output_refs": (frozen_root.output_refs[0], newer_ref)}
    )

    verified = verified_saved_coverage_v8(
        case["identity"],
        case["index"],
        case["coverage_ref"],
        cast(SimpleCheckpointStore, store),
        case["artifacts"],
        predecessor_terminal=frozen_terminal,
        predecessor_root=frozen_root,
    )
    assert verified == case["coverage"]


def test_v10_replay_rejects_unpaired_frozen_predecessor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A terminal-only override cannot bypass the matching frozen root."""

    case = _saved_v10_case(tmp_path, monkeypatch)
    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V8_VERIFIED_INVALID"):
        verified_saved_coverage_v8(
            case["identity"],
            case["index"],
            case["coverage_ref"],
            cast(SimpleCheckpointStore, case["store"]),
            case["artifacts"],
            predecessor_terminal=case["terminal"],
        )


def _saved_v11_empty_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _V11Case:
    case = _saved_v10_case(tmp_path, monkeypatch)
    store = case["store"]
    identity = case["identity"]
    index = case["index"]
    artifacts = case["artifacts"]
    parent = case["coverage"]
    v10_terminal = store.run.candidate_terminal
    v10_root = store.get()
    v10_plan_ref = store.run.surface_enrichment_v10_plan_ref
    assert v10_terminal is not None and v10_plan_ref is not None
    store.list_checkpoints = lambda *_args: (v10_root,)
    targets, snapshot_hash = collect_child_hold_targets_v11(
        identity, index, case["progress"], cast(SimpleCheckpointStore, store)
    )
    assert targets == ()
    import json

    v10_plan = json.loads(artifacts.read(v10_plan_ref))
    plan = prepare_surface_enrichment_v11(
        identity,
        parent,
        v10_plan_ref,
        case["coverage_ref"],
        v10_terminal,
        v10_root,
        targets,
        snapshot_hash,
        v10_plan["v9_progress_hash"],
    )
    plan_ref = artifacts.put_json(plan)
    coverage = evaluate_surface_coverage_v9(parent, targets, {})
    coverage_ref = artifacts.put_json(coverage.to_json())
    counts = {
        status: sum(row.coverage_status == status for row in coverage.surfaces)
        for status in ("COVERED", "UNCOVERED", "INSUFFICIENT")
    }
    v11_terminal = v10_terminal.model_copy(
        update={
            "status": "COMPLETE" if coverage.complete else "PARTIAL",
            "surface_proof_version": 9,
            "surface_coverage_hash": coverage_ref.content_hash,
            "surface_counts": counts,
            "pending_child_count": coverage.pending_child_count,
        }
    )
    store.run = store.run.model_copy(
        update={
            "candidate_terminal": v11_terminal,
            "surface_enrichment_v11_plan_ref": plan_ref,
        }
    )
    v11_root = v10_root.model_copy(
        update={
            "output_refs": (v10_root.output_refs[0], coverage_ref),
        }
    )
    store.get = lambda *_args: v11_root
    store.list_checkpoints = lambda *_args: (v11_root,)
    store.list_surface_child_revalidation_v11 = lambda *_args: {}
    case.update(
        {
            "v10_terminal": v10_terminal,
            "v10_root": v10_root,
            "v11_plan_ref": plan_ref,
            "v11_coverage": coverage,
            "v11_coverage_ref": coverage_ref,
            "v11_terminal": v11_terminal,
        }
    )
    return cast(_V11Case, case)


def test_v11_read_replays_exact_v10_parent_and_empty_child_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A saved V11 claim is visible only after V10 and child-set replay."""

    from sastsimi.simple_runtime.surface_coverage_v9_read import (
        verified_saved_coverage_v9,
    )

    case = _saved_v11_empty_case(tmp_path, monkeypatch)
    verified = verified_saved_coverage_v9(
        case["identity"],
        case["index"],
        case["v11_coverage_ref"],
        cast(SimpleCheckpointStore, case["store"]),
        case["artifacts"],
    )
    assert verified == case["v11_coverage"]


def test_v11_read_accepts_plan_within_promotion_size_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A plan accepted at promotion must remain readable after promotion."""

    from sastsimi.simple_runtime.surface_coverage_v9_read import (
        verified_saved_coverage_v9,
    )

    case = _saved_v11_empty_case(tmp_path, monkeypatch)
    plan_ref = case["v11_plan_ref"]
    original_read = SimpleArtifactRepository.read_bounded

    def read_with_large_plan(
        repository: SimpleArtifactRepository, ref: StoredDataRef, max_bytes: int
    ) -> bytes:
        if ref == plan_ref and max_bytes < 10 * 1024 * 1024:
            raise ValueError("accepted plan rejected by read cap")
        return original_read(repository, ref, max_bytes)

    monkeypatch.setattr(SimpleArtifactRepository, "read_bounded", read_with_large_plan)
    assert (
        verified_saved_coverage_v9(
            case["identity"],
            case["index"],
            case["v11_coverage_ref"],
            cast(SimpleCheckpointStore, case["store"]),
            case["artifacts"],
        )
        == case["v11_coverage"]
    )


def test_v11_read_rejects_changed_v9_progress_after_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A new linked child or changed review cannot inherit stale coverage."""

    from dataclasses import replace

    from sastsimi.simple_runtime.surface_coverage_v9_read import (
        verified_saved_coverage_v9,
    )

    case = _saved_v11_empty_case(tmp_path, monkeypatch)
    progress = case["progress"]
    key = next(iter(progress))
    progress[key] = replace(progress[key], hypothesis_ids=("new-child",))
    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V9_VERIFIED_INVALID"):
        verified_saved_coverage_v9(
            case["identity"],
            case["index"],
            case["v11_coverage_ref"],
            cast(SimpleCheckpointStore, case["store"]),
            case["artifacts"],
        )


def _poc_revalidation_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[_PocCase, ChildHoldTargetV11]:
    data = _case_with_terminal_poc_hold(tmp_path)
    case = data["case"]
    child = case.identity.model_copy(update={"hypothesis_id": "hypothesis-old"})
    original = case.store.require(child, SimpleStage.POC_EXECUTION_DONE)
    target = ChildHoldTargetV11(
        hypothesis_id="hypothesis-old",
        stage=SimpleStage.POC_EXECUTION_DONE,
        surface_ids=(case.index.surfaces[0].surface_id,),
        checkpoint_hash=hashlib.sha256(canonical_bytes(original)).hexdigest(),
    )
    plan_ref = case.artifacts.put_json(
        {
            "kind": "simple_surface_enrichment_plan_v11",
            "analysis_id": case.identity.analysis_id,
            "workspace_id": case.identity.workspace_id,
            "commit_id": case.identity.commit_id,
            "scope_fingerprint": case.index.scope_fingerprint,
            "index_hash": _digest(case.index.to_json()),
            "targets": [
                {
                    "hypothesis_id": target.hypothesis_id,
                    "stage": target.stage.value,
                    "surface_ids": list(target.surface_ids),
                    "checkpoint_hash": target.checkpoint_hash,
                }
            ],
        }
    )
    attempt_id = "revalidate-poc-1"
    result = {
        "kind": "simple_surface_child_revalidation_result_v11",
        "plan_ref": plan_ref.model_dump(mode="json"),
        "hypothesis_id": target.hypothesis_id,
        "stage": target.stage.value,
        "checkpoint_hash": target.checkpoint_hash,
        "status": "RESOLVED",
        "reason_code": "VERIFIED_POC_INCONCLUSIVE",
        "attempt_id": attempt_id,
        "evidence_refs": [ref.model_dump(mode="json") for ref in original.output_refs],
        "new_checkpoint": None,
    }
    result_ref = case.artifacts.put_json(result)
    record = ChildRevalidationProgressRecordV11(
        hypothesis_id=target.hypothesis_id,
        stage=target.stage,
        checkpoint_hash=target.checkpoint_hash,
        status="RESOLVED",
        reason_code="VERIFIED_POC_INCONCLUSIVE",
        result_ref=result_ref,
        attempt_id=attempt_id,
    )
    monkeypatch.setattr(
        case.store,
        "list_surface_child_revalidation_v11",
        lambda *_args: {(target.hypothesis_id, target.stage): record},
    )
    return {
        "case": case,
        "child": child,
        "original": original,
        "plan_ref": plan_ref,
        "result": result,
        "record": record,
    }, target


def test_saved_poc_inconclusive_resolution_replays_exact_old_lineage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An old terminal PoC HOLD may close only with its verified CAS chain."""

    from sastsimi.simple_runtime.surface_coverage_v9_read import (
        verified_child_dispositions_v11,
    )

    saved, target = _poc_revalidation_case(tmp_path, monkeypatch)
    case = saved["case"]
    dispositions = verified_child_dispositions_v11(
        case.identity,
        case.index,
        saved["plan_ref"],
        (target,),
        case.store,
        case.artifacts,
    )
    row = dispositions[(target.hypothesis_id, target.stage)]
    assert row.status == "RESOLVED"
    assert row.reason_code == "VERIFIED_POC_INCONCLUSIVE"
    assert saved["record"].result_ref is not None
    assert row.evidence_hash == saved["record"].result_ref.content_hash


def test_saved_poc_resolution_rejects_extra_unbound_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An extra ref cannot be smuggled into a completed PoC proof."""

    from sastsimi.simple_runtime.surface_coverage_v9_read import (
        verified_child_dispositions_v11,
    )

    saved, target = _poc_revalidation_case(tmp_path, monkeypatch)
    case = saved["case"]
    extra = case.artifacts.put_json({"unrelated": True})
    forged = {
        **saved["result"],
        "evidence_refs": [
            *saved["result"]["evidence_refs"],
            extra.model_dump(mode="json"),
        ],
    }
    result_ref = case.artifacts.put_json(forged)
    record = replace(saved["record"], result_ref=result_ref)
    monkeypatch.setattr(
        case.store,
        "list_surface_child_revalidation_v11",
        lambda *_args: {(target.hypothesis_id, target.stage): record},
    )
    with pytest.raises(ValueError, match="SURFACE_CHILD_V11_VERIFIED_INVALID"):
        verified_child_dispositions_v11(
            case.identity,
            case.index,
            saved["plan_ref"],
            (target,),
            case.store,
            case.artifacts,
        )


def test_saved_poc_resolution_rejects_plan_for_another_scope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A valid old PoC cannot settle obligations from another scope."""

    import json

    from sastsimi.simple_runtime.surface_coverage_v9_read import (
        verified_child_dispositions_v11,
    )

    saved, target = _poc_revalidation_case(tmp_path, monkeypatch)
    case = saved["case"]
    plan = json.loads(case.artifacts.read(saved["plan_ref"]))
    wrong_ref = case.artifacts.put_json({**plan, "scope_fingerprint": "0" * 64})
    forged = {**saved["result"], "plan_ref": wrong_ref.model_dump(mode="json")}
    result_ref = case.artifacts.put_json(forged)
    record = replace(saved["record"], result_ref=result_ref)
    monkeypatch.setattr(
        case.store,
        "list_surface_child_revalidation_v11",
        lambda *_args: {(target.hypothesis_id, target.stage): record},
    )
    with pytest.raises(ValueError, match="SURFACE_CHILD_V11_VERIFIED_INVALID"):
        verified_child_dispositions_v11(
            case.identity,
            case.index,
            wrong_ref,
            (target,),
            case.store,
            case.artifacts,
        )


def _final_true_revalidation_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, outcome: str = "SUPPORTED"
) -> tuple[_FinalCase, ChildHoldTargetV11]:
    saved, _ = _poc_revalidation_case(tmp_path, monkeypatch)
    case = saved["case"]
    child = saved["child"]
    old_poc = saved["original"]
    candidate = case.store.require(child, SimpleStage.POC_CANDIDATE_DONE)
    candidate_ref, content_ref = candidate.output_refs[:2]
    execution_ref, _, cleanup_ref = old_poc.output_refs
    interpretation_ref = case.artifacts.put_json(
        {
            "kind": "simple_dynamic_interpretation",
            "execution_ref": execution_ref.model_dump(mode="json"),
            "result": {"outcome": outcome, "rationale": "Observed effect"},
        }
    )
    validated_ref = case.artifacts.put_json(
        {
            "kind": "simple_validated_poc",
            "candidate_ref": candidate_ref.model_dump(mode="json"),
            "content_ref": content_ref.model_dump(mode="json"),
            "execution_ref": execution_ref.model_dump(mode="json"),
            "interpretation_ref": interpretation_ref.model_dump(mode="json"),
            "attempt_id": old_poc.attempt_id,
        }
    )
    supported = old_poc.model_copy(
        update={
            "output_refs": (
                execution_ref,
                interpretation_ref,
                validated_ref,
                cleanup_ref,
            ),
            "validated_poc_ref": validated_ref,
            "verdict": None,
        }
    )
    case.store.save_checkpoint(supported)
    old_final_ref = case.artifacts.put_json(
        {
            "kind": "simple_verification_result",
            "attempt_id": "old-final",
            "result": {"verdict": "HOLD", "unresolved_conditions": ["No final proof"]},
        }
    )
    old_final = StageCheckpoint(
        identity=child,
        stage=SimpleStage.VERIFICATION_FINAL_DONE,
        stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_FINAL_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=supported.output_refs,
        input_hash=input_reference_hash(supported.output_refs),
        output_refs=(old_final_ref,),
        attempt_id="old-final",
        verdict="HOLD",
    )
    case.store.save_checkpoint(old_final)
    target = ChildHoldTargetV11(
        hypothesis_id="hypothesis-old",
        stage=SimpleStage.VERIFICATION_FINAL_DONE,
        surface_ids=(case.index.surfaces[0].surface_id,),
        checkpoint_hash=hashlib.sha256(canonical_bytes(old_final)).hexdigest(),
    )
    plan_ref = case.artifacts.put_json(
        {
            "kind": "simple_surface_enrichment_plan_v11",
            "analysis_id": case.identity.analysis_id,
            "workspace_id": case.identity.workspace_id,
            "commit_id": case.identity.commit_id,
            "scope_fingerprint": case.index.scope_fingerprint,
            "index_hash": _digest(case.index.to_json()),
            "targets": [
                {
                    "hypothesis_id": target.hypothesis_id,
                    "stage": target.stage.value,
                    "surface_ids": list(target.surface_ids),
                    "checkpoint_hash": target.checkpoint_hash,
                }
            ],
        }
    )
    attempt_id = "revalidate-final-1"
    refs = (old_final_ref, plan_ref, *supported.output_refs)
    verified_ref = case.artifacts.put_json(
        {
            "kind": "simple_verification_result",
            "attempt_id": attempt_id,
            "source_refs": [ref.model_dump(mode="json") for ref in refs],
            "result": {"verdict": "TRUE", "unresolved_conditions": []},
        }
    )
    new_final = StageCheckpoint(
        identity=child,
        stage=SimpleStage.VERIFICATION_FINAL_DONE,
        stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_FINAL_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=refs,
        input_hash=input_reference_hash(refs),
        output_refs=(verified_ref,),
        attempt_id=attempt_id,
        validated_poc_ref=validated_ref,
        verdict="TRUE",
    )
    result = {
        "kind": "simple_surface_child_revalidation_result_v11",
        "plan_ref": plan_ref.model_dump(mode="json"),
        "hypothesis_id": target.hypothesis_id,
        "stage": target.stage.value,
        "checkpoint_hash": target.checkpoint_hash,
        "status": "RESOLVED",
        "reason_code": "VERIFIED_FINAL_TRUE",
        "attempt_id": attempt_id,
        "evidence_refs": [
            ref.model_dump(mode="json")
            for ref in (
                old_final_ref,
                execution_ref,
                interpretation_ref,
                validated_ref,
                cleanup_ref,
                verified_ref,
            )
        ],
        "new_checkpoint": new_final.model_dump(mode="json"),
    }
    result_ref = case.artifacts.put_json(result)
    record = ChildRevalidationProgressRecordV11(
        hypothesis_id=target.hypothesis_id,
        stage=target.stage,
        checkpoint_hash=target.checkpoint_hash,
        status="RESOLVED",
        reason_code="VERIFIED_FINAL_TRUE",
        result_ref=result_ref,
        attempt_id=attempt_id,
    )
    monkeypatch.setattr(
        case.store,
        "list_surface_child_revalidation_v11",
        lambda *_args: {(target.hypothesis_id, target.stage): record},
    )
    return {
        "case": case,
        "child": child,
        "old_final": old_final,
        "poc": supported,
        "plan_ref": plan_ref,
        "result": result,
        "record": record,
    }, target


def test_final_true_without_downstream_gates_cannot_close_analysis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A new TRUE alone cannot stand in for gates, finding and reports."""

    from sastsimi.simple_runtime.surface_coverage_v9_read import (
        verified_child_dispositions_v11,
    )

    saved, target = _final_true_revalidation_case(tmp_path, monkeypatch)
    case = saved["case"]
    with pytest.raises(ValueError, match="SURFACE_CHILD_V11_VERIFIED_INVALID"):
        verified_child_dispositions_v11(
            case.identity,
            case.index,
            saved["plan_ref"],
            (target,),
            case.store,
            case.artifacts,
        )


def test_final_true_rejects_unproved_poc_interpretation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A synthetic TRUE may not upgrade an inconclusive PoC to support."""

    from sastsimi.simple_runtime.surface_coverage_v9_read import (
        verified_child_dispositions_v11,
    )

    saved, target = _final_true_revalidation_case(
        tmp_path, monkeypatch, outcome="INCONCLUSIVE"
    )
    case = saved["case"]
    with pytest.raises(ValueError, match="SURFACE_CHILD_V11_VERIFIED_INVALID"):
        verified_child_dispositions_v11(
            case.identity,
            case.index,
            saved["plan_ref"],
            (target,),
            case.store,
            case.artifacts,
        )


def test_final_true_rejects_missing_plan_in_fresh_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A new final call cannot be detached from this V11 plan."""

    import json

    from sastsimi.simple_runtime.surface_coverage_v9_read import (
        verified_child_dispositions_v11,
    )

    saved, target = _final_true_revalidation_case(tmp_path, monkeypatch)
    case = saved["case"]
    raw = saved["result"]
    fresh = StageCheckpoint.model_validate_json(json.dumps(raw["new_checkpoint"]))
    inputs = tuple(ref for ref in fresh.input_refs if ref != saved["plan_ref"])
    detached = fresh.model_copy(
        update={
            "input_refs": inputs,
            "input_hash": input_reference_hash(inputs),
        }
    )
    forged = {**raw, "new_checkpoint": detached.model_dump(mode="json")}
    result_ref = case.artifacts.put_json(forged)
    record = replace(saved["record"], result_ref=result_ref)
    monkeypatch.setattr(
        case.store,
        "list_surface_child_revalidation_v11",
        lambda *_args: {(target.hypothesis_id, target.stage): record},
    )
    with pytest.raises(ValueError, match="SURFACE_CHILD_V11_VERIFIED_INVALID"):
        verified_child_dispositions_v11(
            case.identity,
            case.index,
            saved["plan_ref"],
            (target,),
            case.store,
            case.artifacts,
        )
