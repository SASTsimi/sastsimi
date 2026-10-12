"""A validated v5 navigation result is not itself a HOLD replay proof."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SurfaceExplorationProgressRecord
from sastsimi.simple_runtime.surface_evidence_validation_v5 import (
    V5ValidatedResponse,
)
from sastsimi.simple_runtime.surface_hold_signal_v5 import (
    evaluate_v5_hold_replay_signal,
)


def _fixture(
    tmp_path: Path,
) -> tuple[
    CheckpointIdentity,
    StageCheckpoint,
    SurfaceExplorationProgressRecord,
    dict[str, object],
    V5ValidatedResponse,
    StoredDataRef,
    StoredDataRef,
]:
    identity = CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="a" * 40,
        hypothesis_id="old-child",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    old_ref = artifacts.put_json({"kind": "simple_initial_verification"})
    child = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(old_ref,),
        external_prerequisites_ref=old_ref,
        verdict="HOLD",
    )
    checked = V5ValidatedResponse(
        status="NO_HYPOTHESIS",
        reason="new execution path; retry old child now",
        qualified=(),
        verified_roles=({"part": "ENTRY", "node_id": "node-1"},),
        reviewed_parts=frozenset({"ENTRY"}),
        evidence_locations=("pkg/views.py:10",),
        verified_path_id="graph-path-1",
    )
    graph_ref = artifacts.put_json({"kind": "simple_surface_evidence_graph_v5"})
    context_ref = artifacts.put_json(
        {
            "kind": "simple_surface_context_v5",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "surface_id": "surface-1",
            "graph_hash": graph_ref.content_hash,
        }
    )
    plan_ref = artifacts.put_json(
        {
            "kind": "simple_surface_enrichment_plan_v5",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
        }
    )
    saved = {
        "kind": "simple_surface_hypothesis_result_v5",
        "analysis_id": identity.analysis_id,
        "surface_id": "surface-1",
        "context_id": "context-1",
        "part_index": 0,
        "part_count": 1,
        "context_hash": context_ref.content_hash,
        "static_bundle_hash": "c" * 64,
        "graph_hash": graph_ref.content_hash,
        "graph_ref": graph_ref.model_dump(mode="json"),
        "status": checked.status,
        "reason": checked.reason,
        "validation_status": "VALID",
        "verified_roles": list(checked.verified_roles),
        "reviewed_parts": sorted(checked.reviewed_parts),
        "evidence_locations": list(checked.evidence_locations),
        "verified_path_id": checked.verified_path_id,
        "seed_ids": [],
        "response": {"reason": "new test input is fresh-input"},
        "validation_feedback": None,
        "attempt_input_refs": [],
        "llm_request_ref": None,
        "llm_response_ref": None,
        "llm_raw_output_ref": None,
    }
    result_ref = artifacts.put_json(saved)
    record = SurfaceExplorationProgressRecord(
        surface_id="surface-1",
        context_id="context-1",
        static_bundle_hash="c" * 64,
        index_hash="d" * 64,
        context_hash=context_ref.content_hash,
        source_sha256="e" * 64,
        status=checked.status,
        result_ref=result_ref,
        hypothesis_ids=(),
        proposal_version=5,
    )
    return identity, child, record, saved, checked, plan_ref, context_ref


def test_valid_navigation_and_prose_do_not_create_replay_material(
    tmp_path: Path,
) -> None:
    identity, child, record, saved, checked, plan_ref, context_ref = _fixture(tmp_path)

    signal = evaluate_v5_hold_replay_signal(
        identity,
        child,
        record,
        saved,
        checked,
        plan_ref=plan_ref,
        context_ref=context_ref,
    )

    assert signal.decision.action == "KEEP_HOLD"
    assert signal.decision.restart_stage is None
    assert signal.decision.evidence_refs == ()
    assert signal.decision.reason == "V5_NAVIGATION_ONLY_NO_REPLAY_PROOF"
    assert signal.review_plan_ref == plan_ref
    assert signal.review_context_ref == context_ref
    assert signal.review_result_ref == record.result_ref


def test_tampered_saved_result_is_not_accepted_as_review_evidence(
    tmp_path: Path,
) -> None:
    identity, child, record, saved, checked, plan_ref, context_ref = _fixture(tmp_path)
    saved["reason"] = "forged contradiction"

    signal = evaluate_v5_hold_replay_signal(
        identity,
        child,
        record,
        saved,
        checked,
        plan_ref=plan_ref,
        context_ref=context_ref,
    )

    assert signal.decision.action == "KEEP_HOLD"
    assert signal.decision.reason == "V5_RESULT_UNVERIFIED"
    assert signal.review_plan_ref is None
    assert signal.review_context_ref is None
    assert signal.review_result_ref is None


def test_stale_context_or_unvalidated_result_is_not_trusted(tmp_path: Path) -> None:
    identity, child, record, saved, checked, plan_ref, context_ref = _fixture(tmp_path)
    stale = replace(record, context_id="other-context")

    signal = evaluate_v5_hold_replay_signal(
        identity,
        child,
        stale,
        saved,
        checked,
        plan_ref=plan_ref,
        context_ref=context_ref,
    )

    assert signal.decision.action == "KEEP_HOLD"
    assert signal.decision.reason == "V5_RESULT_UNVERIFIED"
    assert signal.review_result_ref is None


def test_wrong_context_ref_never_becomes_hold_review_provenance(
    tmp_path: Path,
) -> None:
    identity, child, record, saved, checked, plan_ref, _ = _fixture(tmp_path)
    other = SimpleArtifactRepository(tmp_path / "artifacts", identity).put_json(
        {"kind": "simple_surface_context_v5", "surface_id": "other"}
    )

    signal = evaluate_v5_hold_replay_signal(
        identity,
        child,
        record,
        saved,
        checked,
        plan_ref=plan_ref,
        context_ref=other,
    )

    assert signal.decision.action == "KEEP_HOLD"
    assert signal.decision.reason == "V5_RESULT_UNVERIFIED"
    assert signal.review_plan_ref is None
    assert signal.review_context_ref is None
    assert signal.review_result_ref is None
