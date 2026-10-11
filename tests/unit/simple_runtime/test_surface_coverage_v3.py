"""Saved-v2 and v5 coverage facts stay source-bound and monotonic."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime import surface_coverage_v2, surface_coverage_v3
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SurfaceExplorationProgressRecord
from sastsimi.simple_runtime.surface_coverage_v2 import SurfaceCoverageV2
from sastsimi.simple_runtime.surface_coverage_v3 import (
    evaluate_surface_coverage_v3,
    read_saved_coverage_v2,
)
from sastsimi.simple_runtime.surface_enrichment_v5 import (
    V5Part,
    prepare_surface_enrichment_v5,
)
from sastsimi.simple_runtime.surface_evidence_validation_v5 import (
    validate_v5_response,
)
from tests.unit.simple_runtime.test_surface_coverage_v2 import _Case, _case


def test_read_saved_v2_uses_exact_existing_json(tmp_path: Path) -> None:
    case = _case(tmp_path, omit_sensitive_role=True)
    prior = case.evaluate()
    coverage_ref = case.artifacts.put_json(prior.to_json())
    prior_bytes = case.artifacts.read(coverage_ref)

    loaded = read_saved_coverage_v2(case.artifacts, case.index, coverage_ref)

    assert loaded == prior
    assert case.artifacts.read(coverage_ref) == prior_bytes


def test_read_saved_v2_rejects_forged_scope_and_status(tmp_path: Path) -> None:
    case = _case(tmp_path, omit_sensitive_role=True)
    prior = case.evaluate()
    saved = prior.to_json()
    surfaces = saved["surfaces"]
    assert isinstance(surfaces, list)
    assert isinstance(surfaces[0], dict)
    surfaces[0]["coverage_status"] = "COVERED"
    forged_ref = case.artifacts.put_json(saved)

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V2_SAVED_INVALID"):
        read_saved_coverage_v2(case.artifacts, case.index, forged_ref)


def _v5_case(
    tmp_path: Path,
    *,
    old_hold: bool = False,
    python_gap: bool = False,
    trusted_graph: bool = True,
) -> tuple[
    _Case,
    SurfaceCoverageV2,
    StoredDataRef,
    dict[str, object],
    tuple[V5Part, ...],
    dict[str, object],
    StoredDataRef,
]:
    case = _case(
        tmp_path,
        omit_sensitive_role=True,
        old_hold=old_hold,
        python_gap=python_gap,
    )
    prior = case.evaluate()
    prior_ref = case.artifacts.put_json(prior.to_json())
    v4_ref = case.artifacts.put_json(case.plan)
    v4_row = next(row for row in case.progress.values() if row.proposal_version == 4)
    v4_result = json.loads(case.artifacts.read(v4_row.result_ref))
    graph_ref = StoredDataRef.model_validate(v4_result["graph_ref"])
    graph = json.loads(case.artifacts.read(graph_ref))
    graph["kind"] = "simple_surface_evidence_graph_v5"
    graph["operational_routes"] = []
    if trusted_graph:
        graph["proof_semantics_revision"] = "v5-source-bound-2"
    v5_graph_ref = case.artifacts.put_json(graph)
    target = next(
        surface
        for surface in case.index.surfaces
        if surface.surface_id == prior.surfaces[0].surface_id
    )
    plan, parts = prepare_surface_enrichment_v5(
        case.identity,
        case.index.scope_fingerprint,
        case.index,
        case.index_ref,
        v4_ref,
        prior_ref,
        prior,
        case.progress,
        {target.surface_id: graph},
        v4_plan=case.plan,
        child_checkpoint_hashes={},
    )
    plan_ref = case.artifacts.put_json(plan)
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.candidate_terminal is not None
    case.store.save_analysis_run(
        run.model_copy(
            update={
                "surface_enrichment_v5_plan_ref": plan_ref,
                "candidate_terminal": run.candidate_terminal.model_copy(
                    update={
                        "surface_proof_version": 2,
                        "surface_coverage_hash": prior_ref.content_hash,
                        "scope_certificate_hash": (
                            prior.scope_certificate_ref.content_hash
                        ),
                    }
                ),
            }
        )
    )
    return case, prior, prior_ref, plan, parts, graph, v5_graph_ref


def test_v3_preserves_prior_gaps_until_v5_parts_are_verified(tmp_path: Path) -> None:
    case, prior, prior_ref, plan, _parts, _graph, _graph_ref = _v5_case(tmp_path)
    old_bytes = case.artifacts.read(prior_ref)

    proof = evaluate_surface_coverage_v3(
        case.identity,
        case.index,
        prior,
        plan,
        case.progress,
        case.store,
        case.artifacts,
    )

    assert proof.complete is False
    assert proof.prior_v2_ref == prior_ref
    assert proof.surfaces[0].coverage_status == "INSUFFICIENT"
    assert set(prior.surfaces[0].unresolved_reason_codes).issubset(
        proof.surfaces[0].unresolved_reason_codes
    )
    assert "SURFACE_PART_PENDING" in proof.surfaces[0].unresolved_reason_codes
    assert proof.surfaces[1].coverage_status == "COVERED"
    assert case.artifacts.read(prior_ref) == old_bytes


def _save_verified_v5_part(
    case: _Case,
    part: V5Part,
    graph: dict[str, object],
    graph_ref: StoredDataRef,
    *,
    connected: bool = True,
) -> None:
    context_ref = case.artifacts.put_json(part.payload)
    context = {
        "context_payload": part.payload,
        "graph_payload": graph,
        "context_hash": part.context_hash,
        "context_id": part.context_id,
    }
    source_sha = dict(case.index.ast_source_hashes)["app.py"]
    response = {
        "surface_id": part.surface_id,
        "context_id": part.context_id,
        "status": (
            "NO_HYPOTHESIS" if connected else "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
        ),
        "reason": "Exact request path reviewed without a hypothesis",
        "hypotheses": [],
        "review_evidence": [
            {
                "part": role,
                "location": f"app.py:{line}",
                "context_hash": part.context_hash,
                "source_sha256": source_sha,
                "graph_path_id": "path-real",
                "edge_ids": edges,
                "explanation": "Exact source path and edge reviewed",
            }
            for role, line, edges in (
                ("ENTRY", 1, ["edge-entry"]),
                ("TRUST_BOUNDARY", 3, ["edge-entry", "edge-sink"]),
                ("SENSITIVE_OPERATION", 4, ["edge-sink"]),
            )
        ]
        if connected
        else [],
    }
    checked = validate_v5_response(context, response)
    assert checked.verified_path_id == ("path-real" if connected else None)
    result_ref = case.artifacts.put_json(
        {
            "kind": "simple_surface_hypothesis_result_v5",
            "analysis_id": case.identity.analysis_id,
            "surface_id": part.surface_id,
            "context_id": part.context_id,
            "context_hash": part.context_hash,
            "part_index": part.part_index,
            "part_count": part.part_count,
            "static_bundle_hash": case.index.static_bundle_hash,
            "graph_hash": graph_ref.content_hash,
            "graph_ref": graph_ref.model_dump(mode="json"),
            "status": checked.status,
            "reason": checked.reason,
            "reviewed_parts": sorted(checked.reviewed_parts),
            "evidence_locations": list(checked.evidence_locations),
            "verified_roles": list(checked.verified_roles),
            "verified_path_id": checked.verified_path_id,
            "seed_ids": [],
            "response": response,
            "validation_status": "VALID",
        }
    )
    case.progress[(part.surface_id, part.context_id)] = (
        SurfaceExplorationProgressRecord(
            surface_id=part.surface_id,
            context_id=part.context_id,
            static_bundle_hash=case.index.static_bundle_hash,
            index_hash=case.index_ref.content_hash,
            context_hash=context_ref.content_hash,
            source_sha256=part.source_sha256,
            status=checked.status,
            result_ref=result_ref,
            hypothesis_ids=(),
            proposal_version=5,
        )
    )


def test_v3_new_connected_path_covers_only_non_hold_surface(tmp_path: Path) -> None:
    case, prior, _ref, plan, parts, graph, graph_ref = _v5_case(tmp_path)
    assert len(parts) == 1
    _save_verified_v5_part(case, parts[0], graph, graph_ref)

    proof = evaluate_surface_coverage_v3(
        case.identity,
        case.index,
        prior,
        plan,
        case.progress,
        case.store,
        case.artifacts,
    )

    assert proof.surfaces[0].coverage_status == "COVERED"
    assert proof.surfaces[0].unresolved_reason_codes == ()
    assert proof.surfaces[0].review_classification == "NO_HYPOTHESIS"
    assert proof.complete is True


def test_v3_saved_old_graph_cannot_gain_coverage_after_semantic_fix(
    tmp_path: Path,
) -> None:
    case, prior, _ref, plan, parts, graph, graph_ref = _v5_case(
        tmp_path, trusted_graph=False
    )
    _save_verified_v5_part(case, parts[0], graph, graph_ref)

    proof = evaluate_surface_coverage_v3(
        case.identity,
        case.index,
        prior,
        plan,
        case.progress,
        case.store,
        case.artifacts,
    )

    assert proof.surfaces[0].coverage_status == "INSUFFICIENT"
    assert proof.complete is False


def test_v3_connected_path_keeps_old_child_hold(tmp_path: Path) -> None:
    case, prior, _ref, plan, parts, graph, graph_ref = _v5_case(tmp_path, old_hold=True)
    assert len(parts) == 1
    assert "CHILD_HOLD" in prior.surfaces[0].unresolved_reason_codes
    _save_verified_v5_part(case, parts[0], graph, graph_ref)

    proof = evaluate_surface_coverage_v3(
        case.identity,
        case.index,
        prior,
        plan,
        case.progress,
        case.store,
        case.artifacts,
    )

    assert proof.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "CHILD_HOLD" in proof.surfaces[0].unresolved_reason_codes
    assert proof.complete is False


def test_v3_replaces_old_child_hold_only_after_decisive_current_child(
    tmp_path: Path,
) -> None:
    case, prior, prior_ref, plan, parts, graph, graph_ref = _v5_case(
        tmp_path, old_hold=True
    )
    _save_verified_v5_part(case, parts[0], graph, graph_ref)
    child = case.identity.model_copy(update={"hypothesis_id": "hypothesis-old"})
    held = case.store.get(child, SimpleStage.VERIFICATION_INITIAL_DONE)
    assert held is not None
    decisive_ref = case.artifacts.put_json({"kind": "new-decisive-child-evidence"})
    case.store.save_checkpoint(
        held.model_copy(
            update={
                "verdict": "FALSE",
                "external_prerequisites_ref": None,
                "output_refs": (decisive_ref,),
                "attempt_id": "reviewed-child-transition",
                "attempt_number": held.attempt_number + 1,
            }
        )
    )
    case.store.save_checkpoint(
        StageCheckpoint(
            identity=child,
            stage=SimpleStage.VERIFICATION_FINAL_DONE,
            stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_FINAL_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(decisive_ref,),
            verdict="FALSE",
        )
    )

    proof = evaluate_surface_coverage_v3(
        case.identity,
        case.index,
        prior,
        plan,
        case.progress,
        case.store,
        case.artifacts,
    )

    assert proof.surfaces[0].coverage_status == "COVERED", proof.surfaces[
        0
    ].unresolved_reason_codes
    assert "CHILD_HOLD" not in proof.surfaces[0].unresolved_reason_codes
    coverage_ref = case.artifacts.put_json(proof.to_json())
    assert (
        surface_coverage_v3.read_saved_coverage_v3(
            case.artifacts,
            case.index,
            coverage_ref,
            prior_v2_ref=prior_ref,
            v5_plan_ref=proof.v5_plan_ref,
        )
        == proof
    )


def test_v3_stale_child_cannot_clear_old_hold(tmp_path: Path) -> None:
    case, prior, _ref, plan, parts, graph, graph_ref = _v5_case(tmp_path, old_hold=True)
    _save_verified_v5_part(case, parts[0], graph, graph_ref)
    child = case.identity.model_copy(update={"hypothesis_id": "hypothesis-old"})
    held = case.store.get(child, SimpleStage.VERIFICATION_INITIAL_DONE)
    assert held is not None
    case.store.save_checkpoint(
        held.model_copy(
            update={
                "stage_version": "stale",
                "verdict": None,
                "attempt_id": "stale-child-transition",
                "attempt_number": held.attempt_number + 1,
            }
        )
    )

    proof = evaluate_surface_coverage_v3(
        case.identity,
        case.index,
        prior,
        plan,
        case.progress,
        case.store,
        case.artifacts,
    )

    assert proof.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "CHILD_STALE" in proof.surfaces[0].unresolved_reason_codes


def test_v5_plan_preflight_allows_recoverable_child_error(tmp_path: Path) -> None:
    """A pre-LLM plan check must not block the later child drain/recovery."""

    case, prior, _ref, plan, parts, graph, graph_ref = _v5_case(tmp_path, old_hold=True)
    _save_verified_v5_part(case, parts[0], graph, graph_ref)
    child = case.identity.model_copy(update={"hypothesis_id": "hypothesis-old"})
    old = case.store.get(child, SimpleStage.VERIFICATION_INITIAL_DONE)
    assert old is not None
    case.store.save_checkpoint(
        old.model_copy(
            update={"status": StageStatus.FAILED, "verdict": None, "error_code": "TEST"}
        )
    )

    surface_coverage_v3.validate_surface_plan_v5(
        case.identity,
        case.index,
        prior,
        plan,
        case.progress,
        case.store,
        case.artifacts,
    )
    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V3_PLAN_INVALID"):
        evaluate_surface_coverage_v3(
            case.identity,
            case.index,
            prior,
            plan,
            case.progress,
            case.store,
            case.artifacts,
        )


def test_v5_plan_preflight_rejects_missing_part_after_complete(
    tmp_path: Path,
) -> None:
    """A complete v3 terminal cannot silently replay a lost v5 result row."""

    case, prior, _ref, plan, parts, graph, graph_ref = _v5_case(tmp_path)
    _save_verified_v5_part(case, parts[0], graph, graph_ref)
    proof = evaluate_surface_coverage_v3(
        case.identity,
        case.index,
        prior,
        plan,
        case.progress,
        case.store,
        case.artifacts,
    )
    assert proof.complete is True
    coverage_ref = case.artifacts.put_json(proof.to_json())
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.candidate_terminal is not None
    case.store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_terminal": run.candidate_terminal.model_copy(
                    update={
                        "status": "COMPLETE",
                        "surface_proof_version": 3,
                        "surface_coverage_hash": coverage_ref.content_hash,
                    }
                )
            }
        )
    )
    missing_part_progress = {
        key: row for key, row in case.progress.items() if row.proposal_version != 5
    }

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V3_PLAN_INVALID"):
        surface_coverage_v3.validate_surface_plan_v5(
            case.identity,
            case.index,
            prior,
            plan,
            missing_part_progress,
            case.store,
            case.artifacts,
        )


def test_v3_non_request_classification_does_not_become_coverage(
    tmp_path: Path,
) -> None:
    case, prior, _ref, plan, parts, graph, graph_ref = _v5_case(tmp_path)
    _save_verified_v5_part(case, parts[0], graph, graph_ref, connected=False)

    proof = evaluate_surface_coverage_v3(
        case.identity,
        case.index,
        prior,
        plan,
        case.progress,
        case.store,
        case.artifacts,
    )

    assert proof.surfaces[0].coverage_status == "INSUFFICIENT"
    assert proof.surfaces[0].review_classification == (
        "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    )
    assert "CONNECTED_ROLE_PROOF_MISSING" in (proof.surfaces[0].unresolved_reason_codes)
    assert proof.complete is False


def test_v3_preserves_effective_python_gap_after_connected_path(
    tmp_path: Path,
) -> None:
    case, prior, _ref, plan, parts, graph, graph_ref = _v5_case(
        tmp_path, python_gap=True
    )
    assert prior.effective_python_gaps
    _save_verified_v5_part(case, parts[0], graph, graph_ref)

    proof = evaluate_surface_coverage_v3(
        case.identity,
        case.index,
        prior,
        plan,
        case.progress,
        case.store,
        case.artifacts,
    )

    assert proof.surfaces[0].coverage_status == "COVERED"
    assert proof.effective_python_gaps == prior.effective_python_gaps
    assert proof.complete is False


def test_v3_rejects_forged_validator_output_in_saved_result(tmp_path: Path) -> None:
    case, prior, _ref, plan, parts, graph, graph_ref = _v5_case(tmp_path)
    _save_verified_v5_part(case, parts[0], graph, graph_ref)
    key = (parts[0].surface_id, parts[0].context_id)
    row = case.progress[key]
    result = json.loads(case.artifacts.read(row.result_ref))
    result["verified_path_id"] = "forged-path"
    case.progress[key] = replace(row, result_ref=case.artifacts.put_json(result))

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V3_PLAN_INVALID"):
        evaluate_surface_coverage_v3(
            case.identity,
            case.index,
            prior,
            plan,
            case.progress,
            case.store,
            case.artifacts,
        )


def test_v3_rejects_forged_seed_ids_in_saved_result(tmp_path: Path) -> None:
    case, prior, _ref, plan, parts, graph, graph_ref = _v5_case(tmp_path)
    _save_verified_v5_part(case, parts[0], graph, graph_ref)
    key = (parts[0].surface_id, parts[0].context_id)
    row = case.progress[key]
    result = json.loads(case.artifacts.read(row.result_ref))
    result["seed_ids"] = ["hypothesis-forged"]
    case.progress[key] = replace(
        row,
        result_ref=case.artifacts.put_json(result),
        hypothesis_ids=("hypothesis-forged",),
    )

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V3_PLAN_INVALID"):
        evaluate_surface_coverage_v3(
            case.identity,
            case.index,
            prior,
            plan,
            case.progress,
            case.store,
            case.artifacts,
        )


def test_v3_rejects_saved_plan_with_forged_expected_part(tmp_path: Path) -> None:
    case, prior, _ref, plan, _parts, _graph, _graph_ref = _v5_case(tmp_path)
    forged_plan = deepcopy(plan)
    expected_parts = forged_plan["expected_parts"]
    assert isinstance(expected_parts, list)
    assert isinstance(expected_parts[0], dict)
    expected_parts[0]["context_hash"] = "0" * 64
    forged_ref = case.artifacts.put_json(forged_plan)
    run = case.store.require_analysis_run(case.identity.analysis_id)
    case.store.save_analysis_run(
        run.model_copy(update={"surface_enrichment_v5_plan_ref": forged_ref})
    )

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V3_PLAN_INVALID"):
        evaluate_surface_coverage_v3(
            case.identity,
            case.index,
            prior,
            forged_plan,
            case.progress,
            case.store,
            case.artifacts,
        )


def test_v3_rejects_terminal_with_wrong_v2_certificate_hash(tmp_path: Path) -> None:
    case, prior, _ref, plan, _parts, _graph, _graph_ref = _v5_case(tmp_path)
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.candidate_terminal is not None
    case.store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_terminal": run.candidate_terminal.model_copy(
                    update={"scope_certificate_hash": "0" * 64}
                )
            }
        )
    )

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V3_PLAN_INVALID"):
        evaluate_surface_coverage_v3(
            case.identity,
            case.index,
            prior,
            plan,
            case.progress,
            case.store,
            case.artifacts,
        )


def test_v3_recomputes_global_pending_children_before_complete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case, prior, _ref, plan, parts, graph, graph_ref = _v5_case(tmp_path)
    _save_verified_v5_part(case, parts[0], graph, graph_ref)
    monkeypatch.setattr(
        case.store,
        "list_incomplete_hypotheses",
        lambda _identity, *, after_id, limit: (
            ("unlinked-child",) if after_id is None else ()
        ),
    )

    proof = evaluate_surface_coverage_v3(
        case.identity,
        case.index,
        prior,
        plan,
        case.progress,
        case.store,
        case.artifacts,
    )

    assert all(row.coverage_status == "COVERED" for row in proof.surfaces)
    assert proof.pending_child_count == 1
    assert proof.complete is False


def test_read_saved_v3_requires_exact_cas_and_pinned_prior(
    tmp_path: Path,
) -> None:
    case, prior, prior_ref, plan, _parts, _graph, _graph_ref = _v5_case(tmp_path)
    proof = evaluate_surface_coverage_v3(
        case.identity,
        case.index,
        prior,
        plan,
        case.progress,
        case.store,
        case.artifacts,
    )
    coverage_ref = case.artifacts.put_json(proof.to_json())
    saved_bytes = case.artifacts.read(coverage_ref)

    loaded = surface_coverage_v3.read_saved_coverage_v3(
        case.artifacts,
        case.index,
        coverage_ref,
        prior_v2_ref=prior_ref,
        v5_plan_ref=proof.v5_plan_ref,
    )
    assert loaded == proof
    assert case.artifacts.read(coverage_ref) == saved_bytes

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V3_SAVED_INVALID"):
        surface_coverage_v3.read_saved_coverage_v3(
            case.artifacts,
            case.index,
            coverage_ref,
            prior_v2_ref=proof.original_coverage_ref,
            v5_plan_ref=proof.v5_plan_ref,
        )


def test_v3_terminal_resume_recounts_current_pending_without_v2_evaluator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case, prior, prior_ref, plan, _parts, _graph, _graph_ref = _v5_case(tmp_path)
    saved_proof = evaluate_surface_coverage_v3(
        case.identity,
        case.index,
        prior,
        plan,
        case.progress,
        case.store,
        case.artifacts,
    )
    assert saved_proof.complete is False
    coverage_ref = case.artifacts.put_json(saved_proof.to_json())
    saved_bytes = case.artifacts.read(coverage_ref)
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.candidate_terminal is not None
    case.store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_terminal": run.candidate_terminal.model_copy(
                    update={
                        "surface_proof_version": 3,
                        "surface_coverage_hash": coverage_ref.content_hash,
                    }
                )
            }
        )
    )
    monkeypatch.setattr(
        case.store,
        "list_incomplete_hypotheses",
        lambda _identity, *, after_id, limit: (
            ("new-child",) if after_id is None else ()
        ),
    )
    monkeypatch.setattr(
        surface_coverage_v2,
        "evaluate_surface_coverage_v2",
        lambda *_args, **_kwargs: pytest.fail("v2 evaluator must not rerun"),
    )

    resumed = evaluate_surface_coverage_v3(
        case.identity,
        case.index,
        prior,
        plan,
        case.progress,
        case.store,
        case.artifacts,
    )

    assert resumed.prior_v2_ref == prior_ref
    assert resumed.pending_child_count == 1
    assert resumed.complete is False
    assert case.artifacts.read(coverage_ref) == saved_bytes


def test_verified_saved_v3_rejects_current_pending_drift(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case, prior, _ref, plan, _parts, _graph, _graph_ref = _v5_case(tmp_path)
    for row in case.progress.values():
        case.store.commit_surface_exploration(
            case.identity,
            case.index.scope_fingerprint,
            row.surface_id,
            row.context_id,
            static_bundle_hash=row.static_bundle_hash,
            index_hash=row.index_hash,
            context_hash=row.context_hash,
            source_sha256=row.source_sha256,
            status=row.status,
            result_ref=row.result_ref,
            registrations=(),
            proposal_version=row.proposal_version,
        )
    proof = evaluate_surface_coverage_v3(
        case.identity,
        case.index,
        prior,
        plan,
        case.progress,
        case.store,
        case.artifacts,
    )
    coverage_ref = case.artifacts.put_json(proof.to_json())
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.candidate_terminal is not None
    case.store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_terminal": run.candidate_terminal.model_copy(
                    update={
                        "surface_proof_version": 3,
                        "surface_coverage_hash": coverage_ref.content_hash,
                    }
                )
            }
        )
    )

    verified = surface_coverage_v3.verified_saved_coverage_v3(
        case.identity, case.index, coverage_ref, case.store, case.artifacts
    )
    assert verified == proof

    monkeypatch.setattr(
        case.store,
        "list_incomplete_hypotheses",
        lambda _identity, *, after_id, limit: (
            ("new-child",) if after_id is None else ()
        ),
    )
    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V3_VERIFIED_INVALID"):
        surface_coverage_v3.verified_saved_coverage_v3(
            case.identity, case.index, coverage_ref, case.store, case.artifacts
        )


def test_verified_saved_v3_accepts_persisted_connected_complete_proof(
    tmp_path: Path,
) -> None:
    case, prior, _ref, plan, parts, graph, graph_ref = _v5_case(tmp_path)
    _save_verified_v5_part(case, parts[0], graph, graph_ref)
    for row in case.progress.values():
        case.store.commit_surface_exploration(
            case.identity,
            case.index.scope_fingerprint,
            row.surface_id,
            row.context_id,
            static_bundle_hash=row.static_bundle_hash,
            index_hash=row.index_hash,
            context_hash=row.context_hash,
            source_sha256=row.source_sha256,
            status=row.status,
            result_ref=row.result_ref,
            registrations=(),
            proposal_version=row.proposal_version,
        )
    proof = evaluate_surface_coverage_v3(
        case.identity,
        case.index,
        prior,
        plan,
        case.progress,
        case.store,
        case.artifacts,
    )
    assert proof.complete is True
    coverage_ref = case.artifacts.put_json(proof.to_json())
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.candidate_terminal is not None
    case.store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_terminal": run.candidate_terminal.model_copy(
                    update={
                        "status": "COMPLETE",
                        "surface_proof_version": 3,
                        "surface_coverage_hash": coverage_ref.content_hash,
                        "surface_counts": {
                            "COVERED": 2,
                            "UNCOVERED": 0,
                            "INSUFFICIENT": 0,
                        },
                    }
                )
            }
        )
    )

    verified = surface_coverage_v3.verified_saved_coverage_v3(
        case.identity, case.index, coverage_ref, case.store, case.artifacts
    )

    assert verified == proof
    assert verified.complete is True


def test_verified_saved_v3_rejects_forged_covered_row_without_v5_part(
    tmp_path: Path,
) -> None:
    case, prior, _ref, plan, _parts, _graph, _graph_ref = _v5_case(tmp_path)
    for row in case.progress.values():
        case.store.commit_surface_exploration(
            case.identity,
            case.index.scope_fingerprint,
            row.surface_id,
            row.context_id,
            static_bundle_hash=row.static_bundle_hash,
            index_hash=row.index_hash,
            context_hash=row.context_hash,
            source_sha256=row.source_sha256,
            status=row.status,
            result_ref=row.result_ref,
            registrations=(),
            proposal_version=row.proposal_version,
        )
    proof = evaluate_surface_coverage_v3(
        case.identity,
        case.index,
        prior,
        plan,
        case.progress,
        case.store,
        case.artifacts,
    )
    forged = deepcopy(proof.to_json())
    surfaces = forged["surfaces"]
    assert isinstance(surfaces, list)
    assert isinstance(surfaces[0], dict)
    surfaces[0]["coverage_status"] = "COVERED"
    surfaces[0]["unresolved_reason_codes"] = []
    forged["complete"] = True
    coverage_ref = case.artifacts.put_json(forged)
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.candidate_terminal is not None
    case.store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_terminal": run.candidate_terminal.model_copy(
                    update={
                        "status": "COMPLETE",
                        "surface_proof_version": 3,
                        "surface_coverage_hash": coverage_ref.content_hash,
                        "surface_counts": {
                            "COVERED": 2,
                            "UNCOVERED": 0,
                            "INSUFFICIENT": 0,
                        },
                    }
                )
            }
        )
    )

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V3_VERIFIED_INVALID"):
        surface_coverage_v3.verified_saved_coverage_v3(
            case.identity, case.index, coverage_ref, case.store, case.artifacts
        )
