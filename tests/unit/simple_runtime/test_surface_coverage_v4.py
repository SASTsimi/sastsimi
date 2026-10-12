"""A v4 certificate adds only a source-bound v6 delta to saved v3 bytes."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SurfaceExplorationProgressRecord
from sastsimi.simple_runtime.surface_coverage_v3 import evaluate_surface_coverage_v3
from sastsimi.simple_runtime.surface_coverage_v4 import (
    evaluate_surface_coverage_v4,
    read_saved_coverage_v4,
)
from sastsimi.simple_runtime.surface_enrichment_v6 import (
    V6Part,
    prepare_surface_enrichment_v6,
)
from sastsimi.simple_runtime.surface_evidence_validation_v5 import (
    validate_v5_response,
)
from tests.unit.simple_runtime.test_surface_coverage_v3 import (
    _save_verified_v5_part,
    _v5_case,
)
from tests.unit.simple_runtime.test_surface_proposal import _proposal


def _successor_case(tmp_path: Path, *, old_hold: bool = False) -> dict[str, Any]:
    case, prior_v2, prior_v2_ref, v5_plan, old_parts, old_graph, old_graph_ref = (
        _v5_case(tmp_path, old_hold=old_hold, trusted_graph=False)
    )
    _save_verified_v5_part(case, old_parts[0], old_graph, old_graph_ref)
    prior_v3 = evaluate_surface_coverage_v3(
        case.identity,
        case.index,
        prior_v2,
        v5_plan,
        case.progress,
        case.store,
        case.artifacts,
    )
    assert prior_v3.surfaces[0].coverage_status == "INSUFFICIENT"
    assert prior_v3.surfaces[1].coverage_status == "COVERED"
    prior_v3_ref = case.artifacts.put_json(prior_v3.to_json())
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.candidate_terminal is not None
    case.store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_terminal": run.candidate_terminal.model_copy(
                    update={
                        "surface_proof_version": 3,
                        "surface_coverage_hash": prior_v3_ref.content_hash,
                        "scope_certificate_hash": (
                            prior_v3.scope_certificate_ref.content_hash
                        ),
                        "surface_counts": {
                            "COVERED": 1,
                            "UNCOVERED": 0,
                            "INSUFFICIENT": 1,
                        },
                    }
                )
            }
        )
    )
    graph = deepcopy(old_graph)
    graph["proof_semantics_revision"] = "v5-source-bound-3"
    for path in cast(list[dict[str, object]], graph["paths"]):
        path["blocking_gaps"] = []
    graph_ref = case.artifacts.put_json(graph)
    plan, parts = prepare_surface_enrichment_v6(
        case.identity,
        case.index.scope_fingerprint,
        case.index,
        case.index_ref,
        prior_v3_ref,
        prior_v3,
        prior_v3.v5_plan_ref,
        v5_plan,
        {prior_v3.surfaces[0].surface_id: graph},
        required_graph_revision="v5-source-bound-3",
    )
    plan_ref = case.artifacts.put_json(plan)
    run = case.store.require_analysis_run(case.identity.analysis_id)
    case.store.save_analysis_run(
        run.model_copy(update={"surface_enrichment_v6_plan_ref": plan_ref})
    )
    return {
        "case": case,
        "prior_v2_ref": prior_v2_ref,
        "prior_v3": prior_v3,
        "prior_v3_ref": prior_v3_ref,
        "prior_v5_plan_ref": prior_v3.v5_plan_ref,
        "plan": plan,
        "plan_ref": plan_ref,
        "parts": parts,
        "graph": graph,
        "graph_ref": graph_ref,
    }


def _evaluate(data: dict[str, Any]) -> Any:
    case = data["case"]
    return evaluate_surface_coverage_v4(
        case.identity,
        case.index,
        data["prior_v3_ref"],
        data["prior_v3"],
        data["prior_v5_plan_ref"],
        data["plan_ref"],
        data["plan"],
        case.progress,
        case.store,
        case.artifacts,
    )


def _save_v6_part(
    data: dict[str, Any],
    *,
    connected: bool = True,
    hypotheses: list[dict[str, object]] | None = None,
) -> None:
    case = data["case"]
    part: V6Part = data["parts"][0]
    graph_ref: StoredDataRef = data["graph_ref"]
    graph = data["graph"]
    context_ref = case.artifacts.put_json(part.payload)
    source_sha = dict(case.index.ast_source_hashes)["app.py"]
    response = {
        "surface_id": part.surface_id,
        "context_id": part.context_id,
        "status": (
            "HYPOTHESES"
            if hypotheses
            else "NO_HYPOTHESIS"
            if connected
            else "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
        ),
        "reason": "Exact source path reviewed",
        "hypotheses": hypotheses or [],
        "review_evidence": [
            {
                "part": role,
                "location": f"app.py:{line}",
                "context_hash": part.context_hash,
                "source_sha256": source_sha,
                "graph_path_id": "path-real",
                "edge_ids": edges,
                "explanation": "Reviewed source path and edge",
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
    checked = validate_v5_response(
        {
            "context_payload": part.payload,
            "graph_payload": graph,
            "context_hash": part.context_hash,
            "context_id": part.context_id,
        },
        response,
    )
    seed_ids = [
        "hypothesis-"
        + hashlib.sha256(
            part.surface_id.encode("utf-8")
            + part.context_id.encode("utf-8")
            + canonical_bytes(proposal)
        ).hexdigest()[:32]
        for proposal, _ in checked.qualified
    ]
    result_ref = case.artifacts.put_json(
        {
            "kind": "simple_surface_hypothesis_result_v6",
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
            "seed_ids": seed_ids,
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
            hypothesis_ids=tuple(seed_ids),
            proposal_version=6,
        )
    )


def test_missing_v6_part_keeps_v3_insufficient_and_covered_row(tmp_path: Path) -> None:
    data = _successor_case(tmp_path)

    proof = _evaluate(data)

    assert proof.complete is False
    assert proof.prior_v3_ref == data["prior_v3_ref"]
    assert proof.v6_plan_ref == data["plan_ref"]
    assert proof.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "SURFACE_PART_PENDING" in proof.surfaces[0].unresolved_reason_codes
    assert proof.surfaces[1].coverage_status == "COVERED"
    assert (
        proof.surfaces[1].verified_roles == data["prior_v3"].surfaces[1].verified_roles
    )
    assert proof.surfaces[1].evidence_refs == data["prior_v3"].surfaces[1].evidence_refs


def test_connected_v6_part_clears_only_graph_reasons_and_reads_exact_bytes(
    tmp_path: Path,
) -> None:
    data = _successor_case(tmp_path)
    _save_v6_part(data)

    proof = _evaluate(data)

    assert proof.complete is True
    assert proof.surfaces[0].coverage_status == "COVERED"
    assert set(data["prior_v3"].surfaces[0].evidence_refs).issubset(
        proof.surfaces[0].evidence_refs
    )
    saved_ref = data["case"].artifacts.put_json(proof.to_json())
    assert (
        read_saved_coverage_v4(
            data["case"].artifacts,
            data["case"].index,
            saved_ref,
            prior_v3_ref=data["prior_v3_ref"],
            prior_v5_plan_ref=data["prior_v5_plan_ref"],
            v6_plan_ref=data["plan_ref"],
        )
        == proof
    )


def test_unconnected_v6_review_does_not_clear_graph_reasons(tmp_path: Path) -> None:
    data = _successor_case(tmp_path)
    _save_v6_part(data, connected=False)

    proof = _evaluate(data)

    assert proof.complete is False
    assert proof.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "CONNECTED_ROLE_PROOF_MISSING" in proof.surfaces[0].unresolved_reason_codes


def test_old_hold_needs_current_decisive_child_even_with_connected_v6(
    tmp_path: Path,
) -> None:
    data = _successor_case(tmp_path, old_hold=True)
    _save_v6_part(data)

    held = _evaluate(data)
    assert held.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "CHILD_HOLD" in held.surfaces[0].unresolved_reason_codes

    case = data["case"]
    child = case.identity.model_copy(update={"hypothesis_id": "hypothesis-old"})
    current = case.store.get(child, SimpleStage.VERIFICATION_INITIAL_DONE)
    assert current is not None
    evidence_ref = case.artifacts.put_json({"kind": "new-decisive-child-evidence"})
    case.store.save_checkpoint(
        current.model_copy(
            update={
                "verdict": "FALSE",
                "external_prerequisites_ref": None,
                "output_refs": (evidence_ref,),
                "attempt_id": "v6-reviewed-child-transition",
                "attempt_number": current.attempt_number + 1,
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
            output_refs=(evidence_ref,),
            verdict="FALSE",
        )
    )

    decisive = _evaluate(data)
    assert decisive.complete is True
    assert "CHILD_HOLD" not in decisive.surfaces[0].unresolved_reason_codes


@pytest.mark.parametrize("tamper", ["delete", "remove_child", "replace_result"])
def test_v6_rejects_changed_pinned_old_child_progress(
    tmp_path: Path, tamper: str
) -> None:
    data = _successor_case(tmp_path, old_hold=True)
    _save_v6_part(data)
    case = data["case"]
    key = next(
        key
        for key, row in case.progress.items()
        if row.proposal_version == 3 and row.hypothesis_ids
    )
    old = case.progress[key]
    if tamper == "delete":
        del case.progress[key]
    elif tamper == "remove_child":
        case.progress[key] = replace(old, hypothesis_ids=())
    else:
        case.progress[key] = replace(
            old, result_ref=case.artifacts.put_json({"kind": "changed-old-result"})
        )

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V4_PLAN_INVALID"):
        _evaluate(data)


def test_v6_new_seed_cannot_hide_lost_old_hold_link(tmp_path: Path) -> None:
    data = _successor_case(tmp_path, old_hold=True)
    _save_v6_part(data, hypotheses=[_proposal("app.py:4")])
    case = data["case"]
    old_key = next(
        key for key, row in case.progress.items() if row.proposal_version == 3
    )
    del case.progress[old_key]
    new_record = next(
        row for row in case.progress.values() if row.proposal_version == 6
    )
    assert len(new_record.hypothesis_ids) == 1
    child = case.identity.model_copy(
        update={"hypothesis_id": new_record.hypothesis_ids[0]}
    )
    decisive_ref = case.artifacts.put_json({"kind": "new-seed-decisive"})
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

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V4_PLAN_INVALID"):
        _evaluate(data)


def test_rejects_unbound_v6_progress_and_changed_context(tmp_path: Path) -> None:
    data = _successor_case(tmp_path)
    _save_v6_part(data)
    case = data["case"]
    part: V6Part = data["parts"][0]
    saved = case.progress[(part.surface_id, part.context_id)]
    case.progress[(part.surface_id, "extra-context")] = replace(
        saved, context_id="extra-context"
    )
    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V4"):
        _evaluate(data)
    del case.progress[(part.surface_id, "extra-context")]
    case.progress[(part.surface_id, part.context_id)] = replace(
        saved, context_hash="0" * 64
    )
    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V4"):
        _evaluate(data)


def test_saved_reader_rejects_forged_covered_row(tmp_path: Path) -> None:
    data = _successor_case(tmp_path)
    proof = _evaluate(data)
    payload = proof.to_json()
    surfaces = payload["surfaces"]
    assert isinstance(surfaces, list)
    assert isinstance(surfaces[0], dict)
    surfaces[0]["coverage_status"] = "COVERED"
    surfaces[0]["unresolved_reason_codes"] = []
    forged = data["case"].artifacts.put_json(payload)

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V4_SAVED_INVALID"):
        read_saved_coverage_v4(
            data["case"].artifacts,
            data["case"].index,
            forged,
            prior_v3_ref=data["prior_v3_ref"],
            prior_v5_plan_ref=data["prior_v5_plan_ref"],
            v6_plan_ref=data["plan_ref"],
        )
