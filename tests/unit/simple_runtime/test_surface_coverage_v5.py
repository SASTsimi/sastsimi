"""V7 coverage adds reviewed evidence without hiding v6 gaps or children."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SurfaceExplorationProgressRecord
from sastsimi.simple_runtime.surface_coverage_v2 import (
    _child_reasons as original_child_reasons,
)
from sastsimi.simple_runtime.surface_coverage_v2 import (
    _related_child_ids as original_related_child_ids,
)
from sastsimi.simple_runtime.surface_evidence_validation_v5 import (
    validate_v7_response,
)
from tests.unit.simple_runtime.test_surface_coverage_v4 import (
    _evaluate as _evaluate_v4,
)
from tests.unit.simple_runtime.test_surface_coverage_v4 import (
    _save_v6_part,
)
from tests.unit.simple_runtime.test_surface_enrichment_v7 import _case, _prepare
from tests.unit.simple_runtime.test_surface_proposal import _proposal


def _v7_case(
    tmp_path: Path,
    *,
    missing_v6: bool = False,
    unrelated_gap: bool = False,
    claimed_path_gap: bool = False,
    second_sink_path: bool = False,
    second_path_blocked: bool = True,
) -> dict[str, Any]:
    data = _case(tmp_path)
    if missing_v6:
        old = data["parts"][0]
        del data["case"].progress[(old.surface_id, old.context_id)]
        from tests.unit.simple_runtime.test_surface_coverage_v4 import _evaluate

        parent = _evaluate(data)
        data["parent"] = parent
        data["parent_ref"] = data["case"].artifacts.put_json(parent.to_json())
    if unrelated_gap:
        graph = next(iter(data["new_graphs"].values()))
        graph["gaps"].append(
            {"path": "other.py", "reason": "UNRELATED_DYNAMIC_DISPATCH"}
        )
    if claimed_path_gap:
        graph = next(iter(data["new_graphs"].values()))
        graph["paths"][0]["blocking_gaps"] = ["DYNAMIC_DISPATCH_UNRESOLVED"]
    if second_sink_path:
        graph = next(iter(data["new_graphs"].values()))
        extra = deepcopy(graph["paths"][0])
        extra["path_id"] = "path-second"
        extra["blocking_gaps"] = (
            ["DYNAMIC_DISPATCH_UNRESOLVED"] if second_path_blocked else []
        )
        for step in extra["steps"]:
            step["node_id"] += "-second"
        extra["edge_ids"] = [edge_id + "-second" for edge_id in extra["edge_ids"]]
        for edge in list(graph["edges"]):
            copy = deepcopy(edge)
            copy["edge_id"] += "-second"
            copy["from_node_id"] += "-second"
            copy["to_node_id"] += "-second"
            copy["graph_path_id"] = "path-second"
            graph["edges"].append(copy)
        graph["nodes"].extend(deepcopy(extra["steps"]))
        graph["paths"].append(extra)
    plan, parts = _prepare(data)
    case = data["case"]
    for v7_part in parts:
        case.artifacts.put_json(v7_part.payload)
    part = parts[0]
    graph = data["new_graphs"][part.surface_id]
    return {
        **data,
        "v7_plan": plan,
        "v7_plan_ref": case.artifacts.put_json(plan),
        "v7_parts": parts,
        "v7_graph_ref": case.artifacts.put_json(graph),
        "v7_context_ref": case.artifacts.put_json(part.payload),
    }


def _save_v7_part(
    data: dict[str, Any], *, connected: bool = True, part_index: int = 0
) -> None:
    case = data["case"]
    part = data["v7_parts"][part_index]
    path_id = part.payload.get("target_path_id") or "path-real"
    suffix = "-second" if path_id == "path-second" else ""
    graph_ref = case.artifacts.put_json(data["new_graphs"][part.surface_id])
    context_ref = case.artifacts.put_json(part.payload)
    sink_line = next(
        surface.line
        for surface in case.index.surfaces
        if surface.surface_id == part.surface_id
    )
    response = {
        "surface_id": part.surface_id,
        "context_id": part.context_id,
        "status": (
            "NO_HYPOTHESIS"
            if connected and part.payload["review_mode"] == "STANDARD"
            else "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
        ),
        "reason": "Reviewed pinned source",
        "hypotheses": [],
        "review_evidence": [
            {
                "part": role,
                "location": f"app.py:{line}",
                "context_hash": part.context_hash,
                "source_sha256": part.source_sha256,
                "graph_path_id": path_id,
                "edge_ids": [edge + suffix for edge in edges],
                "explanation": "Source-bound path role",
            }
            for role, line, edges in (
                ("ENTRY", 1, ["edge-entry"]),
                ("TRUST_BOUNDARY", 3, ["edge-entry", "edge-sink"]),
                ("SENSITIVE_OPERATION", sink_line, ["edge-sink"]),
            )
        ]
        if connected
        else [],
    }
    checked = validate_v7_response(
        {
            "context_payload": part.payload,
            "graph_payload": data["new_graphs"][part.surface_id],
            "context_hash": part.context_hash,
            "context_id": part.context_id,
        },
        response,
    )
    result_ref = case.artifacts.put_json(
        {
            "kind": "simple_surface_hypothesis_result_v7",
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
            proposal_version=7,
        )
    )


def _evaluate(data: dict[str, Any]) -> Any:
    from sastsimi.simple_runtime.surface_coverage_v5 import (
        evaluate_surface_coverage_v5,
    )

    case = data["case"]
    return evaluate_surface_coverage_v5(
        case.identity,
        case.index,
        case.index_ref,
        data["parent_ref"],
        data["parent"],
        data["plan_ref"],
        data["plan"],
        data["v7_plan_ref"],
        data["v7_plan"],
        case.progress,
        case.store,
        case.artifacts,
    )


def test_v7_connected_part_can_clear_only_newly_proven_graph_gap(
    tmp_path: Path,
) -> None:
    data = _v7_case(tmp_path)
    _save_v7_part(data)

    proof = _evaluate(data)

    assert proof.surfaces[0].coverage_status == "COVERED"
    assert proof.surfaces[1].coverage_status == "INSUFFICIENT"
    assert "SURFACE_PART_PENDING" in (proof.surfaces[1].unresolved_reason_codes)
    assert proof.complete is False
    assert proof.v7_plan_ref == data["v7_plan_ref"]
    assert proof.prior_v4_ref == data["parent_ref"]
    assert set(data["parent"].surfaces[0].evidence_refs).issubset(
        proof.surfaces[0].evidence_refs
    )


def test_v7_recertified_inherited_covered_can_complete_only_after_its_own_part(
    tmp_path: Path,
) -> None:
    data = _v7_case(tmp_path)
    _save_v7_part(data)
    assert _evaluate(data).complete is False

    _save_v7_part(data, part_index=1)
    proof = _evaluate(data)

    assert proof.complete is True
    assert [row.coverage_status for row in proof.surfaces] == ["COVERED", "COVERED"]
    assert proof.surfaces[1].prior_v4_status == "COVERED"


def test_v7_refreshes_inherited_covered_child_hold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sastsimi.simple_runtime.surface_coverage_v5 as coverage

    data = _v7_case(tmp_path)
    _save_v7_part(data)
    inherited_id = data["parent"].surfaces[1].surface_id

    def related(
        identity: Any, surface: Any, progress: Any, store: Any, scope: str
    ) -> set[str]:
        if surface.surface_id == inherited_id:
            return {"new-bound-child"}
        return original_related_child_ids(identity, surface, progress, store, scope)

    def child_reasons(
        identity: Any, child_id: str, store: Any, artifacts: Any
    ) -> tuple[str, ...]:
        if child_id == "new-bound-child":
            return ("CHILD_HOLD",)
        return original_child_reasons(identity, child_id, store, artifacts)

    monkeypatch.setattr(coverage, "_related_child_ids", related)
    monkeypatch.setattr(coverage, "_child_reasons", child_reasons)

    proof = _evaluate(data)

    assert proof.complete is False
    assert proof.surfaces[1].coverage_status == "INSUFFICIENT"
    assert "CHILD_HOLD" in proof.surfaces[1].unresolved_reason_codes


def test_v7_missing_parent_part_remains_explicitly_insufficient(tmp_path: Path) -> None:
    data = _v7_case(tmp_path, missing_v6=True)
    _save_v7_part(data)

    proof = _evaluate(data)

    assert proof.complete is False
    assert proof.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "PRIOR_V6_PART_MISSING" in proof.surfaces[0].unresolved_reason_codes
    assert "SURFACE_PART_PENDING" in proof.surfaces[0].unresolved_reason_codes


def test_v7_uses_claimed_path_gaps_without_discarding_other_graph_gaps(
    tmp_path: Path,
) -> None:
    unrelated = _v7_case(tmp_path / "unrelated", unrelated_gap=True)
    _save_v7_part(unrelated)
    proof = _evaluate(unrelated)
    assert proof.surfaces[0].coverage_status == "COVERED"
    assert unrelated["new_graphs"][proof.surfaces[0].surface_id]["gaps"]

    blocked = _v7_case(tmp_path / "blocked", claimed_path_gap=True)
    _save_v7_part(blocked, connected=False)
    blocked_proof = _evaluate(blocked)
    assert blocked_proof.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "CONNECTED_ROLE_PROOF_MISSING" in (
        blocked_proof.surfaces[0].unresolved_reason_codes
    )


def test_v7_does_not_clear_other_same_sink_path_gap(tmp_path: Path) -> None:
    data = _v7_case(tmp_path, second_sink_path=True)
    _save_v7_part(data)

    proof = _evaluate(data)

    assert proof.complete is False
    assert proof.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "UNREVIEWED_RELEVANT_PATH" in proof.surfaces[0].unresolved_reason_codes


def test_v7_review_parts_are_one_per_same_sink_path(tmp_path: Path) -> None:
    data = _v7_case(tmp_path, second_sink_path=True, second_path_blocked=False)
    first_id = data["case"].index.surfaces[0].surface_id
    first_parts = [
        (index, part)
        for index, part in enumerate(data["v7_parts"])
        if part.surface_id == first_id
    ]
    assert {part.payload["target_path_id"] for _, part in first_parts} == {
        "path-real",
        "path-second",
    }
    assert len(first_parts) == 2

    _save_v7_part(data, part_index=first_parts[0][0])
    one_path = _evaluate(data)
    assert one_path.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "UNREVIEWED_RELEVANT_PATH" in one_path.surfaces[0].unresolved_reason_codes

    _save_v7_part(data, part_index=first_parts[1][0])
    both_paths = _evaluate(data)
    assert both_paths.surfaces[0].coverage_status == "COVERED"
    assert "UNREVIEWED_RELEVANT_PATH" not in (
        both_paths.surfaces[0].unresolved_reason_codes
    )


def test_v7_does_not_clear_unmaterialized_same_surface_route_gap(
    tmp_path: Path,
) -> None:
    data = _case(tmp_path)
    graph = next(iter(data["new_graphs"].values()))
    graph["gaps"].append({"path": "app.py", "reason": "DYNAMIC_DISPATCH_UNRESOLVED"})
    plan, parts = _prepare(data)
    case = data["case"]
    data.update(
        v7_plan=plan,
        v7_plan_ref=case.artifacts.put_json(plan),
        v7_parts=parts,
        v7_graph_ref=case.artifacts.put_json(graph),
        v7_context_ref=case.artifacts.put_json(parts[0].payload),
    )
    _save_v7_part(data)

    proof = _evaluate(data)

    assert proof.complete is False
    assert proof.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "UNRESOLVED_RELEVANT_GRAPH_GAP" in (
        proof.surfaces[0].unresolved_reason_codes
    )


def test_v7_unconnected_part_preserves_gap_and_progress_snapshot(
    tmp_path: Path,
) -> None:
    data = _v7_case(tmp_path)
    _save_v7_part(data, connected=False)

    proof = _evaluate(data)
    assert proof.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "CONNECTED_ROLE_PROOF_MISSING" in proof.surfaces[0].unresolved_reason_codes

    old_key = next(
        key for key, row in data["case"].progress.items() if row.proposal_version == 6
    )
    old_row = data["case"].progress[old_key]
    data["case"].progress[old_key] = replace(old_row, status="NO_HYPOTHESIS")
    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V5"):
        _evaluate(data)


def test_v7_rejects_mismatched_result_and_retains_raw_gaps(tmp_path: Path) -> None:
    data = _v7_case(tmp_path)
    _save_v7_part(data)
    case = data["case"]
    key = (data["v7_parts"][0].surface_id, data["v7_parts"][0].context_id)
    row = case.progress[key]
    corrupt = case.artifacts.put_json({"kind": "simple_surface_hypothesis_result_v7"})
    case.progress[key] = replace(row, result_ref=corrupt)
    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V5"):
        _evaluate(data)

    case.progress[key] = row
    parent = replace(data["parent"], effective_python_gaps=({"path": "unverified.py"},))
    data["parent"] = parent
    data["parent_ref"] = case.artifacts.put_json(parent.to_json())
    case.progress.pop(key)
    plan, _ = _prepare(data)
    data["v7_plan"] = plan
    data["v7_plan_ref"] = case.artifacts.put_json(plan)
    # A new parent version invalidates the prior v7 part; its raw gap must remain.
    proof = _evaluate(data)
    assert proof.complete is False
    assert proof.effective_python_gaps == ({"path": "unverified.py"},)


def test_v7_rechecks_old_child_hold_against_current_bound_child(tmp_path: Path) -> None:
    data = _case(tmp_path, old_hold=True)
    assert "CHILD_HOLD" in data["parent"].surfaces[0].unresolved_reason_codes
    plan, parts = _prepare(data)
    case = data["case"]
    data.update(
        v7_plan=plan,
        v7_plan_ref=case.artifacts.put_json(plan),
        v7_parts=parts,
        v7_graph_ref=case.artifacts.put_json(data["new_graphs"][parts[0].surface_id]),
        v7_context_ref=case.artifacts.put_json(parts[0].payload),
    )
    _save_v7_part(data)
    held = _evaluate(data)
    assert "CHILD_HOLD" in held.surfaces[0].unresolved_reason_codes

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
                "attempt_id": "v7-reviewed-child-transition",
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
    assert decisive.surfaces[0].coverage_status == "COVERED"
    assert "CHILD_HOLD" not in decisive.surfaces[0].unresolved_reason_codes
    assert not decisive.surfaces[0].unresolved_reason_codes


def test_v7_prior_hypothesis_gets_independent_rev4_review_without_losing_child(
    tmp_path: Path,
) -> None:
    data = _case(tmp_path, old_hold=True)
    _save_v6_part(data, hypotheses=[_proposal("app.py:4")])
    parent = _evaluate_v4(data)
    assert parent.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "CHILD_HOLD" in parent.surfaces[0].unresolved_reason_codes
    case = data["case"]
    data["parent"] = parent
    data["parent_ref"] = case.artifacts.put_json(parent.to_json())
    plan, parts = _prepare(data)
    assert plan["targets"][0]["review_mode"] == "STANDARD"
    data.update(
        v7_plan=plan,
        v7_plan_ref=case.artifacts.put_json(plan),
        v7_parts=parts,
        v7_graph_ref=case.artifacts.put_json(data["new_graphs"][parts[0].surface_id]),
        v7_context_ref=case.artifacts.put_json(parts[0].payload),
    )
    before_children = {
        child_id for row in case.progress.values() for child_id in row.hypothesis_ids
    }
    _save_v7_part(data)
    v7_row = case.progress[(parts[0].surface_id, parts[0].context_id)]
    assert v7_row.hypothesis_ids == ()
    held = _evaluate(data)
    assert "CHILD_HOLD" in held.surfaces[0].unresolved_reason_codes

    seed = next(
        row.hypothesis_ids[0]
        for row in case.progress.values()
        if row.proposal_version == 6
    )
    evidence_ref = case.artifacts.put_json({"kind": "decisive-child-evidence"})
    for hypothesis_id in ("hypothesis-old", seed):
        child = case.identity.model_copy(update={"hypothesis_id": hypothesis_id})
        current = case.store.get(child, SimpleStage.VERIFICATION_INITIAL_DONE)
        if current is not None:
            case.store.save_checkpoint(
                current.model_copy(
                    update={
                        "verdict": "FALSE",
                        "external_prerequisites_ref": None,
                        "output_refs": (evidence_ref,),
                        "attempt_id": "v7-skipped-child-transition",
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

    _save_v7_part(data, part_index=1)
    refreshed = _evaluate(data)
    assert "CHILD_HOLD" not in refreshed.surfaces[0].unresolved_reason_codes
    assert "CHILD_PENDING" not in refreshed.surfaces[0].unresolved_reason_codes
    assert refreshed.surfaces[0].coverage_status == "COVERED"
    assert not refreshed.surfaces[0].unresolved_reason_codes
    assert refreshed.surfaces[1].coverage_status == "COVERED"
    assert refreshed.complete is True
    assert {
        child_id for row in case.progress.values() for child_id in row.hypothesis_ids
    } == before_children
