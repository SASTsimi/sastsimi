"""A finished, unproven hypothesis must not erase verified path coverage."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.reporting.bilingual_bundle import coverage_report_lines
from sastsimi.reporting.coverage_disclosure import CoverageDisclosure
from sastsimi.simple_runtime.models import (
    MAX_RECOVERY_ATTEMPTS,
    STAGE_VERSION,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_proof_read import (
    verified_surface_coverage_counts,
)
from tests.unit.simple_runtime.test_surface_coverage_v5 import (
    _evaluate,
    _save_v7_part,
)
from tests.unit.simple_runtime.test_surface_enrichment_v7 import _case, _prepare


def _base_case(tmp_path: Path) -> dict[str, Any]:
    data = _case(tmp_path, old_hold=True)
    return data


def _finish_plan(data: dict[str, Any]) -> dict[str, Any]:
    case = data["case"]
    plan, parts = _prepare(data)
    data.update(v7_plan=plan, v7_plan_ref=case.artifacts.put_json(plan), v7_parts=parts)
    return data


def _case_with_terminal_initial_hold(tmp_path: Path) -> dict[str, Any]:
    data = _base_case(tmp_path)
    case = data["case"]
    child = case.identity.model_copy(update={"hypothesis_id": "hypothesis-old"})
    old = case.store.get(child, SimpleStage.VERIFICATION_INITIAL_DONE)
    assert old is not None
    attempt_id = "completed-inconclusive-initial"
    evidence_ref = case.artifacts.put_json(
        {
            "kind": "simple_initial_verification",
            "attempt_id": attempt_id,
            "result": {
                "initial_assessment": "HOLD",
                "environment_requirements": [],
                "unmet_external_prerequisites": ["A local browser is unavailable."],
                "limitations": ["Cookie delivery was not observed."],
                "rationale": "Source path is reached; exploitation is unproven.",
                "reproduction_goal": "Observe the request in a real browser.",
                "supporting_refs": [],
            },
        }
    )
    completed = old.model_copy(
        update={
            "attempt_id": attempt_id,
            "output_refs": (evidence_ref,),
            "external_prerequisites_ref": evidence_ref,
        }
    )
    case.store.save_checkpoint(completed)
    assert case.store.verified_terminal_initial_outcome(completed) == "INCONCLUSIVE"
    return _finish_plan(data)


def _case_with_terminal_poc_hold(
    tmp_path: Path,
    *,
    omit_stage: SimpleStage | None = None,
    register_origin: bool = True,
    unregistered_pro_con_input: bool = False,
    origin_hypothesis_id: str = "hypothesis-old",
    malformed_origin: bool = False,
) -> dict[str, Any]:
    data = _base_case(tmp_path)
    case = data["case"]
    child = case.identity.model_copy(update={"hypothesis_id": "hypothesis-old"})
    initial = case.store.get(child, SimpleStage.VERIFICATION_INITIAL_DONE)
    assert initial is not None
    proposal = {
        "kind": "simple_hypothesis_proposal",
        "analysis_id": case.identity.analysis_id,
        "hypothesis_id": origin_hypothesis_id,
        "proposal": {"title": "Source-bound test proposal"},
    }
    proposal_ref = (
        case.artifacts.put_json({**proposal, "kind": "damaged_proposal"})
        if malformed_origin
        else case.artifacts.put_prompt_proposal(proposal)
    )
    if register_origin:
        case.store.upsert_hypothesis(case.identity, "hypothesis-old", proposal_ref)
    if unregistered_pro_con_input:
        proposal_ref = case.artifacts.put_prompt_proposal(
            {
                "kind": "simple_hypothesis_proposal",
                "analysis_id": case.identity.analysis_id,
                "hypothesis_id": "hypothesis-old",
                "proposal": {"title": "Unregistered alternative"},
            }
        )
    pro_con_ref = case.artifacts.put_json({"kind": "simple_pro_con_review"})
    if omit_stage is not SimpleStage.PRO_CON_DONE:
        case.store.save_checkpoint(
            StageCheckpoint(
                identity=child,
                stage=SimpleStage.PRO_CON_DONE,
                stage_version=STAGE_VERSION[SimpleStage.PRO_CON_DONE],
                status=StageStatus.SUCCEEDED,
                input_refs=(proposal_ref,),
                input_hash=input_reference_hash((proposal_ref,)),
                output_refs=(pro_con_ref,),
            )
        )
    initial_ref = case.artifacts.put_json({"kind": "nonterminal_initial_review"})
    if omit_stage is SimpleStage.VERIFICATION_INITIAL_DONE:
        case.store.invalidate_from(
            child,
            SimpleStage.VERIFICATION_INITIAL_DONE,
            new_inputs=(pro_con_ref,),
            force=True,
        )
    else:
        case.store.save_checkpoint(
            initial.model_copy(
                update={
                    "attempt_id": "poc-initial-complete",
                    "verdict": None,
                    "external_prerequisites_ref": None,
                    "input_refs": (pro_con_ref,),
                    "input_hash": input_reference_hash((pro_con_ref,)),
                    "output_refs": (initial_ref,),
                }
            )
        )
    attempt_id = "completed-inconclusive-poc"
    stdout_ref = case.artifacts.put_bytes(b"SASTSIMI_POC_INCONCLUSIVE\n", "text/plain")
    stderr_ref = case.artifacts.put_bytes(b"", "text/plain")
    content_ref = case.artifacts.put_bytes(b"print('inconclusive')\n", "text/x-python")
    candidate_ref = case.artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "content_ref": content_ref.model_dump(mode="json"),
        }
    )
    if omit_stage is not SimpleStage.POC_CANDIDATE_DONE:
        case.store.save_checkpoint(
            StageCheckpoint(
                identity=child,
                stage=SimpleStage.POC_CANDIDATE_DONE,
                stage_version=STAGE_VERSION[SimpleStage.POC_CANDIDATE_DONE],
                status=StageStatus.SUCCEEDED,
                input_refs=(initial_ref,),
                input_hash=input_reference_hash((initial_ref,)),
                output_refs=(candidate_ref, content_ref),
                attempt_id="completed-inconclusive-poc",
            )
        )
    inputs = (candidate_ref, content_ref)
    execution_ref = case.artifacts.put_json(
        {
            "kind": "simple_poc_execution",
            "attempt_id": attempt_id,
            "candidate_ref": candidate_ref.model_dump(mode="json"),
            "content_ref": content_ref.model_dump(mode="json"),
            "stdout_ref": stdout_ref.model_dump(mode="json"),
            "stderr_ref": stderr_ref.model_dump(mode="json"),
            "exit_code": 0,
            "timed_out": False,
            "container_id": "isolated-container",
        }
    )
    interpretation_ref = case.artifacts.put_json(
        {
            "kind": "simple_dynamic_interpretation",
            "execution_ref": execution_ref.model_dump(mode="json"),
            "result": {
                "outcome": "INCONCLUSIVE",
                "rationale": "No decisive observation",
            },
        }
    )
    cleanup_ref = case.artifacts.put_json(
        {
            "kind": "simple_container_cleanup",
            "attempt_id": attempt_id,
            "container_id": "isolated-container",
            "status": "REMOVED",
        }
    )
    completed = StageCheckpoint(
        identity=child,
        stage=SimpleStage.POC_EXECUTION_DONE,
        stage_version=STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=inputs,
        input_hash=input_reference_hash(inputs),
        output_refs=(execution_ref, interpretation_ref, cleanup_ref),
        attempt_id=attempt_id,
        attempt_number=MAX_RECOVERY_ATTEMPTS,
        container_id="isolated-container",
        verdict="HOLD",
    )
    case.store.save_checkpoint(completed)
    assert case.store.verified_terminal_poc_outcome(completed) == "INCONCLUSIVE"
    return _finish_plan(data)


def _review_all_v7_paths(data: dict[str, Any]) -> None:
    for index in range(len(data["v7_parts"])):
        _save_v7_part(data, part_index=index)


def test_initial_free_text_prerequisite_remains_hold_after_reviewed_paths(
    tmp_path: Path,
) -> None:
    data = _case_with_terminal_initial_hold(tmp_path)
    case = data["case"]
    child = case.identity.model_copy(update={"hypothesis_id": "hypothesis-old"})
    original = case.store.get(child, SimpleStage.VERIFICATION_INITIAL_DONE)
    assert original is not None
    _review_all_v7_paths(data)

    proof = _evaluate(data)

    assert proof.complete is False
    assert "CHILD_HOLD" in proof.surfaces[0].unresolved_reason_codes
    assert case.store.get(child, SimpleStage.VERIFICATION_INITIAL_DONE) == original
    assert not proof.surfaces[0].completed_inconclusive_children


def test_terminal_inconclusive_does_not_clear_unreviewed_v7_path(
    tmp_path: Path,
) -> None:
    data = _case_with_terminal_poc_hold(tmp_path)
    _save_v7_part(data, part_index=0)

    proof = _evaluate(data)

    assert proof.complete is False
    assert proof.surfaces[1].coverage_status == "INSUFFICIENT"
    assert "SURFACE_PART_PENDING" in proof.surfaces[1].unresolved_reason_codes


def test_verified_terminal_poc_inconclusive_does_not_block_reviewed_paths(
    tmp_path: Path,
) -> None:
    data = _case_with_terminal_poc_hold(tmp_path)
    case = data["case"]
    child = case.identity.model_copy(update={"hypothesis_id": "hypothesis-old"})
    original = case.store.get(child, SimpleStage.POC_EXECUTION_DONE)
    assert original is not None
    _review_all_v7_paths(data)

    proof = _evaluate(data)

    assert proof.complete is True
    assert case.store.get(child, SimpleStage.POC_EXECUTION_DONE) == original
    first = proof.to_json()["surfaces"][0]
    assert first["completed_inconclusive_children"] == [
        {
            "hypothesis_id": "hypothesis-old",
            "stage": "POC_EXECUTION_DONE",
            "checkpoint_sha256": hashlib.sha256(canonical_bytes(original)).hexdigest(),
            "output_refs": [
                ref.model_dump(mode="json") for ref in original.output_refs
            ],
        }
    ]


def test_registered_hypothesis_origin_is_readable_without_writes(
    tmp_path: Path,
) -> None:
    data = _case_with_terminal_poc_hold(tmp_path)
    case = data["case"]
    child = case.identity.model_copy(update={"hypothesis_id": "hypothesis-old"})
    pro_con = case.store.get(child, SimpleStage.PRO_CON_DONE)
    assert pro_con is not None
    reader = SimpleCheckpointStore(case.artifacts.paths.database, read_only=True)

    assert (
        reader.registered_hypothesis_ref(case.identity, "hypothesis-old")
        == (pro_con.input_refs[0])
    )
    assert reader.registered_hypothesis_ref(case.identity, "missing") is None


@pytest.mark.parametrize(
    "missing_stage",
    (
        SimpleStage.PRO_CON_DONE,
        SimpleStage.VERIFICATION_INITIAL_DONE,
        SimpleStage.POC_CANDIDATE_DONE,
    ),
)
def test_poc_without_required_predecessor_remains_hold(
    tmp_path: Path, missing_stage: SimpleStage
) -> None:
    data = _case_with_terminal_poc_hold(tmp_path, omit_stage=missing_stage)
    _review_all_v7_paths(data)

    proof = _evaluate(data)

    assert proof.complete is False
    assert "CHILD_HOLD" in proof.surfaces[0].unresolved_reason_codes
    assert not proof.surfaces[0].completed_inconclusive_children


def test_poc_with_broken_predecessor_input_chain_remains_hold(tmp_path: Path) -> None:
    data = _case_with_terminal_poc_hold(tmp_path)
    case = data["case"]
    child = case.identity.model_copy(update={"hypothesis_id": "hypothesis-old"})
    candidate = case.store.get(child, SimpleStage.POC_CANDIDATE_DONE)
    assert candidate is not None
    unrelated = case.artifacts.put_json({"kind": "unrelated_input"})
    case.store.save_checkpoint(
        candidate.model_copy(
            update={
                "input_refs": (unrelated,),
                "input_hash": input_reference_hash((unrelated,)),
            }
        )
    )
    _review_all_v7_paths(data)

    proof = _evaluate(data)

    assert proof.complete is False
    assert "CHILD_HOLD" in proof.surfaces[0].unresolved_reason_codes
    assert not proof.surfaces[0].completed_inconclusive_children


def test_poc_without_registered_hypothesis_origin_remains_hold(tmp_path: Path) -> None:
    data = _case_with_terminal_poc_hold(tmp_path, register_origin=False)
    _review_all_v7_paths(data)

    proof = _evaluate(data)

    assert proof.complete is False
    assert "CHILD_HOLD" in proof.surfaces[0].unresolved_reason_codes
    assert not proof.surfaces[0].completed_inconclusive_children


def test_poc_with_unregistered_pro_con_input_remains_hold(tmp_path: Path) -> None:
    data = _case_with_terminal_poc_hold(tmp_path, unregistered_pro_con_input=True)
    _review_all_v7_paths(data)

    proof = _evaluate(data)

    assert proof.complete is False
    assert "CHILD_HOLD" in proof.surfaces[0].unresolved_reason_codes
    assert not proof.surfaces[0].completed_inconclusive_children


def test_poc_with_wrong_registered_proposal_identity_remains_hold(
    tmp_path: Path,
) -> None:
    data = _case_with_terminal_poc_hold(
        tmp_path, origin_hypothesis_id="another-hypothesis"
    )
    _review_all_v7_paths(data)

    proof = _evaluate(data)

    assert proof.complete is False
    assert "CHILD_HOLD" in proof.surfaces[0].unresolved_reason_codes
    assert not proof.surfaces[0].completed_inconclusive_children


def test_terminal_hold_with_failed_later_checkpoint_is_error(tmp_path: Path) -> None:
    data = _case_with_terminal_poc_hold(tmp_path)
    case = data["case"]
    child = case.identity.model_copy(update={"hypothesis_id": "hypothesis-old"})
    terminal = case.store.get(child, SimpleStage.POC_EXECUTION_DONE)
    assert terminal is not None
    case.store.save_checkpoint(
        StageCheckpoint(
            identity=child,
            stage=SimpleStage.VERIFICATION_FINAL_DONE,
            stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_FINAL_DONE],
            status=StageStatus.FAILED,
            input_refs=terminal.output_refs,
            input_hash=input_reference_hash(terminal.output_refs),
            error_code="TEST_LATER_FAILURE",
        )
    )
    _review_all_v7_paths(data)

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V5_PLAN_INVALID"):
        _evaluate(data)


def test_terminal_hold_with_damaged_required_output_is_error(tmp_path: Path) -> None:
    data = _case_with_terminal_poc_hold(tmp_path)
    case = data["case"]
    child = case.identity.model_copy(update={"hypothesis_id": "hypothesis-old"})
    terminal = case.store.get(child, SimpleStage.POC_EXECUTION_DONE)
    assert terminal is not None
    case.artifacts.artifacts.path_for(terminal.output_refs[1].content_hash).unlink()
    _review_all_v7_paths(data)

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V5_PLAN_INVALID"):
        _evaluate(data)


def test_terminal_hold_with_malformed_registered_proposal_is_error(
    tmp_path: Path,
) -> None:
    data = _case_with_terminal_poc_hold(tmp_path, malformed_origin=True)
    _review_all_v7_paths(data)

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V5_PLAN_INVALID"):
        _evaluate(data)


def test_poc_with_mismatched_candidate_content_remains_hold(tmp_path: Path) -> None:
    data = _case_with_terminal_poc_hold(tmp_path)
    case = data["case"]
    child = case.identity.model_copy(update={"hypothesis_id": "hypothesis-old"})
    candidate = case.store.get(child, SimpleStage.POC_CANDIDATE_DONE)
    execution = case.store.get(child, SimpleStage.POC_EXECUTION_DONE)
    assert candidate is not None and execution is not None
    replacement = case.artifacts.put_bytes(b"other proof source\n", "text/x-python")
    case.store.save_checkpoint(
        candidate.model_copy(
            update={"output_refs": (candidate.output_refs[0], replacement)}
        )
    )
    changed_inputs = (candidate.output_refs[0], replacement)
    case.store.save_checkpoint(
        execution.model_copy(
            update={
                "input_refs": changed_inputs,
                "input_hash": input_reference_hash(changed_inputs),
            }
        )
    )
    _review_all_v7_paths(data)

    proof = _evaluate(data)

    assert proof.complete is False
    assert "CHILD_HOLD" in proof.surfaces[0].unresolved_reason_codes
    assert not proof.surfaces[0].completed_inconclusive_children


def test_terminal_inconclusive_does_not_clear_second_same_sink_path(
    tmp_path: Path,
) -> None:
    data = _case_with_terminal_poc_hold(tmp_path)
    first = data["case"].index.surfaces[0]
    graph = data["new_graphs"][first.surface_id]
    second = deepcopy(graph["paths"][0])
    second["path_id"] = "second-route-to-same-sink"
    second["blocking_gaps"] = []
    for step in second["steps"]:
        step["node_id"] += "-second"
    second["edge_ids"] = [edge_id + "-second" for edge_id in second["edge_ids"]]
    for edge in list(graph["edges"]):
        copied = deepcopy(edge)
        copied["edge_id"] += "-second"
        copied["from_node_id"] += "-second"
        copied["to_node_id"] += "-second"
        copied["graph_path_id"] = second["path_id"]
        graph["edges"].append(copied)
    graph["nodes"].extend(deepcopy(second["steps"]))
    graph["paths"].append(second)
    data = _finish_plan(data)
    _save_v7_part(data, part_index=0)
    _save_v7_part(data, part_index=2)

    proof = _evaluate(data)

    assert proof.complete is False
    assert "UNREVIEWED_RELEVANT_PATH" in proof.surfaces[0].unresolved_reason_codes


def test_unverified_hold_artifact_never_counts_as_completed_inconclusive(
    tmp_path: Path,
) -> None:
    data = _case(tmp_path, old_hold=True)
    case = data["case"]
    child = case.identity.model_copy(update={"hypothesis_id": "hypothesis-old"})
    invalid = case.store.get(child, SimpleStage.VERIFICATION_INITIAL_DONE)
    assert invalid is not None
    assert case.store.verified_terminal_initial_outcome(invalid) is None
    plan, parts = _prepare(data)
    data.update(v7_plan=plan, v7_plan_ref=case.artifacts.put_json(plan), v7_parts=parts)
    _review_all_v7_paths(data)

    proof = _evaluate(data)

    assert proof.complete is False
    assert "CHILD_HOLD" in proof.surfaces[0].unresolved_reason_codes


def test_blocked_child_cannot_be_reported_as_completed_inconclusive(
    tmp_path: Path,
) -> None:
    data = _case_with_terminal_poc_hold(tmp_path)
    case = data["case"]
    child = case.identity.model_copy(update={"hypothesis_id": "hypothesis-old"})
    completed = case.store.get(child, SimpleStage.VERIFICATION_INITIAL_DONE)
    assert completed is not None
    case.store.save_checkpoint(
        completed.model_copy(
            update={
                "status": StageStatus.BLOCKED,
                "verdict": None,
                "external_prerequisites_ref": None,
                "error_code": "REPRODUCTION_ENVIRONMENT_BLOCKED",
            }
        )
    )
    _review_all_v7_paths(data)

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V5"):
        _evaluate(data)


def test_verified_completion_count_and_bilingual_limitations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = _case_with_terminal_poc_hold(tmp_path)
    _review_all_v7_paths(data)
    proof = _evaluate(data)
    case = data["case"]
    ref = case.artifacts.put_json(proof.to_json())
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.candidate_terminal is not None
    counts = {
        status: sum(row.coverage_status == status for row in proof.surfaces)
        for status in ("COVERED", "UNCOVERED", "INSUFFICIENT")
    }
    terminal = run.candidate_terminal.model_copy(
        update={
            "status": "COMPLETE",
            "surface_proof_version": 5,
            "surface_index_hash": proof.index_hash,
            "surface_coverage_hash": ref.content_hash,
            "scope_certificate_hash": proof.scope_certificate_ref.content_hash,
            "surface_counts": counts,
            "pending_child_count": proof.pending_child_count,
        }
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_proof_read.verified_saved_coverage_v5",
        lambda *_args: proof,
    )
    observed = verified_surface_coverage_counts(
        proof.to_json(),
        case.index,
        terminal,
        artifacts=case.artifacts,
        coverage_ref=ref,
        store=case.store,
    )
    assert observed is not None
    assert observed["COMPLETED_INCONCLUSIVE_CHILD_COUNT"] == 1
    disclosure = CoverageDisclosure(
        ref=ref,
        fingerprint="f" * 64,
        expected_count=1,
        verified_count=1,
        gap_count=0,
        unsupported_count=0,
        gap_reasons=(),
        unsupported_reasons=(),
        engine_errors=(),
        surface_proof_version=5,
        surface_completed_inconclusive_child_count=1,
    )
    assert any(
        "근거 미확정 가설" in line and "1" in line
        for line in coverage_report_lines(disclosure, korean=True)
    )
    assert any(
        "inconclusive" in line.lower() and "1" in line
        for line in coverage_report_lines(disclosure, korean=False)
    )


def test_environment_block_is_not_completed_inconclusive(tmp_path: Path) -> None:
    data = _case_with_terminal_initial_hold(tmp_path)
    case = data["case"]
    child = case.identity.model_copy(update={"hypothesis_id": "hypothesis-old"})
    initial = case.store.get(child, SimpleStage.VERIFICATION_INITIAL_DONE)
    assert initial is not None
    case.store.save_checkpoint(
        initial.model_copy(update={"environment_block_ref": initial.output_refs[0]})
    )
    _review_all_v7_paths(data)

    proof = _evaluate(data)

    assert proof.complete is False
    assert "CHILD_HOLD" in proof.surfaces[0].unresolved_reason_codes
    assert not proof.surfaces[0].completed_inconclusive_children
