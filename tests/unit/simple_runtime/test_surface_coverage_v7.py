"""Only complete, path-specific Agent reviews may promote connected coverage."""

from __future__ import annotations

import ast
import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.ast_facts import _call_fact
from sastsimi.simple_runtime.attack_surfaces import (
    AttackSurface,
    SurfaceIndex,
    candidate_inventory_hash,
)
from sastsimi.simple_runtime.candidates import normalize_candidate_page
from sastsimi.simple_runtime.models import (
    MAX_RECOVERY_ATTEMPTS,
    STAGE_VERSION,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import (
    SimpleCheckpointStore,
    SurfaceExplorationProgressRecord,
)
from sastsimi.simple_runtime.surface_applicability_v9 import assess_optional_analyzers
from sastsimi.simple_runtime.surface_coverage_v2 import _ref
from sastsimi.simple_runtime.surface_coverage_v6 import surface_coverage_v6_from_json
from sastsimi.simple_runtime.surface_coverage_v7 import (
    SurfaceCoverageV7,
    _route_downstream_reviewed,
    evaluate_surface_coverage_v7,
)
from sastsimi.simple_runtime.surface_enrichment_v9 import (
    V9ReviewedPart,
    V9RoleCitation,
    prepare_surface_enrichment_v9,
)
from sastsimi.simple_runtime.surface_evidence_graph_v4 import _id
from sastsimi.simple_runtime.surface_intrinsic_proof_v9 import prove_intrinsic_surface
from sastsimi.simple_runtime.surface_path_proof_v9 import certify_surface_paths
from tests.unit.simple_runtime.test_surface_enrichment_v9 import connected_inputs
from tests.unit.simple_runtime.test_surface_path_proof_v9 import _request_fixture


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _reviewed_parts(
    parts: tuple[Any, ...], path_id: str
) -> dict[tuple[str, str], V9ReviewedPart]:
    rows: dict[tuple[str, str], V9ReviewedPart] = {}
    for part in parts:
        context = part.payload["context_part"]
        citations = tuple(
            V9RoleCitation(
                path_id=path_id,
                role=entry["role"],
                location=entry["location"],
                source_sha256=context["source_sha256"],
                edge_ids=tuple(entry["edge_ids"]),
            )
            for entry in part.payload["role_directory"]
            if entry["path_id"] == path_id
        )
        reviewed = V9ReviewedPart(
            surface_id=part.surface_id,
            context_id=part.context_id,
            context_hash=part.context_hash,
            part_id=context["part_id"],
            source_sha256=context["source_sha256"],
            content_sha256=context["content_sha256"],
            status="NO_HYPOTHESIS",
            reviewed_path_ids=tuple(context["path_ids"]),
            role_citations=citations,
        )
        rows[(part.surface_id, part.context_id)] = reviewed
    return rows


def _evaluate(
    inputs: dict[str, Any],
    plan: dict[str, object],
    completed: dict[tuple[str, str], V9ReviewedPart],
    *,
    pending_candidate_count: int = 0,
    pending_child_count: int = 0,
) -> SurfaceCoverageV7:
    return evaluate_surface_coverage_v7(
        inputs["identity"],
        inputs["index"],
        inputs["index_ref"],
        inputs["prior_v8_plan_ref"],
        inputs["prior_v8_plan"],
        inputs["prior_v8_coverage_ref"],
        inputs["prior_v8_coverage"],
        _ref(inputs["identity"], _digest(plan)),
        plan,
        inputs["prior_v8_progress_hash"],
        inputs["applicability"],
        inputs["intrinsic_proofs"],
        inputs["path_certificates"],
        inputs["graphs"],
        completed,
        inputs["workspace"],
        pending_candidate_count=pending_candidate_count,
        pending_child_count=pending_child_count,
        candidates=inputs.get("candidates"),
        artifacts=inputs.get("artifacts"),
        progress=inputs.get("progress"),
        store=inputs.get("store"),
    )


def _intrinsic_inputs(tmp_path: Path, *, route: bool) -> dict[str, Any]:
    inputs = connected_inputs(tmp_path)
    old_index: SurfaceIndex = inputs["index"]
    old_surface: AttackSurface = old_index.surfaces[0]
    source = (tmp_path / "app.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    line = 3 if route else 9
    candidates = None
    artifacts = None
    candidate_hash = old_index.candidate_inventory_hash
    linked_ids = old_surface.linked_candidate_ids
    evidence_refs = old_surface.evidence_refs
    if not route:
        artifacts = SimpleArtifactRepository(tmp_path / "artifacts", inputs["identity"])
        row = {
            "check_id": "sastsimi.python.sql-sink",
            "path": "app.py",
            "start": {"line": 9, "col": 1},
            "end": {"line": 9, "col": 30},
            "extra": {"message": "sql"},
        }
        ref = artifacts.put_json({"results": [row]})
        candidate = normalize_candidate_page(
            inputs["identity"],
            old_index.scope_fingerprint,
            "opengrep",
            ref,
            (row,),
            identity_version="exact-v2",
        )[0]
        candidates = {candidate.candidate_id: candidate}
        candidate_hash = candidate_inventory_hash((candidate,))
        linked_ids = (candidate.candidate_id,)
        evidence_refs = (candidate.evidence_ref,)
    surface = replace(
        old_surface,
        type="REQUEST_ENTRY" if route else "SQL_EXECUTION",
        symbol="app.route" if route else "sastsimi.python.sql-sink",
        detector="AST" if route else "STATIC_RULE",
        line=line,
        linked_candidate_ids=linked_ids,
        evidence_refs=evidence_refs,
    )
    index = replace(
        old_index, surfaces=(surface,), candidate_inventory_hash=candidate_hash
    )
    graph = dict(inputs["graphs"][old_surface.surface_id])
    graph["anchor"] = {
        "surface_id": surface.surface_id,
        "path": surface.path,
        "line": surface.line,
    }
    graph["index_hash"] = _digest(index.to_json())
    source_sha = index.ast_source_hashes[0][1]
    ast_sha = graph["source_files"][0]["ast_sha256"]
    facts: list[dict[str, object]] = []
    for node in ast.walk(tree):
        fact: dict[str, object] | None = None
        if isinstance(node, ast.Call):
            fact = _call_fact(node, "app.py")
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fact = {
                "kind": type(node).__name__,
                "path": "app.py",
                "line": node.lineno,
                "name": node.name,
            }
        if fact is not None:
            facts.append(
                {
                    **fact,
                    "fact_id": _id("fact", ("app.py", fact, source_sha)),
                    "source_sha256": source_sha,
                    "ast_sha256": ast_sha,
                }
            )
    graph["ast_facts"] = facts
    index_ref = _ref(inputs["identity"], _digest(index.to_json()))
    v8_plan = dict(inputs["prior_v8_plan"])
    v8_plan["index_hash"] = index_ref.content_hash
    v8_plan["index_ref"] = index_ref.model_dump(mode="json")
    v8_plan["candidate_inventory_hash"] = candidate_hash
    v8_plan_ref = _ref(inputs["identity"], _digest(v8_plan))
    parent = inputs["prior_v8_coverage"]
    parent = replace(
        parent,
        index_hash=index_ref.content_hash,
        candidate_inventory_hash=candidate_hash,
        v8_plan_ref=v8_plan_ref,
        surfaces=(replace(parent.surfaces[0], line=line),),
    )
    intrinsic = prove_intrinsic_surface(
        index,
        surface,
        tmp_path,
        graph,
        candidates=candidates,
        artifacts=artifacts,
    )
    assert intrinsic is not None
    inputs.update(
        index=index,
        index_ref=index_ref,
        prior_v8_plan=v8_plan,
        prior_v8_plan_ref=v8_plan_ref,
        prior_v8_coverage=parent,
        prior_v8_coverage_ref=_ref(inputs["identity"], _digest(parent.to_json())),
        applicability=assess_optional_analyzers(index, tmp_path),
        intrinsic_proofs={surface.surface_id: intrinsic},
        path_certificates={},
        graphs={surface.surface_id: graph},
        candidates=candidates,
        artifacts=artifacts,
    )
    return inputs


def _inherited_hold(inputs: dict[str, Any]) -> None:
    parent = inputs["prior_v8_coverage"]
    old = parent.surfaces[0]
    parent = replace(
        parent,
        surfaces=(
            replace(
                old,
                unresolved_reason_codes=(*old.unresolved_reason_codes, "CHILD_HOLD"),
            ),
        ),
    )
    inputs["prior_v8_coverage"] = parent
    inputs["prior_v8_coverage_ref"] = _ref(
        inputs["identity"], _digest(parent.to_json())
    )


def _attach_child(
    inputs: dict[str, Any],
    *,
    context_id: str,
    proposal_version: int,
    state: str,
) -> tuple[SimpleCheckpointStore, str]:
    identity = inputs["identity"]
    child_id = "hypothesis-old" if proposal_version == 8 else "hypothesis-v9"
    child = identity.model_copy(update={"hypothesis_id": child_id})
    artifacts = SimpleArtifactRepository(inputs["workspace"] / "child-data", identity)
    store = SimpleCheckpointStore(artifacts.paths.database)
    proposal_ref = artifacts.put_prompt_proposal(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": identity.analysis_id,
            "hypothesis_id": child_id,
            "proposal": {"title": "Source-bound test proposal"},
        }
    )
    store.upsert_hypothesis(identity, child_id, proposal_ref)
    surface = inputs["index"].surfaces[0]
    inputs["progress"] = {
        (surface.surface_id, context_id): SurfaceExplorationProgressRecord(
            surface_id=surface.surface_id,
            context_id=context_id,
            static_bundle_hash=inputs["index"].static_bundle_hash,
            index_hash=inputs["index_ref"].content_hash,
            context_hash="c" * 64,
            source_sha256=None,
            status="HYPOTHESES",
            result_ref=artifacts.put_json({"kind": "child-progress"}),
            hypothesis_ids=(child_id,),
            proposal_version=proposal_version,
        )
    }
    inputs["store"] = store
    inputs["artifacts"] = artifacts
    if state == "pending":
        return store, child_id

    pro_con_ref = artifacts.put_json({"kind": "simple_pro_con_review"})
    store.save_checkpoint(
        StageCheckpoint(
            identity=child,
            stage=SimpleStage.PRO_CON_DONE,
            stage_version=(
                "stale" if state == "stale" else STAGE_VERSION[SimpleStage.PRO_CON_DONE]
            ),
            status=StageStatus.SUCCEEDED,
            input_refs=(proposal_ref,),
            input_hash=input_reference_hash((proposal_ref,)),
            output_refs=(pro_con_ref,),
        )
    )
    initial_ref = artifacts.put_json({"kind": "nonterminal_initial_review"})
    store.save_checkpoint(
        StageCheckpoint(
            identity=child,
            stage=SimpleStage.VERIFICATION_INITIAL_DONE,
            stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE],
            status=(StageStatus.FAILED if state == "failed" else StageStatus.SUCCEEDED),
            input_refs=(pro_con_ref,),
            input_hash=input_reference_hash((pro_con_ref,)),
            output_refs=(initial_ref,),
        )
    )
    if state == "failed":
        return store, child_id

    content_ref = artifacts.put_bytes(b"print('inconclusive')\n", "text/x-python")
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "content_ref": content_ref.model_dump(mode="json"),
        }
    )
    if state != "missing_candidate":
        store.save_checkpoint(
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
    attempt_id = "completed-inconclusive-poc"
    stdout_ref = artifacts.put_bytes(b"SASTSIMI_POC_INCONCLUSIVE\n", "text/plain")
    stderr_ref = artifacts.put_bytes(b"", "text/plain")
    execution_ref = artifacts.put_json(
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
    interpretation_ref = artifacts.put_json(
        {
            "kind": "simple_dynamic_interpretation",
            "execution_ref": execution_ref.model_dump(mode="json"),
            "result": {
                "outcome": "INCONCLUSIVE",
                "rationale": "No decisive observation",
            },
        }
    )
    cleanup_ref = artifacts.put_json(
        {
            "kind": "simple_container_cleanup",
            "attempt_id": attempt_id,
            "container_id": "isolated-container",
            "status": "REMOVED",
        }
    )
    execution_inputs = (candidate_ref, content_ref)
    store.save_checkpoint(
        StageCheckpoint(
            identity=child,
            stage=SimpleStage.POC_EXECUTION_DONE,
            stage_version=STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=execution_inputs,
            input_hash=input_reference_hash(execution_inputs),
            output_refs=(execution_ref, interpretation_ref, cleanup_ref),
            attempt_id=attempt_id,
            attempt_number=MAX_RECOVERY_ATTEMPTS,
            container_id="isolated-container",
            verdict="HOLD",
        )
    )
    return store, child_id


def test_all_source_parts_and_each_path_role_are_required(tmp_path: Path) -> None:
    inputs = connected_inputs(tmp_path)
    plan, parts = prepare_surface_enrichment_v9(**inputs)
    path_id = inputs["path_certificates"]["surface-1"].path_ids[0]
    reviewed = _reviewed_parts(parts, path_id)

    covered = _evaluate(inputs, plan, reviewed)
    assert covered.surfaces[0].coverage_status == "COVERED"
    assert covered.complete

    missing_key = next(iter(reviewed))
    missing = {key: value for key, value in reviewed.items() if key != missing_key}
    assert (
        _evaluate(inputs, plan, missing).surfaces[0].coverage_status == "INSUFFICIENT"
    )

    anchor_key = next(
        key
        for key, value in reviewed.items()
        if any(citation.role == "ANCHOR" for citation in value.role_citations)
    )
    without_anchor = dict(reviewed)
    without_anchor[anchor_key] = replace(
        reviewed[anchor_key],
        role_citations=tuple(
            citation
            for citation in reviewed[anchor_key].role_citations
            if citation.role != "ANCHOR"
        ),
    )
    assert _evaluate(inputs, plan, without_anchor).surfaces[0].coverage_status == (
        "INSUFFICIENT"
    )


def test_incomplete_agent_review_stays_insufficient_without_invalidating_saved_part(
    tmp_path: Path,
) -> None:
    inputs = connected_inputs(tmp_path)
    plan, parts = prepare_surface_enrichment_v9(**inputs)
    path_id = inputs["path_certificates"]["surface-1"].path_ids[0]
    reviewed = _reviewed_parts(parts, path_id)
    key = next(iter(reviewed))
    reviewed[key] = replace(
        reviewed[key],
        status="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
        reviewed_path_ids=(),
        role_citations=(),
    )

    proof = _evaluate(inputs, plan, reviewed)

    assert proof.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "SURFACE_EVIDENCE_INSUFFICIENT" in proof.surfaces[0].unresolved_reason_codes
    assert not proof.complete


def test_frozen_v8_parent_round_trip_rejects_changed_payload(tmp_path: Path) -> None:
    inputs = connected_inputs(tmp_path)
    prior = inputs["prior_v8_coverage"]
    assert surface_coverage_v6_from_json(prior.to_json()) == prior

    changed = dict(prior.to_json())
    changed["complete"] = True
    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V6_SAVED_INVALID"):
        surface_coverage_v6_from_json(changed)


def test_request_entry_requires_new_downstream_sink_certificate(tmp_path: Path) -> None:
    index, route, _sink, graph = _request_fixture(tmp_path)
    applicability = assess_optional_analyzers(index, tmp_path)
    certificate = certify_surface_paths(index, route, graph, applicability, tmp_path)
    assert certificate.source_complete

    assert _route_downstream_reviewed(route, certificate, graph)
    assert not _route_downstream_reviewed(route, None, graph)


def test_unresolved_alternate_path_blocks_favorable_review(tmp_path: Path) -> None:
    inputs = connected_inputs(tmp_path, alternate=True)
    plan, parts = prepare_surface_enrichment_v9(**inputs)
    certificate = inputs["path_certificates"]["surface-1"]
    assert len(certificate.path_ids) == 2
    assert len(certificate.unresolved_path_ids) == 1
    favorable = next(
        path
        for path in certificate.path_ids
        if path not in certificate.unresolved_path_ids
    )
    reviewed = _reviewed_parts(parts, favorable)

    result = _evaluate(inputs, plan, reviewed)

    assert result.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "UNREVIEWED_RELEVANT_PATH" in result.surfaces[0].unresolved_reason_codes


def test_second_complete_path_needs_its_own_role_citations(tmp_path: Path) -> None:
    inputs = connected_inputs(tmp_path, alternate=True, alternate_gap=False)
    plan, parts = prepare_surface_enrichment_v9(**inputs)
    certificate = inputs["path_certificates"]["surface-1"]
    assert certificate.source_complete
    assert len(certificate.path_ids) == 2
    favorable = certificate.path_ids[0]
    reviewed = _reviewed_parts(parts, favorable)

    result = _evaluate(inputs, plan, reviewed)

    assert result.surfaces[0].coverage_status == "INSUFFICIENT"
    assert result.surfaces[0].reviewed_path_ids == (favorable,)
    assert "UNREVIEWED_RELEVANT_PATH" in result.surfaces[0].unresolved_reason_codes


def test_static_gap_and_child_hold_remain_blocking(tmp_path: Path) -> None:
    inputs = connected_inputs(tmp_path, static_gap=True)
    parent = inputs["prior_v8_coverage"]
    parent_row = parent.surfaces[0]
    inputs["prior_v8_coverage"] = replace(
        parent,
        surfaces=(
            replace(
                parent_row,
                unresolved_reason_codes=parent_row.unresolved_reason_codes
                + ("CHILD_HOLD",),
            ),
        ),
    )
    inputs["prior_v8_coverage_ref"] = _ref(
        inputs["identity"], _digest(inputs["prior_v8_coverage"].to_json())
    )
    plan, parts = prepare_surface_enrichment_v9(**inputs)
    path_id = inputs["path_certificates"]["surface-1"].path_ids[0]

    result = _evaluate(inputs, plan, _reviewed_parts(parts, path_id))

    assert result.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "CHILD_HOLD" in result.surfaces[0].unresolved_reason_codes
    assert "STATIC_COVERAGE_GAP" in result.surfaces[0].unresolved_reason_codes
    assert not result.complete


def test_inherited_child_hold_clears_only_for_verified_terminal_poc_and_all_v9_paths(
    tmp_path: Path,
) -> None:
    inputs = connected_inputs(tmp_path)
    _inherited_hold(inputs)
    plan, parts = prepare_surface_enrichment_v9(**inputs)
    store, child_id = _attach_child(
        inputs, context_id="old-context", proposal_version=8, state="complete"
    )
    path_id = inputs["path_certificates"]["surface-1"].path_ids[0]
    terminal = store.require(
        inputs["identity"].model_copy(update={"hypothesis_id": child_id}),
        SimpleStage.POC_EXECUTION_DONE,
    )

    result = _evaluate(inputs, plan, _reviewed_parts(parts, path_id))

    assert result.complete
    assert result.surfaces[0].coverage_status == "COVERED"
    assert "CHILD_HOLD" not in result.surfaces[0].unresolved_reason_codes
    assert result.surfaces[0].completed_inconclusive_children == (
        {
            "hypothesis_id": child_id,
            "stage": "POC_EXECUTION_DONE",
            "checkpoint_sha256": _digest(terminal),
            "output_refs": [
                ref.model_dump(mode="json") for ref in terminal.output_refs
            ],
        },
    )


@pytest.mark.parametrize(
    ("state", "expected_reason"),
    [
        ("missing_candidate", "CHILD_HOLD"),
        ("pending", "CHILD_PENDING"),
        ("stale", "CHILD_STALE"),
    ],
)
def test_inherited_hold_cannot_clear_for_incomplete_child(
    tmp_path: Path, state: str, expected_reason: str
) -> None:
    inputs = connected_inputs(tmp_path)
    _inherited_hold(inputs)
    plan, parts = prepare_surface_enrichment_v9(**inputs)
    _attach_child(inputs, context_id="old-context", proposal_version=8, state=state)
    path_id = inputs["path_certificates"]["surface-1"].path_ids[0]

    result = _evaluate(inputs, plan, _reviewed_parts(parts, path_id))

    assert result.surfaces[0].coverage_status == "INSUFFICIENT"
    assert expected_reason in result.surfaces[0].unresolved_reason_codes
    assert not result.surfaces[0].completed_inconclusive_children


def test_failed_child_fails_closed_even_with_reviewed_v9_paths(tmp_path: Path) -> None:
    inputs = connected_inputs(tmp_path)
    _inherited_hold(inputs)
    plan, parts = prepare_surface_enrichment_v9(**inputs)
    _attach_child(inputs, context_id="old-context", proposal_version=8, state="failed")
    path_id = inputs["path_certificates"]["surface-1"].path_ids[0]

    with pytest.raises(ValueError, match="CHILD_FAILED"):
        _evaluate(inputs, plan, _reviewed_parts(parts, path_id))


def test_terminal_child_cannot_clear_hold_when_v9_path_is_unverified(
    tmp_path: Path,
) -> None:
    inputs = connected_inputs(tmp_path, alternate=True)
    _inherited_hold(inputs)
    plan, parts = prepare_surface_enrichment_v9(**inputs)
    _attach_child(
        inputs, context_id="old-context", proposal_version=8, state="complete"
    )
    certificate = inputs["path_certificates"]["surface-1"]
    reviewed_path = next(
        path_id
        for path_id in certificate.path_ids
        if path_id not in certificate.unresolved_path_ids
    )

    result = _evaluate(inputs, plan, _reviewed_parts(parts, reviewed_path))

    assert result.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "CHILD_HOLD" in result.surfaces[0].unresolved_reason_codes
    assert "UNREVIEWED_RELEVANT_PATH" in result.surfaces[0].unresolved_reason_codes
    assert not result.surfaces[0].completed_inconclusive_children


def test_new_v9_hypothesis_hold_blocks_complete_source_review(tmp_path: Path) -> None:
    inputs = connected_inputs(tmp_path)
    plan, parts = prepare_surface_enrichment_v9(**inputs)
    _attach_child(
        inputs,
        context_id=parts[0].context_id,
        proposal_version=9,
        state="missing_candidate",
    )
    path_id = inputs["path_certificates"]["surface-1"].path_ids[0]
    reviewed = _reviewed_parts(parts, path_id)
    key = (parts[0].surface_id, parts[0].context_id)
    reviewed[key] = replace(reviewed[key], status="HYPOTHESES")

    result = _evaluate(inputs, plan, reviewed)

    assert result.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "CHILD_HOLD" in result.surfaces[0].unresolved_reason_codes
    assert not result.complete


def test_new_v9_hypothesis_hold_demotes_inherited_covered_row(tmp_path: Path) -> None:
    inputs = connected_inputs(tmp_path)
    parent = inputs["prior_v8_coverage"]
    parent = replace(
        parent,
        surfaces=(
            replace(
                parent.surfaces[0],
                coverage_status="COVERED",
                unresolved_reason_codes=(),
            ),
        ),
    )
    inputs["prior_v8_coverage"] = parent
    inputs["prior_v8_coverage_ref"] = _ref(
        inputs["identity"], _digest(parent.to_json())
    )
    plan, parts = prepare_surface_enrichment_v9(**inputs)
    _attach_child(
        inputs,
        context_id=parts[0].context_id,
        proposal_version=9,
        state="missing_candidate",
    )
    path_id = inputs["path_certificates"]["surface-1"].path_ids[0]
    reviewed = _reviewed_parts(parts, path_id)
    key = (parts[0].surface_id, parts[0].context_id)
    reviewed[key] = replace(reviewed[key], status="HYPOTHESES")

    result = _evaluate(inputs, plan, reviewed)

    assert result.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "CHILD_HOLD" in result.surfaces[0].unresolved_reason_codes
    assert not result.complete


def test_coverage_rejects_tampered_plan_or_progress_hash(tmp_path: Path) -> None:
    inputs = connected_inputs(tmp_path)
    plan, parts = prepare_surface_enrichment_v9(**inputs)
    path_id = inputs["path_certificates"]["surface-1"].path_ids[0]
    reviewed = _reviewed_parts(parts, path_id)
    tampered = dict(plan)
    tampered["prior_v8_progress_hash"] = "f" * 64

    with pytest.raises(ValueError, match="V7_PLAN"):
        _evaluate(inputs, tampered, reviewed)
    with pytest.raises(ValueError, match="V7_PLAN"):
        _evaluate({**inputs, "prior_v8_progress_hash": "f" * 64}, plan, reviewed)


def test_coverage_rejects_swapped_part_and_cross_path_citation(tmp_path: Path) -> None:
    inputs = connected_inputs(tmp_path)
    plan, parts = prepare_surface_enrichment_v9(**inputs)
    path_id = inputs["path_certificates"]["surface-1"].path_ids[0]
    reviewed = _reviewed_parts(parts, path_id)
    first_key = next(iter(reviewed))
    swapped = dict(reviewed)
    swapped[first_key] = replace(reviewed[first_key], context_hash="0" * 64)
    with pytest.raises(ValueError, match="V7_REVIEW"):
        _evaluate(inputs, plan, swapped)

    cited_key = next(key for key, value in reviewed.items() if value.role_citations)
    cited = reviewed[cited_key]
    crossed = dict(reviewed)
    crossed[cited_key] = replace(
        cited,
        role_citations=(
            replace(cited.role_citations[0], path_id="other-path"),
            *cited.role_citations[1:],
        ),
    )
    with pytest.raises(ValueError, match="V7_REVIEW"):
        _evaluate(inputs, plan, crossed)


def test_coverage_rejects_unvalidated_part_and_changed_source(tmp_path: Path) -> None:
    inputs = connected_inputs(tmp_path)
    plan, parts = prepare_surface_enrichment_v9(**inputs)
    path_id = inputs["path_certificates"]["surface-1"].path_ids[0]
    reviewed = _reviewed_parts(parts, path_id)
    first_key = next(iter(reviewed))

    with pytest.raises(ValueError, match="V7_PROGRESS"):
        _evaluate(
            inputs,
            plan,
            {**reviewed, first_key: cast(Any, {"status": "NO_HYPOTHESIS"})},
        )

    (tmp_path / "app.py").write_text("def changed():\n    pass\n", encoding="utf-8")
    with pytest.raises(ValueError, match="V7_PLAN"):
        _evaluate(inputs, plan, reviewed)


def test_candidate_and_child_pending_counts_block_complete_path(tmp_path: Path) -> None:
    inputs = connected_inputs(tmp_path)
    plan, parts = prepare_surface_enrichment_v9(**inputs)
    path_id = inputs["path_certificates"]["surface-1"].path_ids[0]
    reviewed = _reviewed_parts(parts, path_id)

    candidate_pending = _evaluate(inputs, plan, reviewed, pending_candidate_count=1)
    child_pending = _evaluate(inputs, plan, reviewed, pending_child_count=1)

    assert candidate_pending.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "CANDIDATE_PENDING" in candidate_pending.surfaces[0].unresolved_reason_codes
    assert child_pending.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "CHILD_PENDING" in child_pending.surfaces[0].unresolved_reason_codes


def test_fixed_sql_intrinsic_covers_only_exact_indexed_sink(tmp_path: Path) -> None:
    inputs = _intrinsic_inputs(tmp_path, route=False)

    plan, parts = prepare_surface_enrichment_v9(**inputs)
    result = _evaluate(inputs, plan, {})

    assert parts == ()
    assert result.surfaces[0].coverage_status == "COVERED"
    assert result.surfaces[0].proof_kind == "FIXED_SQL_LITERAL"
    assert result.surfaces[0].reviewed_path_ids == ()


def test_route_declaration_without_downstream_review_stays_insufficient(
    tmp_path: Path,
) -> None:
    inputs = _intrinsic_inputs(tmp_path, route=True)

    plan, parts = prepare_surface_enrichment_v9(**inputs)
    result = _evaluate(inputs, plan, {})

    assert parts == ()
    assert result.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "ROUTE_DOWNSTREAM_UNVERIFIED" in result.surfaces[0].unresolved_reason_codes


def test_fixed_sql_requires_complete_original_candidate_inventory(
    tmp_path: Path,
) -> None:
    inputs = _intrinsic_inputs(tmp_path, route=False)
    without_inventory = dict(inputs)
    without_inventory["candidates"] = None

    with pytest.raises(ValueError, match="V9_PROOF"):
        prepare_surface_enrichment_v9(**without_inventory)
