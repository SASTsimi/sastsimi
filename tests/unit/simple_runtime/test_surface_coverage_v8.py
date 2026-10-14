"""Successor coverage may discharge only source-bound, exhaustive proof."""

from __future__ import annotations

import hashlib
from dataclasses import replace

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.attack_surfaces import (
    AttackSurface,
    StaticGap,
    SurfaceIndex,
)
from sastsimi.simple_runtime.models import (
    CandidateTerminal,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.surface_coverage_v2 import _ref
from sastsimi.simple_runtime.surface_coverage_v7 import (
    SurfaceCoverageV7,
    SurfaceProofV7,
)
from sastsimi.simple_runtime.surface_coverage_v8 import (
    SurfaceCoverageV8,
    evaluate_surface_coverage_v8,
)
from sastsimi.simple_runtime.surface_enrichment_v10 import (
    prepare_surface_enrichment_v10,
)
from sastsimi.simple_runtime.surface_route_boundary_v10 import RouteBoundaryProofV10


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _fixture(
    *,
    reasons: tuple[str, ...] = ("ROUTE_DOWNSTREAM_UNVERIFIED",),
    missing_parts: tuple[dict[str, str], ...] = (),
    gaps: tuple[dict[str, object], ...] = (),
    boundary: str = "PYTHON_RESPONSE",
    discharged: tuple[dict[str, object], ...] = (),
    remaining: tuple[dict[str, object], ...] = (),
) -> tuple[
    CheckpointIdentity,
    SurfaceIndex,
    SurfaceCoverageV7,
    CandidateTerminal,
    RouteBoundaryProofV10,
]:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    surface = AttackSurface(
        surface_id="route-1",
        type="REQUEST_ENTRY",
        path="app.py",
        symbol="index",
        line=4,
        linked_candidate_ids=(),
        evidence_refs=(),
        detector="AST",
    )
    index = SurfaceIndex(
        scope_fingerprint="s" * 64,
        static_bundle_hash="b" * 64,
        ast_manifest_hash="m" * 64,
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        candidate_inventory_hash="c" * 64,
        candidate_count=0,
        surfaces=(surface,),
        static_gaps=(),
        index_version=2,
        ast_source_hashes=(("app.py", "e" * 64),),
    )
    parent = SurfaceCoverageV7(
        scope_fingerprint=index.scope_fingerprint,
        static_bundle_hash=index.static_bundle_hash,
        ast_manifest_hash=index.ast_manifest_hash,
        candidate_inventory_hash=index.candidate_inventory_hash,
        candidate_count=0,
        index_hash=_digest(index.to_json()),
        original_coverage_ref=_ref(identity, "1" * 64),
        scope_certificate_ref=_ref(identity, "2" * 64),
        prior_v6_ref=_ref(identity, "3" * 64),
        v9_plan_ref=_ref(identity, "4" * 64),
        prior_v8_progress_hash="5" * 64,
        applicability_hash="6" * 64,
        raw_static_gaps=gaps,
        effective_python_gaps=gaps,
        missing_v9_parts=missing_parts,
        surfaces=(
            SurfaceProofV7(
                surface_id=surface.surface_id,
                path=surface.path,
                line=surface.line,
                coverage_status="INSUFFICIENT",
                prior_v6_status="INSUFFICIENT",
                proof_kind="NONE",
                review_classification="NO_HYPOTHESIS",
                verified_roles=tuple(
                    {
                        "path_id": "path-1",
                        "role": role,
                        "location": location,
                        "source_sha256": "e" * 64,
                        "edge_ids": ["edge-1"],
                        "context_id": "context-1",
                    }
                    for role, location in (
                        ("ENTRY", "app.py:4"),
                        ("TRUST_BOUNDARY", "app.py:5"),
                        ("ANCHOR", "app.py:4"),
                    )
                ),
                evidence_refs=(),
                unresolved_reason_codes=reasons,
                completed_inconclusive_children=(),
                reviewed_path_ids=(),
                reviewed_context_ids=("context-1",),
                intrinsic_proof_hash=None,
                path_certificate_hash="7" * 64,
            ),
        ),
        pending_candidate_count=0,
        pending_child_count=0,
    )
    terminal = CandidateTerminal(
        status="PARTIAL",
        bundle_hash=index.static_bundle_hash,
        scope_fingerprint=index.scope_fingerprint,
        decision_counts={},
        deep_counts={},
        hypothesis_count=0,
        surface_index_hash=_digest(index.to_json()),
        surface_coverage_hash=_digest(parent.to_json()),
        surface_proof_version=7,
        producer_finished=True,
    )
    proof = RouteBoundaryProofV10(
        surface_id=surface.surface_id,
        source_hashes=index.ast_source_hashes,
        resolved_edges=(
            {
                "path_id": "path-1",
                "edge_id": "edge-1",
                "from_line": 4,
                "to_line": 7,
                "source_sha256": "e" * 64,
            },
        ),
        discharged_gap_events=discharged,
        remaining_gap_events=remaining,
        boundary_kind=boundary,
        external_scope_limit=(
            "TEMPLATE_CONTENT_NOT_ANALYZED" if boundary == "LITERAL_TEMPLATE" else None
        ),
        unresolved_reasons=(),
        expected_v9_path_ids=("path-1",),
        unresolved_v9_path_ids=("path-1",),
        resolved_v9_path_ids=("path-1",),
        expected_v9_part_count=1,
    )
    return identity, index, parent, terminal, proof


def _plan_and_evaluate(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    parent: SurfaceCoverageV7,
    terminal: CandidateTerminal,
    proof: RouteBoundaryProofV10,
    *,
    pending_candidate_count: int = 0,
    pending_child_count: int = 0,
    extra_proofs: dict[str, RouteBoundaryProofV10] | None = None,
) -> tuple[dict[str, object], SurfaceCoverageV8]:
    proofs = {proof.surface_id: proof, **(extra_proofs or {})}
    coverage_ref = _ref(identity, _digest(parent.to_json()))
    index_ref = _ref(identity, _digest(index.to_json()))
    v9_root = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.HYPOTHESIS_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(index_ref, coverage_ref),
    )
    plan = prepare_surface_enrichment_v10(
        identity,
        index,
        parent,
        parent.v9_plan_ref,
        coverage_ref,
        terminal,
        "8" * 64,
        proofs,
        v9_root=v9_root,
    )
    plan_ref = _ref(identity, _digest(plan))
    return plan, evaluate_surface_coverage_v8(
        index,
        parent,
        plan_ref,
        proofs,
        pending_candidate_count=pending_candidate_count,
        pending_child_count=pending_child_count,
    )


def test_v10_plan_binds_immutable_v9_terminal_and_source_inventory() -> None:
    identity, index, parent, terminal, proof = _fixture()
    plan, result = _plan_and_evaluate(identity, index, parent, terminal, proof)

    assert plan["kind"] == "simple_surface_enrichment_plan_v10"
    assert plan["v9_terminal"] == terminal.model_dump(mode="json")
    assert plan["v9_progress_hash"] == "8" * 64
    v9_root = plan["v9_root"]
    assert isinstance(v9_root, dict)
    output_refs = v9_root["output_refs"]
    assert isinstance(output_refs, list)
    assert output_refs[1] == plan["v9_coverage_ref"]
    assert plan["ast_source_hashes"] == [{"path": "app.py", "source_sha256": "e" * 64}]
    assert result.complete
    assert result.surfaces[0].coverage_status == "COVERED"
    assert parent.surfaces[0].coverage_status == "INSUFFICIENT"


def test_excluded_non_python_raw_static_gap_does_not_block_python_route() -> None:
    identity, index, parent, terminal, proof = _fixture()
    index = replace(
        index,
        static_gaps=(
            StaticGap(
                path="frontend/main.js",
                rule_id="STATIC_SCOPE",
                reason="non_python_product_source",
            ),
        ),
    )
    raw_gaps: tuple[dict[str, object], ...] = (
        {
            "path": "frontend/main.js",
            "rule_id": "STATIC_SCOPE",
            "reason": "non_python_product_source",
            "engine": "STATIC",
        },
    )
    parent = replace(
        parent,
        index_hash=_digest(index.to_json()),
        raw_static_gaps=raw_gaps,
        effective_python_gaps=(),
    )
    terminal = terminal.model_copy(
        update={
            "surface_index_hash": _digest(index.to_json()),
            "surface_coverage_hash": _digest(parent.to_json()),
        }
    )

    _plan, result = _plan_and_evaluate(identity, index, parent, terminal, proof)

    assert result.raw_static_gaps == raw_gaps
    assert result.effective_python_gaps == ()
    assert result.surfaces[0].coverage_status == "COVERED"
    assert "STATIC_COVERAGE_GAP" not in result.surfaces[0].unresolved_reason_codes
    assert result.complete


def test_v10_does_not_clear_unattributed_aggregate_graph_gap() -> None:
    event = {
        "path": "app.py",
        "reason": "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE",
        "attribution": "UNLOCATED",
        "event_ordinal": 0,
        "ambiguous_event_count": 1,
        "proof_kind": "PINNED_LINEAR_PYTHON_RESPONSE",
    }
    identity, index, parent, terminal, proof = _fixture(
        reasons=("ROUTE_DOWNSTREAM_UNVERIFIED", "UNRESOLVED_RELEVANT_GRAPH_GAP"),
        discharged=(event,),
        remaining=({"reason": "DYNAMIC_CALL", "event_ordinal": 1},),
    )

    _plan, result = _plan_and_evaluate(identity, index, parent, terminal, proof)

    assert result.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "UNRESOLVED_RELEVANT_GRAPH_GAP" in result.surfaces[0].unresolved_reason_codes
    assert not result.complete


def test_exhaustive_attributed_gap_discharge_clears_only_graph_aggregate() -> None:
    event = {
        "path": "app.py",
        "reason": "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE",
        "attribution": "UNLOCATED",
        "event_ordinal": 0,
        "ambiguous_event_count": 1,
        "proof_kind": "PINNED_LINEAR_PYTHON_RESPONSE",
    }
    identity, index, parent, terminal, proof = _fixture(
        reasons=(
            "ROUTE_DOWNSTREAM_UNVERIFIED",
            "UNRESOLVED_RELEVANT_GRAPH_GAP",
            "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE",
        ),
        discharged=(event,),
    )

    _plan, result = _plan_and_evaluate(identity, index, parent, terminal, proof)

    assert result.surfaces[0].coverage_status == "COVERED"
    assert (
        "UNRESOLVED_RELEVANT_GRAPH_GAP"
        not in result.surfaces[0].unresolved_reason_codes
    )
    assert (
        "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE"
        not in result.surfaces[0].unresolved_reason_codes
    )
    assert result.complete


def test_exact_v9_roles_and_v10_path_close_inherited_source_deficits() -> None:
    event = {
        "path": "app.py",
        "reason": "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE",
        "attribution": "UNLOCATED",
        "event_ordinal": 0,
        "ambiguous_event_count": 1,
        "proof_kind": "PINNED_LINEAR_PYTHON_RESPONSE",
    }
    identity, index, parent, terminal, proof = _fixture(
        reasons=(
            "ROUTE_DOWNSTREAM_UNVERIFIED",
            "SURFACE_SOURCE_UNAVAILABLE",
            "UNREVIEWED_RELEVANT_PATH",
            "CONNECTED_ROLE_PROOF_MISSING",
            "LOCAL_ONLY_ATTACK_PATH_UNVERIFIED",
            "INHERITED_GRAPH_SEMANTICS_UNVERIFIED",
            "UNRESOLVED_RELEVANT_GRAPH_GAP",
            "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE",
        ),
        discharged=(event,),
    )

    _plan, result = _plan_and_evaluate(identity, index, parent, terminal, proof)

    assert result.complete
    assert result.surfaces[0].coverage_status == "COVERED"
    assert result.surfaces[0].reviewed_path_ids == ("path-1",)
    assert result.surfaces[0].unresolved_reason_codes == ()


def test_unresolved_v9_paths_must_all_be_resolved_by_exact_new_edges() -> None:
    identity, index, parent, terminal, proof = _fixture()
    proof = replace(proof, resolved_v9_path_ids=())

    _plan, result = _plan_and_evaluate(identity, index, parent, terminal, proof)

    assert result.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "ROUTE_DOWNSTREAM_UNVERIFIED" in result.surfaces[0].unresolved_reason_codes
    assert not result.complete


def test_two_pinned_paths_require_two_independently_reviewed_role_sets() -> None:
    identity, index, parent, terminal, proof = _fixture()
    proof = replace(
        proof,
        resolved_edges=proof.resolved_edges
        + (
            {
                "path_id": "path-2",
                "edge_id": "edge-2",
                "from_line": 4,
                "to_line": 8,
                "source_sha256": "e" * 64,
            },
        ),
        expected_v9_path_ids=("path-1", "path-2"),
        unresolved_v9_path_ids=("path-1", "path-2"),
        resolved_v9_path_ids=("path-1", "path-2"),
    )

    _plan, missing = _plan_and_evaluate(identity, index, parent, terminal, proof)
    assert missing.surfaces[0].coverage_status == "INSUFFICIENT"

    extra_roles = tuple(
        {**role, "path_id": "path-2", "edge_ids": ["edge-2"]}
        for role in parent.surfaces[0].verified_roles
    )
    parent = replace(
        parent,
        surfaces=(
            replace(
                parent.surfaces[0],
                verified_roles=parent.surfaces[0].verified_roles + extra_roles,
            ),
        ),
    )
    terminal = terminal.model_copy(
        update={"surface_coverage_hash": _digest(parent.to_json())}
    )

    _plan, complete = _plan_and_evaluate(identity, index, parent, terminal, proof)
    assert complete.surfaces[0].coverage_status == "COVERED"
    assert complete.surfaces[0].reviewed_path_ids == ("path-1", "path-2")


def test_completed_v9_review_supersedes_only_inherited_v2_insufficiency() -> None:
    identity, index, parent, terminal, proof = _fixture(
        reasons=(
            "ROUTE_DOWNSTREAM_UNVERIFIED",
            "SURFACE_EVIDENCE_INSUFFICIENT",
        )
    )
    _plan, result = _plan_and_evaluate(identity, index, parent, terminal, proof)
    assert result.complete
    assert result.surfaces[0].unresolved_reason_codes == ()


def test_one_v9_insufficient_part_cannot_be_hidden_by_other_valid_citations() -> None:
    identity, index, parent, terminal, proof = _fixture(
        reasons=(
            "ROUTE_DOWNSTREAM_UNVERIFIED",
            "SURFACE_EVIDENCE_INSUFFICIENT",
        )
    )
    proof = replace(proof, expected_v9_part_count=2)

    _plan, result = _plan_and_evaluate(identity, index, parent, terminal, proof)

    assert result.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "SURFACE_EVIDENCE_INSUFFICIENT" in result.surfaces[0].unresolved_reason_codes
    assert not result.complete


@pytest.mark.parametrize(
    "change",
    (
        "missing_trust_boundary",
        "wrong_source_hash",
        "wrong_context",
        "wrong_edge",
        "wrong_anchor_location",
    ),
)
def test_source_deficit_remains_without_exact_role_citations(change: str) -> None:
    identity, index, parent, terminal, proof = _fixture()
    roles = [dict(role) for role in parent.surfaces[0].verified_roles]
    if change == "missing_trust_boundary":
        roles = [role for role in roles if role["role"] != "TRUST_BOUNDARY"]
    else:
        target = roles[2] if change == "wrong_anchor_location" else roles[0]
        if change == "wrong_source_hash":
            target["source_sha256"] = "f" * 64
        elif change == "wrong_context":
            target["context_id"] = "unreviewed-context"
        elif change == "wrong_edge":
            target["edge_ids"] = ["other-edge"]
        else:
            target["location"] = "app.py:8"
    parent = replace(
        parent,
        surfaces=(replace(parent.surfaces[0], verified_roles=tuple(roles)),),
    )
    terminal = terminal.model_copy(
        update={"surface_coverage_hash": _digest(parent.to_json())}
    )

    _plan, result = _plan_and_evaluate(identity, index, parent, terminal, proof)

    assert result.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "ROUTE_DOWNSTREAM_UNVERIFIED" in result.surfaces[0].unresolved_reason_codes
    assert not result.complete


@pytest.mark.parametrize(
    "template_path",
    ["templates/index.html", "web/templates/index.html"],
)
def test_pinned_literal_template_closes_only_python_route_scope(
    template_path: str,
) -> None:
    discharged_events: tuple[dict[str, object], ...] = (
        {
            "path": "app.py",
            "reason": "DOWNSTREAM_SINK_NOT_PROVEN",
            "attribution": "PATH_CERTIFICATE",
            "event_ordinal": None,
            "ambiguous_event_count": 0,
            "proof_kind": "PINNED_LITERAL_TEMPLATE_HANDOFF",
        },
        *(
            {
                "path": "app.py",
                "reason": reason,
                "attribution": "UNLOCATED",
                "event_ordinal": ordinal,
                "ambiguous_event_count": 1,
                "proof_kind": "PINNED_LITERAL_TEMPLATE_HANDOFF",
            }
            for ordinal, reason in enumerate(
                (
                    "EXTERNAL_IMPLEMENTATION_UNAVAILABLE",
                    "SINK_ENCLOSING_FUNCTION_UNAVAILABLE",
                    "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE",
                )
            )
        ),
    )
    identity, index, parent, terminal, proof = _fixture(
        reasons=(
            "ROUTE_DOWNSTREAM_UNVERIFIED",
            "SURFACE_SOURCE_UNAVAILABLE",
            "CONNECTED_PATH_CERTIFICATE_MISSING",
            "CONNECTED_ROLE_PROOF_MISSING",
            "LOCAL_ONLY_ATTACK_PATH_UNVERIFIED",
            "UNRESOLVED_RELEVANT_GRAPH_GAP",
            "DOWNSTREAM_SINK_NOT_PROVEN",
            "EXTERNAL_IMPLEMENTATION_UNAVAILABLE",
            "SINK_ENCLOSING_FUNCTION_UNAVAILABLE",
            "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE",
        ),
        boundary="LITERAL_TEMPLATE",
        discharged=discharged_events,
    )
    parent = replace(
        parent,
        surfaces=(
            replace(
                parent.surfaces[0],
                verified_roles=(),
                reviewed_context_ids=(),
                reviewed_path_ids=(),
            ),
        ),
    )
    terminal = terminal.model_copy(
        update={"surface_coverage_hash": _digest(parent.to_json())}
    )
    proof = replace(
        proof,
        expected_v9_path_ids=(),
        unresolved_v9_path_ids=(),
        resolved_v9_path_ids=(),
        expected_v9_part_count=0,
        resolved_edges=(
            {
                "path_id": "python-template:route-1",
                "from_line": 4,
                "to_line": 7,
                "source_sha256": "e" * 64,
                "template_path": template_path,
                "template_sha256": "f" * 64,
            },
        ),
    )

    _plan, result = _plan_and_evaluate(identity, index, parent, terminal, proof)

    assert result.complete
    assert result.surfaces[0].unresolved_reason_codes == ()
    assert result.surfaces[0].external_scope_limit == "TEMPLATE_CONTENT_NOT_ANALYZED"


def test_literal_template_retains_unrelated_or_insufficient_reason() -> None:
    identity, index, parent, terminal, proof = _fixture(
        reasons=(
            "ROUTE_DOWNSTREAM_UNVERIFIED",
            "SURFACE_EVIDENCE_INSUFFICIENT",
        ),
        boundary="LITERAL_TEMPLATE",
    )
    proof = replace(
        proof,
        expected_v9_path_ids=(),
        unresolved_v9_path_ids=(),
        resolved_v9_path_ids=(),
        expected_v9_part_count=0,
        resolved_edges=(
            {
                "path_id": "python-template:route-1",
                "from_line": 4,
                "to_line": 7,
                "source_sha256": "e" * 64,
                "template_path": "templates/index.html",
                "template_sha256": "f" * 64,
            },
        ),
    )

    _plan, result = _plan_and_evaluate(identity, index, parent, terminal, proof)

    assert result.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "SURFACE_EVIDENCE_INSUFFICIENT" in result.surfaces[0].unresolved_reason_codes
    assert not result.complete


def test_pinned_python_sink_closes_only_reviewed_route_path() -> None:
    event = {
        "path": "app.py",
        "reason": "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE",
        "attribution": "UNLOCATED",
        "event_ordinal": 0,
        "ambiguous_event_count": 1,
        "proof_kind": "PINNED_PYTHON_SINK_CALL",
    }
    identity, index, parent, terminal, proof = _fixture(
        reasons=(
            "ROUTE_DOWNSTREAM_UNVERIFIED",
            "UNRESOLVED_RELEVANT_GRAPH_GAP",
            "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE",
        ),
        boundary="PINNED_PYTHON_SINK",
        discharged=(event,),
    )
    sink = replace(index.surfaces[0], surface_id="sink-1", type="SQL_EXECUTION", line=7)
    index = replace(index, surfaces=index.surfaces + (sink,))
    parent = replace(
        parent,
        index_hash=_digest(index.to_json()),
        surfaces=parent.surfaces
        + (
            replace(
                parent.surfaces[0],
                surface_id=sink.surface_id,
                line=sink.line,
                coverage_status="COVERED",
                proof_kind="FIXED_SQL_LITERAL",
                unresolved_reason_codes=(),
            ),
        ),
    )
    terminal = terminal.model_copy(
        update={
            "surface_index_hash": _digest(index.to_json()),
            "surface_coverage_hash": _digest(parent.to_json()),
        }
    )
    proof = replace(
        proof,
        resolved_edges=tuple(
            {**edge, "sink_surface_id": sink.surface_id}
            for edge in proof.resolved_edges
        ),
    )
    sink_proof = replace(
        proof,
        surface_id=sink.surface_id,
        boundary_kind="NONE",
        resolved_edges=(),
        discharged_gap_events=(),
        unresolved_reasons=("NOT_REQUEST_ENTRY",),
    )

    _plan, result = _plan_and_evaluate(
        identity,
        index,
        parent,
        terminal,
        proof,
        extra_proofs={sink.surface_id: sink_proof},
    )

    assert result.complete
    assert result.surfaces[0].coverage_status == "COVERED"
    assert result.surfaces[0].proof_kind == "PINNED_PYTHON_SINK"
    assert result.surfaces[1].coverage_status == "COVERED"


def test_pinned_sink_cannot_discharge_external_implementation_gap() -> None:
    identity, index, parent, terminal, proof = _fixture(
        boundary="PINNED_PYTHON_SINK",
        discharged=(
            {
                "path": "app.py",
                "reason": "EXTERNAL_IMPLEMENTATION_UNAVAILABLE",
                "attribution": "UNLOCATED",
                "event_ordinal": 0,
                "ambiguous_event_count": 1,
                "proof_kind": "PINNED_PYTHON_SINK_CALL",
            },
        ),
    )

    with pytest.raises(ValueError, match="V10_PROOF"):
        _plan_and_evaluate(identity, index, parent, terminal, proof)


def test_pinned_sink_requires_an_indexed_exact_target() -> None:
    identity, index, parent, terminal, proof = _fixture(boundary="PINNED_PYTHON_SINK")
    proof = replace(
        proof,
        resolved_edges=(
            {
                "path_id": "path-1",
                "sink_surface_id": "not-indexed",
                "from_line": 4,
                "to_line": 7,
                "source_sha256": "e" * 64,
            },
        ),
    )

    with pytest.raises(ValueError, match="V10_PROOF"):
        _plan_and_evaluate(identity, index, parent, terminal, proof)


def test_remaining_gap_adds_insufficient_even_if_parent_did_not_list_it() -> None:
    identity, index, parent, terminal, proof = _fixture(
        remaining=({"reason": "DYNAMIC_CALL", "event_ordinal": 0},)
    )

    _plan, result = _plan_and_evaluate(identity, index, parent, terminal, proof)

    assert result.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "UNRESOLVED_RELEVANT_GRAPH_GAP" in result.surfaces[0].unresolved_reason_codes
    assert not result.complete


def test_no_v9_anchor_citation_cannot_promote_route() -> None:
    identity, index, parent, terminal, proof = _fixture()
    old = parent.surfaces[0]
    parent = replace(
        parent,
        surfaces=(
            replace(
                old,
                verified_roles=tuple(
                    role for role in old.verified_roles if role["role"] != "ANCHOR"
                ),
            ),
        ),
    )
    terminal = terminal.model_copy(
        update={"surface_coverage_hash": _digest(parent.to_json())}
    )

    _plan, result = _plan_and_evaluate(identity, index, parent, terminal, proof)

    assert result.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "ROUTE_DOWNSTREAM_UNVERIFIED" in result.surfaces[0].unresolved_reason_codes


def test_stale_v6_classification_does_not_override_valid_v9_citations() -> None:
    identity, index, parent, terminal, proof = _fixture()
    old = parent.surfaces[0]
    parent = replace(
        parent,
        surfaces=(
            replace(old, review_classification="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"),
        ),
    )
    terminal = terminal.model_copy(
        update={"surface_coverage_hash": _digest(parent.to_json())}
    )

    _plan, result = _plan_and_evaluate(identity, index, parent, terminal, proof)

    assert result.surfaces[0].coverage_status == "COVERED"


def test_actual_insufficient_v9_evidence_reason_cannot_be_relabelled_covered() -> None:
    identity, index, parent, terminal, proof = _fixture(
        reasons=("ROUTE_DOWNSTREAM_UNVERIFIED", "SURFACE_EVIDENCE_INSUFFICIENT")
    )
    proof = replace(proof, expected_v9_part_count=2)

    _plan, result = _plan_and_evaluate(identity, index, parent, terminal, proof)

    assert result.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "SURFACE_EVIDENCE_INSUFFICIENT" in result.surfaces[0].unresolved_reason_codes


def test_pending_child_prevents_graph_gap_discharge() -> None:
    event = {
        "path": "app.py",
        "reason": "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE",
        "attribution": "UNLOCATED",
        "event_ordinal": 0,
        "ambiguous_event_count": 1,
        "proof_kind": "PINNED_LINEAR_PYTHON_RESPONSE",
    }
    identity, index, parent, terminal, proof = _fixture(
        reasons=("ROUTE_DOWNSTREAM_UNVERIFIED", "UNRESOLVED_RELEVANT_GRAPH_GAP"),
        discharged=(event,),
    )

    _plan, result = _plan_and_evaluate(
        identity, index, parent, terminal, proof, pending_child_count=1
    )

    assert result.surfaces[0].coverage_status == "INSUFFICIENT"
    assert "UNRESOLVED_RELEVANT_GRAPH_GAP" in result.surfaces[0].unresolved_reason_codes


def test_ambiguous_discharge_event_cannot_enter_successor_plan() -> None:
    identity, index, parent, terminal, proof = _fixture(
        reasons=("UNRESOLVED_RELEVANT_GRAPH_GAP",),
        discharged=(
            {
                "path": "app.py",
                "reason": "SYNTACTIC_ROUTE_TO_SINK_UNAVAILABLE",
                "attribution": "UNLOCATED",
                "event_ordinal": 0,
                "ambiguous_event_count": 2,
                "proof_kind": "PINNED_LINEAR_PYTHON_RESPONSE",
            },
        ),
    )

    with pytest.raises(ValueError, match="V10_PROOF"):
        _plan_and_evaluate(identity, index, parent, terminal, proof)


def test_literal_template_ends_at_scope_boundary_not_template_verdict() -> None:
    identity, index, parent, terminal, proof = _fixture(boundary="LITERAL_TEMPLATE")
    parent = replace(
        parent,
        surfaces=(
            replace(
                parent.surfaces[0],
                verified_roles=(),
                reviewed_context_ids=(),
                reviewed_path_ids=(),
            ),
        ),
    )
    terminal = terminal.model_copy(
        update={"surface_coverage_hash": _digest(parent.to_json())}
    )
    proof = replace(
        proof,
        expected_v9_path_ids=(),
        unresolved_v9_path_ids=(),
        resolved_v9_path_ids=(),
        expected_v9_part_count=0,
        resolved_edges=(
            {
                "path_id": "python-template:route-1",
                "from_line": 4,
                "to_line": 7,
                "source_sha256": "e" * 64,
                "template_path": "templates/index.html",
                "template_sha256": "f" * 64,
            },
        ),
    )

    _plan, result = _plan_and_evaluate(identity, index, parent, terminal, proof)

    assert result.surfaces[0].coverage_status == "COVERED"
    assert result.surfaces[0].external_scope_limit == "TEMPLATE_CONTENT_NOT_ANALYZED"
    assert result.complete


def test_static_gap_child_hold_and_pending_counts_never_complete() -> None:
    identity, index, parent, terminal, proof = _fixture(
        reasons=("ROUTE_DOWNSTREAM_UNVERIFIED", "CHILD_HOLD"),
        gaps=({"path": "app.py", "reason": "PARSE_ERROR"},),
    )

    _plan, result = _plan_and_evaluate(
        identity,
        index,
        parent,
        terminal,
        proof,
        pending_candidate_count=1,
        pending_child_count=1,
    )

    assert result.surfaces[0].coverage_status == "INSUFFICIENT"
    assert {
        "CHILD_HOLD",
        "STATIC_COVERAGE_GAP",
        "CANDIDATE_PENDING",
        "CHILD_PENDING",
    } <= set(result.surfaces[0].unresolved_reason_codes)
    assert not result.complete


def test_incomplete_v9_part_cannot_start_v10() -> None:
    identity, index, parent, terminal, proof = _fixture(
        missing_parts=({"surface_id": "route-1", "context_id": "missing"},)
    )

    with pytest.raises(ValueError, match="V10_PARENT"):
        _plan_and_evaluate(identity, index, parent, terminal, proof)


def test_changed_parent_terminal_or_source_binding_rejected() -> None:
    identity, index, parent, terminal, proof = _fixture()
    changed_terminal = terminal.model_copy(update={"surface_coverage_hash": "0" * 64})
    changed_proof = replace(proof, source_hashes=(("app.py", "f" * 64),))

    with pytest.raises(ValueError, match="V10_PARENT"):
        _plan_and_evaluate(identity, index, parent, changed_terminal, proof)
    with pytest.raises(ValueError, match="V10_PROOF"):
        _plan_and_evaluate(identity, index, parent, terminal, changed_proof)


def test_parent_claiming_complete_while_surface_incomplete_is_rejected() -> None:
    identity, index, parent, terminal, proof = _fixture()
    invalid_terminal = terminal.model_copy(update={"status": "COMPLETE"})

    with pytest.raises(ValueError, match="V10_PARENT"):
        _plan_and_evaluate(identity, index, parent, invalid_terminal, proof)


def test_coverage_requires_exact_indexed_surface_set() -> None:
    identity, index, parent, terminal, proof = _fixture()
    second_surface = replace(index.surfaces[0], surface_id="route-2", line=12)
    expanded_index = replace(index, surfaces=index.surfaces + (second_surface,))

    with pytest.raises(ValueError, match="V10_PARENT"):
        _plan_and_evaluate(identity, expanded_index, parent, terminal, proof)


def test_empty_reason_set_does_not_create_coverage_without_new_proof() -> None:
    identity, index, parent, terminal, proof = _fixture(reasons=(), boundary="NONE")
    proof = replace(proof, resolved_edges=())

    _plan, result = _plan_and_evaluate(identity, index, parent, terminal, proof)

    assert result.surfaces[0].coverage_status == "INSUFFICIENT"
    assert not result.complete


def test_non_request_marker_does_not_demote_previously_covered_surface() -> None:
    identity, index, parent, terminal, proof = _fixture(reasons=(), boundary="NONE")
    surface = replace(index.surfaces[0], type="SQL_EXECUTION")
    index = replace(index, surfaces=(surface,))
    row = replace(
        parent.surfaces[0],
        coverage_status="COVERED",
        proof_kind="FIXED_SQL_LITERAL",
    )
    parent = replace(parent, surfaces=(row,), index_hash=_digest(index.to_json()))
    terminal = terminal.model_copy(
        update={
            "surface_index_hash": _digest(index.to_json()),
            "surface_coverage_hash": _digest(parent.to_json()),
        }
    )
    proof = replace(
        proof,
        boundary_kind="NONE",
        resolved_edges=(),
        unresolved_reasons=("NOT_REQUEST_ENTRY",),
    )

    _plan, result = _plan_and_evaluate(identity, index, parent, terminal, proof)

    assert result.surfaces[0].coverage_status == "COVERED"
    assert result.complete


def test_optional_v10_route_proof_failure_does_not_demote_v7_covered_route() -> None:
    identity, index, parent, terminal, proof = _fixture(reasons=(), boundary="NONE")
    parent = replace(
        parent,
        surfaces=(
            replace(
                parent.surfaces[0],
                coverage_status="COVERED",
                proof_kind="CONNECTED_PATHS",
            ),
        ),
    )
    terminal = terminal.model_copy(
        update={"surface_coverage_hash": _digest(parent.to_json())}
    )
    proof = replace(
        proof,
        resolved_edges=(),
        resolved_v9_path_ids=(),
        unresolved_reasons=("ROUTE_BINDING_UNPROVEN",),
    )

    _plan, result = _plan_and_evaluate(identity, index, parent, terminal, proof)

    assert result.surfaces[0].coverage_status == "COVERED"
    assert result.surfaces[0].unresolved_reason_codes == ()
    assert result.complete


@pytest.mark.parametrize("gap_kind", ("route", "static", "pending"))
def test_v7_covered_route_survives_global_successor_gap(gap_kind: str) -> None:
    remaining: tuple[dict[str, object], ...] = (
        (
            {
                "path": "app.py",
                "reason": "UNPROVEN_DYNAMIC_ROUTE",
                "event_ordinal": 0,
            },
        )
        if gap_kind == "route"
        else ()
    )
    static: tuple[dict[str, object], ...] = (
        ({"path": "app.py", "reason": "PARSE_ERROR"},) if gap_kind == "static" else ()
    )
    identity, index, parent, terminal, proof = _fixture(
        reasons=(), remaining=remaining, gaps=static, boundary="NONE"
    )
    parent = replace(
        parent,
        surfaces=(
            replace(
                parent.surfaces[0],
                coverage_status="COVERED",
                proof_kind="CONNECTED_PATHS",
            ),
        ),
    )
    terminal = terminal.model_copy(
        update={"surface_coverage_hash": _digest(parent.to_json())}
    )
    proof = replace(proof, resolved_edges=(), resolved_v9_path_ids=())

    _plan, result = _plan_and_evaluate(
        identity,
        index,
        parent,
        terminal,
        proof,
        pending_candidate_count=1 if gap_kind == "pending" else 0,
    )

    assert result.surfaces[0].coverage_status == "COVERED"
    assert result.surfaces[0].unresolved_reason_codes == ()
    assert not result.complete
    if gap_kind == "route":
        assert remaining
        assert result.remaining_route_gap_events == (
            {"surface_id": "route-1", **remaining[0]},
        )
