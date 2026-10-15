"""Role-aware v8 review preserves exact parent checkpoints and source roles."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, TypedDict, cast

import pytest

import sastsimi.simple_runtime.surface_coverage_v5 as coverage_v5
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attack_surfaces import AttackSurface, SurfaceIndex
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.store import (
    SimpleCheckpointStore,
    SurfaceExplorationProgressRecord,
)
from sastsimi.simple_runtime.surface_coverage_v2 import _ref
from sastsimi.simple_runtime.surface_coverage_v5 import (
    SurfaceCoverageV5,
    SurfaceProofV5,
)
from sastsimi.simple_runtime.surface_coverage_v6 import (
    _frozen_parent_v5_from_json,
    _validated_v8_part,
    evaluate_surface_coverage_v6,
    read_frozen_parent_v5,
)
from sastsimi.simple_runtime.surface_enrichment_v7_bindings import (
    prior_progress_snapshot_hash,
)
from sastsimi.simple_runtime.surface_enrichment_v8 import (
    V8Part,
    prepare_surface_enrichment_v8,
    select_v8_review_parts,
    v8_review_directory,
    v8_review_readiness,
    validate_v8_response,
)
from sastsimi.simple_runtime.surface_enrichment_v8_bindings import (
    missing_v7_part_set,
    prior_v7_progress_snapshot_hash,
)


class _Row(SurfaceExplorationProgressRecord):
    """Test row with the production progress-record contract."""


class _PlannerInputs(TypedDict):
    identity: CheckpointIdentity
    index: SurfaceIndex
    index_ref: StoredDataRef
    v7_plan: dict[str, Any]
    v7_ref: StoredDataRef
    v5: SurfaceCoverageV5
    v5_ref: StoredDataRef
    progress: dict[tuple[str, str], _Row]
    graphs: dict[str, dict[str, Any]]


def _progress() -> tuple[dict[str, object], dict[tuple[str, str], _Row]]:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    row = _Row(
        surface_id="surface-1",
        context_id="context-1",
        static_bundle_hash="a" * 64,
        index_hash="b" * 64,
        context_hash="c" * 64,
        source_sha256="d" * 64,
        status="NO_HYPOTHESIS",
        result_ref=_ref(identity, "e" * 64),
        hypothesis_ids=(),
        proposal_version=7,
    )
    plan: dict[str, object] = {
        "expected_parts": [
            {
                "surface_id": "surface-1",
                "context_id": "context-1",
                "context_hash": "c" * 64,
                "source_sha256": "d" * 64,
            }
        ]
    }
    return plan, {(row.surface_id, row.context_id): row}


def test_v8_progress_snapshot_accepts_complete_exact_v7_parent() -> None:
    plan, progress = _progress()

    digest = prior_v7_progress_snapshot_hash(progress)

    assert len(digest) == 64
    assert missing_v7_part_set(plan, progress) == []
    assert digest == prior_v7_progress_snapshot_hash(dict(progress))


def test_v8_rejects_missing_or_changed_parent_part() -> None:
    plan, progress = _progress()
    assert missing_v7_part_set(plan, {}) == [
        {"surface_id": "surface-1", "context_id": "context-1"}
    ]
    expected_parts = cast(list[dict[str, object]], plan["expected_parts"])
    expected_parts[0]["context_hash"] = "f" * 64
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V8_V7_PART_CHANGED"):
        missing_v7_part_set(plan, progress)


def test_v8_rejects_semantically_inconsistent_parent_progress() -> None:
    _, progress = _progress()
    original = next(iter(progress.values()))
    changed = replace(original, status="HYPOTHESES", hypothesis_ids=())
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V8_PROGRESS_INVALID"):
        prior_v7_progress_snapshot_hash({("surface-1", "context-1"): changed})


def _graph(*, gap_events: list[dict[str, object]] | None = None) -> dict[str, Any]:
    sha = "a" * 64
    ast_sha = "b" * 64
    nodes = [
        {"node_id": "n1", "path": "app.py", "line": 1, "role": "ROUTE_ENTRY"},
        {"node_id": "n2", "path": "app.py", "line": 2, "role": "REQUEST_CONTEXT"},
        {"node_id": "n3", "path": "app.py", "line": 3, "role": "SINK"},
    ]
    return {
        "kind": "simple_surface_evidence_graph_v5",
        "proof_semantics_revision": "v5-source-bound-5",
        "anchor": {"surface_id": "surface-1", "path": "app.py", "line": 3},
        "scope_fingerprint": "f" * 64,
        "index_hash": "i" * 64,
        "ast_manifest_hash": "m" * 64,
        "source_files": [
            {"path": "app.py", "source_sha256": sha, "ast_sha256": ast_sha}
        ],
        "source_lines": [
            {
                "line_id": f"line-{line}",
                "path": "app.py",
                "line": line,
                "text": f"source line {line}",
                "source_sha256": sha,
            }
            for line in (1, 2, 3)
        ],
        "ast_facts": [
            {
                "fact_id": "fact-anchor",
                "path": "app.py",
                "line": 3,
                "kind": "Call",
                "name": "sanitize",
                "source_sha256": sha,
                "ast_sha256": ast_sha,
            }
        ],
        "nodes": nodes,
        "edges": [
            {
                "edge_id": "e1",
                "type": "ENTRY",
                "from_node_id": "n1",
                "to_node_id": "n2",
                "graph_path_id": "route-to-anchor",
            },
            {
                "edge_id": "e2",
                "type": "SENSITIVE_OPERATION",
                "from_node_id": "n2",
                "to_node_id": "n3",
                "graph_path_id": "route-to-anchor",
            },
        ],
        "paths": [
            {
                "path_id": "route-to-anchor",
                "kind": "call_path_v1",
                "assurance": "SYNTACTIC_REACHABILITY",
                "provenance": "python_syntax",
                "steps": nodes,
                "edge_ids": ["e1", "e2"],
                "blocking_gaps": [],
            }
        ],
        "operational_routes": [],
        "gaps": [],
        "gap_events": gap_events or [],
    }


def _surface(surface_type: str = "SANITIZATION_CONTROL") -> AttackSurface:
    return AttackSurface(
        surface_id="surface-1",
        type=surface_type,
        path="app.py",
        symbol="sanitize",
        line=3,
        linked_candidate_ids=(),
        evidence_refs=(),
        detector="test",
    )


def _items(graph: dict[str, Any]) -> list[dict[str, object]]:
    return [
        {"category": category, "ordinal": ordinal, "value": row}
        for category in (
            "source_files",
            "source_lines",
            "ast_facts",
            "nodes",
            "edges",
            "paths",
            "operational_routes",
            "gaps",
        )
        for ordinal, row in enumerate(graph[category])
    ]


def _wrapper(graph: dict[str, Any], *, local_only: bool = False) -> dict[str, Any]:
    from hashlib import sha256

    parts = select_v8_review_parts(_items(graph), _surface())
    selected = next(
        part
        for part in parts
        if part.review_path_kind == ("LOCAL_ONLY" if local_only else "CONNECTED")
    )
    payload: dict[str, Any] = {
        "kind": "simple_surface_context_v8",
        "analysis_id": "analysis-1",
        "workspace_id": "workspace-1",
        "commit_id": "commit-1",
        "scope": "repository",
        "scope_fingerprint": graph["scope_fingerprint"],
        "static_bundle_hash": "s" * 64,
        "ast_manifest_hash": graph["ast_manifest_hash"],
        "surface_index_hash": graph["index_hash"],
        "surface_id": "surface-1",
        "surface_type": "SANITIZATION_CONTROL",
        "path": "app.py",
        "line": 3,
        "source_sha256": "a" * 64,
        "graph_hash": sha256(canonical_bytes(graph)).hexdigest(),
        "plan_binding_hash": "p" * 64,
        "graph_semantics_revision": "v5-source-bound-5",
        "review_mode": "ROLE_AWARE",
        "anchor_contract": "CONTROL",
        "target_path_id": selected.target_path_id,
        "review_path_kind": selected.review_path_kind,
        "part_index": 0,
        "part_count": 1,
        "unavailable_item_count": 0,
        "items": selected.support,
    }
    context_hash = sha256(canonical_bytes(payload)).hexdigest()
    context_id = sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v8",
                "plan_binding_hash": payload["plan_binding_hash"],
                "surface_id": "surface-1",
                "part_index": 0,
                "context_hash": context_hash,
            }
        )
    ).hexdigest()
    return {
        "context_payload": payload,
        "graph_payload": graph,
        "context_hash": context_hash,
        "context_id": context_id,
    }


def _response(wrapper: dict[str, Any], *, local_only: bool = False) -> dict[str, Any]:
    path_id = "" if local_only else "route-to-anchor"
    rows = (
        [
            ("ANCHOR", 3, [] if local_only else ["e2"]),
        ]
        if local_only
        else [
            ("ENTRY", 1, ["e1"]),
            ("TRUST_BOUNDARY", 2, ["e1", "e2"]),
            ("ANCHOR", 3, ["e2"]),
        ]
    )
    return {
        "surface_id": "surface-1",
        "context_id": wrapper["context_id"],
        "status": "NO_HYPOTHESIS",
        "reason": "Reviewed exact source-bound anchor",
        "hypotheses": [],
        "review_evidence": [
            {
                "part": part,
                "location": f"app.py:{line}",
                "context_hash": wrapper["context_hash"],
                "source_sha256": "a" * 64,
                "graph_path_id": path_id,
                "edge_ids": edge_ids,
                "explanation": "Exact source and AST reviewed",
            }
            for part, line, edge_ids in rows
        ],
    }


def test_v8_control_route_path_is_anchor_not_sensitive_sink() -> None:
    graph = _graph()
    wrapper = _wrapper(graph)

    directory = v8_review_directory(wrapper["context_payload"], graph)
    checked = validate_v8_response(wrapper, _response(wrapper))

    assert [row["part"] for row in directory] == ["ENTRY", "TRUST_BOUNDARY", "ANCHOR"]
    assert all(row["part"] != "SENSITIVE_OPERATION" for row in directory)
    assert checked.proof_level == "CONNECTED"
    assert checked.verified_path_id == "route-to-anchor"
    assert {row["part"] for row in checked.verified_roles} == {
        "ENTRY",
        "TRUST_BOUNDARY",
        "ANCHOR",
    }


def test_v8_local_only_anchor_never_certifies_attack_path() -> None:
    graph = _graph()
    graph["paths"] = []
    graph["nodes"] = []
    graph["edges"] = []
    wrapper = _wrapper(graph, local_only=True)

    checked = validate_v8_response(wrapper, _response(wrapper, local_only=True))

    assert checked.proof_level == "LOCAL_ONLY"
    assert checked.verified_path_id is None
    assert checked.reviewed_parts == frozenset({"ANCHOR"})


def test_v8_requires_exact_ast_fact_for_positive_anchor_review() -> None:
    graph = _graph()
    graph["ast_facts"] = []
    wrapper = _wrapper(graph)

    with pytest.raises(ValueError, match="V8_ANCHOR_AST_MISSING"):
        validate_v8_response(wrapper, _response(wrapper))


def test_v8_unlocated_same_file_gap_blocks_connected_claim() -> None:
    graph = _graph(
        gap_events=[
            {
                "path": "app.py",
                "reason": "DYNAMIC_DISPATCH_UNRESOLVED",
                "attribution": "UNLOCATED",
            }
        ]
    )
    graph["gaps"] = [{"path": "app.py", "reason": "DYNAMIC_DISPATCH_UNRESOLVED"}]
    wrapper = _wrapper(graph)

    with pytest.raises(ValueError, match="V8_REVIEW_PATH_INCOMPLETE"):
        validate_v8_response(wrapper, _response(wrapper))


def test_v8_same_location_entry_and_anchor_use_terminal_anchor_step() -> None:
    graph = _graph()
    graph["nodes"][0]["line"] = 3
    wrapper = _wrapper(graph)
    response = _response(wrapper)
    response["review_evidence"][0]["location"] = "app.py:3"

    directory = v8_review_directory(wrapper["context_payload"], graph)
    checked = validate_v8_response(wrapper, response)

    anchor = next(row for row in directory if row["part"] == "ANCHOR")
    assert anchor["edge_ids"] == ["e2"]
    assert checked.proof_level == "CONNECTED"


def test_v8_missing_ast_source_is_insufficient_not_context_corruption() -> None:
    from hashlib import sha256

    graph = _graph()
    graph["source_files"] = []
    graph["source_lines"] = []
    graph["ast_facts"] = []
    graph["nodes"] = []
    graph["edges"] = []
    graph["paths"] = []
    graph["gaps"] = [{"path": "app.py", "reason": "AST_SOURCE_NOT_INDEXED"}]
    graph["gap_events"] = [
        {
            "path": "app.py",
            "reason": "AST_SOURCE_NOT_INDEXED",
            "attribution": "UNLOCATED",
        }
    ]
    wrapper = _wrapper(graph, local_only=True)
    payload = wrapper["context_payload"]
    payload["source_sha256"] = None
    wrapper["context_hash"] = sha256(canonical_bytes(payload)).hexdigest()
    wrapper["context_id"] = sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v8",
                "plan_binding_hash": payload["plan_binding_hash"],
                "surface_id": "surface-1",
                "part_index": 0,
                "context_hash": wrapper["context_hash"],
            }
        )
    ).hexdigest()
    response = _response(wrapper, local_only=True)
    response["status"] = "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    response["review_evidence"] = []

    checked = validate_v8_response(wrapper, response)

    assert checked.proof_level == "INSUFFICIENT"
    assert checked.verified_path_id is None


def test_v8_readiness_short_circuits_missing_ast_and_relevant_gap() -> None:
    clean = _wrapper(_graph())
    assert v8_review_readiness(clean) == (True, "READY")

    missing = _graph()
    missing["ast_facts"] = []
    assert v8_review_readiness(_wrapper(missing)) == (
        False,
        "ANCHOR_AST_UNAVAILABLE",
    )

    gapped = _graph(
        gap_events=[
            {"path": "app.py", "reason": "DYNAMIC_CALL", "attribution": "UNLOCATED"}
        ]
    )
    assert v8_review_readiness(_wrapper(gapped)) == (
        False,
        "RELEVANT_GRAPH_GAP",
    )


def test_v8_duplicate_legacy_gap_needs_distinct_provenance_events() -> None:
    graph = _graph()
    graph["gaps"] = [
        {"path": "app.py", "reason": "DYNAMIC_CALL"},
        {"path": "app.py", "reason": "DYNAMIC_CALL"},
    ]
    graph["gap_events"] = [
        {
            "path": "app.py",
            "reason": "DYNAMIC_CALL",
            "attribution": "PINNED_PATH",
            "graph_path_id": "different-path",
            "route_entry": {
                "path": "app.py",
                "line": 1,
                "source_sha256": "a" * 64,
            },
            "sink": {
                "path": "app.py",
                "line": 2,
                "source_sha256": "a" * 64,
            },
        }
    ]

    assert v8_review_readiness(_wrapper(graph)) == (
        False,
        "RELEVANT_GRAPH_GAP",
    )


def _planner_inputs() -> _PlannerInputs:
    from hashlib import sha256

    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    control = _surface()
    sink = AttackSurface(
        surface_id="surface-2",
        type="SQL_EXECUTION",
        path="app.py",
        symbol="execute",
        line=4,
        linked_candidate_ids=(),
        evidence_refs=(),
        detector="test",
    )
    index = SurfaceIndex(
        scope_fingerprint="f" * 64,
        static_bundle_hash="s" * 64,
        ast_manifest_hash="m" * 64,
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        candidate_inventory_hash="c" * 64,
        candidate_count=2,
        surfaces=(control, sink),
        static_gaps=(),
        index_version=2,
        ast_source_hashes=(("app.py", "a" * 64),),
    )
    index_hash = sha256(canonical_bytes(index.to_json())).hexdigest()
    index_ref = _ref(identity, index_hash)
    v7_parts = [
        {
            "surface_id": surface.surface_id,
            "context_id": f"context-{number}",
            "context_hash": str(number) * 64,
            "source_sha256": "a" * 64,
        }
        for number, surface in enumerate(index.surfaces, 1)
    ]
    v7_plan: dict[str, Any] = {
        "kind": "simple_surface_enrichment_plan_v7",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope": "repository",
        "scope_fingerprint": index.scope_fingerprint,
        "static_bundle_hash": index.static_bundle_hash,
        "ast_manifest_hash": index.ast_manifest_hash,
        "candidate_inventory_hash": index.candidate_inventory_hash,
        "candidate_count": index.candidate_count,
        "index_ref": index_ref.model_dump(mode="json"),
        "index_hash": index_hash,
        "prior_v6_plan_ref": _ref(identity, "6" * 64).model_dump(mode="json"),
        "prior_v6_plan_hash": "6" * 64,
        "prior_v4_coverage_ref": _ref(identity, "4" * 64).model_dump(mode="json"),
        "prior_v4_coverage_hash": "4" * 64,
        "prior_progress_hash": "p" * 64,
        "v4_plan_hash": "d" * 64,
        "v2_coverage_hash": "e" * 64,
        "child_checkpoint_hashes": {},
        "expected_parts": v7_parts,
    }
    v7_ref = _ref(identity, sha256(canonical_bytes(v7_plan)).hexdigest())
    v5 = SurfaceCoverageV5(
        scope_fingerprint=index.scope_fingerprint,
        static_bundle_hash=index.static_bundle_hash,
        ast_manifest_hash=index.ast_manifest_hash,
        candidate_inventory_hash=index.candidate_inventory_hash,
        candidate_count=index.candidate_count,
        index_hash=index_hash,
        original_coverage_ref=_ref(identity, "0" * 64),
        scope_certificate_ref=_ref(identity, "1" * 64),
        prior_v4_ref=_ref(identity, "4" * 64),
        prior_v6_plan_ref=_ref(identity, "6" * 64),
        v7_plan_ref=v7_ref,
        prior_progress_hash="p" * 64,
        missing_v6_parts=(),
        raw_static_gaps=(),
        effective_python_gaps=(),
        surfaces=tuple(
            SurfaceProofV5(
                surface_id=surface.surface_id,
                path=surface.path,
                line=surface.line,
                coverage_status="COVERED",
                prior_v4_status="COVERED",
                review_classification="NO_HYPOTHESIS",
                verified_roles=(),
                evidence_refs=(),
                unresolved_reason_codes=(),
                completed_inconclusive_children=(),
            )
            for surface in index.surfaces
        ),
        pending_candidate_count=0,
        pending_child_count=0,
    )
    v5_ref = _ref(identity, sha256(canonical_bytes(v5.to_json())).hexdigest())
    progress = {
        (part["surface_id"], part["context_id"]): _Row(
            surface_id=part["surface_id"],
            context_id=part["context_id"],
            static_bundle_hash=index.static_bundle_hash,
            index_hash=index_hash,
            context_hash=part["context_hash"],
            source_sha256="a" * 64,
            status="NO_HYPOTHESIS",
            result_ref=_ref(identity, str(number + 7) * 64),
            hypothesis_ids=(),
            proposal_version=7,
        )
        for number, part in enumerate(v7_parts)
    }
    graph = _graph()
    graph["index_hash"] = index_hash
    return {
        "identity": identity,
        "index": index,
        "index_ref": index_ref,
        "v7_plan": v7_plan,
        "v7_ref": v7_ref,
        "v5": v5,
        "v5_ref": v5_ref,
        "progress": progress,
        "graphs": {control.surface_id: graph},
    }


def _prepare(inputs: _PlannerInputs) -> tuple[dict[str, object], tuple[V8Part, ...]]:
    return prepare_surface_enrichment_v8(
        inputs["identity"],
        "repository",
        inputs["index"],
        inputs["index_ref"],
        inputs["v7_ref"],
        inputs["v7_plan"],
        inputs["v5_ref"],
        inputs["v5"],
        inputs["progress"],
        inputs["graphs"],
        required_graph_revision="v5-source-bound-5",
    )


def test_v8_recertifies_even_previously_covered_control_without_replaying_sink() -> (
    None
):
    inputs = _planner_inputs()
    plan, parts = _prepare(inputs)

    assert plan["kind"] == "simple_surface_enrichment_plan_v8"
    assert plan["prior_v7_plan_hash"] == inputs["v7_ref"].content_hash
    assert plan["prior_v5_coverage_hash"] == inputs["v5_ref"].content_hash
    assert plan["missing_v7_parts"] == []
    assert plan["target_surface_ids"] == ["surface-1"]
    assert len(parts) == 1
    assert parts[0].payload["anchor_contract"] == "CONTROL"
    assert parts[0].payload["target_path_id"] == "route-to-anchor"
    assert parts[0].context_id not in {
        part["context_id"] for part in inputs["v7_plan"]["expected_parts"]
    }
    assert canonical_bytes(plan) == canonical_bytes(_prepare(inputs)[0])


def test_v8_plan_rejects_incomplete_v7_checkpoint() -> None:
    inputs = _planner_inputs()
    inputs["progress"].pop(("surface-1", "context-1"))

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V8_PARENT_INCOMPLETE"):
        _prepare(inputs)


def test_v8_frozen_parent_rejects_malformed_saved_v5_row() -> None:
    parent = _planner_inputs()["v5"]
    raw = parent.to_json()
    assert _frozen_parent_v5_from_json(raw) == parent

    raw_surfaces = cast(list[dict[str, object]], raw["surfaces"])
    raw_surfaces[0]["line"] = "3"
    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V6_PARENT_INVALID"):
        _frozen_parent_v5_from_json(raw)


def test_v8_frozen_parent_ignores_new_child_pending_but_rejects_old_row_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from hashlib import sha256

    inputs = _planner_inputs()
    identity = inputs["identity"]
    v7_plan = {
        **inputs["v7_plan"],
        "prior_progress_hash": prior_progress_snapshot_hash({}),
        "targets": [
            {"surface_id": part["surface_id"]}
            for part in inputs["v7_plan"]["expected_parts"]
        ],
    }
    v7_ref = _ref(identity, sha256(canonical_bytes(v7_plan)).hexdigest())
    parent = replace(
        inputs["v5"],
        v7_plan_ref=v7_ref,
        prior_progress_hash=v7_plan["prior_progress_hash"],
    )
    parent_ref = _ref(identity, sha256(canonical_bytes(parent.to_json())).hexdigest())
    saved = {
        v7_ref.content_hash: canonical_bytes(v7_plan),
        parent_ref.content_hash: canonical_bytes(parent.to_json()),
    }

    class _Artifacts:
        def read_bounded(self, ref: StoredDataRef, _maximum: int) -> bytes:
            return saved[ref.content_hash]

        def read(self, _ref: StoredDataRef) -> bytes:
            return b"old checkpoint bytes are present"

    class _Store:
        def list_checkpoints(self, _analysis_id: str) -> tuple[()]:
            return ()

        def list_incomplete_hypotheses(self, *_args: object, **_kwargs: object) -> None:
            raise AssertionError("frozen parent must not recount new v8 children")

    monkeypatch.setattr(
        coverage_v5,
        "_validated_v7_part",
        lambda *_args: ((), (), None, "NO_HYPOTHESIS"),
    )
    new_child = replace(
        next(iter(inputs["progress"].values())),
        surface_id="surface-1",
        context_id="v8-new-child",
        proposal_version=8,
    )
    progress = {**inputs["progress"], ("surface-1", "v8-new-child"): new_child}

    assert (
        read_frozen_parent_v5(
            identity,
            inputs["index"],
            parent_ref,
            v7_ref,
            v7_plan,
            progress,
            cast(SimpleCheckpointStore, _Store()),
            cast(SimpleArtifactRepository, _Artifacts()),
        )
        == parent
    )

    old_key = next(iter(inputs["progress"]))
    tampered = dict(progress)
    tampered[old_key] = replace(tampered[old_key], context_hash="0" * 64)
    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V6_PARENT_INVALID"):
        read_frozen_parent_v5(
            identity,
            inputs["index"],
            parent_ref,
            v7_ref,
            v7_plan,
            tampered,
            cast(SimpleCheckpointStore, _Store()),
            cast(SimpleArtifactRepository, _Artifacts()),
        )


def test_v8_saved_result_revalidates_exact_role_proof(tmp_path: Path) -> None:
    inputs = _planner_inputs()
    plan, parts = _prepare(inputs)
    identity = inputs["identity"]
    index = inputs["index"]
    graph = inputs["graphs"]["surface-1"]
    part = parts[0]
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    artifacts.put_json(graph)
    artifacts.put_json(part.payload)
    wrapper = {
        "context_payload": part.payload,
        "graph_payload": graph,
        "context_hash": part.context_hash,
        "context_id": part.context_id,
    }
    response = _response(wrapper)
    checked = validate_v8_response(wrapper, response)
    graph_hash = part.payload["graph_hash"]
    assert isinstance(graph_hash, str)
    result = {
        "kind": "simple_surface_hypothesis_result_v8",
        "analysis_id": identity.analysis_id,
        "surface_id": part.surface_id,
        "context_id": part.context_id,
        "part_index": part.part_index,
        "part_count": part.part_count,
        "context_hash": part.context_hash,
        "static_bundle_hash": index.static_bundle_hash,
        "status": checked.status,
        "reason": checked.reason,
        "reviewed_parts": sorted(checked.reviewed_parts),
        "evidence_locations": list(checked.evidence_locations),
        "verified_roles": list(checked.verified_roles),
        "verified_path_id": checked.verified_path_id,
        "proof_level": checked.proof_level,
        "graph_hash": graph_hash,
        "graph_ref": _ref(identity, graph_hash).model_dump(mode="json"),
        "seed_ids": [],
        "response": response,
        "validation_status": "VALID",
    }
    result_ref = artifacts.put_json(result)
    row = _Row(
        surface_id=part.surface_id,
        context_id=part.context_id,
        static_bundle_hash=index.static_bundle_hash,
        index_hash=inputs["index_ref"].content_hash,
        context_hash=part.context_hash,
        source_sha256=part.source_sha256,
        status=checked.status,
        result_ref=result_ref,
        hypothesis_ids=(),
        proposal_version=8,
    )
    targets = cast(list[dict[str, object]], plan["targets"])
    expected_parts = cast(list[dict[str, object]], plan["expected_parts"])

    checked_again, _ = _validated_v8_part(
        identity,
        index,
        inputs["index_ref"],
        plan,
        targets[0],
        expected_parts[0],
        row,
        artifacts,
    )
    assert checked_again.proof_level == "CONNECTED"

    artifacts.put_json(index.to_json())
    artifacts.put_json(inputs["v5"].to_json())
    artifacts.put_json(inputs["v7_plan"])
    plan_ref = artifacts.put_json(plan)

    class _ReadOnlyStore:
        def require_analysis_run(self, _analysis_id: str) -> SimpleNamespace:
            return SimpleNamespace(
                candidate_terminal=SimpleNamespace(producer_finished=True)
            )

        def candidate_counts(self, *_args: object) -> dict[str, int]:
            return {}

        def candidate_deep_counts(self, *_args: object) -> dict[str, int]:
            return {}

        def list_incomplete_hypotheses(
            self, *_args: object, **_kwargs: object
        ) -> tuple[()]:
            return ()

    progress = {**inputs["progress"], (row.surface_id, row.context_id): row}
    proof = evaluate_surface_coverage_v6(
        identity,
        index,
        inputs["index_ref"],
        inputs["v5_ref"],
        inputs["v5"],
        inputs["v7_ref"],
        inputs["v7_plan"],
        plan_ref,
        plan,
        progress,
        cast(SimpleCheckpointStore, _ReadOnlyStore()),
        artifacts,
    )
    assert proof.complete
    assert [item.coverage_status for item in proof.surfaces] == [
        "COVERED",
        "COVERED",
    ]

    forged = {**result, "proof_level": "LOCAL_ONLY"}
    forged_row = replace(row, result_ref=artifacts.put_json(forged))
    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V6_PROGRESS_INVALID"):
        _validated_v8_part(
            identity,
            index,
            inputs["index_ref"],
            plan,
            targets[0],
            expected_parts[0],
            forged_row,
            artifacts,
        )
