"""V7 responses require an exact rev4 graph and connected source-bound roles."""

from __future__ import annotations

import hashlib
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.provider import SimpleLLMClient
from sastsimi.simple_runtime.surface_evidence_validation_v5 import (
    validate_v5_response,
)
from tests.unit.simple_runtime.test_surface_enrichment_v7 import (
    _add_inherited_covered_graph,
    _case,
    _prepare,
)
from tests.unit.simple_runtime.test_surface_proposal import _proposal


def _rebind_context(wrapper: dict[str, object]) -> None:
    payload = wrapper["context_payload"]
    assert isinstance(payload, dict)
    context_hash = hashlib.sha256(canonical_bytes(payload)).hexdigest()
    wrapper["context_hash"] = context_hash
    wrapper["context_id"] = hashlib.sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v7",
                "plan_binding_hash": payload["plan_binding_hash"],
                "surface_id": payload["surface_id"],
                "part_index": payload["part_index"],
                "context_hash": context_hash,
            }
        )
    ).hexdigest()


def _wrapper(
    tmp_path: Path, *, unrelated_gap: bool = False
) -> tuple[dict[str, object], dict[str, object]]:
    data = _case(tmp_path)
    if unrelated_gap:
        graph = next(iter(data["new_graphs"].values()))
        graph["gaps"].append(
            {"path": "other.py", "reason": "UNRELATED_DYNAMIC_DISPATCH"}
        )
    _, parts = _prepare(data)
    part = parts[0]
    graph = data["new_graphs"][part.surface_id]
    return (
        {
            "context_payload": part.payload,
            "graph_payload": graph,
            "context_hash": part.context_hash,
            "context_id": part.context_id,
        },
        {
            "surface_id": part.surface_id,
            "context_id": part.context_id,
            "status": "NO_HYPOTHESIS",
            "reason": "Reviewed one pinned path",
            "hypotheses": [],
            "review_evidence": [
                {
                    "part": role,
                    "location": f"app.py:{line}",
                    "context_hash": part.context_hash,
                    "source_sha256": part.source_sha256,
                    "graph_path_id": "path-real",
                    "edge_ids": edges,
                    "explanation": "Source-bound path role",
                }
                for role, line, edges in (
                    ("ENTRY", 1, ["edge-entry"]),
                    ("TRUST_BOUNDARY", 3, ["edge-entry", "edge-sink"]),
                    ("SENSITIVE_OPERATION", 4, ["edge-sink"]),
                )
            ],
        },
    )


def test_v7_accepts_connected_rev4_path_without_loosening_v5(tmp_path: Path) -> None:
    from sastsimi.simple_runtime.surface_evidence_validation_v5 import (
        validate_v7_response,
    )

    wrapper, response = _wrapper(tmp_path)

    checked = validate_v7_response(wrapper, response)

    assert checked.status == "NO_HYPOTHESIS"
    assert checked.verified_path_id == "path-real"
    with pytest.raises(ValueError, match="V5_CONTEXT_INVALID"):
        validate_v5_response(wrapper, response)


def test_v7_refuses_blocked_path_and_changed_parent_hash(tmp_path: Path) -> None:
    from sastsimi.simple_runtime.surface_evidence_validation_v5 import (
        validate_v7_response,
    )

    wrapper, response = _wrapper(tmp_path)
    blocked = deepcopy(wrapper)
    blocked_graph = blocked["graph_payload"]
    assert isinstance(blocked_graph, dict)
    blocked_paths = blocked_graph["paths"]
    assert isinstance(blocked_paths, list)
    blocked_path = blocked_paths[0]
    assert isinstance(blocked_path, dict)
    blocked_path["blocking_gaps"] = ["DYNAMIC_DISPATCH_UNRESOLVED"]
    with pytest.raises(ValueError):
        validate_v7_response(blocked, response)

    changed = deepcopy(wrapper)
    changed_context = changed["context_payload"]
    assert isinstance(changed_context, dict)
    changed_context["prior_v4_coverage_hash"] = "not-a-hash"
    with pytest.raises(ValueError, match="V5_CONTEXT_INVALID"):
        validate_v7_response(changed, response)


def test_v7_accepts_clean_claimed_path_with_unrelated_global_gap(
    tmp_path: Path,
) -> None:
    from sastsimi.simple_runtime.surface_evidence_validation_v5 import (
        validate_v7_response,
    )

    wrapper, response = _wrapper(tmp_path, unrelated_gap=True)

    assert validate_v7_response(wrapper, response).verified_path_id == "path-real"


def test_v7_prior_hypothesis_does_not_forbid_new_rev4_decision(
    tmp_path: Path,
) -> None:
    from sastsimi.simple_runtime.surface_evidence_validation_v5 import (
        validate_v7_response,
    )

    data = _case(tmp_path)
    prior = data["parts"][0]
    key = (prior.surface_id, prior.context_id)
    data["case"].progress[key] = replace(
        data["case"].progress[key],
        status="HYPOTHESES",
        hypothesis_ids=("hypothesis-existing",),
    )
    _add_inherited_covered_graph(data)
    _, parts = _prepare(data)
    part = next(item for item in parts if item.surface_id == prior.surface_id)
    wrapper = {
        "context_payload": part.payload,
        "graph_payload": data["new_graphs"][part.surface_id],
        "context_hash": part.context_hash,
        "context_id": part.context_id,
    }
    response = {
        "surface_id": part.surface_id,
        "context_id": part.context_id,
        "status": "NO_HYPOTHESIS",
        "reason": "Navigation evidence only",
        "hypotheses": [],
        "review_evidence": [
            {
                "part": role,
                "location": f"app.py:{line}",
                "context_hash": part.context_hash,
                "source_sha256": part.source_sha256,
                "graph_path_id": "path-real",
                "edge_ids": edges,
                "explanation": "Source-bound path role",
            }
            for role, line, edges in (
                ("ENTRY", 1, ["edge-entry"]),
                ("TRUST_BOUNDARY", 3, ["edge-entry", "edge-sink"]),
                ("SENSITIVE_OPERATION", 4, ["edge-sink"]),
            )
        ],
    }
    assert part.payload["review_mode"] == "STANDARD"
    assert validate_v7_response(wrapper, response).status == "NO_HYPOTHESIS"

    response["status"] = "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    assert validate_v7_response(wrapper, response).verified_path_id == "path-real"

    response["status"] = "HYPOTHESES"
    response["hypotheses"] = [_proposal("app.py:4")]
    assert len(validate_v7_response(wrapper, response).qualified) == 1


@pytest.mark.parametrize(
    "category", ["source_files", "source_lines", "nodes", "edges", "paths"]
)
def test_v7_rejects_missing_selected_path_support(
    tmp_path: Path, category: str
) -> None:
    from sastsimi.simple_runtime.surface_evidence_validation_v5 import (
        validate_v7_context,
    )

    wrapper, _ = _wrapper(tmp_path)
    changed = deepcopy(wrapper)
    payload = changed["context_payload"]
    assert isinstance(payload, dict)
    items = payload["items"]
    assert isinstance(items, list)
    assert any(item["category"] == category for item in items)
    first = next(item for item in items if item["category"] == category)
    items.remove(first)
    _rebind_context(changed)

    with pytest.raises(ValueError, match="V5_CONTEXT_PATH_SUPPORT_INCOMPLETE"):
        validate_v7_context(changed)


def test_v7_rejects_other_path_row_in_selected_path_part(tmp_path: Path) -> None:
    from sastsimi.simple_runtime.surface_evidence_validation_v5 import (
        validate_v7_context,
    )
    from tests.unit.simple_runtime.test_surface_coverage_v5 import _v7_case

    data = _v7_case(tmp_path, second_sink_path=True)
    part = data["v7_parts"][0]
    assert part.payload["target_path_id"] == "path-real"
    changed = {
        "context_payload": deepcopy(part.payload),
        "graph_payload": data["new_graphs"][part.surface_id],
        "context_hash": part.context_hash,
        "context_id": part.context_id,
    }
    payload = changed["context_payload"]
    assert isinstance(payload, dict)
    items = payload["items"]
    assert isinstance(items, list)
    items.append(
        {
            "category": "paths",
            "ordinal": 1,
            "value": deepcopy(changed["graph_payload"]["paths"][1]),
        }
    )
    _rebind_context(changed)

    with pytest.raises(ValueError, match="V5_CONTEXT_PATH_CONTAMINATION"):
        validate_v7_context(changed)


def test_v7_oversized_path_skips_agent_and_records_insufficient(
    tmp_path: Path,
) -> None:
    from sastsimi.simple_runtime.application import StaticBootstrapResult
    from sastsimi.simple_runtime.bootstrap_stages import (
        DirectHypothesisBootstrap,
        SurfaceProposalResult,
    )
    from sastsimi.simple_runtime.surface_contexts import SurfaceContext

    data = _case(tmp_path)
    graph = data["new_graphs"][data["case"].index.surfaces[0].surface_id]
    graph["source_lines"][0]["text"] = "x" * 70_000
    _, parts = _prepare(data)
    part = parts[0]
    case = data["case"]
    case.artifacts.put_json(graph)
    context_ref = case.artifacts.put_json(part.payload)
    static_ref = case.artifacts.put_json({"kind": "static-bundle"})
    static = StaticBootstrapResult(
        repository_profile_ref=static_ref,
        static_bundle_ref=static_ref,
        workspace_path=tmp_path,
    )
    context = SurfaceContext(
        surface_id=part.surface_id,
        context_id=part.context_id,
        context_hash=part.context_hash,
        context_ref=context_ref,
        part_index=part.part_index,
        part_count=part.part_count,
        prompt_bytes=len(case.artifacts.read(context_ref)),
        source_sha256=part.source_sha256,
        source_unavailable_reason=None,
        ast_unavailable_reason=None,
        omitted_source_line_count=0,
        omitted_ast_fact_count=0,
    )

    def forbidden_agent(
        identity: CheckpointIdentity, artifacts: SimpleArtifactRepository
    ) -> SimpleLLMClient:
        raise AssertionError("Oversized path must not call the Agent")

    bootstrap = DirectHypothesisBootstrap(
        data_dir=tmp_path / "data", client_factory=forbidden_agent
    )
    with pytest.raises(StopIteration) as done:
        bootstrap.propose_surface(case.identity, static, context).send(None)

    assert isinstance(done.value.value, SurfaceProposalResult)
    assert done.value.value.status == "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
