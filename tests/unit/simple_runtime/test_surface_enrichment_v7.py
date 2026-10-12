"""An opt-in v7 plan binds saved v6 evidence and never edits it."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from tests.unit.simple_runtime.test_surface_coverage_v4 import (
    _evaluate,
    _save_v6_part,
    _successor_case,
)


def _case(tmp_path: Path, *, old_hold: bool = False) -> dict[str, Any]:
    data = _successor_case(tmp_path, old_hold=old_hold)
    _save_v6_part(data, connected=False)
    parent = _evaluate(data)
    case = data["case"]
    graph = deepcopy(data["graph"])
    graph["proof_semantics_revision"] = "v5-source-bound-4"
    data = {
        **data,
        "parent": parent,
        "parent_ref": case.artifacts.put_json(parent.to_json()),
        "new_graphs": {parent.surfaces[0].surface_id: graph},
    }
    _add_inherited_covered_graph(data)
    for v7_graph in data["new_graphs"].values():
        case.artifacts.put_json(v7_graph)
    return data


def _prepare(data: dict[str, Any]) -> tuple[dict[str, Any], tuple[Any, ...]]:
    from sastsimi.simple_runtime.surface_enrichment_v7 import (
        prepare_surface_enrichment_v7,
    )

    case = data["case"]
    for graph in data["new_graphs"].values():
        case.artifacts.put_json(graph)
    plan, parts = prepare_surface_enrichment_v7(
        case.identity,
        data["plan"]["scope"],
        case.index,
        case.index_ref,
        data["plan_ref"],
        data["plan"],
        data["parent_ref"],
        data["parent"],
        case.progress,
        data["new_graphs"],
        required_graph_revision="v5-source-bound-4",
    )
    return cast(dict[str, Any], plan), parts


def _add_inherited_covered_graph(data: dict[str, Any]) -> str:
    covered = data["case"].index.surfaces[1]
    graph = deepcopy(data["new_graphs"][data["case"].index.surfaces[0].surface_id])
    graph["anchor"] = {
        "surface_id": covered.surface_id,
        "path": covered.path,
        "line": covered.line,
    }
    for node in graph["nodes"]:
        if node["role"] == "SINK":
            node["line"] = covered.line
    for path in graph["paths"]:
        for step in path["steps"]:
            if step["role"] == "SINK":
                step["line"] = covered.line
    data["new_graphs"][covered.surface_id] = graph
    covered_id = covered.surface_id
    assert isinstance(covered_id, str)
    return covered_id


def test_v7_targets_every_indexed_surface_and_binds_parent_snapshot(
    tmp_path: Path,
) -> None:
    data = _case(tmp_path)
    old_plan = canonical_bytes(data["plan"])
    old_progress = dict(data["case"].progress)

    plan, parts = _prepare(data)

    assert plan["kind"] == "simple_surface_enrichment_plan_v7"
    assert plan["scope"] == data["plan"]["scope"]
    assert plan["scope_fingerprint"] == data["case"].index.scope_fingerprint
    assert plan["graph_semantics_revision"] == "v5-source-bound-4"
    assert plan["prior_v6_plan_hash"] == data["plan_ref"].content_hash
    assert plan["prior_v4_coverage_hash"] == data["parent_ref"].content_hash
    assert plan["target_surface_ids"] == [
        surface.surface_id for surface in data["case"].index.surfaces
    ]
    assert plan["missing_v6_parts"] == []
    assert len(parts) == 2
    assert parts[0].payload["kind"] == "simple_surface_context_v7"
    assert parts[0].payload["prior_v4_coverage_hash"] == data["parent_ref"].content_hash
    assert parts[0].payload["prior_reasons"] == list(
        data["parent"].surfaces[0].unresolved_reason_codes
    )
    assert parts[0].context_id != data["parts"][0].context_id
    assert len(canonical_bytes(parts[0].payload)) <= 64 * 1024
    assert canonical_bytes(data["plan"]) == old_plan
    assert data["case"].progress == old_progress
    assert canonical_bytes(plan) == canonical_bytes(_prepare(data)[0])


def test_v7_rejects_changed_parent_or_source_graph(tmp_path: Path) -> None:
    data = _case(tmp_path)
    data["parent_ref"] = data["plan_ref"]
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V7"):
        _prepare(data)

    data = _case(tmp_path / "source")
    data["new_graphs"][data["parent"].surfaces[0].surface_id]["source_files"][0][
        "source_sha256"
    ] = "0" * 64
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V7"):
        _prepare(data)


def test_v7_rejects_old_graph_revision(tmp_path: Path) -> None:
    data = _case(tmp_path)
    data["new_graphs"][data["parent"].surfaces[0].surface_id][
        "proof_semantics_revision"
    ] = "v5-source-bound-3"
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V7_GRAPH_REVISION"):
        _prepare(data)


def test_v7_records_exact_missing_v6_part_set(tmp_path: Path) -> None:
    data = _case(tmp_path)
    part = data["parts"][0]
    del data["case"].progress[(part.surface_id, part.context_id)]
    parent = _evaluate(data)
    data["parent"] = parent
    data["parent_ref"] = data["case"].artifacts.put_json(parent.to_json())

    plan, _ = _prepare(data)

    assert plan["missing_v6_parts"] == [
        {"surface_id": part.surface_id, "context_id": part.context_id}
    ]


def test_v7_prior_hypothesis_does_not_suppress_new_rev4_review(tmp_path: Path) -> None:
    data = _case(tmp_path)
    part = data["parts"][0]
    key = (part.surface_id, part.context_id)
    old = data["case"].progress[key]
    data["case"].progress[key] = replace(
        old, status="HYPOTHESES", hypothesis_ids=("hypothesis-existing",)
    )

    plan, _ = _prepare(data)
    assert plan["targets"][0]["review_mode"] == "STANDARD"
    assert part.surface_id in plan["existing_hypothesis_surface_ids"]
    assert data["case"].progress[key].hypothesis_ids == ("hypothesis-existing",)


def test_v7_recertifies_inherited_covered_without_changing_parent(
    tmp_path: Path,
) -> None:
    data = _case(tmp_path)
    covered_id = _add_inherited_covered_graph(data)
    old_progress = dict(data["case"].progress)
    old_parent = canonical_bytes(data["parent"].to_json())

    plan, parts = _prepare(data)

    assert covered_id in plan["target_surface_ids"]
    covered = next(row for row in plan["targets"] if row["surface_id"] == covered_id)
    assert covered["review_mode"] == "STANDARD"
    assert any(part.surface_id == covered_id for part in parts)
    assert data["case"].progress == old_progress
    assert canonical_bytes(data["parent"].to_json()) == old_parent


def test_v7_recertifies_existing_hypothesis_with_standard_review(
    tmp_path: Path,
) -> None:
    data = _case(tmp_path)
    first_id = data["case"].index.surfaces[0].surface_id
    first_key = (data["parts"][0].surface_id, data["parts"][0].context_id)
    prior_row = data["case"].progress[first_key]
    data["case"].progress[first_key] = replace(
        prior_row, status="HYPOTHESES", hypothesis_ids=("hypothesis-existing",)
    )
    _add_inherited_covered_graph(data)
    old_progress = dict(data["case"].progress)

    plan, parts = _prepare(data)

    target = next(row for row in plan["targets"] if row["surface_id"] == first_id)
    assert target["review_mode"] == "STANDARD"
    assert first_id in plan["target_surface_ids"]
    assert first_id in plan["existing_hypothesis_surface_ids"]
    assert any(
        part.surface_id == first_id and part.payload["review_mode"] == "STANDARD"
        for part in parts
    )
    assert data["case"].progress == old_progress


def test_v7_rejects_existing_hypothesis_status_without_bound_child_id(
    tmp_path: Path,
) -> None:
    data = _case(tmp_path)
    part = data["parts"][0]
    key = (part.surface_id, part.context_id)
    data["case"].progress[key] = replace(
        data["case"].progress[key], status="HYPOTHESES"
    )

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V7_PROGRESS_INVALID"):
        _prepare(data)


def test_v7_large_graph_keeps_atomic_path_support_bounded(tmp_path: Path) -> None:
    data = _case(tmp_path)
    graph = data["new_graphs"][data["case"].index.surfaces[0].surface_id]
    graph["ast_facts"].append({"path": "unrelated.py", "detail": "x" * 70_000})

    plan, parts = _prepare(data)

    assert len(canonical_bytes(graph)) > 64 * 1024
    first = next(
        part for part in parts if part.surface_id == plan["targets"][0]["surface_id"]
    )
    assert first.payload["target_path_id"] == "path-real"
    assert first.payload["unavailable_item_count"] == 0
    assert len(canonical_bytes(first.payload)) <= 64 * 1024


def test_v7_oversized_single_path_is_explicitly_unavailable(tmp_path: Path) -> None:
    data = _case(tmp_path)
    graph = data["new_graphs"][data["case"].index.surfaces[0].surface_id]
    graph["source_lines"][0]["text"] = "x" * 70_000

    plan, parts = _prepare(data)

    target = plan["targets"][0]
    assert target["unavailable_items"][0]["reason"] == ("ATOMIC_PATH_SUPPORT_TOO_LARGE")
    first = next(part for part in parts if part.surface_id == target["surface_id"])
    assert first.payload["target_path_id"] == "path-real"
    assert first.payload["unavailable_item_count"] == 1
    assert first.payload["items"] == []
    assert len(canonical_bytes(first.payload)) <= 64 * 1024
