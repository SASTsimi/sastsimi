"""Pure v4 planning must bind the saved state and never silently trim evidence."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attack_surfaces import (
    AttackSurface,
    SurfaceCoverage,
    SurfaceIndex,
)
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.store import SurfaceExplorationProgressRecord
from sastsimi.simple_runtime.surface_enrichment_v4 import (
    prepare_surface_enrichment_v4,
)


def _case(tmp_path: Path, *, line_count: int = 3) -> tuple[Any, ...]:
    identity = CheckpointIdentity(
        analysis_id="analysis-v4",
        workspace_id="workspace-v4",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    evidence = artifacts.put_json({"kind": "static-evidence"})
    static_ref = artifacts.put_json({"kind": "static-bundle"})
    surface = AttackSurface(
        surface_id="surface-target",
        type="COMMAND_EXECUTION",
        path="app.py",
        symbol="rule",
        line=2,
        linked_candidate_ids=(),
        evidence_refs=(evidence,),
        detector="AST",
    )
    other = replace(surface, surface_id="surface-covered", line=9)
    source_hash = "e" * 64
    index = SurfaceIndex(
        scope_fingerprint="f" * 64,
        static_bundle_hash=static_ref.content_hash,
        ast_manifest_hash="c" * 64,
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        candidate_inventory_hash="d" * 64,
        candidate_count=0,
        surfaces=(surface, other),
        static_gaps=(),
        index_version=2,
        ast_source_hashes=(("app.py", source_hash),),
    )
    index_ref = artifacts.put_json(index.to_json())
    coverage = SurfaceCoverage(
        scope_fingerprint=index.scope_fingerprint,
        static_bundle_hash=index.static_bundle_hash,
        ast_manifest_hash=index.ast_manifest_hash,
        candidate_inventory_hash=index.candidate_inventory_hash,
        candidate_count=0,
        surfaces=(
            replace(surface, coverage_status="INSUFFICIENT"),
            replace(other, coverage_status="COVERED"),
        ),
        static_gaps=(),
    )
    certificate = {
        "kind": "simple_python_scope_recertification_v1",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope_fingerprint": index.scope_fingerprint,
        "index_hash": index_ref.content_hash,
        "raw_static_gaps": [],
        "effective_static_gaps": [],
    }
    result_ref = artifacts.put_json({"kind": "old-v3-result"})
    parent = SurfaceExplorationProgressRecord(
        surface_id=surface.surface_id,
        context_id="prior-v3-context",
        static_bundle_hash=index.static_bundle_hash,
        index_hash=index_ref.content_hash,
        context_hash="1" * 64,
        source_sha256=source_hash,
        status="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
        result_ref=result_ref,
        hypothesis_ids=(),
        proposal_version=3,
    )
    graph = {
        "kind": "simple_surface_evidence_graph_v4",
        "anchor": {"surface_id": surface.surface_id, "path": "app.py", "line": 2},
        "scope_fingerprint": index.scope_fingerprint,
        "index_hash": index_ref.content_hash,
        "ast_manifest_hash": index.ast_manifest_hash,
        "source_files": [
            {"path": "app.py", "source_sha256": source_hash, "ast_sha256": "2" * 64}
        ],
        "source_lines": [
            {
                "line_id": f"line-{n}",
                "path": "app.py",
                "line": n,
                "text": "return check(value) # " + "x" * 96,
                "source_sha256": source_hash,
            }
            for n in range(1, line_count + 1)
        ],
        "ast_facts": [
            {"fact_id": "fact-1", "path": "app.py", "line": 2, "kind": "Call"}
        ],
        "nodes": [{"node_id": "node-1", "path": "app.py", "line": 2, "role": "SINK"}],
        "edges": [
            {
                "edge_id": "edge-1",
                "type": "CALL",
                "from_node_id": "node-1",
                "to_node_id": "node-1",
            }
        ],
        "paths": [{"path_id": "path-1", "edge_ids": ["edge-1"], "steps": []}],
        "gaps": [{"path": "app.py", "reason": "DYNAMIC_DISPATCH_UNRESOLVED"}],
    }
    return (
        identity,
        index,
        index_ref,
        static_ref,
        certificate,
        coverage,
        {(parent.surface_id, parent.context_id): parent},
        {surface.surface_id: graph},
        artifacts,
    )


def _prepare(case: tuple[Any, ...]) -> tuple[Any, ...]:
    (
        identity,
        index,
        index_ref,
        static_ref,
        certificate,
        coverage,
        progress,
        graphs,
        _,
    ) = case
    return prepare_surface_enrichment_v4(
        identity,
        "candidate",
        static_ref,
        index,
        index_ref,
        certificate,
        coverage,
        progress,
        graphs,
    )


def test_only_insufficient_targets_and_prior_hashes_enter_plan(tmp_path: Path) -> None:
    case = _case(tmp_path)
    plan, parts = _prepare(case)

    assert plan["kind"] == "simple_surface_enrichment_plan_v4"
    assert plan["target_surface_ids"] == ["surface-target"]
    assert {part.surface_id for part in parts} == {"surface-target"}
    parent = plan["targets"][0]["prior_progress"][0]
    saved = next(iter(case[6].values()))
    assert parent["context_id"] == saved.context_id
    assert parent["context_hash"] == saved.context_hash
    assert parent["result_hash"] == saved.result_ref.content_hash
    assert plan["index_hash"] == case[2].content_hash
    assert plan["static_bundle_ref"] == case[3].model_dump(mode="json")


def test_every_part_including_metadata_fits_65536_without_lost_atomic_item(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path, line_count=900)
    plan, parts = _prepare(case)

    assert len(parts) > 1
    assert all(len(canonical_bytes(part.payload)) <= 65536 for part in parts)
    assert [part.part_index for part in parts] == list(range(len(parts)))
    assert {part.part_count for part in parts} == {len(parts)}
    seen = [
        item["value"]["line_id"]
        for part in parts
        for item in part.payload["items"]
        if item["category"] == "source_lines"
    ]
    assert seen == [row["line_id"] for row in case[7]["surface-target"]["source_lines"]]
    assert plan["targets"][0]["unavailable_items"] == []


def test_oversized_atomic_line_is_unavailable_not_sliced(tmp_path: Path) -> None:
    case = _case(tmp_path)
    case[7]["surface-target"]["source_lines"][1]["text"] = "X" * 70000
    plan, parts = _prepare(case)

    unavailable = plan["targets"][0]["unavailable_items"]
    assert len(unavailable) == 1
    assert unavailable[0]["category"] == "source_lines"
    assert unavailable[0]["reason"] == "ATOMIC_ITEM_TOO_LARGE"
    assert "X" * 200 not in str(parts)
    assert all(len(canonical_bytes(part.payload)) <= 65536 for part in parts)


def test_repeated_plan_is_canonical_and_mutated_parent_changes_binding(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path)
    first, parts = _prepare(case)
    again, repeated = _prepare(case)
    assert canonical_bytes(first) == canonical_bytes(again)
    assert [canonical_bytes(part.payload) for part in parts] == [
        canonical_bytes(part.payload) for part in repeated
    ]

    parent = next(iter(case[6].values()))
    changed = list(case)
    changed[6] = {
        (parent.surface_id, parent.context_id): replace(parent, context_hash="9" * 64)
    }
    mutated, _ = _prepare(tuple(changed))
    assert mutated["plan_binding_hash"] != first["plan_binding_hash"]


def test_manifest_lists_each_expected_part_once(tmp_path: Path) -> None:
    case = _case(tmp_path, line_count=600)
    plan, parts = _prepare(case)

    expected = plan["expected_parts"]
    assert len(expected) == len(parts)
    assert len({row["context_id"] for row in expected}) == len(expected)
    assert [(row["part_index"], row["context_hash"]) for row in expected] == [
        (part.part_index, part.context_hash) for part in parts
    ]
    assert all(
        hashlib.sha256(canonical_bytes(part.payload)).hexdigest() == part.context_hash
        for part in parts
    )
    graph = case[7]["surface-target"]
    for category in (
        "source_files",
        "source_lines",
        "ast_facts",
        "nodes",
        "edges",
        "paths",
        "gaps",
    ):
        present = [
            item["value"]
            for part in parts
            for item in part.payload["items"]
            if item["category"] == category
        ]
        assert present == graph[category]
