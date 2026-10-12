"""A v5 plan pins a prior proof and never truncates a graph item."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attack_surfaces import AttackSurface, SurfaceIndex
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.store import SurfaceExplorationProgressRecord
from sastsimi.simple_runtime.surface_coverage_v2 import (
    SurfaceCoverageV2,
    SurfaceProofV2,
)
from sastsimi.simple_runtime.surface_enrichment_v5 import prepare_surface_enrichment_v5


def _case(tmp_path: Path, *, line_count: int = 3) -> dict[str, Any]:
    identity = CheckpointIdentity(
        analysis_id="analysis-v5",
        workspace_id="workspace-v5",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    source_hash = "b" * 64
    static_ref = artifacts.put_json({"kind": "static-bundle"})
    surface = AttackSurface(
        surface_id="surface-missing",
        type="COMMAND_EXECUTION",
        path="app.py",
        symbol="route",
        line=2,
        linked_candidate_ids=(),
        evidence_refs=(),
        detector="AST",
    )
    covered = replace(surface, surface_id="surface-covered", line=9)
    index = SurfaceIndex(
        scope_fingerprint="f" * 64,
        static_bundle_hash=static_ref.content_hash,
        ast_manifest_hash="c" * 64,
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        candidate_inventory_hash="d" * 64,
        candidate_count=0,
        surfaces=(surface, covered),
        static_gaps=(),
        index_version=2,
        ast_source_hashes=(("app.py", source_hash),),
    )
    index_ref = artifacts.put_json(index.to_json())
    base_ref = artifacts.put_json({"kind": "simple_attack_surface_coverage_v1"})
    certificate_ref = artifacts.put_json({"kind": "scope-certificate"})
    prior = SurfaceCoverageV2(
        scope_fingerprint=index.scope_fingerprint,
        static_bundle_hash=index.static_bundle_hash,
        ast_manifest_hash=index.ast_manifest_hash,
        candidate_inventory_hash=index.candidate_inventory_hash,
        candidate_count=0,
        index_hash=index_ref.content_hash,
        original_coverage_ref=base_ref,
        scope_certificate_ref=certificate_ref,
        raw_static_gaps=(),
        effective_python_gaps=(),
        surfaces=(
            SurfaceProofV2(
                surface_id=surface.surface_id,
                path="app.py",
                line=2,
                coverage_status="INSUFFICIENT",
                verified_roles=(),
                evidence_refs=(),
                unresolved_reason_codes=("DYNAMIC_DISPATCH_UNRESOLVED",),
            ),
            SurfaceProofV2(
                surface_id=covered.surface_id,
                path="app.py",
                line=9,
                coverage_status="COVERED",
                verified_roles=(),
                evidence_refs=(),
                unresolved_reason_codes=(),
            ),
        ),
        pending_candidate_count=0,
        pending_child_count=0,
    )
    prior_ref = artifacts.put_json(prior.to_json())
    v4_plan = {
        "kind": "simple_surface_enrichment_plan_v4",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope_fingerprint": index.scope_fingerprint,
        "index_hash": index_ref.content_hash,
        "index_ref": index_ref.model_dump(mode="json"),
        "ast_manifest_hash": index.ast_manifest_hash,
        "candidate_inventory_hash": index.candidate_inventory_hash,
        "static_bundle_ref": static_ref.model_dump(mode="json"),
        "expected_parts": [],
        "target_surface_ids": [],
    }
    v4_ref = artifacts.put_json(v4_plan)
    graph = {
        "kind": "simple_surface_evidence_graph_v5",
        "anchor": {"surface_id": surface.surface_id, "path": "app.py", "line": 2},
        "scope_fingerprint": index.scope_fingerprint,
        "index_hash": index_ref.content_hash,
        "ast_manifest_hash": index.ast_manifest_hash,
        "source_files": [{"path": "app.py", "source_sha256": source_hash}],
        "source_lines": [
            {
                "line_id": f"line-{n}",
                "path": "app.py",
                "line": n,
                "text": "return sink(value) # " + "x" * 96,
                "source_sha256": source_hash,
            }
            for n in range(1, line_count + 1)
        ],
        "ast_facts": [],
        "nodes": [],
        "edges": [],
        "paths": [],
        "gaps": [],
        "operational_routes": [
            {
                "route": "/test",
                "module_path": "app",
                "class_symbol": "Handler",
                "config_path": "routes.xml",
                "config_sha256": "1" * 64,
                "parser_path": "app.py",
                "parser_sha256": source_hash,
                "parser_sites": [2],
                "target_path": "app.py",
                "target_sha256": source_hash,
                "launcher_path": "Dockerfile",
                "launcher_sha256": "2" * 64,
            }
        ],
    }
    return {
        "identity": identity,
        "index": index,
        "index_ref": index_ref,
        "prior": prior,
        "prior_ref": prior_ref,
        "v4_plan": v4_plan,
        "v4_ref": v4_ref,
        "progress": {},
        "graphs": {surface.surface_id: graph},
        "child_hashes": {},
    }


def _prepare(case: dict[str, Any]) -> tuple[Any, ...]:
    return prepare_surface_enrichment_v5(
        case["identity"],
        "candidate",
        case["index"],
        case["index_ref"],
        case["v4_ref"],
        case["prior_ref"],
        case["prior"],
        case["progress"],
        case["graphs"],
        v4_plan=case["v4_plan"],
        child_checkpoint_hashes=case["child_hashes"],
    )


def test_only_current_insufficient_surfaces_enter_immutable_plan(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path)
    plan, parts = _prepare(case)
    again, repeated = _prepare(case)

    assert plan["kind"] == "simple_surface_enrichment_plan_v5"
    assert plan["target_surface_ids"] == ["surface-missing"]
    assert {part.surface_id for part in parts} == {"surface-missing"}
    assert plan["v4_plan_ref"] == case["v4_ref"].model_dump(mode="json")
    assert plan["v2_coverage_ref"] == case["prior_ref"].model_dump(mode="json")
    assert plan["targets"][0]["prior_reasons"] == ["DYNAMIC_DISPATCH_UNRESOLVED"]
    assert canonical_bytes(plan) == canonical_bytes(again)
    assert [canonical_bytes(part.payload) for part in parts] == [
        canonical_bytes(part.payload) for part in repeated
    ]


def test_hash_mutation_and_foreign_graph_fail_closed(tmp_path: Path) -> None:
    case = _case(tmp_path)
    case["graphs"]["surface-missing"]["source_files"][0]["source_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="GRAPH_SOURCE_INVALID"):
        _prepare(case)

    case = _case(tmp_path / "fresh")
    case["graphs"]["surface-missing"]["anchor"]["line"] = 99
    with pytest.raises(ValueError, match="GRAPH_SCOPE_INVALID"):
        _prepare(case)

    case = _case(tmp_path / "fresh-again")
    case["v4_plan"]["target_surface_ids"].append("forged")
    with pytest.raises(ValueError, match="V4_PLAN_INVALID"):
        _prepare(case)


def test_whole_item_chunking_preserves_route_and_source_items(tmp_path: Path) -> None:
    case = _case(tmp_path, line_count=900)
    plan, parts = _prepare(case)

    assert len(parts) > 1
    assert all(len(canonical_bytes(part.payload)) <= 65536 for part in parts)
    assert [part.part_index for part in parts] == list(range(len(parts)))
    assert [
        item["value"]["line_id"]
        for part in parts
        for item in part.payload["items"]
        if item["category"] == "source_lines"
    ] == [row["line_id"] for row in case["graphs"]["surface-missing"]["source_lines"]]
    assert [
        item["value"]
        for part in parts
        for item in part.payload["items"]
        if item["category"] == "operational_routes"
    ] == case["graphs"]["surface-missing"]["operational_routes"]
    assert plan["targets"][0]["unavailable_items"] == []
    assert all(
        hashlib.sha256(canonical_bytes(part.payload)).hexdigest() == part.context_hash
        for part in parts
    )


def test_oversized_atomic_item_remains_explicitly_unavailable(tmp_path: Path) -> None:
    case = _case(tmp_path)
    case["graphs"]["surface-missing"]["source_lines"][1]["text"] = "x" * 70000
    plan, parts = _prepare(case)

    assert (
        plan["targets"][0]["unavailable_items"][0]["reason"] == "ATOMIC_ITEM_TOO_LARGE"
    )
    assert "x" * 200 not in str(parts)
    assert all(len(canonical_bytes(part.payload)) <= 65536 for part in parts)


def test_operational_answer_key_fields_never_reach_a_part(tmp_path: Path) -> None:
    case = _case(tmp_path)
    case["graphs"]["surface-missing"]["operational_routes"][0]["evil_path"] = (
        "hidden-correct-answer"
    )

    with pytest.raises(ValueError, match="CONFIG_ANSWER_KEY_FORBIDDEN"):
        _prepare(case)


def test_targets_are_not_limited_to_a_fixed_count(tmp_path: Path) -> None:
    case = _case(tmp_path)
    first_surface = case["index"].surfaces[0]
    first_proof = case["prior"].surfaces[0]
    surfaces = tuple(
        replace(first_surface, surface_id=f"surface-{ordinal}", line=ordinal + 1)
        for ordinal in range(36)
    )
    case["index"] = replace(case["index"], surfaces=surfaces)
    case["index_ref"] = SimpleArtifactRepository(
        tmp_path / "artifacts", case["identity"]
    ).put_json(case["index"].to_json())
    case["prior"] = replace(
        case["prior"],
        index_hash=case["index_ref"].content_hash,
        surfaces=tuple(
            replace(
                first_proof,
                surface_id=surface.surface_id,
                line=surface.line,
            )
            for surface in surfaces
        ),
    )
    case["prior_ref"] = SimpleArtifactRepository(
        tmp_path / "artifacts", case["identity"]
    ).put_json(case["prior"].to_json())
    case["v4_plan"]["index_hash"] = case["index_ref"].content_hash
    case["v4_plan"]["index_ref"] = case["index_ref"].model_dump(mode="json")
    case["v4_ref"] = SimpleArtifactRepository(
        tmp_path / "artifacts", case["identity"]
    ).put_json(case["v4_plan"])
    graph = case["graphs"].pop("surface-missing")
    case["graphs"] = {
        surface.surface_id: {
            **graph,
            "anchor": {
                "surface_id": surface.surface_id,
                "path": surface.path,
                "line": surface.line,
            },
            "index_hash": case["index_ref"].content_hash,
        }
        for surface in surfaces
    }

    plan, parts = _prepare(case)
    assert len(plan["target_surface_ids"]) == 36
    assert len({part.surface_id for part in parts}) == 36


def test_prior_v4_progress_is_bound_not_replayed(tmp_path: Path) -> None:
    case = _case(tmp_path)
    result_ref = SimpleArtifactRepository(
        tmp_path / "artifacts", case["identity"]
    ).put_json({"status": "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"})
    row = SurfaceExplorationProgressRecord(
        surface_id="surface-missing",
        context_id="prior-part",
        status="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
        static_bundle_hash=case["index"].static_bundle_hash,
        index_hash=case["index_ref"].content_hash,
        context_hash="a" * 64,
        source_sha256="b" * 64,
        result_ref=result_ref,
        hypothesis_ids=(),
        proposal_version=4,
    )
    case["progress"][(row.surface_id, row.context_id)] = row
    case["v4_plan"]["expected_parts"] = [
        {
            "surface_id": row.surface_id,
            "context_id": row.context_id,
            "context_hash": row.context_hash,
            "part_index": 0,
            "part_count": 1,
            "source_sha256": row.source_sha256,
        }
    ]
    case["v4_plan"]["target_surface_ids"] = [row.surface_id]
    case["v4_ref"] = SimpleArtifactRepository(
        tmp_path / "artifacts", case["identity"]
    ).put_json(case["v4_plan"])
    plan, _ = _prepare(case)
    assert (
        plan["targets"][0]["prior_progress"][0]["result_hash"]
        == result_ref.content_hash
    )
    assert plan["targets"][0]["prior_progress"][0]["context_id"] == "prior-part"
