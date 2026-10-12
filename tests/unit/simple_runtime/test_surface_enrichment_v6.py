"""An additive successor plan binds the saved v3 proof without rewriting v5."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.surface_coverage_v3 import (
    SurfaceCoverageV3,
    SurfaceProofV3,
)
from sastsimi.simple_runtime.surface_enrichment_v5 import prepare_surface_enrichment_v5
from sastsimi.simple_runtime.surface_evidence_validation_v5 import validate_v5_context
from tests.unit.simple_runtime.test_surface_enrichment_v5 import _case


def _saved_v3_case(tmp_path: Path, *, line_count: int = 3) -> dict[str, Any]:
    case = _case(tmp_path, line_count=line_count)
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", case["identity"])
    v5_plan, old_parts = prepare_surface_enrichment_v5(
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
    v5_ref = artifacts.put_json(v5_plan)
    prior_v2 = case["prior"]
    prior_v3 = SurfaceCoverageV3(
        scope_fingerprint=prior_v2.scope_fingerprint,
        static_bundle_hash=prior_v2.static_bundle_hash,
        ast_manifest_hash=prior_v2.ast_manifest_hash,
        candidate_inventory_hash=prior_v2.candidate_inventory_hash,
        candidate_count=prior_v2.candidate_count,
        index_hash=prior_v2.index_hash,
        original_coverage_ref=prior_v2.original_coverage_ref,
        scope_certificate_ref=prior_v2.scope_certificate_ref,
        prior_v2_ref=case["prior_ref"],
        v5_plan_ref=v5_ref,
        raw_static_gaps=prior_v2.raw_static_gaps,
        effective_python_gaps=prior_v2.effective_python_gaps,
        surfaces=(
            SurfaceProofV3(
                surface_id="surface-missing",
                path="app.py",
                line=2,
                coverage_status="INSUFFICIENT",
                prior_v2_status="INSUFFICIENT",
                review_classification="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
                verified_roles=(),
                evidence_refs=(),
                unresolved_reason_codes=("DYNAMIC_DISPATCH_UNRESOLVED",),
            ),
            SurfaceProofV3(
                surface_id="surface-covered",
                path="app.py",
                line=9,
                coverage_status="COVERED",
                prior_v2_status="COVERED",
                review_classification=None,
                verified_roles=(),
                evidence_refs=(),
                unresolved_reason_codes=(),
            ),
        ),
        pending_candidate_count=0,
        pending_child_count=0,
    )
    v3_ref = artifacts.put_json(prior_v3.to_json())
    graph = deepcopy(case["graphs"]["surface-missing"])
    graph["proof_semantics_revision"] = "v5-source-bound-3"
    return {
        **case,
        "artifacts": artifacts,
        "v5_plan": v5_plan,
        "v5_ref": v5_ref,
        "old_parts": old_parts,
        "prior_v3": prior_v3,
        "v3_ref": v3_ref,
        "successor_graphs": {"surface-missing": graph},
    }


def _prepare(case: dict[str, Any]) -> tuple[dict[str, object], tuple[Any, ...]]:
    from sastsimi.simple_runtime.surface_enrichment_v6 import (
        prepare_surface_enrichment_v6,
    )

    return prepare_surface_enrichment_v6(
        case["identity"],
        "candidate",
        case["index"],
        case["index_ref"],
        case["v3_ref"],
        case["prior_v3"],
        case["v5_ref"],
        case["v5_plan"],
        case["successor_graphs"],
        required_graph_revision="v5-source-bound-3",
    )


def test_successor_targets_only_current_insufficient_and_keeps_v5_bytes(
    tmp_path: Path,
) -> None:
    case = _saved_v3_case(tmp_path)
    old_plan_bytes = canonical_bytes(case["v5_plan"])

    plan, parts = _prepare(case)

    assert plan["kind"] == "simple_surface_enrichment_plan_v6"
    assert plan["target_surface_ids"] == ["surface-missing"]
    assert plan["prior_v3_coverage_ref"] == case["v3_ref"].model_dump(mode="json")
    assert plan["prior_v5_plan_ref"] == case["v5_ref"].model_dump(mode="json")
    assert len(parts) == 1
    assert parts[0].context_id != case["old_parts"][0].context_id
    assert parts[0].payload["kind"] == "simple_surface_context_v5"
    assert parts[0].payload["plan_binding_hash"] == plan["plan_binding_hash"]
    assert len(canonical_bytes(parts[0].payload)) <= 64 * 1024
    validate_v5_context(
        {
            "context_payload": parts[0].payload,
            "graph_payload": case["successor_graphs"]["surface-missing"],
            "context_hash": parts[0].context_hash,
            "context_id": parts[0].context_id,
        }
    )
    assert canonical_bytes(case["v5_plan"]) == old_plan_bytes
    assert canonical_bytes(plan) == canonical_bytes(_prepare(case)[0])


@pytest.mark.parametrize(
    "change",
    [
        "old_graph_revision",
        "changed_source_file",
        "changed_source_line",
    ],
)
def test_successor_rejects_stale_or_changed_graph(tmp_path: Path, change: str) -> None:
    case = _saved_v3_case(tmp_path)
    graph = case["successor_graphs"]["surface-missing"]
    if change == "old_graph_revision":
        graph["proof_semantics_revision"] = "v5-source-bound-2"
    elif change == "changed_source_file":
        graph["source_files"][0]["source_sha256"] = "0" * 64
    else:
        graph["source_lines"][0]["source_sha256"] = "0" * 64

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V6"):
        _prepare(case)


def test_successor_rejects_changed_predecessor_even_with_exact_new_ref(
    tmp_path: Path,
) -> None:
    case = _saved_v3_case(tmp_path)
    altered = replace(case["prior_v3"], pending_child_count=1)
    case["prior_v3"] = altered
    case["v3_ref"] = case["artifacts"].put_json(altered.to_json())

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V6"):
        _prepare(case)


def test_successor_splits_whole_items_with_every_part_bounded(tmp_path: Path) -> None:
    case = _saved_v3_case(tmp_path, line_count=700)

    plan, parts = _prepare(case)

    assert len(parts) > 1
    assert [part.part_index for part in parts] == list(range(len(parts)))
    assert all(part.part_count == len(parts) for part in parts)
    assert all(len(canonical_bytes(part.payload)) <= 64 * 1024 for part in parts)
    targets = plan["targets"]
    assert isinstance(targets, list)
    target = targets[0]
    assert isinstance(target, dict)
    assert target["unavailable_items"] == []
    assert sum(len(part.payload["items"]) for part in parts) == target["item_count"]
