"""The v9 plan binds every review part to the immutable v8 parent."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.attack_surfaces import SurfaceIndex
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.surface_applicability_v9 import assess_optional_analyzers
from sastsimi.simple_runtime.surface_coverage_v2 import _ref
from sastsimi.simple_runtime.surface_coverage_v6 import (
    SurfaceCoverageV6,
    SurfaceProofV6,
)
from sastsimi.simple_runtime.surface_enrichment_v9 import (
    V9Part,
    _role_directory,
    prepare_surface_enrichment_v9,
)
from sastsimi.simple_runtime.surface_path_proof_v9 import certify_surface_paths
from tests.unit.simple_runtime.test_surface_path_proof_v9 import (
    SOURCE,
    _fixture,
    _request_fixture,
)


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def connected_inputs(
    tmp_path: Path,
    *,
    alternate: bool = False,
    alternate_gap: bool = True,
    static_gap: bool = False,
) -> dict[str, Any]:
    if alternate:
        second_route = (
            "@app.route('/second')\n"
            "def second():\n"
            "    key = request.args['key']\n"
            "    return run_query(key)\n\n"
        )
        source = SOURCE.replace(
            "def run_query(key):", second_route + "def run_query(key):"
        )
    else:
        source = SOURCE
    index, surface, graph = _fixture(tmp_path, source)
    if alternate and alternate_gap:
        paths = cast(list[dict[str, object]], graph["paths"])
        paths[1]["blocking_gaps"] = ["DYNAMIC_CALL"]
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id=index.workspace_id,
        commit_id=index.commit_id,
        hypothesis_id=None,
    )
    index_ref = _ref(identity, _digest(index.to_json()))
    v8_plan: dict[str, object] = {
        "kind": "simple_surface_enrichment_plan_v8",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope": "app.py",
        "scope_fingerprint": index.scope_fingerprint,
        "static_bundle_hash": index.static_bundle_hash,
        "ast_manifest_hash": index.ast_manifest_hash,
        "candidate_inventory_hash": index.candidate_inventory_hash,
        "candidate_count": index.candidate_count,
        "index_hash": index_ref.content_hash,
        "index_ref": index_ref.model_dump(mode="json"),
        "expected_parts": [],
        "targets": [],
    }
    v8_plan_ref = _ref(identity, _digest(v8_plan))
    parent = SurfaceCoverageV6(
        scope_fingerprint=index.scope_fingerprint,
        static_bundle_hash=index.static_bundle_hash,
        ast_manifest_hash=index.ast_manifest_hash,
        candidate_inventory_hash=index.candidate_inventory_hash,
        candidate_count=index.candidate_count,
        index_hash=index_ref.content_hash,
        original_coverage_ref=_ref(identity, "1" * 64),
        scope_certificate_ref=_ref(identity, "2" * 64),
        prior_v5_ref=_ref(identity, "3" * 64),
        prior_v7_plan_ref=_ref(identity, "4" * 64),
        v8_plan_ref=v8_plan_ref,
        prior_progress_hash="5" * 64,
        missing_v7_parts=(),
        raw_static_gaps=(),
        effective_python_gaps=(
            ({"path": "app.py", "reason": "STATIC_RULE_ERROR"},) if static_gap else ()
        ),
        surfaces=(
            SurfaceProofV6(
                surface_id=surface.surface_id,
                path=surface.path,
                line=surface.line,
                coverage_status="INSUFFICIENT",
                prior_v5_status="INSUFFICIENT",
                review_classification="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
                verified_roles=(),
                evidence_refs=(),
                unresolved_reason_codes=(
                    "CONNECTED_ROLE_PROOF_MISSING",
                    "UNREVIEWED_RELEVANT_PATH",
                    "UNRESOLVED_RELEVANT_GRAPH_GAP",
                ),
                completed_inconclusive_children=(),
            ),
        ),
        pending_candidate_count=0,
        pending_child_count=0,
    )
    applicability = assess_optional_analyzers(index, tmp_path)
    certificate = certify_surface_paths(index, surface, graph, applicability, tmp_path)
    assert certificate.source_complete != (alternate and alternate_gap)
    return {
        "identity": identity,
        "scope": "app.py",
        "index": index,
        "index_ref": index_ref,
        "prior_v8_plan_ref": v8_plan_ref,
        "prior_v8_plan": v8_plan,
        "prior_v8_coverage_ref": _ref(identity, _digest(parent.to_json())),
        "prior_v8_coverage": parent,
        "prior_v8_progress_hash": "9" * 64,
        "applicability": applicability,
        "intrinsic_proofs": {},
        "path_certificates": {surface.surface_id: certificate},
        "graphs": {surface.surface_id: graph},
        "workspace": tmp_path,
    }


def test_v9_plan_pins_v8_parent_and_every_ordered_source_part(tmp_path: Path) -> None:
    inputs = connected_inputs(tmp_path)

    plan, parts = prepare_surface_enrichment_v9(**inputs)

    cert = inputs["path_certificates"]["surface-1"]
    assert plan["kind"] == "simple_surface_enrichment_plan_v9"
    assert plan["prior_v8_plan_ref"] == inputs["prior_v8_plan_ref"].model_dump(
        mode="json"
    )
    assert plan["prior_v8_coverage_ref"] == inputs["prior_v8_coverage_ref"].model_dump(
        mode="json"
    )
    assert plan["prior_v8_progress_hash"] == "9" * 64
    assert len(parts) == len(cert.context_parts) > 0
    assert all(isinstance(part, V9Part) for part in parts)
    assert [part.payload["context_part"] for part in parts] == [
        context.to_json() for context in cert.context_parts
    ]
    expected_parts = cast(list[dict[str, object]], plan["expected_parts"])
    assert [part.context_id for part in parts] == [
        row["context_id"] for row in expected_parts
    ]
    assert all(part.payload["source_excerpt"] for part in parts)
    directory = [
        entry
        for part in parts
        for entry in cast(list[dict[str, object]], part.payload["role_directory"])
    ]
    assert {(entry["role"], entry["location"]) for entry in directory} >= {
        ("ENTRY", "app.py:3"),
        ("TRUST_BOUNDARY", "app.py:5"),
        ("ANCHOR", "app.py:9"),
    }


def test_v9_plan_rejects_tampered_parent_or_source_binding(tmp_path: Path) -> None:
    inputs = connected_inputs(tmp_path)
    parent = inputs["prior_v8_coverage"]
    inputs["prior_v8_coverage"] = replace(
        parent, surfaces=(replace(parent.surfaces[0], surface_id="other"),)
    )
    with pytest.raises(ValueError, match="V9_PARENT"):
        prepare_surface_enrichment_v9(**inputs)

    (tmp_path / "second").mkdir()
    inputs = connected_inputs(tmp_path / "second")
    index: SurfaceIndex = inputs["index"]
    inputs["index"] = replace(index, ast_source_hashes=(("app.py", "0" * 64),))
    with pytest.raises(ValueError, match="V9_"):
        prepare_surface_enrichment_v9(**inputs)


def test_request_entry_directory_uses_new_verified_downstream_path(
    tmp_path: Path,
) -> None:
    index, surface, _sink, graph = _request_fixture(tmp_path)
    applicability = assess_optional_analyzers(index, tmp_path)
    certificate = certify_surface_paths(index, surface, graph, applicability, tmp_path)
    assert certificate.source_complete

    directory = [
        row
        for part in certificate.context_parts
        for row in _role_directory(graph, surface, part, certificate)
    ]

    assert {row["role"] for row in directory} >= {
        "ENTRY",
        "TRUST_BOUNDARY",
        "ANCHOR",
    }
    assert {row["path_id"] for row in directory} == set(certificate.path_ids)
