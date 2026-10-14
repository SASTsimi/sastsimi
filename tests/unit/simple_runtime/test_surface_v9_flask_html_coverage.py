"""A pinned Flask HTML response can close review gaps, not prove safety."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.surface_applicability_v9 import assess_optional_analyzers
from sastsimi.simple_runtime.surface_coverage_v2 import _ref
from sastsimi.simple_runtime.surface_coverage_v6 import (
    SurfaceCoverageV6,
    SurfaceProofV6,
)
from sastsimi.simple_runtime.surface_coverage_v7 import _connected_review
from sastsimi.simple_runtime.surface_enrichment_v9 import (
    prepare_surface_enrichment_v9,
)
from sastsimi.simple_runtime.surface_path_proof_v9 import certify_surface_paths
from tests.unit.simple_runtime.test_surface_coverage_v7 import (
    _evaluate,
    _reviewed_parts,
)
from tests.unit.simple_runtime.test_surface_path_proof_v9 import (
    ESCAPED_HTML_SOURCE,
    HTML_SOURCE,
    _html_request_fixture,
)


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _html_inputs(
    tmp_path: Path,
    *,
    source: str = HTML_SOURCE,
    anchor_line: int = 4,
) -> dict[str, Any]:
    index, surface, graph = _html_request_fixture(
        tmp_path, source, anchor_line=anchor_line
    )
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
        effective_python_gaps=(),
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


@pytest.mark.parametrize("anchor_line", [4, 6])
def test_html_route_and_request_anchors_need_all_reviewed_source_parts(
    tmp_path: Path, anchor_line: int
) -> None:
    """Removing one part must demote a genuinely connected entry to incomplete."""

    inputs = _html_inputs(tmp_path, anchor_line=anchor_line)
    certificate = next(iter(inputs["path_certificates"].values()))
    assert certificate.source_complete
    plan, parts = prepare_surface_enrichment_v9(**inputs)
    assert parts
    reviewed = _reviewed_parts(parts, certificate.path_ids[0])

    complete = _evaluate(inputs, plan, reviewed)
    assert complete.complete
    assert complete.surfaces[0].coverage_status == "COVERED"
    assert complete.surfaces[0].proof_kind == "CONNECTED_PATHS"
    assert complete.surfaces[0].reviewed_path_ids == certificate.path_ids

    omitted = dict(reviewed)
    omitted.pop(next(iter(omitted)))
    incomplete = _evaluate(inputs, plan, omitted)
    assert not incomplete.complete
    assert incomplete.surfaces[0].coverage_status == "INSUFFICIENT"


def test_observed_html_escape_is_neither_safe_nor_confirmed_verdict(
    tmp_path: Path,
) -> None:
    """An escape call remains a source fact even when every path was reviewed."""

    inputs = _html_inputs(tmp_path, source=ESCAPED_HTML_SOURCE)
    certificate = next(iter(inputs["path_certificates"].values()))
    assert certificate.source_complete
    assert any(
        step.role == "ESCAPE_CALL_OBSERVED"
        for path in certificate.downstream_paths
        for step in path.steps
    )
    plan, parts = prepare_surface_enrichment_v9(**inputs)
    reviewed = _reviewed_parts(parts, certificate.path_ids[0])

    result = _evaluate(inputs, plan, reviewed)

    assert result.complete
    assert result.surfaces[0].proof_kind == "CONNECTED_PATHS"
    assert result.surfaces[0].review_classification == (
        "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
    )
    assert not any(
        "SAFE" in str(role.get("role", ""))
        for role in result.surfaces[0].verified_roles
    )


def test_changed_source_cannot_reuse_completed_html_review(tmp_path: Path) -> None:
    """A source change after planning invalidates the old pinned certificate."""

    inputs = _html_inputs(tmp_path)
    certificate = next(iter(inputs["path_certificates"].values()))
    plan, parts = prepare_surface_enrichment_v9(**inputs)
    reviewed = _reviewed_parts(parts, certificate.path_ids[0])
    (tmp_path / "app.py").write_text("def changed():\n    pass\n", encoding="utf-8")

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V7_PLAN_INVALID"):
        _evaluate(inputs, plan, reviewed)


def test_extra_unresolved_html_path_is_not_a_complete_review(
    tmp_path: Path,
) -> None:
    """Reviewing one path cannot erase an additional unresolved path."""

    inputs = _html_inputs(tmp_path)
    certificate = next(iter(inputs["path_certificates"].values()))
    _plan, parts = prepare_surface_enrichment_v9(**inputs)
    reviewed = _reviewed_parts(parts, certificate.path_ids[0])
    unresolved = replace(
        certificate,
        path_ids=(*certificate.path_ids, "another-unresolved-path"),
        unresolved_path_ids=("another-unresolved-path",),
        source_complete=False,
    )

    ready, reasons, _roles, reviewed_ids, _contexts = _connected_review(
        certificate.surface_id, unresolved, parts, reviewed
    )

    assert not ready
    assert reviewed_ids == certificate.path_ids
    assert "UNREVIEWED_RELEVANT_PATH" in reasons
    assert "SURFACE_SOURCE_UNAVAILABLE" in reasons


def test_forged_role_citation_cannot_complete_html_path(tmp_path: Path) -> None:
    """The review must cite the exact pinned path role, not just its name."""

    inputs = _html_inputs(tmp_path)
    certificate = next(iter(inputs["path_certificates"].values()))
    plan, parts = prepare_surface_enrichment_v9(**inputs)
    reviewed = _reviewed_parts(parts, certificate.path_ids[0])
    target_key = next(key for key, part in reviewed.items() if part.role_citations)
    target = reviewed[target_key]
    forged = dict(reviewed)
    forged[target_key] = replace(
        target,
        role_citations=(
            replace(target.role_citations[0], location="app.py:999"),
            *target.role_citations[1:],
        ),
    )

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V7_REVIEW_INVALID"):
        _evaluate(inputs, plan, forged)
