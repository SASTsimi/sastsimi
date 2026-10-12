"""A v8 terminal is projected only from its exact proof-version six verifier."""

from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.simple_runtime.surface_coverage_v6 import (
    SurfaceCoverageV6,
    SurfaceProofV6,
)
from sastsimi.simple_runtime.surface_proof_read import (
    verified_surface_coverage_counts,
)
from tests.unit.simple_runtime.test_surface_coverage_v5 import (
    _evaluate,
    _save_v7_part,
    _v7_case,
)


def test_read_side_uses_v6_verifier_and_discloses_local_only_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = _v7_case(tmp_path)
    _save_v7_part(data)
    _save_v7_part(data, part_index=1)
    parent = _evaluate(data)
    case = data["case"]
    parent_ref = case.artifacts.put_json(parent.to_json())
    plan_ref = case.artifacts.put_json({"kind": "simple_surface_enrichment_plan_v8"})
    rows = tuple(
        SurfaceProofV6(
            surface_id=row.surface_id,
            path=row.path,
            line=row.line,
            coverage_status="COVERED" if number == 0 else "INSUFFICIENT",
            prior_v5_status=row.coverage_status,
            review_classification=row.review_classification,
            verified_roles=row.verified_roles,
            evidence_refs=row.evidence_refs,
            unresolved_reason_codes=(
                () if number == 0 else ("LOCAL_ONLY_ATTACK_PATH_UNVERIFIED",)
            ),
            completed_inconclusive_children=row.completed_inconclusive_children,
        )
        for number, row in enumerate(parent.surfaces)
    )
    proof = SurfaceCoverageV6(
        scope_fingerprint=parent.scope_fingerprint,
        static_bundle_hash=parent.static_bundle_hash,
        ast_manifest_hash=parent.ast_manifest_hash,
        candidate_inventory_hash=parent.candidate_inventory_hash,
        candidate_count=parent.candidate_count,
        index_hash=parent.index_hash,
        original_coverage_ref=parent.original_coverage_ref,
        scope_certificate_ref=parent.scope_certificate_ref,
        prior_v5_ref=parent_ref,
        prior_v7_plan_ref=data["v7_plan_ref"],
        v8_plan_ref=plan_ref,
        prior_progress_hash="f" * 64,
        missing_v7_parts=(),
        raw_static_gaps=parent.raw_static_gaps,
        effective_python_gaps=parent.effective_python_gaps,
        surfaces=rows,
        pending_candidate_count=0,
        pending_child_count=0,
    )
    proof_ref = case.artifacts.put_json(proof.to_json())
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.candidate_terminal is not None
    terminal = run.candidate_terminal.model_copy(
        update={
            "status": "PARTIAL",
            "surface_proof_version": 6,
            "surface_index_hash": proof.index_hash,
            "surface_coverage_hash": proof_ref.content_hash,
            "scope_certificate_hash": proof.scope_certificate_ref.content_hash,
            "surface_counts": {"COVERED": 1, "UNCOVERED": 0, "INSUFFICIENT": 1},
            "pending_child_count": 0,
        }
    )
    calls: list[str] = []

    def verified(*_args: object) -> SurfaceCoverageV6:
        calls.append("v6")
        return proof

    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_proof_read.verified_saved_coverage_v6",
        verified,
        raising=False,
    )
    observed = verified_surface_coverage_counts(
        proof.to_json(),
        case.index,
        terminal,
        artifacts=case.artifacts,
        coverage_ref=proof_ref,
        store=case.store,
    )

    assert calls == ["v6"]
    assert observed is not None
    assert observed["COVERED"] == 1
    assert observed["INSUFFICIENT"] == 1
    assert observed["REASON_CODE_LOCAL_ONLY_ATTACK_PATH_UNVERIFIED"] == 1
    assert observed["UNRESOLVED_REASON_COUNT"] == 1
    assert observed["COMPLETED_INCONCLUSIVE_CHILD_COUNT"] == 0

    altered = {**proof.to_json(), "complete": True}
    assert (
        verified_surface_coverage_counts(
            altered,
            case.index,
            terminal,
            artifacts=case.artifacts,
            coverage_ref=proof_ref,
            store=case.store,
        )
        is None
    )
