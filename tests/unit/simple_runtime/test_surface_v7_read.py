"""Proof-version five is counted only after its own verifier accepts it."""

from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.simple_runtime.surface_proof_read import (
    verified_surface_coverage_counts,
)
from tests.unit.simple_runtime.test_surface_coverage_v5 import (
    _evaluate,
    _save_v7_part,
    _v7_case,
)


def test_read_side_dispatches_v7_without_reinterpreting_v4(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = _v7_case(tmp_path)
    _save_v7_part(data)
    proof = _evaluate(data)
    case = data["case"]
    proof_ref = case.artifacts.put_json(proof.to_json())
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.candidate_terminal is not None
    counts = {
        status: sum(row.coverage_status == status for row in proof.surfaces)
        for status in ("COVERED", "UNCOVERED", "INSUFFICIENT")
    }
    terminal = run.candidate_terminal.model_copy(
        update={
            "status": "COMPLETE" if proof.complete else "PARTIAL",
            "surface_proof_version": 5,
            "surface_index_hash": proof.index_hash,
            "surface_coverage_hash": proof_ref.content_hash,
            "scope_certificate_hash": proof.scope_certificate_ref.content_hash,
            "surface_counts": counts,
            "pending_child_count": proof.pending_child_count,
        }
    )
    calls: list[str] = []

    def verified(*_args: object) -> object:
        calls.append("v5")
        return proof

    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_proof_read.verified_saved_coverage_v5",
        verified,
    )
    observed = verified_surface_coverage_counts(
        proof.to_json(),
        case.index,
        terminal,
        artifacts=case.artifacts,
        coverage_ref=proof_ref,
        store=case.store,
    )

    assert calls == ["v5"]
    assert observed is not None
    assert observed["COVERED"] == counts["COVERED"]
    assert observed["UNRESOLVED_REASON_COUNT"] == sum(
        len(row.unresolved_reason_codes) for row in proof.surfaces
    )
    assert terminal.status == "PARTIAL"

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
