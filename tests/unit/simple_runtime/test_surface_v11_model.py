"""A v11 terminal and plan must remain bound to a v10 predecessor."""

from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import SimpleAnalysisRun
from tests.unit.simple_runtime.test_surface_v8_store_pin import _v9_pin_case


def test_v11_run_model_round_trips_without_changing_parent_refs(tmp_path: Path) -> None:
    _store, identity, run, v9_ref, _ = _v9_pin_case(tmp_path)
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    v10_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v10"})
    v11_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v11"})
    assert run.candidate_terminal is not None
    successor = run.model_copy(
        update={
            "surface_enrichment_v9_plan_ref": v9_ref,
            "surface_enrichment_v10_plan_ref": v10_ref,
            "surface_enrichment_v11_plan_ref": v11_ref,
            "candidate_terminal": run.candidate_terminal.model_copy(
                update={"surface_proof_version": 9}
            ),
        }
    )

    restored = SimpleAnalysisRun.model_validate_json(successor.model_dump_json())

    assert restored.surface_enrichment_v9_plan_ref == v9_ref
    assert restored.surface_enrichment_v10_plan_ref == v10_ref
    assert restored.surface_enrichment_v11_plan_ref == v11_ref
    assert restored.candidate_terminal is not None
    assert restored.candidate_terminal.surface_proof_version == 9


def test_v11_plan_without_v10_predecessor_is_rejected(tmp_path: Path) -> None:
    _store, identity, run, v9_ref, _ = _v9_pin_case(tmp_path)
    ref = SimpleArtifactRepository(tmp_path / "data", identity).put_json(
        {"kind": "simple_surface_enrichment_plan_v11"}
    )

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V11_STATE_UNBOUND"):
        SimpleAnalysisRun.model_validate_json(
            run.model_copy(
                update={
                    "surface_enrichment_v9_plan_ref": v9_ref,
                    "surface_enrichment_v11_plan_ref": ref,
                }
            ).model_dump_json()
        )


def test_v11_terminal_without_plan_is_rejected(tmp_path: Path) -> None:
    _store, identity, run, v9_ref, _ = _v9_pin_case(tmp_path)
    v10_ref = SimpleArtifactRepository(tmp_path / "data", identity).put_json(
        {"kind": "simple_surface_enrichment_plan_v10"}
    )
    assert run.candidate_terminal is not None

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V11_STATE_UNBOUND"):
        SimpleAnalysisRun.model_validate_json(
            run.model_copy(
                update={
                    "surface_enrichment_v9_plan_ref": v9_ref,
                    "surface_enrichment_v10_plan_ref": v10_ref,
                    "candidate_terminal": run.candidate_terminal.model_copy(
                        update={"surface_proof_version": 9}
                    ),
                }
            ).model_dump_json()
        )
