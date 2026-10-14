"""Dashboard projection must pass v9 proofs through the verified read path."""

from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.dashboard.query import DashboardQuery
from sastsimi.reporting.coverage_disclosure import CoverageDisclosure
from sastsimi.simple_runtime import stages
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.stages import ReporterStage
from tests.unit.progress.test_surface_v4_projection import _saved_v4_case


def test_v9_dashboard_uses_verified_counts_and_shows_unresolved_reasons(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data, checkpoint, terminal = _saved_v4_case(tmp_path, old_hold=True)
    case = data["case"]
    terminal = terminal.model_copy(update={"surface_proof_version": 7})
    run = case.store.require_analysis_run(case.identity.analysis_id)
    run = run.model_copy(update={"candidate_terminal": terminal})
    case.store.save_analysis_run(run)
    observed: list[object] = []

    def verified(
        _proof: object, _index: object, _terminal: object, **kwargs: object
    ) -> dict[str, int]:
        observed.append(kwargs.get("store"))
        return {
            "COVERED": 1,
            "UNCOVERED": 0,
            "INSUFFICIENT": 1,
            "UNRESOLVED_REASON_COUNT": 1,
            "REASON_CODE_CHILD_HOLD": 1,
            "RAW_STATIC_GAP_COUNT": 0,
            "EFFECTIVE_PYTHON_GAP_COUNT": 0,
        }

    monkeypatch.setattr(
        "sastsimi.dashboard.query.verified_surface_coverage_counts", verified
    )
    dashboard = DashboardQuery(tmp_path / "data")
    counts, _ = dashboard._surface_metrics(run, [checkpoint])
    assert counts is not None and counts["REASON_CODE_CHILD_HOLD"] == 1
    assert observed and observed[0] is not None
    reason_count, preview = dashboard._surface_unresolved_preview(
        run, [checkpoint], counts
    )
    assert reason_count == 1
    assert preview[0]["reason"] == "CHILD_HOLD"


def test_v9_report_discloses_only_verified_partial_counts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data, _checkpoint, terminal = _saved_v4_case(tmp_path, old_hold=True)
    case = data["case"]
    terminal = terminal.model_copy(update={"surface_proof_version": 7})
    run = case.store.require_analysis_run(case.identity.analysis_id)
    case.store.save_analysis_run(
        run.model_copy(update={"candidate_terminal": terminal})
    )
    assert run.static_coverage_ref is not None
    disclosure = CoverageDisclosure(
        ref=run.static_coverage_ref,
        fingerprint="f" * 64,
        expected_count=1,
        verified_count=1,
        gap_count=0,
        unsupported_count=0,
        gap_reasons=(),
        unsupported_reasons=(),
        engine_errors=(),
    )
    monkeypatch.setattr(stages, "coverage_disclosure", lambda *_a, **_k: disclosure)
    monkeypatch.setattr(
        stages,
        "verified_surface_coverage_counts",
        lambda *_a, **_k: {
            "COVERED": 1,
            "UNCOVERED": 0,
            "INSUFFICIENT": 1,
            "RAW_STATIC_GAP_COUNT": 0,
            "EFFECTIVE_PYTHON_GAP_COUNT": 0,
            "UNRESOLVED_REASON_COUNT": 1,
            "COMPLETED_INCONCLUSIVE_CHILD_COUNT": 0,
            "REASON_CODE_CHILD_HOLD": 1,
        },
    )
    child_identity = case.identity.model_copy(update={"hypothesis_id": "child-1"})
    reporter = object.__new__(ReporterStage)
    reporter._store = case.store
    reporter._artifacts = SimpleArtifactRepository(
        tmp_path / "data", child_identity, create_dirs=False
    )
    checkpoint = StageCheckpoint(
        identity=child_identity,
        stage=SimpleStage.REPORT_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(),
    )
    observed = reporter._coverage(checkpoint)
    assert observed is not None
    assert observed.surface_proof_version == 7
    assert observed.surface_insufficient_count == 1
    assert observed.analysis_status == "PARTIAL"
