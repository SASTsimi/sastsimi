"""V11 successor proof must be the only source of visible coverage claims."""

from __future__ import annotations

from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.dashboard.query import DashboardQuery
from sastsimi.interfaces.cli.public import emit_public
from sastsimi.progress.projector import ProgressProjector
from sastsimi.reporting.bilingual_bundle import coverage_report_lines
from sastsimi.reporting.coverage_disclosure import CoverageDisclosure
from sastsimi.simple_runtime import stages
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.report_currentness import (
    candidate_report_currentness_blocked,
)
from sastsimi.simple_runtime.runner import StageFailed
from sastsimi.simple_runtime.stages import ReporterStage
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_proof_read import (
    verified_surface_coverage_counts,
)
from tests.unit.progress.test_surface_v4_projection import _saved_v4_case
from tests.unit.simple_runtime.test_surface_v11_read import _saved_v11_empty_case


def test_proof9_counts_come_from_independent_saved_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Disabling V11 replay must make a forged successor count invisible."""

    case = _saved_v11_empty_case(tmp_path, monkeypatch)
    counts = verified_surface_coverage_counts(
        case["v11_coverage"].to_json(),
        case["index"],
        case["v11_terminal"],
        artifacts=case["artifacts"],
        coverage_ref=case["v11_coverage_ref"],
        store=cast(SimpleCheckpointStore, case["store"]),
    )
    assert counts is not None
    assert counts["COVERED"] == 0
    assert counts["INSUFFICIENT"] == 1
    assert counts["CHILD_REVALIDATION_RESOLVED_COUNT"] == 0
    assert counts["CHILD_REVALIDATION_PENDING_COUNT"] == 0
    assert counts["CHILD_REVALIDATION_STILL_HOLD_COUNT"] == 0
    assert counts["CHILD_REVALIDATION_ERROR_COUNT"] == 0
    assert (
        verified_surface_coverage_counts(
            {**case["v11_coverage"].to_json(), "complete": True},
            case["index"],
            case["v11_terminal"],
            artifacts=case["artifacts"],
            coverage_ref=case["v11_coverage_ref"],
            store=cast(SimpleCheckpointStore, case["store"]),
        )
        is None
    )


def test_pinned_v11_withholds_v10_reports_even_with_active_lease(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An old report is historical while the successor is not certified."""

    case = _saved_v11_empty_case(tmp_path, monkeypatch)
    run = cast(SimpleAnalysisRun, case["store"].run)
    old = run.model_copy(update={"candidate_terminal": case["v10_terminal"]})
    monkeypatch.setattr(
        "sastsimi.simple_runtime.report_currentness.analysis_run_lease_active",
        lambda *_args: True,
    )
    assert candidate_report_currentness_blocked(
        old,
        (),
        data_dir=tmp_path / "data",
        store=cast(SimpleCheckpointStore, case["store"]),
    )


def test_bilingual_report_separates_child_revalidation_from_surface_coverage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A resolved child count is not a finding count or whole-scan completion."""

    case = _saved_v11_empty_case(tmp_path, monkeypatch)
    disclosure = CoverageDisclosure(
        ref=case["v11_coverage_ref"],
        fingerprint="f" * 64,
        expected_count=2,
        verified_count=2,
        gap_count=0,
        unsupported_count=0,
        gap_reasons=(),
        unsupported_reasons=(),
        engine_errors=(),
        analysis_status="PARTIAL",
        surface_proof_version=9,
        surface_child_resolved_count=1,
        surface_child_pending_count=2,
        surface_child_still_hold_count=3,
        surface_child_error_count=4,
    )
    english = "\n".join(coverage_report_lines(disclosure, korean=False))
    korean = "\n".join(coverage_report_lines(disclosure, korean=True))
    assert (
        "Child revalidation: resolved 1 · pending 2 · still HOLD 3 · error 4" in english
    )
    assert "자식 근거 재검증: 해결 1 · 대기 2 · HOLD 유지 3 · 오류 4" in korean
    assert "PARTIAL" in english and "PARTIAL" in korean


def test_reporter_refuses_old_surface_proof_while_v11_is_pinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A new report must not copy old V10 coverage during revalidation."""

    data, _checkpoint, _terminal = _saved_v4_case(tmp_path)
    case = data["case"]
    run = case.store.require_analysis_run(case.identity.analysis_id)
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
    pinned = run.model_copy(
        update={
            "surface_enrichment_v11_plan_ref": run.static_coverage_ref,
            "surface_enrichment_status": "RUNNING",
        }
    )
    monkeypatch.setattr(case.store, "require_analysis_run", lambda *_a: pinned)
    child = case.identity.model_copy(update={"hypothesis_id": "child-1"})
    reporter = object.__new__(ReporterStage)
    reporter._store = case.store
    reporter._artifacts = SimpleArtifactRepository(
        tmp_path / "data", child, create_dirs=False
    )
    checkpoint = StageCheckpoint(
        identity=child,
        stage=SimpleStage.REPORT_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(),
    )
    with pytest.raises(StageFailed) as error:
        reporter._coverage(checkpoint)
    assert error.value.failure.code == "REPORT_SURFACE_PROOF_UNVERIFIED"


def test_progress_separates_v11_child_obligations_from_surface_completion(
    tmp_path: Path,
) -> None:
    """A child HOLD is visible without being counted as a completed surface."""

    data, _checkpoint, terminal = _saved_v4_case(tmp_path, old_hold=True)
    case = data["case"]
    terminal = terminal.model_copy(update={"surface_proof_version": 9})
    snapshot = ProgressProjector(case.store).snapshot(
        case.identity.analysis_id,
        candidate_pipeline_version=2,
        candidate_counts={},
        candidate_deep_counts={},
        candidate_terminal=terminal,
        candidate_bundle_hash=case.index.static_bundle_hash,
        candidate_scope_fingerprint=case.index.scope_fingerprint,
        surface_counts={
            "TOTAL": 2,
            "CONTEXT_RECORDS": 1,
            "COVERED": 1,
            "UNCOVERED": 0,
            "INSUFFICIENT": 1,
            "RAW_STATIC_GAP_COUNT": 0,
            "EFFECTIVE_PYTHON_GAP_COUNT": 0,
            "UNRESOLVED_REASON_COUNT": 1,
            "REASON_CODE_CHILD_HOLD": 1,
            "CHILD_REVALIDATION_RESOLVED_COUNT": 0,
            "CHILD_REVALIDATION_PENDING_COUNT": 0,
            "CHILD_REVALIDATION_STILL_HOLD_COUNT": 1,
            "CHILD_REVALIDATION_ERROR_COUNT": 0,
        },
        surface_index_hash=case.index_ref.content_hash,
    )
    assert snapshot.status != "COMPLETE"
    assert snapshot.phase_counts["surface"]["completed"] == 1
    assert snapshot.phase_counts["surface"]["child_revalidation_still_hold"] == 1
    assert snapshot.phase_counts["surface"]["proof_version"] == 9


def test_dashboard_v11_requires_verified_reader_and_keeps_reason_preview(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A proof-9 dashboard must provide the read-only store to replay the plan."""

    data, checkpoint, terminal = _saved_v4_case(tmp_path, old_hold=True)
    case = data["case"]
    run = case.store.require_analysis_run(case.identity.analysis_id).model_copy(
        update={
            "candidate_terminal": terminal.model_copy(
                update={"surface_proof_version": 9}
            )
        }
    )
    seen: list[object] = []

    def verified(
        _proof: object, _index: object, _terminal: object, **kwargs: object
    ) -> dict[str, int]:
        seen.append(kwargs.get("store"))
        return {
            "COVERED": 1,
            "UNCOVERED": 0,
            "INSUFFICIENT": 1,
            "UNRESOLVED_REASON_COUNT": 1,
            "REASON_CODE_CHILD_HOLD": 1,
            "RAW_STATIC_GAP_COUNT": 0,
            "EFFECTIVE_PYTHON_GAP_COUNT": 0,
            "CHILD_REVALIDATION_RESOLVED_COUNT": 0,
            "CHILD_REVALIDATION_PENDING_COUNT": 0,
            "CHILD_REVALIDATION_STILL_HOLD_COUNT": 1,
            "CHILD_REVALIDATION_ERROR_COUNT": 0,
        }

    monkeypatch.setattr(
        "sastsimi.dashboard.query.verified_surface_coverage_counts", verified
    )
    dashboard = DashboardQuery(tmp_path / "data")
    counts, _ = dashboard._surface_metrics(run, [checkpoint])
    assert seen and seen[0] is not None
    assert counts is not None and counts["CHILD_REVALIDATION_STILL_HOLD_COUNT"] == 1
    total, preview = dashboard._surface_unresolved_preview(run, [checkpoint], counts)
    assert total == 1 and preview[0]["reason"] == "CHILD_HOLD"


def test_cli_v11_status_separates_child_revalidation_counts() -> None:
    """CLI status must not call a resolved HOLD a confirmed Finding."""

    output = StringIO()
    emit_public(
        "text",
        output,
        command="status",
        data={
            "analysis_id": "A-001",
            "status": "PARTIAL",
            "percentage_kind": "known_checkpoint_fraction",
            "phase_counts": {
                "surface": {
                    "proof_version": 9,
                    "total": 2,
                    "covered": 1,
                    "uncovered": 0,
                    "insufficient": 1,
                    "child_revalidation_resolved": 1,
                    "child_revalidation_pending": 0,
                    "child_revalidation_still_hold": 1,
                    "child_revalidation_error": 0,
                }
            },
        },
    )
    text = output.getvalue()
    assert "자식 근거 재검증: 해결 1 · 대기 0 · HOLD 유지 1 · 오류 0" in text
    assert "Finding" not in text


def test_completed_v11_does_not_make_an_old_v10_report_current(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Matching static coverage is insufficient when the surface proof changed."""

    case = _saved_v11_empty_case(tmp_path, monkeypatch)
    artifacts = case["artifacts"]
    static_ref = artifacts.put_json({"kind": "static"})
    finding_ref = artifacts.put_json({"kind": "finding"})
    report = StageCheckpoint(
        identity=case["identity"],
        stage=SimpleStage.REPORT_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(),
        bundle_manifest_ref=artifacts.put_json({"kind": "manifest"}),
    )
    monkeypatch.setattr(
        artifacts,
        "published_report_coverage",
        lambda *_args: (static_ref, "FULL"),
    )
    monkeypatch.setattr(
        artifacts,
        "published_report_surface_proof",
        lambda *_args: (8, "a" * 64),
        raising=False,
    )
    with pytest.raises(ValueError, match="REPORT_SURFACE_PROOF_STALE"):
        artifacts.require_current_report_coverage(
            report,
            finding_ref,
            static_ref,
            "FULL",
            current_surface_proof_version=9,
            current_surface_hash=case["v11_coverage_ref"].content_hash,
        )


def test_partial_v11_allows_only_exact_surface_proof_reports(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sastsimi.simple_runtime.report_currentness import (
        current_surface_report_binding,
    )

    case = _saved_v11_empty_case(tmp_path, monkeypatch)
    case["store"].get_attack_surface_index = lambda *_args: SimpleNamespace(
        index_ref=case["artifacts"].put_json(case["index"].to_json())
    )
    run = cast(SimpleAnalysisRun, case["store"].run)
    run = run.model_copy(update={"surface_enrichment_status": "PARTIAL"})
    expected = {
        "current_surface_proof_version": 9,
        "current_surface_hash": case["v11_coverage_ref"].content_hash,
    }
    assert (
        current_surface_report_binding(
            run,
            (),
            data_dir=tmp_path / "data",
            store=cast(SimpleCheckpointStore, case["store"]),
        )
        == expected
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.report_currentness.analysis_run_lease_active",
        lambda *_args: True,
    )
    assert not candidate_report_currentness_blocked(
        run,
        (),
        data_dir=tmp_path / "data",
        store=cast(SimpleCheckpointStore, case["store"]),
    )


@pytest.mark.parametrize("large_ref_kind", ["index", "coverage"])
def test_v11_report_currentness_accepts_large_verified_refs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, large_ref_kind: str
) -> None:
    """Read-side report binding must accept saved refs within promotion's cap."""

    from sastsimi.simple_runtime.report_currentness import (
        current_surface_report_binding,
    )

    case = _saved_v11_empty_case(tmp_path, monkeypatch)
    index_ref = case["artifacts"].put_json(case["index"].to_json())
    case["store"].get_attack_surface_index = lambda *_args: SimpleNamespace(
        index_ref=index_ref
    )
    selected_ref = index_ref if large_ref_kind == "index" else case["v11_coverage_ref"]
    # The predecessor replay already bounds the index to 8 MiB, while the
    # successor coverage itself may reach the 16 MiB promotion bound.
    accepted_size = (3 if large_ref_kind == "index" else 10) * 1024 * 1024
    original_read = SimpleArtifactRepository.read_bounded

    def read_with_large_ref(
        repository: SimpleArtifactRepository, ref: StoredDataRef, max_bytes: int
    ) -> bytes:
        if ref == selected_ref and max_bytes < accepted_size:
            raise ValueError("accepted proof rejected by report read cap")
        return original_read(repository, ref, max_bytes)

    monkeypatch.setattr(SimpleArtifactRepository, "read_bounded", read_with_large_ref)
    run = cast(SimpleAnalysisRun, case["store"].run).model_copy(
        update={"surface_enrichment_status": "PARTIAL"}
    )
    assert current_surface_report_binding(
        run,
        (),
        data_dir=tmp_path / "data",
        store=cast(SimpleCheckpointStore, case["store"]),
    ) == {
        "current_surface_proof_version": 9,
        "current_surface_hash": case["v11_coverage_ref"].content_hash,
    }


def test_v11_report_currentness_rejects_unverified_proof_even_if_hash_matches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sastsimi.simple_runtime.report_currentness import (
        current_surface_report_binding,
    )

    case = _saved_v11_empty_case(tmp_path, monkeypatch)
    case["store"].get_attack_surface_index = lambda *_args: SimpleNamespace(
        index_ref=case["artifacts"].put_json(case["index"].to_json())
    )
    run = cast(SimpleAnalysisRun, case["store"].run).model_copy(
        update={"surface_enrichment_status": "PARTIAL"}
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.report_currentness.verified_surface_coverage_counts",
        lambda *_args, **_kwargs: None,
    )
    with pytest.raises(ValueError, match="REPORT_SURFACE_PROOF_STALE"):
        current_surface_report_binding(
            run,
            (),
            data_dir=tmp_path / "data",
            store=cast(SimpleCheckpointStore, case["store"]),
        )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.report_currentness.analysis_run_lease_active",
        lambda *_args: True,
    )
    assert candidate_report_currentness_blocked(
        run,
        (),
        data_dir=tmp_path / "data",
        store=cast(SimpleCheckpointStore, case["store"]),
    )
