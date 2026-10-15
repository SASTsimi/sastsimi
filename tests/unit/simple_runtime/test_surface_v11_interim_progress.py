"""Pinned V11 attempts stay visible before a proof9 result is promoted."""

from __future__ import annotations

from dataclasses import replace
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from sastsimi.composition.simple_runtime_composition import (
    PublicSimpleRuntimeApplication,
)
from sastsimi.config.user_config import UserConfig
from sastsimi.dashboard.query import DashboardQuery
from sastsimi.interfaces.cli.public import emit_public
from sastsimi.progress.projector import ProgressProjector
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from tests.unit.progress.test_surface_v4_projection import _saved_v4_case
from tests.unit.simple_runtime.test_surface_v11_store import _v11_case


def test_interim_counts_come_from_the_exact_pinned_ledger(tmp_path: Path) -> None:
    """A pinned PENDING row is visible while V10 coverage remains provisional."""

    from sastsimi.simple_runtime.surface_child_evidence_v11 import (
        interim_child_attempt_counts_v11,
    )

    store, identity, original, root, plan_ref = _v11_case(tmp_path, with_hold=True)
    assert store.pin_surface_enrichment_v11_plan(original, plan_ref)
    run = store.require_analysis_run(identity.analysis_id)
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity, create_dirs=False)

    counts = interim_child_attempt_counts_v11(
        run, identity, root.output_refs[0].content_hash, store, artifacts
    )
    assert counts == {
        "PENDING": 1,
        "RUNNING": 0,
        "RESOLVED": 0,
        "STILL_HOLD": 0,
        "ERROR": 0,
    }


@pytest.mark.parametrize("status", ["RUNNING", "RESOLVED", "STILL_HOLD", "ERROR"])
def test_interim_counts_keep_each_attempt_status_distinct(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    """Ledger outcomes are displayed as attempts, with no proof promotion."""

    from sastsimi.simple_runtime.surface_child_evidence_v11 import (
        interim_child_attempt_counts_v11,
    )

    store, identity, original, root, plan_ref = _v11_case(tmp_path, with_hold=True)
    assert store.pin_surface_enrichment_v11_plan(original, plan_ref)
    run = store.require_analysis_run(identity.analysis_id)
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity, create_dirs=False)
    rows = store.list_surface_child_revalidation_v11(
        identity, run.candidate_scope_fingerprint or "", plan_ref
    )
    key, pending = next(iter(rows.items()))
    final = status not in {"PENDING", "RUNNING"}
    updated = replace(
        pending,
        status=status,
        reason_code="RECORDED_ATTEMPT" if final else None,
        result_ref=artifacts.put_json({"attempt": status}) if final else None,
        attempt_id="attempt-1",
    )
    monkeypatch.setattr(
        store, "list_surface_child_revalidation_v11", lambda *_: {key: updated}
    )
    counts = interim_child_attempt_counts_v11(
        run, identity, root.output_refs[0].content_hash, store, artifacts
    )
    assert counts[status] == 1
    assert sum(counts.values()) == 1


def test_interim_counts_reject_missing_or_mismatched_plan_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A gap or a changed checkpoint hash cannot be displayed as progress."""

    from sastsimi.simple_runtime.surface_child_evidence_v11 import (
        interim_child_attempt_counts_v11,
    )

    store, identity, original, root, plan_ref = _v11_case(tmp_path, with_hold=True)
    assert store.pin_surface_enrichment_v11_plan(original, plan_ref)
    run = store.require_analysis_run(identity.analysis_id)
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity, create_dirs=False)
    assert run.surface_enrichment_v10_plan_ref is not None
    forged = run.model_copy(
        update={"surface_enrichment_v11_plan_ref": run.surface_enrichment_v10_plan_ref}
    )
    with pytest.raises(ValueError, match="SURFACE_CHILD_V11_INTERIM_INVALID"):
        interim_child_attempt_counts_v11(
            forged, identity, root.output_refs[0].content_hash, store, artifacts
        )

    rows = store.list_surface_child_revalidation_v11(
        identity, run.candidate_scope_fingerprint or "", plan_ref
    )
    monkeypatch.setattr(store, "list_surface_child_revalidation_v11", lambda *_: {})
    with pytest.raises(ValueError, match="SURFACE_CHILD_V11_INTERIM_INVALID"):
        interim_child_attempt_counts_v11(
            run, identity, root.output_refs[0].content_hash, store, artifacts
        )
    key, row = next(iter(rows.items()))
    monkeypatch.setattr(
        store,
        "list_surface_child_revalidation_v11",
        lambda *_: {key: replace(row, checkpoint_hash="0" * 64)},
    )
    with pytest.raises(ValueError, match="SURFACE_CHILD_V11_INTERIM_INVALID"):
        interim_child_attempt_counts_v11(
            run, identity, root.output_refs[0].content_hash, store, artifacts
        )


def test_interim_attempts_do_not_credit_surface_completion_or_complete_status(
    tmp_path: Path,
) -> None:
    """Resolved attempt rows stay distinct from verified coverage."""

    data, _checkpoint, terminal = _saved_v4_case(tmp_path, old_hold=True)
    case = data["case"]
    snapshot = ProgressProjector(case.store).snapshot(
        case.identity.analysis_id,
        candidate_pipeline_version=2,
        candidate_counts={},
        candidate_deep_counts={},
        candidate_terminal=terminal.model_copy(
            update={"surface_proof_version": 8, "status": "PARTIAL"}
        ),
        candidate_bundle_hash=case.index.static_bundle_hash,
        candidate_scope_fingerprint=case.index.scope_fingerprint,
        surface_counts={"TOTAL": 2, "CONTEXT_RECORDS": 1},
        surface_index_hash=case.index_ref.content_hash,
        surface_enrichment_status="RUNNING",
        child_attempt_counts={
            "PENDING": 1,
            "RUNNING": 1,
            "RESOLVED": 1,
            "STILL_HOLD": 1,
            "ERROR": 1,
        },
    )
    surface = snapshot.phase_counts["surface"]
    assert snapshot.status != "COMPLETE"
    assert surface["completed"] == 0
    assert "covered" not in surface
    assert surface["child_revalidation_attempts_unverified"] == 1
    assert surface["child_revalidation_attempt_pending"] == 1
    assert surface["child_revalidation_attempt_running"] == 1
    assert surface["child_revalidation_attempt_resolved"] == 1
    assert surface["child_revalidation_attempt_still_hold"] == 1
    assert surface["child_revalidation_attempt_error"] == 1

    output = StringIO()
    emit_public("text", output, command="status", data=snapshot.model_dump(mode="json"))
    text = output.getvalue()
    assert "검증 전 시도 기록" in text
    assert "대기 1 · 실행 중 1 · 해결 1 · HOLD 유지 1 · 오류 1" in text
    assert "검토 근거 충족" not in text


@pytest.mark.parametrize("enrichment_status", ["RUNNING", "BLOCKED"])
def test_cli_and_dashboard_readers_project_interim_ledger_separately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, enrichment_status: str
) -> None:
    """Both status paths use the ledger reader and withhold old coverage."""

    data, checkpoint, terminal = _saved_v4_case(tmp_path, old_hold=True)
    case = data["case"]
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.static_coverage_ref is not None
    run = run.model_copy(
        update={
            "candidate_terminal": terminal.model_copy(
                update={"surface_proof_version": 8, "status": "PARTIAL"}
            ),
            "surface_enrichment_v11_plan_ref": run.static_coverage_ref,
            "surface_enrichment_status": enrichment_status,
            "surface_enrichment_error_code": (
                "SURFACE_CHILD_V11_RECHECK_BLOCKED"
                if enrichment_status == "BLOCKED"
                else None
            ),
        }
    )
    counts = {"PENDING": 0, "RUNNING": 1, "RESOLVED": 0, "STILL_HOLD": 0, "ERROR": 0}
    monkeypatch.setattr(
        "sastsimi.composition.simple_runtime_composition.interim_child_attempt_counts_v11",
        lambda *_args: counts,
        raising=False,
    )
    monkeypatch.setattr(
        "sastsimi.dashboard.query.interim_child_attempt_counts_v11",
        lambda *_args: counts,
        raising=False,
    )
    base_coverage = {
        "COVERED": 1,
        "UNCOVERED": 0,
        "INSUFFICIENT": 1,
        "RAW_STATIC_GAP_COUNT": 0,
        "EFFECTIVE_PYTHON_GAP_COUNT": 0,
    }
    monkeypatch.setattr(
        "sastsimi.composition.simple_runtime_composition.verified_v11_predecessor_counts",
        lambda *_args: base_coverage,
    )
    monkeypatch.setattr(
        "sastsimi.dashboard.query.verified_v11_predecessor_counts",
        lambda *_args: base_coverage,
    )

    app = object.__new__(PublicSimpleRuntimeApplication)
    app._store = case.store
    app._config = cast(UserConfig, SimpleNamespace(data_dir=tmp_path / "data"))
    cli_counts, _ = app._surface_metrics(
        run, case.identity, case.index.scope_fingerprint
    )
    dashboard_counts, _ = DashboardQuery(tmp_path / "data")._surface_metrics(
        run, [checkpoint]
    )
    assert cli_counts is not None and dashboard_counts is not None
    for projected in (cli_counts, dashboard_counts):
        assert projected["CHILD_REVALIDATION_ATTEMPT_RUNNING_COUNT"] == 1
        assert "COVERED" not in projected
        assert projected["BASE_COVERED"] == 1
        assert projected["BASE_UNCOVERED"] == 0
        assert projected["BASE_INSUFFICIENT"] == 1


def test_readers_keep_verified_base_when_v11_attempt_ledger_is_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bad successor ledger does not erase independent base-work evidence."""

    data, checkpoint, terminal = _saved_v4_case(tmp_path, old_hold=True)
    case = data["case"]
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.static_coverage_ref is not None
    run = run.model_copy(
        update={
            "candidate_terminal": terminal.model_copy(
                update={"surface_proof_version": 8, "status": "PARTIAL"}
            ),
            "surface_enrichment_v11_plan_ref": run.static_coverage_ref,
            "surface_enrichment_status": "BLOCKED",
        }
    )

    def invalid_ledger(*_args: object) -> dict[str, int]:
        raise ValueError("ledger unavailable")

    for module in (
        "sastsimi.composition.simple_runtime_composition",
        "sastsimi.dashboard.query",
    ):
        monkeypatch.setattr(
            f"{module}.interim_child_attempt_counts_v11", invalid_ledger
        )
        monkeypatch.setattr(
            f"{module}.verified_v11_predecessor_counts",
            lambda *_args: {
                "COVERED": 1,
                "UNCOVERED": 0,
                "INSUFFICIENT": 1,
                "RAW_STATIC_GAP_COUNT": 0,
                "EFFECTIVE_PYTHON_GAP_COUNT": 0,
            },
            raising=False,
        )
    app = object.__new__(PublicSimpleRuntimeApplication)
    app._store = case.store
    app._config = cast(UserConfig, SimpleNamespace(data_dir=tmp_path / "data"))
    cli_counts, _ = app._surface_metrics(
        run, case.identity, case.index.scope_fingerprint
    )
    dashboard_counts, _ = DashboardQuery(tmp_path / "data")._surface_metrics(
        run, [checkpoint]
    )
    for projected in (cli_counts, dashboard_counts):
        assert projected is not None
        assert projected["BASE_COVERED"] == 1
        assert projected["BASE_INSUFFICIENT"] == 1
        assert "COVERED" not in projected
        assert "CHILD_REVALIDATION_ATTEMPT_PENDING_COUNT" not in projected
