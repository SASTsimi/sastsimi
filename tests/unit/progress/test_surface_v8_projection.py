"""A verified proof-six PARTIAL result remains visible in public status views."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.composition.simple_runtime_composition import (
    PublicSimpleRuntimeApplication,
)
from sastsimi.config.user_config import UserConfig
from sastsimi.dashboard.query import DashboardQuery
from sastsimi.progress.projector import ProgressProjector
from tests.unit.progress.test_surface_v4_projection import _saved_v4_case


def test_v6_verified_partial_reason_reaches_cli_dashboard_and_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data, checkpoint, old_terminal = _saved_v4_case(tmp_path, old_hold=True)
    case = data["case"]
    terminal = old_terminal.model_copy(update={"surface_proof_version": 6})
    run = case.store.require_analysis_run(case.identity.analysis_id).model_copy(
        update={"candidate_terminal": terminal}
    )
    case.store.save_analysis_run(run)
    verified = {
        "COVERED": 1,
        "UNCOVERED": 0,
        "INSUFFICIENT": 1,
        "RAW_STATIC_GAP_COUNT": 0,
        "EFFECTIVE_PYTHON_GAP_COUNT": 0,
        "UNRESOLVED_REASON_COUNT": 1,
        "REASON_CODE_LOCAL_ONLY_ATTACK_PATH_UNVERIFIED": 1,
    }

    def count_if_scope_verified(*_args: object, **kwargs: Any) -> dict[str, int] | None:
        if kwargs.get("certificate_payload") is None or kwargs.get("store") is None:
            return None
        return verified

    monkeypatch.setattr(
        "sastsimi.dashboard.query.verified_surface_coverage_counts",
        count_if_scope_verified,
    )
    monkeypatch.setattr(
        "sastsimi.composition.simple_runtime_composition.verified_surface_coverage_counts",
        count_if_scope_verified,
    )
    dashboard = DashboardQuery(tmp_path / "data")
    web_counts, _ = dashboard._surface_metrics(run, [checkpoint])
    app = object.__new__(PublicSimpleRuntimeApplication)
    app._store = case.store
    app._config = cast(UserConfig, SimpleNamespace(data_dir=tmp_path / "data"))
    cli_counts, _ = app._surface_metrics(
        run, case.identity, case.index.scope_fingerprint
    )
    assert web_counts is not None and web_counts["INSUFFICIENT"] == 1
    assert cli_counts is not None and cli_counts["INSUFFICIENT"] == 1
    assert cli_counts["REASON_CODE_LOCAL_ONLY_ATTACK_PATH_UNVERIFIED"] == 1

    snapshot = ProgressProjector(case.store).snapshot(
        case.identity.analysis_id,
        candidate_pipeline_version=2,
        candidate_counts={},
        candidate_deep_counts={},
        candidate_terminal=terminal,
        candidate_bundle_hash=case.index.static_bundle_hash,
        candidate_scope_fingerprint=case.index.scope_fingerprint,
        surface_counts={"TOTAL": 2, "CONTEXT_RECORDS": 1, **verified},
        surface_index_hash=case.index_ref.content_hash,
    )
    assert snapshot.status != "COMPLETE"
    assert snapshot.phase_counts["surface"]["insufficient"] == 1
    assert (
        snapshot.phase_counts["surface"][
            "reason_code_LOCAL_ONLY_ATTACK_PATH_UNVERIFIED"
        ]
        == 1
    )
