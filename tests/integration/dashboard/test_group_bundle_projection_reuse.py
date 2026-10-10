"""Outputs-tab group links reuse its one current Finding-group projection."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.dashboard.query import DashboardQuery
from sastsimi.reporting.grouped_bundle import GroupBundleUnavailable
from sastsimi.simple_runtime import group_report_projection as group_projection
from sastsimi.simple_runtime.finding_group_projection import (
    project_current_finding_groups,
)
from sastsimi.simple_runtime.finding_groups import FindingGroupProjection
from sastsimi.simple_runtime.group_report_projection import (
    current_group_bundle,
    current_report_groups,
)
from sastsimi.simple_runtime.models import SimpleAnalysisRun, StageCheckpoint
from tests.simple_runtime.test_group_report_projection import _reported_case


def test_outputs_reuses_request_projection_but_download_rechecks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SASTSIMI_DASHBOARD_INDEX_MODE", "source")
    run, _checkpoints, group, data_dir, _database, _store = _reported_case(tmp_path)
    query = DashboardQuery(data_dir)
    counts = {"refs": 0, "groups": 0}
    original_refs = group_projection._current_display_refs
    original_groups = project_current_finding_groups

    def count_refs(
        run: SimpleAnalysisRun,
        checkpoints: Sequence[StageCheckpoint],
        database_path: Path,
    ) -> dict[str, StoredDataRef]:
        counts["refs"] += 1
        return original_refs(run, checkpoints, database_path)

    def count_groups(
        run: SimpleAnalysisRun,
        checkpoints: Sequence[StageCheckpoint],
        eligible: Mapping[str, StoredDataRef],
        *,
        data_dir: Path,
        database_path: Path,
    ) -> FindingGroupProjection:
        counts["groups"] += 1
        return original_groups(
            run,
            checkpoints,
            eligible,
            data_dir=data_dir,
            database_path=database_path,
        )

    monkeypatch.setattr(group_projection, "_current_display_refs", count_refs)
    monkeypatch.setattr(
        group_projection, "project_current_finding_groups", count_groups
    )
    outputs = query.get_analysis_tab(run.analysis_id, "outputs")
    groups = outputs["finding_groups"]
    assert isinstance(groups, list) and isinstance(groups[0], dict)
    assert groups[0]["bundle_url"]
    assert counts == {"refs": 1, "groups": 1}

    archive = query.group_bundle_bytes(run.analysis_id, group.group_id)
    assert archive.startswith(b"PK")
    assert counts == {"refs": 3, "groups": 3}


def test_request_snapshot_does_not_accept_a_changed_group_object(
    tmp_path: Path,
) -> None:
    run, checkpoints, group, data_dir, database, _store = _reported_case(tmp_path)
    snapshot = current_report_groups(
        run, checkpoints, data_dir=data_dir, database_path=database
    )
    forged = replace(group, members=tuple(reversed(group.members)))
    with pytest.raises(GroupBundleUnavailable, match="GROUP_NOT_CURRENT"):
        current_group_bundle(
            run,
            checkpoints,
            forged,
            data_dir=data_dir,
            database_path=database,
            _current_projection=snapshot,
        )
