"""A legacy report must not hide a verified current group in default exports."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sastsimi.dashboard.query import DashboardQuery, _default_report_export_selection
from tests.simple_runtime.test_group_report_projection import _reported_case


def test_mixed_report_detail_retains_the_verified_current_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, _checkpoints, group, data_dir, _database, _store = _reported_case(tmp_path)
    query = DashboardQuery(data_dir)
    original_reports = query._reports(run.analysis_id)
    legacy = original_reports[0].model_copy(update={"display_id": "F-099"})
    monkeypatch.setattr(
        query, "_reports", lambda _analysis_id: (*original_reports, legacy)
    )

    detail = query.get_analysis(run.analysis_id)
    assert len(detail.reports) == 3
    assert detail.finding_group_count is None  # Full group coverage is unproven.
    assert len(detail.finding_groups) == 1
    assert detail.finding_groups[0].group_id == group.group_id


def test_mixed_default_selection_reduces_only_verified_current_members(
    tmp_path: Path,
) -> None:
    run, _checkpoints, group, data_dir, _database, _store = _reported_case(tmp_path)
    detail = DashboardQuery(data_dir).get_analysis(run.analysis_id)
    selected, metadata = _default_report_export_selection(
        frozenset({"F-001", "F-002", "F-099"}), detail.finding_groups
    )
    assert selected == frozenset({"F-001", "F-099"})
    assert metadata is not None
    assert metadata["mode"] == "PROVEN_FLOW_DEDUP"
    assert metadata["grouping_coverage"] == "PARTIAL"
    assert metadata["ungrouped_raw_report_ids"] == ["F-099"]
    groups = metadata["groups"]
    assert isinstance(groups, list) and isinstance(groups[0], dict)
    assert groups[0]["group_id"] == group.group_id


def test_presentation_summary_marks_partial_grouping_and_raw_legacy_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, _checkpoints, _group, data_dir, _database, _store = _reported_case(tmp_path)
    query = DashboardQuery(data_dir)
    detail = query.get_analysis(run.analysis_id)
    legacy = detail.reports[0].model_copy(update={"display_id": "F-099"})
    mixed_detail = detail.model_copy(
        update={
            "reports": (*detail.reports, legacy),
            "finding_group_count": None,
        }
    )
    members = query.bundle_members(run.analysis_id)
    selection = json.loads(members["reports/export-selection.json"])
    selection["grouping_coverage"] = "PARTIAL"
    selection["ungrouped_raw_report_ids"] = ["F-099"]
    members["reports/export-selection.json"] = json.dumps(selection).encode()
    members["reports/F-099.md"] = b"# Historical report\n"
    monkeypatch.setattr(query, "get_analysis", lambda _analysis_id: mixed_detail)
    monkeypatch.setattr(query, "bundle_members", lambda _analysis_id: members)

    presentation = query.presentation_bundle_members(run.analysis_id)
    summary = json.loads(presentation["presentation/summary.json"])
    assert summary["report_export_mode"] == "PROVEN_FLOW_DEDUP"
    assert summary["grouping_coverage"] == "PARTIAL"
    assert summary["ungrouped_raw_report_ids"] == ["F-099"]
    assert summary["original_member_report_ids"] == ["F-002"]
    assert "reports/F-099.md" in presentation
