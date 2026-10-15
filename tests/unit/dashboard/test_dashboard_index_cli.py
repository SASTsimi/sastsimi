"""Dashboard index rebuild command reports retryable publication conflicts."""

from __future__ import annotations

from pathlib import Path

from pytest import MonkeyPatch

from sastsimi.dashboard.read_model import RebuildResult
from sastsimi.interfaces.cli import dashboard_index


def test_stale_rebuild_counts_as_skipped_not_failed(
    monkeypatch: MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        dashboard_index,
        "rebuild_analysis",
        lambda *_args, **_kwargs: RebuildResult("A-001", {}, {}, False, "STALE"),
    )

    result = dashboard_index.run(
        tmp_path, analysis_id="A-001", rebuild_all_analyses=False, dry_run=False
    )

    assert result["status"] == "PARTIAL"
    assert result["succeeded"] == 0
    assert result["failed"] == 0
    assert result["skipped"] == 1
