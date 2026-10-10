"""Explicit dashboard read-model migration and rebuild command."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path

from sastsimi.dashboard.projection import rebuild_all, rebuild_analysis


def run(
    data_dir: str | Path,
    *,
    analysis_id: str | None,
    rebuild_all_analyses: bool,
    dry_run: bool,
) -> dict[str, object]:
    if (analysis_id is None) == (not rebuild_all_analyses):
        raise ValueError("DASHBOARD_INDEX_SCOPE_REQUIRED")
    results = (
        rebuild_all(data_dir, dry_run=dry_run)
        if rebuild_all_analyses
        else (rebuild_analysis(data_dir, analysis_id or "", dry_run=dry_run),)
    )
    payload = [asdict(item) for item in results]
    return {
        "status": "READY"
        if all(item.status in {"READY", "DRY_RUN"} for item in results)
        else "PARTIAL",
        "dry_run": dry_run,
        "processed": len(results),
        "succeeded": sum(item.status in {"READY", "DRY_RUN"} for item in results),
        "failed": sum(item.status == "FAILED" for item in results),
        "skipped": 0,
        "analyses": payload,
    }
