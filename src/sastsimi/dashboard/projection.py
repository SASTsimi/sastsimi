"""Source-to-SQLite projection service for the dashboard read model."""

from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

from .query import DashboardQuery
from .read_model import (
    _PAGE_KEYS,
    INDEXED_TABS,
    DashboardIndexNotReady,
    DashboardReadModel,
    RebuildResult,
    _aux,
    _dict_items,
    _integer,
)


def _marker(query: DashboardQuery, analysis_id: str) -> str:
    text = "|".join(
        sorted(
            f"{x.identity.hypothesis_id or ''}:{x.stage.value}:{x.input_hash}:"
            f"{x.updated_at.isoformat()}"
            for x in query._checkpoints(analysis_id)
        )
    )
    return hashlib.sha256(text.encode()).hexdigest()


def collect_source_pages(
    query: DashboardQuery, analysis_id: str
) -> tuple[str, dict[str, tuple[list[dict[str, object]], dict[str, object]]]]:
    pages = {}
    for tab in INDEXED_TABS:
        offset = 0
        items: list[dict[str, object]] = []
        summary = None
        while True:
            page = query._get_analysis_tab_from_source(
                analysis_id, tab, offset=offset, limit=200
            )
            current = _dict_items(page.get("items"))
            if summary is None:
                summary = {k: v for k, v in page.items() if k not in _PAGE_KEYS}
            for item in current:
                copied = dict(item)
                copied["_dashboard_auxiliary"] = _aux(tab, page, item)
                items.append(copied)
            total = _integer(
                page.get("total_items", page.get("total", len(items))), len(items)
            )
            offset += len(current)
            if not current or offset >= total:
                break
        pages[tab] = (items, summary or {"tab": tab})
    return _marker(query, analysis_id), pages


def rebuild_analysis(
    data_dir: str | Path, analysis_id: str, *, dry_run: bool = False
) -> RebuildResult:
    from .query import DashboardQuery

    query = DashboardQuery(data_dir)
    model = DashboardReadModel(data_dir)
    try:
        marker, pages = collect_source_pages(query, analysis_id)
        source = {kind: len(data[0]) for kind, data in pages.items()}
        if dry_run:
            return RebuildResult(analysis_id, source, {}, True, "DRY_RUN")
        model.initialize()
        indexed = model.replace(analysis_id, marker, pages)
        return RebuildResult(analysis_id, source, indexed, False, "READY")
    except Exception as error:
        if not dry_run:
            model.mark_incomplete(
                analysis_id, "unknown", f"{type(error).__name__}: {error}"
            )
        return RebuildResult(
            analysis_id, {}, {}, dry_run, "FAILED", f"{type(error).__name__}: {error}"
        )


def rebuild_all(
    data_dir: str | Path, *, dry_run: bool = False
) -> tuple[RebuildResult, ...]:
    from .query import DashboardQuery

    query = DashboardQuery(data_dir)
    return tuple(
        rebuild_analysis(data_dir, item.analysis_id, dry_run=dry_run)
        for item in query.list_analyses()
    )


def project_after_source_write(data_dir: str | Path, analysis_id: str) -> None:
    """Run after the source commit. Projection failures never roll it back."""
    model = DashboardReadModel(data_dir)
    try:
        with model._connect() as connection:
            if not model.schema_present(connection):
                return
    except (DashboardIndexNotReady, OSError, sqlite3.Error):
        return
    result = rebuild_analysis(data_dir, analysis_id)
    if result.status != "READY":
        model.mark_incomplete(
            analysis_id, "post-commit", result.error or "DASHBOARD_INDEX_FAILED"
        )
