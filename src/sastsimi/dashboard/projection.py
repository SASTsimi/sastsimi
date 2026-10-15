"""Source-to-SQLite projection service for the dashboard read model."""

from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Callable
from pathlib import Path

from sastsimi.simple_runtime.hold_projection_generation import hold_marker_count

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
    _json,
    _object_items,
)


def _marker(query: DashboardQuery, analysis_id: str) -> str:
    text = "|".join(
        sorted(
            f"{x.identity.hypothesis_id or ''}:{x.stage.value}:{x.input_hash}:"
            f"{x.updated_at.isoformat()}"
            for x in query._checkpoints(analysis_id)
        )
    )
    with query._connect() as connection:
        generation = hold_marker_count(connection, analysis_id)
    return f"{hashlib.sha256(text.encode()).hexdigest()}:hold:{generation}"


def _indexed_auxiliaries(
    tab: str, page: dict[str, object], items: list[dict[str, object]]
) -> list[dict[str, object]]:
    """Join full-tab metadata once instead of rescanning it for every row."""

    Key = tuple[str, str]
    Index = dict[Key, list[tuple[int, dict[str, object]]]]

    def key(kind: str, value: object) -> Key:
        return kind, _json(value)

    def index_rows(field: str, keys: Callable[[dict[str, object]], list[Key]]) -> Index:
        index: Index = {}
        for ordinal, row in enumerate(_dict_items(page.get(field))):
            for row_key in set(keys(row)):
                index.setdefault(row_key, []).append((ordinal, row))
        return index

    def matching(index: Index, keys: list[Key]) -> list[dict[str, object]]:
        rows = {
            ordinal: row for row_key in keys for ordinal, row in index.get(row_key, ())
        }
        return [rows[ordinal] for ordinal in sorted(rows)]

    if tab == "findings":
        traces = index_rows(
            "finding_traces", lambda row: [key("hypothesis", row.get("hypothesis_id"))]
        )
        return [
            {
                "finding_traces": [
                    row
                    for _, row in traces.get(
                        key("hypothesis", item.get("hypothesis_id")), []
                    )
                ]
            }
            for item in items
        ]
    if tab == "artifacts":
        relations = index_rows(
            "relations",
            lambda row: [
                key("artifact", row.get("source_artifact_id")),
                key("artifact", row.get("target_artifact_id")),
            ],
        )
        return [
            {
                "relations": [
                    row
                    for _, row in relations.get(
                        key("artifact", item.get("artifact_id")), []
                    )
                ]
            }
            for item in items
        ]
    if tab == "outputs":
        traces = index_rows(
            "finding_traces",
            lambda row: [
                key("report", row.get("display_id")),
                *(
                    key("artifact", aid)
                    for aid in _object_items(row.get("artifact_ids"))
                ),
            ],
        )
        groups = index_rows(
            "finding_groups",
            lambda row: [
                key("report", rid) for rid in _object_items(row.get("member_ids"))
            ],
        )
        poc_ids = {
            key("artifact", aid) for aid in _object_items(page.get("poc_artifact_ids"))
        }
        evidence_ids = {
            key("artifact", aid)
            for aid in _object_items(page.get("evidence_artifact_ids"))
        }
        result: list[dict[str, object]] = []
        for item in items:
            artifact = item.get("artifact")
            report = item.get("report")
            aid = artifact.get("artifact_id") if isinstance(artifact, dict) else None
            rid = report.get("display_id") if isinstance(report, dict) else None
            result.append(
                {
                    "finding_traces": matching(
                        traces, [key("report", rid), key("artifact", aid)]
                    ),
                    "finding_groups": [
                        row for _, row in groups.get(key("report", rid), [])
                    ],
                    "is_poc": key("artifact", aid) in poc_ids,
                    "is_evidence": key("artifact", aid) in evidence_ids,
                }
            )
        return result
    return [{} for _ in items]


def collect_source_pages(
    query: DashboardQuery, analysis_id: str
) -> tuple[str, dict[str, tuple[list[dict[str, object]], dict[str, object]]]]:
    # Pin the generation before collecting pages. A marker committed mid-scan
    # must not be claimed by a projection of the older source snapshot.
    marker = _marker(query, analysis_id)
    pages = {}
    whole_tab = getattr(query, "_get_analysis_tab_for_projection", None)
    for tab in INDEXED_TABS:
        if callable(whole_tab):
            page = whole_tab(analysis_id, tab)
            current = _dict_items(page.get("items"))
            total = _integer(page.get("total_items", page.get("total")), len(current))
            if total != len(current):
                raise ValueError("DASHBOARD_PROJECTION_SOURCE_INCOMPLETE")
            full_items: list[dict[str, object]] = []
            for item, auxiliary in zip(
                current, _indexed_auxiliaries(tab, page, current), strict=True
            ):
                copied = dict(item)
                copied["_dashboard_auxiliary"] = auxiliary
                full_items.append(copied)
            full_summary = {k: v for k, v in page.items() if k not in _PAGE_KEYS}
            pages[tab] = (full_items, full_summary)
            continue
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
    return marker, pages


def rebuild_analysis(
    data_dir: str | Path, analysis_id: str, *, dry_run: bool = False
) -> RebuildResult:
    from .query import DashboardQuery

    query = DashboardQuery(data_dir)
    model = DashboardReadModel(data_dir)
    indexed_id = analysis_id
    guard: sqlite3.Connection | None = None
    expected_state_marker: str | None = None
    expected_data_version: int | None = None
    try:
        indexed_id = query._resolved(analysis_id)
        if not dry_run:
            model.initialize()
            guard = model._connect(True)
            expected_data_version = int(
                guard.execute("PRAGMA data_version").fetchone()[0]
            )
            state = guard.execute(
                "SELECT source_marker FROM dashboard_index_state WHERE analysis_id=?",
                (indexed_id,),
            ).fetchone()
            expected_state_marker = str(state["source_marker"]) if state else None
        marker, pages = collect_source_pages(query, indexed_id)
        source = {kind: len(data[0]) for kind, data in pages.items()}
        if dry_run:
            return RebuildResult(analysis_id, source, {}, True, "DRY_RUN")
        assert guard is not None
        indexed = model.replace_if_current(
            indexed_id,
            marker,
            pages,
            guard=guard,
            expected_data_version=expected_data_version,
            expected_state_marker=expected_state_marker,
        )
        if indexed is None:
            return RebuildResult(analysis_id, source, {}, False, "STALE")
        return RebuildResult(analysis_id, source, indexed, False, "READY")
    except Exception as error:
        if not dry_run:
            if indexed_id == analysis_id:
                try:
                    indexed_id = query._resolved(analysis_id)
                except Exception:
                    pass
            try:
                model.mark_incomplete_if_current(
                    indexed_id,
                    expected_state_marker,
                    f"{type(error).__name__}: {error}",
                    guard=guard,
                    expected_data_version=expected_data_version,
                )
            except (OSError, sqlite3.Error):
                pass
        return RebuildResult(
            analysis_id, {}, {}, dry_run, "FAILED", f"{type(error).__name__}: {error}"
        )
    finally:
        if guard is not None:
            guard.close()


def rebuild_all(
    data_dir: str | Path, *, dry_run: bool = False
) -> tuple[RebuildResult, ...]:
    from .query import DashboardQuery

    query = DashboardQuery(data_dir)
    return tuple(
        rebuild_analysis(data_dir, item.analysis_id, dry_run=dry_run)
        for item in query.list_analyses()
    )


def initialize_empty_read_model(data_dir: Path) -> None:
    """Prepare an empty index only for a newly created analysis database."""
    DashboardReadModel(data_dir).initialize()


def project_after_source_write(data_dir: str | Path, analysis_id: str) -> None:
    """Run after the source commit. Projection failures never roll it back."""
    model = DashboardReadModel(data_dir)
    try:
        with model._connect() as connection:
            if not model.schema_present(connection):
                return
    except (DashboardIndexNotReady, OSError, sqlite3.Error):
        return
    rebuild_analysis(data_dir, analysis_id)
