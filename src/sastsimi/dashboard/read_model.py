"""Rebuildable read model used only by dashboard list APIs."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sastsimi.config.runtime_paths import RuntimePaths

if TYPE_CHECKING:
    from .query import DashboardQuery

VERSION = 1
INDEXED_TABS = ("findings", "coverage", "artifacts", "llm", "outputs")
_PAGE_KEYS = {
    "items",
    "page",
    "page_size",
    "total_items",
    "total_pages",
    "has_previous",
    "has_next",
    "total",
    "offset",
    "limit",
    "finding_traces",
    "relations",
    "static_tool_findings",
    "reports",
    "finding_groups",
    "artifacts",
    "poc_artifact_ids",
    "evidence_artifact_ids",
}


class DashboardIndexNotReady(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class RebuildResult:
    analysis_id: str
    source_counts: dict[str, int]
    indexed_counts: dict[str, int]
    dry_run: bool
    status: str
    error: str | None = None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS dashboard_index_state (
 analysis_id TEXT PRIMARY KEY, projection_version INTEGER NOT NULL,
 source_marker TEXT NOT NULL, status TEXT NOT NULL
 CHECK(status IN ('READY','INCOMPLETE')), last_error TEXT, indexed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dashboard_list_summaries (
 analysis_id TEXT NOT NULL, list_kind TEXT NOT NULL,
 projection_version INTEGER NOT NULL, summary_json TEXT NOT NULL,
 PRIMARY KEY(analysis_id,list_kind),
 FOREIGN KEY(analysis_id) REFERENCES dashboard_index_state(analysis_id)
 ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS dashboard_list_items (
 analysis_id TEXT NOT NULL, list_kind TEXT NOT NULL, item_id TEXT NOT NULL,
 sort_ordinal INTEGER NOT NULL, sort_value TEXT, status_value TEXT,
 kind_value TEXT, data_kind_value TEXT, search_text TEXT NOT NULL,
 payload_json TEXT NOT NULL, auxiliary_json TEXT NOT NULL,
 detail_ref_json TEXT NOT NULL, projection_version INTEGER NOT NULL,
 PRIMARY KEY(analysis_id,list_kind,item_id),
 FOREIGN KEY(analysis_id) REFERENCES dashboard_index_state(analysis_id)
 ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_dashboard_list_page ON dashboard_list_items
 (analysis_id,list_kind,sort_ordinal DESC,item_id DESC);
CREATE INDEX IF NOT EXISTS idx_dashboard_list_status ON dashboard_list_items
 (analysis_id,list_kind,status_value,sort_ordinal DESC,item_id DESC);
CREATE INDEX IF NOT EXISTS idx_dashboard_list_kind ON dashboard_list_items
 (analysis_id,list_kind,kind_value,data_kind_value,sort_ordinal DESC,item_id DESC);
"""


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _item_id(tab: str, item: dict[str, object]) -> str:
    keys = {
        "findings": "hypothesis_id",
        "artifacts": "artifact_id",
        "llm": "invocation_id",
    }
    if tab in keys:
        return str(item[keys[tab]])
    if tab == "coverage":
        identity = {key: item.get(key) for key in ("location", "tools", "rule_ids")}
        return hashlib.sha256(_json(identity).encode()).hexdigest()
    if tab == "outputs":
        nested = item.get("artifact") or item.get("report")
        if isinstance(nested, dict):
            value = nested.get("artifact_id") or nested.get("display_id")
            return f"{item.get('output_type')}:{value}"
    raise ValueError(f"DASHBOARD_INDEX_ITEM_ID_MISSING:{tab}")


def _search(item: dict[str, object]) -> str:
    parts: list[str] = []

    def walk(value: object) -> None:
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, dict):
            for child in value.values():
                walk(child)
        elif isinstance(value, (list, tuple)):
            for child in value:
                walk(child)

    walk(item)
    return " ".join(parts).casefold()


def _dict_items(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _object_items(value: object) -> list[object]:
    return list(value) if isinstance(value, list) else []


def _decoded_dict(value: str) -> dict[str, object]:
    decoded = json.loads(value)
    return dict(decoded) if isinstance(decoded, dict) else {}


def _integer(value: object, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return default
    return default


def _subject(tab: str, item: dict[str, object]) -> dict[str, object]:
    nested = item.get("artifact") or item.get("report") if tab == "outputs" else None
    return nested if isinstance(nested, dict) else item


def _aux(
    tab: str, page: dict[str, object], item: dict[str, object]
) -> dict[str, object]:
    if tab == "findings":
        key = item.get("hypothesis_id")
        return {
            "finding_traces": [
                x
                for x in _dict_items(page.get("finding_traces"))
                if isinstance(x, dict) and x.get("hypothesis_id") == key
            ]
        }
    if tab == "artifacts":
        key = item.get("artifact_id")
        return {
            "relations": [
                x
                for x in _dict_items(page.get("relations"))
                if isinstance(x, dict)
                and key in (x.get("source_artifact_id"), x.get("target_artifact_id"))
            ]
        }
    if tab == "outputs":
        artifact = item.get("artifact")
        report = item.get("report")
        aid = artifact.get("artifact_id") if isinstance(artifact, dict) else None
        rid = report.get("display_id") if isinstance(report, dict) else None
        return {
            "finding_traces": [
                x
                for x in _dict_items(page.get("finding_traces"))
                if isinstance(x, dict)
                and (
                    x.get("display_id") == rid
                    or aid in _object_items(x.get("artifact_ids"))
                )
            ],
            "finding_groups": [
                x
                for x in _dict_items(page.get("finding_groups"))
                if isinstance(x, dict) and rid in _object_items(x.get("member_ids"))
            ],
            "is_poc": aid in _object_items(page.get("poc_artifact_ids")),
            "is_evidence": aid in _object_items(page.get("evidence_artifact_ids")),
        }
    return {}


def _unique(values: Any) -> list[dict[str, object]]:
    seen: set[str] = set()
    result = []
    for value in values:
        if isinstance(value, dict) and _json(value) not in seen:
            seen.add(_json(value))
            result.append(value)
    return result


def _page(
    items: list[dict[str, object]], total: int, offset: int, limit: int, tab: str
) -> dict[str, object]:
    number = offset // limit + 1
    pages = (total + limit - 1) // limit if total else 0
    return {
        "items": items,
        "page": number,
        "page_size": limit,
        "total_items": total,
        "total_pages": pages,
        "has_previous": number > 1,
        "has_next": number < pages,
        "total": total,
        "offset": offset,
        "limit": limit,
        "tab": tab,
    }


class DashboardReadModel:
    def __init__(self, data_dir: str | Path) -> None:
        self.data_dir = Path(data_dir).resolve()
        self.database = RuntimePaths(self.data_dir).database.resolve()

    def _connect(self, writable: bool = False) -> sqlite3.Connection:
        if writable:
            self.database.parent.mkdir(parents=True, exist_ok=True)
            connection = sqlite3.connect(self.database, timeout=5)
        else:
            if not self.database.is_file():
                raise DashboardIndexNotReady("DASHBOARD_INDEX_NOT_READY")
            connection = sqlite3.connect(
                f"file:{self.database.as_posix()}?mode=ro", uri=True, timeout=5
            )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    @staticmethod
    def schema_present(connection: sqlite3.Connection) -> bool:
        return (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='dashboard_index_state'"
            ).fetchone()
            is not None
        )

    def initialize(self) -> None:
        with self._connect(True) as connection:
            connection.executescript(_SCHEMA)

    def mark_incomplete(self, analysis_id: str, marker: str, error: str) -> None:
        try:
            with self._connect(True) as connection:
                if not self.schema_present(connection):
                    return
                connection.execute(
                    """INSERT INTO dashboard_index_state
                    (analysis_id,projection_version,source_marker,status,last_error,indexed_at)
                    VALUES (?,?,?,'INCOMPLETE',?,?)
                    ON CONFLICT(analysis_id) DO UPDATE SET
                    projection_version=excluded.projection_version,
                    source_marker=excluded.source_marker,status='INCOMPLETE',
                    last_error=excluded.last_error,indexed_at=excluded.indexed_at""",
                    (
                        analysis_id,
                        VERSION,
                        marker,
                        error[:1000],
                        datetime.now(UTC).isoformat(),
                    ),
                )
        except (OSError, sqlite3.Error):
            pass

    def replace(
        self,
        analysis_id: str,
        marker: str,
        pages: dict[str, tuple[list[dict[str, object]], dict[str, object]]],
    ) -> dict[str, int]:
        counts = {kind: len(data[0]) for kind, data in pages.items()}
        connection = self._connect(True)
        try:
            if not self.schema_present(connection):
                raise DashboardIndexNotReady("DASHBOARD_INDEX_SCHEMA_MISSING")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """INSERT INTO dashboard_index_state
                (analysis_id,projection_version,source_marker,status,last_error,indexed_at)
                VALUES (?,?,?,'INCOMPLETE',NULL,?)
                ON CONFLICT(analysis_id) DO UPDATE SET
                projection_version=excluded.projection_version,
                source_marker=excluded.source_marker,status='INCOMPLETE',
                last_error=NULL,indexed_at=excluded.indexed_at""",
                (analysis_id, VERSION, marker, datetime.now(UTC).isoformat()),
            )
            connection.execute(
                "DELETE FROM dashboard_list_items WHERE analysis_id=?", (analysis_id,)
            )
            connection.execute(
                "DELETE FROM dashboard_list_summaries WHERE analysis_id=?",
                (analysis_id,),
            )
            for kind, (items, summary) in pages.items():
                connection.execute(
                    "INSERT INTO dashboard_list_summaries VALUES (?,?,?,?)",
                    (analysis_id, kind, VERSION, _json(summary)),
                )
                total = len(items)
                for position, raw in enumerate(items):
                    item = dict(raw)
                    auxiliary = item.pop("_dashboard_auxiliary", {})
                    subject = _subject(kind, item)
                    sort_value = next(
                        (
                            str(subject[k])
                            for k in ("created_at", "started_at", "updated_at")
                            if subject.get(k) is not None
                        ),
                        None,
                    )
                    status = next(
                        (
                            str(subject[k])
                            for k in ("status", "verdict", "validation_status")
                            if subject.get(k) is not None
                        ),
                        None,
                    )
                    kind_value = (
                        str(subject["kind"])
                        if subject.get("kind") is not None
                        else None
                    )
                    data_kind = (
                        str(subject["data_kind"])
                        if subject.get("data_kind") is not None
                        else None
                    )
                    detail = {
                        k: item[k]
                        for k in (
                            "hypothesis_id",
                            "artifact_id",
                            "invocation_id",
                            "output_type",
                        )
                        if item.get(k) is not None
                    }
                    connection.execute(
                        """INSERT INTO dashboard_list_items VALUES
                        (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            analysis_id,
                            kind,
                            _item_id(kind, item),
                            total - position,
                            sort_value,
                            status,
                            kind_value,
                            data_kind,
                            _search(item),
                            _json(item),
                            _json(auxiliary),
                            _json(detail),
                            VERSION,
                        ),
                    )
            connection.execute(
                "UPDATE dashboard_index_state SET status='READY',last_error=NULL "
                "WHERE analysis_id=?",
                (analysis_id,),
            )
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return counts

    def page(
        self,
        analysis_id: str,
        tab: str,
        *,
        offset: int,
        limit: int,
        query: str = "",
        artifact_type: str | None = None,
    ) -> dict[str, object]:
        if tab not in INDEXED_TABS:
            raise ValueError("DASHBOARD_INDEX_KIND_INVALID")
        with self._connect() as connection:
            if not self.schema_present(connection):
                raise DashboardIndexNotReady("DASHBOARD_INDEX_SCHEMA_MISSING")
            state = connection.execute(
                "SELECT status,projection_version FROM dashboard_index_state "
                "WHERE analysis_id=?",
                (analysis_id,),
            ).fetchone()
            if (
                state is None
                or state["status"] != "READY"
                or int(state["projection_version"]) != VERSION
            ):
                raise DashboardIndexNotReady("DASHBOARD_INDEX_NOT_READY")
            summary = connection.execute(
                "SELECT summary_json FROM dashboard_list_summaries "
                "WHERE analysis_id=? AND list_kind=?",
                (analysis_id, tab),
            ).fetchone()
            if summary is None:
                raise DashboardIndexNotReady("DASHBOARD_INDEX_NOT_READY")
            where = ["analysis_id=?", "list_kind=?"]
            values: list[object] = [analysis_id, tab]
            search = query.strip().casefold()
            if search:
                where.append("search_text LIKE ? ESCAPE '\\'")
                escaped = (
                    search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                )
                values.append(f"%{escaped}%")
            if artifact_type:
                where.append("(kind_value=? OR data_kind_value=?)")
                values.extend((artifact_type, artifact_type))
            predicate = " AND ".join(where)
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM dashboard_list_items WHERE {predicate}",
                    values,
                ).fetchone()[0]
            )
            rows = connection.execute(
                f"""SELECT payload_json,auxiliary_json FROM dashboard_list_items
                WHERE {predicate}
                ORDER BY sort_ordinal DESC,item_id DESC LIMIT ? OFFSET ?""",
                [*values, limit, offset],
            ).fetchall()
        items = [_decoded_dict(row["payload_json"]) for row in rows]
        auxiliaries = [_decoded_dict(row["auxiliary_json"]) for row in rows]
        result: dict[str, object] = _decoded_dict(summary["summary_json"])
        result.update(_page(items, total, offset, limit, tab))
        if tab == "findings":
            result["finding_traces"] = _unique(
                x for aux in auxiliaries for x in _dict_items(aux.get("finding_traces"))
            )
        elif tab == "coverage":
            result["static_tool_findings"] = items
        elif tab == "artifacts":
            result["relations"] = _unique(
                x for aux in auxiliaries for x in _dict_items(aux.get("relations"))
            )
        elif tab == "outputs":
            artifacts: list[dict[str, object]] = []
            reports: list[dict[str, object]] = []
            poc_artifact_ids: list[object] = []
            evidence_artifact_ids: list[object] = []
            for item, auxiliary in zip(items, auxiliaries, strict=True):
                artifact = item.get("artifact")
                report = item.get("report")
                if isinstance(artifact, dict):
                    artifacts.append(dict(artifact))
                    artifact_id = artifact.get("artifact_id")
                    if auxiliary.get("is_poc") and artifact_id is not None:
                        poc_artifact_ids.append(artifact_id)
                    if auxiliary.get("is_evidence") and artifact_id is not None:
                        evidence_artifact_ids.append(artifact_id)
                if isinstance(report, dict):
                    reports.append(dict(report))
            result["artifacts"] = artifacts
            result["reports"] = reports
            result["finding_traces"] = _unique(
                x for aux in auxiliaries for x in _dict_items(aux.get("finding_traces"))
            )
            result["finding_groups"] = _unique(
                x for aux in auxiliaries for x in _dict_items(aux.get("finding_groups"))
            )
            result["poc_artifact_ids"] = poc_artifact_ids
            result["evidence_artifact_ids"] = evidence_artifact_ids
        return result


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
