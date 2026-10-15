"""Task-local dashboard projection deferral with durable source dirty markers."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from sastsimi.config.runtime_paths import RuntimePaths

Projector = Callable[[Path, str], None]


@dataclass(slots=True)
class _Scope:
    data_dir: Path
    analysis_id: str
    project: Projector
    active: bool = True
    pending: bool = False


_SCOPES: ContextVar[tuple[_Scope, ...]] = ContextVar(
    "dashboard_projection_scopes", default=()
)


def _matching(data_dir: Path, analysis_id: str) -> _Scope | None:
    resolved = data_dir.resolve()
    for scope in reversed(_SCOPES.get()):
        if (
            scope.active
            and scope.data_dir == resolved
            and scope.analysis_id == analysis_id
        ):
            return scope
    return None


def projection_is_deferred(data_dir: Path, analysis_id: str) -> bool:
    return _matching(data_dir, analysis_id) is not None


def dispatch_dashboard_projection(
    data_dir: Path, analysis_id: str, project: Projector
) -> None:
    scope = _matching(data_dir, analysis_id)
    if scope is not None:
        scope.pending = True
        return
    project(data_dir, analysis_id)


def _index_needs_rebuild(data_dir: Path, analysis_id: str) -> bool:
    database = RuntimePaths(data_dir).database
    if not database.is_file():
        return False
    try:
        with sqlite3.connect(
            f"{database.resolve().as_uri()}?mode=ro", uri=True
        ) as connection:
            schema = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='dashboard_index_state'"
            ).fetchone()
            if schema is None:
                return False
            state = connection.execute(
                "SELECT status FROM dashboard_index_state WHERE analysis_id=?",
                (analysis_id,),
            ).fetchone()
            return state is None or state[0] != "READY"
    except (OSError, sqlite3.Error):
        # Retain the durable dirty row and let the guarded projector diagnose it.
        return True


@contextmanager
def defer_dashboard_projection(
    data_dir: Path, analysis_id: str, project: Projector
) -> Iterator[None]:
    resolved = data_dir.resolve()
    if _matching(resolved, analysis_id) is not None:
        yield
        return
    scope = _Scope(resolved, analysis_id, project)
    token = _SCOPES.set((*_SCOPES.get(), scope))
    try:
        yield
    finally:
        scope.active = False
        _SCOPES.reset(token)
        if scope.pending or _index_needs_rebuild(resolved, analysis_id):
            try:
                project(resolved, analysis_id)
            except Exception:
                # Source commits are already durable; their INCOMPLETE marker
                # remains available for an explicit rebuild or safe resume.
                pass


def mark_index_dirty_connection(
    connection: sqlite3.Connection, analysis_id: str
) -> None:
    """Make a source transaction's dashboard invalidation atomic with its data."""
    schema = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='dashboard_index_state'"
    ).fetchone()
    if schema is None:
        return
    connection.execute(
        """INSERT INTO dashboard_index_state
        (analysis_id,projection_version,source_marker,status,last_error,indexed_at)
        VALUES (?,0,?,'INCOMPLETE','DASHBOARD_INDEX_SOURCE_UPDATED',?)
        ON CONFLICT(analysis_id) DO UPDATE SET
        projection_version=0,source_marker=excluded.source_marker,
        status='INCOMPLETE',last_error=excluded.last_error,
        indexed_at=excluded.indexed_at""",
        (analysis_id, uuid4().hex, datetime.now(UTC).isoformat()),
    )
