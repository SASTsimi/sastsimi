"""A dashboard projection scope never delays or mislabels source commits."""

from __future__ import annotations

import sqlite3
from contextvars import copy_context
from pathlib import Path

from sastsimi.dashboard.read_model import DashboardReadModel
from sastsimi.simple_runtime.dashboard_projection_batch import (
    defer_dashboard_projection,
    dispatch_dashboard_projection,
    mark_index_dirty_connection,
    projection_is_deferred,
)


def test_nested_scope_flushes_once_and_other_analysis_is_independent(
    tmp_path: Path,
) -> None:
    model = DashboardReadModel(tmp_path)
    model.initialize()
    projected: list[str] = []

    def project(_path: Path, analysis_id: str) -> None:
        projected.append(analysis_id)

    with defer_dashboard_projection(tmp_path, "A-1", project):
        assert projection_is_deferred(tmp_path, "A-1")
        with defer_dashboard_projection(tmp_path, "A-1", project):
            dispatch_dashboard_projection(tmp_path, "A-1", project)
        assert projected == []
        dispatch_dashboard_projection(tmp_path, "A-2", project)
        assert projected == ["A-2"]
    assert projected == ["A-2", "A-1"]


def test_copied_context_after_scope_exit_projects_immediately(tmp_path: Path) -> None:
    projected: list[str] = []

    def project(_path: Path, analysis_id: str) -> None:
        projected.append(analysis_id)

    with defer_dashboard_projection(tmp_path, "A-1", project):
        inherited = copy_context()
    inherited.run(dispatch_dashboard_projection, tmp_path, "A-1", project)

    assert not inherited.run(projection_is_deferred, tmp_path, "A-1")
    assert projected == ["A-1"]


def test_dirty_marker_rolls_back_with_source_write(tmp_path: Path) -> None:
    model = DashboardReadModel(tmp_path)
    model.initialize()
    database = model.database
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE source_rows (value TEXT)")

    connection = sqlite3.connect(database)
    try:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("INSERT INTO source_rows VALUES ('rolled-back')")
        mark_index_dirty_connection(connection, "A-1")
        connection.rollback()
    finally:
        connection.close()
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM source_rows").fetchone()[0] == 0
        assert (
            connection.execute("SELECT COUNT(*) FROM dashboard_index_state").fetchone()[
                0
            ]
            == 0
        )


def test_missing_index_schema_never_prevents_source_commit(tmp_path: Path) -> None:
    database = tmp_path / "without-index.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute("CREATE TABLE source_rows (value TEXT)")
        connection.execute("INSERT INTO source_rows VALUES ('kept')")
        mark_index_dirty_connection(connection, "A-1")

    with sqlite3.connect(database) as connection:
        assert (
            connection.execute("SELECT value FROM source_rows").fetchone()[0] == "kept"
        )
