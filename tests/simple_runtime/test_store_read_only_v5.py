"""A dashboard may inspect checkpoints without initializing or mutating storage."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from sastsimi.simple_runtime.store import SimpleCheckpointStore


def test_read_only_open_does_not_create_missing_database_or_parent(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "absent" / "checkpoint.sqlite3"

    reader = SimpleCheckpointStore(database_path, read_only=True)

    assert not database_path.parent.exists()
    with pytest.raises(sqlite3.OperationalError):
        reader.list_analysis_ids()
    assert not database_path.parent.exists()


def test_read_only_connection_queries_without_mutating_database(tmp_path: Path) -> None:
    database_path = tmp_path / "checkpoint.sqlite3"
    SimpleCheckpointStore(database_path)
    prior_files = {entry.name for entry in tmp_path.iterdir()}
    prior_bytes = database_path.read_bytes()

    reader = SimpleCheckpointStore(database_path, read_only=True)

    assert reader.list_analysis_ids() == ()
    with reader._connect() as connection:
        assert connection.execute("PRAGMA query_only").fetchone()[0] == 1
        with pytest.raises(sqlite3.OperationalError):
            connection.execute("DELETE FROM simple_analysis_runs")
    assert {entry.name for entry in tmp_path.iterdir()} == prior_files
    assert database_path.read_bytes() == prior_bytes


def test_read_only_rejects_mutation_apis_before_argument_validation(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "checkpoint.sqlite3"
    SimpleCheckpointStore(database_path)
    reader = SimpleCheckpointStore(database_path, read_only=True)

    mutation_apis = (
        "save_checkpoint",
        "save_analysis_run",
        "prepare_surface_hold_replay",
        "prepare_recovery",
        "replace_from",
        "commit_surface_exploration",
        "claim_hypothesis",
        "register_free_hypothesis",
        "repair_pending_pro_con_role_cache",
        "record_llm_attempt",
        "begin_codex_call",
        "mark_running",
    )
    for method_name in mutation_apis:
        with pytest.raises(RuntimeError, match="SIMPLE_CHECKPOINT_STORE_READ_ONLY"):
            getattr(reader, method_name)()
