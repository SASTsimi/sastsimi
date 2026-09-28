from __future__ import annotations

import math
import sqlite3
from pathlib import Path

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _identity(**changes: str) -> CheckpointIdentity:
    values = {
        "analysis_id": "analysis-1",
        "workspace_id": "workspace-1",
        "commit_id": "a" * 40,
        "hypothesis_id": None,
    }
    values.update(changes)
    return CheckpointIdentity.model_validate(values)


def _ref(tmp_path: Path, identity: CheckpointIdentity, value: bytes) -> StoredDataRef:
    return SimpleArtifactRepository(tmp_path / "data", identity).put_bytes(
        value, "application/json"
    )


def test_execution_ledger_migrates_legacy_database_without_changing_summary(
    tmp_path: Path,
) -> None:
    database = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE simple_static_scan_attempts (analysis_id TEXT)"
        )
        connection.execute(
            "INSERT INTO simple_static_scan_attempts VALUES ('existing')"
        )

    identity = _identity()
    store = SimpleCheckpointStore(database)
    assert store.count_static_scan_executions(identity, "owner/repo") == 0
    store.record_static_scan_execution(
        identity,
        "owner/repo",
        "fingerprint-1",
        "opengrep",
        "batch-1",
        "BLOCKED",
        None,
        "OPENGREP_EXECUTION_FAILED",
        timeout_seconds=30.0,
    )

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT analysis_id FROM simple_static_scan_attempts"
        ).fetchone() == ("existing",)
    assert (
        SimpleCheckpointStore(database).count_static_scan_executions(
            identity, "owner/repo"
        )
        == 1
    )


def test_legacy_history_marker_captures_only_preexisting_summary_scopes(
    tmp_path: Path,
) -> None:
    database = tmp_path / "legacy-with-attempts.sqlite3"
    identity = _identity()
    with sqlite3.connect(database) as connection:
        connection.execute(
            """
            CREATE TABLE simple_static_scan_attempts (
                analysis_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                commit_id TEXT NOT NULL,
                repository TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                tool TEXT NOT NULL,
                run_key TEXT NOT NULL,
                status TEXT NOT NULL,
                raw_ref_json TEXT,
                coverage_ref_json TEXT,
                error_code TEXT,
                PRIMARY KEY (
                    analysis_id, workspace_id, commit_id, repository,
                    fingerprint, tool, run_key
                )
            )
            """
        )
        for run_key in ("batch-1", "batch-2"):
            connection.execute(
                "INSERT INTO simple_static_scan_attempts "
                "(analysis_id, workspace_id, commit_id, repository, "
                "fingerprint, tool, run_key, status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    identity.analysis_id,
                    identity.workspace_id,
                    identity.commit_id,
                    "owner/repo",
                    "fingerprint-old",
                    "opengrep",
                    run_key,
                    "BLOCKED",
                ),
            )

    store = SimpleCheckpointStore(database)
    assert store.static_scan_legacy_history_incomplete(
        identity, "owner/repo", "fingerprint-old"
    )
    assert not store.static_scan_legacy_history_incomplete(
        identity, "owner/repo", "fingerprint-new"
    )
    assert not store.static_scan_legacy_history_incomplete(
        _identity(analysis_id="another"), "owner/repo", "fingerprint-old"
    )
    assert not store.static_scan_legacy_history_incomplete(
        identity, "owner/other", "fingerprint-old"
    )
    store.save_static_scan_attempt(
        identity,
        "owner/repo",
        "fingerprint-new",
        "opengrep",
        "batch-3",
        "BLOCKED",
        None,
        None,
        "SCAN_FAILED",
    )
    store.record_static_scan_execution(
        identity,
        "owner/repo",
        "fingerprint-old",
        "opengrep",
        "batch-1",
        "BLOCKED",
        None,
        "SCAN_FAILED",
        timeout_seconds=30.0,
    )
    reopened = SimpleCheckpointStore(database)
    assert reopened.static_scan_legacy_history_incomplete(
        identity, "owner/repo", "fingerprint-old"
    )
    assert not reopened.static_scan_legacy_history_incomplete(
        identity, "owner/repo", "fingerprint-new"
    )


def test_repeated_executions_append_while_summary_rewrites_do_not_count(
    tmp_path: Path,
) -> None:
    identity = _identity()
    store = SimpleCheckpointStore(tmp_path / "checkpoints.sqlite3")
    request = _ref(tmp_path, identity, b"request")
    raw = _ref(tmp_path, identity, b"raw")
    error = _ref(tmp_path, identity, b"error")

    store.save_static_scan_attempt(
        identity,
        "owner/repo",
        "fingerprint-1",
        "opengrep",
        "batch-1",
        "BLOCKED",
        None,
        None,
        "OPENGREP_EXECUTION_FAILED",
        request,
    )
    assert store.count_static_scan_executions(identity, "owner/repo") == 0

    for _ in range(2):
        store.record_static_scan_execution(
            identity,
            "owner/repo",
            "fingerprint-1",
            "opengrep",
            "batch-1",
            "BLOCKED",
            raw,
            "OPENGREP_EXECUTION_FAILED",
            request_ref=request,
            error_ref=error,
            timeout_seconds=30.0,
        )
    store.save_static_scan_attempt(
        identity,
        "owner/repo",
        "fingerprint-1",
        "opengrep",
        "batch-1",
        "SUCCEEDED",
        raw,
        None,
        None,
        request,
    )

    reopened = SimpleCheckpointStore(store.database_path)
    history = reopened.list_static_scan_executions(
        identity, "owner/repo", "fingerprint-1", tool="opengrep", run_key="batch-1"
    )
    assert len(history) == 2
    assert history[0].execution_id < history[1].execution_id
    assert tuple(item.error_code for item in history) == (
        "OPENGREP_EXECUTION_FAILED",
        "OPENGREP_EXECUTION_FAILED",
    )
    assert all(item.raw_ref == raw and item.error_ref == error for item in history)
    assert all(
        item.request_ref == request and item.timeout_seconds == 30.0 for item in history
    )
    assert (
        reopened.count_static_scan_executions(
            identity, "owner/repo", "fingerprint-1", tool="opengrep", run_key="batch-1"
        )
        == 2
    )
    assert (
        reopened.list_static_scan_attempts(identity, "owner/repo", "fingerprint-1")[
            0
        ].status
        == "SUCCEEDED"
    )


def test_execution_history_filters_by_exact_identity_and_key(tmp_path: Path) -> None:
    identity = _identity()
    store = SimpleCheckpointStore(tmp_path / "checkpoints.sqlite3")
    for fingerprint, tool, run_key in (
        ("fingerprint-1", "opengrep", "batch-1"),
        ("fingerprint-2", "opengrep", "batch-1"),
        ("fingerprint-1", "semgrep", "batch-2"),
    ):
        store.record_static_scan_execution(
            identity,
            "owner/repo",
            fingerprint,
            tool,
            run_key,
            "BLOCKED",
            None,
            "SCAN_FAILED",
            timeout_seconds=20.0,
        )
    assert store.count_static_scan_executions(identity, "owner/repo") == 3
    assert (
        store.count_static_scan_executions(
            identity, "owner/repo", tool="opengrep", run_key="batch-1"
        )
        == 2
    )
    assert tuple(
        item.fingerprint
        for item in store.list_static_scan_executions(
            identity, "owner/repo", tool="opengrep", run_key="batch-1"
        )
    ) == ("fingerprint-1", "fingerprint-2")
    for other_identity in (
        _identity(analysis_id="analysis-2"),
        _identity(workspace_id="workspace-2"),
        _identity(commit_id="b" * 40),
    ):
        assert store.count_static_scan_executions(other_identity, "owner/repo") == 0
        assert store.list_static_scan_executions(other_identity, "owner/repo") == ()
    assert store.count_static_scan_executions(identity, "owner/other") == 0
    assert (
        store.count_static_scan_executions(
            identity, "owner/repo", "fingerprint-1", tool="opengrep", run_key="batch-2"
        )
        == 0
    )


@pytest.mark.parametrize("ref_name", ["raw_ref", "request_ref", "error_ref"])
def test_execution_refs_are_scoped_before_atomic_insert(
    tmp_path: Path, ref_name: str
) -> None:
    identity = _identity()
    store = SimpleCheckpointStore(tmp_path / "checkpoints.sqlite3")
    wrong = _ref(tmp_path, _identity(workspace_id="other"), b"wrong")
    optional_refs = {ref_name: wrong}

    with pytest.raises(ValueError, match="STATIC_SCAN_REF_SCOPE_MISMATCH"):
        store.record_static_scan_execution(
            identity,
            "owner/repo",
            "fingerprint-1",
            "opengrep",
            "batch-1",
            "BLOCKED",
            optional_refs.get("raw_ref"),
            "SCAN_FAILED",
            request_ref=optional_refs.get("request_ref"),
            error_ref=optional_refs.get("error_ref"),
            timeout_seconds=30.0,
        )
    assert store.count_static_scan_executions(identity, "owner/repo") == 0


@pytest.mark.parametrize("timeout_seconds", [0.0, -1.0, math.inf, math.nan])
def test_execution_timeout_must_be_positive_and_finite(
    tmp_path: Path, timeout_seconds: float
) -> None:
    identity = _identity()
    store = SimpleCheckpointStore(tmp_path / "checkpoints.sqlite3")

    with pytest.raises(ValueError, match="STATIC_SCAN_TIMEOUT_INVALID"):
        store.record_static_scan_execution(
            identity,
            "owner/repo",
            "fingerprint-1",
            "opengrep",
            "batch-1",
            "BLOCKED",
            None,
            "SCAN_FAILED",
            timeout_seconds=timeout_seconds,
        )
    assert store.count_static_scan_executions(identity, "owner/repo") == 0


def test_corrupt_execution_ref_is_reported_instead_of_hiding_attempt(
    tmp_path: Path,
) -> None:
    identity = _identity()
    store = SimpleCheckpointStore(tmp_path / "checkpoints.sqlite3")
    store.record_static_scan_execution(
        identity,
        "owner/repo",
        "fingerprint-1",
        "opengrep",
        "batch-1",
        "BLOCKED",
        None,
        "SCAN_FAILED",
        timeout_seconds=30.0,
    )
    wrong = _ref(tmp_path, _identity(workspace_id="other"), b"wrong")
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE simple_static_scan_executions SET error_ref_json = ?",
            (wrong.model_dump_json(),),
        )

    assert store.count_static_scan_executions(identity, "owner/repo") == 1
    with pytest.raises(ValueError, match="STATIC_SCAN_EXECUTION_REF_INVALID"):
        store.list_static_scan_executions(identity, "owner/repo")


def test_begin_execution_persists_a_started_row_before_completion(
    tmp_path: Path,
) -> None:
    identity = _identity()
    store = SimpleCheckpointStore(tmp_path / "checkpoints.sqlite3")
    request = _ref(tmp_path, identity, b"scan request")

    execution_id = store.begin_static_scan_execution(
        identity,
        "owner/repo",
        "fingerprint-1",
        "opengrep",
        "batch-1",
        request,
        timeout_seconds=30.0,
    )

    reopened = SimpleCheckpointStore(store.database_path)
    executions = reopened.list_static_scan_executions(
        identity, "owner/repo", "fingerprint-1"
    )
    assert len(executions) == 1
    assert executions[0].execution_id == execution_id
    assert executions[0].status == "STARTED"
    assert executions[0].request_ref == request
    assert executions[0].raw_ref is None
    assert executions[0].error_code is None
    assert executions[0].timeout_seconds == 30.0
    assert reopened.count_static_scan_executions(identity, "owner/repo") == 1


def test_finish_execution_updates_started_row_without_appending(tmp_path: Path) -> None:
    identity = _identity()
    store = SimpleCheckpointStore(tmp_path / "checkpoints.sqlite3")
    initial_request = _ref(tmp_path, identity, b"initial request")
    final_request = _ref(tmp_path, identity, b"final request")
    raw = _ref(tmp_path, identity, b"raw scanner output")
    error = _ref(tmp_path, identity, b"scanner error")
    execution_id = store.begin_static_scan_execution(
        identity,
        "owner/repo",
        "fingerprint-1",
        "semgrep",
        "batch-1",
        initial_request,
        timeout_seconds=23.0,
    )

    store.finish_static_scan_execution(
        execution_id,
        identity,
        "BLOCKED",
        raw,
        "SEMGREP_PARTIAL_SCAN",
        final_request,
        error,
    )

    reopened = SimpleCheckpointStore(store.database_path)
    executions = reopened.list_static_scan_executions(identity, "owner/repo")
    assert len(executions) == 1
    assert executions[0].execution_id == execution_id
    assert executions[0].status == "BLOCKED"
    assert executions[0].raw_ref == raw
    assert executions[0].error_code == "SEMGREP_PARTIAL_SCAN"
    assert executions[0].request_ref == final_request
    assert executions[0].error_ref == error
    assert executions[0].timeout_seconds == 23.0


@pytest.mark.parametrize(
    "other_identity",
    [
        _identity(analysis_id="other-analysis"),
        _identity(workspace_id="other-workspace"),
        _identity(commit_id="b" * 40),
    ],
)
def test_finish_rejects_other_identity_without_changing_started_row(
    tmp_path: Path, other_identity: CheckpointIdentity
) -> None:
    identity = _identity()
    store = SimpleCheckpointStore(tmp_path / "checkpoints.sqlite3")
    execution_id = store.begin_static_scan_execution(
        identity,
        "owner/repo",
        "fingerprint-1",
        "opengrep",
        "batch-1",
        None,
        timeout_seconds=30.0,
    )

    with pytest.raises(ValueError, match="STATIC_SCAN_EXECUTION_NOT_STARTED"):
        store.finish_static_scan_execution(
            execution_id, other_identity, "BLOCKED", None, "SCAN_FAILED", None, None
        )

    assert store.list_static_scan_executions(identity, "owner/repo")[0].status == (
        "STARTED"
    )
    assert store.count_static_scan_executions(other_identity, "owner/repo") == 0


def test_finish_rejects_second_finalization_and_preserves_first_result(
    tmp_path: Path,
) -> None:
    identity = _identity()
    store = SimpleCheckpointStore(tmp_path / "checkpoints.sqlite3")
    request = _ref(tmp_path, identity, b"request")
    error = _ref(tmp_path, identity, b"first error")
    execution_id = store.begin_static_scan_execution(
        identity,
        "owner/repo",
        "fingerprint-1",
        "semgrep",
        "batch-1",
        request,
        timeout_seconds=30.0,
    )
    store.finish_static_scan_execution(
        execution_id, identity, "BLOCKED", None, "SCAN_FAILED", None, error
    )

    with pytest.raises(ValueError, match="STATIC_SCAN_EXECUTION_NOT_STARTED"):
        store.finish_static_scan_execution(
            execution_id, identity, "SUCCEEDED", None, None, None, None
        )

    executions = store.list_static_scan_executions(identity, "owner/repo")
    assert len(executions) == 1
    assert executions[0].status == "BLOCKED"
    assert executions[0].error_code == "SCAN_FAILED"
    assert executions[0].error_ref == error
    assert executions[0].request_ref == request


def test_finish_rejects_legacy_terminal_row(tmp_path: Path) -> None:
    identity = _identity()
    store = SimpleCheckpointStore(tmp_path / "checkpoints.sqlite3")
    execution_id = store.record_static_scan_execution(
        identity,
        "owner/repo",
        "fingerprint-1",
        "opengrep",
        "batch-1",
        "BLOCKED",
        None,
        "SCAN_FAILED",
        timeout_seconds=30.0,
    )

    with pytest.raises(ValueError, match="STATIC_SCAN_EXECUTION_NOT_STARTED"):
        store.finish_static_scan_execution(
            execution_id, identity, "SUCCEEDED", None, None, None, None
        )

    assert store.list_static_scan_executions(identity, "owner/repo")[0].status == (
        "BLOCKED"
    )


def test_begin_and_finish_validate_refs_before_mutating_a_row(tmp_path: Path) -> None:
    identity = _identity()
    store = SimpleCheckpointStore(tmp_path / "checkpoints.sqlite3")
    wrong = _ref(tmp_path, _identity(workspace_id="other"), b"wrong")

    with pytest.raises(ValueError, match="STATIC_SCAN_REF_SCOPE_MISMATCH"):
        store.begin_static_scan_execution(
            identity,
            "owner/repo",
            "fingerprint-1",
            "opengrep",
            "batch-1",
            wrong,
            timeout_seconds=30.0,
        )
    assert store.count_static_scan_executions(identity, "owner/repo") == 0

    execution_id = store.begin_static_scan_execution(
        identity,
        "owner/repo",
        "fingerprint-1",
        "opengrep",
        "batch-1",
        None,
        timeout_seconds=30.0,
    )
    with pytest.raises(ValueError, match="STATIC_SCAN_REF_SCOPE_MISMATCH"):
        store.finish_static_scan_execution(
            execution_id, identity, "BLOCKED", wrong, "SCAN_FAILED", None, None
        )
    assert store.list_static_scan_executions(identity, "owner/repo")[0].status == (
        "STARTED"
    )
