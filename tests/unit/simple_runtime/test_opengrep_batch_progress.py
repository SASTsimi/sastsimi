from __future__ import annotations

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


def test_progress_survives_reopen(tmp_path: Path) -> None:
    identity = _identity()
    ref = _ref(tmp_path, identity, b'{"results":[]}')
    store = SimpleCheckpointStore(tmp_path / "checkpoints.sqlite3")

    store.save_opengrep_batch(identity, "owner/repo", "fingerprint-1", "batch-1", ref)
    store.save_opengrep_batch(identity, "owner/repo", "fingerprint-1", "batch-1", ref)
    reopened = SimpleCheckpointStore(store.database_path)

    assert (
        reopened.opengrep_batch_ref(identity, "owner/repo", "fingerprint-1", "batch-1")
        == ref
    )
    other = _ref(tmp_path, identity, b'{"results":[1]}')
    with pytest.raises(ValueError, match="OPENGREP_BATCH_PROGRESS_CONFLICT"):
        reopened.save_opengrep_batch(
            identity, "owner/repo", "fingerprint-1", "batch-1", other
        )


def test_progress_key_is_exact(tmp_path: Path) -> None:
    identity = _identity()
    ref = _ref(tmp_path, identity, b'{"results":[]}')
    store = SimpleCheckpointStore(tmp_path / "checkpoints.sqlite3")
    store.save_opengrep_batch(identity, "owner/repo", "fingerprint-1", "batch-1", ref)

    alternatives = (
        (_identity(analysis_id="analysis-2"), "owner/repo", "fingerprint-1", "batch-1"),
        (
            _identity(workspace_id="workspace-2"),
            "owner/repo",
            "fingerprint-1",
            "batch-1",
        ),
        (_identity(commit_id="b" * 40), "owner/repo", "fingerprint-1", "batch-1"),
        (identity, "owner/other", "fingerprint-1", "batch-1"),
        (identity, "owner/repo", "fingerprint-2", "batch-1"),
        (identity, "owner/repo", "fingerprint-1", "batch-2"),
    )
    for alternate in alternatives:
        assert store.opengrep_batch_ref(*alternate) is None


def test_invalid_ref_can_be_replaced_conditionally(tmp_path: Path) -> None:
    identity = _identity()
    store = SimpleCheckpointStore(tmp_path / "checkpoints.sqlite3")
    first = _ref(tmp_path, identity, b"first")
    second = _ref(tmp_path, identity, b"second")
    store.save_opengrep_batch(identity, "owner/repo", "fingerprint-1", "batch-1", first)

    with pytest.raises(ValueError, match="OPENGREP_BATCH_PROGRESS_CONFLICT"):
        store.save_opengrep_batch(
            identity,
            "owner/repo",
            "fingerprint-1",
            "batch-1",
            second,
            replaces=second,
        )
    assert (
        store.opengrep_batch_ref(identity, "owner/repo", "fingerprint-1", "batch-1")
        == first
    )

    wrong_scope = _ref(tmp_path, _identity(workspace_id="other"), b"third")
    with pytest.raises(ValueError, match="OPENGREP_BATCH_REF_SCOPE_MISMATCH"):
        store.save_opengrep_batch(
            identity,
            "owner/repo",
            "fingerprint-1",
            "batch-1",
            wrong_scope,
            replaces=first,
        )
    store.save_opengrep_batch(
        identity,
        "owner/repo",
        "fingerprint-1",
        "batch-1",
        second,
        replaces=first,
    )
    assert (
        store.opengrep_batch_ref(identity, "owner/repo", "fingerprint-1", "batch-1")
        == second
    )


@pytest.mark.parametrize(
    "damage", ["invalid-json", "wrong-scope", "wrong-kind", "wrong-id"]
)
def test_malformed_progress_row_is_replaced_after_rescan(
    tmp_path: Path, damage: str
) -> None:
    identity = _identity()
    store = SimpleCheckpointStore(tmp_path / "checkpoints.sqlite3")
    first = _ref(tmp_path, identity, b"first")
    second = _ref(tmp_path, identity, b"second")
    store.save_opengrep_batch(identity, "owner/repo", "fingerprint-1", "batch-1", first)
    if damage == "invalid-json":
        malformed = "{not-json"
    elif damage == "wrong-scope":
        malformed = _ref(
            tmp_path, _identity(workspace_id="other"), b"other"
        ).model_dump_json()
    else:
        field = "data_kind" if damage == "wrong-kind" else "stored_data_id"
        value = "record" if damage == "wrong-kind" else "0" * 64
        malformed = StoredDataRef.model_validate(
            first.model_dump() | {field: value}
        ).model_dump_json()
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE simple_opengrep_batch_progress SET ref_json = ?",
            (malformed,),
        )

    assert (
        store.opengrep_batch_ref(identity, "owner/repo", "fingerprint-1", "batch-1")
        is None
    )
    store.save_opengrep_batch(
        identity, "owner/repo", "fingerprint-1", "batch-1", second
    )
    assert (
        store.opengrep_batch_ref(identity, "owner/repo", "fingerprint-1", "batch-1")
        == second
    )


def test_static_attempts_are_fingerprinted_and_scoped(tmp_path: Path) -> None:
    identity = _identity()
    store = SimpleCheckpointStore(tmp_path / "checkpoints.sqlite3")
    raw = _ref(tmp_path, identity, b'{"results": []}')
    coverage = _ref(tmp_path, identity, b'{"gaps": []}')
    store.save_static_scan_attempt(
        identity,
        "owner/repo",
        "fingerprint-1",
        "semgrep",
        "batch-1",
        "SUCCEEDED",
        raw,
        coverage,
        None,
    )
    reopened = SimpleCheckpointStore(store.database_path)
    attempts = reopened.list_static_scan_attempts(
        identity, "owner/repo", "fingerprint-1"
    )
    assert len(attempts) == 1
    assert attempts[0].raw_ref == raw
    assert attempts[0].coverage_ref == coverage
    assert attempts[0].status == "SUCCEEDED"
    assert (
        reopened.list_static_scan_attempts(identity, "owner/repo", "fingerprint-2")
        == ()
    )
    with pytest.raises(ValueError, match="STATIC_SCAN_REF_SCOPE_MISMATCH"):
        reopened.save_static_scan_attempt(
            identity,
            "owner/repo",
            "fingerprint-1",
            "semgrep",
            "batch-2",
            "SUCCEEDED",
            _ref(tmp_path, _identity(workspace_id="other"), b"bad"),
            None,
            None,
        )


def test_legacy_static_attempt_migration_locks_before_schema_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    database = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE simple_static_scan_attempts (analysis_id TEXT)"
        )
        connection.execute(
            "INSERT INTO simple_static_scan_attempts VALUES ('existing')"
        )
    statements: list[str] = []
    original_connect = SimpleCheckpointStore._connect

    def traced_connect(self: SimpleCheckpointStore) -> sqlite3.Connection:
        connection = original_connect(self)
        connection.set_trace_callback(statements.append)
        return connection

    monkeypatch.setattr(SimpleCheckpointStore, "_connect", traced_connect)
    SimpleCheckpointStore(database)
    schema_read = next(
        index
        for index, statement in enumerate(statements)
        if "PRAGMA table_info(simple_static_scan_attempts)" in statement
    )
    assert any(
        statement.strip().upper() == "BEGIN IMMEDIATE"
        for statement in statements[:schema_read]
    )
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT analysis_id FROM simple_static_scan_attempts"
        ).fetchone() == ("existing",)
        assert "request_ref_json" in {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info(simple_static_scan_attempts)"
            )
        }


def test_static_failed_attempt_can_have_no_raw_output(tmp_path: Path) -> None:
    identity = _identity()
    store = SimpleCheckpointStore(tmp_path / "checkpoints.sqlite3")
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
    )
    attempt = store.list_static_scan_attempts(identity, "owner/repo", "fingerprint-1")[
        0
    ]
    assert attempt.raw_ref is None
    assert attempt.error_code == "OPENGREP_EXECUTION_FAILED"


def test_static_attempt_run_key_lookup_is_newest_first_and_exactly_scoped(
    tmp_path: Path,
) -> None:
    identity = _identity()
    store = SimpleCheckpointStore(tmp_path / "checkpoints.sqlite3")
    first = _ref(tmp_path, identity, b"first")
    second = _ref(tmp_path, identity, b"second")
    for fingerprint, ref in (("older", first), ("newer", second)):
        store.save_static_scan_attempt(
            identity,
            "owner/repo",
            fingerprint,
            "opengrep",
            "batch-1",
            "BLOCKED",
            ref,
            None,
            "OPENGREP_PARTIAL_SCAN",
        )
    found = store.list_static_scan_attempts_for_run_key(
        identity, "owner/repo", "opengrep", "batch-1"
    )
    assert tuple(item.raw_ref for item in found) == (second, first)
    for other_identity, repository, tool, run_key in (
        (_identity(analysis_id="analysis-2"), "owner/repo", "opengrep", "batch-1"),
        (_identity(workspace_id="workspace-2"), "owner/repo", "opengrep", "batch-1"),
        (_identity(commit_id="b" * 40), "owner/repo", "opengrep", "batch-1"),
        (identity, "owner/other", "opengrep", "batch-1"),
        (identity, "owner/repo", "semgrep", "batch-1"),
        (identity, "owner/repo", "opengrep", "batch-2"),
    ):
        assert (
            store.list_static_scan_attempts_for_run_key(
                other_identity, repository, tool, run_key
            )
            == ()
        )


def test_opengrep_partial_proofs_are_scoped_and_do_not_claim_completed_batch(
    tmp_path: Path,
) -> None:
    identity = _identity()
    store = SimpleCheckpointStore(tmp_path / "checkpoints.sqlite3")
    first = _ref(tmp_path, identity, b"first-partial")
    second = _ref(tmp_path, identity, b"second-partial")
    store.save_opengrep_partial_proof(
        identity, "owner/repo", "fingerprint-a", "batch-1", first
    )
    store.save_opengrep_partial_proof(
        identity, "owner/repo", "fingerprint-b", "batch-1", second
    )
    assert (
        store.opengrep_batch_ref(identity, "owner/repo", "fingerprint-a", "batch-1")
        is None
    )
    assert store.opengrep_partial_refs(
        identity, "owner/repo", frozenset({"fingerprint-a"}), "batch-1"
    ) == (first,)
    assert store.opengrep_partial_refs(
        identity,
        "owner/repo",
        frozenset({"fingerprint-a", "fingerprint-b"}),
        "batch-1",
    ) == (second, first)
    assert (
        store.opengrep_partial_refs(
            _identity(analysis_id="another"),
            "owner/repo",
            frozenset({"fingerprint-a", "fingerprint-b"}),
            "batch-1",
        )
        == ()
    )
    assert (
        store.opengrep_partial_refs(
            identity,
            "owner/other",
            frozenset({"fingerprint-a", "fingerprint-b"}),
            "batch-1",
        )
        == ()
    )
