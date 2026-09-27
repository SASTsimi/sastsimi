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
