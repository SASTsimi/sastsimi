import hashlib
import json
from pathlib import Path

import pytest

from sastsimi.contracts.ids import CommitId, WorkspaceId
from sastsimi.contracts.work import WorkExecutionState
from tests.unit.contracts.test_core_models import work


def test_record_candidates_are_invisible_and_exact_revisions_are_immutable(
    tmp_path: Path,
) -> None:
    from sastsimi.storage.database import Database
    from sastsimi.storage.migrations import upgrade
    from sastsimi.storage.repositories import SQLiteRecordStore

    database = Database(tmp_path / "db")
    upgrade(database)
    store = SQLiteRecordStore(database)
    record = WorkExecutionState.model_validate_json(json.dumps(work()))
    ref = store.stage_record(record)
    with pytest.raises(LookupError):
        store.get_exact(ref)
    with database.write() as connection:
        store.publish(connection, ref)
    assert store.get_exact(ref) == record
    assert store.stage_record(record) == ref
    with pytest.raises(ValueError, match="RECORD"):
        store.stage_record(record.model_copy(update={"input_hash": "f" * 64}))
    with pytest.raises(ValueError):
        store.get_exact(ref.model_copy(update={"content_hash": "f" * 64}))


def test_artifact_is_durable_scoped_and_every_read_rechecks_hash(
    tmp_path: Path,
) -> None:
    from sastsimi.storage.artifact_store import LocalArtifactStore

    store = LocalArtifactStore(
        tmp_path / "artifacts", WorkspaceId("w1"), CommitId("c1")
    )
    staged = store.stage_bytes(b"evidence", "text/plain")
    assert list((tmp_path / "staging").iterdir())
    ref = store.commit(staged)
    assert ref.content_hash == hashlib.sha256(b"evidence").hexdigest()
    assert store.open_verified(ref).read() == b"evidence"
    assert store.commit(staged) == ref
    with pytest.raises(ValueError, match="WORKSPACE"):
        store.open_verified(ref.model_copy(update={"workspace_id": WorkspaceId("w2")}))
    store.path_for(ref.content_hash).write_bytes(b"tampered")
    with pytest.raises(ValueError, match="HASH"):
        store.open_verified(ref)


def test_revision_must_resolve_exact_predecessor_and_cannot_fork(
    tmp_path: Path,
) -> None:
    from sastsimi.storage.database import Database
    from sastsimi.storage.migrations import upgrade
    from sastsimi.storage.repositories import SQLiteRecordStore

    database = Database(tmp_path / "db")
    upgrade(database)
    store = SQLiteRecordStore(database)
    data = work()
    data["meta"].update(record_id="r2", previous_record_id="r1", revision_number=2)
    next_record = WorkExecutionState.model_validate_json(json.dumps(data))
    ref = store.stage_record(next_record)
    with pytest.raises(ValueError, match="predecessor"), database.write() as connection:
        store.publish(connection, ref)
