from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor

import pytest

from sastsimi.contracts.ids import CommitId, RecordId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore


def _ref(name: str) -> StoredDataRef:
    digest = hashlib.sha256(name.encode()).hexdigest()
    return StoredDataRef(
        stored_data_id=StoredDataId(f"stored-{name}"),
        data_kind="finding",
        content_hash=digest,
        workspace_id=WorkspaceId("workspace-1"),
        commit_id=CommitId("commit-1"),
        record_id=RecordId(f"record-{name}"),
    )


def test_same_finding_keeps_display_id_and_next_finding_increments(tmp_path) -> None:
    store = FindingDisplayIdStore(tmp_path / "sastsimi.sqlite3")

    assert store.get_or_allocate("analysis-1", _ref("finding-a")) == "F-001"
    assert store.get_or_allocate("analysis-1", _ref("finding-a")) == "F-001"
    assert store.get_or_allocate("analysis-1", _ref("finding-b")) == "F-002"
    assert store.get_or_allocate("analysis-2", _ref("finding-a")) == "F-001"
    assert store.resolve("analysis-1", "F-002") == _ref("finding-b")


def test_concurrent_allocation_never_reuses_a_number(tmp_path) -> None:
    database = tmp_path / "sastsimi.sqlite3"

    def allocate(name: str) -> str:
        return FindingDisplayIdStore(database).get_or_allocate("analysis-1", _ref(name))

    with ThreadPoolExecutor(max_workers=2) as pool:
        values = tuple(pool.map(allocate, ("finding-a", "finding-b")))

    assert set(values) == {"F-001", "F-002"}


@pytest.mark.parametrize("display_id", ["F-1", "f-001", "../F-001", "F-001.md"])
def test_resolve_rejects_invalid_display_id(tmp_path, display_id: str) -> None:
    store = FindingDisplayIdStore(tmp_path / "sastsimi.sqlite3")

    with pytest.raises(ValueError, match="FINDING_DISPLAY_ID_INVALID"):
        store.resolve("analysis-1", display_id)


# mypy: disable-error-code="no-untyped-def"
