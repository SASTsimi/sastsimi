"""A final primitive-pool batch is resumed only from its exact scoped proof."""

from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def test_chaining_pool_batch_is_idempotent_and_scoped(tmp_path: Path) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    store = SimpleCheckpointStore(tmp_path / "data" / "db" / "sastsimi.sqlite3")
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    first = artifacts.put_json({"kind": "simple_chaining_result", "children": []})
    other = artifacts.put_json({"kind": "simple_chaining_result", "children": [1]})

    assert store.list_chaining_pool_batches(identity, "pool-1") == {}
    assert store.save_chaining_pool_batch(identity, "pool-1", 0, 2, first)
    assert not store.save_chaining_pool_batch(identity, "pool-1", 0, 2, first)
    assert store.list_chaining_pool_batches(identity, "pool-1") == {0: (2, first)}
    assert store.list_chaining_pool_batches(identity, "pool-2") == {}
    assert SimpleCheckpointStore(store.database_path).list_chaining_pool_batches(
        identity, "pool-1"
    ) == {0: (2, first)}

    with pytest.raises(ValueError, match="CHAINING_POOL_BATCH_CONFLICT"):
        store.save_chaining_pool_batch(identity, "pool-1", 0, 2, other)
    with pytest.raises(ValueError, match="CHAINING_POOL_BATCH_CONFLICT"):
        store.save_chaining_pool_batch(identity, "pool-1", 0, 3, first)
