"""Durable per-role evidence must replay only for the exact child inputs."""

from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def test_role_evidence_replays_only_for_exact_input_hash(tmp_path: Path) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    store = SimpleCheckpointStore(tmp_path / "data" / "db" / "sastsimi.sqlite3")
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    first = artifacts.put_json({"kind": "simple_pro_evidence", "result": {}})
    second = artifacts.put_json({"kind": "simple_con_evidence", "result": {}})

    assert store.get_pro_con_batch_evidence(identity, "pro", "input-1") is None
    assert store.save_pro_con_batch_evidence(identity, "pro", "input-1", first)
    assert not store.save_pro_con_batch_evidence(identity, "pro", "input-1", first)
    assert store.save_pro_con_batch_evidence(identity, "con", "input-1", second)
    assert store.get_pro_con_batch_evidence(identity, "pro", "input-1") == first
    assert store.get_pro_con_batch_evidence(identity, "con", "input-1") == second
    assert store.get_pro_con_batch_evidence(identity, "pro", "input-2") is None

    reopened = SimpleCheckpointStore(store.database_path)
    assert reopened.get_pro_con_batch_evidence(identity, "pro", "input-1") == first
    with pytest.raises(ValueError, match="PRO_CON_BATCH_EVIDENCE_CONFLICT"):
        reopened.save_pro_con_batch_evidence(identity, "pro", "input-1", second)
