"""Projection contract for direct replay transactions that return checkpoints."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.models import (
    SimpleStage,
    StageCheckpoint,
    StageStatus,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from tests.simple_runtime.test_legacy_import_stop_replan import _seed
from tests.simple_runtime.test_poc_extract_exhaustion_replay import _exhausted_extract
from tests.simple_runtime.test_poc_placeholder_exhaustion_replay import (
    _placeholder_exhaustion,
)
from tests.simple_runtime.test_poc_sensitive_replay import _sensitive_stop
from tests.simple_runtime.test_report_validator_replay import _blocked_report


@pytest.mark.parametrize(
    "case",
    ("report", "extract", "placeholder", "sensitive", "fallback"),
)
def test_replay_projects_once_only_after_durable_commit(
    tmp_path: Path, case: str
) -> None:
    draft_ref: StoredDataRef | None = None
    if case == "report":
        seeded_store, artifacts, stopped, draft_ref, _ = _blocked_report(tmp_path)
    elif case == "extract":
        seeded_store, artifacts, stopped = _exhausted_extract(tmp_path)
    elif case == "placeholder":
        seeded_store, artifacts, stopped = _placeholder_exhaustion(tmp_path)
    elif case == "sensitive":
        seeded_store, artifacts, stopped = _sensitive_stop(tmp_path)
    else:
        seeded_store, artifacts, stopped, _ = _seed(
            tmp_path,
            stderr=b"TypeError: mismatch\nTraceback: __call__ > handler",
        )

    expected_stage = (
        stopped.stage
        if case in {"report", "placeholder", "sensitive"}
        else SimpleStage.POC_CANDIDATE_DONE
    )
    projected: list[str] = []

    def project(data_dir: Path, analysis_id: str) -> None:
        assert data_dir == tmp_path / "data"
        with sqlite3.connect(seeded_store.database_path) as connection:
            row = connection.execute(
                "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
                (analysis_id, stopped.identity.hypothesis_id, expected_stage.value),
            ).fetchone()
        assert row is not None
        visible = StageCheckpoint.model_validate_json(row[0])
        assert visible.status is StageStatus.PENDING
        projected.append(analysis_id)

    store = SimpleCheckpointStore(
        seeded_store.database_path,
        artifact_data_dir=tmp_path / "data",
        post_commit_projection=project,
    )

    def replay(crash: bool) -> StageCheckpoint:
        if case == "report":
            assert draft_ref is not None
            return store.prepare_report_validator_replay(
                stopped, draft_ref, artifacts, fail_before_commit=crash
            )
        if case == "extract":
            return store.prepare_poc_extract_exhaustion_replay(
                stopped, artifacts, fail_before_commit=crash
            )
        if case == "placeholder":
            return store.prepare_poc_placeholder_exhaustion_replay(
                stopped, artifacts, fail_before_commit=crash
            )
        if case == "sensitive":
            return store.prepare_poc_sensitive_content_replay(
                stopped, artifacts, fail_before_commit=crash
            )
        return store.prepare_fallback_poc_stop_replan(
            stopped, artifacts, fail_before_commit=crash
        )

    with pytest.raises(RuntimeError, match="simulated crash"):
        replay(True)
    assert store.require(stopped.identity, stopped.stage) == stopped
    assert projected == []

    pending = replay(False)
    assert pending.stage is expected_stage
    assert store.require(stopped.identity, expected_stage) == pending
    assert projected == [stopped.identity.analysis_id]

    with pytest.raises(ValueError):
        replay(False)
    assert projected == [stopped.identity.analysis_id]
