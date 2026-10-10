"""Direct recovery transactions refresh the dashboard after durable commit."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import StageCheckpoint, StageStatus
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from tests.simple_runtime.test_a002_auth_required_replay import _failed_auth_candidate
from tests.simple_runtime.test_initial_exhaustion_replay import _exhausted_initial
from tests.simple_runtime.test_poc_django_migration_settings_replay import (
    _blocked_migration_candidate_attempt,
)
from tests.simple_runtime.test_poc_exit_one_inconclusive_promotion import (
    _seed as _exit_one_seed,
)
from tests.simple_runtime.test_poc_urlconf_exhaustion_replay import (
    _blocked_candidate_constraint,
)
from tests.simple_runtime.test_poc_validator_correction_replay import (
    _blocked_validator_candidate,
)


@pytest.mark.parametrize(
    "case",
    (
        "initial_environment",
        "validator_correction",
        "candidate_constraint",
        "django_migration_candidate",
        "auth_required",
        "exit_one_inconclusive",
    ),
)
def test_direct_recovery_sink_projects_once_after_commit(
    tmp_path: Path, case: str
) -> None:
    if case == "initial_environment":
        seeded_store, artifacts, stopped = _exhausted_initial(
            tmp_path, error_code="PINNED_CONTEXT_UNAVAILABLE"
        )
    elif case == "validator_correction":
        seeded_store, artifacts, stopped = _blocked_validator_candidate(tmp_path)
    elif case == "candidate_constraint":
        seeded_store, artifacts, stopped = _blocked_candidate_constraint(tmp_path)
    elif case == "django_migration_candidate":
        seeded_store, artifacts, stopped, _ = _blocked_migration_candidate_attempt(
            tmp_path
        )
    elif case == "auth_required":
        seeded_store, artifacts, stopped = _failed_auth_candidate(tmp_path)
    elif case == "exit_one_inconclusive":
        seeded_store, artifacts, stopped = _exit_one_seed(tmp_path)
    else:
        raise AssertionError(case)

    def replay(
        store: SimpleCheckpointStore,
        data: SimpleArtifactRepository,
        item: StageCheckpoint,
        crash: bool,
    ) -> StageCheckpoint:
        if case == "initial_environment":
            return store.prepare_initial_environment_exhaustion_replay(
                item, data, fail_before_commit=crash
            )
        if case == "validator_correction":
            return store.prepare_poc_generated_input_replay(
                item, data, fail_before_commit=crash
            )
        if case == "candidate_constraint":
            return store.prepare_poc_candidate_constraint_replay(
                item, data, fail_before_commit=crash
            )
        if case == "django_migration_candidate":
            return store.prepare_poc_django_migration_settings_exhaustion_replay(
                item, data, fail_before_commit=crash
            )
        if case == "auth_required":
            return store.prepare_auth_required_replay(
                item, data, fail_before_commit=crash
            )
        return store.promote_exit_one_inconclusive_execution(item, artifacts=data)

    projected: list[str] = []

    def project(data_dir: Path, analysis_id: str) -> None:
        assert data_dir == tmp_path / "data"
        with sqlite3.connect(seeded_store.database_path) as connection:
            row = connection.execute(
                "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
                (analysis_id, stopped.identity.hypothesis_id, stopped.stage.value),
            ).fetchone()
        assert row is not None
        visible = StageCheckpoint.model_validate_json(row[0])
        assert visible.status is (
            StageStatus.SUCCEEDED
            if case == "exit_one_inconclusive"
            else StageStatus.PENDING
        )
        projected.append(analysis_id)

    store = SimpleCheckpointStore(
        seeded_store.database_path,
        artifact_data_dir=tmp_path / "data",
        post_commit_projection=project,
    )
    if case != "exit_one_inconclusive":
        with pytest.raises(RuntimeError, match="simulated crash"):
            replay(store, artifacts, stopped, True)
        assert store.require(stopped.identity, stopped.stage) == stopped
        assert projected == []

    completed = replay(store, artifacts, stopped, False)

    assert store.require(stopped.identity, stopped.stage) == completed
    assert projected == [stopped.identity.analysis_id]
    with pytest.raises(ValueError):
        replay(store, artifacts, stopped, False)
    assert projected == [stopped.identity.analysis_id]
