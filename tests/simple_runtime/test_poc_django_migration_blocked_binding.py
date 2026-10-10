"""A candidate replay must retain the original migration-setting source proof."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from sastsimi.simple_runtime.models import SimpleStage, StageStatus
from sastsimi.simple_runtime.recovery import (
    migration_settings_blocked_replay_binding,
    migration_settings_replay_binding,
)
from tests.simple_runtime.test_poc_django_migration_settings_replay import (
    _blocked_migration_candidate_attempt,
    _exhausted_migration_attempt,
)


def test_blocked_migration_candidate_can_rebind_original_source_proof(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_migration_attempt(tmp_path)
    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        exhausted, artifacts
    )
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-4"
    )
    blocked = running.model_copy(
        update={
            "status": StageStatus.BLOCKED,
            "error_code": "RECOVERY_EXHAUSTED",
            "retryable": False,
        }
    )
    proof = migration_settings_blocked_replay_binding(blocked, artifacts)
    assert proof is not None
    assert proof[0] == "HELPDESK_TEAMS_MODE_ENABLED"
    assert proof[1].attempt_number == 3
    with pytest.raises(
        ValueError, match="POC_DJANGO_MIGRATION_SETTINGS_REPLAY_UNBOUND"
    ):
        migration_settings_replay_binding(blocked, artifacts)
    assert (
        migration_settings_blocked_replay_binding(
            blocked.model_copy(update={"error_code": "OTHER"}), artifacts
        )
        is None
    )
    assert (
        migration_settings_blocked_replay_binding(
            blocked.model_copy(update={"attempt_number": 9}), artifacts
        )
        is None
    )


def test_candidate_only_replay_rebinds_original_pinned_candidate(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, original_rule_ref = _blocked_migration_candidate_attempt(
        tmp_path
    )
    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        stopped, artifacts
    )
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-5"
    )
    proof = migration_settings_replay_binding(running, artifacts)
    assert proof is not None
    assert proof[0] == "HELPDESK_TEAMS_MODE_ENABLED"
    assert proof[1].attempt_number == 3
    assert original_rule_ref in running.recovery_decision_refs


@pytest.mark.parametrize("corruption", ["cross_commit", "old_stage_version"])
def test_candidate_replay_rejects_stale_root_checkpoint(
    tmp_path: Path, corruption: str
) -> None:
    store, artifacts, stopped, _ = _blocked_migration_candidate_attempt(tmp_path)
    root_identity = stopped.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    altered = root.model_copy(
        update=(
            {"identity": root_identity.model_copy(update={"commit_id": "f" * 40})}
            if corruption == "cross_commit"
            else {"stage_version": "obsolete"}
        )
    )
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE simple_runtime_checkpoints SET checkpoint_json = ? "
            "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
            (
                altered.model_dump_json(),
                root_identity.analysis_id,
                store._hypothesis_key(root_identity),
                SimpleStage.HYPOTHESIS_DONE.value,
            ),
        )
    with pytest.raises(ValueError, match="ROOT_INVALID"):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            stopped, artifacts
        )
