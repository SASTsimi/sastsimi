from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.composition.simple_runtime_composition import (
    PublicSimpleRuntimeApplication,
)
from sastsimi.simple_runtime.models import (
    MAX_RECOVERY_ATTEMPTS,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _exhausted(identity: CheckpointIdentity) -> StageCheckpoint:
    return StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.BLOCKED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-3",
        attempt_number=MAX_RECOVERY_ATTEMPTS,
        error_code="RECOVERY_EXHAUSTED",
        retryable=False,
    )


def _retryable_blocked(identity: CheckpointIdentity) -> StageCheckpoint:
    return StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.BLOCKED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-2",
        attempt_number=2,
        error_code="CURSOR_TIMED_OUT",
        retryable=True,
    )


def test_reopen_exhausted_grants_exactly_one_attempt_and_drops_downstream(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    exhausted = _exhausted(identity)
    store.save_checkpoint(exhausted)
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.POC_EXECUTION_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
        )
    )

    pending = store.reopen_for_manual_retry(exhausted)

    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == MAX_RECOVERY_ATTEMPTS - 1
    assert pending.error_code is None
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    with pytest.raises(ValueError, match="MANUAL_RETRY_CHECKPOINT_STALE"):
        store.reopen_for_manual_retry(exhausted)


def test_reopen_retryable_blocked_bypasses_recovery_stop(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    blocked = _retryable_blocked(identity)
    store.save_checkpoint(blocked)

    pending = store.reopen_for_manual_retry(blocked)

    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 2
    assert pending.error_code is None
    assert pending.retryable is False


def test_public_retry_backs_up_database_and_reopens_display_analysis(
    tmp_path: Path,
) -> None:
    config = cast(Any, SimpleNamespace(data_dir=tmp_path))
    application = PublicSimpleRuntimeApplication(config, cast(Any, None))
    exact = "analysis-1"
    display = application._display.get_or_allocate(exact)
    application._store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=exact,
            display_analysis_id=display,
            workspace_id="workspace-1",
            commit_id="commit-1",
            repository="https://example.invalid/repository.git",
            hypothesis_ids=("hypothesis-1",),
        )
    )
    identity = CheckpointIdentity(
        analysis_id=exact,
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    application._store.save_checkpoint(_exhausted(identity))

    result = application.retry(display)

    backup = tmp_path / str(result["backup_path"])
    assert result["status"] == "READY_TO_RESUME"
    assert result["hypothesis_id"] == "hypothesis-1"
    assert backup.is_file()
    assert backup.stat().st_size > 0


def test_public_retry_reopens_current_retryable_blocked_checkpoint(
    tmp_path: Path,
) -> None:
    config = cast(Any, SimpleNamespace(data_dir=tmp_path))
    application = PublicSimpleRuntimeApplication(config, cast(Any, None))
    exact = "analysis-1"
    display = application._display.get_or_allocate(exact)
    application._store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=exact,
            display_analysis_id=display,
            workspace_id="workspace-1",
            commit_id="commit-1",
            repository="https://example.invalid/repository.git",
            hypothesis_ids=("hypothesis-1",),
        )
    )
    identity = CheckpointIdentity(
        analysis_id=exact,
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    application._store.save_checkpoint(_retryable_blocked(identity))

    result = application.retry(display)

    assert result["status"] == "READY_TO_RESUME"
    assert result["retry_source_error"] == "CURSOR_TIMED_OUT"
    assert (
        application._store.require(identity, SimpleStage.POC_CANDIDATE_DONE).status
        is StageStatus.PENDING
    )


def test_public_retry_skips_non_exhausted_analysis_without_backup(
    tmp_path: Path,
) -> None:
    config = cast(Any, SimpleNamespace(data_dir=tmp_path))
    application = PublicSimpleRuntimeApplication(config, cast(Any, None))
    exact = "analysis-1"
    display = application._display.get_or_allocate(exact)
    application._store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=exact,
            display_analysis_id=display,
            workspace_id="workspace-1",
            commit_id="commit-1",
            repository="https://example.invalid/repository.git",
        )
    )
    identity = CheckpointIdentity(
        analysis_id=exact,
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    application._store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.STATIC_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
        )
    )

    result = application.retry(display)

    assert result["retry_skipped_reason"] == "ANALYSIS_NOT_MANUALLY_RETRYABLE"
    assert not (tmp_path / "db" / "backups").exists()
