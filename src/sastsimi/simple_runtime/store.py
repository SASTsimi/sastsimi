from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from sastsimi.contracts.refs import StoredDataRef

from .models import (
    STAGE_ORDER,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageResult,
    StageStatus,
    input_reference_hash,
)


class SimpleCheckpointStore:
    """Atomic checkpoint storage for the single-process local runtime."""

    def __init__(self, database_path: str | Path) -> None:
        self._database_path = Path(database_path)
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_runtime_checkpoints (
                    analysis_id TEXT NOT NULL,
                    hypothesis_key TEXT NOT NULL,
                    stage TEXT NOT NULL,
                    checkpoint_json TEXT NOT NULL,
                    input_hash TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (analysis_id, hypothesis_key, stage)
                )
                """
            )

    @staticmethod
    def _hypothesis_key(identity: CheckpointIdentity) -> str:
        return identity.hypothesis_id or ""

    def get(
        self,
        identity: CheckpointIdentity,
        stage: SimpleStage,
    ) -> StageCheckpoint | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT checkpoint_json
                FROM simple_runtime_checkpoints
                WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?
                """,
                (identity.analysis_id, self._hypothesis_key(identity), stage.value),
            ).fetchone()
        if row is None:
            return None
        checkpoint = StageCheckpoint.model_validate_json(row["checkpoint_json"])
        if checkpoint.identity != identity:
            return None
        return checkpoint

    def reusable(
        self,
        identity: CheckpointIdentity,
        stage: SimpleStage,
        input_refs: tuple[StoredDataRef, ...],
    ) -> bool:
        checkpoint = self.get(identity, stage)
        return bool(
            checkpoint is not None
            and checkpoint.status is StageStatus.SUCCEEDED
            and checkpoint.input_refs == input_refs
            and checkpoint.input_hash == input_reference_hash(input_refs)
        )

    def save_success(
        self,
        checkpoint: StageCheckpoint,
        *,
        outputs: tuple[StoredDataRef, ...],
        fail_before_commit: bool = False,
    ) -> StageCheckpoint:
        completed = checkpoint.model_copy(
            update={
                "status": StageStatus.SUCCEEDED,
                "output_refs": outputs,
                "error_code": None,
                "retryable": False,
                "updated_at": datetime.now(UTC),
            }
        )
        self._write(completed, fail_before_commit=fail_before_commit)
        return completed

    def save_checkpoint(self, checkpoint: StageCheckpoint) -> None:
        self._write(checkpoint)

    def mark_running(
        self,
        identity: CheckpointIdentity,
        stage: SimpleStage,
        input_refs: tuple[StoredDataRef, ...],
        *,
        attempt_id: str,
    ) -> StageCheckpoint:
        previous = self.get(identity, stage)
        checkpoint = StageCheckpoint(
            identity=identity,
            stage=stage,
            status=StageStatus.RUNNING,
            input_refs=input_refs,
            input_hash=input_reference_hash(input_refs),
            attempt_id=attempt_id,
            attempt_number=(previous.attempt_number if previous else 0) + 1,
            recipe_ref=previous.recipe_ref if previous else None,
            image_digest=previous.image_digest if previous else None,
            container_id=previous.container_id if previous else None,
        )
        self._write(checkpoint)
        return checkpoint

    def complete(
        self,
        checkpoint: StageCheckpoint,
        result: StageResult,
    ) -> StageCheckpoint:
        completed = checkpoint.model_copy(
            update={
                "status": StageStatus.SUCCEEDED,
                "output_refs": result.output_refs,
                "error_code": None,
                "retryable": False,
                "recipe_ref": result.recipe_ref or checkpoint.recipe_ref,
                "image_digest": result.image_digest or checkpoint.image_digest,
                "container_id": result.container_id or checkpoint.container_id,
                "validated_poc_ref": result.validated_poc_ref,
                "report_ref": result.report_ref,
                "verdict": result.verdict,
                "markdown_path": result.markdown_path,
                "updated_at": datetime.now(UTC),
            }
        )
        self._write(completed)
        return completed

    def mark_failure(
        self,
        checkpoint: StageCheckpoint,
        failure: StageFailure,
        status: StageStatus,
    ) -> StageCheckpoint:
        if status not in (StageStatus.BLOCKED, StageStatus.FAILED):
            raise ValueError("SimpleRuntime failure status must be BLOCKED or FAILED")
        failed = checkpoint.model_copy(
            update={
                "status": status,
                "error_code": failure.code,
                "retryable": failure.retryable,
                "updated_at": datetime.now(UTC),
            }
        )
        self._write(failed)
        return failed

    def require(
        self,
        identity: CheckpointIdentity,
        stage: SimpleStage,
    ) -> StageCheckpoint:
        checkpoint = self.get(identity, stage)
        if checkpoint is None:
            raise LookupError(f"Missing SimpleRuntime checkpoint: {stage.value}")
        return checkpoint

    def prior(
        self,
        identity: CheckpointIdentity,
        stage: SimpleStage,
    ) -> dict[SimpleStage, StageCheckpoint]:
        limit = STAGE_ORDER.index(stage)
        result: dict[SimpleStage, StageCheckpoint] = {}
        for item in STAGE_ORDER[:limit]:
            checkpoint = self.get(identity, item)
            if checkpoint is not None:
                result[item] = checkpoint
        return result

    def input_refs_for(
        self,
        identity: CheckpointIdentity,
        stage: SimpleStage,
    ) -> tuple[StoredDataRef, ...]:
        existing = self.get(identity, stage)
        if existing is not None:
            return existing.input_refs
        limit = STAGE_ORDER.index(stage)
        for item in reversed(STAGE_ORDER[:limit]):
            checkpoint = self.get(identity, item)
            if checkpoint is not None and checkpoint.status is StageStatus.SUCCEEDED:
                return checkpoint.output_refs
        return ()

    def _write(
        self,
        checkpoint: StageCheckpoint,
        *,
        fail_before_commit: bool = False,
    ) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO simple_runtime_checkpoints (
                    analysis_id,
                    hypothesis_key,
                    stage,
                    checkpoint_json,
                    input_hash,
                    updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT (analysis_id, hypothesis_key, stage) DO UPDATE SET
                    checkpoint_json = excluded.checkpoint_json,
                    input_hash = excluded.input_hash,
                    updated_at = excluded.updated_at
                """,
                (
                    checkpoint.identity.analysis_id,
                    self._hypothesis_key(checkpoint.identity),
                    checkpoint.stage.value,
                    checkpoint.model_dump_json(),
                    checkpoint.input_hash,
                    checkpoint.updated_at.isoformat(),
                ),
            )
            if fail_before_commit:
                raise RuntimeError("simulated crash")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def invalidate_from(
        self,
        identity: CheckpointIdentity,
        stage: SimpleStage,
        *,
        new_inputs: tuple[StoredDataRef, ...],
    ) -> None:
        if self.reusable(identity, stage, new_inputs):
            return
        first_index = STAGE_ORDER.index(stage)
        stages = tuple(item.value for item in STAGE_ORDER[first_index:])
        placeholders = ",".join("?" for _ in stages)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                f"""
                DELETE FROM simple_runtime_checkpoints
                WHERE analysis_id = ?
                  AND hypothesis_key = ?
                  AND stage IN ({placeholders})
                """,  # noqa: S608 - placeholders are generated, never user supplied.
                (
                    identity.analysis_id,
                    self._hypothesis_key(identity),
                    *stages,
                ),
            )
            connection.commit()

    def _first_value(
        self,
        identity: CheckpointIdentity,
        stages: Iterable[SimpleStage],
        field: str,
    ) -> object | None:
        for stage in stages:
            checkpoint = self.get(identity, stage)
            if checkpoint is None or checkpoint.status is not StageStatus.SUCCEEDED:
                continue
            value = getattr(checkpoint, field)
            if value is not None:
                return value
        return None

    def validated_poc(self, identity: CheckpointIdentity) -> StoredDataRef | None:
        value = self._first_value(
            identity,
            (SimpleStage.POC_EXECUTION_DONE, SimpleStage.VERIFICATION_FINAL_DONE),
            "validated_poc_ref",
        )
        return value if isinstance(value, StoredDataRef) else None

    def verdict(self, identity: CheckpointIdentity) -> str | None:
        value = self._first_value(
            identity,
            (SimpleStage.VERIFICATION_FINAL_DONE,),
            "verdict",
        )
        return value if isinstance(value, str) else None
