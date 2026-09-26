from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.observability.agent_activity import (
    ActivityKind,
    AgentActivityEvent,
)
from sastsimi.storage.agent_activity import AgentActivityStore

from .models import (
    STAGE_ORDER,
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageResult,
    StageStatus,
    input_reference_hash,
)

ROLE_BY_STAGE: dict[SimpleStage, str] = {
    SimpleStage.STATIC_DONE: "Static Analysis Runtime",
    SimpleStage.HYPOTHESIS_DONE: "Hypothesis Agent",
    SimpleStage.PRO_CON_DONE: "Pro·Con Agents",
    SimpleStage.VERIFICATION_INITIAL_DONE: "Verification Agent",
    SimpleStage.POC_CANDIDATE_DONE: "Dynamic Reproduction Agent",
    SimpleStage.POC_EXECUTION_DONE: "Reproduction Runtime",
    SimpleStage.VERIFICATION_FINAL_DONE: "Verification Agent",
    SimpleStage.CWE_DONE: "CWE Labeling Agent",
    SimpleStage.TECH_GATE_DONE: "Technical Gate Agent",
    SimpleStage.SCOPE_GATE_DONE: "Rule Scope Gate Agent",
    SimpleStage.PRIMITIVE_ADMISSION_DONE: "Primitive Admission Runtime",
    SimpleStage.CHAINING_DONE: "Chaining Agent",
    SimpleStage.FINDING_DONE: "Finding Runtime",
    SimpleStage.REPORT_DONE: "Reporter Agent",
}


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
            AgentActivityStore.initialize_connection(connection)
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_analysis_runs (
                    analysis_id TEXT PRIMARY KEY,
                    run_json TEXT NOT NULL
                )
                """
            )

    @property
    def database_path(self) -> Path:
        return self._database_path

    def save_analysis_run(self, run: object) -> None:
        validated = SimpleAnalysisRun.model_validate(run)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO simple_analysis_runs (analysis_id, run_json)
                VALUES (?, ?)
                ON CONFLICT (analysis_id) DO UPDATE SET run_json = excluded.run_json
                """,
                (validated.analysis_id, validated.model_dump_json()),
            )

    def require_analysis_run(self, analysis_id: str) -> SimpleAnalysisRun:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT run_json FROM simple_analysis_runs WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()
        if row is None:
            raise LookupError("SIMPLE_ANALYSIS_RUN_NOT_FOUND")
        return SimpleAnalysisRun.model_validate_json(row[0])

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

    def list_checkpoints(self, analysis_id: str) -> tuple[StageCheckpoint, ...]:
        """Return immutable validated checkpoints for exactly one analysis."""

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT checkpoint_json
                FROM simple_runtime_checkpoints
                WHERE analysis_id = ?
                ORDER BY updated_at, hypothesis_key, stage
                """,
                (analysis_id,),
            ).fetchall()
        return tuple(
            StageCheckpoint.model_validate_json(row["checkpoint_json"]) for row in rows
        )

    def list_analysis_ids(self) -> tuple[str, ...]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT DISTINCT analysis_id
                FROM simple_runtime_checkpoints
                ORDER BY analysis_id
                """
            ).fetchall()
        return tuple(str(row[0]) for row in rows)

    def has_stage_activity(
        self,
        identity: CheckpointIdentity,
        stage: SimpleStage,
        attempt_id: str,
    ) -> bool:
        """Return whether an append-only event already used this stage attempt."""

        return bool(self.stage_activity(identity, stage, attempt_id))

    def stage_activity(
        self,
        identity: CheckpointIdentity,
        stage: SimpleStage,
        attempt_id: str,
    ) -> tuple[AgentActivityEvent, ...]:
        """Read exact append-only events retained for one stage attempt."""

        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT event_json
                FROM agent_activity_events
                WHERE analysis_id = ?
                  AND hypothesis_key = ?
                  AND attempt_id = ?
                """,
                (
                    identity.analysis_id,
                    self._hypothesis_key(identity),
                    attempt_id,
                ),
            ).fetchall()
        return tuple(
            event
            for row in rows
            if (
                event := AgentActivityEvent.model_validate_json(row["event_json"])
            ).stage
            == stage.value
        )

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
            and checkpoint.stage_version == STAGE_VERSION[stage]
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
        event: AgentActivityEvent | None = None
        if (
            checkpoint.status is StageStatus.SUCCEEDED
            and checkpoint.stage is SimpleStage.PRO_CON_DONE
        ):
            event = self._lifecycle_event(
                checkpoint,
                ActivityKind.EVIDENCE_RECORDED,
                sequence=self._stage_sequence(checkpoint.stage, 10),
                status=StageStatus.SUCCEEDED,
                summary_ko="Pro·Con Agent의 찬성·반대 근거를 연결했습니다.",
                output_refs=checkpoint.output_refs,
            )
        elif (
            checkpoint.status is StageStatus.SUCCEEDED
            and checkpoint.stage is SimpleStage.VERIFICATION_INITIAL_DONE
        ):
            event = self._lifecycle_event(
                checkpoint,
                ActivityKind.DECISION_RECORDED,
                sequence=self._stage_sequence(checkpoint.stage, 10),
                status=StageStatus.SUCCEEDED,
                summary_ko="초기 검증 판정과 필요한 동적 재현 목적을 연결했습니다.",
                output_refs=checkpoint.output_refs,
            )
        self._write(checkpoint, activity_events=((event,) if event else ()))

    def mark_running(
        self,
        identity: CheckpointIdentity,
        stage: SimpleStage,
        input_refs: tuple[StoredDataRef, ...],
        *,
        attempt_id: str,
        inherit_from: StageCheckpoint | None = None,
        retry_evidence_refs: tuple[StoredDataRef, ...] = (),
    ) -> StageCheckpoint:
        previous = self.get(identity, stage)
        reusable_state = previous or inherit_from
        checkpoint = StageCheckpoint(
            identity=identity,
            stage=stage,
            stage_version=STAGE_VERSION[stage],
            status=StageStatus.RUNNING,
            input_refs=input_refs,
            input_hash=input_reference_hash(input_refs),
            attempt_id=attempt_id,
            attempt_number=(previous.attempt_number if previous else 0) + 1,
            recipe_ref=reusable_state.recipe_ref if reusable_state else None,
            image_digest=reusable_state.image_digest if reusable_state else None,
            container_id=reusable_state.container_id if reusable_state else None,
            retry_evidence_refs=retry_evidence_refs,
        )
        self._write(
            checkpoint,
            activity_events=(
                self._lifecycle_event(
                    checkpoint,
                    ActivityKind.STAGE_STARTED,
                    sequence=self._stage_sequence(stage, 1),
                    status=StageStatus.RUNNING,
                    summary_ko="단계 실행을 시작했습니다.",
                ),
            ),
        )
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
        final_sequence = (
            max(
                (event.sequence for event in result.activity_events),
                default=self._stage_sequence(checkpoint.stage, 1),
            )
            + 1
        )
        self._write(
            completed,
            activity_events=(
                *result.activity_events,
                self._lifecycle_event(
                    completed,
                    ActivityKind.STAGE_COMPLETED,
                    sequence=final_sequence,
                    status=StageStatus.SUCCEEDED,
                    summary_ko="단계 결과를 저장했습니다.",
                    output_refs=result.output_refs,
                ),
            ),
        )
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
                "output_refs": failure.evidence_refs,
                "error_code": failure.code,
                "retryable": failure.retryable,
                "updated_at": datetime.now(UTC),
            }
        )
        kind = (
            ActivityKind.STAGE_BLOCKED
            if status is StageStatus.BLOCKED
            else ActivityKind.STAGE_FAILED
        )
        self._write(
            failed,
            activity_events=(
                self._lifecycle_event(
                    failed,
                    kind,
                    sequence=self._stage_sequence(checkpoint.stage, 99),
                    status=status,
                    summary_ko="단계가 완료되지 않아 중단했습니다.",
                    output_refs=failure.evidence_refs,
                    error_code=failure.code,
                ),
            ),
        )
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
        activity_events: tuple[AgentActivityEvent, ...] = (),
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
            for event in activity_events:
                AgentActivityStore.append_connection(connection, event)
            if fail_before_commit:
                raise RuntimeError("simulated crash")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _stage_sequence(stage: SimpleStage, offset: int) -> int:
        return (STAGE_ORDER.index(stage) + 1) * 100 + offset

    @staticmethod
    def _lifecycle_event(
        checkpoint: StageCheckpoint,
        kind: ActivityKind,
        *,
        sequence: int,
        status: StageStatus,
        summary_ko: str,
        output_refs: tuple[StoredDataRef, ...] = (),
        error_code: str | None = None,
    ) -> AgentActivityEvent:
        attempt_id = checkpoint.attempt_id or "checkpoint"
        event_key = ":".join(
            (
                checkpoint.identity.analysis_id,
                checkpoint.identity.hypothesis_id or "",
                attempt_id,
                str(sequence),
                kind.value,
            )
        )
        return AgentActivityEvent(
            event_id=hashlib.sha256(event_key.encode("utf-8")).hexdigest(),
            analysis_id=checkpoint.identity.analysis_id,
            workspace_id=checkpoint.identity.workspace_id,
            commit_id=checkpoint.identity.commit_id,
            hypothesis_id=checkpoint.identity.hypothesis_id,
            stage=checkpoint.stage.value,
            agent_role=ROLE_BY_STAGE[checkpoint.stage],
            attempt_id=attempt_id,
            sequence=sequence,
            kind=kind,
            status=status.value,
            summary_ko=summary_ko,
            input_refs=checkpoint.input_refs,
            output_refs=output_refs,
            error_code=error_code,
            started_at=checkpoint.updated_at,
            finished_at=(
                checkpoint.updated_at
                if kind is not ActivityKind.STAGE_STARTED
                else None
            ),
        )

    def invalidate_from(
        self,
        identity: CheckpointIdentity,
        stage: SimpleStage,
        *,
        new_inputs: tuple[StoredDataRef, ...],
        force: bool = False,
    ) -> None:
        if not force and self.reusable(identity, stage, new_inputs):
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
                return cast(object, value)
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
