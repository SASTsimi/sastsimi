from __future__ import annotations

import hashlib
import sqlite3
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from sastsimi.contracts.canonical_json import canonical_bytes
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
from .recovery import (
    MAX_RECOVERY_ATTEMPTS,
    RecoveryAction,
    RecoveryResolution,
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
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_llm_attempts (
                    attempt_id TEXT PRIMARY KEY,
                    analysis_id TEXT NOT NULL,
                    agent TEXT NOT NULL,
                    model TEXT NOT NULL,
                    attempt_number INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    elapsed_ms INTEGER NOT NULL,
                    input_tokens INTEGER,
                    output_tokens INTEGER,
                    cost_cents REAL,
                    artifact_ref_json TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_hypothesis_survey_progress (
                    analysis_id TEXT NOT NULL,
                    bundle_hash TEXT NOT NULL,
                    item_key TEXT NOT NULL,
                    ref_json TEXT NOT NULL,
                    PRIMARY KEY (analysis_id, bundle_hash, item_key)
                )
                """
            )

    @property
    def database_path(self) -> Path:
        return self._database_path

    def save_survey_progress(
        self, analysis_id: str, bundle_hash: str, item_key: str, ref: StoredDataRef
    ) -> None:
        """Durably record one immutable survey decision before advancing."""

        encoded = ref.model_dump_json()
        with self._connect() as connection:
            row = connection.execute(
                "SELECT ref_json FROM simple_hypothesis_survey_progress "
                "WHERE analysis_id = ? AND bundle_hash = ? AND item_key = ?",
                (analysis_id, bundle_hash, item_key),
            ).fetchone()
            if row is not None:
                if StoredDataRef.model_validate_json(row[0]) != ref:
                    raise ValueError("SURVEY_PROGRESS_CONFLICT")
                return
            connection.execute(
                "INSERT INTO simple_hypothesis_survey_progress "
                "(analysis_id, bundle_hash, item_key, ref_json) VALUES (?, ?, ?, ?)",
                (analysis_id, bundle_hash, item_key, encoded),
            )

    def survey_progress(
        self, analysis_id: str, bundle_hash: str
    ) -> dict[str, StoredDataRef]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT item_key, ref_json FROM simple_hypothesis_survey_progress "
                "WHERE analysis_id = ? AND bundle_hash = ? ORDER BY item_key",
                (analysis_id, bundle_hash),
            ).fetchall()
        return {
            str(row["item_key"]): StoredDataRef.model_validate_json(row["ref_json"])
            for row in rows
        }

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

    def record_llm_attempt(
        self,
        *,
        attempt_id: str,
        analysis_id: str,
        agent: str,
        model: str,
        attempt_number: int,
        status: str,
        elapsed_ms: int,
        input_tokens: int | None,
        output_tokens: int | None,
        cost_cents: float | None,
        artifact_ref: StoredDataRef,
    ) -> None:
        values = (
            attempt_id,
            analysis_id,
            agent,
            model,
            attempt_number,
            status,
            elapsed_ms,
            input_tokens,
            output_tokens,
            cost_cents,
            artifact_ref.model_dump_json(),
        )
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO simple_llm_attempts (
                    attempt_id, analysis_id, agent, model, attempt_number,
                    status, elapsed_ms, input_tokens, output_tokens,
                    cost_cents, artifact_ref_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                values,
            )
            if cursor.rowcount == 0:
                row = connection.execute(
                    "SELECT * FROM simple_llm_attempts WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()
                if row is None or tuple(row) != values:
                    raise ValueError("LLM_ATTEMPT_CONFLICT")

    @staticmethod
    def usage_summary_from_connection(
        connection: sqlite3.Connection, analysis_id: str
    ) -> dict[str, int | float | None]:
        row = connection.execute(
            """
            SELECT COUNT(*) AS calls,
                   COALESCE(SUM(input_tokens), 0) AS input_tokens,
                   COALESCE(SUM(output_tokens), 0) AS output_tokens,
                   SUM(cost_cents) AS cost_minor_units,
                   COALESCE(SUM(CASE WHEN cost_cents IS NULL THEN 1 ELSE 0 END), 0)
                       AS unknown_cost_calls
            FROM simple_llm_attempts WHERE analysis_id = ?
            """,
            (analysis_id,),
        ).fetchone()
        assert row is not None
        return {
            "calls": int(row["calls"]),
            "input_tokens": int(row["input_tokens"]),
            "output_tokens": int(row["output_tokens"]),
            "cost_minor_units": (
                float(row["cost_minor_units"])
                if row["cost_minor_units"] is not None
                else None
            ),
            "unknown_cost_calls": int(row["unknown_cost_calls"]),
        }

    def usage_summary(self, analysis_id: str) -> dict[str, int | float | None]:
        with self._connect() as connection:
            return self.usage_summary_from_connection(connection, analysis_id)

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
    ) -> StageCheckpoint:
        previous = self.get(identity, stage)
        reusable_state = previous or inherit_from
        recovery_refs = reusable_state.recovery_decision_refs if reusable_state else ()
        exact_inputs = tuple(dict.fromkeys(input_refs + recovery_refs))
        if previous is not None:
            attempt_number = previous.attempt_number + 1
        elif inherit_from is not None and inherit_from.recovery_lineage_id is not None:
            attempt_number = inherit_from.attempt_number
        else:
            attempt_number = 1
        checkpoint = StageCheckpoint(
            identity=identity,
            stage=stage,
            stage_version=STAGE_VERSION[stage],
            status=StageStatus.RUNNING,
            input_refs=exact_inputs,
            input_hash=input_reference_hash(exact_inputs),
            attempt_id=attempt_id,
            attempt_number=attempt_number,
            recovery_lineage_id=(
                reusable_state.recovery_lineage_id if reusable_state else None
            ),
            recovery_origin_stage=(
                reusable_state.recovery_origin_stage if reusable_state else None
            ),
            recovery_decision_refs=recovery_refs,
            recipe_ref=reusable_state.recipe_ref if reusable_state else None,
            image_digest=reusable_state.image_digest if reusable_state else None,
            container_id=reusable_state.container_id if reusable_state else None,
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
        updates: dict[str, object] = {
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
        if checkpoint.recovery_origin_stage is checkpoint.stage:
            updates.update(
                recovery_lineage_id=None,
                recovery_origin_stage=None,
                recovery_decision_refs=(),
            )
        completed = checkpoint.model_copy(update=updates)
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

    def prepare_recovery(
        self,
        failed: StageCheckpoint,
        resolution: RecoveryResolution,
        restart_stage: SimpleStage,
        *,
        fail_before_commit: bool = False,
    ) -> StageCheckpoint:
        """Record one decision and atomically seed its next bounded attempt."""

        if failed.status not in {StageStatus.BLOCKED, StageStatus.FAILED}:
            raise ValueError("RECOVERY_CHECKPOINT_NOT_FAILED")
        if resolution.decision.action is RecoveryAction.STOP:
            raise ValueError("RECOVERY_STOP_CANNOT_PREPARE")
        if STAGE_ORDER.index(restart_stage) > STAGE_ORDER.index(failed.stage):
            raise ValueError("RECOVERY_RESTART_STAGE_INVALID")
        restart = self.get(failed.identity, restart_stage)
        decision_refs = tuple(
            dict.fromkeys(failed.recovery_decision_refs + (resolution.decision_ref,))
        )
        original_inputs = restart.input_refs if restart is not None else ()
        inputs = tuple(
            dict.fromkeys(
                original_inputs + failed.input_refs + failed.output_refs + decision_refs
            )
        )
        lineage_id = (
            failed.recovery_lineage_id
            or hashlib.sha256(
                canonical_bytes(
                    {
                        "identity": failed.identity,
                        "stage": failed.stage.value,
                        "stage_version": failed.stage_version,
                        "input_hash": failed.input_hash,
                        "error_code": failed.error_code,
                    }
                )
            ).hexdigest()
        )
        rebuild = resolution.decision.action is RecoveryAction.REBUILD_ENVIRONMENT
        pending = StageCheckpoint(
            identity=failed.identity,
            stage=restart_stage,
            stage_version=STAGE_VERSION[restart_stage],
            status=StageStatus.PENDING,
            input_refs=inputs,
            input_hash=input_reference_hash(inputs),
            attempt_number=failed.attempt_number,
            recovery_lineage_id=lineage_id,
            recovery_origin_stage=(failed.recovery_origin_stage or failed.stage),
            recovery_decision_refs=decision_refs,
            recipe_ref=None if rebuild else failed.recipe_ref,
            image_digest=None if rebuild else failed.image_digest,
            container_id=None,
        )
        event = self._recovery_event(failed, resolution)
        first_index = STAGE_ORDER.index(restart_stage)
        stages = tuple(item.value for item in STAGE_ORDER[first_index:])
        placeholders = ",".join("?" for _ in stages)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            AgentActivityStore.append_connection(connection, event)
            connection.execute(
                f"""
                DELETE FROM simple_runtime_checkpoints
                WHERE analysis_id = ?
                  AND hypothesis_key = ?
                  AND stage IN ({placeholders})
                """,  # noqa: S608 - placeholders are generated, never user supplied.
                (
                    failed.identity.analysis_id,
                    self._hypothesis_key(failed.identity),
                    *stages,
                ),
            )
            self._upsert_checkpoint_connection(connection, pending)
            if fail_before_commit:
                raise RuntimeError("simulated crash")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        return pending

    def record_recovery_stop(
        self,
        failed: StageCheckpoint,
        resolution: RecoveryResolution,
        *,
        fail_before_commit: bool = False,
    ) -> None:
        if resolution.decision.action is not RecoveryAction.STOP:
            raise ValueError("RECOVERY_STOP_ACTION_REQUIRED")
        self.record_recovery_decision(
            failed,
            resolution,
            fail_before_commit=fail_before_commit,
        )

    def record_recovery_decision(
        self,
        failed: StageCheckpoint,
        resolution: RecoveryResolution,
        *,
        fail_before_commit: bool = False,
    ) -> None:
        self._write(
            failed,
            fail_before_commit=fail_before_commit,
            activity_events=(self._recovery_event(failed, resolution),),
        )

    def mark_recovery_exhausted(
        self,
        checkpoint: StageCheckpoint,
    ) -> StageCheckpoint:
        exhausted = checkpoint.model_copy(
            update={
                "status": StageStatus.BLOCKED,
                "error_code": "RECOVERY_EXHAUSTED",
                "retryable": False,
                "updated_at": datetime.now(UTC),
            }
        )
        self._write(
            exhausted,
            activity_events=(
                self._lifecycle_event(
                    exhausted,
                    ActivityKind.STAGE_BLOCKED,
                    sequence=self._stage_sequence(exhausted.stage, 100),
                    status=StageStatus.BLOCKED,
                    summary_ko=(
                        f"자동 복구가 attempt {exhausted.attempt_number}/"
                        f"{MAX_RECOVERY_ATTEMPTS}에서 종료됐습니다."
                    ),
                    output_refs=exhausted.output_refs,
                    error_code="RECOVERY_EXHAUSTED",
                ),
            ),
        )
        return exhausted

    def _recovery_event(
        self,
        failed: StageCheckpoint,
        resolution: RecoveryResolution,
    ) -> AgentActivityEvent:
        return self._lifecycle_event(
            failed,
            ActivityKind.DECISION_RECORDED,
            sequence=self._stage_sequence(failed.stage, 40),
            status=StageStatus.BLOCKED,
            summary_ko=(
                f"자동 복구 결정 {resolution.decision.action.value} · "
                f"attempt {failed.attempt_number}/{MAX_RECOVERY_ATTEMPTS}"
            ),
            output_refs=(resolution.decision_ref,),
            error_code=failed.error_code,
        )

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
            self._upsert_checkpoint_connection(connection, checkpoint)
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

    def _upsert_checkpoint_connection(
        self,
        connection: sqlite3.Connection,
        checkpoint: StageCheckpoint,
    ) -> None:
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
