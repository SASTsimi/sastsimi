from __future__ import annotations

import hashlib
import json
import math
import sqlite3
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, cast

from sastsimi.config.user_config import ElapsedLimit, TokenLimit
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.observability.agent_activity import (
    ActivityKind,
    AgentActivityEvent,
)
from sastsimi.storage.agent_activity import AgentActivityStore

from .artifacts import SimpleArtifactRepository
from .attempt_owner import AttemptOwner, PromptByteCounts
from .candidates import StaticCandidate
from .models import (
    HYPOTHESIS_STAGES,
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
    terminal_gate_outcome,
    terminal_poc_outcome,
)
from .recovery import (
    MAX_RECOVERY_ATTEMPTS,
    RecoveryAction,
    RecoveryResolution,
)
from .run_lease import AnalysisRunBusy, analysis_run_lease

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

# Match the non-response statuses ignored by RunUsageBudget's token check.
_NO_MODEL_RESPONSE_STATUSES = (
    "AUTH_REQUIRED",
    "RATE_LIMITED",
    "OPENAI_SDK_UNAVAILABLE",
    "MODEL_OR_REQUEST_UNSUPPORTED",
    "CONTEXT_LIMIT_EXCEEDED",
    "CURSOR_AUTH_REQUIRED",
    "CURSOR_AUTH_FAILED",
    "CURSOR_CONFIGURATION_FAILED",
    "CURSOR_PLAN_LIMIT",
    "CURSOR_RATE_LIMITED",
    "CLAUDE_AUTH_REQUIRED",
    "CLAUDE_RATE_LIMITED",
)


@dataclass(frozen=True, slots=True)
class StaticScanAttempt:
    fingerprint: str
    tool: str
    run_key: str
    status: Literal["SUCCEEDED", "BLOCKED"]
    raw_ref: StoredDataRef | None
    coverage_ref: StoredDataRef | None
    request_ref: StoredDataRef | None
    error_code: str | None


@dataclass(frozen=True, slots=True)
class StaticScanExecution:
    execution_id: int
    repository: str
    fingerprint: str
    tool: str
    run_key: str
    status: Literal["STARTED", "SUCCEEDED", "BLOCKED"]
    raw_ref: StoredDataRef | None
    error_code: str | None
    request_ref: StoredDataRef | None
    error_ref: StoredDataRef | None
    timeout_seconds: float


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
            # Serialize additive schema checks and ALTERs across CLI processes.
            connection.execute("BEGIN IMMEDIATE")
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
                CREATE TABLE IF NOT EXISTS simple_llm_attempt_metadata (
                    attempt_id TEXT PRIMARY KEY,
                    analysis_id TEXT NOT NULL,
                    stage TEXT,
                    candidate_ids_json TEXT,
                    hypothesis_id TEXT,
                    surface_id TEXT,
                    file_path TEXT,
                    batch_id TEXT,
                    context_id TEXT,
                    checkpoint_attempt_id TEXT,
                    retry_of TEXT,
                    raw_source_bytes INTEGER,
                    shared_context_bytes INTEGER,
                    candidate_specific_bytes INTEGER,
                    fixed_prompt_bytes INTEGER
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_llm_attempt_metadata_stage "
                "ON simple_llm_attempt_metadata (analysis_id, stage)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_codex_calls (
                    call_id TEXT PRIMARY KEY,
                    analysis_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN ('IN_FLIGHT', 'SAFE', 'CONFIRMED')
                    ),
                    started_at TEXT NOT NULL,
                    resolved_at TEXT,
                    confirmation_ref_json TEXT
                )
                """
            )
            connection.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS simple_codex_one_in_flight
                ON simple_codex_calls (analysis_id)
                WHERE status = 'IN_FLIGHT'
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_codex_child_spawns (
                    call_id TEXT NOT NULL,
                    analysis_id TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN ('SPAWNING', 'CAPTURED', 'EXITED')
                    ),
                    pid INTEGER,
                    start_identity TEXT,
                    PRIMARY KEY (call_id, phase)
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_codex_call_versions (
                    call_id TEXT PRIMARY KEY,
                    analysis_id TEXT NOT NULL,
                    candidate_pipeline_version INTEGER NOT NULL
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
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_opengrep_batch_progress (
                    analysis_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    commit_id TEXT NOT NULL,
                    repository TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    batch_key TEXT NOT NULL,
                    ref_json TEXT NOT NULL,
                    PRIMARY KEY (
                        analysis_id, workspace_id, commit_id,
                        repository, fingerprint, batch_key
                    )
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_static_scan_attempts (
                    analysis_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    commit_id TEXT NOT NULL,
                    repository TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    run_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    raw_ref_json TEXT,
                    coverage_ref_json TEXT,
                    request_ref_json TEXT,
                    error_code TEXT,
                    PRIMARY KEY (
                        analysis_id, workspace_id, commit_id,
                        repository, fingerprint, tool, run_key
                    )
                )
                """
            )
            columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(simple_static_scan_attempts)"
                )
            }
            if "request_ref_json" not in columns:
                connection.execute(
                    "ALTER TABLE simple_static_scan_attempts "
                    "ADD COLUMN request_ref_json TEXT"
                )
            legacy_marker_exists = (
                connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE type = 'table' "
                    "AND name = 'simple_static_scan_legacy_history'"
                ).fetchone()
                is not None
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_static_scan_legacy_history (
                    analysis_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    commit_id TEXT NOT NULL,
                    repository TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    PRIMARY KEY (
                        analysis_id, workspace_id, commit_id,
                        repository, fingerprint
                    )
                )
                """
            )
            if (
                not legacy_marker_exists
                and {
                    "analysis_id",
                    "workspace_id",
                    "commit_id",
                    "repository",
                    "fingerprint",
                }
                <= columns
            ):
                connection.execute(
                    "INSERT OR IGNORE INTO simple_static_scan_legacy_history "
                    "(analysis_id, workspace_id, commit_id, repository, fingerprint) "
                    "SELECT DISTINCT analysis_id, workspace_id, commit_id, "
                    "repository, fingerprint FROM simple_static_scan_attempts"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_static_scan_executions (
                    execution_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    commit_id TEXT NOT NULL,
                    repository TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    run_key TEXT NOT NULL,
                    status TEXT NOT NULL,
                    raw_ref_json TEXT,
                    error_code TEXT,
                    request_ref_json TEXT,
                    error_ref_json TEXT,
                    timeout_seconds REAL NOT NULL
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_static_scan_executions_scope "
                "ON simple_static_scan_executions "
                "(analysis_id, workspace_id, commit_id, repository, "
                "fingerprint, tool, run_key)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_report_drafts (
                    identity_json TEXT NOT NULL,
                    input_hash TEXT NOT NULL,
                    stage_version TEXT NOT NULL,
                    finding_ref_json TEXT NOT NULL,
                    draft_ref_json TEXT NOT NULL,
                    PRIMARY KEY (identity_json, input_hash, stage_version)
                )
                """
            )

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_static_candidates (
                    analysis_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    commit_id TEXT NOT NULL,
                    scope_fingerprint TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    candidate_json TEXT NOT NULL,
                    decision TEXT NOT NULL DEFAULT 'PENDING',
                    decision_reason TEXT NOT NULL DEFAULT '',
                    decision_evidence_refs_json TEXT NOT NULL DEFAULT '[]',
                    decision_attempt_ref_json TEXT,
                    deep_status TEXT NOT NULL DEFAULT 'PENDING',
                    PRIMARY KEY (
                        analysis_id, workspace_id, commit_id,
                        scope_fingerprint, candidate_id
                    )
                )
                """
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_static_candidates_decision "
                "ON simple_static_candidates "
                "(analysis_id, workspace_id, commit_id, scope_fingerprint, "
                "decision, candidate_id)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_candidate_artifact_cursors (
                    analysis_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    commit_id TEXT NOT NULL,
                    scope_fingerprint TEXT NOT NULL,
                    artifact_hash TEXT NOT NULL,
                    artifact_ref_json TEXT NOT NULL,
                    result_offset INTEGER NOT NULL,
                    PRIMARY KEY (
                        analysis_id, workspace_id, commit_id,
                        scope_fingerprint, artifact_hash
                    )
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_candidate_hypotheses (
                    analysis_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    commit_id TEXT NOT NULL,
                    hypothesis_id TEXT NOT NULL,
                    hypothesis_ref_json TEXT,
                    chain_depth INTEGER NOT NULL DEFAULT 0,
                    parent_hypothesis_ids_json TEXT NOT NULL DEFAULT '[]',
                    PRIMARY KEY (
                        analysis_id, workspace_id, commit_id, hypothesis_id
                    )
                )
                """
            )
            hypothesis_columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(simple_candidate_hypotheses)"
                )
            }
            if "chain_depth" not in hypothesis_columns:
                connection.execute(
                    "ALTER TABLE simple_candidate_hypotheses "
                    "ADD COLUMN chain_depth INTEGER NOT NULL DEFAULT 0"
                )
            if "parent_hypothesis_ids_json" not in hypothesis_columns:
                connection.execute(
                    "ALTER TABLE simple_candidate_hypotheses "
                    "ADD COLUMN parent_hypothesis_ids_json TEXT NOT NULL DEFAULT '[]'"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_candidate_hypothesis_links (
                    analysis_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    commit_id TEXT NOT NULL,
                    scope_fingerprint TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    hypothesis_id TEXT NOT NULL,
                    PRIMARY KEY (
                        analysis_id, workspace_id, commit_id,
                        scope_fingerprint, candidate_id, hypothesis_id
                    )
                )
                """
            )

    @property
    def database_path(self) -> Path:
        return self._database_path

    @staticmethod
    def _candidate_scope_key(
        identity: CheckpointIdentity, scope_fingerprint: str
    ) -> tuple[str, str, str, str]:
        if identity.hypothesis_id is not None or not scope_fingerprint.strip():
            raise ValueError("CANDIDATE_SCOPE_INVALID")
        return (
            identity.analysis_id,
            identity.workspace_id,
            identity.commit_id,
            scope_fingerprint,
        )

    @staticmethod
    def _candidate_ref_json(
        identity: CheckpointIdentity, ref: StoredDataRef | None
    ) -> str | None:
        if ref is None:
            return None
        if (
            str(ref.workspace_id) != identity.workspace_id
            or str(ref.commit_id) != identity.commit_id
            or ref.record_id is not None
            or ref.data_kind != "artifact"
            or str(ref.stored_data_id) != ref.content_hash
        ):
            raise ValueError("CANDIDATE_REF_SCOPE_MISMATCH")
        return ref.model_dump_json()

    def candidate_cursor(
        self,
        identity: CheckpointIdentity,
        scope_fingerprint: str,
        artifact_ref: StoredDataRef,
    ) -> int:
        key = self._candidate_scope_key(identity, scope_fingerprint)
        encoded = self._candidate_ref_json(identity, artifact_ref)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT artifact_ref_json, result_offset "
                "FROM simple_candidate_artifact_cursors "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND scope_fingerprint = ? AND artifact_hash = ?",
                (*key, artifact_ref.content_hash),
            ).fetchone()
        if row is None:
            return 0
        if row["artifact_ref_json"] != encoded:
            raise ValueError("CANDIDATE_CURSOR_CONFLICT")
        return int(row["result_offset"])

    def upsert_candidate_page(
        self,
        identity: CheckpointIdentity,
        scope_fingerprint: str,
        artifact_ref: StoredDataRef,
        start_offset: int,
        end_offset: int,
        candidates: tuple[StaticCandidate, ...],
    ) -> None:
        """Persist a bounded candidate page and its raw cursor atomically."""

        key = self._candidate_scope_key(identity, scope_fingerprint)
        encoded_ref = self._candidate_ref_json(identity, artifact_ref)
        if start_offset < 0 or end_offset <= start_offset:
            raise ValueError("CANDIDATE_PAGE_INVALID")
        for candidate in candidates:
            if (
                candidate.decision != "PENDING"
                or candidate.deep_status != "PENDING"
                or not candidate.origins
                or any(
                    self._candidate_ref_json(identity, origin.artifact_ref)
                    != encoded_ref
                    or origin.result_index < start_offset
                    or origin.result_index >= end_offset
                    for origin in candidate.origins
                )
            ):
                raise ValueError("CANDIDATE_PAGE_INVALID")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT artifact_ref_json, result_offset "
                "FROM simple_candidate_artifact_cursors "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND scope_fingerprint = ? AND artifact_hash = ?",
                (*key, artifact_ref.content_hash),
            ).fetchone()
            current = int(row["result_offset"]) if row is not None else 0
            if row is not None and row["artifact_ref_json"] != encoded_ref:
                raise ValueError("CANDIDATE_CURSOR_CONFLICT")
            if current == end_offset and start_offset < current:
                # A page committed before an interruption is safe to replay.
                return
            if current != start_offset:
                raise ValueError("CANDIDATE_CURSOR_CONFLICT")
            for candidate in candidates:
                saved = connection.execute(
                    "SELECT candidate_json FROM simple_static_candidates "
                    "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                    "AND scope_fingerprint = ? AND candidate_id = ?",
                    (*key, candidate.candidate_id),
                ).fetchone()
                if saved is None:
                    connection.execute(
                        "INSERT INTO simple_static_candidates "
                        "(analysis_id, workspace_id, commit_id, scope_fingerprint, "
                        "candidate_id, candidate_json) VALUES (?, ?, ?, ?, ?, ?)",
                        (*key, candidate.candidate_id, candidate.model_dump_json()),
                    )
                    continue
                previous = StaticCandidate.model_validate_json(saved["candidate_json"])
                if (
                    previous.kind != candidate.kind
                    or previous.path != candidate.path
                    or previous.line != candidate.line
                    or previous.end_line != candidate.end_line
                    or previous.flow_identity != candidate.flow_identity
                    or previous.evidence_key != candidate.evidence_key
                ):
                    raise ValueError("CANDIDATE_ID_CONFLICT")
                origins = {
                    (
                        origin.engine,
                        origin.rule_id,
                        origin.artifact_ref.content_hash,
                        origin.result_index,
                    ): origin
                    for origin in (*previous.origins, *candidate.origins)
                }
                merged = previous.model_copy(
                    update={"origins": tuple(origins[key] for key in sorted(origins))}
                )
                connection.execute(
                    "UPDATE simple_static_candidates SET candidate_json = ? "
                    "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                    "AND scope_fingerprint = ? AND candidate_id = ?",
                    (merged.model_dump_json(), *key, candidate.candidate_id),
                )
            connection.execute(
                "INSERT INTO simple_candidate_artifact_cursors "
                "(analysis_id, workspace_id, commit_id, scope_fingerprint, "
                "artifact_hash, artifact_ref_json, result_offset) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (analysis_id, workspace_id, commit_id, "
                "scope_fingerprint, artifact_hash) DO UPDATE SET "
                "result_offset = excluded.result_offset",
                (*key, artifact_ref.content_hash, encoded_ref, end_offset),
            )

    def list_candidates(
        self,
        identity: CheckpointIdentity,
        scope_fingerprint: str,
        *,
        status: str | tuple[str, ...] | None = None,
        after_id: str | None = None,
        limit: int = 100,
    ) -> tuple[StaticCandidate, ...]:
        key = self._candidate_scope_key(identity, scope_fingerprint)
        if limit <= 0:
            raise ValueError("CANDIDATE_PAGE_ARGUMENT_INVALID")
        statuses = (status,) if isinstance(status, str) else status
        query = (
            "SELECT candidate_json, decision, decision_reason, "
            "decision_evidence_refs_json, decision_attempt_ref_json, deep_status "
            "FROM simple_static_candidates "
            "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
            "AND scope_fingerprint = ?"
        )
        args: list[object] = list(key)
        if statuses is not None:
            if not statuses:
                return ()
            query += " AND decision IN (" + ",".join("?" for _ in statuses) + ")"
            args.extend(statuses)
        if after_id is not None:
            query += " AND candidate_id > ?"
            args.append(after_id)
        query += " ORDER BY candidate_id LIMIT ?"
        args.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, args).fetchall()
        result: list[StaticCandidate] = []
        for row in rows:
            candidate = StaticCandidate.model_validate_json(row["candidate_json"])
            refs = tuple(
                StoredDataRef.model_validate(ref)
                for ref in json.loads(row["decision_evidence_refs_json"])
            )
            attempt = (
                StoredDataRef.model_validate_json(row["decision_attempt_ref_json"])
                if row["decision_attempt_ref_json"] is not None
                else None
            )
            result.append(
                candidate.model_copy(
                    update={
                        "decision": row["decision"],
                        "decision_reason": row["decision_reason"],
                        "decision_evidence_refs": refs,
                        "decision_attempt_ref": attempt,
                        "deep_status": row["deep_status"],
                    }
                )
            )
        return tuple(result)

    def candidate_counts(
        self, identity: CheckpointIdentity, scope_fingerprint: str
    ) -> dict[str, int]:
        key = self._candidate_scope_key(identity, scope_fingerprint)
        result = {
            status: 0
            for status in ("PENDING", "INCLUDE", "EXCLUDE", "UNDECIDED", "ERROR")
        }
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT decision, COUNT(*) AS count FROM simple_static_candidates "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND scope_fingerprint = ? GROUP BY decision",
                key,
            ).fetchall()
        for row in rows:
            result[str(row["decision"])] = int(row["count"])
        return result

    def candidate_deep_counts(
        self, identity: CheckpointIdentity, scope_fingerprint: str
    ) -> dict[str, int]:
        key = self._candidate_scope_key(identity, scope_fingerprint)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT deep_status, COUNT(*) AS count "
                "FROM simple_static_candidates "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND scope_fingerprint = ? AND decision IN ('INCLUDE', 'UNDECIDED') "
                "GROUP BY deep_status",
                key,
            ).fetchall()
        return {str(row["deep_status"]): int(row["count"]) for row in rows}

    def save_candidate_decision(
        self,
        identity: CheckpointIdentity,
        scope_fingerprint: str,
        candidate_id: str,
        decision: str,
        reason: str,
        *,
        evidence_refs: tuple[StoredDataRef, ...] = (),
        attempt_ref: StoredDataRef | None = None,
    ) -> None:
        key = self._candidate_scope_key(identity, scope_fingerprint)
        if decision not in {"PENDING", "INCLUDE", "EXCLUDE", "UNDECIDED", "ERROR"}:
            raise ValueError("CANDIDATE_DECISION_INVALID")
        if decision != "PENDING" and not reason.strip():
            raise ValueError("CANDIDATE_DECISION_REASON_REQUIRED")
        for ref in evidence_refs:
            self._candidate_ref_json(identity, ref)
        attempt_json = self._candidate_ref_json(identity, attempt_ref)
        refs_json = json.dumps(
            [ref.model_dump(mode="json") for ref in evidence_refs],
            sort_keys=True,
            separators=(",", ":"),
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT decision, decision_reason, decision_evidence_refs_json, "
                "decision_attempt_ref_json FROM simple_static_candidates "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND scope_fingerprint = ? AND candidate_id = ?",
                (*key, candidate_id),
            ).fetchone()
            if row is None:
                raise ValueError("CANDIDATE_NOT_FOUND")
            if row["decision"] not in {"PENDING", "ERROR"}:
                if (
                    row["decision"] == decision
                    and row["decision_reason"] == reason
                    and row["decision_evidence_refs_json"] == refs_json
                    and row["decision_attempt_ref_json"] == attempt_json
                ):
                    return
                raise ValueError("CANDIDATE_DECISION_CONFLICT")
            connection.execute(
                "UPDATE simple_static_candidates SET decision = ?, "
                "decision_reason = ?, decision_evidence_refs_json = ?, "
                "decision_attempt_ref_json = ? "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND scope_fingerprint = ? AND candidate_id = ?",
                (decision, reason, refs_json, attempt_json, *key, candidate_id),
            )

    def save_candidate_deep_status(
        self,
        identity: CheckpointIdentity,
        scope_fingerprint: str,
        candidate_id: str,
        deep_status: str,
    ) -> None:
        key = self._candidate_scope_key(identity, scope_fingerprint)
        if deep_status not in {
            "PENDING",
            "RUNNING",
            "COMPLETE",
            "NO_HYPOTHESIS",
            "ERROR",
        }:
            raise ValueError("CANDIDATE_DEEP_STATUS_INVALID")
        with self._connect() as connection:
            row = connection.execute(
                "SELECT decision FROM simple_static_candidates "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND scope_fingerprint = ? AND candidate_id = ?",
                (*key, candidate_id),
            ).fetchone()
            if row is None:
                raise ValueError("CANDIDATE_NOT_FOUND")
            if row["decision"] not in {"INCLUDE", "UNDECIDED"}:
                raise ValueError("CANDIDATE_DEEP_STATUS_CONFLICT")
            connection.execute(
                "UPDATE simple_static_candidates SET deep_status = ? "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND scope_fingerprint = ? AND candidate_id = ?",
                (deep_status, *key, candidate_id),
            )

    @staticmethod
    def _hypothesis_scope_key(
        identity: CheckpointIdentity,
    ) -> tuple[str, str, str]:
        if identity.hypothesis_id is not None:
            raise ValueError("CANDIDATE_HYPOTHESIS_SCOPE_INVALID")
        return identity.analysis_id, identity.workspace_id, identity.commit_id

    def upsert_hypothesis(
        self,
        identity: CheckpointIdentity,
        hypothesis_id: str,
        hypothesis_ref: StoredDataRef | None = None,
        *,
        chain_depth: int = 0,
        parent_hypothesis_ids: tuple[str, ...] = (),
    ) -> None:
        key = self._hypothesis_scope_key(identity)
        if (
            not hypothesis_id.strip()
            or chain_depth < 0
            or hypothesis_id in parent_hypothesis_ids
            or len(set(parent_hypothesis_ids)) != len(parent_hypothesis_ids)
        ):
            raise ValueError("CANDIDATE_HYPOTHESIS_ID_INVALID")
        ref_json = self._candidate_ref_json(identity, hypothesis_ref)
        parents_json = json.dumps(
            parent_hypothesis_ids, ensure_ascii=False, separators=(",", ":")
        )
        with self._connect() as connection:
            row = connection.execute(
                "SELECT hypothesis_ref_json, chain_depth, "
                "parent_hypothesis_ids_json "
                "FROM simple_candidate_hypotheses "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND hypothesis_id = ?",
                (*key, hypothesis_id),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO simple_candidate_hypotheses "
                    "(analysis_id, workspace_id, commit_id, hypothesis_id, "
                    "hypothesis_ref_json, chain_depth, parent_hypothesis_ids_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (*key, hypothesis_id, ref_json, chain_depth, parents_json),
                )
                return
            if row["hypothesis_ref_json"] not in {None, ref_json}:
                raise ValueError("CANDIDATE_HYPOTHESIS_REF_CONFLICT")
            previous_depth = int(row["chain_depth"])
            previous_parents = str(row["parent_hypothesis_ids_json"])
            if (previous_depth, previous_parents) != (chain_depth, parents_json):
                if previous_depth != 0 or previous_parents != "[]":
                    raise ValueError("CANDIDATE_HYPOTHESIS_METADATA_CONFLICT")
            connection.execute(
                "UPDATE simple_candidate_hypotheses "
                "SET hypothesis_ref_json = COALESCE(hypothesis_ref_json, ?), "
                "chain_depth = ?, parent_hypothesis_ids_json = ? "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND hypothesis_id = ?",
                (ref_json, chain_depth, parents_json, *key, hypothesis_id),
            )

    def hypothesis_metadata(
        self, identity: CheckpointIdentity, hypothesis_id: str
    ) -> tuple[int, tuple[str, ...]] | None:
        key = self._hypothesis_scope_key(identity)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT chain_depth, parent_hypothesis_ids_json "
                "FROM simple_candidate_hypotheses "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND hypothesis_id = ?",
                (*key, hypothesis_id),
            ).fetchone()
        if row is None:
            return None
        parents = json.loads(row["parent_hypothesis_ids_json"])
        if not isinstance(parents, list) or not all(
            isinstance(value, str) for value in parents
        ):
            raise ValueError("CANDIDATE_HYPOTHESIS_METADATA_CORRUPT")
        return int(row["chain_depth"]), tuple(parents)

    def has_hypothesis(self, identity: CheckpointIdentity, hypothesis_id: str) -> bool:
        return self.hypothesis_metadata(identity, hypothesis_id) is not None

    def register_candidate_hypothesis(
        self,
        identity: CheckpointIdentity,
        scope_fingerprint: str,
        candidate_id: str,
        hypothesis_id: str,
        hypothesis_ref: StoredDataRef,
        *,
        checkpoint: StageCheckpoint | None = None,
        chain_depth: int = 0,
        parent_hypothesis_ids: tuple[str, ...] = (),
    ) -> None:
        """Commit a focused hypothesis, link, and pending checkpoint together."""

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._register_candidate_hypothesis_connection(
                connection,
                identity,
                scope_fingerprint,
                candidate_id,
                hypothesis_id,
                hypothesis_ref,
                checkpoint=checkpoint,
                chain_depth=chain_depth,
                parent_hypothesis_ids=parent_hypothesis_ids,
            )

    def register_candidate_hypotheses_batch(
        self,
        identity: CheckpointIdentity,
        scope_fingerprint: str,
        candidate_id: str,
        registrations: Sequence[tuple[str, StoredDataRef, StageCheckpoint]],
    ) -> None:
        """Commit every seed from one candidate proposal or none of them."""

        if not registrations:
            raise ValueError("CANDIDATE_HYPOTHESIS_BATCH_EMPTY")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            for hypothesis_id, hypothesis_ref, checkpoint in registrations:
                self._register_candidate_hypothesis_connection(
                    connection,
                    identity,
                    scope_fingerprint,
                    candidate_id,
                    hypothesis_id,
                    hypothesis_ref,
                    checkpoint=checkpoint,
                )

    def _register_candidate_hypothesis_connection(
        self,
        connection: sqlite3.Connection,
        identity: CheckpointIdentity,
        scope_fingerprint: str,
        candidate_id: str,
        hypothesis_id: str,
        hypothesis_ref: StoredDataRef,
        *,
        checkpoint: StageCheckpoint | None,
        chain_depth: int = 0,
        parent_hypothesis_ids: tuple[str, ...] = (),
    ) -> None:
        key = self._candidate_scope_key(identity, scope_fingerprint)
        ref_json = self._candidate_ref_json(identity, hypothesis_ref)
        if (
            not hypothesis_id.strip()
            or chain_depth < 0
            or hypothesis_id in parent_hypothesis_ids
            or len(set(parent_hypothesis_ids)) != len(parent_hypothesis_ids)
        ):
            raise ValueError("CANDIDATE_HYPOTHESIS_ID_INVALID")
        parents_json = json.dumps(
            parent_hypothesis_ids, ensure_ascii=False, separators=(",", ":")
        )
        candidate = connection.execute(
            "SELECT decision FROM simple_static_candidates "
            "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
            "AND scope_fingerprint = ? AND candidate_id = ?",
            (*key, candidate_id),
        ).fetchone()
        if candidate is None or candidate["decision"] not in {
            "INCLUDE",
            "UNDECIDED",
        }:
            raise ValueError("CANDIDATE_HYPOTHESIS_LINK_INVALID")
        row = connection.execute(
            "SELECT hypothesis_ref_json, chain_depth, "
            "parent_hypothesis_ids_json "
            "FROM simple_candidate_hypotheses "
            "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
            "AND hypothesis_id = ?",
            (*key[:3], hypothesis_id),
        ).fetchone()
        if row is None:
            connection.execute(
                "INSERT INTO simple_candidate_hypotheses "
                "(analysis_id, workspace_id, commit_id, hypothesis_id, "
                "hypothesis_ref_json, chain_depth, parent_hypothesis_ids_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (*key[:3], hypothesis_id, ref_json, chain_depth, parents_json),
            )
        elif row["hypothesis_ref_json"] not in {None, ref_json} or (
            int(row["chain_depth"]),
            str(row["parent_hypothesis_ids_json"]),
        ) != (chain_depth, parents_json):
            raise ValueError("CANDIDATE_HYPOTHESIS_REF_CONFLICT")
        elif row["hypothesis_ref_json"] is None:
            connection.execute(
                "UPDATE simple_candidate_hypotheses "
                "SET hypothesis_ref_json = ? "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND hypothesis_id = ?",
                (ref_json, *key[:3], hypothesis_id),
            )
        connection.execute(
            "INSERT OR IGNORE INTO simple_candidate_hypothesis_links "
            "(analysis_id, workspace_id, commit_id, scope_fingerprint, "
            "candidate_id, hypothesis_id) VALUES (?, ?, ?, ?, ?, ?)",
            (*key, candidate_id, hypothesis_id),
        )
        if checkpoint is not None:
            self._insert_pending_pro_con_connection(
                connection, identity, hypothesis_id, hypothesis_ref, checkpoint
            )

    def register_free_hypothesis(
        self,
        identity: CheckpointIdentity,
        hypothesis_id: str,
        hypothesis_ref: StoredDataRef,
        checkpoint: StageCheckpoint,
        *,
        chain_depth: int = 0,
        parent_hypothesis_ids: tuple[str, ...] = (),
    ) -> None:
        """Commit a free-exploration hypothesis and its pending stage atomically."""

        key = self._hypothesis_scope_key(identity)
        ref_json = self._candidate_ref_json(identity, hypothesis_ref)
        if (
            not hypothesis_id.strip()
            or chain_depth < 0
            or hypothesis_id in parent_hypothesis_ids
            or len(set(parent_hypothesis_ids)) != len(parent_hypothesis_ids)
        ):
            raise ValueError("CANDIDATE_HYPOTHESIS_ID_INVALID")
        parents_json = json.dumps(
            parent_hypothesis_ids, ensure_ascii=False, separators=(",", ":")
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT hypothesis_ref_json, chain_depth, "
                "parent_hypothesis_ids_json FROM simple_candidate_hypotheses "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND hypothesis_id = ?",
                (*key, hypothesis_id),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO simple_candidate_hypotheses "
                    "(analysis_id, workspace_id, commit_id, hypothesis_id, "
                    "hypothesis_ref_json, chain_depth, parent_hypothesis_ids_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (*key, hypothesis_id, ref_json, chain_depth, parents_json),
                )
            elif row["hypothesis_ref_json"] not in {None, ref_json} or (
                int(row["chain_depth"]),
                str(row["parent_hypothesis_ids_json"]),
            ) != (chain_depth, parents_json):
                raise ValueError("CANDIDATE_HYPOTHESIS_REF_CONFLICT")
            elif row["hypothesis_ref_json"] is None:
                connection.execute(
                    "UPDATE simple_candidate_hypotheses "
                    "SET hypothesis_ref_json = ? "
                    "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                    "AND hypothesis_id = ?",
                    (ref_json, *key, hypothesis_id),
                )
            self._insert_pending_pro_con_connection(
                connection, identity, hypothesis_id, hypothesis_ref, checkpoint
            )

    def _insert_pending_pro_con_connection(
        self,
        connection: sqlite3.Connection,
        identity: CheckpointIdentity,
        hypothesis_id: str,
        hypothesis_ref: StoredDataRef,
        checkpoint: StageCheckpoint,
    ) -> None:
        child = identity.model_copy(update={"hypothesis_id": hypothesis_id})
        if (
            checkpoint.identity != child
            or checkpoint.stage is not SimpleStage.PRO_CON_DONE
            or checkpoint.stage_version != STAGE_VERSION[SimpleStage.PRO_CON_DONE]
            or checkpoint.status is not StageStatus.PENDING
            or not checkpoint.input_refs
            or checkpoint.input_refs[0] != hypothesis_ref
            or checkpoint.input_hash != input_reference_hash(checkpoint.input_refs)
        ):
            raise ValueError("CANDIDATE_HYPOTHESIS_CHECKPOINT_INVALID")
        row = connection.execute(
            "SELECT checkpoint_json FROM simple_runtime_checkpoints "
            "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
            (identity.analysis_id, hypothesis_id, SimpleStage.PRO_CON_DONE.value),
        ).fetchone()
        if row is not None:
            existing = StageCheckpoint.model_validate_json(row["checkpoint_json"])
            if (
                existing.identity != child
                or existing.input_refs != checkpoint.input_refs
                or existing.input_hash != checkpoint.input_hash
            ):
                raise ValueError("CANDIDATE_HYPOTHESIS_CHECKPOINT_CONFLICT")
            return
        self._upsert_checkpoint_connection(connection, checkpoint)

    def list_incomplete_hypotheses(
        self,
        identity: CheckpointIdentity,
        *,
        after_id: str | None = None,
        limit: int = 100,
    ) -> tuple[str, ...]:
        """Page nonterminal hypotheses using current checkpoint evidence."""

        key = self._hypothesis_scope_key(identity)
        if limit <= 0:
            raise ValueError("CANDIDATE_PAGE_ARGUMENT_INVALID")
        selected: list[str] = []
        scanned_after = after_id or ""
        with self._connect() as connection:
            while len(selected) < limit:
                rows = connection.execute(
                    "SELECT hypothesis_id FROM simple_candidate_hypotheses "
                    "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                    "AND hypothesis_id > ? ORDER BY hypothesis_id LIMIT ?",
                    (*key, scanned_after, max(32, limit)),
                ).fetchall()
                if not rows:
                    break
                for row in rows:
                    hypothesis_id = str(row["hypothesis_id"])
                    scanned_after = hypothesis_id
                    checkpoints = connection.execute(
                        "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                        "WHERE analysis_id = ? AND hypothesis_key = ?",
                        (identity.analysis_id, hypothesis_id),
                    ).fetchall()
                    stages: dict[SimpleStage, StageCheckpoint] = {}
                    for item in checkpoints:
                        checkpoint = StageCheckpoint.model_validate_json(
                            item["checkpoint_json"]
                        )
                        if checkpoint.identity != identity.model_copy(
                            update={"hypothesis_id": hypothesis_id}
                        ):
                            raise ValueError("CANDIDATE_HYPOTHESIS_CHECKPOINT_CORRUPT")
                        if (
                            checkpoint.status is StageStatus.SUCCEEDED
                            and checkpoint.stage_version
                            == STAGE_VERSION[checkpoint.stage]
                        ):
                            stages[checkpoint.stage] = checkpoint
                    final = stages.get(SimpleStage.VERIFICATION_FINAL_DONE)
                    chain = stages.get(SimpleStage.CHAINING_DONE)
                    terminal = (
                        terminal_poc_outcome(stages.get(SimpleStage.POC_EXECUTION_DONE))
                        is not None
                        or final is not None
                        and (
                            final.verdict == "FALSE"
                            or final.verdict == "HOLD"
                            and chain is not None
                        )
                        or terminal_gate_outcome(stages.get(SimpleStage.TECH_GATE_DONE))
                        is not None
                        or SimpleStage.REPORT_DONE in stages
                    )
                    if not terminal:
                        selected.append(hypothesis_id)
                        if len(selected) >= limit:
                            break
                if len(rows) < max(32, limit):
                    break
        return tuple(selected)

    def list_hypotheses(
        self,
        identity: CheckpointIdentity,
        *,
        after_id: str | None = None,
        limit: int = 100,
    ) -> tuple[str, ...]:
        key = self._hypothesis_scope_key(identity)
        if limit <= 0:
            raise ValueError("CANDIDATE_PAGE_ARGUMENT_INVALID")
        query = (
            "SELECT hypothesis_id FROM simple_candidate_hypotheses "
            "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ?"
        )
        args: list[object] = list(key)
        if after_id is not None:
            query += " AND hypothesis_id > ?"
            args.append(after_id)
        query += " ORDER BY hypothesis_id LIMIT ?"
        args.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, args).fetchall()
        return tuple(str(row["hypothesis_id"]) for row in rows)

    def hypothesis_count(self, identity: CheckpointIdentity) -> int:
        key = self._hypothesis_scope_key(identity)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM simple_candidate_hypotheses "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ?",
                key,
            ).fetchone()
        return int(row[0]) if row is not None else 0

    def link_candidate_hypothesis(
        self,
        identity: CheckpointIdentity,
        scope_fingerprint: str,
        candidate_id: str,
        hypothesis_id: str,
    ) -> None:
        key = self._candidate_scope_key(identity, scope_fingerprint)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            candidate = connection.execute(
                "SELECT 1 FROM simple_static_candidates "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND scope_fingerprint = ? AND candidate_id = ?",
                (*key, candidate_id),
            ).fetchone()
            hypothesis = connection.execute(
                "SELECT 1 FROM simple_candidate_hypotheses "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND hypothesis_id = ?",
                (*key[:3], hypothesis_id),
            ).fetchone()
            if candidate is None or hypothesis is None:
                raise ValueError("CANDIDATE_HYPOTHESIS_LINK_INVALID")
            connection.execute(
                "INSERT OR IGNORE INTO simple_candidate_hypothesis_links "
                "(analysis_id, workspace_id, commit_id, scope_fingerprint, "
                "candidate_id, hypothesis_id) VALUES (?, ?, ?, ?, ?, ?)",
                (*key, candidate_id, hypothesis_id),
            )

    def list_candidate_hypothesis_ids(
        self,
        identity: CheckpointIdentity,
        scope_fingerprint: str,
        candidate_id: str,
        *,
        after_id: str | None = None,
        limit: int = 100,
    ) -> tuple[str, ...]:
        key = self._candidate_scope_key(identity, scope_fingerprint)
        if limit <= 0:
            raise ValueError("CANDIDATE_PAGE_ARGUMENT_INVALID")
        query = (
            "SELECT hypothesis_id FROM simple_candidate_hypothesis_links "
            "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
            "AND scope_fingerprint = ? AND candidate_id = ?"
        )
        args: list[object] = [*key, candidate_id]
        if after_id is not None:
            query += " AND hypothesis_id > ?"
            args.append(after_id)
        query += " ORDER BY hypothesis_id LIMIT ?"
        args.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, args).fetchall()
        return tuple(str(row["hypothesis_id"]) for row in rows)

    @staticmethod
    def _opengrep_batch_key(
        identity: CheckpointIdentity,
        repository: str,
        fingerprint: str,
        batch_key: str,
    ) -> tuple[str, str, str, str, str, str]:
        if identity.hypothesis_id is not None or not all(
            value.strip() for value in (repository, fingerprint, batch_key)
        ):
            raise ValueError("OPENGREP_BATCH_KEY_INVALID")
        return (
            identity.analysis_id,
            identity.workspace_id,
            identity.commit_id,
            repository,
            fingerprint,
            batch_key,
        )

    @staticmethod
    def _require_opengrep_ref_scope(
        identity: CheckpointIdentity, ref: StoredDataRef
    ) -> None:
        if (str(ref.workspace_id), str(ref.commit_id)) != (
            identity.workspace_id,
            identity.commit_id,
        ) or (
            ref.record_id is not None
            or ref.data_kind != "artifact"
            or str(ref.stored_data_id) != ref.content_hash
        ):
            raise ValueError("OPENGREP_BATCH_REF_SCOPE_MISMATCH")

    @classmethod
    def _valid_opengrep_batch_ref(
        cls, identity: CheckpointIdentity, raw: str
    ) -> StoredDataRef | None:
        try:
            ref = StoredDataRef.model_validate_json(raw)
            cls._require_opengrep_ref_scope(identity, ref)
        except ValueError:
            return None
        return ref

    def opengrep_batch_ref(
        self,
        identity: CheckpointIdentity,
        repository: str,
        fingerprint: str,
        batch_key: str,
    ) -> StoredDataRef | None:
        key = self._opengrep_batch_key(identity, repository, fingerprint, batch_key)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT ref_json FROM simple_opengrep_batch_progress "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND repository = ? AND fingerprint = ? AND batch_key = ?",
                key,
            ).fetchone()
        if row is None:
            return None
        return self._valid_opengrep_batch_ref(identity, row["ref_json"])

    def opengrep_partial_refs(
        self,
        identity: CheckpointIdentity,
        repository: str,
        fingerprints: frozenset[str],
        batch_key: str,
    ) -> tuple[StoredDataRef, ...]:
        """Return separately proven partial raws for the same scoped batch."""

        self._opengrep_batch_key(identity, repository, "partial", batch_key)
        if not fingerprints:
            return ()
        prefix = f"{batch_key}:partial:"
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT fingerprint, ref_json FROM simple_opengrep_batch_progress "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND repository = ? AND substr(batch_key, 1, ?) = ? "
                "ORDER BY rowid DESC",
                (
                    identity.analysis_id,
                    identity.workspace_id,
                    identity.commit_id,
                    repository,
                    len(prefix),
                    prefix,
                ),
            ).fetchall()
        refs: list[StoredDataRef] = []
        for row in rows:
            if row["fingerprint"] not in fingerprints:
                continue
            ref = self._valid_opengrep_batch_ref(identity, row["ref_json"])
            if ref is not None and ref not in refs:
                refs.append(ref)
        return tuple(refs)

    def save_opengrep_partial_proof(
        self,
        identity: CheckpointIdentity,
        repository: str,
        fingerprint: str,
        batch_key: str,
        ref: StoredDataRef,
    ) -> None:
        """Keep complementary exit-zero partial evidence across resumes."""

        self.save_opengrep_batch(
            identity,
            repository,
            fingerprint,
            f"{batch_key}:partial:{ref.content_hash}",
            ref,
        )

    def save_opengrep_batch(
        self,
        identity: CheckpointIdentity,
        repository: str,
        fingerprint: str,
        batch_key: str,
        ref: StoredDataRef,
        *,
        replaces: StoredDataRef | None = None,
    ) -> None:
        """Record one accepted batch; replace only an explicitly matched old ref."""

        key = self._opengrep_batch_key(identity, repository, fingerprint, batch_key)
        self._require_opengrep_ref_scope(identity, ref)
        encoded = ref.model_dump_json()
        with self._connect() as connection:
            if replaces is None:
                inserted = connection.execute(
                    "INSERT OR IGNORE INTO simple_opengrep_batch_progress "
                    "(analysis_id, workspace_id, commit_id, repository, "
                    "fingerprint, batch_key, ref_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (*key, encoded),
                )
                if inserted.rowcount == 1:
                    return
            row = connection.execute(
                "SELECT ref_json FROM simple_opengrep_batch_progress "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND repository = ? AND fingerprint = ? AND batch_key = ?",
                key,
            ).fetchone()
            if row is None:
                raise ValueError("OPENGREP_BATCH_PROGRESS_CONFLICT")
            current = self._valid_opengrep_batch_ref(identity, row["ref_json"])
            if current == ref:
                return
            if current is not None and (replaces is None or current != replaces):
                raise ValueError("OPENGREP_BATCH_PROGRESS_CONFLICT")
            updated = connection.execute(
                "UPDATE simple_opengrep_batch_progress SET ref_json = ? "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND repository = ? AND fingerprint = ? AND batch_key = ? "
                "AND ref_json = ?",
                (encoded, *key, row["ref_json"]),
            )
            if updated.rowcount != 1:
                raise ValueError("OPENGREP_BATCH_PROGRESS_CONFLICT")

    @staticmethod
    def _static_ref_json(
        identity: CheckpointIdentity, ref: StoredDataRef | None
    ) -> str | None:
        if ref is None:
            return None
        try:
            SimpleCheckpointStore._require_opengrep_ref_scope(identity, ref)
        except ValueError as error:
            raise ValueError("STATIC_SCAN_REF_SCOPE_MISMATCH") from error
        return ref.model_dump_json()

    def save_static_scan_attempt(
        self,
        identity: CheckpointIdentity,
        repository: str,
        fingerprint: str,
        tool: str,
        run_key: str,
        status: Literal["SUCCEEDED", "BLOCKED"],
        raw_ref: StoredDataRef | None,
        coverage_ref: StoredDataRef | None,
        error_code: str | None,
        request_ref: StoredDataRef | None = None,
    ) -> None:
        if identity.hypothesis_id is not None or not all(
            part.strip() for part in (repository, fingerprint, tool, run_key)
        ):
            raise ValueError("STATIC_SCAN_KEY_INVALID")
        raw_json = self._static_ref_json(identity, raw_ref)
        coverage_json = self._static_ref_json(identity, coverage_ref)
        request_json = self._static_ref_json(identity, request_ref)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO simple_static_scan_attempts "
                "(analysis_id, workspace_id, commit_id, repository, fingerprint, "
                "tool, run_key, status, raw_ref_json, coverage_ref_json, "
                "error_code, request_ref_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT (analysis_id, workspace_id, commit_id, repository, "
                "fingerprint, tool, run_key) DO UPDATE SET "
                "status=excluded.status, raw_ref_json=excluded.raw_ref_json, "
                "coverage_ref_json=excluded.coverage_ref_json, "
                "error_code=excluded.error_code, "
                "request_ref_json=COALESCE(excluded.request_ref_json, "
                "simple_static_scan_attempts.request_ref_json)",
                (
                    identity.analysis_id,
                    identity.workspace_id,
                    identity.commit_id,
                    repository,
                    fingerprint,
                    tool,
                    run_key,
                    status,
                    raw_json,
                    coverage_json,
                    error_code,
                    request_json,
                ),
            )

    def record_static_scan_execution(
        self,
        identity: CheckpointIdentity,
        repository: str,
        fingerprint: str,
        tool: str,
        run_key: str,
        status: Literal["SUCCEEDED", "BLOCKED"],
        raw_ref: StoredDataRef | None,
        error_code: str | None,
        request_ref: StoredDataRef | None = None,
        error_ref: StoredDataRef | None = None,
        *,
        timeout_seconds: float,
    ) -> int:
        """Append exactly one actual scanner invocation and return its stable ID."""

        if identity.hypothesis_id is not None or not all(
            part.strip() for part in (repository, fingerprint, tool, run_key)
        ):
            raise ValueError("STATIC_SCAN_KEY_INVALID")
        if status not in {"SUCCEEDED", "BLOCKED"}:
            raise ValueError("STATIC_SCAN_EXECUTION_STATUS_INVALID")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("STATIC_SCAN_TIMEOUT_INVALID")
        raw_json = self._static_ref_json(identity, raw_ref)
        request_json = self._static_ref_json(identity, request_ref)
        error_json = self._static_ref_json(identity, error_ref)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "INSERT INTO simple_static_scan_executions "
                "(analysis_id, workspace_id, commit_id, repository, fingerprint, "
                "tool, run_key, status, raw_ref_json, error_code, request_ref_json, "
                "error_ref_json, timeout_seconds) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    identity.analysis_id,
                    identity.workspace_id,
                    identity.commit_id,
                    repository,
                    fingerprint,
                    tool,
                    run_key,
                    status,
                    raw_json,
                    error_code,
                    request_json,
                    error_json,
                    float(timeout_seconds),
                ),
            )
            execution_id = cursor.lastrowid
            if execution_id is None:
                raise RuntimeError("STATIC_SCAN_EXECUTION_ID_MISSING")
            return execution_id

    def begin_static_scan_execution(
        self,
        identity: CheckpointIdentity,
        repository: str,
        fingerprint: str,
        tool: str,
        run_key: str,
        request_ref: StoredDataRef | None,
        *,
        timeout_seconds: float,
    ) -> int:
        """Durably reserve one invocation before calling the scanner process."""

        if identity.hypothesis_id is not None or not all(
            part.strip() for part in (repository, fingerprint, tool, run_key)
        ):
            raise ValueError("STATIC_SCAN_KEY_INVALID")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("STATIC_SCAN_TIMEOUT_INVALID")
        request_json = self._static_ref_json(identity, request_ref)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "INSERT INTO simple_static_scan_executions "
                "(analysis_id, workspace_id, commit_id, repository, fingerprint, "
                "tool, run_key, status, request_ref_json, timeout_seconds) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, 'STARTED', ?, ?)",
                (
                    identity.analysis_id,
                    identity.workspace_id,
                    identity.commit_id,
                    repository,
                    fingerprint,
                    tool,
                    run_key,
                    request_json,
                    float(timeout_seconds),
                ),
            )
            execution_id = cursor.lastrowid
            if execution_id is None:
                raise RuntimeError("STATIC_SCAN_EXECUTION_ID_MISSING")
            return execution_id

    def finish_static_scan_execution(
        self,
        execution_id: int,
        identity: CheckpointIdentity,
        status: Literal["SUCCEEDED", "BLOCKED"],
        raw_ref: StoredDataRef | None,
        error_code: str | None,
        request_ref: StoredDataRef | None,
        error_ref: StoredDataRef | None,
    ) -> None:
        """Finalize exactly one started invocation in its original scope."""

        if (
            isinstance(execution_id, bool)
            or not isinstance(execution_id, int)
            or execution_id < 1
        ):
            raise ValueError("STATIC_SCAN_EXECUTION_ID_INVALID")
        if identity.hypothesis_id is not None:
            raise ValueError("STATIC_SCAN_KEY_INVALID")
        if status not in {"SUCCEEDED", "BLOCKED"}:
            raise ValueError("STATIC_SCAN_EXECUTION_STATUS_INVALID")
        raw_json = self._static_ref_json(identity, raw_ref)
        request_json = self._static_ref_json(identity, request_ref)
        error_json = self._static_ref_json(identity, error_ref)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                "UPDATE simple_static_scan_executions SET "
                "status = ?, raw_ref_json = ?, error_code = ?, "
                "request_ref_json = COALESCE(?, request_ref_json), "
                "error_ref_json = ? WHERE execution_id = ? "
                "AND analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND status = 'STARTED'",
                (
                    status,
                    raw_json,
                    error_code,
                    request_json,
                    error_json,
                    execution_id,
                    identity.analysis_id,
                    identity.workspace_id,
                    identity.commit_id,
                ),
            )
            if updated.rowcount != 1:
                raise ValueError("STATIC_SCAN_EXECUTION_NOT_STARTED")

    @staticmethod
    def _static_execution_filter(
        identity: CheckpointIdentity,
        repository: str,
        fingerprint: str | None,
        tool: str | None,
        run_key: str | None,
    ) -> tuple[str, tuple[str, ...]]:
        if (
            identity.hypothesis_id is not None
            or not repository.strip()
            or any(
                part is not None and not part.strip()
                for part in (fingerprint, tool, run_key)
            )
        ):
            raise ValueError("STATIC_SCAN_KEY_INVALID")
        filters = (
            "analysis_id = ? AND workspace_id = ? AND commit_id = ? AND repository = ?"
        )
        params = [
            identity.analysis_id,
            identity.workspace_id,
            identity.commit_id,
            repository,
        ]
        for column, value in (
            ("fingerprint", fingerprint),
            ("tool", tool),
            ("run_key", run_key),
        ):
            if value is not None:
                filters += f" AND {column} = ?"
                params.append(value)
        return filters, tuple(params)

    def count_static_scan_executions(
        self,
        identity: CheckpointIdentity,
        repository: str,
        fingerprint: str | None = None,
        *,
        tool: str | None = None,
        run_key: str | None = None,
    ) -> int:
        """Count durable dispatch records, including unfinished STARTED rows."""

        filters, params = self._static_execution_filter(
            identity, repository, fingerprint, tool, run_key
        )
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM simple_static_scan_executions WHERE " + filters,
                params,
            ).fetchone()
        return int(row[0])

    def static_scan_legacy_history_incomplete(
        self,
        identity: CheckpointIdentity,
        repository: str,
        fingerprint: str,
    ) -> bool:
        """Whether this scope had summary rows before the ledger existed."""

        if not fingerprint.strip():
            raise ValueError("STATIC_SCAN_KEY_INVALID")
        filters, params = self._static_execution_filter(
            identity, repository, fingerprint, None, None
        )
        with self._connect() as connection:
            row = connection.execute(
                "SELECT 1 FROM simple_static_scan_legacy_history WHERE "
                + filters
                + " LIMIT 1",
                params,
            ).fetchone()
        return row is not None

    @classmethod
    def _static_execution_ref(
        cls, identity: CheckpointIdentity, raw: str | None
    ) -> StoredDataRef | None:
        if raw is None:
            return None
        ref = cls._valid_opengrep_batch_ref(identity, raw)
        if ref is None:
            raise ValueError("STATIC_SCAN_EXECUTION_REF_INVALID")
        return ref

    def list_static_scan_executions(
        self,
        identity: CheckpointIdentity,
        repository: str,
        fingerprint: str | None = None,
        *,
        tool: str | None = None,
        run_key: str | None = None,
    ) -> tuple[StaticScanExecution, ...]:
        """Read append-only invocation history in execution order."""

        filters, params = self._static_execution_filter(
            identity, repository, fingerprint, tool, run_key
        )
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT execution_id, repository, fingerprint, tool, run_key, "
                "status, raw_ref_json, error_code, request_ref_json, "
                "error_ref_json, timeout_seconds "
                "FROM simple_static_scan_executions WHERE "
                + filters
                + " ORDER BY execution_id",
                params,
            ).fetchall()
        executions: list[StaticScanExecution] = []
        for row in rows:
            if row["status"] not in {"STARTED", "SUCCEEDED", "BLOCKED"}:
                raise ValueError("STATIC_SCAN_EXECUTION_STATUS_INVALID")
            executions.append(
                StaticScanExecution(
                    execution_id=row["execution_id"],
                    repository=row["repository"],
                    fingerprint=row["fingerprint"],
                    tool=row["tool"],
                    run_key=row["run_key"],
                    status=row["status"],
                    raw_ref=self._static_execution_ref(identity, row["raw_ref_json"]),
                    error_code=row["error_code"],
                    request_ref=self._static_execution_ref(
                        identity, row["request_ref_json"]
                    ),
                    error_ref=self._static_execution_ref(
                        identity, row["error_ref_json"]
                    ),
                    timeout_seconds=row["timeout_seconds"],
                )
            )
        return tuple(executions)

    def list_static_scan_attempts(
        self, identity: CheckpointIdentity, repository: str, fingerprint: str
    ) -> tuple[StaticScanAttempt, ...]:
        if identity.hypothesis_id is not None:
            raise ValueError("STATIC_SCAN_KEY_INVALID")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT tool, run_key, status, raw_ref_json, coverage_ref_json, "
                "error_code, request_ref_json FROM simple_static_scan_attempts "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND repository = ? AND fingerprint = ? ORDER BY tool, run_key",
                (
                    identity.analysis_id,
                    identity.workspace_id,
                    identity.commit_id,
                    repository,
                    fingerprint,
                ),
            ).fetchall()
        attempts: list[StaticScanAttempt] = []
        for row in rows:
            if row["status"] not in {"SUCCEEDED", "BLOCKED"}:
                continue
            raw_ref = (
                self._valid_opengrep_batch_ref(identity, row["raw_ref_json"])
                if row["raw_ref_json"] is not None
                else None
            )
            coverage_ref = (
                self._valid_opengrep_batch_ref(identity, row["coverage_ref_json"])
                if row["coverage_ref_json"] is not None
                else None
            )
            request_ref = (
                self._valid_opengrep_batch_ref(identity, row["request_ref_json"])
                if row["request_ref_json"] is not None
                else None
            )
            if (
                row["raw_ref_json"] is not None
                and raw_ref is None
                or row["coverage_ref_json"] is not None
                and coverage_ref is None
                or row["request_ref_json"] is not None
                and request_ref is None
            ):
                continue
            attempts.append(
                StaticScanAttempt(
                    fingerprint=fingerprint,
                    tool=row["tool"],
                    run_key=row["run_key"],
                    status=row["status"],
                    raw_ref=raw_ref,
                    coverage_ref=coverage_ref,
                    request_ref=request_ref,
                    error_code=row["error_code"],
                )
            )
        return tuple(attempts)

    def list_static_scan_replay_attempts(
        self,
        identity: CheckpointIdentity,
        repository: str,
        fingerprint: str,
        *,
        tool: str,
    ) -> tuple[StaticScanAttempt, ...]:
        """Read legacy summaries and every raw-bearing invocation for replay."""

        filters, params = self._static_execution_filter(
            identity, repository, fingerprint, tool, None
        )
        attempts = [
            attempt
            for attempt in self.list_static_scan_attempts(
                identity, repository, fingerprint
            )
            if attempt.tool == tool
        ]
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT tool, run_key, status, raw_ref_json, error_code, "
                "request_ref_json FROM simple_static_scan_executions WHERE "
                + filters
                + " AND status IN ('SUCCEEDED', 'BLOCKED') "
                "AND raw_ref_json IS NOT NULL ORDER BY execution_id",
                params,
            ).fetchall()
        for row in rows:
            raw_ref = self._valid_opengrep_batch_ref(identity, row["raw_ref_json"])
            request_json = row["request_ref_json"]
            request_ref = (
                self._valid_opengrep_batch_ref(identity, request_json)
                if request_json is not None
                else None
            )
            if raw_ref is None or request_json is not None and request_ref is None:
                continue
            attempts.append(
                StaticScanAttempt(
                    fingerprint=fingerprint,
                    tool=row["tool"],
                    run_key=row["run_key"],
                    status=row["status"],
                    raw_ref=raw_ref,
                    coverage_ref=None,
                    request_ref=request_ref,
                    error_code=row["error_code"],
                )
            )
        unique: dict[
            tuple[str, str, str, str, str | None, str | None], StaticScanAttempt
        ] = {}
        for attempt in attempts:
            key = (
                attempt.tool,
                attempt.run_key,
                attempt.status,
                attempt.raw_ref.model_dump_json() if attempt.raw_ref else "",
                attempt.request_ref.model_dump_json() if attempt.request_ref else None,
                attempt.error_code,
            )
            unique.setdefault(key, attempt)
        return tuple(unique.values())

    def list_static_scan_attempts_for_run_key(
        self,
        identity: CheckpointIdentity,
        repository: str,
        tool: str,
        run_key: str,
    ) -> tuple[StaticScanAttempt, ...]:
        """Find exact-run prior attempts across coverage fingerprints, newest first."""

        if identity.hypothesis_id is not None or not all(
            part.strip() for part in (repository, tool, run_key)
        ):
            raise ValueError("STATIC_SCAN_KEY_INVALID")
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT fingerprint, tool, run_key, status, raw_ref_json, "
                "coverage_ref_json, "
                "error_code, request_ref_json FROM simple_static_scan_attempts "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND repository = ? AND tool = ? AND run_key = ? "
                "ORDER BY rowid DESC",
                (
                    identity.analysis_id,
                    identity.workspace_id,
                    identity.commit_id,
                    repository,
                    tool,
                    run_key,
                ),
            ).fetchall()
        attempts: list[StaticScanAttempt] = []
        for row in rows:
            if row["status"] not in {"SUCCEEDED", "BLOCKED"}:
                continue
            raw_ref = (
                self._valid_opengrep_batch_ref(identity, row["raw_ref_json"])
                if row["raw_ref_json"] is not None
                else None
            )
            coverage_ref = (
                self._valid_opengrep_batch_ref(identity, row["coverage_ref_json"])
                if row["coverage_ref_json"] is not None
                else None
            )
            request_ref = (
                self._valid_opengrep_batch_ref(identity, row["request_ref_json"])
                if row["request_ref_json"] is not None
                else None
            )
            if (
                row["raw_ref_json"] is not None
                and raw_ref is None
                or row["coverage_ref_json"] is not None
                and coverage_ref is None
                or row["request_ref_json"] is not None
                and request_ref is None
            ):
                continue
            attempts.append(
                StaticScanAttempt(
                    fingerprint=row["fingerprint"],
                    tool=row["tool"],
                    run_key=row["run_key"],
                    status=row["status"],
                    raw_ref=raw_ref,
                    coverage_ref=coverage_ref,
                    request_ref=request_ref,
                    error_code=row["error_code"],
                )
            )
        return tuple(attempts)

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

    def report_draft(
        self,
        identity: CheckpointIdentity,
        source_hash: str,
        finding_ref: StoredDataRef,
    ) -> StoredDataRef | None:
        """Find a validated draft for the exact current Finding and source set."""

        with self._connect() as connection:
            row = connection.execute(
                "SELECT finding_ref_json, draft_ref_json FROM simple_report_drafts "
                "WHERE identity_json = ? AND input_hash = ? AND stage_version = ?",
                (
                    identity.model_dump_json(),
                    source_hash,
                    STAGE_VERSION[SimpleStage.REPORT_DONE],
                ),
            ).fetchone()
        if row is None:
            return None
        if StoredDataRef.model_validate_json(row["finding_ref_json"]) != finding_ref:
            raise ValueError("REPORT_DRAFT_FINDING_CONFLICT")
        return StoredDataRef.model_validate_json(row["draft_ref_json"])

    def save_report_draft(
        self,
        identity: CheckpointIdentity,
        source_hash: str,
        finding_ref: StoredDataRef,
        draft_ref: StoredDataRef,
    ) -> None:
        """Persist the validated LLM draft before fallible report publication."""

        values = (
            identity.model_dump_json(),
            source_hash,
            STAGE_VERSION[SimpleStage.REPORT_DONE],
            finding_ref.model_dump_json(),
            draft_ref.model_dump_json(),
        )
        with self._connect() as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO simple_report_drafts "
                "(identity_json, input_hash, stage_version, "
                "finding_ref_json, draft_ref_json) VALUES (?, ?, ?, ?, ?)",
                values,
            )
            if cursor.rowcount == 0:
                row = connection.execute(
                    "SELECT finding_ref_json, draft_ref_json FROM simple_report_drafts "
                    "WHERE identity_json = ? AND input_hash = ? AND stage_version = ?",
                    values[:3],
                ).fetchone()
                if (
                    row is None
                    or (row["finding_ref_json"], row["draft_ref_json"]) != values[3:]
                ):
                    raise ValueError("REPORT_DRAFT_CONFLICT")

    def save_analysis_run(self, run: object) -> None:
        validated = SimpleAnalysisRun.model_validate(run)
        with self._connect() as connection:
            self._upsert_analysis_run_connection(connection, validated)

    @staticmethod
    def _upsert_analysis_run_connection(
        connection: sqlite3.Connection, run: SimpleAnalysisRun
    ) -> None:
        connection.execute(
            """
            INSERT INTO simple_analysis_runs (analysis_id, run_json)
            VALUES (?, ?)
            ON CONFLICT (analysis_id) DO UPDATE SET run_json = excluded.run_json
            """,
            (run.analysis_id, run.model_dump_json()),
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
        owner: AttemptOwner | None = None,
        retry_of: str | None = None,
        prompt_bytes: PromptByteCounts | None = None,
    ) -> None:
        if owner is not None and owner.analysis_id != analysis_id:
            raise ValueError("LLM_ATTEMPT_OWNER_INVALID")
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
                    "SELECT attempt_id, analysis_id, agent, model, attempt_number, "
                    "status, elapsed_ms, input_tokens, output_tokens, cost_cents, "
                    "artifact_ref_json FROM simple_llm_attempts WHERE attempt_id = ?",
                    (attempt_id,),
                ).fetchone()
                if row is None or tuple(row) != values:
                    raise ValueError("LLM_ATTEMPT_CONFLICT")
            if owner is not None or retry_of is not None or prompt_bytes is not None:
                metadata = (
                    attempt_id,
                    analysis_id,
                    owner.stage if owner else None,
                    json.dumps(owner.candidate_ids, separators=(",", ":"))
                    if owner
                    else None,
                    owner.hypothesis_id if owner else None,
                    owner.surface_id if owner else None,
                    owner.file_path if owner else None,
                    owner.batch_id if owner else None,
                    owner.context_id if owner else None,
                    owner.checkpoint_attempt_id if owner else None,
                    retry_of,
                    prompt_bytes.raw_source_bytes if prompt_bytes else None,
                    prompt_bytes.shared_context_bytes if prompt_bytes else None,
                    prompt_bytes.candidate_specific_bytes if prompt_bytes else None,
                    prompt_bytes.fixed_prompt_bytes if prompt_bytes else None,
                )
                inserted = connection.execute(
                    "INSERT OR IGNORE INTO simple_llm_attempt_metadata VALUES "
                    "(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    metadata,
                )
                if inserted.rowcount == 0:
                    row = connection.execute(
                        "SELECT attempt_id, analysis_id, stage, candidate_ids_json, "
                        "hypothesis_id, surface_id, file_path, batch_id, context_id, "
                        "checkpoint_attempt_id, retry_of, raw_source_bytes, "
                        "shared_context_bytes, candidate_specific_bytes, "
                        "fixed_prompt_bytes FROM simple_llm_attempt_metadata "
                        "WHERE attempt_id = ?",
                        (attempt_id,),
                    ).fetchone()
                    if row is None or tuple(row) != metadata:
                        raise ValueError("LLM_ATTEMPT_CONFLICT")

    def unresolved_codex_call(self, analysis_id: str) -> str | None:
        """Return the durable call ID that still needs process resolution."""

        with self._connect() as connection:
            row = connection.execute(
                "SELECT call_id FROM simple_codex_calls "
                "WHERE analysis_id = ? AND status = 'IN_FLIGHT'",
                (analysis_id,),
            ).fetchone()
        return str(row["call_id"]) if row is not None else None

    def confirmed_codex_call_covering(
        self, analysis_id: str, observed_at: datetime
    ) -> bool:
        """Match a sibling's blocked time to a resolved, audited Codex call."""

        if observed_at.tzinfo is None:
            return False
        observed_utc = observed_at.astimezone(UTC)
        with self._connect() as connection:
            unresolved = connection.execute(
                "SELECT 1 FROM simple_codex_calls "
                "WHERE analysis_id = ? AND status = 'IN_FLIGHT' LIMIT 1",
                (analysis_id,),
            ).fetchone()
            if unresolved is not None:
                return False
            rows = connection.execute(
                "SELECT started_at, resolved_at FROM simple_codex_calls "
                "WHERE analysis_id = ? AND status = 'CONFIRMED' "
                "AND confirmation_ref_json IS NOT NULL AND resolved_at IS NOT NULL",
                (analysis_id,),
            ).fetchall()
        for row in rows:
            try:
                started = datetime.fromisoformat(row["started_at"])
                resolved = datetime.fromisoformat(row["resolved_at"])
            except (TypeError, ValueError):
                continue
            if (
                started.tzinfo is not None
                and resolved.tzinfo is not None
                and started.astimezone(UTC) <= observed_utc <= resolved.astimezone(UTC)
            ):
                return True
        return False

    def begin_codex_call(self, call_id: str, analysis_id: str) -> bool:
        """Atomically reserve one Codex process for an analysis across processes."""

        if not call_id or not analysis_id:
            raise ValueError("CODEX_CALL_IDENTITY_INVALID")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT 1 FROM simple_codex_calls "
                "WHERE analysis_id = ? AND status = 'IN_FLIGHT'",
                (analysis_id,),
            ).fetchone()
            if row is not None:
                return False
            connection.execute(
                "INSERT INTO simple_codex_calls "
                "(call_id, analysis_id, status, started_at) "
                "VALUES (?, ?, 'IN_FLIGHT', ?)",
                (call_id, analysis_id, datetime.now(UTC).isoformat()),
            )
            run = connection.execute(
                "SELECT run_json FROM simple_analysis_runs WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()
            if run is not None:
                version = SimpleAnalysisRun.model_validate_json(
                    run["run_json"]
                ).candidate_pipeline_version
                if version is not None:
                    connection.execute(
                        "INSERT INTO simple_codex_call_versions "
                        "(call_id, analysis_id, candidate_pipeline_version) "
                        "VALUES (?, ?, ?)",
                        (call_id, analysis_id, version),
                    )
            return True

    def begin_codex_child_spawn(
        self, *, call_id: str, analysis_id: str, phase: str
    ) -> None:
        """Durably record intent before any one of the three Codex child spawns."""

        if phase not in {"VERSION", "LOGIN", "EXEC"}:
            raise ValueError("CODEX_CHILD_IDENTITY_INVALID")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            call = connection.execute(
                "SELECT 1 FROM simple_codex_calls WHERE call_id = ? "
                "AND analysis_id = ? AND status = 'IN_FLIGHT'",
                (call_id, analysis_id),
            ).fetchone()
            if call is None:
                raise ValueError("CODEX_CHILD_IDENTITY_INVALID")
            try:
                connection.execute(
                    "INSERT INTO simple_codex_child_spawns "
                    "(call_id, analysis_id, phase, status) "
                    "VALUES (?, ?, ?, 'SPAWNING')",
                    (call_id, analysis_id, phase),
                )
            except sqlite3.IntegrityError as error:
                raise ValueError("CODEX_CHILD_IDENTITY_CONFLICT") from error

    def record_codex_child_spawn(
        self,
        *,
        call_id: str,
        analysis_id: str,
        phase: str,
        pid: int,
        start_identity: str,
    ) -> None:
        """Bind a spawned OS process to its pre-existing durable intent."""

        if type(pid) is not int or pid <= 0 or not start_identity:
            raise ValueError("CODEX_CHILD_IDENTITY_INVALID")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                "UPDATE simple_codex_child_spawns SET status = 'CAPTURED', "
                "pid = ?, start_identity = ? WHERE call_id = ? "
                "AND analysis_id = ? AND phase = ? AND status = 'SPAWNING'",
                (pid, start_identity, call_id, analysis_id, phase),
            )
            if changed.rowcount != 1:
                raise ValueError("CODEX_CHILD_IDENTITY_CONFLICT")

    def mark_codex_child_exited(
        self,
        *,
        call_id: str,
        analysis_id: str,
        phase: str,
        pid: int,
        start_identity: str,
    ) -> None:
        """A checked child exit may settle only the exact captured identity."""

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                "UPDATE simple_codex_child_spawns SET status = 'EXITED' "
                "WHERE call_id = ? AND analysis_id = ? AND phase = ? "
                "AND pid = ? AND start_identity = ? AND status = 'CAPTURED'",
                (call_id, analysis_id, phase, pid, start_identity),
            )
            if changed.rowcount != 1:
                raise ValueError("CODEX_CHILD_IDENTITY_CONFLICT")

    def mark_codex_call_safe(self, call_id: str, analysis_id: str) -> None:
        """Resolve only a call whose matching attempt was durably recorded."""

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                "UPDATE simple_codex_calls "
                "SET status = 'SAFE', resolved_at = ? "
                "WHERE call_id = ? AND analysis_id = ? AND status = 'IN_FLIGHT' "
                "AND EXISTS (SELECT 1 FROM simple_llm_attempts "
                "WHERE attempt_id = ? AND analysis_id = ?)",
                (
                    datetime.now(UTC).isoformat(),
                    call_id,
                    analysis_id,
                    call_id,
                    analysis_id,
                ),
            )
            if cursor.rowcount != 1:
                raise ValueError("CODEX_CALL_SAFE_UNVERIFIED")

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
                       AS unknown_cost_calls,
                   COALESCE(SUM(CASE
                       WHEN (input_tokens IS NULL OR output_tokens IS NULL)
                            AND status NOT IN ("""
            + ",".join("?" for _ in _NO_MODEL_RESPONSE_STATUSES)
            + """
                       ) THEN 1 ELSE 0 END), 0) AS unknown_token_calls
            FROM simple_llm_attempts WHERE analysis_id = ?
            """,
            (*_NO_MODEL_RESPONSE_STATUSES, analysis_id),
        ).fetchone()
        assert row is not None
        tables = {
            str(item["name"])
            for item in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name IN ('simple_codex_calls', 'agent_activity_events')"
            )
        }
        tracked_rows = (
            connection.execute(
                "SELECT call_id, status, confirmation_ref_json "
                "FROM simple_codex_calls WHERE analysis_id = ? "
                "AND status IN ('CONFIRMED', 'IN_FLIGHT')",
                (analysis_id,),
            ).fetchall()
            if "simple_codex_calls" in tables
            else []
        )
        tracked_refs = {
            str(item["confirmation_ref_json"])
            for item in tracked_rows
            if item["status"] == "CONFIRMED"
            and item["confirmation_ref_json"] is not None
        }
        missing_tracked = [
            item
            for item in tracked_rows
            if connection.execute(
                "SELECT 1 FROM simple_llm_attempts "
                "WHERE attempt_id = ? AND analysis_id = ?",
                (str(item["call_id"]), analysis_id),
            ).fetchone()
            is None
        ]
        unrecorded_in_flight = sum(
            item["status"] == "IN_FLIGHT" for item in missing_tracked
        )
        legacy_refs: set[str] = set()
        events = (
            connection.execute(
                "SELECT event_json FROM agent_activity_events "
                "WHERE analysis_id = ? AND event_json LIKE ?",
                (analysis_id, '%"CODEX_PROCESS_CLEANUP_CONFIRMED"%'),
            )
            if "agent_activity_events" in tables
            else ()
        )
        for item in events:
            event = AgentActivityEvent.model_validate_json(item["event_json"])
            if (
                event.kind is ActivityKind.DECISION_RECORDED
                and event.error_code == "CODEX_PROCESS_CLEANUP_CONFIRMED"
                and len(event.output_refs) == 1
            ):
                ref_json = event.output_refs[0].model_dump_json()
                if ref_json not in tracked_refs:
                    legacy_refs.add(ref_json)
        unlinked = len(missing_tracked) + len(legacy_refs)
        return {
            "calls": int(row["calls"]) + unlinked,
            "input_tokens": int(row["input_tokens"]),
            "output_tokens": int(row["output_tokens"]),
            "cost_minor_units": (
                float(row["cost_minor_units"])
                if row["cost_minor_units"] is not None
                else None
            ),
            "unknown_cost_calls": int(row["unknown_cost_calls"]) + unlinked,
            "unknown_token_calls": int(row["unknown_token_calls"]) + unlinked,
            "unlinked_codex_usage_calls": unlinked,
            "unrecorded_in_flight_codex_calls": unrecorded_in_flight,
        }

    def usage_summary(self, analysis_id: str) -> dict[str, int | float | None]:
        with self._connect() as connection:
            return self.usage_summary_from_connection(connection, analysis_id)

    def llm_elapsed_ms(self, analysis_id: str) -> int:
        """Return elapsed time of recorded LLM attempts across every resume."""

        with self._connect() as connection:
            row = connection.execute(
                "SELECT COALESCE(SUM(elapsed_ms), 0) "
                "FROM simple_llm_attempts WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()
        assert row is not None
        return int(row[0])

    def reopen_elapsed_budget_failures(
        self, analysis_id: str, max_elapsed_seconds: ElapsedLimit
    ) -> int:
        """Reopen elapsed-limit failures only on explicit resume with headroom."""

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            elapsed = connection.execute(
                "SELECT COALESCE(SUM(elapsed_ms), 0) "
                "FROM simple_llm_attempts WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()
            assert elapsed is not None
            if (
                max_elapsed_seconds != "unlimited"
                and int(elapsed[0]) >= max_elapsed_seconds * 1000
            ):
                connection.commit()
                return 0
            rows = connection.execute(
                "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                "WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchall()
            reopened = 0
            for row in rows:
                checkpoint = StageCheckpoint.model_validate_json(row[0])
                if (
                    checkpoint.status is not StageStatus.FAILED
                    or checkpoint.error_code != "LLM_ELAPSED_BUDGET_EXHAUSTED"
                ):
                    continue
                pending = checkpoint.model_copy(
                    update={
                        "status": StageStatus.PENDING,
                        "attempt_id": None,
                        "output_refs": (),
                        "error_code": None,
                        "retryable": False,
                        "updated_at": datetime.now(UTC),
                    }
                )
                self._upsert_checkpoint_connection(connection, pending)
                reopened += 1
            connection.commit()
            return reopened
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def reopen_token_budget_failures(self, analysis_id: str) -> int:
        """Reopen only token-ceiling failures on an unlimited-token resume."""

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                "WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchall()
            reopened = 0
            for row in rows:
                checkpoint = StageCheckpoint.model_validate_json(row[0])
                if (
                    checkpoint.status is not StageStatus.FAILED
                    or checkpoint.error_code
                    not in {
                        "LLM_TOKEN_BUDGET_EXHAUSTED",
                        "LLM_TOKEN_USAGE_UNAVAILABLE",
                    }
                ):
                    continue
                pending = checkpoint.model_copy(
                    update={
                        "status": StageStatus.PENDING,
                        "attempt_id": None,
                        "output_refs": (),
                        "error_code": None,
                        "retryable": False,
                        "updated_at": datetime.now(UTC),
                    }
                )
                self._upsert_checkpoint_connection(connection, pending)
                reopened += 1
            connection.commit()
            return reopened
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def reopen_budget_failures(
        self,
        analysis_id: str,
        *,
        max_tokens: TokenLimit,
        max_cost_minor_units: int,
        max_elapsed_seconds: ElapsedLimit,
    ) -> int:
        """Reopen only exhausted-budget checkpoints when all ceilings have headroom."""

        if max_cost_minor_units <= 0:
            raise ValueError("LLM_COST_BUDGET_INVALID")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            summary = self.usage_summary_from_connection(connection, analysis_id)
            tokens = int(summary["input_tokens"] or 0) + int(
                summary["output_tokens"] or 0
            )
            cost = summary["cost_minor_units"]
            elapsed = connection.execute(
                "SELECT COALESCE(SUM(elapsed_ms), 0) "
                "FROM simple_llm_attempts WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()
            assert elapsed is not None
            if (
                (
                    max_tokens != "unlimited"
                    and (
                        tokens >= max_tokens
                        or int(summary["unknown_token_calls"] or 0) > 0
                    )
                )
                or (cost is not None and float(cost) >= max_cost_minor_units)
                or (
                    max_elapsed_seconds != "unlimited"
                    and int(elapsed[0]) >= max_elapsed_seconds * 1000
                )
            ):
                connection.commit()
                return 0
            rows = connection.execute(
                "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                "WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchall()
            reopened = 0
            for row in rows:
                checkpoint = StageCheckpoint.model_validate_json(row[0])
                if (
                    checkpoint.status is not StageStatus.FAILED
                    or checkpoint.error_code
                    not in {
                        "LLM_TOKEN_BUDGET_EXHAUSTED",
                        "LLM_TOKEN_USAGE_UNAVAILABLE",
                        "LLM_COST_BUDGET_EXHAUSTED",
                        "LLM_ELAPSED_BUDGET_EXHAUSTED",
                    }
                ):
                    continue
                pending = checkpoint.model_copy(
                    update={
                        "status": StageStatus.PENDING,
                        "attempt_id": None,
                        "output_refs": (),
                        "error_code": None,
                        "retryable": False,
                        "updated_at": datetime.now(UTC),
                    }
                )
                self._upsert_checkpoint_connection(connection, pending)
                reopened += 1
            connection.commit()
            return reopened
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

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

    def _codex_cleanup_confirmation_valid(
        self,
        checkpoint: StageCheckpoint,
        ref: StoredDataRef,
        artifacts: SimpleArtifactRepository,
    ) -> bool:
        identity = checkpoint.identity
        if (
            artifacts.identity != identity
            or str(ref.workspace_id) != identity.workspace_id
            or str(ref.commit_id) != identity.commit_id
            or checkpoint.attempt_id is None
        ):
            return False
        try:
            marker = json.loads(artifacts.read(ref))
        except (OSError, TypeError, ValueError):
            return False
        if not isinstance(marker, dict):
            return False
        call_id = marker.get("call_id")
        if "call_id" in marker:
            if (
                not isinstance(call_id, str)
                or not call_id
                or checkpoint.status
                not in {StageStatus.RUNNING, StageStatus.BLOCKED, StageStatus.FAILED}
            ):
                return False
        else:
            legacy_stage = (
                checkpoint.stage is SimpleStage.HYPOTHESIS_DONE
                and identity.hypothesis_id is None
            ) or (
                checkpoint.stage in HYPOTHESIS_STAGES
                and identity.hypothesis_id is not None
            )
            if (
                not legacy_stage
                or checkpoint.error_code != "CODEX_PROCESS_CLEANUP_UNCONFIRMED"
                or checkpoint.status not in {StageStatus.BLOCKED, StageStatus.FAILED}
            ):
                return False
        observed = marker.get("observed_at")
        if not isinstance(observed, str):
            return False
        try:
            observed_at = datetime.fromisoformat(observed)
        except (TypeError, ValueError):
            return False
        if (
            observed_at.tzinfo is None
            or observed_at <= checkpoint.updated_at
            or observed_at > datetime.now(UTC) + timedelta(minutes=5)
        ):
            return False
        with self._connect() as connection:
            version_row = (
                connection.execute(
                    "SELECT candidate_pipeline_version "
                    "FROM simple_codex_call_versions WHERE call_id = ? "
                    "AND analysis_id = ?",
                    (call_id, identity.analysis_id),
                ).fetchone()
                if call_id is not None
                else None
            )
            child_rows = (
                connection.execute(
                    "SELECT phase, status, pid, start_identity "
                    "FROM simple_codex_child_spawns WHERE call_id = ? "
                    "AND analysis_id = ? ORDER BY phase",
                    (call_id, identity.analysis_id),
                ).fetchall()
                if call_id is not None
                else []
            )
        strict_identity = bool(child_rows) or (
            version_row is not None
            and int(version_row["candidate_pipeline_version"]) >= 2
        )
        if strict_identity:
            if call_id is None:
                return False
            if not child_rows or any(
                row["status"] == "SPAWNING"
                or row["pid"] is None
                or not row["start_identity"]
                for row in child_rows
            ):
                return False
            expected_children = [
                {
                    "phase": str(row["phase"]),
                    "pid": int(row["pid"]),
                    "start_identity": str(row["start_identity"]),
                }
                for row in child_rows
            ]
            observed_children = marker.get("observed_children")
            if (
                not isinstance(observed_children, list)
                or sorted(
                    observed_children,
                    key=lambda item: (
                        str(item.get("phase")) if isinstance(item, dict) else ""
                    ),
                )
                != expected_children
                or marker.get("former_parent_pid")
                not in {child["pid"] for child in expected_children}
            ):
                return False
            from sastsimi.providers.codex_subscription import _child_identity_matches

            if any(
                _child_identity_matches(
                    cast(int, child["pid"]), cast(str, child["start_identity"])
                )
                is not False
                for child in expected_children
            ):
                return False
        return bool(
            marker.get("kind") == "simple_codex_cleanup_confirmation"
            and marker.get("analysis_id") == identity.analysis_id
            and marker.get("stage") == checkpoint.stage.value
            and marker.get("attempt_id") == checkpoint.attempt_id
            and marker.get("checkpoint_sha256")
            == hashlib.sha256(canonical_bytes(checkpoint)).hexdigest()
            and marker.get("process_tree_stopped") is True
            and marker.get("verification_method")
            in {"windows_process_inventory", "posix_process_inventory"}
            and type(marker.get("former_parent_pid")) is int
            and marker["former_parent_pid"] > 0
            and type(marker.get("observed_matching_process_count")) is int
            and marker["observed_matching_process_count"] == 0
        )

    def has_codex_cleanup_confirmation(
        self,
        checkpoint: StageCheckpoint,
        artifacts: SimpleArtifactRepository,
    ) -> bool:
        """Accept only an append-only confirmation for this exact failed attempt."""

        if checkpoint.attempt_id is None:
            return False
        for event in self.stage_activity(
            checkpoint.identity, checkpoint.stage, checkpoint.attempt_id
        ):
            if (
                event.kind is not ActivityKind.DECISION_RECORDED
                or event.error_code != "CODEX_PROCESS_CLEANUP_CONFIRMED"
                or len(event.output_refs) != 1
                or not self._codex_cleanup_confirmation_valid(
                    checkpoint, event.output_refs[0], artifacts
                )
            ):
                continue
            marker = json.loads(artifacts.read(event.output_refs[0]))
            call_id = marker.get("call_id")
            if call_id is None:
                if (
                    self.require_analysis_run(
                        checkpoint.identity.analysis_id
                    ).candidate_pipeline_version
                    == 1
                    and self.unresolved_codex_call(checkpoint.identity.analysis_id)
                    is None
                ):
                    return True
            else:
                with self._connect() as connection:
                    row = connection.execute(
                        "SELECT status, confirmation_ref_json "
                        "FROM simple_codex_calls "
                        "WHERE call_id = ? AND analysis_id = ?",
                        (call_id, checkpoint.identity.analysis_id),
                    ).fetchone()
                if (
                    row is not None
                    and row["status"] == "CONFIRMED"
                    and row["confirmation_ref_json"]
                    == event.output_refs[0].model_dump_json()
                ):
                    return True
        return False

    def confirm_codex_cleanup(
        self,
        checkpoint: StageCheckpoint,
        confirmation_ref: StoredDataRef,
        artifacts: SimpleArtifactRepository,
    ) -> None:
        """Confirm cleanup only while holding this analysis's exclusive run lease."""

        if artifacts.paths.database.resolve() != self._database_path.resolve():
            raise ValueError("CODEX_CLEANUP_CONFIRMATION_INVALID")
        try:
            with analysis_run_lease(
                artifacts.data_dir, checkpoint.identity.analysis_id
            ):
                self._confirm_codex_cleanup_with_lease(
                    checkpoint, confirmation_ref, artifacts
                )
        except AnalysisRunBusy as error:
            raise ValueError("CODEX_CLEANUP_CONFIRMATION_ACTIVE_RUN") from error

    def _confirm_codex_cleanup_with_lease(
        self,
        checkpoint: StageCheckpoint,
        confirmation_ref: StoredDataRef,
        artifacts: SimpleArtifactRepository,
    ) -> None:
        """Record a human process-inventory check without altering the failure."""

        if not self._codex_cleanup_confirmation_valid(
            checkpoint, confirmation_ref, artifacts
        ):
            raise ValueError("CODEX_CLEANUP_CONFIRMATION_INVALID")
        marker = json.loads(artifacts.read(confirmation_ref))
        call_id = marker.get("call_id")
        if call_id is None and (
            self.require_analysis_run(
                checkpoint.identity.analysis_id
            ).candidate_pipeline_version
            != 1
        ):
            raise ValueError("CODEX_CLEANUP_CONFIRMATION_INVALID")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT checkpoint_json FROM simple_runtime_checkpoints
                WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?
                """,
                (
                    checkpoint.identity.analysis_id,
                    self._hypothesis_key(checkpoint.identity),
                    checkpoint.stage.value,
                ),
            ).fetchone()
            if (
                row is None
                or StageCheckpoint.model_validate_json(row["checkpoint_json"])
                != checkpoint
            ):
                raise ValueError("CODEX_CLEANUP_CONFIRMATION_STALE")
            unresolved = connection.execute(
                "SELECT call_id FROM simple_codex_calls "
                "WHERE analysis_id = ? AND status = 'IN_FLIGHT'",
                (checkpoint.identity.analysis_id,),
            ).fetchone()
            if call_id is None:
                if unresolved is not None:
                    raise ValueError("CODEX_CLEANUP_CONFIRMATION_INVALID")
            elif unresolved is None or unresolved["call_id"] != call_id:
                raise ValueError("CODEX_CLEANUP_CONFIRMATION_INVALID")
            prior_events = connection.execute(
                "SELECT sequence, event_json FROM agent_activity_events "
                "WHERE analysis_id = ? AND hypothesis_key = ? AND attempt_id = ?",
                (
                    checkpoint.identity.analysis_id,
                    self._hypothesis_key(checkpoint.identity),
                    checkpoint.attempt_id,
                ),
            ).fetchall()
            if call_id is None and any(
                (
                    event := AgentActivityEvent.model_validate_json(item["event_json"])
                ).error_code
                == "CODEX_PROCESS_CLEANUP_CONFIRMED"
                and event.output_refs == (confirmation_ref,)
                for item in prior_events
            ):
                return
            used = {int(item["sequence"]) for item in prior_events}
            sequence = next(
                (
                    value
                    for offset in range(21, 99)
                    if (value := self._stage_sequence(checkpoint.stage, offset))
                    not in used
                ),
                None,
            )
            if sequence is None:
                raise ValueError("CODEX_CLEANUP_CONFIRMATION_EVENT_LIMIT")
            event = self._lifecycle_event(
                checkpoint,
                ActivityKind.DECISION_RECORDED,
                sequence=sequence,
                status=checkpoint.status,
                summary_ko="하위 Codex 프로세스 종료 확인 후 재개를 승인했습니다.",
                output_refs=(confirmation_ref,),
                error_code="CODEX_PROCESS_CLEANUP_CONFIRMED",
            )
            AgentActivityStore.append_connection(connection, event)
            if call_id is not None:
                attempt = connection.execute(
                    "SELECT analysis_id FROM simple_llm_attempts WHERE attempt_id = ?",
                    (call_id,),
                ).fetchone()
                if attempt is None:
                    connection.execute(
                        """
                        INSERT INTO simple_llm_attempts (
                            attempt_id, analysis_id, agent, model, attempt_number,
                            status, elapsed_ms, input_tokens, output_tokens,
                            cost_cents, artifact_ref_json
                        ) VALUES (?, ?, 'unknown', 'unknown', 0,
                                  'CODEX_USAGE_UNAVAILABLE', 0, NULL, NULL,
                                  NULL, ?)
                        """,
                        (
                            call_id,
                            checkpoint.identity.analysis_id,
                            confirmation_ref.model_dump_json(),
                        ),
                    )
                elif attempt["analysis_id"] != checkpoint.identity.analysis_id:
                    raise ValueError("LLM_ATTEMPT_CONFLICT")
                updated = connection.execute(
                    "UPDATE simple_codex_calls "
                    "SET status = 'CONFIRMED', resolved_at = ?, "
                    "confirmation_ref_json = ? "
                    "WHERE call_id = ? AND analysis_id = ? AND status = 'IN_FLIGHT'",
                    (
                        datetime.now(UTC).isoformat(),
                        confirmation_ref.model_dump_json(),
                        call_id,
                        checkpoint.identity.analysis_id,
                    ),
                )
                if updated.rowcount != 1:
                    raise ValueError("CODEX_CLEANUP_CONFIRMATION_STALE")
            connection.commit()

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
            gate_revision_count=(
                reusable_state.gate_revision_count if reusable_state else 0
            ),
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
        *,
        analysis_run: SimpleAnalysisRun | None = None,
    ) -> StageCheckpoint:
        if analysis_run is not None and (
            checkpoint.stage is not SimpleStage.STATIC_DONE
            or analysis_run.analysis_id != checkpoint.identity.analysis_id
            or analysis_run.workspace_id != checkpoint.identity.workspace_id
            or analysis_run.commit_id != checkpoint.identity.commit_id
        ):
            raise ValueError("STATIC_RUN_IDENTITY_MISMATCH")
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
            "bundle_manifest_ref": result.bundle_manifest_ref,
            "bundle_archive_ref": result.bundle_archive_ref,
            "verdict": result.verdict,
            "gate_decision": result.gate_decision,
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
            analysis_run=analysis_run,
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
            gate_revision_count=failed.gate_revision_count,
            recovery_lineage_id=lineage_id,
            recovery_origin_stage=(failed.recovery_origin_stage or failed.stage),
            recovery_decision_refs=decision_refs,
            recipe_ref=None if rebuild else failed.recipe_ref,
            image_digest=None if rebuild else failed.image_digest,
            container_id=None,
        )
        first_index = STAGE_ORDER.index(restart_stage)
        stages = tuple(item.value for item in STAGE_ORDER[first_index:])
        placeholders = ",".join("?" for _ in stages)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            event = self._recovery_event(connection, failed, resolution)
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

    def prepare_gate_revision(
        self,
        gate: StageCheckpoint,
        *,
        fail_before_commit: bool = False,
    ) -> StageCheckpoint:
        """Atomically restart PoC from one accepted revision request."""

        if (
            gate.stage is not SimpleStage.TECH_GATE_DONE
            or gate.stage_version != STAGE_VERSION[SimpleStage.TECH_GATE_DONE]
            or gate.status is not StageStatus.SUCCEEDED
            or gate.gate_decision != "REVISE"
            or len(gate.output_refs) != 1
            or gate.gate_revision_count >= 2
        ):
            raise ValueError("GATE_REVISION_NOT_PREPARABLE")
        identity = gate.identity
        key = self._hypothesis_key(identity)
        stages = tuple(
            stage.value
            for stage in STAGE_ORDER[
                STAGE_ORDER.index(SimpleStage.POC_CANDIDATE_DONE) :
            ]
        )
        placeholders = ",".join("?" for _ in stages)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")

            def checkpoint_at(stage: SimpleStage) -> StageCheckpoint | None:
                row = connection.execute(
                    """
                    SELECT checkpoint_json FROM simple_runtime_checkpoints
                    WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?
                    """,
                    (identity.analysis_id, key, stage.value),
                ).fetchone()
                return (
                    StageCheckpoint.model_validate_json(row["checkpoint_json"])
                    if row is not None
                    else None
                )

            current = checkpoint_at(SimpleStage.TECH_GATE_DONE)
            candidate = checkpoint_at(SimpleStage.POC_CANDIDATE_DONE)
            if current is None:
                if (
                    candidate is not None
                    and candidate.status is StageStatus.PENDING
                    and candidate.gate_revision_count == gate.gate_revision_count + 1
                    and candidate.input_refs
                    and candidate.input_refs[0] == gate.output_refs[0]
                ):
                    connection.commit()
                    return candidate
                raise ValueError("GATE_REVISION_STALE")
            if current != gate:
                raise ValueError("GATE_REVISION_STALE")
            if candidate is None or candidate.status is not StageStatus.SUCCEEDED:
                raise ValueError("GATE_REVISION_CANDIDATE_MISSING")
            execution = checkpoint_at(SimpleStage.POC_EXECUTION_DONE)
            if execution is None or execution.status is not StageStatus.SUCCEEDED:
                raise ValueError("GATE_REVISION_EXECUTION_MISSING")
            inputs = tuple(
                dict.fromkeys(
                    gate.output_refs
                    + candidate.input_refs
                    + candidate.output_refs
                    + execution.output_refs
                )
            )
            pending = StageCheckpoint(
                identity=identity,
                stage=SimpleStage.POC_CANDIDATE_DONE,
                stage_version=STAGE_VERSION[SimpleStage.POC_CANDIDATE_DONE],
                status=StageStatus.PENDING,
                input_refs=inputs,
                input_hash=input_reference_hash(inputs),
                gate_revision_count=gate.gate_revision_count + 1,
                recipe_ref=candidate.recipe_ref or gate.recipe_ref,
                image_digest=candidate.image_digest or gate.image_digest,
            )
            connection.execute(
                f"""
                DELETE FROM simple_runtime_checkpoints
                WHERE analysis_id = ? AND hypothesis_key = ?
                  AND stage IN ({placeholders})
                """,  # noqa: S608 - generated stage placeholders only.
                (identity.analysis_id, key, *stages),
            )
            self._upsert_checkpoint_connection(connection, pending)
            if fail_before_commit:
                raise RuntimeError("simulated crash")
            connection.commit()
            return pending
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

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
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._upsert_checkpoint_connection(connection, failed)
            event = self._recovery_event(connection, failed, resolution)
            AgentActivityStore.append_connection(connection, event)
            if fail_before_commit:
                raise RuntimeError("simulated crash")
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

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

    def promote_inconclusive_execution(
        self, exhausted: StageCheckpoint
    ) -> StageCheckpoint:
        """Atomically preserve an executed, evidence-checked PoC as non-reportable."""

        if (
            exhausted.stage is not SimpleStage.POC_EXECUTION_DONE
            or exhausted.stage_version != STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE]
            or exhausted.status is not StageStatus.BLOCKED
            or exhausted.error_code != "RECOVERY_EXHAUSTED"
            or exhausted.attempt_number < MAX_RECOVERY_ATTEMPTS
            or len(exhausted.output_refs) != 2
            or exhausted.validated_poc_ref is not None
        ):
            raise ValueError("POC_INCONCLUSIVE_PROMOTION_INVALID")
        completed = exhausted.model_copy(
            update={
                "status": StageStatus.SUCCEEDED,
                "verdict": "HOLD",
                "error_code": None,
                "retryable": False,
                "updated_at": datetime.now(UTC),
            }
        )
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
                (
                    exhausted.identity.analysis_id,
                    self._hypothesis_key(exhausted.identity),
                    exhausted.stage.value,
                ),
            ).fetchone()
            if (
                row is None
                or StageCheckpoint.model_validate_json(row["checkpoint_json"])
                != exhausted
            ):
                raise ValueError("POC_INCONCLUSIVE_PROMOTION_STALE")
            self._upsert_checkpoint_connection(connection, completed)
            AgentActivityStore.append_connection(
                connection,
                self._lifecycle_event(
                    completed,
                    ActivityKind.STAGE_COMPLETED,
                    sequence=self._stage_sequence(completed.stage, 2),
                    status=StageStatus.SUCCEEDED,
                    summary_ko=(
                        "완료된 PoC 실행의 반복된 근거 부족을 미확정으로 기록했습니다."
                    ),
                    output_refs=completed.output_refs,
                ),
            )
            connection.commit()
            return completed
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _recovery_event(
        self,
        connection: sqlite3.Connection,
        failed: StageCheckpoint,
        resolution: RecoveryResolution,
    ) -> AgentActivityEvent:
        base = self._stage_sequence(failed.stage, 40)
        rows = connection.execute(
            "SELECT sequence, event_json FROM agent_activity_events "
            "WHERE analysis_id = ? AND hypothesis_key = ? AND attempt_id = ? "
            "AND sequence >= ? AND sequence < ? ORDER BY sequence",
            (
                failed.identity.analysis_id,
                self._hypothesis_key(failed.identity),
                failed.attempt_id or "checkpoint",
                base,
                base + 59,
            ),
        ).fetchall()
        used = {int(row["sequence"]) for row in rows}
        for row in rows:
            existing = AgentActivityEvent.model_validate_json(row["event_json"])
            if (
                existing.stage == failed.stage.value
                and existing.kind is ActivityKind.DECISION_RECORDED
                and existing.output_refs == (resolution.decision_ref,)
            ):
                return existing
        sequence = next(
            (value for value in range(base, base + 59) if value not in used),
            None,
        )
        if sequence is None:
            raise ValueError("RECOVERY_EVENT_SEQUENCE_EXHAUSTED")
        return self._lifecycle_event(
            failed,
            ActivityKind.DECISION_RECORDED,
            sequence=sequence,
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
        analysis_run: SimpleAnalysisRun | None = None,
        activity_events: tuple[AgentActivityEvent, ...] = (),
    ) -> None:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._upsert_checkpoint_connection(connection, checkpoint)
            if analysis_run is not None:
                self._upsert_analysis_run_connection(connection, analysis_run)
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

    def replace_from(
        self,
        pending: StageCheckpoint,
        *,
        fail_before_commit: bool = False,
    ) -> None:
        """Atomically invalidate downstream stages and seed a replay checkpoint."""

        if pending.status is not StageStatus.PENDING:
            raise ValueError("REPLAY_CHECKPOINT_NOT_PENDING")
        first_index = STAGE_ORDER.index(pending.stage)
        stages = tuple(item.value for item in STAGE_ORDER[first_index:])
        placeholders = ",".join("?" for _ in stages)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                f"""
                DELETE FROM simple_runtime_checkpoints
                WHERE analysis_id = ?
                  AND hypothesis_key = ?
                  AND stage IN ({placeholders})
                """,  # noqa: S608 - placeholders are generated, never user supplied.
                (
                    pending.identity.analysis_id,
                    self._hypothesis_key(pending.identity),
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
