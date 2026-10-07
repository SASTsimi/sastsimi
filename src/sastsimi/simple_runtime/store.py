from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, cast
from uuid import uuid4

from sastsimi.config.user_config import ElapsedLimit, TokenLimit
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.poc_candidate import POC_CANDIDATE_VALIDATOR_REVISION
from sastsimi.contracts.prompt_redaction import redact_untrusted_text
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.reporting import (
    BilingualReportContent,
    has_legacy_report_ipv4_false_positive,
    validate_report_content,
)
from sastsimi.observability.agent_activity import (
    ActivityKind,
    AgentActivityEvent,
)
from sastsimi.storage.agent_activity import AgentActivityStore

from .artifacts import LEGACY_RECOVERY_FALLBACK_STOPS, SimpleArtifactRepository
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
    terminal_initial_outcome,
    terminal_poc_outcome,
)
from .recovery import (
    ALLOWED_ACTIONS,
    MAX_RECOVERY_ATTEMPTS,
    SANITIZED_EXTRACT_RECOVERY_REVISION,
    RecoveryAction,
    RecoveryCategory,
    RecoveryDecision,
    RecoveryResolution,
    _python_import_traceback_spans,
    has_python_import_failure,
    sanitized_extract_failure,
    sanitized_extract_recovery_decision,
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


@dataclass(frozen=True, slots=True)
class CandidateBatchOutcomeRecord:
    candidate_id: str
    batch_id: str
    static_bundle_hash: str
    source_sha256: str | None
    context_hash: str
    status: str
    result_ref: StoredDataRef


@dataclass(frozen=True, slots=True)
class AttackSurfaceIndexRecord:
    static_bundle_hash: str
    ast_manifest_hash: str
    candidate_inventory_hash: str
    candidate_count: int
    index_ref: StoredDataRef


@dataclass(frozen=True, slots=True)
class SurfaceExplorationProgressRecord:
    surface_id: str
    context_id: str
    static_bundle_hash: str
    index_hash: str
    context_hash: str
    source_sha256: str | None
    status: str
    result_ref: StoredDataRef
    hypothesis_ids: tuple[str, ...]
    proposal_version: int


class SimpleCheckpointStore:
    """Atomic checkpoint storage for the single-process local runtime."""

    def __init__(
        self, database_path: str | Path, *, artifact_data_dir: str | Path | None = None
    ) -> None:
        self._database_path = Path(database_path)
        self._artifact_data_dir = (
            Path(artifact_data_dir) if artifact_data_dir is not None else None
        )
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
                "CREATE INDEX IF NOT EXISTS idx_static_candidates_file_order "
                "ON simple_static_candidates "
                "(analysis_id, workspace_id, commit_id, scope_fingerprint, "
                "json_extract(candidate_json, '$.path'), candidate_id)"
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
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_candidate_batch_outcomes (
                    analysis_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    commit_id TEXT NOT NULL,
                    scope_fingerprint TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    batch_id TEXT NOT NULL,
                    static_bundle_hash TEXT NOT NULL,
                    source_sha256 TEXT,
                    context_hash TEXT NOT NULL,
                    status TEXT NOT NULL,
                    result_ref_json TEXT NOT NULL,
                    PRIMARY KEY (
                        analysis_id, workspace_id, commit_id,
                        scope_fingerprint, candidate_id
                    )
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_candidate_batch_progress (
                    analysis_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    commit_id TEXT NOT NULL,
                    scope_fingerprint TEXT NOT NULL,
                    batch_id TEXT NOT NULL,
                    marker_ref_json TEXT NOT NULL,
                    PRIMARY KEY (
                        analysis_id, workspace_id, commit_id,
                        scope_fingerprint, batch_id
                    )
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_candidate_child_claims (
                    analysis_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    commit_id TEXT NOT NULL,
                    hypothesis_id TEXT NOT NULL,
                    turn_id TEXT NOT NULL,
                    PRIMARY KEY (
                        analysis_id, workspace_id, commit_id, hypothesis_id
                    )
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_attack_surface_indexes (
                    analysis_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    commit_id TEXT NOT NULL,
                    scope_fingerprint TEXT NOT NULL,
                    static_bundle_hash TEXT NOT NULL,
                    ast_manifest_hash TEXT NOT NULL,
                    candidate_inventory_hash TEXT NOT NULL,
                    candidate_count INTEGER NOT NULL,
                    index_ref_json TEXT NOT NULL,
                    PRIMARY KEY (
                        analysis_id, workspace_id, commit_id, scope_fingerprint
                    )
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_surface_exploration_progress (
                    analysis_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    commit_id TEXT NOT NULL,
                    scope_fingerprint TEXT NOT NULL,
                    surface_id TEXT NOT NULL,
                    context_id TEXT NOT NULL,
                    static_bundle_hash TEXT NOT NULL,
                    index_hash TEXT NOT NULL,
                    context_hash TEXT NOT NULL,
                    source_sha256 TEXT,
                    status TEXT NOT NULL,
                    proposal_version INTEGER NOT NULL DEFAULT 1,
                    result_ref_json TEXT NOT NULL,
                    registrations_json TEXT NOT NULL,
                    PRIMARY KEY (
                        analysis_id, workspace_id, commit_id,
                        scope_fingerprint, surface_id, context_id
                    )
                )
                """
            )
            surface_columns = {
                str(row["name"])
                for row in connection.execute(
                    "PRAGMA table_info(simple_surface_exploration_progress)"
                )
            }
            if "proposal_version" not in surface_columns:
                connection.execute(
                    "ALTER TABLE simple_surface_exploration_progress "
                    "ADD COLUMN proposal_version INTEGER NOT NULL DEFAULT 1"
                )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_pro_con_batch_evidence (
                    analysis_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    commit_id TEXT NOT NULL,
                    hypothesis_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    input_hash TEXT NOT NULL,
                    evidence_ref_json TEXT NOT NULL,
                    PRIMARY KEY (
                        analysis_id, workspace_id, commit_id,
                        hypothesis_id, role, input_hash
                    )
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS simple_chaining_pool_batches (
                    analysis_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    commit_id TEXT NOT NULL,
                    pool_fingerprint TEXT NOT NULL,
                    batch_index INTEGER NOT NULL,
                    batch_count INTEGER NOT NULL,
                    result_ref_json TEXT NOT NULL,
                    PRIMARY KEY (
                        analysis_id, workspace_id, commit_id,
                        pool_fingerprint, batch_index
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
        return tuple(self._candidate_from_row(row) for row in rows)

    @staticmethod
    def _candidate_from_row(row: sqlite3.Row) -> StaticCandidate:
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
        return candidate.model_copy(
            update={
                "decision": row["decision"],
                "decision_reason": row["decision_reason"],
                "decision_evidence_refs": refs,
                "decision_attempt_ref": attempt,
                "deep_status": row["deep_status"],
            }
        )

    def list_candidate_batch_page(
        self,
        identity: CheckpointIdentity,
        scope_fingerprint: str,
        *,
        after: tuple[str, str] | None = None,
        limit: int = 32,
    ) -> tuple[StaticCandidate, ...]:
        """Page selected candidates by file then ID, never by raw-result page."""

        if limit <= 0:
            raise ValueError("CANDIDATE_PAGE_ARGUMENT_INVALID")
        key = self._candidate_scope_key(identity, scope_fingerprint)
        path_expr = "json_extract(candidate_json, '$.path')"
        query = (
            "SELECT candidate_json, decision, decision_reason, "
            "decision_evidence_refs_json, decision_attempt_ref_json, deep_status "
            "FROM simple_static_candidates "
            "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
            "AND scope_fingerprint = ? AND decision IN ('INCLUDE', 'UNDECIDED')"
        )
        args: list[object] = list(key)
        if after is not None:
            query += f" AND ({path_expr} > ? OR ({path_expr} = ? AND candidate_id > ?))"
            args.extend((after[0], after[0], after[1]))
        query += f" ORDER BY {path_expr}, candidate_id LIMIT ?"
        args.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, args).fetchall()
        return tuple(self._candidate_from_row(row) for row in rows)

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
            "INCONCLUSIVE",
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

    def commit_candidate_batch_outcome(
        self,
        identity: CheckpointIdentity,
        scope_fingerprint: str,
        candidate_id: str,
        *,
        batch_id: str,
        static_bundle_hash: str,
        source_sha256: str | None,
        context_hash: str,
        status: str,
        result_ref: StoredDataRef,
        registrations: Sequence[tuple[str, StoredDataRef, StageCheckpoint]],
    ) -> bool:
        """Commit a v2 candidate verdict, all children, and deep status atomically."""

        key = self._candidate_scope_key(identity, scope_fingerprint)
        encoded_ref = self._candidate_ref_json(identity, result_ref)
        if (
            not candidate_id
            or not batch_id
            or not static_bundle_hash
            or not context_hash
            or status
            not in {
                "HYPOTHESES",
                "NO_HYPOTHESIS",
                "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
            }
            or (status == "HYPOTHESES") != bool(registrations)
        ):
            raise ValueError("CANDIDATE_BATCH_OUTCOME_INVALID")
        deep_status = {
            "HYPOTHESES": "RUNNING",
            "NO_HYPOTHESIS": "NO_HYPOTHESIS",
            "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS": "INCONCLUSIVE",
        }[status]
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute(
                "SELECT batch_id, static_bundle_hash, source_sha256, "
                "context_hash, status, result_ref_json "
                "FROM simple_candidate_batch_outcomes "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND scope_fingerprint = ? AND candidate_id = ?",
                (*key, candidate_id),
            ).fetchone()
            if prior is not None:
                if (
                    prior["batch_id"],
                    prior["static_bundle_hash"],
                    prior["source_sha256"],
                    prior["context_hash"],
                    prior["status"],
                    prior["result_ref_json"],
                ) != (
                    batch_id,
                    static_bundle_hash,
                    source_sha256,
                    context_hash,
                    status,
                    encoded_ref,
                ):
                    raise ValueError("CANDIDATE_BATCH_OUTCOME_CONFLICT")
                return False
            candidate = connection.execute(
                "SELECT decision, deep_status FROM simple_static_candidates "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND scope_fingerprint = ? AND candidate_id = ?",
                (*key, candidate_id),
            ).fetchone()
            if (
                candidate is None
                or candidate["decision"]
                not in {
                    "INCLUDE",
                    "UNDECIDED",
                }
                or candidate["deep_status"] not in {"PENDING", "ERROR"}
            ):
                raise ValueError("CANDIDATE_BATCH_OUTCOME_CONFLICT")
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
            connection.execute(
                "UPDATE simple_static_candidates SET deep_status = ? "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND scope_fingerprint = ? AND candidate_id = ?",
                (deep_status, *key, candidate_id),
            )
            connection.execute(
                "INSERT INTO simple_candidate_batch_outcomes "
                "(analysis_id, workspace_id, commit_id, scope_fingerprint, "
                "candidate_id, batch_id, static_bundle_hash, source_sha256, "
                "context_hash, status, result_ref_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    *key,
                    candidate_id,
                    batch_id,
                    static_bundle_hash,
                    source_sha256,
                    context_hash,
                    status,
                    encoded_ref,
                ),
            )
        return True

    def list_candidate_batch_outcomes(
        self, identity: CheckpointIdentity, scope_fingerprint: str
    ) -> dict[str, CandidateBatchOutcomeRecord]:
        key = self._candidate_scope_key(identity, scope_fingerprint)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT candidate_id, batch_id, static_bundle_hash, source_sha256, "
                "context_hash, status, result_ref_json "
                "FROM simple_candidate_batch_outcomes "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND scope_fingerprint = ? ORDER BY candidate_id",
                key,
            ).fetchall()
        return {
            str(row["candidate_id"]): CandidateBatchOutcomeRecord(
                candidate_id=str(row["candidate_id"]),
                batch_id=str(row["batch_id"]),
                static_bundle_hash=str(row["static_bundle_hash"]),
                source_sha256=row["source_sha256"],
                context_hash=str(row["context_hash"]),
                status=str(row["status"]),
                result_ref=StoredDataRef.model_validate_json(row["result_ref_json"]),
            )
            for row in rows
        }

    def save_candidate_batch_progress(
        self,
        identity: CheckpointIdentity,
        scope_fingerprint: str,
        batch_id: str,
        marker_ref: StoredDataRef,
    ) -> None:
        key = self._candidate_scope_key(identity, scope_fingerprint)
        encoded_ref = self._candidate_ref_json(identity, marker_ref)
        if not batch_id:
            raise ValueError("CANDIDATE_BATCH_ID_INVALID")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT marker_ref_json FROM simple_candidate_batch_progress "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND scope_fingerprint = ? AND batch_id = ?",
                (*key, batch_id),
            ).fetchone()
            if row is not None:
                if row["marker_ref_json"] != encoded_ref:
                    raise ValueError("CANDIDATE_BATCH_PROGRESS_CONFLICT")
                return
            connection.execute(
                "INSERT INTO simple_candidate_batch_progress "
                "(analysis_id, workspace_id, commit_id, scope_fingerprint, "
                "batch_id, marker_ref_json) VALUES (?, ?, ?, ?, ?, ?)",
                (*key, batch_id, encoded_ref),
            )

    def list_candidate_batch_progress(
        self, identity: CheckpointIdentity, scope_fingerprint: str
    ) -> dict[str, StoredDataRef]:
        key = self._candidate_scope_key(identity, scope_fingerprint)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT batch_id, marker_ref_json FROM simple_candidate_batch_progress "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND scope_fingerprint = ? ORDER BY batch_id",
                key,
            ).fetchall()
        return {
            str(row["batch_id"]): StoredDataRef.model_validate_json(
                row["marker_ref_json"]
            )
            for row in rows
        }

    def clear_stale_hypothesis_claims(self, identity: CheckpointIdentity) -> None:
        """Call only after acquiring the analysis lease and checking Codex cleanup."""

        key = self._hypothesis_scope_key(identity)
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM simple_candidate_child_claims "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ?",
                key,
            )

    def save_attack_surface_index(
        self,
        identity: CheckpointIdentity,
        scope_fingerprint: str,
        *,
        static_bundle_hash: str,
        ast_manifest_hash: str,
        candidate_inventory_hash: str,
        candidate_count: int,
        index_ref: StoredDataRef,
    ) -> None:
        key = self._candidate_scope_key(identity, scope_fingerprint)
        encoded_ref = self._candidate_ref_json(identity, index_ref)
        if (
            not static_bundle_hash
            or not ast_manifest_hash
            or not candidate_inventory_hash
            or candidate_count < 0
        ):
            raise ValueError("SURFACE_INDEX_CHECKPOINT_INVALID")
        expected = (
            static_bundle_hash,
            ast_manifest_hash,
            candidate_inventory_hash,
            candidate_count,
            encoded_ref,
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT static_bundle_hash, ast_manifest_hash, "
                "candidate_inventory_hash, candidate_count, index_ref_json "
                "FROM simple_attack_surface_indexes "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND scope_fingerprint = ?",
                key,
            ).fetchone()
            if row is not None:
                existing = (
                    row["static_bundle_hash"],
                    row["ast_manifest_hash"],
                    row["candidate_inventory_hash"],
                    row["candidate_count"],
                    row["index_ref_json"],
                )
                if existing != expected:
                    raise ValueError("SURFACE_INDEX_CHECKPOINT_CONFLICT")
                return
            connection.execute(
                "INSERT INTO simple_attack_surface_indexes "
                "(analysis_id, workspace_id, commit_id, scope_fingerprint, "
                "static_bundle_hash, ast_manifest_hash, candidate_inventory_hash, "
                "candidate_count, index_ref_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (*key, *expected),
            )

    def get_attack_surface_index(
        self, identity: CheckpointIdentity, scope_fingerprint: str
    ) -> AttackSurfaceIndexRecord | None:
        key = self._candidate_scope_key(identity, scope_fingerprint)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT static_bundle_hash, ast_manifest_hash, "
                "candidate_inventory_hash, candidate_count, index_ref_json "
                "FROM simple_attack_surface_indexes "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND scope_fingerprint = ?",
                key,
            ).fetchone()
        if row is None:
            return None
        return AttackSurfaceIndexRecord(
            static_bundle_hash=str(row["static_bundle_hash"]),
            ast_manifest_hash=str(row["ast_manifest_hash"]),
            candidate_inventory_hash=str(row["candidate_inventory_hash"]),
            candidate_count=int(row["candidate_count"]),
            index_ref=StoredDataRef.model_validate_json(row["index_ref_json"]),
        )

    def commit_surface_exploration(
        self,
        identity: CheckpointIdentity,
        scope_fingerprint: str,
        surface_id: str,
        context_id: str,
        *,
        static_bundle_hash: str,
        index_hash: str,
        context_hash: str,
        source_sha256: str | None,
        status: str,
        result_ref: StoredDataRef,
        registrations: Sequence[tuple[str, StoredDataRef, StageCheckpoint]],
        proposal_version: int = 1,
    ) -> bool:
        """Commit one context part and all its free hypotheses atomically."""

        key = self._candidate_scope_key(identity, scope_fingerprint)
        encoded_ref = cast(str, self._candidate_ref_json(identity, result_ref))
        if (
            not surface_id.strip()
            or not context_id.strip()
            or not static_bundle_hash.strip()
            or not index_hash.strip()
            or not context_hash.strip()
            or (source_sha256 is not None and not source_sha256.strip())
            or status
            not in {
                "HYPOTHESES",
                "NO_HYPOTHESIS",
                "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
            }
            or (status == "HYPOTHESES") != bool(registrations)
            or proposal_version not in {1, 2}
        ):
            raise ValueError("SURFACE_EXPLORATION_INVALID")
        if len({item[0] for item in registrations}) != len(registrations):
            raise ValueError("SURFACE_EXPLORATION_INVALID")
        registrations_json = json.dumps(
            [
                (
                    hypothesis_id,
                    self._candidate_ref_json(identity, hypothesis_ref),
                    checkpoint.model_dump(mode="json", exclude={"updated_at"}),
                )
                for hypothesis_id, hypothesis_ref, checkpoint in registrations
            ],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        expected = (
            static_bundle_hash,
            index_hash,
            context_hash,
            source_sha256,
            status,
            proposal_version,
            encoded_ref,
            registrations_json,
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute(
                "SELECT static_bundle_hash, index_hash, context_hash, "
                "source_sha256, status, proposal_version, result_ref_json, "
                "registrations_json "
                "FROM simple_surface_exploration_progress "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND scope_fingerprint = ? AND surface_id = ? AND context_id = ?",
                (*key, surface_id, context_id),
            ).fetchone()
            if prior is not None:
                actual = (
                    prior["static_bundle_hash"],
                    prior["index_hash"],
                    prior["context_hash"],
                    prior["source_sha256"],
                    prior["status"],
                    prior["proposal_version"],
                    prior["result_ref_json"],
                    prior["registrations_json"],
                )
                if actual != expected:
                    raise ValueError("SURFACE_EXPLORATION_CONFLICT")
                return False
            for hypothesis_id, hypothesis_ref, checkpoint in registrations:
                self._register_free_hypothesis_connection(
                    connection, identity, hypothesis_id, hypothesis_ref, checkpoint
                )
            connection.execute(
                "INSERT INTO simple_surface_exploration_progress "
                "(analysis_id, workspace_id, commit_id, scope_fingerprint, "
                "surface_id, context_id, static_bundle_hash, index_hash, "
                "context_hash, source_sha256, status, proposal_version, "
                "result_ref_json, "
                "registrations_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (*key, surface_id, context_id, *expected),
            )
        return True

    def _surface_registration_ids(
        self,
        identity: CheckpointIdentity,
        status: str,
        registrations_json: str,
    ) -> tuple[str, ...]:
        try:
            registrations: object = json.loads(registrations_json)
        except (TypeError, ValueError) as error:
            raise ValueError("SURFACE_EXPLORATION_REGISTRATIONS_CORRUPT") from error
        if not isinstance(registrations, list):
            raise ValueError("SURFACE_EXPLORATION_REGISTRATIONS_CORRUPT")
        ids: list[str] = []
        for registration in registrations:
            if (
                not isinstance(registration, list)
                or len(registration) != 3
                or not isinstance(registration[0], str)
                or not registration[0].strip()
                or not isinstance(registration[1], str)
                or not isinstance(registration[2], dict)
                or registration[0] in ids
            ):
                raise ValueError("SURFACE_EXPLORATION_REGISTRATIONS_CORRUPT")
            hypothesis_id, ref_json, checkpoint_json = registration
            try:
                hypothesis_ref = StoredDataRef.model_validate_json(ref_json)
                self._candidate_ref_json(identity, hypothesis_ref)
                checkpoint = StageCheckpoint.model_validate_json(
                    json.dumps(checkpoint_json, ensure_ascii=False)
                )
            except (TypeError, ValueError) as error:
                raise ValueError("SURFACE_EXPLORATION_REGISTRATIONS_CORRUPT") from error
            if (
                checkpoint.identity
                != identity.model_copy(update={"hypothesis_id": hypothesis_id})
                or checkpoint.stage is not SimpleStage.PRO_CON_DONE
                or checkpoint.stage_version != STAGE_VERSION[SimpleStage.PRO_CON_DONE]
                or checkpoint.status is not StageStatus.PENDING
                or not checkpoint.input_refs
                or checkpoint.input_refs[0] != hypothesis_ref
            ):
                raise ValueError("SURFACE_EXPLORATION_REGISTRATIONS_CORRUPT")
            ids.append(hypothesis_id)
        if status not in {
            "HYPOTHESES",
            "NO_HYPOTHESIS",
            "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
        } or (status == "HYPOTHESES") != bool(ids):
            raise ValueError("SURFACE_EXPLORATION_REGISTRATIONS_CORRUPT")
        return tuple(ids)

    def list_surface_exploration_progress(
        self, identity: CheckpointIdentity, scope_fingerprint: str
    ) -> dict[tuple[str, str], SurfaceExplorationProgressRecord]:
        key = self._candidate_scope_key(identity, scope_fingerprint)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT surface_id, context_id, static_bundle_hash, index_hash, "
                "context_hash, source_sha256, status, proposal_version, "
                "result_ref_json, "
                "registrations_json "
                "FROM simple_surface_exploration_progress "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND scope_fingerprint = ? ORDER BY surface_id, context_id",
                key,
            ).fetchall()
        return {
            (str(row["surface_id"]), str(row["context_id"])): (
                SurfaceExplorationProgressRecord(
                    surface_id=str(row["surface_id"]),
                    context_id=str(row["context_id"]),
                    static_bundle_hash=str(row["static_bundle_hash"]),
                    index_hash=str(row["index_hash"]),
                    context_hash=str(row["context_hash"]),
                    source_sha256=row["source_sha256"],
                    status=str(row["status"]),
                    result_ref=StoredDataRef.model_validate_json(
                        row["result_ref_json"]
                    ),
                    hypothesis_ids=self._surface_registration_ids(
                        identity, str(row["status"]), str(row["registrations_json"])
                    ),
                    proposal_version=int(row["proposal_version"]),
                )
            )
            for row in rows
        }

    @staticmethod
    def _pro_con_batch_key(
        identity: CheckpointIdentity, role: str, input_hash: str
    ) -> tuple[str, str, str, str, str, str]:
        if (
            not identity.hypothesis_id
            or role not in {"pro", "con"}
            or not input_hash.strip()
        ):
            raise ValueError("PRO_CON_BATCH_EVIDENCE_INVALID")
        return (
            identity.analysis_id,
            identity.workspace_id,
            identity.commit_id,
            identity.hypothesis_id,
            role,
            input_hash,
        )

    def save_pro_con_batch_evidence(
        self,
        identity: CheckpointIdentity,
        role: str,
        input_hash: str,
        evidence_ref: StoredDataRef,
    ) -> bool:
        """Save one role as soon as it succeeds; exact replay never replaces it."""

        key = self._pro_con_batch_key(identity, role, input_hash)
        encoded = self._candidate_ref_json(identity, evidence_ref)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT evidence_ref_json FROM simple_pro_con_batch_evidence "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND hypothesis_id = ? AND role = ? AND input_hash = ?",
                key,
            ).fetchone()
            if row is not None:
                if row["evidence_ref_json"] != encoded:
                    raise ValueError("PRO_CON_BATCH_EVIDENCE_CONFLICT")
                return False
            connection.execute(
                "INSERT INTO simple_pro_con_batch_evidence "
                "(analysis_id, workspace_id, commit_id, hypothesis_id, role, "
                "input_hash, evidence_ref_json) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (*key, encoded),
            )
        return True

    def get_pro_con_batch_evidence(
        self,
        identity: CheckpointIdentity,
        role: str,
        input_hash: str,
    ) -> StoredDataRef | None:
        key = self._pro_con_batch_key(identity, role, input_hash)
        with self._connect() as connection:
            row = connection.execute(
                "SELECT evidence_ref_json FROM simple_pro_con_batch_evidence "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND hypothesis_id = ? AND role = ? AND input_hash = ?",
                key,
            ).fetchone()
        if row is None:
            return None
        ref = StoredDataRef.model_validate_json(row["evidence_ref_json"])
        self._candidate_ref_json(identity, ref)
        return ref

    def repair_pending_pro_con_role_cache(
        self,
        checkpoint: StageCheckpoint,
        invalid_roles: Mapping[str, StoredDataRef],
        *,
        expected_role_cache: Mapping[str, StoredDataRef | None],
    ) -> bool:
        """Reopen one incomplete legacy child after an exact role-cache audit."""

        if not invalid_roles:
            return False
        if (
            checkpoint.stage is not SimpleStage.PRO_CON_DONE
            or checkpoint.status not in {StageStatus.PENDING, StageStatus.BLOCKED}
            or checkpoint.identity.hypothesis_id is None
            or checkpoint.stage_version != STAGE_VERSION[SimpleStage.PRO_CON_DONE]
            or set(expected_role_cache) != {"pro", "con"}
            or not set(invalid_roles) <= {"pro", "con"}
        ):
            raise ValueError("PRO_CON_PENDING_CACHE_REPAIR_INVALID")
        for role, ref in invalid_roles.items():
            if expected_role_cache[role] != ref:
                raise ValueError("PRO_CON_PENDING_CACHE_REPAIR_STALE")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            run_row = connection.execute(
                "SELECT run_json FROM simple_analysis_runs WHERE analysis_id = ?",
                (checkpoint.identity.analysis_id,),
            ).fetchone()
            run = (
                SimpleAnalysisRun.model_validate_json(run_row["run_json"])
                if run_row is not None
                else None
            )
            if (
                run is None
                or run.candidate_pipeline_version not in {1, 2}
                or run.workspace_id != checkpoint.identity.workspace_id
                or run.commit_id != checkpoint.identity.commit_id
            ):
                raise ValueError("PRO_CON_PENDING_CACHE_REPAIR_STALE")
            row = connection.execute(
                "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
                (
                    checkpoint.identity.analysis_id,
                    self._hypothesis_key(checkpoint.identity),
                    SimpleStage.PRO_CON_DONE.value,
                ),
            ).fetchone()
            if (
                row is None
                or StageCheckpoint.model_validate_json(row["checkpoint_json"])
                != checkpoint
            ):
                raise ValueError("PRO_CON_PENDING_CACHE_REPAIR_STALE")
            after_pro_con = STAGE_ORDER.index(SimpleStage.PRO_CON_DONE) + 1
            later = tuple(stage.value for stage in STAGE_ORDER[after_pro_con:])
            placeholders = ",".join("?" for _ in later)
            if connection.execute(
                "SELECT 1 FROM simple_runtime_checkpoints WHERE analysis_id = ? "
                "AND hypothesis_key = ? "
                f"AND stage IN ({placeholders}) LIMIT 1",  # noqa: S608
                (
                    checkpoint.identity.analysis_id,
                    self._hypothesis_key(checkpoint.identity),
                    *later,
                ),
            ).fetchone():
                raise ValueError("PRO_CON_PENDING_CACHE_REPAIR_STALE")
            for role in ("pro", "con"):
                key = self._pro_con_batch_key(
                    checkpoint.identity, role, checkpoint.input_hash
                )
                saved = connection.execute(
                    "SELECT evidence_ref_json FROM simple_pro_con_batch_evidence "
                    "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                    "AND hypothesis_id = ? AND role = ? AND input_hash = ?",
                    key,
                ).fetchone()
                expected = expected_role_cache[role]
                encoded = (
                    self._candidate_ref_json(checkpoint.identity, expected)
                    if expected is not None
                    else None
                )
                if (saved["evidence_ref_json"] if saved else None) != encoded:
                    raise ValueError("PRO_CON_PENDING_CACHE_REPAIR_STALE")
            for role in invalid_roles:
                connection.execute(
                    "DELETE FROM simple_pro_con_batch_evidence WHERE analysis_id = ? "
                    "AND workspace_id = ? AND commit_id = ? AND hypothesis_id = ? "
                    "AND role = ? AND input_hash = ?",
                    self._pro_con_batch_key(
                        checkpoint.identity, role, checkpoint.input_hash
                    ),
                )
            pending = checkpoint.model_copy(
                update={
                    "status": StageStatus.PENDING,
                    "output_refs": (),
                    "attempt_id": None,
                    "error_code": None,
                    "retryable": False,
                    "updated_at": datetime.now(UTC),
                }
            )
            self._upsert_checkpoint_connection(connection, pending)
            if run.candidate_terminal is not None:
                self._upsert_analysis_run_connection(
                    connection, run.model_copy(update={"candidate_terminal": None})
                )
            audit = checkpoint.model_copy(
                update={"attempt_id": f"role-cache-repair-{uuid4().hex}"}
            )
            AgentActivityStore.append_connection(
                connection,
                self._lifecycle_event(
                    audit,
                    ActivityKind.EVIDENCE_REVIEWED,
                    sequence=self._stage_sequence(SimpleStage.PRO_CON_DONE, 88),
                    status=StageStatus.BLOCKED,
                    summary_ko="Pro/Con 인용 오류로 해당 역할을 다시 실행합니다.",
                    output_refs=tuple(invalid_roles.values()),
                    error_code="PRO_CON_LEGACY_ROLE_CACHE_REPAIRED",
                ),
            )
            connection.commit()
            return True
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def save_chaining_pool_batch(
        self,
        identity: CheckpointIdentity,
        pool_fingerprint: str,
        batch_index: int,
        batch_count: int,
        result_ref: StoredDataRef,
    ) -> bool:
        """Persist one exact final-pool result before registering its children."""

        key = self._candidate_scope_key(identity, pool_fingerprint)
        encoded = self._candidate_ref_json(identity, result_ref)
        if batch_count < 1 or not 0 <= batch_index < batch_count:
            raise ValueError("CHAINING_POOL_BATCH_INVALID")
        batch_key = (*key, batch_index)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT batch_count, result_ref_json "
                "FROM simple_chaining_pool_batches "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND pool_fingerprint = ? AND batch_index = ?",
                batch_key,
            ).fetchone()
            if row is not None:
                if (int(row["batch_count"]), row["result_ref_json"]) != (
                    batch_count,
                    encoded,
                ):
                    raise ValueError("CHAINING_POOL_BATCH_CONFLICT")
                return False
            connection.execute(
                "INSERT INTO simple_chaining_pool_batches "
                "(analysis_id, workspace_id, commit_id, pool_fingerprint, "
                "batch_index, batch_count, result_ref_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (*batch_key, batch_count, encoded),
            )
        return True

    def list_chaining_pool_batches(
        self, identity: CheckpointIdentity, pool_fingerprint: str
    ) -> dict[int, tuple[int, StoredDataRef]]:
        """Return only this workspace/commit/pool's durable batch outputs."""

        key = self._candidate_scope_key(identity, pool_fingerprint)
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT batch_index, batch_count, result_ref_json "
                "FROM simple_chaining_pool_batches "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND pool_fingerprint = ? ORDER BY batch_index",
                key,
            ).fetchall()
        result: dict[int, tuple[int, StoredDataRef]] = {}
        for row in rows:
            ref = StoredDataRef.model_validate_json(row["result_ref_json"])
            self._candidate_ref_json(identity, ref)
            result[int(row["batch_index"])] = (int(row["batch_count"]), ref)
        return result

    def claim_hypothesis(
        self, identity: CheckpointIdentity, hypothesis_id: str, turn_id: str
    ) -> bool:
        """Claim one child atomically, preventing duplicate concurrent starts."""

        key = self._hypothesis_scope_key(identity)
        if not hypothesis_id or not turn_id:
            raise ValueError("CANDIDATE_CHILD_CLAIM_INVALID")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            inserted = connection.execute(
                "INSERT OR IGNORE INTO simple_candidate_child_claims "
                "(analysis_id, workspace_id, commit_id, hypothesis_id, turn_id) "
                "VALUES (?, ?, ?, ?, ?)",
                (*key, hypothesis_id, turn_id),
            )
        return inserted.rowcount == 1

    def release_hypothesis_claim(
        self, identity: CheckpointIdentity, hypothesis_id: str, turn_id: str
    ) -> None:
        key = self._hypothesis_scope_key(identity)
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM simple_candidate_child_claims "
                "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                "AND hypothesis_id = ? AND turn_id = ?",
                (*key, hypothesis_id, turn_id),
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

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._register_free_hypothesis_connection(
                connection,
                identity,
                hypothesis_id,
                hypothesis_ref,
                checkpoint,
                chain_depth=chain_depth,
                parent_hypothesis_ids=parent_hypothesis_ids,
            )

    def _register_free_hypothesis_connection(
        self,
        connection: sqlite3.Connection,
        identity: CheckpointIdentity,
        hypothesis_id: str,
        hypothesis_ref: StoredDataRef,
        checkpoint: StageCheckpoint,
        *,
        chain_depth: int = 0,
        parent_hypothesis_ids: tuple[str, ...] = (),
    ) -> None:
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
                    stale_stage = False
                    stale_poc_or_downstream = False
                    poc_index = STAGE_ORDER.index(SimpleStage.POC_EXECUTION_DONE)
                    for item in checkpoints:
                        checkpoint = StageCheckpoint.model_validate_json(
                            item["checkpoint_json"]
                        )
                        if checkpoint.identity != identity.model_copy(
                            update={"hypothesis_id": hypothesis_id}
                        ):
                            raise ValueError("CANDIDATE_HYPOTHESIS_CHECKPOINT_CORRUPT")
                        if (
                            checkpoint.stage in HYPOTHESIS_STAGES
                            and checkpoint.stage_version
                            != STAGE_VERSION[checkpoint.stage]
                        ):
                            stale_stage = True
                            if STAGE_ORDER.index(checkpoint.stage) >= poc_index:
                                stale_poc_or_downstream = True
                        if (
                            checkpoint.status is StageStatus.SUCCEEDED
                            and checkpoint.stage_version
                            == STAGE_VERSION[checkpoint.stage]
                        ):
                            stages[checkpoint.stage] = checkpoint
                    final = stages.get(SimpleStage.VERIFICATION_FINAL_DONE)
                    chain = stages.get(SimpleStage.CHAINING_DONE)
                    terminal_poc = (
                        self.verified_terminal_poc_outcome(
                            stages.get(SimpleStage.POC_EXECUTION_DONE)
                        )
                        is not None
                    )
                    terminal = (
                        self.verified_terminal_initial_outcome(
                            stages.get(SimpleStage.VERIFICATION_INITIAL_DONE)
                        )
                        is not None
                        or terminal_poc
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
                    if (
                        stale_stage
                        and not (terminal_poc and not stale_poc_or_downstream)
                    ) or not terminal:
                        selected.append(hypothesis_id)
                        if len(selected) >= limit:
                            break
                if len(rows) < max(32, limit):
                    break
        return tuple(selected)

    def verified_terminal_initial_outcome(
        self, checkpoint: StageCheckpoint | None
    ) -> Literal["INCONCLUSIVE"] | None:
        if terminal_initial_outcome(checkpoint) is None:
            return None
        if self._artifact_data_dir is None or checkpoint is None:
            return None
        try:
            return SimpleArtifactRepository(
                self._artifact_data_dir, checkpoint.identity
            ).verified_terminal_initial_outcome(checkpoint)
        except (OSError, ValueError, sqlite3.Error):
            return None

    def verified_terminal_poc_outcome(
        self, checkpoint: StageCheckpoint | None
    ) -> Literal["INCONCLUSIVE"] | None:
        if terminal_poc_outcome(checkpoint) is None or checkpoint is None:
            return None
        if self._artifact_data_dir is None:
            return None
        try:
            return SimpleArtifactRepository(
                self._artifact_data_dir, checkpoint.identity
            ).verified_terminal_poc_outcome(checkpoint)
        except (OSError, ValueError, sqlite3.Error):
            return None

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

    def prepare_report_validator_replay(
        self,
        stopped: StageCheckpoint,
        draft_ref: StoredDataRef,
        artifacts: SimpleArtifactRepository,
        *,
        fail_before_commit: bool = False,
    ) -> StageCheckpoint:
        """Reuse one newly valid draft; reopen only its exact blocked report.

        Caller holds the analysis lease. The immutable draft is checked before
        the transaction, then every mutable binding is compared under CAS.
        """

        identity = stopped.identity
        exhausted_report = (
            stopped.error_code == "RECOVERY_EXHAUSTED"
            and stopped.attempt_number == MAX_RECOVERY_ATTEMPTS
            and stopped.output_refs == (draft_ref,)
            and stopped.recovery_origin_stage is SimpleStage.REPORT_DONE
            and stopped.recovery_lineage_id is not None
            and len(stopped.recovery_decision_refs) == MAX_RECOVERY_ATTEMPTS - 1
        )
        stopped_second_report = (
            stopped.error_code == "REPORT_CONTENT_INVALID"
            and stopped.attempt_number == 2
            and stopped.output_refs == (draft_ref,)
            and stopped.recovery_origin_stage is SimpleStage.REPORT_DONE
            and stopped.recovery_lineage_id is not None
            and len(stopped.recovery_decision_refs) == 1
            and stopped.recovery_decision_refs[0] in stopped.input_refs
        )
        legacy_report = (
            stopped.error_code
            in {"STAGE_UNEXPECTED_ERROR", "REPORT_UNSUPPORTED_METADATA_CLAIM"}
            and 1 <= stopped.attempt_number < MAX_RECOVERY_ATTEMPTS
            and not stopped.output_refs
        )
        if (
            identity.hypothesis_id is None
            or stopped.stage is not SimpleStage.REPORT_DONE
            or stopped.stage_version != STAGE_VERSION[SimpleStage.REPORT_DONE]
            or stopped.status is not StageStatus.BLOCKED
            or not (legacy_report or exhausted_report or stopped_second_report)
            or stopped.retryable
            or stopped.attempt_id is None
            or stopped.report_ref is not None
            or artifacts.identity != identity
            or artifacts.paths.database.resolve() != self._database_path.resolve()
        ):
            raise ValueError("REPORT_VALIDATOR_REPLAY_INVALID")

        def validated_draft(
            ref: StoredDataRef, attempt_id: str
        ) -> tuple[dict[str, object], BilingualReportContent]:
            try:
                envelope = json.loads(artifacts.read_bounded(ref, 4 * 1024 * 1024))
                if (
                    not isinstance(envelope, dict)
                    or envelope.get("kind") != "simple_report_draft"
                    or envelope.get("attempt_id") != attempt_id
                    or not isinstance(envelope.get("result"), dict)
                    or not isinstance(envelope.get("source_refs"), list)
                    or not isinstance(envelope.get("prompt_digest"), str)
                    or re.fullmatch(r"[0-9a-f]{64}", envelope["prompt_digest"]) is None
                    or envelope.get("output_digest")
                    != hashlib.sha256(canonical_bytes(envelope["result"])).hexdigest()
                ):
                    raise ValueError("invalid draft envelope")
                content = BilingualReportContent.model_validate_json(
                    canonical_bytes(envelope["result"])
                )
                validate_report_content(
                    content.model_dump(mode="json"), allowed_locations=()
                )
            except (OSError, TypeError, ValueError) as error:
                raise ValueError("REPORT_VALIDATOR_REPLAY_DRAFT_INVALID") from error
            return envelope, content

        assert stopped.attempt_id is not None
        envelope, content = validated_draft(draft_ref, stopped.attempt_id)
        if (
            stopped.error_code == "STAGE_UNEXPECTED_ERROR"
            or exhausted_report
            or stopped_second_report
        ) and not has_legacy_report_ipv4_false_positive(content):
            raise ValueError("REPORT_VALIDATOR_REPLAY_LEGACY_CAUSE_UNPROVEN")
        first_draft_ref: StoredDataRef | None = None
        first_attempt_id: str | None = None
        retry_ref: StoredDataRef | None = None
        first_envelope: dict[str, object] | None = None
        if stopped_second_report:
            retry_ref = stopped.recovery_decision_refs[0]
            try:
                retry_record = json.loads(artifacts.read_bounded(retry_ref, 64 * 1024))
                if not isinstance(retry_record, dict):
                    raise ValueError("invalid retry decision")
                retry_failure = StageFailure.model_validate_json(
                    canonical_bytes(retry_record.get("original_error"))
                )
                retry_decision = RecoveryDecision.model_validate_json(
                    canonical_bytes(retry_record.get("decision"))
                )
                first_attempt_id = retry_record.get("attempt_id")
                if (
                    retry_record.get("kind") != "simple_recovery_decision"
                    or retry_record.get("identity") != identity.model_dump(mode="json")
                    or retry_record.get("stage") != SimpleStage.REPORT_DONE.value
                    or retry_record.get("attempt") != 1
                    or not isinstance(first_attempt_id, str)
                    or not first_attempt_id
                    or first_attempt_id == stopped.attempt_id
                    or retry_record.get("decision_origin") != "AGENT"
                    or retry_failure.code != "REPORT_CONTENT_INVALID"
                    or not retry_failure.retryable
                    or len(retry_failure.evidence_refs) != 1
                    or retry_decision.category is not RecoveryCategory.GENERATED_INPUT
                    or retry_decision.action is not RecoveryAction.REGENERATE_INPUT
                    or retry_decision.environment_patch != ""
                ):
                    raise ValueError("retry is not the saved validator failure")
                first_draft_ref = retry_failure.evidence_refs[0]
                if (
                    first_draft_ref not in stopped.input_refs
                    or first_draft_ref == draft_ref
                    or retry_ref == draft_ref
                ):
                    raise ValueError("retry references are not carried forward")
            except (OSError, TypeError, ValueError) as error:
                raise ValueError("REPORT_VALIDATOR_REPLAY_CAUSE_UNPROVEN") from error
            first_envelope, first_content = validated_draft(
                first_draft_ref, first_attempt_id
            )
            if not has_legacy_report_ipv4_false_positive(first_content):
                raise ValueError("REPORT_VALIDATOR_REPLAY_LEGACY_CAUSE_UNPROVEN")
        if exhausted_report:
            try:
                for attempt, ref in enumerate(stopped.recovery_decision_refs, 1):
                    decision = json.loads(artifacts.read_bounded(ref, 64 * 1024))
                    if (
                        not isinstance(decision, dict)
                        or decision.get("kind") != "simple_recovery_decision"
                        or decision.get("identity") != identity.model_dump(mode="json")
                        or decision.get("stage") != SimpleStage.REPORT_DONE.value
                        or decision.get("attempt") != attempt
                        or not isinstance(decision.get("attempt_id"), str)
                        or not decision["attempt_id"]
                        or not isinstance(decision.get("original_error"), dict)
                        or decision["original_error"].get("code")
                        != "REPORT_CONTENT_INVALID"
                    ):
                        raise ValueError("recovery decision is not report validation")
            except (OSError, TypeError, ValueError) as error:
                raise ValueError("REPORT_VALIDATOR_REPLAY_CAUSE_UNPROVEN") from error

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")

            def checkpoint_at(
                child: CheckpointIdentity, stage: SimpleStage
            ) -> StageCheckpoint | None:
                row = connection.execute(
                    "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                    "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
                    (child.analysis_id, self._hypothesis_key(child), stage.value),
                ).fetchone()
                return (
                    StageCheckpoint.model_validate_json(row["checkpoint_json"])
                    if row is not None
                    else None
                )

            if checkpoint_at(identity, SimpleStage.REPORT_DONE) != stopped:
                raise ValueError("REPORT_VALIDATOR_REPLAY_STALE")
            if stopped_second_report:
                assert first_attempt_id is not None
                assert first_draft_ref is not None
                assert retry_ref is not None

                def attempt_events(attempt_id: str) -> tuple[AgentActivityEvent, ...]:
                    rows = connection.execute(
                        "SELECT event_json FROM agent_activity_events "
                        "WHERE analysis_id = ? AND hypothesis_key = ? "
                        "AND attempt_id = ?",
                        (identity.analysis_id, identity.hypothesis_id, attempt_id),
                    ).fetchall()
                    try:
                        return tuple(
                            AgentActivityEvent.model_validate_json(row["event_json"])
                            for row in rows
                        )
                    except ValueError as error:
                        raise ValueError(
                            "REPORT_VALIDATOR_REPLAY_CAUSE_UNPROVEN"
                        ) from error

                def sole_report_event(
                    events: tuple[AgentActivityEvent, ...],
                    attempt_id: str,
                    kind: ActivityKind,
                    refs: tuple[StoredDataRef, ...] | None,
                ) -> AgentActivityEvent:
                    matches = tuple(
                        event
                        for event in events
                        if event.stage == SimpleStage.REPORT_DONE.value
                        and event.kind is kind
                    )
                    if len(matches) != 1:
                        raise ValueError("REPORT_VALIDATOR_REPLAY_CAUSE_UNPROVEN")
                    event = matches[0]
                    if (
                        event.analysis_id != identity.analysis_id
                        or event.workspace_id != identity.workspace_id
                        or event.commit_id != identity.commit_id
                        or event.hypothesis_id != identity.hypothesis_id
                        or event.attempt_id != attempt_id
                        or event.status != StageStatus.BLOCKED.value
                        or event.error_code != "REPORT_CONTENT_INVALID"
                        or refs is not None
                        and event.output_refs != refs
                    ):
                        raise ValueError("REPORT_VALIDATOR_REPLAY_CAUSE_UNPROVEN")
                    return event

                first_events = attempt_events(first_attempt_id)
                second_events = attempt_events(stopped.attempt_id)
                first_failure_event = sole_report_event(
                    first_events,
                    first_attempt_id,
                    ActivityKind.STAGE_BLOCKED,
                    (first_draft_ref,),
                )
                first_retry_event = sole_report_event(
                    first_events,
                    first_attempt_id,
                    ActivityKind.DECISION_RECORDED,
                    (retry_ref,),
                )
                second_failure_event = sole_report_event(
                    second_events,
                    stopped.attempt_id,
                    ActivityKind.STAGE_BLOCKED,
                    (draft_ref,),
                )
                second_stop_event = sole_report_event(
                    second_events,
                    stopped.attempt_id,
                    ActivityKind.DECISION_RECORDED,
                    None,
                )
                first_inputs = first_failure_event.input_refs
                expected_lineage = hashlib.sha256(
                    canonical_bytes(
                        {
                            "identity": identity,
                            "stage": SimpleStage.REPORT_DONE.value,
                            "stage_version": stopped.stage_version,
                            "input_hash": input_reference_hash(first_inputs),
                            "error_code": "REPORT_CONTENT_INVALID",
                        }
                    )
                ).hexdigest()
                if (
                    first_retry_event.input_refs != first_inputs
                    or first_draft_ref in first_inputs
                    or retry_ref in first_inputs
                    or stopped.recovery_lineage_id != expected_lineage
                    or stopped.input_refs
                    != tuple(dict.fromkeys(first_inputs + (first_draft_ref, retry_ref)))
                    or second_failure_event.input_refs != stopped.input_refs
                    or second_stop_event.input_refs != stopped.input_refs
                    or any(
                        event.kind
                        in {ActivityKind.STAGE_COMPLETED, ActivityKind.STAGE_FAILED}
                        and event.stage == SimpleStage.REPORT_DONE.value
                        for event in (*first_events, *second_events)
                    )
                    or len(second_stop_event.output_refs) != 1
                ):
                    raise ValueError("REPORT_VALIDATOR_REPLAY_CAUSE_UNPROVEN")
                stop_ref = second_stop_event.output_refs[0]
                try:
                    stop_record = json.loads(
                        artifacts.read_bounded(stop_ref, 64 * 1024)
                    )
                    if not isinstance(stop_record, dict):
                        raise ValueError("invalid STOP decision")
                    stop_failure = StageFailure.model_validate_json(
                        canonical_bytes(stop_record.get("original_error"))
                    )
                    stop_decision = RecoveryDecision.model_validate_json(
                        canonical_bytes(stop_record.get("decision"))
                    )
                    if (
                        stop_ref in stopped.input_refs
                        or stop_ref in stopped.output_refs
                        or stop_record.get("kind") != "simple_recovery_decision"
                        or stop_record.get("identity")
                        != identity.model_dump(mode="json")
                        or stop_record.get("stage") != SimpleStage.REPORT_DONE.value
                        or stop_record.get("attempt") != 2
                        or stop_record.get("attempt_id") != stopped.attempt_id
                        or stop_record.get("decision_origin") != "AGENT"
                        or stop_failure.code != "REPORT_CONTENT_INVALID"
                        or not stop_failure.retryable
                        or stop_failure.evidence_refs != (draft_ref,)
                        or stop_decision.category
                        is not RecoveryCategory.GENERATED_INPUT
                        or stop_decision.action is not RecoveryAction.STOP
                        or stop_decision.environment_patch != ""
                    ):
                        raise ValueError("STOP does not bind the failed report")
                except (OSError, TypeError, ValueError) as error:
                    raise ValueError(
                        "REPORT_VALIDATOR_REPLAY_CAUSE_UNPROVEN"
                    ) from error
            if exhausted_report:
                event_rows = connection.execute(
                    "SELECT event_json FROM agent_activity_events "
                    "WHERE analysis_id = ? AND hypothesis_key = ? AND attempt_id = ?",
                    (identity.analysis_id, identity.hypothesis_id, stopped.attempt_id),
                ).fetchall()
                try:
                    failure_events = tuple(
                        AgentActivityEvent.model_validate_json(row["event_json"])
                        for row in event_rows
                    )
                except ValueError as error:
                    raise ValueError(
                        "REPORT_VALIDATOR_REPLAY_CAUSE_UNPROVEN"
                    ) from error
                if not any(
                    event.kind is ActivityKind.STAGE_BLOCKED
                    and event.stage == SimpleStage.REPORT_DONE.value
                    and event.error_code == "REPORT_CONTENT_INVALID"
                    and event.status == StageStatus.BLOCKED.value
                    and event.workspace_id == identity.workspace_id
                    and event.commit_id == identity.commit_id
                    and event.output_refs == (draft_ref,)
                    for event in failure_events
                ):
                    raise ValueError("REPORT_VALIDATOR_REPLAY_CAUSE_UNPROVEN")
            root_identity = identity.model_copy(update={"hypothesis_id": None})
            root = checkpoint_at(root_identity, SimpleStage.HYPOTHESIS_DONE)
            expected_root_error = (
                "CANDIDATE_CHILD_ERROR_BOUND:"
                f"{stopped.error_code}:{identity.hypothesis_id}:{stopped.attempt_id}"
            )
            if (
                root is None
                or root.status is not StageStatus.BLOCKED
                or root.error_code != expected_root_error
            ):
                raise ValueError("REPORT_VALIDATOR_REPLAY_ROOT_UNBOUND")
            run_row = connection.execute(
                "SELECT run_json FROM simple_analysis_runs WHERE analysis_id = ?",
                (identity.analysis_id,),
            ).fetchone()
            if run_row is None:
                raise ValueError("REPORT_VALIDATOR_REPLAY_RUN_INVALID")
            run = SimpleAnalysisRun.model_validate_json(run_row["run_json"])
            registered = identity.hypothesis_id in run.hypothesis_ids or (
                connection.execute(
                    "SELECT 1 FROM simple_candidate_hypotheses "
                    "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                    "AND hypothesis_id = ? LIMIT 1",
                    (
                        identity.analysis_id,
                        identity.workspace_id,
                        identity.commit_id,
                        identity.hypothesis_id,
                    ),
                ).fetchone()
                is not None
            )
            if (
                run.workspace_id != identity.workspace_id
                or run.commit_id != identity.commit_id
                or not registered
                or run.candidate_pipeline_version != 2
            ):
                raise ValueError("REPORT_VALIDATOR_REPLAY_RUN_INVALID")
            if (
                connection.execute(
                    "SELECT 1 FROM simple_codex_calls "
                    "WHERE analysis_id = ? AND status = 'IN_FLIGHT' LIMIT 1",
                    (identity.analysis_id,),
                ).fetchone()
                is not None
            ):
                raise ValueError("REPORT_VALIDATOR_REPLAY_CODEX_IN_FLIGHT")
            prior: dict[SimpleStage, StageCheckpoint] = {}
            for stage in HYPOTHESIS_STAGES[:-1]:
                checkpoint = checkpoint_at(identity, stage)
                if (
                    checkpoint is None
                    or checkpoint.status is not StageStatus.SUCCEEDED
                    or checkpoint.stage_version != STAGE_VERSION[stage]
                ):
                    raise ValueError("REPORT_VALIDATOR_REPLAY_PRIOR_INVALID")
                prior[stage] = checkpoint
            finding = prior[SimpleStage.FINDING_DONE]
            execution = prior[SimpleStage.POC_EXECUTION_DONE]
            if (
                finding.verdict != "TRUE"
                or len(finding.output_refs) != 1
                or execution.validated_poc_ref is None
            ):
                raise ValueError("REPORT_VALIDATOR_REPLAY_PRIOR_INVALID")
            refs = tuple(
                dict.fromkeys(
                    ref
                    for checkpoint in prior.values()
                    for ref in checkpoint.output_refs
                )
            )
            if envelope["source_refs"] != [ref.model_dump(mode="json") for ref in refs]:
                raise ValueError("REPORT_VALIDATOR_REPLAY_SOURCE_MISMATCH")
            if stopped_second_report and (
                first_envelope is None
                or first_envelope["source_refs"]
                != [ref.model_dump(mode="json") for ref in refs]
            ):
                raise ValueError("REPORT_VALIDATOR_REPLAY_SOURCE_MISMATCH")
            source_hash = hashlib.sha256(
                canonical_bytes(
                    {
                        "refs": refs,
                        "finding_attempt_id": finding.attempt_id,
                        "poc_attempt_id": execution.attempt_id,
                    }
                )
            ).hexdigest()
            cache_key = (
                identity.model_dump_json(),
                source_hash,
                STAGE_VERSION[SimpleStage.REPORT_DONE],
            )
            existing = connection.execute(
                "SELECT 1 FROM simple_report_drafts "
                "WHERE identity_json = ? AND input_hash = ? AND stage_version = ?",
                cache_key,
            ).fetchone()
            if existing is not None:
                raise ValueError("REPORT_VALIDATOR_REPLAY_ALREADY_CACHED")
            pending = stopped.model_copy(
                update={
                    "status": StageStatus.PENDING,
                    "attempt_id": None,
                    "output_refs": (),
                    "error_code": None,
                    "retryable": False,
                    "updated_at": datetime.now(UTC),
                }
            )
            connection.execute(
                "INSERT INTO simple_report_drafts "
                "(identity_json, input_hash, stage_version, finding_ref_json, "
                "draft_ref_json) VALUES (?, ?, ?, ?, ?)",
                (
                    *cache_key,
                    finding.output_refs[0].model_dump_json(),
                    draft_ref.model_dump_json(),
                ),
            )
            self._upsert_checkpoint_connection(connection, pending)
            AgentActivityStore.append_connection(
                connection,
                self._lifecycle_event(
                    stopped,
                    ActivityKind.DECISION_RECORDED,
                    sequence=self._stage_sequence(stopped.stage, 70),
                    status=StageStatus.BLOCKED,
                    summary_ko="검증기 수정 근거로 동일 보고서 초안을 재검증합니다.",
                    error_code="REPORT_VALIDATOR_REPLAYED",
                ),
            )
            if fail_before_commit:
                raise RuntimeError("simulated crash")
            connection.commit()
            return pending
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

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

    def _reconcile_unspawned_codex_call_with_lease(
        self, run: SimpleAnalysisRun, data_dir: Path
    ) -> bool:
        """Settle a v2 Codex reservation that provably never spawned a child.

        The caller must hold the exclusive analysis run lease. Production Codex
        invokes ``begin_codex_child_spawn`` synchronously before creating each
        subprocess, so an empty intent ledger is a durable pre-spawn boundary.
        The conditional update and empty-ledger check share one write transaction:
        a late callback cannot spawn after this transaction wins.
        """

        if (
            run.candidate_pipeline_version != 2
            or run.provider != "codex"
            or run.llm_provider != "codex"
            or run.started_at is None
        ):
            return False
        identity = CheckpointIdentity(
            analysis_id=run.analysis_id,
            workspace_id=run.workspace_id,
            commit_id=run.commit_id,
            hypothesis_id=None,
        )
        artifacts = SimpleArtifactRepository(data_dir, identity)
        if artifacts.paths.database.resolve() != self._database_path.resolve():
            raise ValueError("CODEX_PRE_SPAWN_DATABASE_MISMATCH")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT call_id, started_at FROM simple_codex_calls "
                "WHERE analysis_id = ? AND status = 'IN_FLIGHT'",
                (run.analysis_id,),
            ).fetchone()
            if row is None:
                return False
            call_id = str(row["call_id"])
            version = connection.execute(
                "SELECT candidate_pipeline_version FROM simple_codex_call_versions "
                "WHERE call_id = ? AND analysis_id = ?",
                (call_id, run.analysis_id),
            ).fetchone()
            saved_run = connection.execute(
                "SELECT run_json FROM simple_analysis_runs WHERE analysis_id = ?",
                (run.analysis_id,),
            ).fetchone()
            child = connection.execute(
                "SELECT 1 FROM simple_codex_child_spawns WHERE call_id = ? LIMIT 1",
                (call_id,),
            ).fetchone()
            attempt = connection.execute(
                "SELECT 1 FROM simple_llm_attempts WHERE attempt_id = ? LIMIT 1",
                (call_id,),
            ).fetchone()
            try:
                started_at = datetime.fromisoformat(str(row["started_at"]))
                exact_run = (
                    SimpleAnalysisRun.model_validate_json(saved_run["run_json"])
                    if saved_run is not None
                    else None
                )
            except (TypeError, ValueError):
                return False
            now = datetime.now(UTC)
            if (
                version is None
                or int(version["candidate_pipeline_version"]) != 2
                or exact_run != run
                or child is not None
                or attempt is not None
                or started_at.tzinfo is None
                or run.started_at.tzinfo is None
                or not run.started_at <= started_at <= now
            ):
                return False
            confirmation = artifacts.put_json(
                {
                    "kind": "simple_codex_pre_spawn_confirmation",
                    "analysis_id": run.analysis_id,
                    "workspace_id": run.workspace_id,
                    "commit_id": run.commit_id,
                    "call_id": call_id,
                    "call_started_at": started_at.isoformat(),
                    "confirmed_at": now.isoformat(),
                    "candidate_pipeline_version": 2,
                    "child_spawn_rows": 0,
                    "llm_attempt_rows": 0,
                }
            )
            connection.execute(
                "INSERT INTO simple_llm_attempts "
                "(attempt_id, analysis_id, agent, model, attempt_number, status, "
                "elapsed_ms, input_tokens, output_tokens, cost_cents, "
                "artifact_ref_json) VALUES (?, ?, 'unknown', ?, 0, "
                "'CODEX_NOT_SPAWNED', 0, 0, 0, 0, ?)",
                (
                    call_id,
                    run.analysis_id,
                    run.model or "unknown",
                    confirmation.model_dump_json(),
                ),
            )
            changed = connection.execute(
                "UPDATE simple_codex_calls SET status = 'CONFIRMED', "
                "resolved_at = ?, confirmation_ref_json = ? "
                "WHERE call_id = ? AND analysis_id = ? AND status = 'IN_FLIGHT'",
                (
                    now.isoformat(),
                    confirmation.model_dump_json(),
                    call_id,
                    run.analysis_id,
                ),
            )
            if changed.rowcount != 1:
                raise ValueError("CODEX_PRE_SPAWN_RECONCILIATION_STALE")
            connection.commit()
            return True
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _reconcile_exited_codex_call_with_lease(
        self, run: SimpleAnalysisRun, data_dir: Path
    ) -> bool:
        """Never infer a stopped process tree from direct-child PID absence.

        A Codex child may have exited while an untracked descendant remains.
        Only an independently audited cleanup confirmation may release the
        durable IN_FLIGHT reservation after a parent crash.
        """

        return False

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
            SELECT COALESCE(SUM(CASE WHEN status != 'CODEX_NOT_SPAWNED'
                   THEN 1 ELSE 0 END), 0) AS calls,
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
            from sastsimi.providers.codex_subscription import child_identity_matches

            if any(
                child_identity_matches(
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
            "external_prerequisites_ref": result.external_prerequisites_ref,
            "environment_block_ref": result.environment_block_ref,
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
        *,
        activity_attempt_id: str | None = None,
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
        # An integrity audit is a new event, not a replay of the stage's old
        # failure event. Keep the checkpoint's actual execution attempt intact.
        event_checkpoint = (
            failed.model_copy(update={"attempt_id": activity_attempt_id})
            if activity_attempt_id is not None
            else failed
        )
        self._write(
            failed,
            activity_events=(
                self._lifecycle_event(
                    event_checkpoint,
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
        rebuild = resolution.decision.action in {
            RecoveryAction.REBUILD_ENVIRONMENT,
            RecoveryAction.REPLAN_ENVIRONMENT,
        }
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

    def prepare_offline_environment_repair(
        self,
        exhausted: StageCheckpoint,
        proof_ref: StoredDataRef,
        artifacts: SimpleArtifactRepository,
        *,
        fail_before_commit: bool = False,
    ) -> StageCheckpoint:
        """Allow one explicit, evidenced environment correction after PoC exhaustion.

        This is not an automatic recovery retry. The old PoC result remains in
        immutable artifacts and activity, while only this child's checkpoints
        from initial verification onward are replaced inside one transaction.
        """

        identity = exhausted.identity
        if (
            identity.hypothesis_id is None
            or exhausted.stage is not SimpleStage.POC_EXECUTION_DONE
            or exhausted.stage_version != STAGE_VERSION[exhausted.stage]
            or exhausted.status is not StageStatus.BLOCKED
            or exhausted.error_code != "RECOVERY_EXHAUSTED"
            or exhausted.retryable
            or exhausted.attempt_number != MAX_RECOVERY_ATTEMPTS
            or exhausted.attempt_id is None
            or exhausted.recipe_ref is None
            or not exhausted.output_refs
            or exhausted.validated_poc_ref is not None
            or artifacts.identity != identity
        ):
            raise ValueError("OFFLINE_REPAIR_EXHAUSTION_INVALID")
        try:
            proof = json.loads(artifacts.read_bounded(proof_ref, 256 * 1024))
            recipe = json.loads(
                artifacts.read_bounded(exhausted.recipe_ref, 256 * 1024)
            )
        except (OSError, ValueError, TypeError, sqlite3.Error) as error:
            raise ValueError("OFFLINE_REPAIR_EVIDENCE_INVALID") from error
        if not isinstance(proof, dict) or not isinstance(recipe, dict):
            raise ValueError("OFFLINE_REPAIR_EVIDENCE_INVALID")
        old_base = recipe.get("base_image_digest")
        new_base = proof.get("new_base_image_digest")
        digest_pattern = r"sha256:[0-9a-f]{64}"
        try:
            wheel_archive_ref = StoredDataRef.model_validate(
                recipe.get("wheel_archive_ref")
            )
        except ValueError as error:
            raise ValueError("OFFLINE_REPAIR_RECIPE_INVALID") from error
        expected_proof = {
            "kind": "simple_offline_environment_repair",
            "identity": identity.model_dump(mode="json"),
            "stage": SimpleStage.POC_EXECUTION_DONE.value,
            "exhausted_attempt_id": exhausted.attempt_id,
            "exhausted_attempt_number": exhausted.attempt_number,
            "exhausted_checkpoint_hash": hashlib.sha256(
                canonical_bytes(exhausted.model_dump(mode="json"))
            ).hexdigest(),
            "old_base_image_digest": old_base,
        }
        if (
            recipe.get("kind") != "simple_environment_recipe"
            or recipe.get("dockerfile_source") != "GENERATED_OFFLINE_WHEELS"
            or recipe.get("build_network") != "none"
            or recipe.get("wheel_archive_sha256") != wheel_archive_ref.content_hash
            or str(wheel_archive_ref.workspace_id) != identity.workspace_id
            or str(wheel_archive_ref.commit_id) != identity.commit_id
            or not isinstance(old_base, str)
            or re.fullmatch(digest_pattern, old_base) is None
            or not isinstance(new_base, str)
            or re.fullmatch(digest_pattern, new_base) is None
            or new_base == old_base
            or any(proof.get(key) != value for key, value in expected_proof.items())
            or not isinstance(proof.get("browser_command"), str)
            or not proof["browser_command"].startswith("/")
            or not isinstance(proof.get("python_version"), str)
            or not proof["python_version"].startswith("3.12.")
            or not isinstance(proof.get("smoke_output_digest"), str)
            or re.fullmatch(digest_pattern, proof["smoke_output_digest"]) is None
        ):
            raise ValueError("OFFLINE_REPAIR_EVIDENCE_INVALID")

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")

            def checkpoint_at(stage: SimpleStage) -> StageCheckpoint | None:
                row = connection.execute(
                    "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                    "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
                    (identity.analysis_id, self._hypothesis_key(identity), stage.value),
                ).fetchone()
                return (
                    StageCheckpoint.model_validate_json(row["checkpoint_json"])
                    if row is not None
                    else None
                )

            current = checkpoint_at(SimpleStage.POC_EXECUTION_DONE)
            initial = checkpoint_at(SimpleStage.VERIFICATION_INITIAL_DONE)
            candidate = checkpoint_at(SimpleStage.POC_CANDIDATE_DONE)
            if current != exhausted:
                raise ValueError("OFFLINE_REPAIR_STALE")
            if (
                initial is None
                or initial.status is not StageStatus.SUCCEEDED
                or initial.stage_version != STAGE_VERSION[initial.stage]
                or initial.recipe_ref != exhausted.recipe_ref
                or candidate is None
                or candidate.status is not StageStatus.SUCCEEDED
                or candidate.stage_version != STAGE_VERSION[candidate.stage]
                or candidate.attempt_id != exhausted.attempt_id
                or candidate.attempt_number != exhausted.attempt_number
                or candidate.recipe_ref != exhausted.recipe_ref
                or any(
                    checkpoint_at(stage) is not None
                    for stage in STAGE_ORDER[
                        STAGE_ORDER.index(SimpleStage.VERIFICATION_FINAL_DONE) :
                    ]
                )
            ):
                raise ValueError("OFFLINE_REPAIR_LINEAGE_INVALID")

            decision_refs = tuple(
                dict.fromkeys(exhausted.recovery_decision_refs + (proof_ref,))
            )
            inputs = tuple(
                dict.fromkeys(
                    initial.input_refs
                    + initial.output_refs
                    + candidate.input_refs
                    + candidate.output_refs
                    + exhausted.input_refs
                    + exhausted.output_refs
                    + decision_refs
                )
            )
            lineage_id = (
                exhausted.recovery_lineage_id
                or hashlib.sha256(
                    canonical_bytes(
                        {
                            "identity": identity,
                            "attempt_id": exhausted.attempt_id,
                            "error_code": exhausted.error_code,
                        }
                    )
                ).hexdigest()
            )
            pending = StageCheckpoint(
                identity=identity,
                stage=SimpleStage.VERIFICATION_INITIAL_DONE,
                stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE],
                status=StageStatus.PENDING,
                input_refs=inputs,
                input_hash=input_reference_hash(inputs),
                attempt_number=exhausted.attempt_number,
                gate_revision_count=exhausted.gate_revision_count,
                recovery_lineage_id=lineage_id,
                # Keep attempt 4 through candidate and execution. `complete`
                # clears a lineage when its origin stage succeeds.
                recovery_origin_stage=SimpleStage.POC_EXECUTION_DONE,
                recovery_decision_refs=decision_refs,
            )
            AgentActivityStore.append_connection(
                connection,
                self._lifecycle_event(
                    exhausted,
                    ActivityKind.EVIDENCE_RECORDED,
                    sequence=self._stage_sequence(exhausted.stage, 101),
                    status=StageStatus.BLOCKED,
                    summary_ko=(
                        "격리된 오프라인 실행 환경을 검증한 뒤 한 번의 수동 재시도를 "
                        "승인했습니다. 기존 PoC 실패 기록은 보존합니다."
                    ),
                    output_refs=(proof_ref,),
                ).model_copy(
                    update={
                        "input_refs": tuple(
                            dict.fromkeys(exhausted.input_refs + exhausted.output_refs)
                        )
                    }
                ),
            )
            stages = tuple(
                stage.value
                for stage in STAGE_ORDER[
                    STAGE_ORDER.index(SimpleStage.VERIFICATION_INITIAL_DONE) :
                ]
            )
            placeholders = ",".join("?" for _ in stages)
            connection.execute(
                f"DELETE FROM simple_runtime_checkpoints WHERE analysis_id = ? "
                f"AND hypothesis_key = ? AND stage IN ({placeholders})",  # noqa: S608
                (identity.analysis_id, self._hypothesis_key(identity), *stages),
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

    def prepare_legacy_import_stop_replan(
        self,
        stopped: StageCheckpoint,
        artifacts: SimpleArtifactRepository,
        *,
        fail_before_commit: bool = False,
    ) -> StageCheckpoint:
        """Supersede one evidence-bound import STOP under the caller's run lease."""

        return self._prepare_fallback_poc_stop_replan(
            stopped, artifacts, mode="import", fail_before_commit=fail_before_commit
        )

    def prepare_fallback_poc_stop_replan(
        self,
        stopped: StageCheckpoint,
        artifacts: SimpleArtifactRepository,
        *,
        fail_before_commit: bool = False,
    ) -> StageCheckpoint:
        """Explicitly retry a policy-invalid fallback STOP for a non-import PoC.

        The import path remains separate because it can alter the environment;
        this path preserves the pinned recipe and regenerates only the PoC.
        """

        try:
            return self._prepare_fallback_poc_stop_replan(
                stopped,
                artifacts,
                mode="generated_input",
                fail_before_commit=fail_before_commit,
            )
        except ValueError as error:
            message = str(error)
            if message.startswith("LEGACY_IMPORT_STOP_"):
                raise ValueError(
                    message.replace("LEGACY_IMPORT_STOP_", "FALLBACK_POC_STOP_", 1)
                ) from error
            raise

    def prepare_pre_execution_docker_replay(
        self,
        exhausted: StageCheckpoint,
        absence_ref: StoredDataRef,
        artifacts: SimpleArtifactRepository,
        *,
        fail_before_commit: bool = False,
    ) -> StageCheckpoint:
        """Replay one exhausted attempt only when no PoC container was created.

        The caller must confirm exact owner-label absence with Docker under the
        analysis lease. The prior exhaustion and its events remain append-only.
        A marker prevents another attempt-3 replay for this child.
        """

        identity = exhausted.identity
        if (
            identity.hypothesis_id is None
            or exhausted.stage is not SimpleStage.POC_EXECUTION_DONE
            or exhausted.stage_version != STAGE_VERSION[exhausted.stage]
            or exhausted.status is not StageStatus.BLOCKED
            or exhausted.error_code != "RECOVERY_EXHAUSTED"
            or exhausted.retryable
            or exhausted.attempt_number != MAX_RECOVERY_ATTEMPTS
            or not exhausted.attempt_id
            or exhausted.output_refs
            or exhausted.container_id is not None
            or exhausted.recipe_ref is None
            or exhausted.image_digest is None
            or exhausted.validated_poc_ref is not None
            or artifacts.identity != identity
            or artifacts.paths.database.resolve() != self._database_path.resolve()
        ):
            raise ValueError("DOCKER_LIST_EXHAUSTION_INVALID")
        try:
            absence = json.loads(artifacts.read_bounded(absence_ref, 8 * 1024))
        except (OSError, ValueError, TypeError, sqlite3.Error) as error:
            raise ValueError("DOCKER_LIST_EXHAUSTION_ABSENCE_INVALID") from error
        if (
            not isinstance(absence, dict)
            or absence.get("kind") != "simple_owned_attempt_container_absence"
            or absence.get("identity") != identity.model_dump(mode="json")
            or absence.get("attempt_id") != exhausted.attempt_id
            or absence.get("present") is not False
            or absence.get("exhausted_checkpoint_hash")
            != hashlib.sha256(
                canonical_bytes(exhausted.model_dump(mode="json"))
            ).hexdigest()
        ):
            raise ValueError("DOCKER_LIST_EXHAUSTION_ABSENCE_INVALID")

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")

            def checkpoint_at(stage: SimpleStage) -> StageCheckpoint | None:
                row = connection.execute(
                    "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                    "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
                    (identity.analysis_id, self._hypothesis_key(identity), stage.value),
                ).fetchone()
                return (
                    StageCheckpoint.model_validate_json(row["checkpoint_json"])
                    if row is not None
                    else None
                )

            if checkpoint_at(SimpleStage.POC_EXECUTION_DONE) != exhausted:
                raise ValueError("DOCKER_LIST_EXHAUSTION_STALE")
            run_row = connection.execute(
                "SELECT run_json FROM simple_analysis_runs WHERE analysis_id = ?",
                (identity.analysis_id,),
            ).fetchone()
            if run_row is None:
                raise ValueError("DOCKER_LIST_EXHAUSTION_RUN_INVALID")
            run = SimpleAnalysisRun.model_validate_json(run_row["run_json"])
            registered = identity.hypothesis_id in run.hypothesis_ids or (
                connection.execute(
                    "SELECT 1 FROM simple_candidate_hypotheses "
                    "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                    "AND hypothesis_id = ?",
                    (
                        identity.analysis_id,
                        identity.workspace_id,
                        identity.commit_id,
                        identity.hypothesis_id,
                    ),
                ).fetchone()
                is not None
            )
            if (
                run.workspace_id != identity.workspace_id
                or run.commit_id != identity.commit_id
                or run.candidate_pipeline_version != 2
                or run.candidate_terminal is not None
                or run.workspace_path is None
                or run.repository_profile_ref is None
                or run.static_bundle_ref is None
                or run.static_coverage_ref is None
                or run.candidate_scope_fingerprint is None
                or not registered
            ):
                raise ValueError("DOCKER_LIST_EXHAUSTION_RUN_INVALID")
            root_identity = identity.model_copy(update={"hypothesis_id": None})
            static = self.get(root_identity, SimpleStage.STATIC_DONE)
            if (
                static is None
                or static.status is not StageStatus.SUCCEEDED
                or static.stage_version != STAGE_VERSION[SimpleStage.STATIC_DONE]
                or run.repository_profile_ref not in static.output_refs
                or run.static_bundle_ref not in static.output_refs
                or any(
                    str(ref.workspace_id) != identity.workspace_id
                    or str(ref.commit_id) != identity.commit_id
                    for ref in (
                        run.repository_profile_ref,
                        run.static_bundle_ref,
                        run.static_coverage_ref,
                    )
                )
            ):
                raise ValueError("DOCKER_LIST_EXHAUSTION_STATIC_INVALID")
            all_rows = connection.execute(
                "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                "WHERE analysis_id = ?",
                (identity.analysis_id,),
            ).fetchall()
            if any(
                StageCheckpoint.model_validate_json(row["checkpoint_json"]).status
                in {StageStatus.RUNNING, StageStatus.PENDING}
                for row in all_rows
            ):
                raise ValueError("DOCKER_LIST_EXHAUSTION_RUN_ACTIVE")
            root = self.get(root_identity, SimpleStage.HYPOTHESIS_DONE)
            root_code = (
                "CANDIDATE_CHILD_ERROR_BOUND:RECOVERY_EXHAUSTED:"
                f"{identity.hypothesis_id}:{exhausted.attempt_id}"
            )
            if (
                root is None
                or root.stage_version != STAGE_VERSION[SimpleStage.HYPOTHESIS_DONE]
                or root.status is not StageStatus.BLOCKED
                or root.retryable
                or not root.attempt_id
                or root.error_code != root_code
            ):
                raise ValueError("DOCKER_LIST_EXHAUSTION_ROOT_BOUND_INVALID")
            activity_rows = connection.execute(
                "SELECT event_json FROM agent_activity_events "
                "WHERE analysis_id = ? ORDER BY rowid",
                (identity.analysis_id,),
            ).fetchall()
            events = tuple(
                AgentActivityEvent.model_validate_json(row["event_json"])
                for row in activity_rows
            )
            if not any(
                event.kind is ActivityKind.STAGE_BLOCKED
                and event.analysis_id == identity.analysis_id
                and event.workspace_id == identity.workspace_id
                and event.commit_id == identity.commit_id
                and event.hypothesis_id is None
                and event.stage == SimpleStage.HYPOTHESIS_DONE.value
                and event.attempt_id == root.attempt_id
                and event.error_code == root_code
                for event in events
            ):
                raise ValueError("DOCKER_LIST_EXHAUSTION_ROOT_BOUND_INVALID")
            if any(
                event.hypothesis_id == identity.hypothesis_id
                and event.kind is ActivityKind.DECISION_RECORDED
                and event.error_code == "DOCKER_OWNED_LIST_EXHAUSTION_REPLAYED"
                for event in events
            ):
                raise ValueError("DOCKER_LIST_EXHAUSTION_ALREADY_REPLAYED")
            stage_events = tuple(
                event
                for event in events
                if event.hypothesis_id == identity.hypothesis_id
                and event.stage == SimpleStage.POC_EXECUTION_DONE.value
                and event.attempt_id == exhausted.attempt_id
            )
            if (
                len(stage_events) != 3
                or tuple((event.kind, event.error_code) for event in stage_events)
                != (
                    (ActivityKind.STAGE_STARTED, None),
                    (ActivityKind.STAGE_BLOCKED, "DOCKER_OWNED_LIST_FAILED"),
                    (ActivityKind.STAGE_BLOCKED, "RECOVERY_EXHAUSTED"),
                )
                or any(
                    event.analysis_id != identity.analysis_id
                    or event.workspace_id != identity.workspace_id
                    or event.commit_id != identity.commit_id
                    or event.output_refs
                    for event in stage_events
                )
                or any(
                    event.hypothesis_id == identity.hypothesis_id
                    and event.stage
                    in {
                        stage.value
                        for stage in STAGE_ORDER[
                            STAGE_ORDER.index(SimpleStage.VERIFICATION_FINAL_DONE) :
                        ]
                    }
                    and event.started_at >= stage_events[0].started_at
                    for event in events
                )
            ):
                raise ValueError("DOCKER_LIST_EXHAUSTION_EVENT_INVALID")
            unresolved = connection.execute(
                "SELECT 1 FROM simple_codex_calls WHERE analysis_id = ? "
                "AND (status = 'IN_FLIGHT' OR resolved_at IS NULL) LIMIT 1",
                (identity.analysis_id,),
            ).fetchone()
            unexited = connection.execute(
                "SELECT 1 FROM simple_codex_child_spawns WHERE analysis_id = ? "
                "AND (status != 'EXITED' OR pid IS NULL OR "
                "start_identity IS NULL OR start_identity = '') LIMIT 1",
                (identity.analysis_id,),
            ).fetchone()
            if unresolved is not None or unexited is not None:
                raise ValueError("DOCKER_LIST_EXHAUSTION_CODEX_UNRESOLVED")
            pro_con = checkpoint_at(SimpleStage.PRO_CON_DONE)
            initial = checkpoint_at(SimpleStage.VERIFICATION_INITIAL_DONE)
            candidate = checkpoint_at(SimpleStage.POC_CANDIDATE_DONE)
            if (
                pro_con is None
                or pro_con.status is not StageStatus.SUCCEEDED
                or pro_con.stage_version != STAGE_VERSION[SimpleStage.PRO_CON_DONE]
                or initial is None
                or initial.status is not StageStatus.SUCCEEDED
                or initial.stage_version
                != STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE]
                or initial.recipe_ref != exhausted.recipe_ref
                or initial.image_digest != exhausted.image_digest
                or candidate is None
                or candidate.status is not StageStatus.SUCCEEDED
                or candidate.stage_version != STAGE_VERSION[candidate.stage]
                or candidate.attempt_id != exhausted.attempt_id
                or candidate.attempt_number != exhausted.attempt_number
                or candidate.gate_revision_count != exhausted.gate_revision_count
                or candidate.recipe_ref != exhausted.recipe_ref
                or candidate.image_digest != exhausted.image_digest
                or candidate.container_id is not None
                or len(candidate.output_refs) < 2
                or any(
                    ref not in exhausted.input_refs for ref in candidate.output_refs[:2]
                )
                or any(
                    checkpoint_at(stage) is not None
                    for stage in STAGE_ORDER[
                        STAGE_ORDER.index(SimpleStage.VERIFICATION_FINAL_DONE) :
                    ]
                )
            ):
                raise ValueError("DOCKER_LIST_EXHAUSTION_LINEAGE_INVALID")
            try:
                record = json.loads(
                    artifacts.read_bounded(candidate.output_refs[0], 64 * 1024)
                )
                content = artifacts.read_bounded(candidate.output_refs[1], 1024 * 1024)
            except (OSError, ValueError, TypeError, sqlite3.Error) as error:
                raise ValueError("DOCKER_LIST_EXHAUSTION_CANDIDATE_INVALID") from error
            if (
                not isinstance(record, dict)
                or record.get("kind") != "simple_poc_candidate"
                or record.get("attempt_id") != exhausted.attempt_id
                or record.get("content_ref")
                != candidate.output_refs[1].model_dump(mode="json")
                or record.get("content_digest") != hashlib.sha256(content).hexdigest()
            ):
                raise ValueError("DOCKER_LIST_EXHAUSTION_CANDIDATE_INVALID")
            marker_ref = artifacts.put_json(
                {
                    "kind": "simple_docker_list_exhaustion_replay",
                    "identity": identity.model_dump(mode="json"),
                    "old_attempt_id": exhausted.attempt_id,
                    "old_attempt_number": exhausted.attempt_number,
                    "exhausted_checkpoint_hash": absence["exhausted_checkpoint_hash"],
                    "absence_ref": absence_ref.model_dump(mode="json"),
                    "candidate_ref": candidate.output_refs[0].model_dump(mode="json"),
                    "reason": "DOCKER_OWNED_LIST_FAILED_BEFORE_CONTAINER_CREATE",
                }
            )
            inputs = tuple(
                dict.fromkeys(
                    (
                        *candidate.input_refs,
                        *candidate.output_refs,
                        *exhausted.input_refs,
                        absence_ref,
                        marker_ref,
                    )
                )
            )
            pending = StageCheckpoint(
                identity=identity,
                stage=SimpleStage.POC_CANDIDATE_DONE,
                stage_version=STAGE_VERSION[SimpleStage.POC_CANDIDATE_DONE],
                status=StageStatus.PENDING,
                input_refs=inputs,
                input_hash=input_reference_hash(inputs),
                attempt_number=MAX_RECOVERY_ATTEMPTS - 1,
                gate_revision_count=candidate.gate_revision_count,
                recovery_lineage_id=(
                    exhausted.recovery_lineage_id
                    or hashlib.sha256(
                        canonical_bytes(
                            {"identity": identity, "attempt_id": exhausted.attempt_id}
                        )
                    ).hexdigest()
                ),
                recovery_origin_stage=SimpleStage.POC_EXECUTION_DONE,
                recovery_decision_refs=exhausted.recovery_decision_refs,
                recipe_ref=exhausted.recipe_ref,
                image_digest=exhausted.image_digest,
                container_id=None,
            )
            connection.execute(
                "DELETE FROM simple_runtime_checkpoints WHERE analysis_id = ? "
                "AND hypothesis_key = ? AND stage = ?",
                (
                    identity.analysis_id,
                    self._hypothesis_key(identity),
                    SimpleStage.POC_EXECUTION_DONE.value,
                ),
            )
            self._upsert_checkpoint_connection(connection, pending)
            AgentActivityStore.append_connection(
                connection,
                self._lifecycle_event(
                    exhausted,
                    ActivityKind.DECISION_RECORDED,
                    sequence=self._stage_sequence(exhausted.stage, 102),
                    status=StageStatus.BLOCKED,
                    summary_ko=(
                        "컨테이너 생성 전 Docker 목록 실패를 확인하고 "
                        "명시적 재시드를 기록했습니다."
                    ),
                    output_refs=(marker_ref,),
                    error_code="DOCKER_OWNED_LIST_EXHAUSTION_REPLAYED",
                ),
            )
            if fail_before_commit:
                raise RuntimeError("simulated crash")
            connection.commit()
            return pending
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def prepare_poc_extract_exhaustion_replay(
        self,
        exhausted: StageCheckpoint,
        artifacts: SimpleArtifactRepository,
        *,
        fail_before_commit: bool = False,
    ) -> StageCheckpoint:
        """Explicitly regenerate one PoC after a bound sanitized extract failure.

        The attempt-3 PoC and exhaustion events remain append-only. A distinct
        rule event permits one new candidate attempt without changing the
        automatic three-attempt recovery ceiling.
        """

        identity = exhausted.identity
        if (
            identity.hypothesis_id is None
            or exhausted.stage is not SimpleStage.POC_EXECUTION_DONE
            or exhausted.stage_version != STAGE_VERSION[exhausted.stage]
            or exhausted.status is not StageStatus.BLOCKED
            or exhausted.error_code != "RECOVERY_EXHAUSTED"
            or exhausted.retryable
            or exhausted.attempt_number != MAX_RECOVERY_ATTEMPTS
            or not exhausted.attempt_id
            or len(exhausted.output_refs) != 4
            or exhausted.input_hash != input_reference_hash(exhausted.input_refs)
            or exhausted.container_id is not None
            or exhausted.recipe_ref is None
            or exhausted.image_digest is None
            or exhausted.validated_poc_ref is not None
            or artifacts.identity != identity
            or artifacts.paths.database.resolve() != self._database_path.resolve()
        ):
            raise ValueError("POC_EXTRACT_EXHAUSTION_INVALID")

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")

            def checkpoint_at(stage: SimpleStage) -> StageCheckpoint | None:
                row = connection.execute(
                    "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                    "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
                    (identity.analysis_id, self._hypothesis_key(identity), stage.value),
                ).fetchone()
                return (
                    StageCheckpoint.model_validate_json(row["checkpoint_json"])
                    if row is not None
                    else None
                )

            if checkpoint_at(SimpleStage.POC_EXECUTION_DONE) != exhausted:
                raise ValueError("POC_EXTRACT_EXHAUSTION_STALE")
            run_row = connection.execute(
                "SELECT run_json FROM simple_analysis_runs WHERE analysis_id = ?",
                (identity.analysis_id,),
            ).fetchone()
            if run_row is None:
                raise ValueError("POC_EXTRACT_EXHAUSTION_RUN_INVALID")
            run = SimpleAnalysisRun.model_validate_json(run_row["run_json"])
            registered = identity.hypothesis_id in run.hypothesis_ids or (
                connection.execute(
                    "SELECT 1 FROM simple_candidate_hypotheses "
                    "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                    "AND hypothesis_id = ?",
                    (
                        identity.analysis_id,
                        identity.workspace_id,
                        identity.commit_id,
                        identity.hypothesis_id,
                    ),
                ).fetchone()
                is not None
            )
            if (
                run.workspace_id != identity.workspace_id
                or run.commit_id != identity.commit_id
                or run.candidate_pipeline_version != 2
                or run.candidate_terminal is not None
                or run.workspace_path is None
                or run.repository_profile_ref is None
                or run.static_bundle_ref is None
                or run.static_coverage_ref is None
                or run.candidate_scope_fingerprint is None
                or not registered
            ):
                raise ValueError("POC_EXTRACT_EXHAUSTION_RUN_INVALID")
            root_identity = identity.model_copy(update={"hypothesis_id": None})
            static = self.get(root_identity, SimpleStage.STATIC_DONE)
            if (
                static is None
                or static.status is not StageStatus.SUCCEEDED
                or static.stage_version != STAGE_VERSION[SimpleStage.STATIC_DONE]
                or run.repository_profile_ref not in static.output_refs
                or run.static_bundle_ref not in static.output_refs
                or any(
                    str(ref.workspace_id) != identity.workspace_id
                    or str(ref.commit_id) != identity.commit_id
                    for ref in (
                        run.repository_profile_ref,
                        run.static_bundle_ref,
                        run.static_coverage_ref,
                    )
                )
            ):
                raise ValueError("POC_EXTRACT_EXHAUSTION_STATIC_INVALID")
            all_rows = connection.execute(
                "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                "WHERE analysis_id = ?",
                (identity.analysis_id,),
            ).fetchall()
            if any(
                StageCheckpoint.model_validate_json(row["checkpoint_json"]).status
                in {StageStatus.RUNNING, StageStatus.PENDING}
                for row in all_rows
            ):
                raise ValueError("POC_EXTRACT_EXHAUSTION_RUN_ACTIVE")
            root = self.get(root_identity, SimpleStage.HYPOTHESIS_DONE)
            root_code = (
                "CANDIDATE_CHILD_ERROR_BOUND:RECOVERY_EXHAUSTED:"
                f"{identity.hypothesis_id}:{exhausted.attempt_id}"
            )
            if (
                root is None
                or root.stage_version != STAGE_VERSION[SimpleStage.HYPOTHESIS_DONE]
                or root.status is not StageStatus.BLOCKED
                or root.retryable
                or not root.attempt_id
                or root.error_code != root_code
            ):
                raise ValueError("POC_EXTRACT_EXHAUSTION_ROOT_BOUND_INVALID")
            activity_rows = connection.execute(
                "SELECT event_json FROM agent_activity_events "
                "WHERE analysis_id = ? ORDER BY rowid",
                (identity.analysis_id,),
            ).fetchall()
            events = tuple(
                AgentActivityEvent.model_validate_json(row["event_json"])
                for row in activity_rows
            )
            if not any(
                event.kind is ActivityKind.STAGE_BLOCKED
                and event.analysis_id == identity.analysis_id
                and event.workspace_id == identity.workspace_id
                and event.commit_id == identity.commit_id
                and event.hypothesis_id is None
                and event.stage == SimpleStage.HYPOTHESIS_DONE.value
                and event.attempt_id == root.attempt_id
                and event.error_code == root_code
                for event in events
            ):
                raise ValueError("POC_EXTRACT_EXHAUSTION_ROOT_BOUND_INVALID")
            if any(
                event.hypothesis_id == identity.hypothesis_id
                and event.kind is ActivityKind.DECISION_RECORDED
                and event.error_code == "POC_EXTRACT_EXHAUSTION_REPLAYED"
                for event in events
            ):
                raise ValueError("POC_EXTRACT_EXHAUSTION_ALREADY_REPLAYED")
            stage_events = tuple(
                event
                for event in events
                if event.hypothesis_id == identity.hypothesis_id
                and event.stage == SimpleStage.POC_EXECUTION_DONE.value
                and event.attempt_id == exhausted.attempt_id
            )
            if (
                len(stage_events) != 3
                or tuple((event.kind, event.error_code) for event in stage_events)
                != (
                    (ActivityKind.STAGE_STARTED, None),
                    (ActivityKind.STAGE_BLOCKED, "POC_EXECUTION_FAILED"),
                    (ActivityKind.STAGE_BLOCKED, "RECOVERY_EXHAUSTED"),
                )
                or any(
                    event.analysis_id != identity.analysis_id
                    or event.workspace_id != identity.workspace_id
                    or event.commit_id != identity.commit_id
                    or event.input_refs != exhausted.input_refs
                    for event in stage_events
                )
                or stage_events[0].output_refs
                or any(
                    event.output_refs != exhausted.output_refs
                    for event in stage_events[1:]
                )
                or any(
                    event.hypothesis_id == identity.hypothesis_id
                    and event.stage
                    in {
                        stage.value
                        for stage in STAGE_ORDER[
                            STAGE_ORDER.index(SimpleStage.VERIFICATION_FINAL_DONE) :
                        ]
                    }
                    and event.started_at >= stage_events[0].started_at
                    for event in events
                )
            ):
                raise ValueError("POC_EXTRACT_EXHAUSTION_EVENT_INVALID")
            unresolved = connection.execute(
                "SELECT 1 FROM simple_codex_calls WHERE analysis_id = ? "
                "AND (status = 'IN_FLIGHT' OR resolved_at IS NULL) LIMIT 1",
                (identity.analysis_id,),
            ).fetchone()
            unexited = connection.execute(
                "SELECT 1 FROM simple_codex_child_spawns WHERE analysis_id = ? "
                "AND (status != 'EXITED' OR pid IS NULL OR "
                "start_identity IS NULL OR start_identity = '') LIMIT 1",
                (identity.analysis_id,),
            ).fetchone()
            if unresolved is not None or unexited is not None:
                raise ValueError("POC_EXTRACT_EXHAUSTION_CODEX_UNRESOLVED")
            pro_con = checkpoint_at(SimpleStage.PRO_CON_DONE)
            initial = checkpoint_at(SimpleStage.VERIFICATION_INITIAL_DONE)
            candidate = checkpoint_at(SimpleStage.POC_CANDIDATE_DONE)
            if (
                pro_con is None
                or pro_con.status is not StageStatus.SUCCEEDED
                or pro_con.stage_version != STAGE_VERSION[pro_con.stage]
                or initial is None
                or initial.status is not StageStatus.SUCCEEDED
                or initial.stage_version != STAGE_VERSION[initial.stage]
                or initial.recipe_ref != exhausted.recipe_ref
                or initial.image_digest != exhausted.image_digest
                or candidate is None
                or candidate.status is not StageStatus.SUCCEEDED
                or candidate.stage_version != STAGE_VERSION[candidate.stage]
                or candidate.attempt_id != exhausted.attempt_id
                or candidate.attempt_number != exhausted.attempt_number
                or candidate.gate_revision_count != exhausted.gate_revision_count
                or candidate.recipe_ref != exhausted.recipe_ref
                or candidate.image_digest != exhausted.image_digest
                or candidate.container_id is not None
                or len(candidate.output_refs) < 2
                or any(
                    ref not in exhausted.input_refs for ref in candidate.output_refs[:2]
                )
                or any(
                    checkpoint_at(stage) is not None
                    for stage in STAGE_ORDER[
                        STAGE_ORDER.index(SimpleStage.VERIFICATION_FINAL_DONE) :
                    ]
                )
            ):
                raise ValueError("POC_EXTRACT_EXHAUSTION_LINEAGE_INVALID")
            execution_ref, stdout_ref, stderr_ref, cleanup_ref = exhausted.output_refs
            try:
                candidate_record = json.loads(
                    artifacts.read_bounded(candidate.output_refs[0], 64 * 1024)
                )
                candidate_content = artifacts.read_bounded(
                    candidate.output_refs[1], 1024 * 1024
                )
                execution = json.loads(artifacts.read_bounded(execution_ref, 64 * 1024))
                # Attest bounded stdout, but use only stderr as the failure diagnostic.
                artifacts.read_bounded(stdout_ref, 1024 * 1024)
                stderr = artifacts.read_bounded(stderr_ref, 1024 * 1024)
                cleanup = json.loads(artifacts.read_bounded(cleanup_ref, 64 * 1024))
            except (OSError, ValueError, TypeError, sqlite3.Error) as error:
                raise ValueError("POC_EXTRACT_EXHAUSTION_EVIDENCE_INVALID") from error
            diagnostic = sanitized_extract_failure(stderr)
            if (
                not isinstance(candidate_record, dict)
                or candidate_record.get("kind") != "simple_poc_candidate"
                or candidate_record.get("attempt_id") != exhausted.attempt_id
                or candidate_record.get("content_ref")
                != candidate.output_refs[1].model_dump(mode="json")
                or candidate_record.get("content_digest")
                != hashlib.sha256(candidate_content).hexdigest()
                or not isinstance(execution, dict)
                or execution.get("kind") != "simple_poc_execution"
                or execution.get("attempt_id") != exhausted.attempt_id
                or execution.get("candidate_ref")
                != candidate.output_refs[0].model_dump(mode="json")
                or execution.get("content_ref")
                != candidate.output_refs[1].model_dump(mode="json")
                or execution.get("stdout_ref") != stdout_ref.model_dump(mode="json")
                or execution.get("stderr_ref") != stderr_ref.model_dump(mode="json")
                or execution.get("image_digest") != exhausted.image_digest
                or not isinstance(execution.get("container_id"), str)
                or not execution["container_id"]
                or type(execution.get("exit_code")) is not int
                or execution["exit_code"] == 0
                or execution.get("timed_out") is not False
                or diagnostic is None
                or not isinstance(cleanup, dict)
                or cleanup.get("kind") != "simple_container_cleanup"
                or cleanup.get("attempt_id") != exhausted.attempt_id
                or cleanup.get("container_id") != execution["container_id"]
                or cleanup.get("status") != "REMOVED"
            ):
                raise ValueError("POC_EXTRACT_EXHAUSTION_EVIDENCE_INVALID")

            rule_decision = sanitized_extract_recovery_decision()
            original_error = StageFailure(
                code="POC_EXECUTION_FAILED",
                retryable=True,
                safe_message="PoC failed during sanitized source extraction",
                evidence_refs=exhausted.output_refs,
            )
            rule_ref = artifacts.put_json(
                {
                    "kind": "simple_recovery_decision",
                    "identity": identity.model_dump(mode="json"),
                    "stage": exhausted.stage.value,
                    "attempt": exhausted.attempt_number,
                    "attempt_id": exhausted.attempt_id,
                    "original_error": original_error.model_dump(mode="json"),
                    "decision": rule_decision.model_dump(mode="json"),
                    "decision_origin": "RULE",
                    "diagnostic_excerpt": diagnostic.decode("ascii"),
                    "explicit_exhaustion_replay": True,
                    "recovery_revision": SANITIZED_EXTRACT_RECOVERY_REVISION,
                    "exhausted_checkpoint_hash": hashlib.sha256(
                        canonical_bytes(exhausted.model_dump(mode="json"))
                    ).hexdigest(),
                    "failure_event_id": stage_events[1].event_id,
                    "exhaustion_event_id": stage_events[2].event_id,
                }
            )
            decision_refs = tuple(
                dict.fromkeys((*exhausted.recovery_decision_refs, rule_ref))
            )
            inputs = tuple(
                dict.fromkeys(
                    (
                        *candidate.input_refs,
                        *candidate.output_refs,
                        *exhausted.input_refs,
                        *exhausted.output_refs,
                        *decision_refs,
                    )
                )
            )
            pending = StageCheckpoint(
                identity=identity,
                stage=SimpleStage.POC_CANDIDATE_DONE,
                stage_version=STAGE_VERSION[SimpleStage.POC_CANDIDATE_DONE],
                status=StageStatus.PENDING,
                input_refs=inputs,
                input_hash=input_reference_hash(inputs),
                attempt_number=exhausted.attempt_number,
                gate_revision_count=exhausted.gate_revision_count,
                recovery_lineage_id=(
                    exhausted.recovery_lineage_id
                    or hashlib.sha256(
                        canonical_bytes(
                            {"identity": identity, "attempt_id": exhausted.attempt_id}
                        )
                    ).hexdigest()
                ),
                recovery_origin_stage=SimpleStage.POC_EXECUTION_DONE,
                recovery_decision_refs=decision_refs,
                recipe_ref=exhausted.recipe_ref,
                image_digest=exhausted.image_digest,
                container_id=None,
            )
            connection.execute(
                "DELETE FROM simple_runtime_checkpoints WHERE analysis_id = ? "
                "AND hypothesis_key = ? AND stage IN (?, ?)",
                (
                    identity.analysis_id,
                    self._hypothesis_key(identity),
                    SimpleStage.POC_CANDIDATE_DONE.value,
                    SimpleStage.POC_EXECUTION_DONE.value,
                ),
            )
            self._upsert_checkpoint_connection(connection, pending)
            AgentActivityStore.append_connection(
                connection,
                self._lifecycle_event(
                    exhausted,
                    ActivityKind.DECISION_RECORDED,
                    sequence=self._stage_sequence(exhausted.stage, 102),
                    status=StageStatus.BLOCKED,
                    summary_ko=(
                        "검증된 PoC 추출 오류를 보존하고 후보만 한 번 다시 생성합니다."
                    ),
                    output_refs=(rule_ref,),
                    error_code="POC_EXTRACT_EXHAUSTION_REPLAYED",
                ),
            )
            if fail_before_commit:
                raise RuntimeError("simulated crash")
            connection.commit()
            return pending
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def prepare_poc_placeholder_exhaustion_replay(
        self,
        exhausted: StageCheckpoint,
        artifacts: SimpleArtifactRepository,
        *,
        fail_before_commit: bool = False,
    ) -> StageCheckpoint:
        """Explicitly replay one exact validator-blocked candidate after a code fix.

        No candidate or execution result exists for this attempt. The original
        validator failure, exhaustion, and LLM call history stay append-only.
        """

        identity = exhausted.identity
        if (
            identity.hypothesis_id is None
            or exhausted.stage is not SimpleStage.POC_CANDIDATE_DONE
            or exhausted.stage_version != STAGE_VERSION[exhausted.stage]
            or exhausted.status is not StageStatus.BLOCKED
            or exhausted.error_code != "RECOVERY_EXHAUSTED"
            or exhausted.retryable
            or exhausted.attempt_number != MAX_RECOVERY_ATTEMPTS
            or not exhausted.attempt_id
            or len(exhausted.output_refs) > 1
            or exhausted.input_hash != input_reference_hash(exhausted.input_refs)
            or exhausted.container_id is not None
            or exhausted.recipe_ref is None
            or exhausted.image_digest is None
            or exhausted.validated_poc_ref is not None
            or artifacts.identity != identity
            or artifacts.paths.database.resolve() != self._database_path.resolve()
        ):
            raise ValueError("POC_PLACEHOLDER_EXHAUSTION_INVALID")

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")

            def checkpoint_at(stage: SimpleStage) -> StageCheckpoint | None:
                row = connection.execute(
                    "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                    "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
                    (identity.analysis_id, self._hypothesis_key(identity), stage.value),
                ).fetchone()
                return (
                    StageCheckpoint.model_validate_json(row["checkpoint_json"])
                    if row is not None
                    else None
                )

            if checkpoint_at(SimpleStage.POC_CANDIDATE_DONE) != exhausted:
                raise ValueError("POC_PLACEHOLDER_EXHAUSTION_STALE")
            run_row = connection.execute(
                "SELECT run_json FROM simple_analysis_runs WHERE analysis_id = ?",
                (identity.analysis_id,),
            ).fetchone()
            if run_row is None:
                raise ValueError("POC_PLACEHOLDER_EXHAUSTION_RUN_INVALID")
            run = SimpleAnalysisRun.model_validate_json(run_row["run_json"])
            registered = identity.hypothesis_id in run.hypothesis_ids or (
                connection.execute(
                    "SELECT 1 FROM simple_candidate_hypotheses "
                    "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                    "AND hypothesis_id = ?",
                    (
                        identity.analysis_id,
                        identity.workspace_id,
                        identity.commit_id,
                        identity.hypothesis_id,
                    ),
                ).fetchone()
                is not None
            )
            if (
                run.workspace_id != identity.workspace_id
                or run.commit_id != identity.commit_id
                or run.candidate_pipeline_version != 2
                or run.candidate_terminal is not None
                or run.workspace_path is None
                or run.repository_profile_ref is None
                or run.static_bundle_ref is None
                or run.static_coverage_ref is None
                or run.candidate_scope_fingerprint is None
                or not registered
            ):
                raise ValueError("POC_PLACEHOLDER_EXHAUSTION_RUN_INVALID")
            root_identity = identity.model_copy(update={"hypothesis_id": None})
            static = self.get(root_identity, SimpleStage.STATIC_DONE)
            if (
                static is None
                or static.status is not StageStatus.SUCCEEDED
                or static.stage_version != STAGE_VERSION[SimpleStage.STATIC_DONE]
                or run.repository_profile_ref not in static.output_refs
                or run.static_bundle_ref not in static.output_refs
            ):
                raise ValueError("POC_PLACEHOLDER_EXHAUSTION_STATIC_INVALID")
            all_rows = connection.execute(
                "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                "WHERE analysis_id = ?",
                (identity.analysis_id,),
            ).fetchall()
            if any(
                StageCheckpoint.model_validate_json(row["checkpoint_json"]).status
                in {StageStatus.RUNNING, StageStatus.PENDING}
                for row in all_rows
            ):
                raise ValueError("POC_PLACEHOLDER_EXHAUSTION_RUN_ACTIVE")
            root = self.get(root_identity, SimpleStage.HYPOTHESIS_DONE)
            root_code = (
                "CANDIDATE_CHILD_ERROR_BOUND:RECOVERY_EXHAUSTED:"
                f"{identity.hypothesis_id}:{exhausted.attempt_id}"
            )
            if (
                root is None
                or root.stage_version != STAGE_VERSION[SimpleStage.HYPOTHESIS_DONE]
                or root.status is not StageStatus.BLOCKED
                or root.retryable
                or not root.attempt_id
                or root.error_code != root_code
            ):
                raise ValueError("POC_PLACEHOLDER_EXHAUSTION_ROOT_BOUND_INVALID")
            activity_rows = connection.execute(
                "SELECT event_json FROM agent_activity_events "
                "WHERE analysis_id = ? ORDER BY rowid",
                (identity.analysis_id,),
            ).fetchall()
            events = tuple(
                AgentActivityEvent.model_validate_json(row["event_json"])
                for row in activity_rows
            )
            if not any(
                event.kind is ActivityKind.STAGE_BLOCKED
                and event.analysis_id == identity.analysis_id
                and event.workspace_id == identity.workspace_id
                and event.commit_id == identity.commit_id
                and event.hypothesis_id is None
                and event.stage == SimpleStage.HYPOTHESIS_DONE.value
                and event.attempt_id == root.attempt_id
                and event.error_code == root_code
                for event in events
            ):
                raise ValueError("POC_PLACEHOLDER_EXHAUSTION_ROOT_BOUND_INVALID")
            replay_events = tuple(
                (index, event)
                for index, event in enumerate(events)
                if event.hypothesis_id == identity.hypothesis_id
                and event.kind is ActivityKind.DECISION_RECORDED
                and event.error_code == "POC_PLACEHOLDER_EXHAUSTION_REPLAYED"
            )
            seen_revisions: set[str] = set()
            seen_legacy = False
            prior_attempts: set[str] = set()
            last_replay_index = -1
            for event_index, replay_event in replay_events:
                if (
                    replay_event.analysis_id != identity.analysis_id
                    or replay_event.workspace_id != identity.workspace_id
                    or replay_event.commit_id != identity.commit_id
                    or replay_event.stage != SimpleStage.POC_CANDIDATE_DONE.value
                    or len(replay_event.output_refs) != 1
                    or replay_event.attempt_id in prior_attempts
                    or event_index <= last_replay_index
                ):
                    raise ValueError("POC_PLACEHOLDER_EXHAUSTION_MARKER_INVALID")
                try:
                    marker = json.loads(artifacts.read(replay_event.output_refs[0]))
                except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
                    raise ValueError(
                        "POC_PLACEHOLDER_EXHAUSTION_MARKER_INVALID"
                    ) from error
                if not isinstance(marker, dict):
                    raise ValueError("POC_PLACEHOLDER_EXHAUSTION_MARKER_INVALID")
                revision = marker.get("validator_revision")
                legacy_fields = {
                    "kind",
                    "identity",
                    "old_attempt_id",
                    "old_attempt_number",
                    "exhausted_checkpoint_hash",
                    "validator_error_event_id",
                    "reason",
                }
                if (
                    set(marker)
                    != (
                        legacy_fields
                        if revision is None
                        else legacy_fields | {"validator_revision"}
                    )
                    or marker.get("kind") != "simple_poc_placeholder_exhaustion_replay"
                    or marker.get("identity") != identity.model_dump(mode="json")
                    or marker.get("old_attempt_id") != replay_event.attempt_id
                    or marker.get("old_attempt_number") != MAX_RECOVERY_ATTEMPTS
                    or marker.get("reason")
                    != "POC_PLACEHOLDER_FORBIDDEN_AFTER_VALIDATOR_FIX"
                    or not isinstance(marker.get("exhausted_checkpoint_hash"), str)
                    or re.fullmatch(
                        r"[0-9a-f]{64}", marker["exhausted_checkpoint_hash"]
                    )
                    is None
                    or not isinstance(marker.get("validator_error_event_id"), str)
                    or replay_event.output_refs[0] not in exhausted.input_refs
                    or replay_event.attempt_id == exhausted.attempt_id
                    or revision is not None
                    and (not isinstance(revision, str) or not revision)
                ):
                    raise ValueError("POC_PLACEHOLDER_EXHAUSTION_MARKER_INVALID")
                if revision is None:
                    if seen_legacy:
                        raise ValueError("POC_PLACEHOLDER_EXHAUSTION_MARKER_INVALID")
                    seen_legacy = True
                elif revision in seen_revisions:
                    raise ValueError("POC_PLACEHOLDER_EXHAUSTION_MARKER_INVALID")
                else:
                    seen_revisions.add(revision)
                old_events = tuple(
                    event
                    for event in events[:event_index]
                    if event.hypothesis_id == identity.hypothesis_id
                    and event.stage == SimpleStage.POC_CANDIDATE_DONE.value
                    and event.attempt_id == replay_event.attempt_id
                )
                if (
                    len(old_events) != 3
                    or tuple((event.kind, event.error_code) for event in old_events)
                    != (
                        (ActivityKind.STAGE_STARTED, None),
                        (ActivityKind.STAGE_BLOCKED, "POC_PLACEHOLDER_FORBIDDEN"),
                        (ActivityKind.STAGE_BLOCKED, "RECOVERY_EXHAUSTED"),
                    )
                    or old_events[1].event_id != marker["validator_error_event_id"]
                    or any(
                        event.workspace_id != identity.workspace_id
                        or event.commit_id != identity.commit_id
                        or event.analysis_id != identity.analysis_id
                        for event in old_events
                    )
                ):
                    raise ValueError("POC_PLACEHOLDER_EXHAUSTION_MARKER_INVALID")
                prior_attempts.add(replay_event.attempt_id)
                last_replay_index = event_index
            if POC_CANDIDATE_VALIDATOR_REVISION in seen_revisions:
                raise ValueError("POC_PLACEHOLDER_EXHAUSTION_REVISION_ALREADY_REPLAYED")
            stage_events = tuple(
                event
                for event in events
                if event.hypothesis_id == identity.hypothesis_id
                and event.stage == SimpleStage.POC_CANDIDATE_DONE.value
                and event.attempt_id == exhausted.attempt_id
            )
            if (
                len(stage_events) != 3
                or tuple((event.kind, event.error_code) for event in stage_events)
                != (
                    (ActivityKind.STAGE_STARTED, None),
                    (ActivityKind.STAGE_BLOCKED, "POC_PLACEHOLDER_FORBIDDEN"),
                    (ActivityKind.STAGE_BLOCKED, "RECOVERY_EXHAUSTED"),
                )
                or any(
                    event.analysis_id != identity.analysis_id
                    or event.workspace_id != identity.workspace_id
                    or event.commit_id != identity.commit_id
                    or event.output_refs != exhausted.output_refs
                    and event.kind is not ActivityKind.STAGE_STARTED
                    or event.output_refs
                    and event.kind is ActivityKind.STAGE_STARTED
                    for event in stage_events
                )
                or next(
                    index
                    for index, event in enumerate(events)
                    if event is stage_events[0]
                )
                <= last_replay_index
            ):
                raise ValueError("POC_PLACEHOLDER_EXHAUSTION_EVENT_INVALID")
            if exhausted.output_refs:
                try:
                    diagnostic = json.loads(artifacts.read(exhausted.output_refs[0]))
                except (OSError, ValueError, TypeError, json.JSONDecodeError) as error:
                    raise ValueError(
                        "POC_PLACEHOLDER_EXHAUSTION_DIAGNOSTIC_INVALID"
                    ) from error
                numeric = (
                    "line_count",
                    "branch_count",
                    "inconclusive_line_count",
                    "exit_two_line_count",
                    "exit_zero_line_count",
                )
                if (
                    not isinstance(diagnostic, dict)
                    or set(diagnostic) != {"kind", "reason", *numeric}
                    or diagnostic.get("kind")
                    != "simple_poc_candidate_rejection_diagnostic"
                    or diagnostic.get("reason") != "INCONCLUSIVE_EXIT2_UNPROVEN"
                    or any(
                        type(diagnostic.get(field)) is not int or diagnostic[field] < 0
                        for field in numeric
                    )
                ):
                    raise ValueError("POC_PLACEHOLDER_EXHAUSTION_DIAGNOSTIC_INVALID")
            elif replay_events and not (len(replay_events) == 1 and seen_legacy):
                raise ValueError("POC_PLACEHOLDER_EXHAUSTION_DIAGNOSTIC_MISSING")
            unresolved = connection.execute(
                "SELECT 1 FROM simple_codex_calls WHERE analysis_id = ? "
                "AND (status = 'IN_FLIGHT' OR resolved_at IS NULL) LIMIT 1",
                (identity.analysis_id,),
            ).fetchone()
            unexited = connection.execute(
                "SELECT 1 FROM simple_codex_child_spawns WHERE analysis_id = ? "
                "AND (status != 'EXITED' OR pid IS NULL OR "
                "start_identity IS NULL OR start_identity = '') LIMIT 1",
                (identity.analysis_id,),
            ).fetchone()
            if unresolved is not None or unexited is not None:
                raise ValueError("POC_PLACEHOLDER_EXHAUSTION_CODEX_UNRESOLVED")
            pro_con = checkpoint_at(SimpleStage.PRO_CON_DONE)
            initial = checkpoint_at(SimpleStage.VERIFICATION_INITIAL_DONE)
            if (
                pro_con is None
                or pro_con.status is not StageStatus.SUCCEEDED
                or pro_con.stage_version != STAGE_VERSION[SimpleStage.PRO_CON_DONE]
                or initial is None
                or initial.status is not StageStatus.SUCCEEDED
                or initial.stage_version
                != STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE]
                or initial.recipe_ref != exhausted.recipe_ref
                or initial.image_digest != exhausted.image_digest
                or checkpoint_at(SimpleStage.POC_EXECUTION_DONE) is not None
                or any(
                    checkpoint_at(stage) is not None
                    for stage in STAGE_ORDER[
                        STAGE_ORDER.index(SimpleStage.VERIFICATION_FINAL_DONE) :
                    ]
                )
            ):
                raise ValueError("POC_PLACEHOLDER_EXHAUSTION_LINEAGE_INVALID")
            marker_ref = artifacts.put_json(
                {
                    "kind": "simple_poc_placeholder_exhaustion_replay",
                    "identity": identity.model_dump(mode="json"),
                    "old_attempt_id": exhausted.attempt_id,
                    "old_attempt_number": exhausted.attempt_number,
                    "exhausted_checkpoint_hash": hashlib.sha256(
                        canonical_bytes(exhausted.model_dump(mode="json"))
                    ).hexdigest(),
                    "validator_error_event_id": stage_events[1].event_id,
                    "reason": "POC_PLACEHOLDER_FORBIDDEN_AFTER_VALIDATOR_FIX",
                    "validator_revision": POC_CANDIDATE_VALIDATOR_REVISION,
                }
            )
            inputs = tuple(dict.fromkeys((*exhausted.input_refs, marker_ref)))
            pending = StageCheckpoint(
                identity=identity,
                stage=SimpleStage.POC_CANDIDATE_DONE,
                stage_version=STAGE_VERSION[SimpleStage.POC_CANDIDATE_DONE],
                status=StageStatus.PENDING,
                input_refs=inputs,
                input_hash=input_reference_hash(inputs),
                attempt_number=MAX_RECOVERY_ATTEMPTS - 1,
                gate_revision_count=exhausted.gate_revision_count,
                recovery_lineage_id=(
                    exhausted.recovery_lineage_id
                    or hashlib.sha256(
                        canonical_bytes(
                            {"identity": identity, "attempt_id": exhausted.attempt_id}
                        )
                    ).hexdigest()
                ),
                recovery_origin_stage=SimpleStage.POC_CANDIDATE_DONE,
                recovery_decision_refs=exhausted.recovery_decision_refs,
                recipe_ref=exhausted.recipe_ref,
                image_digest=exhausted.image_digest,
                container_id=None,
            )
            self._upsert_checkpoint_connection(connection, pending)
            AgentActivityStore.append_connection(
                connection,
                self._lifecycle_event(
                    exhausted,
                    ActivityKind.DECISION_RECORDED,
                    sequence=self._stage_sequence(exhausted.stage, 102),
                    status=StageStatus.BLOCKED,
                    summary_ko="검증기 오류 PoC 후보만 명시적으로 재실행합니다.",
                    output_refs=(marker_ref,),
                    error_code="POC_PLACEHOLDER_EXHAUSTION_REPLAYED",
                ),
            )
            if fail_before_commit:
                raise RuntimeError("simulated crash")
            connection.commit()
            return pending
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def prepare_poc_sensitive_content_replay(
        self,
        stopped: StageCheckpoint,
        artifacts: SimpleArtifactRepository,
        *,
        fail_before_commit: bool = False,
    ) -> StageCheckpoint:
        """Reopen one old sensitive-content STOP after diagnostic revision.

        This never reads or stores the rejected PoC. The two old, numeric-only
        diagnostics and recovery decisions must match the bound child exactly.
        """

        identity = stopped.identity
        if (
            identity.hypothesis_id is None
            or stopped.stage is not SimpleStage.POC_CANDIDATE_DONE
            or stopped.stage_version != STAGE_VERSION[stopped.stage]
            or stopped.status is not StageStatus.BLOCKED
            or stopped.error_code != "POC_SENSITIVE_CONTENT"
            or stopped.retryable
            or stopped.attempt_number != 2
            or not stopped.attempt_id
            or len(stopped.output_refs) != 1
            or stopped.input_hash != input_reference_hash(stopped.input_refs)
            or stopped.container_id is not None
            or stopped.recipe_ref is None
            or stopped.image_digest is None
            or stopped.validated_poc_ref is not None
            or artifacts.identity != identity
            or artifacts.paths.database.resolve() != self._database_path.resolve()
        ):
            raise ValueError("POC_SENSITIVE_CONTENT_REPLAY_INVALID")

        def old_diagnostic(ref: StoredDataRef) -> bool:
            try:
                value = json.loads(artifacts.read_bounded(ref, 4 * 1024))
            except (OSError, ValueError, TypeError) as error:
                raise ValueError(
                    "POC_SENSITIVE_CONTENT_REPLAY_DIAGNOSTIC_INVALID"
                ) from error
            fields = {
                "kind",
                "reason",
                "line_count",
                "branch_count",
                "inconclusive_line_count",
                "exit_two_line_count",
                "exit_zero_line_count",
            }
            return (
                isinstance(value, dict)
                and set(value) == fields
                and value.get("kind") == "simple_poc_candidate_rejection_diagnostic"
                and value.get("reason") == "SENSITIVE_CONTENT"
                and all(
                    type(value[field]) is int and value[field] >= 0
                    for field in fields - {"kind", "reason"}
                )
            )

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")

            def checkpoint_at(
                hypothesis_key: str, stage: SimpleStage
            ) -> StageCheckpoint | None:
                row = connection.execute(
                    "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                    "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
                    (identity.analysis_id, hypothesis_key, stage.value),
                ).fetchone()
                return (
                    StageCheckpoint.model_validate_json(row["checkpoint_json"])
                    if row is not None
                    else None
                )

            child_key = self._hypothesis_key(identity)
            if checkpoint_at(child_key, stopped.stage) != stopped:
                raise ValueError("POC_SENSITIVE_CONTENT_REPLAY_STALE")
            run_row = connection.execute(
                "SELECT run_json FROM simple_analysis_runs WHERE analysis_id = ?",
                (identity.analysis_id,),
            ).fetchone()
            if run_row is None:
                raise ValueError("POC_SENSITIVE_CONTENT_REPLAY_RUN_INVALID")
            run = SimpleAnalysisRun.model_validate_json(run_row["run_json"])
            registered = identity.hypothesis_id in run.hypothesis_ids or (
                connection.execute(
                    "SELECT 1 FROM simple_candidate_hypotheses "
                    "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                    "AND hypothesis_id = ?",
                    (
                        identity.analysis_id,
                        identity.workspace_id,
                        identity.commit_id,
                        identity.hypothesis_id,
                    ),
                ).fetchone()
                is not None
            )
            if (
                run.workspace_id != identity.workspace_id
                or run.commit_id != identity.commit_id
                or run.candidate_pipeline_version != 2
                or run.candidate_terminal is not None
                or run.workspace_path is None
                or run.repository_profile_ref is None
                or run.static_bundle_ref is None
                or run.static_coverage_ref is None
                or run.candidate_scope_fingerprint is None
                or not registered
            ):
                raise ValueError("POC_SENSITIVE_CONTENT_REPLAY_RUN_INVALID")
            root_key = self._hypothesis_key(
                identity.model_copy(update={"hypothesis_id": None})
            )
            static = checkpoint_at(root_key, SimpleStage.STATIC_DONE)
            if (
                static is None
                or static.status is not StageStatus.SUCCEEDED
                or static.stage_version != STAGE_VERSION[SimpleStage.STATIC_DONE]
                or run.repository_profile_ref not in static.output_refs
                or run.static_bundle_ref not in static.output_refs
            ):
                raise ValueError("POC_SENSITIVE_CONTENT_REPLAY_STATIC_INVALID")
            rows = connection.execute(
                "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                "WHERE analysis_id = ?",
                (identity.analysis_id,),
            ).fetchall()
            if any(
                StageCheckpoint.model_validate_json(row["checkpoint_json"]).status
                in {StageStatus.RUNNING, StageStatus.PENDING}
                for row in rows
            ):
                raise ValueError("POC_SENSITIVE_CONTENT_REPLAY_RUN_ACTIVE")
            root = checkpoint_at(root_key, SimpleStage.HYPOTHESIS_DONE)
            root_code = (
                "CANDIDATE_CHILD_ERROR_BOUND:POC_SENSITIVE_CONTENT:"
                f"{identity.hypothesis_id}:{stopped.attempt_id}"
            )
            if (
                root is None
                or root.stage_version != STAGE_VERSION[SimpleStage.HYPOTHESIS_DONE]
                or root.status is not StageStatus.BLOCKED
                or root.retryable
                or not root.attempt_id
                or root.error_code != root_code
            ):
                raise ValueError("POC_SENSITIVE_CONTENT_REPLAY_ROOT_BOUND_INVALID")
            events = tuple(
                AgentActivityEvent.model_validate_json(row["event_json"])
                for row in connection.execute(
                    "SELECT event_json FROM agent_activity_events "
                    "WHERE analysis_id = ? ORDER BY rowid",
                    (identity.analysis_id,),
                )
            )
            if any(
                event.hypothesis_id == identity.hypothesis_id
                and event.error_code == "POC_SENSITIVE_CONTENT_REPLAYED"
                for event in events
            ):
                raise ValueError("POC_SENSITIVE_CONTENT_REPLAY_ALREADY_REPLAYED")
            if not any(
                event.kind is ActivityKind.STAGE_BLOCKED
                and event.analysis_id == identity.analysis_id
                and event.workspace_id == identity.workspace_id
                and event.commit_id == identity.commit_id
                and event.hypothesis_id is None
                and event.stage == SimpleStage.HYPOTHESIS_DONE.value
                and event.attempt_id == root.attempt_id
                and event.error_code == root_code
                for event in events
            ):
                raise ValueError("POC_SENSITIVE_CONTENT_REPLAY_ROOT_BOUND_INVALID")
            attempts = tuple(
                event
                for event in events
                if event.hypothesis_id == identity.hypothesis_id
                and event.stage == SimpleStage.POC_CANDIDATE_DONE.value
                and event.kind
                in {
                    ActivityKind.STAGE_STARTED,
                    ActivityKind.STAGE_BLOCKED,
                    ActivityKind.DECISION_RECORDED,
                }
            )
            if len(attempts) != 6:
                raise ValueError("POC_SENSITIVE_CONTENT_REPLAY_EVENT_INVALID")
            first_attempt_evidence: tuple[StoredDataRef, ...] = ()
            for index, action in enumerate(("REGENERATE_INPUT", "STOP")):
                started, blocked, decision = attempts[index * 3 : index * 3 + 3]
                attempt_id = started.attempt_id
                if (
                    not attempt_id
                    or (index == 1 and attempt_id != stopped.attempt_id)
                    or (index == 0 and attempt_id == stopped.attempt_id)
                    or tuple(event.kind for event in (started, blocked, decision))
                    != (
                        ActivityKind.STAGE_STARTED,
                        ActivityKind.STAGE_BLOCKED,
                        ActivityKind.DECISION_RECORDED,
                    )
                    or started.output_refs
                    or (index == 1 and blocked.output_refs != stopped.output_refs)
                    or (
                        index == 1
                        and any(
                            ref not in stopped.input_refs
                            for ref in first_attempt_evidence
                        )
                    )
                    or len(blocked.output_refs) != 1
                    or len(decision.output_refs) != 1
                    or any(
                        event.analysis_id != identity.analysis_id
                        or event.workspace_id != identity.workspace_id
                        or event.commit_id != identity.commit_id
                        or event.attempt_id != attempt_id
                        for event in (started, blocked, decision)
                    )
                    or blocked.error_code != "POC_SENSITIVE_CONTENT"
                    or decision.error_code != "POC_SENSITIVE_CONTENT"
                    or not old_diagnostic(blocked.output_refs[0])
                ):
                    raise ValueError("POC_SENSITIVE_CONTENT_REPLAY_EVENT_INVALID")
                try:
                    recovery = json.loads(
                        artifacts.read_bounded(decision.output_refs[0], 64 * 1024)
                    )
                except (OSError, ValueError, TypeError) as error:
                    raise ValueError(
                        "POC_SENSITIVE_CONTENT_REPLAY_DECISION_INVALID"
                    ) from error
                decision_body = (
                    recovery.get("decision") if isinstance(recovery, dict) else None
                )
                original = (
                    recovery.get("original_error")
                    if isinstance(recovery, dict)
                    else None
                )
                if (
                    not isinstance(recovery, dict)
                    or recovery.get("kind") != "simple_recovery_decision"
                    or recovery.get("identity") != identity.model_dump(mode="json")
                    or recovery.get("stage") != stopped.stage.value
                    or recovery.get("attempt") != index + 1
                    or recovery.get("attempt_id") != attempt_id
                    or not isinstance(decision_body, dict)
                    or decision_body.get("action") != action
                    or decision_body.get("category") != "GENERATED_INPUT"
                    or not isinstance(original, dict)
                    or original.get("code") != "POC_SENSITIVE_CONTENT"
                    or original.get("evidence_refs")
                    != [blocked.output_refs[0].model_dump(mode="json")]
                ):
                    raise ValueError("POC_SENSITIVE_CONTENT_REPLAY_DECISION_INVALID")
                if index == 0:
                    first_attempt_evidence = (
                        blocked.output_refs[0],
                        decision.output_refs[0],
                    )
            unresolved = connection.execute(
                "SELECT 1 FROM simple_codex_calls WHERE analysis_id = ? "
                "AND (status = 'IN_FLIGHT' OR resolved_at IS NULL) LIMIT 1",
                (identity.analysis_id,),
            ).fetchone()
            unexited = connection.execute(
                "SELECT 1 FROM simple_codex_child_spawns WHERE analysis_id = ? "
                "AND (status != 'EXITED' OR pid IS NULL OR "
                "start_identity IS NULL OR start_identity = '') LIMIT 1",
                (identity.analysis_id,),
            ).fetchone()
            if unresolved is not None or unexited is not None:
                raise ValueError("POC_SENSITIVE_CONTENT_REPLAY_CODEX_UNRESOLVED")
            pro_con = checkpoint_at(child_key, SimpleStage.PRO_CON_DONE)
            initial = checkpoint_at(child_key, SimpleStage.VERIFICATION_INITIAL_DONE)
            if (
                pro_con is None
                or pro_con.status is not StageStatus.SUCCEEDED
                or pro_con.stage_version != STAGE_VERSION[SimpleStage.PRO_CON_DONE]
                or initial is None
                or initial.status is not StageStatus.SUCCEEDED
                or initial.stage_version
                != STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE]
                or initial.recipe_ref != stopped.recipe_ref
                or initial.image_digest != stopped.image_digest
                or any(
                    checkpoint_at(child_key, stage) is not None
                    for stage in STAGE_ORDER[
                        STAGE_ORDER.index(SimpleStage.POC_EXECUTION_DONE) :
                    ]
                )
            ):
                raise ValueError("POC_SENSITIVE_CONTENT_REPLAY_LINEAGE_INVALID")
            marker_ref = artifacts.put_json(
                {
                    "kind": "simple_poc_sensitive_content_replay",
                    "identity": identity.model_dump(mode="json"),
                    "old_attempt_id": stopped.attempt_id,
                    "old_attempt_number": stopped.attempt_number,
                    "old_checkpoint_hash": hashlib.sha256(
                        canonical_bytes(stopped.model_dump(mode="json"))
                    ).hexdigest(),
                    "validator_revision": POC_CANDIDATE_VALIDATOR_REVISION,
                }
            )
            inputs = tuple(dict.fromkeys((*stopped.input_refs, marker_ref)))
            pending = StageCheckpoint(
                identity=identity,
                stage=SimpleStage.POC_CANDIDATE_DONE,
                stage_version=STAGE_VERSION[SimpleStage.POC_CANDIDATE_DONE],
                status=StageStatus.PENDING,
                input_refs=inputs,
                input_hash=input_reference_hash(inputs),
                attempt_number=2,
                gate_revision_count=stopped.gate_revision_count,
                recovery_lineage_id=(
                    stopped.recovery_lineage_id
                    or hashlib.sha256(
                        canonical_bytes(
                            {"identity": identity, "attempt_id": stopped.attempt_id}
                        )
                    ).hexdigest()
                ),
                recovery_origin_stage=SimpleStage.POC_CANDIDATE_DONE,
                recovery_decision_refs=stopped.recovery_decision_refs,
                recipe_ref=stopped.recipe_ref,
                image_digest=stopped.image_digest,
            )
            self._upsert_checkpoint_connection(connection, pending)
            AgentActivityStore.append_connection(
                connection,
                self._lifecycle_event(
                    stopped,
                    ActivityKind.DECISION_RECORDED,
                    sequence=self._stage_sequence(stopped.stage, 102),
                    status=StageStatus.BLOCKED,
                    summary_ko="기존 민감도 검사로 차단된 PoC 후보만 재검증합니다.",
                    output_refs=(marker_ref,),
                    error_code="POC_SENSITIVE_CONTENT_REPLAYED",
                ),
            )
            if fail_before_commit:
                raise RuntimeError("simulated crash")
            connection.commit()
            return pending
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _prepare_fallback_poc_stop_replan(
        self,
        stopped: StageCheckpoint,
        artifacts: SimpleArtifactRepository,
        *,
        mode: Literal["import", "generated_input"],
        fail_before_commit: bool,
    ) -> StageCheckpoint:
        """Supersede one evidence-bound PoC STOP under the caller's lease.

        The old checkpoint, STOP event, and LLM/usage records remain in their
        append-only ledgers. Only this child's mutable stage checkpoints are
        reseeded; the exact old checkpoint is compared under BEGIN IMMEDIATE.
        """

        identity = stopped.identity
        if (
            identity.hypothesis_id is None
            or stopped.stage is not SimpleStage.POC_EXECUTION_DONE
            or stopped.stage_version != STAGE_VERSION[stopped.stage]
            or stopped.status is not StageStatus.BLOCKED
            or stopped.error_code
            not in (
                {"POC_EXECUTION_FAILED", "POC_RUNTIME_IMPORT_FAILED"}
                if mode == "import"
                else {"POC_EXECUTION_FAILED"}
            )
            or stopped.retryable
            or stopped.attempt_id is None
            or not 1 <= stopped.attempt_number < MAX_RECOVERY_ATTEMPTS
            or len(stopped.output_refs) != 4
            or stopped.recipe_ref is None
            or stopped.validated_poc_ref is not None
            or artifacts.identity != identity
            or artifacts.paths.database.resolve() != self._database_path.resolve()
        ):
            raise ValueError("LEGACY_IMPORT_STOP_INVALID")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")

            def checkpoint_at(stage: SimpleStage) -> StageCheckpoint | None:
                row = connection.execute(
                    "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                    "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
                    (identity.analysis_id, self._hypothesis_key(identity), stage.value),
                ).fetchone()
                return (
                    StageCheckpoint.model_validate_json(row["checkpoint_json"])
                    if row is not None
                    else None
                )

            if checkpoint_at(stopped.stage) != stopped:
                raise ValueError("LEGACY_IMPORT_STOP_STALE")
            run_row = connection.execute(
                "SELECT run_json FROM simple_analysis_runs WHERE analysis_id = ?",
                (identity.analysis_id,),
            ).fetchone()
            if run_row is None:
                raise ValueError("LEGACY_IMPORT_STOP_RUN_INVALID")
            run = SimpleAnalysisRun.model_validate_json(run_row["run_json"])
            registered = identity.hypothesis_id in run.hypothesis_ids or (
                connection.execute(
                    "SELECT 1 FROM simple_candidate_hypotheses "
                    "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                    "AND hypothesis_id = ?",
                    (
                        identity.analysis_id,
                        identity.workspace_id,
                        identity.commit_id,
                        identity.hypothesis_id,
                    ),
                ).fetchone()
                is not None
            )
            if (
                run.workspace_id != identity.workspace_id
                or run.commit_id != identity.commit_id
                or run.candidate_pipeline_version != 2
                or run.candidate_terminal is not None
                or run.workspace_path is None
                or run.repository_profile_ref is None
                or run.static_bundle_ref is None
                or run.static_coverage_ref is None
                or run.candidate_scope_fingerprint is None
                or not registered
            ):
                raise ValueError("LEGACY_IMPORT_STOP_RUN_INVALID")
            root_identity = identity.model_copy(update={"hypothesis_id": None})
            static_row = connection.execute(
                "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                "WHERE analysis_id = ? AND hypothesis_key = '' AND stage = ?",
                (identity.analysis_id, SimpleStage.STATIC_DONE.value),
            ).fetchone()
            static_checkpoint = (
                StageCheckpoint.model_validate_json(static_row["checkpoint_json"])
                if static_row is not None
                else None
            )
            if (
                static_checkpoint is None
                or static_checkpoint.identity != root_identity
                or static_checkpoint.status is not StageStatus.SUCCEEDED
                or static_checkpoint.stage_version
                != STAGE_VERSION[SimpleStage.STATIC_DONE]
                or run.repository_profile_ref not in static_checkpoint.output_refs
                or run.static_bundle_ref not in static_checkpoint.output_refs
                or any(
                    str(ref.workspace_id) != identity.workspace_id
                    or str(ref.commit_id) != identity.commit_id
                    for ref in (
                        run.repository_profile_ref,
                        run.static_bundle_ref,
                        run.static_coverage_ref,
                    )
                )
            ):
                raise ValueError("LEGACY_IMPORT_STOP_RUN_INVALID")
            analysis_rows = connection.execute(
                "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                "WHERE analysis_id = ?",
                (identity.analysis_id,),
            ).fetchall()
            if any(
                StageCheckpoint.model_validate_json(row["checkpoint_json"]).status
                in {StageStatus.RUNNING, StageStatus.PENDING}
                for row in analysis_rows
            ):
                raise ValueError("LEGACY_IMPORT_STOP_RUN_ACTIVE")
            root_row = connection.execute(
                "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                "WHERE analysis_id = ? AND hypothesis_key = '' AND stage = ?",
                (identity.analysis_id, SimpleStage.HYPOTHESIS_DONE.value),
            ).fetchone()
            root = (
                StageCheckpoint.model_validate_json(root_row["checkpoint_json"])
                if root_row is not None
                else None
            )
            expected_root_code = (
                f"CANDIDATE_CHILD_ERROR_BOUND:{stopped.error_code}:"
                f"{identity.hypothesis_id}:{stopped.attempt_id}"
            )
            if (
                root is None
                or root.identity != root_identity
                or root.stage is not SimpleStage.HYPOTHESIS_DONE
                or root.status is not StageStatus.BLOCKED
                or root.retryable
                or root.attempt_id is None
                or root.error_code != expected_root_code
            ):
                raise ValueError("LEGACY_IMPORT_STOP_ROOT_BOUND_INVALID")
            root_events = connection.execute(
                "SELECT event_json FROM agent_activity_events "
                "WHERE analysis_id = ? AND hypothesis_key = '' AND attempt_id = ?",
                (identity.analysis_id, root.attempt_id),
            ).fetchall()
            if not any(
                (
                    event := AgentActivityEvent.model_validate_json(row["event_json"])
                ).kind
                is ActivityKind.STAGE_BLOCKED
                and event.stage == root.stage.value
                and event.analysis_id == identity.analysis_id
                and event.workspace_id == identity.workspace_id
                and event.commit_id == identity.commit_id
                and event.hypothesis_id is None
                and event.error_code == expected_root_code
                for row in root_events
            ):
                raise ValueError("LEGACY_IMPORT_STOP_ROOT_BOUND_INVALID")
            unresolved = connection.execute(
                "SELECT 1 FROM simple_codex_calls WHERE analysis_id = ? "
                "AND (status = 'IN_FLIGHT' OR resolved_at IS NULL) LIMIT 1",
                (identity.analysis_id,),
            ).fetchone()
            if unresolved is not None:
                raise ValueError("LEGACY_IMPORT_STOP_CODEX_UNRESOLVED")
            unexited = connection.execute(
                "SELECT 1 FROM simple_codex_child_spawns WHERE analysis_id = ? "
                "AND (status != 'EXITED' OR pid IS NULL OR "
                "start_identity IS NULL OR start_identity = '') LIMIT 1",
                (identity.analysis_id,),
            ).fetchone()
            if unexited is not None:
                raise ValueError("LEGACY_IMPORT_STOP_CODEX_CLEANUP_UNCONFIRMED")

            pro_con = checkpoint_at(SimpleStage.PRO_CON_DONE)
            initial = checkpoint_at(SimpleStage.VERIFICATION_INITIAL_DONE)
            candidate = checkpoint_at(SimpleStage.POC_CANDIDATE_DONE)
            if (
                pro_con is None
                or pro_con.status is not StageStatus.SUCCEEDED
                or pro_con.stage_version != STAGE_VERSION[pro_con.stage]
                or initial is None
                or initial.status is not StageStatus.SUCCEEDED
                or initial.stage_version != STAGE_VERSION[initial.stage]
                or initial.recipe_ref != stopped.recipe_ref
                or candidate is None
                or candidate.status is not StageStatus.SUCCEEDED
                or candidate.stage_version != STAGE_VERSION[candidate.stage]
                or candidate.attempt_id != stopped.attempt_id
                or candidate.attempt_number != stopped.attempt_number
                or candidate.recipe_ref != stopped.recipe_ref
                or len(candidate.output_refs) < 2
                or not candidate.image_digest
                or initial.image_digest != candidate.image_digest
                or stopped.image_digest != candidate.image_digest
                or any(
                    ref not in stopped.input_refs for ref in candidate.output_refs[:2]
                )
                or (
                    mode == "generated_input"
                    and (
                        candidate.image_digest != stopped.image_digest
                        or candidate.gate_revision_count != stopped.gate_revision_count
                        or candidate.output_refs[0] not in stopped.input_refs
                        or stopped.gate_revision_count > 0
                        and not candidate.input_refs
                    )
                )
                or any(
                    checkpoint_at(stage) is not None
                    for stage in STAGE_ORDER[
                        STAGE_ORDER.index(SimpleStage.VERIFICATION_FINAL_DONE) :
                    ]
                )
            ):
                raise ValueError("LEGACY_IMPORT_STOP_LINEAGE_INVALID")

            execution_ref, stdout_ref, stderr_ref, cleanup_ref = stopped.output_refs
            try:
                candidate_record = json.loads(
                    artifacts.read_bounded(candidate.output_refs[0], 64 * 1024)
                )
                candidate_content = artifacts.read_bounded(
                    candidate.output_refs[1], 1024 * 1024
                )
                execution = json.loads(artifacts.read_bounded(execution_ref, 64 * 1024))
                cleanup = json.loads(artifacts.read_bounded(cleanup_ref, 64 * 1024))
                stderr = artifacts.read_bounded(stderr_ref, 1024 * 1024)
                stdout = artifacts.read_bounded(stdout_ref, 1024 * 1024)
            except (OSError, ValueError, TypeError, sqlite3.Error) as error:
                raise ValueError("LEGACY_IMPORT_STOP_EVIDENCE_INVALID") from error
            if (
                not isinstance(candidate_record, dict)
                or candidate_record.get("kind") != "simple_poc_candidate"
                or candidate_record.get("attempt_id") != stopped.attempt_id
                or candidate_record.get("content_ref")
                != candidate.output_refs[1].model_dump(mode="json")
                or candidate_record.get("content_digest")
                != hashlib.sha256(candidate_content).hexdigest()
                or not isinstance(execution, dict)
                or execution.get("kind") != "simple_poc_execution"
                or execution.get("attempt_id") != stopped.attempt_id
                or not isinstance(execution.get("container_id"), str)
                or not execution["container_id"]
                or execution.get("candidate_ref")
                != candidate.output_refs[0].model_dump(mode="json")
                or execution.get("content_ref")
                != candidate.output_refs[1].model_dump(mode="json")
                or execution.get("image_digest") != candidate.image_digest
                or execution.get("stdout_ref") != stdout_ref.model_dump(mode="json")
                or execution.get("stderr_ref") != stderr_ref.model_dump(mode="json")
                or execution.get("timed_out") is not False
                or type(execution.get("exit_code")) is not int
                or execution.get("exit_code") != 2
                or not isinstance(cleanup, dict)
                or cleanup.get("kind") != "simple_container_cleanup"
                or cleanup.get("attempt_id") != stopped.attempt_id
                or cleanup.get("container_id") != execution["container_id"]
                or cleanup.get("status") != "REMOVED"
            ):
                raise ValueError("LEGACY_IMPORT_STOP_EVIDENCE_INVALID")
            import_matches: dict[bytes, bytes] = {}
            if mode == "import":
                nonterminal_import = False
                for stream in (stderr, stdout):
                    matches, terminal = _python_import_traceback_spans(stream)
                    if stream.strip() and not matches:
                        raise ValueError("LEGACY_IMPORT_STOP_IMPORT_UNVERIFIED")
                    nonterminal_import |= bool(matches) and not terminal
                    for name, span in matches.items():
                        import_matches.setdefault(name, span)
                if len(import_matches) != 1 or nonterminal_import:
                    raise ValueError("LEGACY_IMPORT_STOP_IMPORT_UNVERIFIED")
            elif (
                not stderr.strip()
                or has_python_import_failure(stderr)
                or has_python_import_failure(stdout)
            ):
                raise ValueError("LEGACY_IMPORT_STOP_DIAGNOSTIC_INVALID")

            stop_ref: StoredDataRef | None = None
            rows = connection.execute(
                "SELECT event_json FROM agent_activity_events WHERE analysis_id = ? "
                "AND hypothesis_key = ? AND attempt_id = ?",
                (
                    identity.analysis_id,
                    self._hypothesis_key(identity),
                    stopped.attempt_id,
                ),
            ).fetchall()
            for row in rows:
                event = AgentActivityEvent.model_validate_json(row["event_json"])
                if (
                    event.kind is not ActivityKind.DECISION_RECORDED
                    or event.stage != stopped.stage.value
                    or event.analysis_id != identity.analysis_id
                    or event.workspace_id != identity.workspace_id
                    or event.commit_id != identity.commit_id
                    or event.hypothesis_id != identity.hypothesis_id
                    or event.attempt_id != stopped.attempt_id
                    or event.error_code != stopped.error_code
                    or len(event.output_refs) != 1
                ):
                    continue
                ref = event.output_refs[0]
                try:
                    value = json.loads(artifacts.read_bounded(ref, 64 * 1024))
                    original = StageFailure.model_validate_json(
                        canonical_bytes(value["original_error"])
                    )
                    decision = RecoveryDecision.model_validate_json(
                        canonical_bytes(value["decision"])
                    )
                except (OSError, ValueError, TypeError, KeyError, sqlite3.Error):
                    continue
                if (
                    value.get("kind") == "simple_recovery_decision"
                    and value.get("identity") == identity.model_dump(mode="json")
                    and value.get("stage") == stopped.stage.value
                    and value.get("attempt") == stopped.attempt_number
                    and value.get("attempt_id") == stopped.attempt_id
                    and value.get("decision_origin")
                    == (
                        "RULE"
                        if stopped.error_code == "POC_RUNTIME_IMPORT_FAILED"
                        else "FALLBACK"
                    )
                    and original.code == stopped.error_code
                    and original.retryable
                    and original.evidence_refs == stopped.output_refs
                    and decision.category is RecoveryCategory.TERMINAL
                    and decision.action is RecoveryAction.STOP
                    and decision.environment_patch == ""
                    and (decision.diagnosis, decision.guidance)
                    == (
                        (
                            "Python import failure lacks isolated terminal evidence",
                            "Review both exact PoC output streams; automatic "
                            "dependency selection and Dockerfile patching are "
                            "not justified",
                        )
                        if stopped.error_code == "POC_RUNTIME_IMPORT_FAILED"
                        else (
                            "recovery output failed policy validation",
                            "preserve the failure for manual review",
                        )
                    )
                ):
                    if stop_ref is not None:
                        raise ValueError("LEGACY_IMPORT_STOP_DECISION_AMBIGUOUS")
                    stop_ref = ref
            if stop_ref is None:
                raise ValueError("LEGACY_IMPORT_STOP_FALLBACK_UNVERIFIED")

            try:
                diagnostic = (
                    next(iter(import_matches.values())) if mode == "import" else stderr
                )
                excerpt = (
                    diagnostic[:4_096] if mode == "import" else diagnostic[-4_096:]
                )
                safe_bytes = redact_untrusted_text(excerpt).data
                if (
                    not safe_bytes
                    or len(safe_bytes) > 4 * 1024
                    or redact_untrusted_text(safe_bytes).data != safe_bytes
                ):
                    raise ValueError("unusable diagnostic")
                safe_diagnostic = safe_bytes.decode("utf-8", errors="replace")
            except ValueError as error:
                raise ValueError("LEGACY_IMPORT_STOP_DIAGNOSTIC_INVALID") from error
            if not safe_diagnostic.strip():
                raise ValueError("LEGACY_IMPORT_STOP_DIAGNOSTIC_INVALID")
            if mode == "import":
                rule_decision = RecoveryDecision(
                    category=RecoveryCategory.ENVIRONMENT,
                    action=RecoveryAction.REPLAN_ENVIRONMENT,
                    diagnosis="Isolated Python runtime could not import a module",
                    guidance=(
                        "Revisit pinned source imports and dependency evidence; "
                        "include only a supported explicit pip requirement."
                    ),
                )
                original_error = StageFailure(
                    code="POC_RUNTIME_IMPORT_FAILED",
                    retryable=True,
                    safe_message="Verified import failure needs environment replanning",
                    evidence_refs=stopped.output_refs,
                )
            else:
                rule_decision = RecoveryDecision(
                    category=RecoveryCategory.GENERATED_INPUT,
                    action=RecoveryAction.REGENERATE_INPUT,
                    diagnosis="PoC script exited with a non-import runtime error",
                    guidance=(
                        "Correct only the PoC harness or fixtures using the "
                        "pinned execution evidence. Preserve source behavior, "
                        "the prepared recipe, and declared dependencies; do not "
                        "monkeypatch the vulnerable path or claim reproduction "
                        "from a runtime error."
                    ),
                )
                original_error = StageFailure(
                    code="POC_EXECUTION_FAILED",
                    retryable=True,
                    safe_message="PoC script exited with a runtime error",
                    evidence_refs=stopped.output_refs,
                )
            rule_ref = artifacts.put_json(
                {
                    "kind": "simple_recovery_decision",
                    "identity": identity.model_dump(mode="json"),
                    "stage": stopped.stage.value,
                    "attempt": stopped.attempt_number,
                    "attempt_id": stopped.attempt_id,
                    "original_error": original_error.model_dump(mode="json"),
                    "decision": rule_decision.model_dump(mode="json"),
                    "decision_origin": "RULE",
                    "diagnostic_excerpt": safe_diagnostic,
                    "supersedes_stop_ref": stop_ref.model_dump(mode="json"),
                    "supersedes_checkpoint_hash": hashlib.sha256(
                        canonical_bytes(stopped.model_dump(mode="json"))
                    ).hexdigest(),
                }
            )
            decision_refs = tuple(
                dict.fromkeys((*stopped.recovery_decision_refs, stop_ref, rule_ref))
            )
            gate_feedback = (
                (candidate.input_refs[0],)
                if mode == "generated_input" and stopped.gate_revision_count > 0
                else ()
            )
            inputs = tuple(
                dict.fromkeys(
                    (
                        *gate_feedback,
                        *initial.input_refs,
                        *initial.output_refs,
                        *candidate.input_refs,
                        *candidate.output_refs,
                        *stopped.input_refs,
                        *stopped.output_refs,
                        *decision_refs,
                    )
                )
            )
            lineage_id = (
                stopped.recovery_lineage_id
                or hashlib.sha256(
                    canonical_bytes(
                        {
                            "identity": identity,
                            "attempt_id": stopped.attempt_id,
                            "error_code": stopped.error_code,
                        }
                    )
                ).hexdigest()
            )
            restart_stage = (
                SimpleStage.VERIFICATION_INITIAL_DONE
                if mode == "import"
                else SimpleStage.POC_CANDIDATE_DONE
            )
            pending = StageCheckpoint(
                identity=identity,
                stage=restart_stage,
                stage_version=STAGE_VERSION[restart_stage],
                status=StageStatus.PENDING,
                input_refs=inputs,
                input_hash=input_reference_hash(inputs),
                attempt_number=stopped.attempt_number,
                gate_revision_count=stopped.gate_revision_count,
                recovery_lineage_id=lineage_id,
                recovery_origin_stage=SimpleStage.POC_EXECUTION_DONE,
                recovery_decision_refs=decision_refs,
                recipe_ref=(stopped.recipe_ref if mode == "generated_input" else None),
                image_digest=(
                    stopped.image_digest if mode == "generated_input" else None
                ),
            )
            AgentActivityStore.append_connection(
                connection,
                self._recovery_event(
                    connection,
                    stopped,
                    RecoveryResolution(decision=rule_decision, decision_ref=rule_ref),
                ),
            )
            stages = tuple(
                stage.value for stage in STAGE_ORDER[STAGE_ORDER.index(restart_stage) :]
            )
            placeholders = ",".join("?" for _ in stages)
            connection.execute(
                f"DELETE FROM simple_runtime_checkpoints WHERE analysis_id = ? "
                f"AND hypothesis_key = ? AND stage IN ({placeholders})",  # noqa: S608
                (identity.analysis_id, self._hypothesis_key(identity), *stages),
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
    ) -> StageCheckpoint:
        if resolution.decision.action is not RecoveryAction.STOP:
            raise ValueError("RECOVERY_STOP_ACTION_REQUIRED")
        stopped = failed.model_copy(
            update={
                "retryable": False,
                "updated_at": datetime.now(UTC),
            }
        )
        self.record_recovery_decision(
            stopped,
            resolution,
            fail_before_commit=fail_before_commit,
        )
        return stopped

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

    def promote_initial_environment_inconclusive(
        self,
        blocked: StageCheckpoint,
        *,
        artifacts: SimpleArtifactRepository,
    ) -> StageCheckpoint:
        """Atomically terminalize an exact non-retryable resolver incompatibility.

        The method only upgrades immutable evidence that was already linked to
        the failed initial-verification checkpoint.  It does not create or alter
        an Agent result, and it leaves every other recovery STOP blocked.
        """

        if (
            blocked.stage is not SimpleStage.VERIFICATION_INITIAL_DONE
            or blocked.stage_version
            != STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE]
            or blocked.status is not StageStatus.BLOCKED
            or blocked.error_code
            not in {"POC_AUTO_BUNDLE_DOWNLOAD_FAILED", "RECOVERY_EXHAUSTED"}
            or blocked.attempt_id is None
            or blocked.attempt_number < 1
            or blocked.recipe_ref is not None
            or blocked.validated_poc_ref is not None
            or blocked.external_prerequisites_ref is not None
            or blocked.environment_block_ref is not None
            or artifacts.identity != blocked.identity
        ):
            raise ValueError("INITIAL_ENVIRONMENT_INCONCLUSIVE_PROMOTION_INVALID")
        environment_block_ref = (
            artifacts.build_initial_environment_block_from_checkpoint(blocked)
        )
        if environment_block_ref is None:
            raise ValueError("INITIAL_ENVIRONMENT_INCONCLUSIVE_EVIDENCE_INVALID")
        completed = blocked.model_copy(
            update={
                "status": StageStatus.SUCCEEDED,
                "output_refs": tuple(
                    dict.fromkeys((*blocked.output_refs, environment_block_ref))
                ),
                "environment_block_ref": environment_block_ref,
                "verdict": "HOLD",
                "error_code": None,
                "retryable": False,
                "updated_at": datetime.now(UTC),
            }
        )
        if artifacts.verified_terminal_initial_outcome(completed) is None:
            raise ValueError("INITIAL_ENVIRONMENT_INCONCLUSIVE_EVIDENCE_INVALID")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
                (
                    blocked.identity.analysis_id,
                    self._hypothesis_key(blocked.identity),
                    blocked.stage.value,
                ),
            ).fetchone()
            if (
                row is None
                or StageCheckpoint.model_validate_json(row["checkpoint_json"])
                != blocked
            ):
                raise ValueError("INITIAL_ENVIRONMENT_INCONCLUSIVE_PROMOTION_STALE")
            self._upsert_checkpoint_connection(connection, completed)
            AgentActivityStore.append_connection(
                connection,
                self._lifecycle_event(
                    completed,
                    ActivityKind.STAGE_COMPLETED,
                    sequence=self._stage_sequence(completed.stage, 2),
                    status=StageStatus.SUCCEEDED,
                    summary_ko=(
                        "고정된 Python 배포본의 재현 환경 비호환을 "
                        "검증된 미확정 상태로 기록했습니다."
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

    def promote_inconclusive_execution(
        self,
        exhausted: StageCheckpoint,
        *,
        artifacts: SimpleArtifactRepository | None = None,
    ) -> StageCheckpoint:
        """Atomically preserve an executed, evidence-checked PoC as non-reportable."""

        exhausted_attempts = (
            exhausted.error_code == "RECOVERY_EXHAUSTED"
            and exhausted.attempt_number >= MAX_RECOVERY_ATTEMPTS
        )
        stopped_inconclusive = (
            exhausted.error_code == "POC_INCONCLUSIVE"
            and exhausted.attempt_number >= 1
            and artifacts is not None
            and artifacts.identity == exhausted.identity
        )
        if (
            exhausted.stage is not SimpleStage.POC_EXECUTION_DONE
            or exhausted.stage_version != STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE]
            or exhausted.status is not StageStatus.BLOCKED
            or not (exhausted_attempts or stopped_inconclusive)
            or len(exhausted.output_refs) != 2
            or exhausted.validated_poc_ref is not None
        ):
            raise ValueError("POC_INCONCLUSIVE_PROMOTION_INVALID")
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
            stop_ref = None
            if stopped_inconclusive:
                assert artifacts is not None
                stop_ref = self._verified_inconclusive_stop(
                    connection, exhausted, artifacts
                )
                if stop_ref is None:
                    raise ValueError("POC_INCONCLUSIVE_STOP_UNVERIFIED")
            completed = exhausted.model_copy(
                update={
                    "status": StageStatus.SUCCEEDED,
                    "verdict": "HOLD",
                    "error_code": None,
                    "retryable": False,
                    "poc_stop_decision_ref": stop_ref,
                    "updated_at": datetime.now(UTC),
                }
            )
            self._upsert_checkpoint_connection(connection, completed)
            AgentActivityStore.append_connection(
                connection,
                self._lifecycle_event(
                    completed,
                    ActivityKind.STAGE_COMPLETED,
                    sequence=self._stage_sequence(completed.stage, 2),
                    status=StageStatus.SUCCEEDED,
                    summary_ko=(
                        "완료된 PoC 실행의 근거 부족과 복구 중단 결정을 미확정으로 "
                        "기록했습니다."
                        if stop_ref is not None
                        else (
                            "완료된 PoC 실행의 반복된 근거 부족을 "
                            "미확정으로 기록했습니다."
                        )
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

    def _verified_inconclusive_stop(
        self,
        connection: sqlite3.Connection,
        checkpoint: StageCheckpoint,
        artifacts: SimpleArtifactRepository,
    ) -> StoredDataRef | None:
        """Require linked execution, interpretation and append-only STOP evidence."""

        if checkpoint.attempt_id is None:
            return None
        execution_ref, interpretation_ref = checkpoint.output_refs
        try:
            execution = json.loads(artifacts.read(execution_ref))
            interpretation = json.loads(artifacts.read(interpretation_ref))
        except (OSError, ValueError, TypeError, sqlite3.Error):
            return None
        if not isinstance(execution, dict) or not isinstance(interpretation, dict):
            return None
        result = interpretation.get("result")
        if (
            execution.get("kind") != "simple_poc_execution"
            or execution.get("attempt_id") != checkpoint.attempt_id
            or execution.get("timed_out") is not False
            or type(execution.get("exit_code")) is not int
            or execution.get("exit_code") != 0
            or interpretation.get("kind") != "simple_dynamic_interpretation"
            or interpretation.get("execution_ref")
            != execution_ref.model_dump(mode="json")
            or not isinstance(result, dict)
            or result.get("outcome") != "INCONCLUSIVE"
        ):
            return None
        rows = connection.execute(
            "SELECT event_json FROM agent_activity_events "
            "WHERE analysis_id = ? AND hypothesis_key = ? AND attempt_id = ?",
            (
                checkpoint.identity.analysis_id,
                self._hypothesis_key(checkpoint.identity),
                checkpoint.attempt_id,
            ),
        ).fetchall()
        for row in rows:
            event = AgentActivityEvent.model_validate_json(row["event_json"])
            if (
                event.kind is not ActivityKind.DECISION_RECORDED
                or event.stage != checkpoint.stage.value
                or event.analysis_id != checkpoint.identity.analysis_id
                or event.workspace_id != checkpoint.identity.workspace_id
                or event.commit_id != checkpoint.identity.commit_id
                or event.hypothesis_id != checkpoint.identity.hypothesis_id
                or event.attempt_id != checkpoint.attempt_id
                or event.error_code != checkpoint.error_code
                or len(event.output_refs) != 1
            ):
                continue
            decision_ref = event.output_refs[0]
            try:
                decision = json.loads(artifacts.read(decision_ref))
            except (OSError, ValueError, TypeError, sqlite3.Error):
                continue
            if not isinstance(decision, dict):
                continue
            try:
                original_error = StageFailure.model_validate_json(
                    canonical_bytes(decision.get("original_error"))
                )
                stop = RecoveryDecision.model_validate_json(
                    canonical_bytes(decision.get("decision"))
                )
            except (ValueError, TypeError):
                continue
            if (
                decision.get("kind") == "simple_recovery_decision"
                and decision.get("identity")
                == checkpoint.identity.model_dump(mode="json")
                and decision.get("stage") == checkpoint.stage.value
                and decision.get("attempt") == checkpoint.attempt_number
                and decision.get("attempt_id") == checkpoint.attempt_id
                and original_error.code == checkpoint.error_code
                and original_error.retryable
                and original_error.evidence_refs == checkpoint.output_refs
                and stop.action is RecoveryAction.STOP
                and stop.action in ALLOWED_ACTIONS[stop.category]
                and stop.environment_patch == ""
                and (
                    decision.get("decision_origin") == "AGENT"
                    or "decision_origin" not in decision
                    and (stop.diagnosis, stop.guidance)
                    not in LEGACY_RECOVERY_FALLBACK_STOPS
                )
            ):
                return decision_ref
        return None

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

    def repair_legacy_pro_con_evidence(
        self,
        checkpoint: StageCheckpoint,
        invalid_roles: dict[str, StoredDataRef],
        *,
        expected_role_cache: Mapping[str, StoredDataRef | None],
    ) -> bool:
        """Atomically reopen one child's invalid legacy evidence and descendants."""

        if (
            checkpoint.stage is not SimpleStage.PRO_CON_DONE
            or checkpoint.status is not StageStatus.SUCCEEDED
            or checkpoint.identity.hypothesis_id is None
            or len(checkpoint.output_refs) != 2
            or not invalid_roles
            or set(invalid_roles) - {"pro", "con"}
            or set(expected_role_cache) != {"pro", "con"}
            or any(
                invalid_roles[role] != checkpoint.output_refs[0 if role == "pro" else 1]
                for role in invalid_roles
            )
        ):
            raise ValueError("PRO_CON_LEGACY_REPAIR_INVALID")
        identity = checkpoint.identity
        first_index = STAGE_ORDER.index(SimpleStage.PRO_CON_DONE)
        stages = tuple(stage.value for stage in STAGE_ORDER[first_index:])
        placeholders = ",".join("?" for _ in stages)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
                (
                    identity.analysis_id,
                    self._hypothesis_key(identity),
                    checkpoint.stage.value,
                ),
            ).fetchone()
            if (
                row is None
                or StageCheckpoint.model_validate_json(row["checkpoint_json"])
                != checkpoint
            ):
                raise ValueError("PRO_CON_LEGACY_REPAIR_STALE")
            run_row = connection.execute(
                "SELECT run_json FROM simple_analysis_runs WHERE analysis_id = ?",
                (identity.analysis_id,),
            ).fetchone()
            if run_row is None:
                raise ValueError("PRO_CON_LEGACY_REPAIR_STALE")
            run = SimpleAnalysisRun.model_validate_json(run_row["run_json"])
            if (run.workspace_id, run.commit_id) != (
                identity.workspace_id,
                identity.commit_id,
            ):
                raise ValueError("PRO_CON_LEGACY_REPAIR_STALE")
            for role in ("pro", "con"):
                key = self._pro_con_batch_key(identity, role, checkpoint.input_hash)
                cached = connection.execute(
                    "SELECT evidence_ref_json FROM simple_pro_con_batch_evidence "
                    "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                    "AND hypothesis_id = ? AND role = ? AND input_hash = ?",
                    key,
                ).fetchone()
                actual_ref = (
                    StoredDataRef.model_validate_json(cached["evidence_ref_json"])
                    if cached is not None
                    else None
                )
                if actual_ref != expected_role_cache[role] or (
                    actual_ref is not None
                    and actual_ref != checkpoint.output_refs[0 if role == "pro" else 1]
                ):
                    raise ValueError("PRO_CON_LEGACY_REPAIR_STALE")
                if role in invalid_roles and cached is not None:
                    connection.execute(
                        "DELETE FROM simple_pro_con_batch_evidence "
                        "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                        "AND hypothesis_id = ? AND role = ? AND input_hash = ?",
                        key,
                    )
                elif role not in invalid_roles and cached is None:
                    # The saved successful checkpoint itself contains this
                    # audited valid role, even if old runs never cached it.
                    valid_ref = checkpoint.output_refs[0 if role == "pro" else 1]
                    encoded = self._candidate_ref_json(identity, valid_ref)
                    connection.execute(
                        "INSERT INTO simple_pro_con_batch_evidence "
                        "(analysis_id, workspace_id, commit_id, hypothesis_id, "
                        "role, input_hash, evidence_ref_json) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (*key, encoded),
                    )
            scope = (identity.analysis_id, identity.workspace_id, identity.commit_id)
            registrations = connection.execute(
                "SELECT hypothesis_id, parent_hypothesis_ids_json "
                "FROM simple_candidate_hypotheses WHERE analysis_id = ? "
                "AND workspace_id = ? AND commit_id = ?",
                scope,
            ).fetchall()
            parents_by_id: dict[str, tuple[str, ...]] = {}
            for registered in registrations:
                hypothesis_id = str(registered["hypothesis_id"])
                parents = json.loads(registered["parent_hypothesis_ids_json"])
                if (
                    not isinstance(parents, list)
                    or any(not isinstance(parent, str) for parent in parents)
                    or len(parents) != len(set(parents))
                    or hypothesis_id in parents
                ):
                    raise ValueError("PRO_CON_LEGACY_REPAIR_STALE")
                parents_by_id[hypothesis_id] = tuple(parents)
            if identity.hypothesis_id not in parents_by_id:
                raise ValueError("PRO_CON_LEGACY_REPAIR_STALE")
            descendants: set[str] = set()
            frontier = {identity.hypothesis_id}
            while frontier:
                next_frontier = {
                    child_id
                    for child_id, parents in parents_by_id.items()
                    if child_id not in descendants
                    and child_id != identity.hypothesis_id
                    and any(parent in frontier for parent in parents)
                }
                descendants.update(next_frontier)
                frontier = next_frontier
            if any(
                parent not in descendants and parent != identity.hypothesis_id
                for child_id in descendants
                for parent in parents_by_id[child_id]
            ):
                # A co-parent may have a completed Chaining result referring
                # to the invalidated primitive. Rebuilding that pool needs a
                # separate, lineage-aware replay rather than a local repair.
                raise ValueError("PRO_CON_LEGACY_REPAIR_COPARENT")
            affected_ids = descendants | {identity.hypothesis_id}
            revoked_primitives: set[StoredDataRef] = set()
            for primitive_row in connection.execute(
                "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                "WHERE analysis_id = ? AND stage = ?",
                (identity.analysis_id, SimpleStage.PRIMITIVE_ADMISSION_DONE.value),
            ):
                primitive_checkpoint = StageCheckpoint.model_validate_json(
                    primitive_row["checkpoint_json"]
                )
                if primitive_checkpoint.identity.hypothesis_id not in affected_ids:
                    continue
                if (
                    primitive_checkpoint.identity.workspace_id != identity.workspace_id
                    or primitive_checkpoint.identity.commit_id != identity.commit_id
                ):
                    raise ValueError("PRO_CON_LEGACY_REPAIR_STALE")
                if primitive_checkpoint.status is StageStatus.SUCCEEDED:
                    if primitive_checkpoint.stage_version != STAGE_VERSION[
                        SimpleStage.PRIMITIVE_ADMISSION_DONE
                    ] or len(primitive_checkpoint.output_refs) not in {1, 2}:
                        raise ValueError("PRO_CON_LEGACY_REPAIR_DEPENDENT_CHAINING")
                    if len(primitive_checkpoint.output_refs) == 1:
                        # A DENY or a non-material ALLOW has an admission
                        # record but deliberately creates no primitive.
                        if self._artifact_data_dir is None:
                            raise ValueError("PRO_CON_LEGACY_REPAIR_DEPENDENT_CHAINING")
                        primitive_artifacts = SimpleArtifactRepository(
                            self._artifact_data_dir, primitive_checkpoint.identity
                        )
                        try:
                            admission = json.loads(
                                primitive_artifacts.read(
                                    primitive_checkpoint.output_refs[0]
                                )
                            )
                        except (OSError, ValueError, TypeError) as error:
                            raise ValueError(
                                "PRO_CON_LEGACY_REPAIR_DEPENDENT_CHAINING"
                            ) from error
                        if (
                            not isinstance(admission, dict)
                            or admission.get("kind") != "simple_primitive_admission"
                            or admission.get("analysis_id") != identity.analysis_id
                            or admission.get("hypothesis_id")
                            != primitive_checkpoint.identity.hypothesis_id
                            or admission.get("decision") not in {"ALLOW", "DENY"}
                        ):
                            raise ValueError("PRO_CON_LEGACY_REPAIR_DEPENDENT_CHAINING")
                    else:
                        revoked_primitives.add(primitive_checkpoint.output_refs[1])
            dependent_no_child_ids: set[str] = set()
            if revoked_primitives:
                for chain_row in connection.execute(
                    "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                    "WHERE analysis_id = ? AND stage = ?",
                    (identity.analysis_id, SimpleStage.CHAINING_DONE.value),
                ):
                    chain = StageCheckpoint.model_validate_json(
                        chain_row["checkpoint_json"]
                    )
                    if (
                        chain.status is not StageStatus.SUCCEEDED
                        or chain.identity.hypothesis_id in affected_ids
                    ):
                        continue
                    if (
                        chain.identity.workspace_id != identity.workspace_id
                        or chain.identity.commit_id != identity.commit_id
                        or chain.identity.hypothesis_id is None
                        or len(chain.output_refs) != 1
                        or self._artifact_data_dir is None
                    ):
                        raise ValueError("PRO_CON_LEGACY_REPAIR_DEPENDENT_CHAINING")
                    artifacts = SimpleArtifactRepository(
                        self._artifact_data_dir, chain.identity
                    )
                    try:
                        result = json.loads(artifacts.read(chain.output_refs[0]))
                        if (
                            not isinstance(result, dict)
                            or result.get("kind") != "simple_chaining_result"
                            or result.get("analysis_id") != identity.analysis_id
                            or result.get("source_hypothesis_id")
                            != chain.identity.hypothesis_id
                            or not isinstance(
                                result.get("considered_primitive_refs"), list
                            )
                        ):
                            raise ValueError("invalid surviving chaining result")
                        considered = {
                            StoredDataRef.model_validate(ref)
                            for ref in result["considered_primitive_refs"]
                        }
                    except (OSError, ValueError, KeyError, TypeError) as error:
                        raise ValueError(
                            "PRO_CON_LEGACY_REPAIR_DEPENDENT_CHAINING"
                        ) from error
                    if considered & revoked_primitives:
                        owner_id = chain.identity.hypothesis_id
                        if (
                            chain.stage_version
                            != STAGE_VERSION[SimpleStage.CHAINING_DONE]
                            or result.get("status") != "NO_MATERIAL_CHILD"
                            or result.get("children") != []
                            or len(considered)
                            != len(result["considered_primitive_refs"])
                            or owner_id not in parents_by_id
                            or any(
                                owner_id in parents
                                for parents in parents_by_id.values()
                            )
                        ):
                            # Material or lineage-bearing results need a wider
                            # replay; preserve every checkpoint and block.
                            raise ValueError("PRO_CON_LEGACY_REPAIR_DEPENDENT_CHAINING")
                        dependent_no_child_ids.add(owner_id)
            rewind_stages = tuple(
                stage.value
                for stage in STAGE_ORDER[STAGE_ORDER.index(SimpleStage.CHAINING_DONE) :]
            )
            rewind_placeholders = ",".join("?" for _ in rewind_stages)
            for owner_id in dependent_no_child_ids:
                connection.execute(
                    "DELETE FROM simple_runtime_checkpoints WHERE analysis_id = ? "
                    "AND hypothesis_key = ? "
                    f"AND stage IN ({rewind_placeholders})",  # noqa: S608
                    (identity.analysis_id, owner_id, *rewind_stages),
                )
            for descendant_id in descendants:
                descendant_scope = (*scope, descendant_id)
                connection.execute(
                    "DELETE FROM simple_runtime_checkpoints WHERE analysis_id = ? "
                    "AND hypothesis_key = ?",
                    (identity.analysis_id, descendant_id),
                )
                for table in (
                    "simple_pro_con_batch_evidence",
                    "simple_candidate_child_claims",
                    "simple_candidate_hypothesis_links",
                    "simple_candidate_hypotheses",
                ):
                    connection.execute(
                        f"DELETE FROM {table} WHERE analysis_id = ? "
                        "AND workspace_id = ? AND commit_id = ? "
                        "AND hypothesis_id = ?",  # noqa: S608 - constant table names.
                        descendant_scope,
                    )
            connection.execute(
                f"DELETE FROM simple_runtime_checkpoints WHERE analysis_id = ? "
                f"AND hypothesis_key = ? AND stage IN ({placeholders})",  # noqa: S608
                (identity.analysis_id, self._hypothesis_key(identity), *stages),
            )
            pending = checkpoint.model_copy(
                update={
                    "status": StageStatus.PENDING,
                    "output_refs": (),
                    "attempt_id": None,
                    "error_code": None,
                    "retryable": False,
                    "updated_at": datetime.now(UTC),
                }
            )
            self._upsert_checkpoint_connection(connection, pending)
            if run.candidate_terminal is not None:
                self._upsert_analysis_run_connection(
                    connection, run.model_copy(update={"candidate_terminal": None})
                )
            AgentActivityStore.append_connection(
                connection,
                self._lifecycle_event(
                    checkpoint,
                    ActivityKind.EVIDENCE_REVIEWED,
                    sequence=self._stage_sequence(SimpleStage.PRO_CON_DONE, 88),
                    status=StageStatus.BLOCKED,
                    summary_ko="Pro/Con 근거 해시 오류로 후속 검증을 다시 시작합니다.",
                    output_refs=tuple(invalid_roles.values()),
                    error_code="PRO_CON_LEGACY_EVIDENCE_REPAIRED",
                ),
            )
            connection.commit()
            return True
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

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
