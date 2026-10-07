"""Compare a pinned, external vulnerability oracle with saved analysis state."""

from __future__ import annotations

import json
import sqlite3
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, TypedDict

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.candidates import StaticCandidate
from sastsimi.simple_runtime.finding_group_projection import _verified_closure
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
)


@dataclass(frozen=True, slots=True)
class OracleCase:
    case_id: str
    cwe: str
    path: str
    source_line: int | None
    sink_line: int
    rationale: str
    # IDs are checked by a human against pinned source/PoC after the run. A
    # matching line alone is never proof that two vulnerability paths coincide.
    vetted_candidate_ids: tuple[str, ...] = ()
    vetted_hypothesis_ids: tuple[str, ...] = ()
    finding_inventory_reviewed: bool = False
    kind: Literal["FLOW", "MISSING_GUARD", "CONFIGURATION"] = "FLOW"
    sink_path: str | None = None
    scope: Literal["PYTHON", "OUT_OF_SCOPE"] = "PYTHON"


@dataclass(frozen=True, slots=True)
class Oracle:
    repository: str
    commit: str
    cases: tuple[OracleCase, ...]
    version: Literal[1, 2] = 1
    completeness: Literal["UNDECLARED", "DOCUMENTED_CASES", "EXHAUSTIVE_PYTHON"] = (
        "UNDECLARED"
    )


class AuditCaseResult(TypedDict):
    case_id: str
    status: str
    first_gap: str | None
    candidate_ids: list[str]
    vetted_candidate_ids: list[str]
    decisions: dict[str, str]
    deep_states: dict[str, str]
    hypothesis_ids: list[str]
    vetted_hypothesis_ids: list[str]
    finding_inventory_reviewed: bool


class AuditResult(TypedDict):
    analysis_id: str
    oracle_commit: str
    analysis_complete: bool
    cases: list[AuditCaseResult]
    counts: dict[str, int]


def _analysis_run(
    connection: sqlite3.Connection, analysis_id: str
) -> SimpleAnalysisRun:
    row = connection.execute(
        "SELECT run_json FROM simple_analysis_runs WHERE analysis_id = ?",
        (analysis_id,),
    ).fetchone()
    if row is None:
        raise ValueError("RECALL_ANALYSIS_NOT_FOUND")
    return SimpleAnalysisRun.model_validate_json(row[0])


def _static_product_paths(
    connection: sqlite3.Connection, data_dir: Path, run: SimpleAnalysisRun
) -> tuple[frozenset[str], bool] | None:
    """Require exact, hash-verified full static evidence before measuring a miss."""

    bundle_ref = run.static_bundle_ref
    coverage_ref = run.static_coverage_ref
    scope = run.candidate_scope_fingerprint
    if not scope or bundle_ref is None or coverage_ref is None:
        return None
    rows = connection.execute(
        "SELECT checkpoint_json FROM simple_runtime_checkpoints "
        "WHERE analysis_id = ? AND stage = ?",
        (run.analysis_id, SimpleStage.STATIC_DONE.value),
    ).fetchall()
    if len(rows) != 1:
        return None
    checkpoint = StageCheckpoint.model_validate_json(rows[0][0])
    if (
        checkpoint.identity
        != CheckpointIdentity(
            analysis_id=run.analysis_id,
            workspace_id=run.workspace_id,
            commit_id=run.commit_id,
            hypothesis_id=None,
        )
        or checkpoint.status is not StageStatus.SUCCEEDED
        or checkpoint.stage_version != STAGE_VERSION[SimpleStage.STATIC_DONE]
        or len(checkpoint.output_refs) < 2
        or checkpoint.output_refs[1] != bundle_ref
    ):
        return None
    paths = RuntimePaths(data_dir)
    if not all(
        value.is_dir()
        for value in (paths.staging, paths.artifacts / "sha256", paths.quarantine)
    ):
        return None
    artifacts = SimpleArtifactRepository(data_dir, checkpoint.identity)
    try:
        bundle = json.loads(artifacts.read_bounded(bundle_ref, 16 * 1024 * 1024))
        if not isinstance(bundle, dict):
            return None
        if any(
            bundle.get(key) != expected
            for key, expected in (
                ("kind", "simple_static_fact_bundle"),
                ("analysis_id", run.analysis_id),
                ("workspace_id", run.workspace_id),
                ("commit_id", run.commit_id),
            )
        ):
            return None
        if (
            StoredDataRef.model_validate(bundle.get("static_coverage_ref"))
            != coverage_ref
        ):
            return None
        manifest_ref = StoredDataRef.model_validate(bundle.get("source_manifest_ref"))
        manifest = json.loads(artifacts.read_bounded(manifest_ref, 16 * 1024 * 1024))
        coverage = json.loads(artifacts.read_bounded(coverage_ref, 16 * 1024 * 1024))
    except (OSError, ValueError, TypeError, UnicodeError, KeyError):
        return None
    if (
        not isinstance(manifest, dict)
        or manifest.get("kind") != "simple_tracked_sources"
    ):
        return None
    selected = manifest.get("paths")
    if (
        not isinstance(selected, list)
        or not selected
        or any(
            not isinstance(item, str)
            or Path(item).suffix.lower() not in {".py", ".pyi"}
            for item in selected
        )
        or len(set(selected)) != len(selected)
        or not isinstance(coverage, dict)
        or coverage.get("kind") != "simple_static_coverage_v1"
        or coverage.get("fingerprint") != scope
        or any(
            coverage.get(key) != expected
            for key, expected in (
                ("analysis_id", run.analysis_id),
                ("workspace_id", run.workspace_id),
                ("commit_id", run.commit_id),
            )
        )
    ):
        return None
    expected = coverage.get("expected_count")
    verified = coverage.get("verified_count")
    limitation_lists = (
        "gaps",
        "unsupported",
        "unsupported_files",
        "unavailable_paths",
        "ast_parse_errors",
        "ast_oversize_paths",
        "engine_errors",
    )
    out_of_scope = coverage.get("out_of_scope_product_files")
    if not isinstance(out_of_scope, list) or any(
        not isinstance(item, dict)
        or not isinstance(item.get("path"), str)
        or not isinstance(item.get("reason"), str)
        or not item["reason"]
        or Path(item["path"]).suffix.lower() in {".py", ".pyi"}
        for item in out_of_scope
    ):
        return None
    if (
        type(expected) is not int
        or type(verified) is not int
        or expected <= 0
        or verified != expected
        or any(not isinstance(coverage.get(key), list) for key in limitation_lists)
        or any(coverage.get(key) for key in limitation_lists)
        or (
            coverage.get("unavailable") is not None
            and coverage.get("unavailable") is not False
        )
        or coverage.get("codeql_error")
        or any(
            type(coverage.get(key, 0)) is not int or coverage.get(key, 0) != 0
            for key in ("ast_parse_error_count", "ast_oversize_count")
        )
        or coverage.get("ast_truncated") is not False
        or (
            coverage.get("codeql_configured") is True
            and coverage.get("codeql_executed") is not True
        )
    ):
        return None
    if run.static_disposition == "PARTIAL" and not out_of_scope:
        return None
    return frozenset(selected), bool(out_of_scope)


def _pipeline_complete(
    run: SimpleAnalysisRun, *, python_scope_complete: bool, nonpython_out_of_scope: bool
) -> bool:
    terminal = run.candidate_terminal
    return bool(
        terminal is not None
        and (
            terminal.status == "COMPLETE"
            or (
                terminal.status == "PARTIAL"
                and python_scope_complete
                and nonpython_out_of_scope
            )
        )
        and terminal.producer_finished
        and terminal.pending_child_count == 0
        and terminal.scope_fingerprint == run.candidate_scope_fingerprint
        and run.static_bundle_ref is not None
        and terminal.bundle_hash == run.static_bundle_ref.content_hash
        and not any(
            terminal.decision_counts.get(key, 0) for key in ("PENDING", "ERROR")
        )
        and not any(
            terminal.deep_counts.get(key, 0) for key in ("PENDING", "RUNNING", "ERROR")
        )
        and not any(
            terminal.surface_counts.get(key, 0) for key in ("UNCOVERED", "INSUFFICIENT")
        )
    )


def _root_hypothesis_current(
    connection: sqlite3.Connection, data_dir: Path, run: SimpleAnalysisRun
) -> bool:
    """Do not trust a terminal marker after its root provenance was rejected."""

    if run.static_bundle_ref is None:
        return False
    rows = connection.execute(
        "SELECT checkpoint_json FROM simple_runtime_checkpoints "
        "WHERE analysis_id = ? AND hypothesis_key = '' AND stage = ?",
        (run.analysis_id, SimpleStage.HYPOTHESIS_DONE.value),
    ).fetchall()
    if len(rows) != 1:
        return False
    checkpoint = StageCheckpoint.model_validate_json(rows[0][0])
    if (
        checkpoint.identity
        != CheckpointIdentity(
            analysis_id=run.analysis_id,
            workspace_id=run.workspace_id,
            commit_id=run.commit_id,
            hypothesis_id=None,
        )
        or checkpoint.status is not StageStatus.SUCCEEDED
        or checkpoint.stage_version != STAGE_VERSION[SimpleStage.HYPOTHESIS_DONE]
        or run.static_bundle_ref not in checkpoint.input_refs
        or not checkpoint.output_refs
    ):
        return False
    paths = RuntimePaths(data_dir)
    if not all(
        value.is_dir()
        for value in (paths.staging, paths.artifacts / "sha256", paths.quarantine)
    ):
        return False
    artifacts = SimpleArtifactRepository(data_dir, checkpoint.identity)
    try:
        for ref in checkpoint.output_refs:
            artifacts.read_bounded(ref, 128 * 1024 * 1024)
    except (OSError, ValueError, TypeError, UnicodeError):
        return False
    return True


def _matches(case: OracleCase, candidate: StaticCandidate) -> bool:
    target_path = (
        case.path if candidate.kind == "ENTRY_POINT" else case.sink_path or case.path
    )
    if candidate.path != target_path:
        return False
    target = case.source_line if candidate.kind == "ENTRY_POINT" else case.sink_line
    if target is None or not candidate.line <= target <= candidate.end_line:
        return False
    trace = candidate.flow_trace
    trace_cwe = trace.get("cwe") if isinstance(trace, dict) else None
    if isinstance(trace_cwe, str):
        return trace_cwe.upper() == case.cwe.upper()
    return True


def _linked_hypotheses(
    connection: sqlite3.Connection,
    run: SimpleAnalysisRun,
    candidate_ids: tuple[str, ...],
) -> tuple[str, ...]:
    if not candidate_ids:
        return ()
    found: set[str] = set()
    for offset in range(0, len(candidate_ids), 500):
        batch = candidate_ids[offset : offset + 500]
        placeholders = ",".join("?" for _ in batch)
        rows = connection.execute(
            "SELECT DISTINCT hypothesis_id FROM simple_candidate_hypothesis_links "
            "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
            f"AND scope_fingerprint = ? AND candidate_id IN ({placeholders})",
            (
                run.analysis_id,
                run.workspace_id,
                run.commit_id,
                run.candidate_scope_fingerprint,
                *batch,
            ),
        ).fetchall()
        found.update(str(row[0]) for row in rows)
    return tuple(sorted(found))


def _hypothesis_stages(
    connection: sqlite3.Connection,
    run: SimpleAnalysisRun,
    hypothesis_id: str,
) -> dict[SimpleStage, StageCheckpoint]:
    rows = connection.execute(
        "SELECT checkpoint_json FROM simple_runtime_checkpoints "
        "WHERE analysis_id = ? AND hypothesis_key = ?",
        (run.analysis_id, hypothesis_id),
    ).fetchall()
    checkpoints = (StageCheckpoint.model_validate_json(row[0]) for row in rows)
    return {
        checkpoint.stage: checkpoint
        for checkpoint in checkpoints
        if checkpoint.identity.analysis_id == run.analysis_id
        and checkpoint.identity.workspace_id == run.workspace_id
        and checkpoint.identity.commit_id == run.commit_id
        and checkpoint.identity.hypothesis_id == hypothesis_id
    }


def _confirmed(
    data_dir: Path,
    run: SimpleAnalysisRun,
    hypothesis_id: str,
    case: OracleCase,
    stages: dict[SimpleStage, StageCheckpoint],
) -> bool:
    """Reuse the strict Finding closure and require a current report artifact."""

    finding = stages.get(SimpleStage.FINDING_DONE)
    report = stages.get(SimpleStage.REPORT_DONE)
    cwe = stages.get(SimpleStage.CWE_DONE)
    if (
        finding is None
        or len(finding.output_refs) != 1
        or report is None
        or report.status is not StageStatus.SUCCEEDED
        or report.stage_version != STAGE_VERSION[SimpleStage.REPORT_DONE]
        or not report.output_refs
        or finding.output_refs[0] not in report.input_refs
        or report.validated_poc_ref is None
        or cwe is None
        or len(cwe.output_refs) != 1
    ):
        return False
    paths = RuntimePaths(data_dir)
    if not all(
        value.is_dir()
        for value in (paths.staging, paths.artifacts / "sha256", paths.quarantine)
    ):
        return False
    artifacts = SimpleArtifactRepository(
        data_dir,
        CheckpointIdentity(
            analysis_id=run.analysis_id,
            workspace_id=run.workspace_id,
            commit_id=run.commit_id,
            hypothesis_id=hypothesis_id,
        ),
    )
    try:
        closure = _verified_closure(stages, finding.output_refs[0], artifacts)
        if closure is None or not closure[2] or report.validated_poc_ref != closure[1]:
            return False
        cwe_data = json.loads(artifacts.read_bounded(cwe.output_refs[0], 1024 * 1024))
        if (
            not isinstance(cwe_data, dict)
            or cwe_data.get("kind") != "simple_cwe_label"
            or not isinstance(cwe_data.get("result"), dict)
            or cwe_data["result"].get("primary_cwe") != case.cwe
        ):
            return False
        for ref in report.output_refs:
            artifacts.read_bounded(ref, 16 * 1024 * 1024)
    except (OSError, ValueError, TypeError, UnicodeError):
        return False
    return True


def audit_analysis(data_dir: Path, analysis_id: str, oracle: Oracle) -> AuditResult:
    """Read an existing analysis without initializing or changing its database."""

    database = RuntimePaths(data_dir).database.resolve(strict=True)
    with sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN")
        run = _analysis_run(connection, analysis_id)
        if run.commit_id != oracle.commit or run.repository != oracle.repository:
            raise ValueError("RECALL_ORACLE_TARGET_MISMATCH")
        static_scope = _static_product_paths(connection, data_dir, run)
        static_paths = static_scope[0] if static_scope is not None else None
        root_current = _root_hypothesis_current(connection, data_dir, run)
        terminal_complete = (
            static_scope is not None
            and root_current
            and _pipeline_complete(
                run,
                python_scope_complete=True,
                nonpython_out_of_scope=static_scope[1],
            )
        )
        cursor = connection.execute(
            "SELECT candidate_id, candidate_json, decision, deep_status "
            "FROM simple_static_candidates "
            "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
            "AND scope_fingerprint = ? ORDER BY candidate_id",
            (
                run.analysis_id,
                run.workspace_id,
                run.commit_id,
                run.candidate_scope_fingerprint,
            ),
        )
        matches_by_case: list[list[tuple[StaticCandidate, str, str]]] = [
            [] for _ in oracle.cases
        ]
        observed_decisions: Counter[str] = Counter()
        observed_deep: Counter[str] = Counter()
        while rows := cursor.fetchmany(500):
            for row in rows:
                candidate = StaticCandidate.model_validate_json(row["candidate_json"])
                if candidate.candidate_id != row["candidate_id"]:
                    raise ValueError("RECALL_CANDIDATE_ID_MISMATCH")
                item = (candidate, str(row["decision"]), str(row["deep_status"]))
                observed_decisions[item[1]] += 1
                if item[1] in {"INCLUDE", "UNDECIDED"}:
                    observed_deep[item[2]] += 1
                for index, case in enumerate(oracle.cases):
                    if _matches(case, candidate):
                        matches_by_case[index].append(item)
        terminal = run.candidate_terminal
        ledger_consistent = bool(
            terminal is not None
            and dict(observed_decisions)
            == {key: count for key, count in terminal.decision_counts.items() if count}
            and dict(observed_deep)
            == {key: count for key, count in terminal.deep_counts.items() if count}
        )
        pipeline_complete = terminal_complete and ledger_consistent
        cases: list[AuditCaseResult] = []
        for case, matched in zip(oracle.cases, matches_by_case, strict=True):
            candidate_ids = tuple(item[0].candidate_id for item in matched)
            decisions = {item[0].candidate_id: item[1] for item in matched}
            deep_states = {item[0].candidate_id: item[2] for item in matched}
            vetted_ids = tuple(
                item for item in candidate_ids if item in case.vetted_candidate_ids
            )
            hypothesis_ids = tuple(
                sorted(
                    set(
                        _linked_hypotheses(connection, run, candidate_ids)
                        + case.vetted_hypothesis_ids
                    )
                )
            )
            relevant_hypothesis_ids = tuple(
                sorted(
                    set(
                        _linked_hypotheses(connection, run, vetted_ids)
                        + case.vetted_hypothesis_ids
                    )
                )
            )
            stages = {
                hypothesis_id: _hypothesis_stages(connection, run, hypothesis_id)
                for hypothesis_id in relevant_hypothesis_ids
            }
            vetted_stages = {
                key: value
                for key, value in stages.items()
                if key in case.vetted_hypothesis_ids
            }
            complete = (
                static_paths is not None
                and pipeline_complete
                and case.path in static_paths
                and (case.sink_path is None or case.sink_path in static_paths)
            )
            if set(case.vetted_candidate_ids) - set(vetted_ids):
                status, first_gap = "INCOMPLETE", "ORACLE_CANDIDATE_MAPPING_INVALID"
            elif not root_current:
                status, first_gap = (
                    "INCOMPLETE",
                    "STATIC_EVIDENCE_UNVERIFIED"
                    if static_paths is None
                    else "ROOT_HYPOTHESIS_UNVERIFIED",
                )
            elif any(
                _confirmed(data_dir, run, key, case, item)
                for key, item in vetted_stages.items()
            ):
                status, first_gap = "DETECTED", None
            elif not ledger_consistent:
                status, first_gap = "INCOMPLETE", "CANDIDATE_LEDGER_MISMATCH"
            elif any(
                checkpoint.verdict == "HOLD"
                or checkpoint.environment_block_ref is not None
                for item in stages.values()
                for checkpoint in item.values()
            ):
                status, first_gap = "INCOMPLETE", "HOLD_VERIFICATION"
            elif any(
                checkpoint.status in {StageStatus.FAILED, StageStatus.BLOCKED}
                for item in stages.values()
                for checkpoint in item.values()
            ):
                status, first_gap = (
                    "INCOMPLETE",
                    "POC_EXECUTION_ERROR"
                    if any(
                        item.get(SimpleStage.POC_EXECUTION_DONE) is not None
                        and item[SimpleStage.POC_EXECUTION_DONE].status
                        in {StageStatus.FAILED, StageStatus.BLOCKED}
                        for item in stages.values()
                    )
                    else "AGENT_ERROR",
                )
            elif any(
                (final := item.get(SimpleStage.VERIFICATION_FINAL_DONE)) is not None
                and final.status is StageStatus.SUCCEEDED
                and final.verdict == "TRUE"
                for item in vetted_stages.values()
            ):
                status, first_gap = "INCOMPLETE", "FINDING_EVIDENCE_UNVERIFIED"
            elif not complete:
                status, first_gap = (
                    "INCOMPLETE",
                    (
                        "STATIC_EVIDENCE_UNVERIFIED"
                        if static_paths is None
                        else "ORACLE_OUT_OF_SCOPE"
                        if case.path not in static_paths
                        else "PIPELINE_UNFINISHED"
                    ),
                )
            elif not matched and not case.vetted_hypothesis_ids:
                status, first_gap = "MISSED", "STATIC_CANDIDATE"
            elif matched and not vetted_ids and not case.vetted_hypothesis_ids:
                status, first_gap = (
                    "POSSIBLE",
                    (
                        "HYPOTHESIS"
                        if all(item[0].kind == "ENTRY_POINT" for item in matched)
                        else "CANDIDATE_IDENTITY_UNVERIFIED"
                    ),
                )
            elif vetted_ids and all(
                decisions[value] == "EXCLUDE" for value in vetted_ids
            ):
                status, first_gap = (
                    ("MISSED" if complete else "INCOMPLETE"),
                    "DISCOVERY",
                )
            elif any(
                decisions[value] in {"PENDING", "ERROR"} for value in vetted_ids
            ) or any(
                deep_states[value] in {"PENDING", "RUNNING", "ERROR"}
                for value in vetted_ids
            ):
                status, first_gap = "INCOMPLETE", "DISCOVERY_OR_DEEP_PENDING"
            elif not relevant_hypothesis_ids:
                status, first_gap = (
                    ("MISSED", "HYPOTHESIS")
                    if vetted_ids
                    and all(
                        deep_states[value] in {"NO_HYPOTHESIS", "INCONCLUSIVE"}
                        for value in vetted_ids
                    )
                    else ("INCOMPLETE", "HYPOTHESIS")
                )
            elif any(
                item.get(SimpleStage.VERIFICATION_FINAL_DONE) is None
                for item in stages.values()
            ):
                status, first_gap = "INCOMPLETE", "VALIDATION_UNFINISHED"
            else:
                status, first_gap = (
                    ("MISSED", "VALIDATION")
                    if case.vetted_hypothesis_ids
                    else ("POSSIBLE", "HYPOTHESIS_IDENTITY_UNVERIFIED")
                )
            if status == "MISSED" and not case.finding_inventory_reviewed:
                status, first_gap = "POSSIBLE", "FINDING_INVENTORY_UNREVIEWED"
            cases.append(
                {
                    "case_id": case.case_id,
                    "status": status,
                    "first_gap": first_gap,
                    "candidate_ids": list(candidate_ids),
                    "vetted_candidate_ids": list(vetted_ids),
                    "decisions": decisions,
                    "deep_states": deep_states,
                    "hypothesis_ids": list(hypothesis_ids),
                    "vetted_hypothesis_ids": list(case.vetted_hypothesis_ids),
                    "finding_inventory_reviewed": case.finding_inventory_reviewed,
                }
            )
    return {
        "analysis_id": analysis_id,
        "oracle_commit": oracle.commit,
        "analysis_complete": pipeline_complete,
        "cases": cases,
        "counts": dict(Counter(str(item["status"]) for item in cases)),
    }
