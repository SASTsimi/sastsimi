"""Read-only, case-level recall scoring from a frozen oracle and later review."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections import Counter
from contextlib import closing
from functools import partial
from pathlib import Path
from typing import TypedDict

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.reporting.bundle_files import (
    MAX_BUNDLE_ARCHIVE_BYTES,
    MAX_BUNDLE_MANIFEST_BYTES,
    parse_bundle_manifest,
    read_bundle_archive,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.finding_group_projection import _verified_closure
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
)
from sastsimi.simple_runtime.recall_audit import (
    Oracle,
    _analysis_run,
    _confirmed,
    _hypothesis_stages,
    _static_product_paths,
    audit_analysis,
    repository_targets_match,
    strict_terminal_proof,
)
from sastsimi.simple_runtime.recall_oracle import parse_oracle_bytes
from sastsimi.simple_runtime.recall_review import ReviewLedger, reviewed_oracle


class ScoredCase(TypedDict):
    case_id: str
    status: str
    first_gap: str | None


class RecallScore(TypedDict):
    analysis_id: str
    analysis_status: str
    analysis_complete: bool
    oracle_commit: str
    oracle_completeness: str
    case_counts: dict[str, int]
    finding_counts: dict[str, int]
    cases: list[ScoredCase]
    recall: float | None
    recall_label: str | None


def _required_static_artifacts_intact(data_dir: Path, run: SimpleAnalysisRun) -> None:
    """Reject damaged saved evidence; valid but incomplete coverage stays HOLD."""

    bundle_ref = run.static_bundle_ref
    coverage_ref = run.static_coverage_ref
    if bundle_ref is None and coverage_ref is None:
        return
    if bundle_ref is None or coverage_ref is None:
        raise ValueError("RECALL_REVIEW_STATIC_EVIDENCE_INVALID")
    artifacts = SimpleArtifactRepository(
        data_dir,
        CheckpointIdentity(
            analysis_id=run.analysis_id,
            workspace_id=run.workspace_id,
            commit_id=run.commit_id,
            hypothesis_id=None,
        ),
        create_dirs=False,
    )
    try:
        bundle = json.loads(artifacts.read_bounded(bundle_ref, 16 * 1024 * 1024))
        coverage = json.loads(artifacts.read_bounded(coverage_ref, 16 * 1024 * 1024))
        if (
            not isinstance(bundle, dict)
            or bundle.get("kind") != "simple_static_fact_bundle"
            or bundle.get("analysis_id") != run.analysis_id
            or bundle.get("workspace_id") != run.workspace_id
            or bundle.get("commit_id") != run.commit_id
            or StoredDataRef.model_validate(bundle.get("static_coverage_ref"))
            != coverage_ref
            or not isinstance(coverage, dict)
            or coverage.get("kind") != "simple_static_coverage_v1"
        ):
            raise ValueError("invalid static artifact")
        expected = coverage.get("expected_count")
        verified = coverage.get("verified_count")
        if (
            any(
                coverage.get(key) != value
                for key, value in (
                    ("analysis_id", run.analysis_id),
                    ("workspace_id", run.workspace_id),
                    ("commit_id", run.commit_id),
                    ("fingerprint", run.candidate_scope_fingerprint),
                )
            )
            or type(expected) is not int
            or type(verified) is not int
            or expected < 0
            or verified < 0
            or verified > expected
            or any(
                not isinstance(coverage.get(key), list)
                for key in (
                    "gaps",
                    "unsupported",
                    "unsupported_files",
                    "unavailable_paths",
                    "ast_parse_errors",
                    "ast_oversize_paths",
                    "engine_errors",
                    "excluded_test_files",
                    "out_of_scope_product_files",
                )
            )
            or type(coverage.get("ast_parse_error_count")) is not int
            or type(coverage.get("ast_oversize_count")) is not int
            or coverage["ast_parse_error_count"] < 0
            or coverage["ast_oversize_count"] < 0
            or type(coverage.get("ast_truncated")) is not bool
            or ("unavailable" in coverage and type(coverage["unavailable"]) is not bool)
            or type(coverage.get("codeql_configured")) is not bool
            or type(coverage.get("codeql_executed")) is not bool
            or not all(
                isinstance(item, dict)
                and all(
                    isinstance(item.get(key), str) and item[key]
                    for key in ("path", "rule_id", "reason")
                )
                for item in coverage["gaps"]
            )
            or not all(
                isinstance(item, dict)
                and isinstance(item.get("path"), str)
                and bool(item["path"])
                and isinstance(item.get("reason"), str)
                and bool(item["reason"])
                for field in (
                    "unsupported_files",
                    "unavailable_paths",
                    "excluded_test_files",
                    "out_of_scope_product_files",
                )
                for item in coverage[field]
            )
            or not all(
                isinstance(item, dict)
                and isinstance(item.get("extension"), str)
                and type(item.get("file_count")) is int
                and item["file_count"] >= 0
                for item in coverage["unsupported"]
            )
        ):
            raise ValueError("invalid static coverage identity or schema")
        manifest_ref = StoredDataRef.model_validate(bundle.get("source_manifest_ref"))
        manifest = json.loads(artifacts.read_bounded(manifest_ref, 16 * 1024 * 1024))
        if (
            not isinstance(manifest, dict)
            or manifest.get("kind") != "simple_tracked_sources"
            or not isinstance(manifest.get("paths"), list)
            or not manifest["paths"]
            or not all(
                isinstance(path, str) and path.endswith((".py", ".pyi"))
                for path in manifest["paths"]
            )
            or len(set(manifest["paths"])) != len(manifest["paths"])
        ):
            raise ValueError("invalid source manifest")
    except (OSError, ValueError, TypeError, UnicodeError) as error:
        raise ValueError("RECALL_REVIEW_STATIC_EVIDENCE_INVALID") from error


def _current_findings(
    connection: sqlite3.Connection, data_dir: Path, analysis_id: str
) -> tuple[dict[str, tuple[str, StoredDataRef]], int]:
    """Return report-backed Findings and the count awaiting report completion."""

    run = _analysis_run(connection, analysis_id)
    rows = connection.execute(
        "SELECT hypothesis_key, checkpoint_json FROM simple_runtime_checkpoints "
        "WHERE analysis_id = ? AND stage = ?",
        (analysis_id, SimpleStage.FINDING_DONE.value),
    ).fetchall()
    current_by_hash: dict[str, tuple[str, StoredDataRef]] = {}
    bundle_display_ids: dict[str, str] = {}
    unfinished_reports = 0
    for hypothesis_id, raw in rows:
        checkpoint = StageCheckpoint.model_validate_json(raw)
        if checkpoint.status is not StageStatus.SUCCEEDED:
            unfinished_reports += 1
            continue
        if (
            not hypothesis_id
            or checkpoint.stage is not SimpleStage.FINDING_DONE
            or checkpoint.identity.analysis_id != analysis_id
            or checkpoint.identity.workspace_id != run.workspace_id
            or checkpoint.identity.commit_id != run.commit_id
            or checkpoint.identity.hypothesis_id != hypothesis_id
            or checkpoint.stage_version != STAGE_VERSION[SimpleStage.FINDING_DONE]
        ):
            raise ValueError("RECALL_REVIEW_FINDING_EVIDENCE_INVALID")
        if len(checkpoint.output_refs) != 1:
            raise ValueError("RECALL_REVIEW_FINDING_EVIDENCE_INVALID")
        stages = _hypothesis_stages(connection, run, hypothesis_id)
        report = stages.get(SimpleStage.REPORT_DONE)
        ref = checkpoint.output_refs[0]
        if report is None or report.status is not StageStatus.SUCCEEDED:
            unfinished_reports += 1
            continue
        if (
            report.stage_version != STAGE_VERSION[SimpleStage.REPORT_DONE]
            or ref not in report.input_refs
            or len(report.output_refs) < 2
            or report.bundle_manifest_ref is None
            or report.bundle_archive_ref is None
        ):
            raise ValueError("RECALL_REVIEW_FINDING_EVIDENCE_INVALID")
        artifacts = SimpleArtifactRepository(
            data_dir, checkpoint.identity, create_dirs=False
        )
        try:
            closure = _verified_closure(stages, ref, artifacts)
            if (
                closure is None
                or not closure[2]
                or report.validated_poc_ref != closure[1]
            ):
                raise ValueError("RECALL_REVIEW_FINDING_EVIDENCE_INVALID")
            for output in report.output_refs:
                artifacts.read_bounded(output, 16 * 1024 * 1024)
            artifacts.require_current_report_coverage(
                report, ref, run.static_coverage_ref, run.static_disposition
            )
            manifest = parse_bundle_manifest(
                artifacts.read_bounded(
                    report.bundle_manifest_ref, MAX_BUNDLE_MANIFEST_BYTES
                ),
                finding_ref=ref,
            )
            candidate = stages.get(SimpleStage.POC_CANDIDATE_DONE)
            if (
                manifest.analysis_id != analysis_id
                or candidate is None
                or len(candidate.output_refs) < 2
                or manifest.poc_original_sha256 != candidate.output_refs[1].content_hash
            ):
                raise ValueError("RECALL_REVIEW_FINDING_EVIDENCE_INVALID")
            archive = read_bundle_archive(
                manifest,
                report.bundle_archive_ref,
                partial(
                    artifacts.read_bounded,
                    max_bytes=MAX_BUNDLE_ARCHIVE_BYTES,
                ),
            )
            artifacts.require_published_report_bundle(report, manifest, archive)
        except (OSError, ValueError, TypeError, UnicodeError) as error:
            raise ValueError("RECALL_REVIEW_FINDING_EVIDENCE_INVALID") from error
        current_by_hash[ref.content_hash] = (hypothesis_id, ref)
        bundle_display_ids[ref.content_hash] = manifest.display_id
    table = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name='finding_display_ids'"
    ).fetchone()
    if table is None:
        if current_by_hash:
            raise ValueError("RECALL_REVIEW_FINDING_DISPLAY_MISSING")
        return {}, unfinished_reports
    display_rows = connection.execute(
        "SELECT display_number, finding_hash, finding_ref_json "
        "FROM finding_display_ids "
        "WHERE analysis_id = ?",
        (analysis_id,),
    ).fetchall()
    result: dict[str, tuple[str, StoredDataRef]] = {}
    seen_display_refs: set[str] = set()
    for number, finding_hash, raw in display_rows:
        ref = StoredDataRef.model_validate_json(raw)
        if finding_hash != ref.content_hash or ref.content_hash in seen_display_refs:
            raise ValueError("RECALL_REVIEW_FINDING_DISPLAY_MISSING")
        seen_display_refs.add(ref.content_hash)
        current = current_by_hash.get(ref.content_hash)
        if current is not None and current[1] == ref:
            display_id = f"F-{int(number):03d}"
            if bundle_display_ids[ref.content_hash] != display_id:
                raise ValueError("RECALL_REVIEW_FINDING_EVIDENCE_INVALID")
            result[display_id] = current
    if {ref.content_hash for _hypothesis, ref in result.values()} != set(
        current_by_hash
    ):
        raise ValueError("RECALL_REVIEW_FINDING_DISPLAY_MISSING")
    return result, unfinished_reports


def score_analysis(
    data_dir: Path,
    analysis_id: str,
    oracle: Oracle,
    oracle_bytes: bytes,
    review: ReviewLedger,
) -> RecallScore:
    """Score current, human-linked evidence without writing run data or artifacts."""

    if oracle.version != 2:
        raise ValueError("RECALL_REVIEW_VERSION_MISMATCH")
    try:
        if parse_oracle_bytes(oracle_bytes) != oracle:
            raise ValueError("oracle object does not match frozen bytes")
    except ValueError as error:
        raise ValueError("RECALL_REVIEW_ORACLE_BINDING_INVALID") from error
    if review.analysis_id != analysis_id:
        raise ValueError("RECALL_REVIEW_ANALYSIS_MISMATCH")
    if review.oracle_sha256 != hashlib.sha256(oracle_bytes).hexdigest():
        raise ValueError("RECALL_REVIEW_ORACLE_HASH_MISMATCH")
    database = RuntimePaths(data_dir).database.resolve(strict=True)
    with closing(
        sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)
    ) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("BEGIN")
        run = _analysis_run(connection, analysis_id)
        if (
            not repository_targets_match(oracle.repository, run.repository)
            or run.commit_id != oracle.commit
        ):
            raise ValueError("RECALL_ORACLE_TARGET_MISMATCH")
        _required_static_artifacts_intact(data_dir, run)
        static_scope = _static_product_paths(connection, data_dir, run)
        current, unfinished_reports = _current_findings(
            connection, data_dir, analysis_id
        )
        if review.inventory_reviewed and set(current) != {
            item.finding_id for item in review.findings
        }:
            raise ValueError("RECALL_REVIEW_INVENTORY_MISMATCH")
        for finding in review.findings:
            if finding.finding_id not in current:
                raise ValueError("RECALL_REVIEW_FINDING_STALE")
        for case in review.cases:
            for hypothesis_id in case.hypothesis_ids:
                row = connection.execute(
                    "SELECT 1 FROM simple_candidate_hypotheses "
                    "WHERE analysis_id = ? AND workspace_id = ? AND commit_id = ? "
                    "AND hypothesis_id = ?",
                    (analysis_id, run.workspace_id, run.commit_id, hypothesis_id),
                ).fetchone()
                if row is None or not _hypothesis_stages(
                    connection, run, hypothesis_id
                ):
                    raise ValueError("RECALL_REVIEW_HYPOTHESIS_STALE")
            for finding_id in case.finding_ids:
                item = current.get(finding_id)
                if item is None or item[0] not in case.hypothesis_ids:
                    raise ValueError("RECALL_REVIEW_FINDING_LINK_INVALID")
        vetted = reviewed_oracle(
            oracle, review, complete_inventory=review.inventory_reviewed
        )
        matched_hypotheses = {
            case.case_id: frozenset(
                current[finding_id][0] for finding_id in case.finding_ids
            )
            for case in review.cases
        }
        stage_audit = audit_analysis(
            data_dir,
            analysis_id,
            vetted,
            connection=connection,
            reviewed_root_causes=True,
            matched_hypotheses_by_case=matched_hypotheses,
        )
        by_case = {case.case_id: case for case in review.cases}
        terminal = run.candidate_terminal
        needs_terminal_proof = any(
            oracle_case.scope == "PYTHON"
            and (case_review := by_case.get(oracle_case.case_id)) is not None
            and bool(case_review.finding_ids)
            for oracle_case in oracle.cases
        ) or bool(
            stage_audit["analysis_complete"]
            and review.inventory_reviewed
            and any(audit["status"] == "MISSED" for audit in stage_audit["cases"])
        )
        terminal_proven = (
            strict_terminal_proof(connection, data_dir, run, allow_surface_gaps=True)
            if needs_terminal_proof
            and static_scope is not None
            and terminal is not None
            and terminal.producer_finished
            and terminal.pending_child_count == 0
            else False
        )
        complete_terminal_proven = (
            strict_terminal_proof(connection, data_dir, run)
            if terminal_proven and stage_audit["analysis_complete"]
            else False
        )
        scored: list[ScoredCase] = []
        counts: Counter[str] = Counter()
        for oracle_case, audit in zip(oracle.cases, stage_audit["cases"], strict=True):
            first_gap = audit["first_gap"]
            case_static_verified = (
                static_scope is not None
                and oracle_case.path in static_scope[0]
                and (
                    oracle_case.sink_path is None
                    or oracle_case.sink_path in static_scope[0]
                )
            )
            linked = by_case.get(oracle_case.case_id)
            if linked is not None and set(linked.candidate_ids) - set(
                audit["candidate_ids"]
            ):
                raise ValueError("RECALL_REVIEW_CANDIDATE_STALE")
            if oracle_case.scope == "OUT_OF_SCOPE":
                status = "OUT_OF_SCOPE"
                first_gap = "DECLARED_OUT_OF_SCOPE"
            elif linked is None:
                status = "REVIEW_REQUIRED"
            elif (
                audit["status"] == "DETECTED"
                and case_static_verified
                and terminal_proven
                and linked.finding_ids
                and any(
                    _confirmed(
                        data_dir,
                        run,
                        current[finding_id][0],
                        oracle_case,
                        _hypothesis_stages(connection, run, current[finding_id][0]),
                        reviewed_root_cause=True,
                    )
                    for finding_id in linked.finding_ids
                )
            ):
                status = "TP"
                first_gap = None
            elif audit["status"] == "DETECTED" and not case_static_verified:
                status = "HOLD"
                first_gap = (
                    "STATIC_EVIDENCE_UNVERIFIED"
                    if static_scope is None
                    else "ORACLE_OUT_OF_SCOPE"
                )
            elif audit["status"] == "DETECTED" and not terminal_proven:
                status = "HOLD"
                first_gap = (
                    "TERMINAL_INCOMPLETE"
                    if stage_audit["analysis_complete"]
                    else "PIPELINE_UNFINISHED"
                )
            elif unfinished_reports:
                status = "HOLD"
                first_gap = "REPORT_UNFINISHED"
            elif audit["status"] == "MISSED" and review.inventory_reviewed:
                status = (
                    "FN"
                    if stage_audit["analysis_complete"] and complete_terminal_proven
                    else "HOLD"
                )
                if status == "HOLD":
                    first_gap = "TERMINAL_INCOMPLETE"
            elif audit["status"] == "INCOMPLETE":
                status = "HOLD"
            else:
                status = "REVIEW_REQUIRED"
            counts[status] += 1
            scored.append(
                {
                    "case_id": oracle_case.case_id,
                    "status": status,
                    "first_gap": first_gap,
                }
            )
        reviewed_findings = {item.finding_id: item for item in review.findings}
        finding_counts = {
            "MATCHED": sum(item.status == "MATCHED" for item in review.findings),
            "FP": sum(item.status == "FALSE_POSITIVE" for item in review.findings),
            "UNMATCHED_REVIEW_REQUIRED": sum(
                finding_id not in reviewed_findings
                or reviewed_findings[finding_id].status == "UNMATCHED_REVIEWED"
                for finding_id in current
            ),
            "UNFINISHED_REPORTS": unfinished_reports,
        }
    recall: float | None = None
    label: str | None = None
    if (
        oracle.completeness != "UNDECLARED"
        and review.inventory_reviewed
        and not unfinished_reports
        and static_scope is not None
        and terminal_proven
        and not counts["HOLD"]
        and not counts["REVIEW_REQUIRED"]
        and counts["TP"] + counts["FN"] > 0
    ):
        recall = counts["TP"] / (counts["TP"] + counts["FN"])
        label = (
            "documented_cases"
            if oracle.completeness == "DOCUMENTED_CASES"
            else "exhaustive_python_declared"
        )
    return {
        "analysis_id": analysis_id,
        "analysis_status": (
            terminal.status
            if terminal is not None
            and terminal.producer_finished
            and terminal.pending_child_count == 0
            else "UNFINISHED"
        ),
        "analysis_complete": stage_audit["analysis_complete"],
        "oracle_commit": oracle.commit,
        "oracle_completeness": oracle.completeness,
        "case_counts": {
            name: counts[name]
            for name in ("TP", "FN", "HOLD", "OUT_OF_SCOPE", "REVIEW_REQUIRED")
        },
        "finding_counts": finding_counts,
        "cases": scored,
        "recall": recall,
        "recall_label": label,
    }
