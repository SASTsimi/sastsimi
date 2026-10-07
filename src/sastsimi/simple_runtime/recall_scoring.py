"""Read-only, case-level recall scoring from a frozen oracle and later review."""

from __future__ import annotations

import hashlib
import sqlite3
from collections import Counter
from pathlib import Path
from typing import TypedDict

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.finding_group_projection import _verified_closure
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
)
from sastsimi.simple_runtime.recall_audit import (
    Oracle,
    _analysis_run,
    _confirmed,
    _hypothesis_stages,
    audit_analysis,
)
from sastsimi.simple_runtime.recall_review import ReviewLedger, reviewed_oracle


class ScoredCase(TypedDict):
    case_id: str
    status: str
    first_gap: str | None


class RecallScore(TypedDict):
    analysis_id: str
    oracle_commit: str
    oracle_completeness: str
    case_counts: dict[str, int]
    finding_counts: dict[str, int]
    cases: list[ScoredCase]
    recall: float | None
    recall_label: str | None


def _current_findings(
    connection: sqlite3.Connection, data_dir: Path, analysis_id: str
) -> dict[str, tuple[str, StoredDataRef]]:
    """Return only display IDs backed by current verified Finding/report closures."""

    run = _analysis_run(connection, analysis_id)
    rows = connection.execute(
        "SELECT hypothesis_key, checkpoint_json FROM simple_runtime_checkpoints "
        "WHERE analysis_id = ? AND stage = ?",
        (analysis_id, SimpleStage.FINDING_DONE.value),
    ).fetchall()
    current_by_hash: dict[str, tuple[str, StoredDataRef]] = {}
    for hypothesis_id, raw in rows:
        checkpoint = StageCheckpoint.model_validate_json(raw)
        if (
            not hypothesis_id
            or checkpoint.identity.analysis_id != analysis_id
            or checkpoint.identity.workspace_id != run.workspace_id
            or checkpoint.identity.commit_id != run.commit_id
            or checkpoint.identity.hypothesis_id != hypothesis_id
            or checkpoint.status is not StageStatus.SUCCEEDED
            or checkpoint.stage_version != STAGE_VERSION[SimpleStage.FINDING_DONE]
        ):
            continue
        if len(checkpoint.output_refs) != 1:
            raise ValueError("RECALL_REVIEW_FINDING_EVIDENCE_INVALID")
        stages = _hypothesis_stages(connection, run, hypothesis_id)
        report = stages.get(SimpleStage.REPORT_DONE)
        ref = checkpoint.output_refs[0]
        if (
            report is None
            or report.status is not StageStatus.SUCCEEDED
            or report.stage_version != STAGE_VERSION[SimpleStage.REPORT_DONE]
            or ref not in report.input_refs
            or not report.output_refs
        ):
            raise ValueError("RECALL_REVIEW_FINDING_EVIDENCE_INVALID")
        artifacts = SimpleArtifactRepository(data_dir, checkpoint.identity)
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
        except (OSError, ValueError, TypeError, UnicodeError) as error:
            raise ValueError("RECALL_REVIEW_FINDING_EVIDENCE_INVALID") from error
        current_by_hash[ref.content_hash] = (hypothesis_id, ref)
    table = connection.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name='finding_display_ids'"
    ).fetchone()
    if table is None:
        return {}
    display_rows = connection.execute(
        "SELECT display_number, finding_ref_json FROM finding_display_ids "
        "WHERE analysis_id = ?",
        (analysis_id,),
    ).fetchall()
    result: dict[str, tuple[str, StoredDataRef]] = {}
    for number, raw in display_rows:
        ref = StoredDataRef.model_validate_json(raw)
        current = current_by_hash.get(ref.content_hash)
        if current is not None and current[1] == ref:
            result[f"F-{int(number):03d}"] = current
    return result


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
    if review.analysis_id != analysis_id:
        raise ValueError("RECALL_REVIEW_ANALYSIS_MISMATCH")
    if review.oracle_sha256 != hashlib.sha256(oracle_bytes).hexdigest():
        raise ValueError("RECALL_REVIEW_ORACLE_HASH_MISMATCH")
    database = RuntimePaths(data_dir).database.resolve(strict=True)
    with sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True) as connection:
        connection.execute("BEGIN")
        run = _analysis_run(connection, analysis_id)
        if run.repository != oracle.repository or run.commit_id != oracle.commit:
            raise ValueError("RECALL_ORACLE_TARGET_MISMATCH")
        current = _current_findings(connection, data_dir, analysis_id)
        if review.inventory_reviewed and set(current) != {
            item.finding_id for item in review.findings
        }:
            raise ValueError("RECALL_REVIEW_INVENTORY_MISMATCH")
        for finding in review.findings:
            try:
                resolved = FindingDisplayIdStore.resolve_existing(
                    database, analysis_id, finding.finding_id
                )
            except (LookupError, ValueError, sqlite3.DatabaseError) as error:
                raise ValueError("RECALL_REVIEW_FINDING_STALE") from error
            item = current.get(finding.finding_id)
            if item is None or item[1] != resolved:
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
        stage_audit = audit_analysis(data_dir, analysis_id, vetted)
        by_case = {case.case_id: case for case in review.cases}
        scored: list[ScoredCase] = []
        counts: Counter[str] = Counter()
        for oracle_case, audit in zip(oracle.cases, stage_audit["cases"], strict=True):
            linked = by_case.get(oracle_case.case_id)
            if linked is not None and set(linked.candidate_ids) - set(
                audit["candidate_ids"]
            ):
                raise ValueError("RECALL_REVIEW_CANDIDATE_STALE")
            if oracle_case.scope == "OUT_OF_SCOPE":
                status = "OUT_OF_SCOPE"
            elif linked is None:
                status = "REVIEW_REQUIRED"
            elif (
                audit["status"] == "DETECTED"
                and linked.finding_ids
                and any(
                    _confirmed(
                        data_dir,
                        run,
                        current[finding_id][0],
                        oracle_case,
                        _hypothesis_stages(connection, run, current[finding_id][0]),
                    )
                    for finding_id in linked.finding_ids
                )
            ):
                status = "TP"
            elif audit["status"] == "MISSED" and review.inventory_reviewed:
                status = "FN"
            elif audit["status"] == "INCOMPLETE" and (
                str(audit["first_gap"]).startswith("HOLD_")
                or audit["first_gap"] in {"POC_EXECUTION_ERROR", "AGENT_ERROR"}
            ):
                status = "HOLD"
            else:
                status = "REVIEW_REQUIRED"
            counts[status] += 1
            scored.append(
                {
                    "case_id": oracle_case.case_id,
                    "status": status,
                    "first_gap": audit["first_gap"],
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
        }
    recall: float | None = None
    label: str | None = None
    if (
        oracle.completeness != "UNDECLARED"
        and review.inventory_reviewed
        and not counts["HOLD"]
        and not counts["REVIEW_REQUIRED"]
        and not finding_counts["UNMATCHED_REVIEW_REQUIRED"]
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
