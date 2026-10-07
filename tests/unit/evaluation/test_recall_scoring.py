"""Case-level recall and Finding-level FP review stay separate and read-only."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore
from sastsimi.simple_runtime.models import SimpleStage, StageCheckpoint
from sastsimi.simple_runtime.recall_audit import Oracle
from sastsimi.simple_runtime.recall_review import load_review
from sastsimi.simple_runtime.recall_scoring import score_analysis
from tests.unit.evaluation.test_recall_audit import (
    _candidate,
    _checkpoint,
    _link,
    _oracle,
    _saved_run,
    _verified_finding_chain,
)


def _v2_oracle(*, scope: str = "PYTHON") -> Oracle:
    legacy = _oracle()
    return replace(
        legacy,
        version=2,
        completeness="DOCUMENTED_CASES",
        cases=(replace(legacy.cases[0], scope=scope),),
    )


_ORACLE_BYTES = b"frozen-oracle-v2-test"


def _review(
    *,
    case_links: dict[str, list[str]] | None = None,
    finding_reviews: list[dict[str, str]] | None = None,
    inventory_reviewed: bool = True,
    analysis_id: str = "analysis-1",
    oracle_sha256: str | None = None,
) -> object:
    links = case_links or {}
    return load_review(
        json.dumps(
            {
                "version": 2,
                "analysis_id": analysis_id,
                "oracle_sha256": oracle_sha256
                or hashlib.sha256(_ORACLE_BYTES).hexdigest(),
                "inventory_reviewed": inventory_reviewed,
                "cases": [
                    {
                        "case_id": "sql-1",
                        "candidate_ids": links.get("candidate_ids", []),
                        "hypothesis_ids": links.get("hypothesis_ids", []),
                        "finding_ids": links.get("finding_ids", []),
                        "rationale": "checked source and executed PoC",
                    }
                ],
                "findings": finding_reviews or [],
            }
        ).encode("utf-8")
    )


def _finding_id(data_dir: Path, database: Path) -> str:
    _verified_finding_chain(data_dir, database)
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT checkpoint_json FROM simple_runtime_checkpoints "
            "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
            ("analysis-1", "hyp-1", SimpleStage.FINDING_DONE.value),
        ).fetchone()
    assert row is not None
    ref = StageCheckpoint.model_validate_json(row[0]).output_refs[0]
    return FindingDisplayIdStore(database).get_or_allocate("analysis-1", ref)


def test_verified_finding_is_one_case_tp_and_read_only(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    finding_id = _finding_id(data_dir, database)
    before = database.read_bytes()
    review = _review(
        case_links={
            "candidate_ids": ["candidate-1"],
            "hypothesis_ids": ["hyp-1"],
            "finding_ids": [finding_id],
        },
        finding_reviews=[
            {
                "finding_id": finding_id,
                "status": "MATCHED",
                "case_id": "sql-1",
                "evidence": "same request parameter and SQL execution",
            }
        ],
    )

    result = score_analysis(data_dir, "analysis-1", _v2_oracle(), _ORACLE_BYTES, review)

    assert result["case_counts"]["TP"] == 1
    assert result["finding_counts"]["FP"] == 0
    assert result["recall"] == 1.0
    assert database.read_bytes() == before


def test_reviewed_complete_python_miss_is_one_fn(tmp_path: Path) -> None:
    data_dir, _ = _saved_run(tmp_path)

    result = score_analysis(
        data_dir, "analysis-1", _v2_oracle(), _ORACLE_BYTES, _review()
    )

    assert result["case_counts"]["FN"] == 1
    assert result["recall"] == 0.0
    assert result["recall_label"] == "documented_cases"


def test_hold_and_out_of_scope_do_not_become_false_negatives(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    _checkpoint(database, SimpleStage.VERIFICATION_INITIAL_DONE, verdict="HOLD")
    review = _review(
        case_links={"candidate_ids": ["candidate-1"], "hypothesis_ids": ["hyp-1"]}
    )

    held = score_analysis(data_dir, "analysis-1", _v2_oracle(), _ORACLE_BYTES, review)
    excluded = score_analysis(
        data_dir, "analysis-1", _v2_oracle(scope="OUT_OF_SCOPE"), _ORACLE_BYTES, review
    )

    assert held["case_counts"]["HOLD"] == 1
    assert held["recall"] is None
    assert excluded["case_counts"]["OUT_OF_SCOPE"] == 1
    assert excluded["case_counts"]["FN"] == 0


def test_unmatched_finding_needs_review_not_false_positive(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    _finding_id(data_dir, database)

    result = score_analysis(
        data_dir,
        "analysis-1",
        _v2_oracle(),
        _ORACLE_BYTES,
        _review(inventory_reviewed=False),
    )

    assert result["finding_counts"]["FP"] == 0
    assert result["finding_counts"]["UNMATCHED_REVIEW_REQUIRED"] == 1
    assert result["recall"] is None


def test_explicit_current_false_positive_requires_evidence(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    finding_id = _finding_id(data_dir, database)
    review = _review(
        finding_reviews=[
            {
                "finding_id": finding_id,
                "status": "FALSE_POSITIVE",
                "evidence": "PoC reaches only a safe parameterized query",
            }
        ],
    )

    result = score_analysis(data_dir, "analysis-1", _v2_oracle(), _ORACLE_BYTES, review)

    assert result["finding_counts"]["FP"] == 1


def test_corrupt_current_finding_prevents_scoring(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    _finding_id(data_dir, database)
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT checkpoint_json FROM simple_runtime_checkpoints "
            "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
            ("analysis-1", "hyp-1", SimpleStage.POC_EXECUTION_DONE.value),
        ).fetchone()
    assert row is not None
    validated = StageCheckpoint.model_validate_json(row[0]).validated_poc_ref
    assert validated is not None
    artifact = (
        RuntimePaths(data_dir).artifacts
        / "sha256"
        / validated.content_hash[:2]
        / validated.content_hash[2:]
    )
    artifact.write_bytes(b"corrupt")

    with pytest.raises(ValueError, match="RECALL_REVIEW_FINDING_EVIDENCE_INVALID"):
        score_analysis(data_dir, "analysis-1", _v2_oracle(), _ORACLE_BYTES, _review())


@pytest.mark.parametrize(
    "review",
    [
        _review(analysis_id="another-analysis"),
        _review(oracle_sha256="b" * 64),
        _review(
            case_links={"finding_ids": ["F-999"]},
            finding_reviews=[
                {
                    "finding_id": "F-999",
                    "status": "MATCHED",
                    "case_id": "sql-1",
                    "evidence": "old report",
                }
            ],
        ),
    ],
)
def test_wrong_analysis_hash_or_stale_finding_fails_closed(
    tmp_path: Path, review: object
) -> None:
    data_dir, _ = _saved_run(tmp_path)

    with pytest.raises(ValueError, match="RECALL_REVIEW_"):
        score_analysis(data_dir, "analysis-1", _v2_oracle(), _ORACLE_BYTES, review)
