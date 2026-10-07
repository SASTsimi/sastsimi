"""Case-level recall and Finding-level FP review stay separate and read-only."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import asdict, replace
from pathlib import Path
from typing import Literal

import pytest

import sastsimi.simple_runtime.recall_scoring as recall_scoring_module
from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.reporting.bundle_files import (
    MAX_BUNDLE_MANIFEST_BYTES,
    parse_bundle_manifest,
)
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attack_surfaces import StaticGap
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.recall_audit import (
    AuditResult,
    Oracle,
)
from sastsimi.simple_runtime.recall_audit import (
    audit_analysis as actual_audit_analysis,
)
from sastsimi.simple_runtime.recall_review import ReviewLedger, load_review
from sastsimi.simple_runtime.recall_scoring import score_analysis
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from tests.unit.evaluation.test_recall_audit import (
    _candidate,
    _checkpoint,
    _link,
    _oracle,
    _saved_run,
    _strict_proof_fixture,
    _verified_finding_chain,
)


def _v2_oracle(*, scope: Literal["PYTHON", "OUT_OF_SCOPE"] = "PYTHON") -> Oracle:
    legacy = _oracle()
    return replace(
        legacy,
        version=2,
        completeness="DOCUMENTED_CASES",
        cases=(replace(legacy.cases[0], scope=scope),),
    )


_ORACLE_BYTES = json.dumps(asdict(_v2_oracle())).encode("utf-8")


def _review(
    *,
    case_links: dict[str, list[str]] | None = None,
    finding_reviews: list[dict[str, str]] | None = None,
    inventory_reviewed: bool = True,
    analysis_id: str = "analysis-1",
    oracle_sha256: str | None = None,
) -> ReviewLedger:
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


def _complete_finding_terminal(
    data_dir: Path,
    database: Path,
    *,
    surface_gaps: tuple[StaticGap, ...] = (),
) -> None:
    _strict_proof_fixture(data_dir, database, surface_gaps=surface_gaps)
    store = SimpleCheckpointStore(database)
    run = store.require_analysis_run("analysis-1")
    assert run.candidate_terminal is not None
    store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_terminal": run.candidate_terminal.model_copy(
                    update={"hypothesis_count": 1}
                )
            }
        )
    )


def test_verified_finding_is_one_case_tp_and_read_only(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    finding_id = _finding_id(data_dir, database)
    _complete_finding_terminal(data_dir, database)
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


def test_verified_finding_rejects_broken_terminal_chaining_evidence(
    tmp_path: Path,
) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    finding_id = _finding_id(data_dir, database)
    _complete_finding_terminal(data_dir, database)
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM simple_chaining_pool_batches")
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

    with pytest.raises(ValueError, match="RECALL_REVIEW_TERMINAL_EVIDENCE_INVALID"):
        score_analysis(data_dir, "analysis-1", _v2_oracle(), _ORACLE_BYTES, review)


def test_confirmed_finding_with_python_static_gap_is_hold_not_tp(
    tmp_path: Path,
) -> None:
    data_dir, database = _saved_run(
        tmp_path,
        coverage_overrides={
            "verified_count": 0,
            "gaps": [{"path": "app.py", "rule_id": "r", "reason": "timeout"}],
        },
    )
    _candidate(data_dir, database)
    _link(database)
    finding_id = _finding_id(data_dir, database)
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

    assert result["case_counts"]["TP"] == 0
    assert result["case_counts"]["HOLD"] == 1
    assert result["cases"][0]["first_gap"] == "STATIC_EVIDENCE_UNVERIFIED"
    assert result["recall"] is None


def test_confirmed_finding_before_candidate_terminal_is_hold(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    finding_id = _finding_id(data_dir, database)
    store = SimpleCheckpointStore(database)
    run = store.require_analysis_run("analysis-1")
    assert run.candidate_terminal is not None
    store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_terminal": run.candidate_terminal.model_copy(
                    update={"producer_finished": False, "pending_child_count": 1}
                )
            }
        )
    )
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

    assert result["case_counts"]["TP"] == 0
    assert result["case_counts"]["HOLD"] == 1
    assert result["cases"][0]["first_gap"] == "PIPELINE_UNFINISHED"
    assert result["recall"] is None


def test_confirmed_finding_on_nonpython_only_partial_can_score_tp(
    tmp_path: Path,
) -> None:
    data_dir, database = _saved_run(
        tmp_path,
        terminal="PARTIAL",
        static_disposition="PARTIAL",
        coverage_overrides={
            "out_of_scope_product_files": [
                {"path": "frontend/app.ts", "reason": "non_python_product_source"}
            ]
        },
    )
    _candidate(data_dir, database)
    _link(database)
    finding_id = _finding_id(data_dir, database)
    _complete_finding_terminal(
        data_dir,
        database,
        surface_gaps=(
            StaticGap(
                path="frontend/app.ts",
                rule_id="STATIC_SCOPE",
                reason="non_python_product_source",
            ),
        ),
    )
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
    assert result["recall"] == 1.0


def test_unfinished_unrelated_report_suppresses_numeric_recall(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    finding_id = _finding_id(data_dir, database)
    _complete_finding_terminal(data_dir, database)
    second_identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hyp-2",
    )
    second_finding = SimpleArtifactRepository(data_dir, second_identity).put_json(
        {"kind": "simple_finding", "hypothesis_id": "hyp-2"}
    )
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT checkpoint_json FROM simple_runtime_checkpoints "
            "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
            ("analysis-1", "hyp-1", SimpleStage.FINDING_DONE.value),
        ).fetchone()
        assert row is not None
        copied = StageCheckpoint.model_validate_json(row[0]).model_copy(
            update={"identity": second_identity, "output_refs": (second_finding,)}
        )
        connection.execute(
            "INSERT INTO simple_runtime_checkpoints "
            "(analysis_id, hypothesis_key, stage, checkpoint_json, input_hash, "
            "updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                "analysis-1",
                "hyp-2",
                SimpleStage.FINDING_DONE.value,
                copied.model_dump_json(),
                copied.input_hash,
                copied.updated_at.isoformat(),
            ),
        )
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
    assert result["finding_counts"]["UNFINISHED_REPORTS"] == 1
    assert result["recall"] is None


def test_reviewed_complete_python_miss_is_one_fn(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    _strict_proof_fixture(data_dir, database)

    result = score_analysis(
        data_dir, "analysis-1", _v2_oracle(), _ORACLE_BYTES, _review()
    )

    assert result["case_counts"]["FN"] == 1
    assert result["recall"] == 0.0
    assert result["recall_label"] == "documented_cases"


def test_score_accepts_github_clone_suffix_for_same_pinned_repository(
    tmp_path: Path,
) -> None:
    data_dir, database = _saved_run(tmp_path)
    _strict_proof_fixture(data_dir, database)
    store = SimpleCheckpointStore(database)
    run = store.require_analysis_run("analysis-1")
    store.save_analysis_run(
        run.model_copy(update={"repository": "https://github.com/team/repo.git"})
    )
    oracle = replace(_v2_oracle(), repository="https://github.com/team/repo")
    oracle_bytes = json.dumps(asdict(oracle)).encode("utf-8")

    result = score_analysis(
        data_dir,
        "analysis-1",
        oracle,
        oracle_bytes,
        _review(oracle_sha256=hashlib.sha256(oracle_bytes).hexdigest()),
    )

    assert result["case_counts"]["FN"] == 1


def test_missing_terminal_batch_cannot_be_scored_as_false_negative(
    tmp_path: Path,
) -> None:
    data_dir, database = _saved_run(tmp_path)
    _strict_proof_fixture(data_dir, database)
    with sqlite3.connect(database) as connection:
        connection.execute("DELETE FROM simple_chaining_pool_batches")

    with pytest.raises(ValueError, match="RECALL_REVIEW_TERMINAL_EVIDENCE_INVALID"):
        score_analysis(data_dir, "analysis-1", _v2_oracle(), _ORACLE_BYTES, _review())


@pytest.mark.parametrize(
    ("stage_version", "workspace_id"),
    [
        ("obsolete-stage", "workspace-1"),
        (STAGE_VERSION[SimpleStage.FINDING_DONE], "old-workspace"),
    ],
)
def test_noncurrent_successful_finding_cannot_be_skipped_as_false_negative(
    tmp_path: Path, stage_version: str, workspace_id: str
) -> None:
    data_dir, database = _saved_run(tmp_path)
    _strict_proof_fixture(data_dir, database)
    checkpoint = StageCheckpoint(
        identity=CheckpointIdentity(
            analysis_id="analysis-1",
            workspace_id=workspace_id,
            commit_id="a" * 40,
            hypothesis_id="hyp-old",
        ),
        stage=SimpleStage.FINDING_DONE,
        stage_version=stage_version,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
    )
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO simple_runtime_checkpoints "
            "(analysis_id, hypothesis_key, stage, checkpoint_json, input_hash, "
            "updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                "analysis-1",
                "hyp-old",
                SimpleStage.FINDING_DONE.value,
                checkpoint.model_dump_json(),
                checkpoint.input_hash,
                checkpoint.updated_at.isoformat(),
            ),
        )

    with pytest.raises(ValueError, match="RECALL_REVIEW_FINDING_EVIDENCE_INVALID"):
        score_analysis(data_dir, "analysis-1", _v2_oracle(), _ORACLE_BYTES, _review())


@pytest.mark.parametrize("status", [StageStatus.RUNNING, StageStatus.FAILED])
def test_unfinished_finding_checkpoint_cannot_be_scored_as_false_negative(
    tmp_path: Path, status: StageStatus
) -> None:
    data_dir, database = _saved_run(tmp_path)
    _strict_proof_fixture(data_dir, database)
    checkpoint = StageCheckpoint(
        identity=CheckpointIdentity(
            analysis_id="analysis-1",
            workspace_id="workspace-1",
            commit_id="a" * 40,
            hypothesis_id="hyp-incomplete",
        ),
        stage=SimpleStage.FINDING_DONE,
        stage_version=STAGE_VERSION[SimpleStage.FINDING_DONE],
        status=status,
        input_refs=(),
        input_hash=input_reference_hash(()),
    )
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO simple_runtime_checkpoints "
            "(analysis_id, hypothesis_key, stage, checkpoint_json, input_hash, "
            "updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                "analysis-1",
                "hyp-incomplete",
                SimpleStage.FINDING_DONE.value,
                checkpoint.model_dump_json(),
                checkpoint.input_hash,
                checkpoint.updated_at.isoformat(),
            ),
        )

    result = score_analysis(
        data_dir, "analysis-1", _v2_oracle(), _ORACLE_BYTES, _review()
    )

    assert result["case_counts"]["HOLD"] == 1
    assert result["case_counts"]["FN"] == 0
    assert result["cases"][0]["first_gap"] == "REPORT_UNFINISHED"
    assert result["recall"] is None


def test_verified_python_miss_with_nonpython_out_of_scope_is_fn(
    tmp_path: Path,
) -> None:
    data_dir, database = _saved_run(
        tmp_path,
        terminal="PARTIAL",
        static_disposition="PARTIAL",
        coverage_overrides={
            "out_of_scope_product_files": [
                {"path": "frontend/app.ts", "reason": "non_python_product_source"}
            ]
        },
    )
    _strict_proof_fixture(
        data_dir,
        database,
        surface_gaps=(
            StaticGap(
                path="frontend/app.ts",
                rule_id="STATIC_SCOPE",
                reason="non_python_product_source",
            ),
        ),
    )

    result = score_analysis(
        data_dir, "analysis-1", _v2_oracle(), _ORACLE_BYTES, _review()
    )

    assert result["case_counts"]["FN"] == 1


def test_hold_and_out_of_scope_do_not_become_false_negatives(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    _checkpoint(database, SimpleStage.VERIFICATION_INITIAL_DONE, verdict="HOLD")
    review = _review(
        case_links={"candidate_ids": ["candidate-1"], "hypothesis_ids": ["hyp-1"]}
    )

    held = score_analysis(data_dir, "analysis-1", _v2_oracle(), _ORACLE_BYTES, review)
    excluded_oracle = _v2_oracle(scope="OUT_OF_SCOPE")
    excluded_bytes = json.dumps(asdict(excluded_oracle)).encode("utf-8")
    excluded = score_analysis(
        data_dir,
        "analysis-1",
        excluded_oracle,
        excluded_bytes,
        _review(oracle_sha256=hashlib.sha256(excluded_bytes).hexdigest()),
    )

    assert held["case_counts"]["HOLD"] == 1
    assert held["recall"] is None
    assert excluded["case_counts"]["OUT_OF_SCOPE"] == 1
    assert excluded["case_counts"]["FN"] == 0


def test_static_gap_is_hold_not_review_ambiguity(tmp_path: Path) -> None:
    data_dir, _ = _saved_run(
        tmp_path,
        coverage_overrides={
            "gaps": [{"path": "app.py", "rule_id": "r", "reason": "timeout"}]
        },
    )

    result = score_analysis(
        data_dir, "analysis-1", _v2_oracle(), _ORACLE_BYTES, _review()
    )

    assert result["case_counts"]["HOLD"] == 1
    assert result["recall"] is None


def test_terminal_inconclusive_deep_analysis_is_known_case_false_negative(
    tmp_path: Path,
) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database, deep_status="INCONCLUSIVE")
    _strict_proof_fixture(data_dir, database)

    result = score_analysis(
        data_dir,
        "analysis-1",
        _v2_oracle(),
        _ORACLE_BYTES,
        _review(case_links={"candidate_ids": ["candidate-1"]}),
    )

    assert result["case_counts"]["FN"] == 1
    assert result["cases"][0]["first_gap"] == "HYPOTHESIS"
    assert result["recall"] == 0.0


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


def test_reviewed_unmatched_finding_does_not_hide_documented_case_recall(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    finding_id = _finding_id(data_dir, database)
    monkeypatch.setattr(
        "sastsimi.simple_runtime.recall_scoring.audit_analysis",
        lambda *_args, **_kwargs: {
            "analysis_complete": True,
            "cases": [
                {
                    "case_id": "sql-1",
                    "status": "MISSED",
                    "first_gap": "STATIC_CANDIDATE",
                    "candidate_ids": [],
                    "vetted_candidate_ids": [],
                    "deep_states": {},
                }
            ],
        },
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.recall_scoring.strict_terminal_proof",
        lambda *_args: True,
        raising=False,
    )

    result = score_analysis(
        data_dir,
        "analysis-1",
        _v2_oracle(),
        _ORACLE_BYTES,
        _review(
            finding_reviews=[
                {
                    "finding_id": finding_id,
                    "status": "UNMATCHED_REVIEWED",
                    "evidence": "inventory reviewed; this finding is a different route",
                }
            ]
        ),
    )

    assert result["case_counts"]["FN"] == 1
    assert result["finding_counts"]["UNMATCHED_REVIEW_REQUIRED"] == 1
    assert result["recall"] == 0.0


def test_verified_finding_without_display_id_blocks_inventory_score(
    tmp_path: Path,
) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    _verified_finding_chain(data_dir, database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "DELETE FROM finding_display_ids WHERE analysis_id = ?",
            ("analysis-1",),
        )

    with pytest.raises(ValueError, match="RECALL_REVIEW_FINDING_DISPLAY_MISSING"):
        score_analysis(data_dir, "analysis-1", _v2_oracle(), _ORACLE_BYTES, _review())


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


def test_corrupt_report_archive_prevents_verified_finding_score(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    _verified_finding_chain(data_dir, database)
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT checkpoint_json FROM simple_runtime_checkpoints "
            "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
            ("analysis-1", "hyp-1", SimpleStage.REPORT_DONE.value),
        ).fetchone()
    assert row is not None
    archive_ref = StageCheckpoint.model_validate_json(row[0]).bundle_archive_ref
    assert archive_ref is not None
    archive_path = (
        RuntimePaths(data_dir).artifacts
        / "sha256"
        / archive_ref.content_hash[:2]
        / archive_ref.content_hash[2:]
    )
    archive_path.write_bytes(b"corrupt")

    with pytest.raises(ValueError, match="RECALL_REVIEW_FINDING_EVIDENCE_INVALID"):
        score_analysis(
            data_dir,
            "analysis-1",
            _v2_oracle(),
            _ORACLE_BYTES,
            _review(inventory_reviewed=False),
        )


@pytest.mark.parametrize("member", ["manifest.json", "bundle.zip"])
def test_corrupt_published_bundle_prevents_verified_finding_score(
    tmp_path: Path, member: str
) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    _verified_finding_chain(data_dir, database)
    published = data_dir / "reports" / "analysis-1" / "F-001" / member
    published.write_bytes(b"corrupt")

    with pytest.raises(ValueError, match="RECALL_REVIEW_FINDING_EVIDENCE_INVALID"):
        score_analysis(
            data_dir,
            "analysis-1",
            _v2_oracle(),
            _ORACLE_BYTES,
            _review(inventory_reviewed=False),
        )


def test_corrupt_report_member_prevents_verified_finding_score(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    _verified_finding_chain(data_dir, database)
    with sqlite3.connect(database) as connection:
        report_row = connection.execute(
            "SELECT checkpoint_json FROM simple_runtime_checkpoints "
            "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
            ("analysis-1", "hyp-1", SimpleStage.REPORT_DONE.value),
        ).fetchone()
        finding_row = connection.execute(
            "SELECT checkpoint_json FROM simple_runtime_checkpoints "
            "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
            ("analysis-1", "hyp-1", SimpleStage.FINDING_DONE.value),
        ).fetchone()
    assert report_row is not None and finding_row is not None
    report = StageCheckpoint.model_validate_json(report_row[0])
    finding_ref = StageCheckpoint.model_validate_json(finding_row[0]).output_refs[0]
    assert report.bundle_manifest_ref is not None
    artifacts = SimpleArtifactRepository(data_dir, report.identity, create_dirs=False)
    manifest = parse_bundle_manifest(
        artifacts.read_bounded(report.bundle_manifest_ref, MAX_BUNDLE_MANIFEST_BYTES),
        finding_ref=finding_ref,
    )
    member_ref = next(
        entry.artifact_ref for entry in manifest.files if entry.path == "report_en.md"
    )
    member_path = (
        RuntimePaths(data_dir).artifacts
        / "sha256"
        / member_ref.content_hash[:2]
        / member_ref.content_hash[2:]
    )
    member_path.write_bytes(b"corrupt")

    with pytest.raises(ValueError, match="RECALL_REVIEW_FINDING_EVIDENCE_INVALID"):
        score_analysis(
            data_dir,
            "analysis-1",
            _v2_oracle(),
            _ORACLE_BYTES,
            _review(inventory_reviewed=False),
        )


def test_superseded_report_coverage_prevents_verified_finding_score(
    tmp_path: Path,
) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    _verified_finding_chain(data_dir, database, stale_report_coverage=True)

    with pytest.raises(ValueError, match="RECALL_REVIEW_FINDING_EVIDENCE_INVALID"):
        score_analysis(
            data_dir,
            "analysis-1",
            _v2_oracle(),
            _ORACLE_BYTES,
            _review(inventory_reviewed=False),
        )


def test_report_bundle_display_id_must_match_current_finding_id(
    tmp_path: Path,
) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    _verified_finding_chain(data_dir, database, wrong_bundle_display_id=True)

    with pytest.raises(ValueError, match="RECALL_REVIEW_FINDING_EVIDENCE_INVALID"):
        score_analysis(
            data_dir,
            "analysis-1",
            _v2_oracle(),
            _ORACLE_BYTES,
            _review(inventory_reviewed=False),
        )


def test_duplicate_display_rows_for_one_finding_ref_refuse_score(
    tmp_path: Path,
) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    _finding_id(data_dir, database)
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT finding_hash, finding_ref_json FROM finding_display_ids "
            "WHERE analysis_id = ?",
            ("analysis-1",),
        ).fetchone()
        assert row is not None
        wrong_hash = "f" * 64 if row[0] != "f" * 64 else "e" * 64
        connection.execute(
            "INSERT INTO finding_display_ids "
            "(analysis_id, finding_hash, finding_ref_json, display_number) "
            "VALUES (?, ?, ?, ?)",
            ("analysis-1", wrong_hash, row[1], 2),
        )

    with pytest.raises(ValueError, match="RECALL_REVIEW_FINDING_"):
        score_analysis(
            data_dir,
            "analysis-1",
            _v2_oracle(),
            _ORACLE_BYTES,
            _review(inventory_reviewed=False),
        )


def test_display_row_hash_must_match_exact_finding_ref(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    _finding_id(data_dir, database)
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT finding_hash FROM finding_display_ids WHERE analysis_id = ?",
            ("analysis-1",),
        ).fetchone()
        assert row is not None
        wrong_hash = "f" * 64 if row[0] != "f" * 64 else "e" * 64
        connection.execute(
            "UPDATE finding_display_ids SET finding_hash = ? WHERE analysis_id = ?",
            (wrong_hash, "analysis-1"),
        )

    with pytest.raises(ValueError, match="RECALL_REVIEW_FINDING_DISPLAY_MISSING"):
        score_analysis(
            data_dir,
            "analysis-1",
            _v2_oracle(),
            _ORACLE_BYTES,
            _review(inventory_reviewed=False),
        )


def test_failed_report_after_finding_is_hold_not_corrupt_inventory(
    tmp_path: Path,
) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    _finding_id(data_dir, database)
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT checkpoint_json FROM simple_runtime_checkpoints "
            "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
            ("analysis-1", "hyp-1", SimpleStage.REPORT_DONE.value),
        ).fetchone()
        assert row is not None
        checkpoint = StageCheckpoint.model_validate_json(row[0]).model_copy(
            update={"status": StageStatus.FAILED}
        )
        connection.execute(
            "UPDATE simple_runtime_checkpoints SET checkpoint_json = ? "
            "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
            (
                checkpoint.model_dump_json(),
                "analysis-1",
                "hyp-1",
                SimpleStage.REPORT_DONE.value,
            ),
        )

    result = score_analysis(
        data_dir, "analysis-1", _v2_oracle(), _ORACLE_BYTES, _review()
    )

    assert result["case_counts"]["HOLD"] == 1
    assert result["case_counts"]["FN"] == 0
    assert result["cases"][0]["first_gap"] == "REPORT_UNFINISHED"
    assert result["recall"] is None


def test_corrupt_static_artifact_refuses_numeric_score(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    run = SimpleCheckpointStore(database).require_analysis_run("analysis-1")
    ref = run.static_coverage_ref
    assert ref is not None
    artifact = (
        RuntimePaths(data_dir).artifacts
        / "sha256"
        / ref.content_hash[:2]
        / ref.content_hash[2:]
    )
    artifact.write_bytes(b"corrupt")

    with pytest.raises(ValueError, match="RECALL_REVIEW_STATIC_EVIDENCE_INVALID"):
        score_analysis(data_dir, "analysis-1", _v2_oracle(), _ORACLE_BYTES, _review())


def test_normal_static_coverage_may_omit_unavailable_field(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    store = SimpleCheckpointStore(database)
    run = store.require_analysis_run("analysis-1")
    assert run.static_coverage_ref is not None
    assert run.static_bundle_ref is not None
    assert run.candidate_terminal is not None
    artifacts = SimpleArtifactRepository(
        data_dir,
        CheckpointIdentity(
            analysis_id="analysis-1",
            workspace_id="workspace-1",
            commit_id="a" * 40,
            hypothesis_id=None,
        ),
    )
    coverage = json.loads(artifacts.read(run.static_coverage_ref))
    assert coverage.pop("unavailable") is False
    coverage_ref = artifacts.put_json(coverage)
    bundle = json.loads(artifacts.read(run.static_bundle_ref))
    bundle["static_coverage_ref"] = coverage_ref.model_dump(mode="json")
    bundle_ref = artifacts.put_json(bundle)
    store.save_analysis_run(
        run.model_copy(
            update={
                "static_coverage_ref": coverage_ref,
                "static_bundle_ref": bundle_ref,
                "candidate_terminal": run.candidate_terminal.model_copy(
                    update={"bundle_hash": bundle_ref.content_hash}
                ),
            }
        )
    )
    with sqlite3.connect(database) as connection:
        for stage in (SimpleStage.STATIC_DONE, SimpleStage.HYPOTHESIS_DONE):
            row = connection.execute(
                "SELECT checkpoint_json FROM simple_runtime_checkpoints "
                "WHERE analysis_id = ? AND hypothesis_key = '' AND stage = ?",
                ("analysis-1", stage.value),
            ).fetchone()
            assert row is not None
            checkpoint = StageCheckpoint.model_validate_json(row[0])
            replacement = (
                checkpoint.model_copy(
                    update={"output_refs": (coverage_ref, bundle_ref)}
                )
                if stage is SimpleStage.STATIC_DONE
                else checkpoint.model_copy(
                    update={
                        "input_refs": (bundle_ref,),
                        "input_hash": input_reference_hash((bundle_ref,)),
                    }
                )
            )
            connection.execute(
                "UPDATE simple_runtime_checkpoints SET checkpoint_json = ?, "
                "input_hash = ? WHERE analysis_id = ? AND hypothesis_key = '' "
                "AND stage = ?",
                (
                    replacement.model_dump_json(),
                    replacement.input_hash,
                    "analysis-1",
                    stage.value,
                ),
            )

    result = score_analysis(
        data_dir,
        "analysis-1",
        _v2_oracle(),
        _ORACLE_BYTES,
        _review(inventory_reviewed=False),
    )

    assert result["case_counts"]["REVIEW_REQUIRED"] == 1


@pytest.mark.parametrize(
    "coverage_overrides",
    [
        {"analysis_id": "other-analysis"},
        {"fingerprint": "different-scope"},
        {"expected_count": "1"},
    ],
)
def test_semantically_invalid_static_coverage_refuses_score(
    tmp_path: Path, coverage_overrides: dict[str, object]
) -> None:
    data_dir, _ = _saved_run(tmp_path, coverage_overrides=coverage_overrides)

    with pytest.raises(ValueError, match="RECALL_REVIEW_STATIC_EVIDENCE_INVALID"):
        score_analysis(data_dir, "analysis-1", _v2_oracle(), _ORACLE_BYTES, _review())


def test_score_does_not_recreate_missing_runtime_directories(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    finding_id = _finding_id(data_dir, database)
    staging = RuntimePaths(data_dir).staging
    assert staging.is_dir()
    staging.rename(data_dir / "staging-saved")
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
                "evidence": "reviewed same flow",
            }
        ],
    )

    score_analysis(data_dir, "analysis-1", _v2_oracle(), _ORACLE_BYTES, review)

    assert not staging.exists()


def test_score_audit_uses_same_sqlite_read_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir, database = _saved_run(tmp_path)
    _strict_proof_fixture(data_dir, database)

    def observe_audit(
        data_dir: Path,
        analysis_id: str,
        oracle: Oracle,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> AuditResult:
        assert isinstance(connection, sqlite3.Connection)
        assert connection.in_transaction
        return actual_audit_analysis(
            data_dir, analysis_id, oracle, connection=connection
        )

    monkeypatch.setattr(recall_scoring_module, "audit_analysis", observe_audit)
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
    tmp_path: Path, review: ReviewLedger
) -> None:
    data_dir, _ = _saved_run(tmp_path)

    with pytest.raises(ValueError, match="RECALL_REVIEW_"):
        score_analysis(data_dir, "analysis-1", _v2_oracle(), _ORACLE_BYTES, review)


def test_oracle_object_must_match_hashed_bytes(tmp_path: Path) -> None:
    data_dir, _ = _saved_run(tmp_path)
    altered = _v2_oracle(scope="OUT_OF_SCOPE")

    with pytest.raises(ValueError, match="RECALL_REVIEW_ORACLE_BINDING_INVALID"):
        score_analysis(data_dir, "analysis-1", altered, _ORACLE_BYTES, _review())
