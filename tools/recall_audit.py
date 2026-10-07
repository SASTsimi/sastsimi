"""Compare an external, pinned oracle with a saved analysis (read-only)."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

# A script launched from tools/ does not otherwise see this checkout's src/.
# Prefer the adjacent source over a stale editable install from another worktree.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from sastsimi.simple_runtime.recall_audit import (  # noqa: E402
    Oracle,
    OracleCase,
    audit_analysis,
)
from sastsimi.simple_runtime.recall_review import load_review  # noqa: E402
from sastsimi.simple_runtime.recall_scoring import score_analysis  # noqa: E402


class _CaseInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    case_id: str = Field(min_length=1)
    cwe: str = Field(pattern=r"^CWE-[0-9]+$")
    path: str = Field(min_length=1)
    source_line: int | None = Field(ge=1)
    sink_line: int = Field(ge=1)
    rationale: str = Field(min_length=1)
    vetted_candidate_ids: tuple[str, ...] = ()
    vetted_hypothesis_ids: tuple[str, ...] = ()
    finding_inventory_reviewed: bool = False
    kind: Literal["FLOW", "MISSING_GUARD", "CONFIGURATION"] = "FLOW"
    sink_path: str | None = None
    scope: Literal["PYTHON", "OUT_OF_SCOPE"] = "PYTHON"


class _OracleInput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    repository: str = Field(min_length=1)
    commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    cases: tuple[_CaseInput, ...] = Field(min_length=1)
    version: Literal[1, 2] = 1
    completeness: Literal["UNDECLARED", "DOCUMENTED_CASES", "EXHAUSTIVE_PYTHON"] = (
        "UNDECLARED"
    )

    @model_validator(mode="after")
    def unique_case_ids(self) -> _OracleInput:
        case_ids = [case.case_id for case in self.cases]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("duplicate oracle case ID")
        if self.version == 2:
            for case in self.cases:
                if (
                    case.vetted_candidate_ids
                    or case.vetted_hypothesis_ids
                    or case.finding_inventory_reviewed
                ):
                    raise ValueError("v2 oracle must be frozen before review")
                for path in (case.path, case.sink_path):
                    if path is None:
                        continue
                    if (
                        path.startswith("/")
                        or "\\" in path
                        or ":" in path
                        or any(part in {"", ".", ".."} for part in path.split("/"))
                    ):
                        raise ValueError("unsafe oracle source path")
        return self


class _AuditInputError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)


def _oracle_bytes(path: Path) -> bytes:
    try:
        if path.stat().st_size > 1024 * 1024:
            raise _AuditInputError("RECALL_ORACLE_TOO_LARGE")
        return path.read_bytes()
    except FileNotFoundError as error:
        raise _AuditInputError("RECALL_ORACLE_NOT_FOUND") from error
    except OSError as error:
        raise _AuditInputError("RECALL_ORACLE_READ_FAILED") from error


def _parse_oracle(payload: bytes) -> Oracle:
    try:
        parsed = _OracleInput.model_validate_json(payload)
    except ValidationError as error:
        raise _AuditInputError("RECALL_ORACLE_INVALID") from error
    return Oracle(
        repository=parsed.repository,
        commit=parsed.commit,
        cases=tuple(
            OracleCase(
                case_id=case.case_id,
                cwe=case.cwe,
                path=case.path,
                source_line=case.source_line,
                sink_line=case.sink_line,
                rationale=case.rationale,
                vetted_candidate_ids=case.vetted_candidate_ids,
                vetted_hypothesis_ids=case.vetted_hypothesis_ids,
                finding_inventory_reviewed=case.finding_inventory_reviewed,
                kind=case.kind,
                sink_path=case.sink_path,
                scope=case.scope,
            )
            for case in parsed.cases
        ),
        version=parsed.version,
        completeness=parsed.completeness,
    )


def _load_oracle(path: Path) -> Oracle:
    return _parse_oracle(_oracle_bytes(path))


def _review_bytes(path: Path) -> bytes:
    try:
        if path.stat().st_size > 1024 * 1024:
            raise _AuditInputError("RECALL_REVIEW_TOO_LARGE")
        return path.read_bytes()
    except FileNotFoundError as error:
        raise _AuditInputError("RECALL_REVIEW_NOT_FOUND") from error
    except OSError as error:
        raise _AuditInputError("RECALL_REVIEW_READ_FAILED") from error


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            "Set finding_inventory_reviewed=true for a case only after manually "
            "checking its complete Finding inventory. A MISSED result requires "
            "that review; otherwise it reports POSSIBLE with "
            "FINDING_INVENTORY_UNREVIEWED."
        ),
    )
    parser.add_argument("--data-dir", required=True, type=Path)
    parser.add_argument("--analysis-id", required=True)
    parser.add_argument("--oracle", required=True, type=Path)
    parser.add_argument("--score", action="store_true", help="score a frozen v2 oracle")
    parser.add_argument("--review", type=Path, help="post-run human review JSON")
    arguments = parser.parse_args(argv)
    try:
        if bool(arguments.score) != (arguments.review is not None):
            raise _AuditInputError("RECALL_REVIEW_REQUIRED_FOR_SCORE")
        raw_oracle = _oracle_bytes(arguments.oracle)
        oracle = _parse_oracle(raw_oracle)
        if arguments.score:
            if oracle.version != 2:
                raise _AuditInputError("RECALL_SCORE_REQUIRES_V2_ORACLE")
            try:
                review = load_review(_review_bytes(arguments.review))
            except (ValidationError, ValueError) as error:
                raise _AuditInputError("RECALL_REVIEW_INVALID") from error
            score_result = score_analysis(
                arguments.data_dir,
                arguments.analysis_id,
                oracle,
                raw_oracle,
                review,
            )
            output = json.dumps(score_result, ensure_ascii=False, sort_keys=True)
        else:
            audit_result = audit_analysis(
                arguments.data_dir, arguments.analysis_id, oracle
            )
            output = json.dumps(audit_result, ensure_ascii=False, sort_keys=True)
    except _AuditInputError as error:
        print(str(error), file=sys.stderr)
        return 2
    except FileNotFoundError:
        print("RECALL_ANALYSIS_DB_MISSING", file=sys.stderr)
        return 2
    except (sqlite3.DatabaseError, ValidationError):
        print("RECALL_ANALYSIS_DATA_CORRUPT", file=sys.stderr)
        return 2
    except ValueError as error:
        code = str(error)
        if code not in {
            "RECALL_ANALYSIS_NOT_FOUND",
            "RECALL_ORACLE_TARGET_MISMATCH",
            "RECALL_CANDIDATE_ID_MISMATCH",
        }:
            if not code.startswith("RECALL_REVIEW_"):
                code = "RECALL_ANALYSIS_DATA_CORRUPT"
        print(code, file=sys.stderr)
        return 2
    except OSError:
        print("RECALL_ANALYSIS_READ_FAILED", file=sys.stderr)
        return 2
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
