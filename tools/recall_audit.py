"""Compare an external, pinned oracle with a saved analysis (read-only)."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import ValidationError

# A script launched from tools/ does not otherwise see this checkout's src/.
# Prefer the adjacent source over a stale editable install from another worktree.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from sastsimi.simple_runtime.recall_audit import (  # noqa: E402
    Oracle,
    audit_analysis,
)
from sastsimi.simple_runtime.recall_oracle import parse_oracle_bytes  # noqa: E402
from sastsimi.simple_runtime.recall_review import load_review  # noqa: E402
from sastsimi.simple_runtime.recall_scoring import score_analysis  # noqa: E402


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
        return parse_oracle_bytes(payload)
    except ValidationError as error:
        raise _AuditInputError("RECALL_ORACLE_INVALID") from error


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
            "For legacy stage audit, set finding_inventory_reviewed=true in "
            "a case only after checking its complete Finding inventory; "
            "otherwise MISSED remains POSSIBLE with "
            "FINDING_INVENTORY_UNREVIEWED. For v2 --score, set "
            "inventory_reviewed=true in the separate review JSON, never in "
            "the frozen oracle."
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
