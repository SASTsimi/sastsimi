"""Small factual report projection of a hash-verified static coverage artifact."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Literal

from sastsimi.contracts.refs import StoredDataRef


@dataclass(frozen=True, slots=True)
class CoverageDisclosure:
    ref: StoredDataRef
    fingerprint: str
    expected_count: int
    verified_count: int
    gap_count: int
    unsupported_count: int
    gap_reasons: tuple[tuple[str, int], ...]
    unsupported_reasons: tuple[tuple[str, int], ...]
    engine_errors: tuple[str, ...]
    disposition: Literal["FULL", "PARTIAL"] | None = None

    @property
    def partial(self) -> bool:
        if self.disposition is not None:
            return self.disposition == "PARTIAL"
        return bool(self.gap_count or self.unsupported_count or self.engine_errors)


def coverage_disclosure(
    data: Mapping[str, object],
    ref: StoredDataRef,
    *,
    analysis_id: str,
    workspace_id: str,
    commit_id: str,
    disposition: Literal["FULL", "PARTIAL"] | None = None,
) -> CoverageDisclosure:
    """Project exact limitations while rejecting malformed or cross-run evidence."""

    if (
        data.get("kind") != "simple_static_coverage_v1"
        or data.get("analysis_id") != analysis_id
        or data.get("workspace_id") != workspace_id
        or data.get("commit_id") != commit_id
        or str(ref.workspace_id) != workspace_id
        or str(ref.commit_id) != commit_id
    ):
        raise ValueError("REPORT_STATIC_COVERAGE_SCOPE_INVALID")
    expected = data.get("expected_count")
    verified = data.get("verified_count")
    fingerprint = data.get("fingerprint")
    gaps = data.get("gaps")
    unsupported = data.get("unsupported_files")
    errors = data.get("engine_errors", [])
    if (
        not isinstance(expected, int)
        or isinstance(expected, bool)
        or not isinstance(verified, int)
        or isinstance(verified, bool)
        or not 0 <= verified <= expected
        or not isinstance(fingerprint, str)
        or re.fullmatch(r"[0-9a-f]{64}", fingerprint) is None
        or not isinstance(gaps, list)
        or not isinstance(unsupported, list)
        or not isinstance(errors, list)
    ):
        raise ValueError("REPORT_STATIC_COVERAGE_INVALID")

    def reasons(rows: list[object]) -> tuple[tuple[str, int], ...]:
        result: Counter[str] = Counter()
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError("REPORT_STATIC_COVERAGE_INVALID")
            reason = row.get("reason")
            if not isinstance(reason, str) or not reason or len(reason) > 128:
                raise ValueError("REPORT_STATIC_COVERAGE_INVALID")
            result[reason] += 1
        return tuple(sorted(result.items()))

    gap_reasons = reasons(gaps)
    unsupported_reasons = reasons(unsupported)
    errors = list(errors)
    if data.get("ast_parse_error_count", 0):
        errors.append("ast_parse_errors")
    if data.get("ast_truncated", False):
        errors.append("ast_truncated")
    if data.get("ast_oversize_count", 0):
        errors.append("ast_oversize_files")
    if data.get("codeql_error"):
        errors.append("codeql_error")
    if len(gaps) != expected - verified or len(errors) > 32 or any(
        not isinstance(item, str) or not item or len(item) > 128 for item in errors
    ):
        raise ValueError("REPORT_STATIC_COVERAGE_INVALID")
    if disposition == "FULL" and (
        gaps
        or unsupported
        or data.get("ast_parse_error_count", 0)
        or data.get("ast_oversize_count", 0)
        or data.get("codeql_error")
    ):
        raise ValueError("REPORT_STATIC_COVERAGE_DISPOSITION_INVALID")
    return CoverageDisclosure(
        ref=ref,
        fingerprint=fingerprint,
        expected_count=expected,
        verified_count=verified,
        gap_count=len(gaps),
        unsupported_count=len(unsupported),
        gap_reasons=gap_reasons,
        unsupported_reasons=unsupported_reasons,
        engine_errors=tuple(sorted(set(errors))),
        disposition=disposition,
    )
