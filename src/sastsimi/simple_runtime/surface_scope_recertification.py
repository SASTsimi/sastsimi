"""Additive, pinned-source recertification of a saved Python static scope."""

from __future__ import annotations

import hashlib
import subprocess
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.python_coverage_scope import out_of_scope_limits_python_coverage
from sastsimi.contracts.refs import StoredDataRef

from .attack_surfaces import StaticGap, SurfaceIndex, _static_gaps
from .facts import safe_tracked_file
from .models import CheckpointIdentity

_MAX_SOURCE_BYTES = 2 * 1024 * 1024


def _git(workspace: Path, *args: str) -> bytes:
    try:
        result = subprocess.run(
            ["git", "-C", str(workspace), *args],
            check=False,
            capture_output=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("SCOPE_RECERTIFICATION_GIT_UNAVAILABLE") from error
    if result.returncode:
        raise ValueError("SCOPE_RECERTIFICATION_GIT_UNAVAILABLE")
    return result.stdout


def _pinned_source_hash(
    workspace: Path, commit_id: str, path: str
) -> tuple[str | None, str]:
    source = safe_tracked_file(workspace, path)
    if source is None:
        return None, "SOURCE_MISSING_OR_UNSAFE"
    object_name = f"{commit_id}:{path}"
    try:
        size = int(_git(workspace, "cat-file", "-s", object_name).strip())
    except (ValueError, UnicodeError):
        return None, "PINNED_BLOB_UNAVAILABLE"
    if size > _MAX_SOURCE_BYTES:
        return None, "SOURCE_TOO_LARGE"
    try:
        pinned = _git(workspace, "cat-file", "blob", object_name)
        with source.open("rb") as stream:
            checkout = stream.read(_MAX_SOURCE_BYTES + 1)
    except (OSError, ValueError):
        return None, "SOURCE_MISSING_OR_UNSAFE"
    if len(checkout) > _MAX_SOURCE_BYTES or len(pinned) != size:
        return None, "SOURCE_TOO_LARGE"
    pinned_hash = hashlib.sha256(pinned).hexdigest()
    if hashlib.sha256(checkout).hexdigest() != pinned_hash:
        return None, "SOURCE_HASH_MISMATCH"
    return pinned_hash, "PINNED_MATCH"


def _out_of_scope_rows(coverage: Mapping[str, object]) -> list[dict[str, str]]:
    raw = coverage.get("out_of_scope_product_files")
    if not isinstance(raw, list):
        raise ValueError("SCOPE_RECERTIFICATION_COVERAGE_INVALID")
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for value in raw:
        if (
            not isinstance(value, dict)
            or not isinstance(value.get("path"), str)
            or not value["path"]
            or not isinstance(value.get("reason"), str)
            or not value["reason"]
        ):
            raise ValueError("SCOPE_RECERTIFICATION_COVERAGE_INVALID")
        pair = (value["path"], value["reason"])
        if pair in seen:
            raise ValueError("SCOPE_RECERTIFICATION_COVERAGE_INVALID")
        seen.add(pair)
        rows.append({"path": pair[0], "reason": pair[1]})
    return rows


def _coverage_gap_rows(coverage: Mapping[str, object]) -> list[dict[str, str]]:
    raw = coverage.get("gaps")
    if not isinstance(raw, list):
        raise ValueError("SCOPE_RECERTIFICATION_COVERAGE_INVALID")
    rows: list[dict[str, str]] = []
    for value in raw:
        if not isinstance(value, dict) or not all(
            isinstance(value.get(key), str) and value[key]
            for key in ("path", "rule_id", "reason")
        ):
            raise ValueError("SCOPE_RECERTIFICATION_COVERAGE_INVALID")
        rows.append({key: value[key] for key in ("path", "rule_id", "reason")})
    return rows


def build_python_scope_certificate(
    identity: CheckpointIdentity,
    index: SurfaceIndex,
    index_ref: StoredDataRef,
    coverage_ref: StoredDataRef,
    coverage: Mapping[str, object],
    workspace: Path,
) -> dict[str, object]:
    """Retain raw gaps, excluding only source-verified non-Python rows."""

    index_payload = index.to_json()
    if (
        identity.hypothesis_id is not None
        or index.commit_id != identity.commit_id
        or index.workspace_id != identity.workspace_id
        or index.index_version not in {1, 2}
        or str(index_ref.workspace_id) != identity.workspace_id
        or str(index_ref.commit_id) != identity.commit_id
        or str(coverage_ref.workspace_id) != identity.workspace_id
        or str(coverage_ref.commit_id) != identity.commit_id
        or index_ref.content_hash
        != hashlib.sha256(canonical_bytes(index_payload)).hexdigest()
        or coverage_ref.content_hash
        != hashlib.sha256(canonical_bytes(coverage)).hexdigest()
    ):
        raise ValueError("SCOPE_RECERTIFICATION_REFERENCE_INVALID")
    if (
        coverage.get("kind") != "simple_static_coverage_v1"
        or coverage.get("analysis_id") != identity.analysis_id
        or coverage.get("workspace_id") != identity.workspace_id
        or coverage.get("commit_id") != identity.commit_id
        or coverage.get("fingerprint") != index.scope_fingerprint
    ):
        raise ValueError("SCOPE_RECERTIFICATION_COVERAGE_INVALID")
    raw_exclusions = _out_of_scope_rows(coverage)
    coverage_gaps = _coverage_gap_rows(coverage)
    ast_errors = coverage.get("ast_parse_errors")
    ast_oversize = coverage.get("ast_oversize_paths")
    engine_errors = coverage.get("engine_errors")
    expected = coverage.get("expected_count")
    verified = coverage.get("verified_count")
    excluded_paths = coverage.get("excluded_paths")
    gap_pairs = {(row["path"], row["rule_id"]) for row in coverage_gaps}
    if (
        not isinstance(ast_errors, list)
        or any(not isinstance(path, str) or not path for path in ast_errors)
        or type(coverage.get("ast_parse_error_count")) is not int
        or coverage["ast_parse_error_count"] != len(ast_errors)
        or not isinstance(ast_oversize, list)
        or any(not isinstance(path, str) or not path for path in ast_oversize)
        or type(coverage.get("ast_oversize_count")) is not int
        or coverage["ast_oversize_count"] != len(ast_oversize)
        or type(coverage.get("ast_truncated")) is not bool
        or type(coverage.get("unavailable", False)) is not bool
        or (
            coverage.get("codeql_error") is not None
            and not isinstance(coverage["codeql_error"], str)
        )
        or not isinstance(engine_errors, list)
        or any(not isinstance(error, str) or not error for error in engine_errors)
        or type(expected) is not int
        or type(verified) is not int
        or expected < 0
        or verified < 0
        or verified > expected
        or expected - verified != len(coverage_gaps)
        or len(gap_pairs) != len(coverage_gaps)
        or any(
            not isinstance(coverage.get(field), list)
            for field in (
                "unsupported",
                "unsupported_files",
                "unavailable_paths",
            )
        )
        or not isinstance(excluded_paths, list)
        or any(not isinstance(path, str) or not path for path in excluded_paths)
    ):
        raise ValueError("SCOPE_RECERTIFICATION_COVERAGE_INVALID")
    try:
        derived_gaps = _static_gaps(
            coverage, {"parse_errors": ast_errors, "oversize_paths": ast_oversize}
        )
    except (AssertionError, TypeError, ValueError) as error:
        raise ValueError("SCOPE_RECERTIFICATION_COVERAGE_INVALID") from error
    if coverage.get("ast_truncated") is True:
        derived_gaps += (StaticGap("", "AST", "AST_TRUNCATED", "AST"),)
    derived_gaps += tuple(
        StaticGap("", "STATIC", f"ENGINE_ERROR:{error}") for error in engine_errors
    )
    commit = (
        _git(workspace, "rev-parse", "HEAD").decode("ascii", errors="strict").strip()
    )
    if commit != identity.commit_id:
        raise ValueError("SCOPE_RECERTIFICATION_COMMIT_MISMATCH")

    raw_gaps = index_payload["static_gaps"]
    if not isinstance(raw_gaps, list):
        raise ValueError("SCOPE_RECERTIFICATION_INDEX_INVALID")
    exclusions = {(row["path"], row["reason"]) for row in raw_exclusions}
    decisions: list[dict[str, Any]] = []
    by_pair: dict[tuple[str, str], dict[str, Any]] = {}
    for path, reason in sorted(
        exclusions
        | {(gap.path, gap.reason) for gap in index.static_gaps}
        | {(gap["path"], gap["reason"]) for gap in coverage_gaps}
        | {(gap.path, gap.reason) for gap in derived_gaps}
    ):
        source_sha256, verification = _pinned_source_hash(workspace, commit, path)
        excluded = (
            (path, reason) in exclusions
            and not out_of_scope_limits_python_coverage(path, reason)
            and source_sha256 is not None
        )
        row = {
            "path": path,
            "extension": Path(path).suffix.casefold(),
            "reason": reason,
            "source_sha256": source_sha256,
            "verification": verification,
            "decision": "OUT_OF_SCOPE" if excluded else "IN_SCOPE",
        }
        decisions.append(row)
        by_pair[(path, reason)] = row
    effective_gaps: list[dict[str, object]] = []
    seen_effective: set[tuple[str, str, str, str]] = set()
    for gap, serialized in zip(index.static_gaps, raw_gaps, strict=True):
        if (
            gap.rule_id == "STATIC_SCOPE"
            and gap.engine == "STATIC"
            and by_pair[(gap.path, gap.reason)]["decision"] == "OUT_OF_SCOPE"
        ):
            continue
        if not isinstance(serialized, dict):
            raise ValueError("SCOPE_RECERTIFICATION_INDEX_INVALID")
        effective_gaps.append(serialized)
        seen_effective.add((gap.path, gap.rule_id, gap.reason, gap.engine))
    for gap in derived_gaps:
        if (
            gap.rule_id == "STATIC_SCOPE"
            and gap.engine == "STATIC"
            and by_pair[(gap.path, gap.reason)]["decision"] == "OUT_OF_SCOPE"
        ):
            continue
        key = (gap.path, gap.rule_id, gap.reason, gap.engine)
        if key not in seen_effective:
            effective_gaps.append(
                {
                    "path": gap.path,
                    "rule_id": gap.rule_id,
                    "reason": gap.reason,
                    "engine": gap.engine,
                }
            )
            seen_effective.add(key)
    for path, reason in sorted(exclusions):
        if by_pair[(path, reason)]["decision"] == "OUT_OF_SCOPE":
            continue
        key = (path, "STATIC_SCOPE", reason, "STATIC")
        if key not in seen_effective:
            effective_gaps.append(
                {
                    "path": path,
                    "rule_id": "STATIC_SCOPE",
                    "reason": reason,
                    "engine": "STATIC",
                }
            )
            seen_effective.add(key)
    return {
        "kind": "simple_python_scope_recertification_v1",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "scope_fingerprint": index.scope_fingerprint,
        "index_ref": index_ref.model_dump(mode="json"),
        "coverage_ref": coverage_ref.model_dump(mode="json"),
        "index_hash": index_ref.content_hash,
        "raw_static_gaps": raw_gaps,
        "raw_coverage_gaps": deepcopy(coverage["gaps"]),
        "raw_out_of_scope_product_files": raw_exclusions,
        "file_decisions": decisions,
        "effective_static_gaps": effective_gaps,
    }
