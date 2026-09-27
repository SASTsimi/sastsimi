"""Versioned, fail-closed coverage accounting for configured static rules."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, deque
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .opengrep_rule_batches import RuleBatch, RuleBatchPlan, parse_rule_batch

_SNIPPET_LIMIT = 500

_POLICY_VERSION = 1
_LANGUAGE_EXTENSIONS: dict[str, frozenset[str]] = {
    "python": frozenset({".py", ".pyi"}),
    "javascript": frozenset(
        {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
    ),
    "typescript": frozenset({".ts", ".tsx", ".mts", ".cts"}),
}
_KNOWN_SOURCE_EXTENSIONS = frozenset(
    {
        ".go",
        ".java",
        ".rs",
        ".rb",
        ".php",
        ".cs",
        ".cpp",
        ".cc",
        ".c",
        ".h",
        ".hpp",
        ".swift",
        ".kt",
        ".scala",
        ".sh",
        ".ps1",
        ".vue",
        ".svelte",
        ".lua",
        ".ex",
        ".exs",
        ".dart",
        ".sql",
    }
)

Pair = tuple[str, str]


@dataclass(frozen=True, slots=True)
class StaticCoveragePlan:
    workspace: Path
    fingerprint: str
    expected_pairs: frozenset[Pair]
    unavailable_pairs: frozenset[Pair]
    unsupported: tuple[tuple[str, int], ...]
    excluded_paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CoverageSlice:
    engine: Literal["opengrep", "semgrep"]
    batch_key: str
    rule_ids: tuple[str, ...]
    verified_pairs: frozenset[Pair]
    gap_reasons: tuple[tuple[str, str, str], ...]
    parsed: dict[str, object]
    normalized_results: tuple[dict[str, object], ...]
    raw_ref: StoredDataRef | None = None


@dataclass(frozen=True, slots=True)
class CoverageGap:
    path: str
    rule_id: str
    reason: str


@dataclass(frozen=True, slots=True)
class StaticCoverageReport:
    fingerprint: str
    expected_count: int
    verified_count: int
    gaps: tuple[CoverageGap, ...]
    unsupported: tuple[tuple[str, int], ...]
    excluded_paths: tuple[str, ...]

    def to_json(self) -> dict[str, object]:
        return {
            "kind": "simple_static_coverage_v1",
            "fingerprint": self.fingerprint,
            "expected_count": self.expected_count,
            "verified_count": self.verified_count,
            "gaps": [
                {"path": item.path, "rule_id": item.rule_id, "reason": item.reason}
                for item in self.gaps
            ],
            "unsupported": [
                {"extension": extension, "file_count": count}
                for extension, count in self.unsupported
            ],
            "excluded_paths": list(self.excluded_paths),
        }


def _safe_relative(workspace: Path, raw: str) -> str | None:
    if not raw or "\x00" in raw:
        return None
    root = workspace.resolve()
    supplied = Path(raw.replace("/", "\\"))
    candidate = supplied if supplied.is_absolute() else root / supplied
    try:
        if candidate.is_symlink():
            return None
        resolved = candidate.resolve(strict=True)
        relative = resolved.relative_to(root)
        if not resolved.is_file():
            return None
    except (OSError, RuntimeError, ValueError):
        return None
    return relative.as_posix()


def plan_static_coverage(
    workspace: Path,
    tracked: Sequence[str],
    commit_id: str,
    rules: RuleBatchPlan,
    *,
    fallback_tool_fingerprint: str | None = None,
) -> StaticCoveragePlan:
    """Bind applicable pairs to one checkout, rule catalog, and scanner digest."""

    if len(rules.rule_ids) != len(rules.rule_languages):
        raise ValueError("STATIC_COVERAGE_RULE_METADATA_INVALID")
    if any(
        language not in _LANGUAGE_EXTENSIONS
        for languages in rules.rule_languages
        for language in languages
    ):
        raise ValueError("STATIC_COVERAGE_LANGUAGE_UNSUPPORTED")
    pairs: set[Pair] = set()
    unavailable_pairs: set[Pair] = set()
    excluded: set[str] = set()
    unsupported: Counter[str] = Counter()
    known = frozenset().union(*_LANGUAGE_EXTENSIONS.values())
    for raw in sorted(set(tracked)):
        if (
            not raw
            or "\\" in raw
            or ":" in raw
            or any(ord(character) < 32 for character in raw)
            or any(part in {"", ".", ".."} for part in raw.split("/"))
            or Path(raw).is_absolute()
        ):
            raise ValueError("STATIC_COVERAGE_TRACKED_PATH_INVALID")
        relative = _safe_relative(workspace, raw)
        if relative is None:
            excluded.add(raw)
            relative = raw
            unavailable = True
        else:
            unavailable = False
        extension = Path(relative).suffix.lower()
        matched = False
        for rule_id, languages in zip(
            rules.rule_ids, rules.rule_languages, strict=True
        ):
            if any(
                extension in _LANGUAGE_EXTENSIONS.get(language, ())
                for language in languages
            ):
                pairs.add((relative, rule_id))
                if unavailable:
                    unavailable_pairs.add((relative, rule_id))
                matched = True
        if not matched and extension in _KNOWN_SOURCE_EXTENSIONS | known:
            unsupported[extension] += 1
    fingerprint = hashlib.sha256(
        canonical_bytes(
            {
                "version": _POLICY_VERSION,
                "commit_id": commit_id,
                "tracked": sorted(set(tracked)),
                "rules_fingerprint": rules.fingerprint,
                "fallback_tool_fingerprint": fallback_tool_fingerprint,
                "language_extensions": {
                    key: sorted(value)
                    for key, value in sorted(_LANGUAGE_EXTENSIONS.items())
                },
            }
        )
    ).hexdigest()
    return StaticCoveragePlan(
        workspace=workspace.resolve(),
        fingerprint=fingerprint,
        expected_pairs=frozenset(pairs),
        unavailable_pairs=frozenset(unavailable_pairs),
        unsupported=tuple(sorted(unsupported.items())),
        excluded_paths=tuple(sorted(excluded)),
    )


def _paths(value: object, workspace: Path) -> set[str]:
    if not isinstance(value, list):
        raise ValueError("STATIC_SCAN_PATHS_INVALID")
    paths: set[str] = set()
    for item in value:
        raw = item.get("path") if isinstance(item, dict) else item
        if not isinstance(raw, str):
            raise ValueError("STATIC_SCAN_PATHS_INVALID")
        path = _safe_relative(workspace, raw)
        if path is None:
            raise ValueError("STATIC_SCAN_PATHS_INVALID")
        paths.add(path)
    return paths


def assess_scan(
    plan: StaticCoveragePlan,
    batch: RuleBatch,
    raw: bytes,
    *,
    engine: Literal["opengrep", "semgrep"],
    targets: Sequence[str] | None = None,
) -> CoverageSlice:
    """Only explicit, error-free scanned paths earn this batch's rule coverage."""

    parsed = parse_rule_batch(raw, batch, allow_errors=True)
    paths = parsed.get("paths")
    if not isinstance(paths, dict):
        raise ValueError("STATIC_SCAN_PATHS_INVALID")
    scanned = _paths(paths.get("scanned"), plan.workspace)
    skipped = _paths(paths.get("skipped", []), plan.workspace)
    target_set = _paths(list(targets), plan.workspace) if targets is not None else None
    allowed = {
        pair
        for pair in plan.expected_pairs
        if pair not in plan.unavailable_pairs
        and pair[1] in batch.rule_ids
        and (target_set is None or pair[0] in target_set)
    }
    reasons: dict[Pair, str] = {}
    errors = parsed.get("errors", [])
    assert isinstance(errors, list)
    for raw_error in errors:
        error = cast(dict[str, object], raw_error)
        path_value = error.get("path")
        path = (
            _safe_relative(plan.workspace, path_value)
            if isinstance(path_value, str)
            else None
        )
        if path is None:
            for pair in allowed:
                reasons[pair] = "unlocated_scan_error"
            continue
        for pair in allowed:
            if pair[0] == path:
                reasons[pair] = "parse_or_scan_error"
    skipped_rules = parsed.get("skipped_rules", [])
    if not isinstance(skipped_rules, list):
        raise ValueError("STATIC_SCAN_RULES_INVALID")
    for item in skipped_rules:
        rule_id = item.get("id") if isinstance(item, dict) else item
        if not isinstance(rule_id, str) or rule_id not in batch.rule_ids:
            raise ValueError("STATIC_SCAN_RULES_INVALID")
        for pair in allowed:
            if pair[1] == rule_id:
                reasons[pair] = "skipped_rule"
    for path in skipped:
        for pair in allowed:
            if pair[0] == path:
                reasons[pair] = "skipped_file"
    verified = frozenset(
        pair for pair in allowed if pair[0] in scanned and pair not in reasons
    )
    normalized_results: list[dict[str, object]] = []
    for result in cast(list[dict[str, object]], parsed["results"]):
        path_value = result["path"]
        relative = (
            _safe_relative(plan.workspace, path_value)
            if isinstance(path_value, str)
            else None
        )
        if relative is None:
            raise ValueError("STATIC_SCAN_RESULT_PATH_INVALID")
        pair = (relative, cast(str, result["check_id"]))
        if pair in allowed:
            normalized_results.append(
                {
                    **result,
                    "path": relative,
                    "scan_incomplete": pair not in verified,
                }
            )
    return CoverageSlice(
        engine=engine,
        batch_key=batch.key,
        rule_ids=batch.rule_ids,
        verified_pairs=verified,
        gap_reasons=tuple(
            sorted(
                (path, rule_id, reason) for (path, rule_id), reason in reasons.items()
            )
        ),
        parsed=parsed,
        normalized_results=tuple(normalized_results),
    )


def finish_coverage(
    plan: StaticCoveragePlan, slices: Sequence[CoverageSlice]
) -> StaticCoverageReport:
    verified = (
        set().union(*(slice_.verified_pairs for slice_ in slices)) if slices else set()
    )
    verified &= plan.expected_pairs - plan.unavailable_pairs
    reasons = {
        (path, rule_id): reason
        for slice_ in slices
        for path, rule_id, reason in slice_.gap_reasons
    }
    gaps = tuple(
        CoverageGap(
            path,
            rule_id,
            "source_unavailable"
            if (path, rule_id) in plan.unavailable_pairs
            else reasons.get((path, rule_id), "not_scanned"),
        )
        for path, rule_id in sorted(plan.expected_pairs - verified)
    )
    return StaticCoverageReport(
        fingerprint=plan.fingerprint,
        expected_count=len(plan.expected_pairs),
        verified_count=len(verified),
        gaps=gaps,
        unsupported=plan.unsupported,
        excluded_paths=plan.excluded_paths,
    )


def _candidate_hit_key(item: dict[str, object]) -> tuple[str, int, str]:
    path = item.get("path")
    start = item.get("start")
    line = start.get("line") if isinstance(start, dict) else None
    encoded = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
    return (
        path if isinstance(path, str) else "",
        line if type(line) is int else 0,
        encoded,
    )


def merge_static_candidates(
    plan: RuleBatchPlan, slices: Sequence[CoverageSlice]
) -> bytes:
    """Deduplicate verified hits while preserving fair per-rule visibility."""

    buckets: dict[str, deque[dict[str, object]]] = {
        rule_id: deque() for rule_id in plan.rule_ids
    }
    seen: dict[tuple[str, str, str, str], dict[str, object]] = {}
    batches: list[dict[str, object]] = []
    for slice_ in slices:
        for item in sorted(slice_.normalized_results, key=_candidate_hit_key):
            rule_id = item.get("check_id")
            path = item.get("path")
            start = item.get("start")
            line = start.get("line") if isinstance(start, dict) else None
            if (
                not isinstance(rule_id, str)
                or rule_id not in buckets
                or not isinstance(path, str)
                or type(line) is not int
            ):
                raise ValueError("STATIC_CANDIDATE_INVALID")
            key = (
                rule_id,
                path,
                json.dumps(start, ensure_ascii=False, sort_keys=True),
                json.dumps(item.get("end"), ensure_ascii=False, sort_keys=True),
            )
            candidate = {**item, "engine": slice_.engine, "engines": [slice_.engine]}
            previous = seen.get(key)
            if previous is None:
                seen[key] = candidate
                buckets[rule_id].append(candidate)
            else:
                engines = cast(list[str], previous["engines"])
                if slice_.engine not in engines:
                    engines.append(slice_.engine)
                if previous.get("scan_incomplete") and not candidate.get(
                    "scan_incomplete"
                ):
                    previous.update(candidate)
                    previous["engines"] = engines
        batches.append(
            {
                "key": slice_.batch_key,
                "rule_ids": slice_.rule_ids,
                "engine": slice_.engine,
                "raw_ref": (
                    slice_.raw_ref.model_dump(mode="json")
                    if slice_.raw_ref is not None
                    else None
                ),
                "paths": slice_.parsed.get("paths", {}),
                "errors": slice_.parsed.get("errors", []),
            }
        )
    merged: list[dict[str, object]] = []
    active = list(plan.rule_ids)
    while active:
        following: list[str] = []
        for rule_id in active:
            if buckets[rule_id]:
                merged.append(buckets[rule_id].popleft())
            if buckets[rule_id]:
                following.append(rule_id)
        active = following
    return json.dumps(
        {
            "kind": "simple_static_merged_candidates_v1",
            "plan_fingerprint": plan.fingerprint,
            "rule_ids": plan.rule_ids,
            "results": merged,
            "errors": [],
            "batches": batches,
            "candidate_snippet_limit": _SNIPPET_LIMIT,
            "candidate_snippets_truncated": len(merged) > _SNIPPET_LIMIT,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
