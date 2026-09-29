"""Versioned, fail-closed coverage accounting for configured static rules."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, deque
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .opengrep_rule_batches import RuleBatch, RuleBatchPlan, parse_rule_batch

_SNIPPET_LIMIT = 500
_MAX_STATIC_CANDIDATES = 500_000
_MAX_STATIC_CANDIDATE_RAW_BYTES = 4 * 1024 * 1024 * 1024

_POLICY_VERSION = 2
_LANGUAGE_EXTENSIONS: dict[str, frozenset[str]] = {
    "python": frozenset({".py", ".pyi"}),
    "javascript": frozenset(
        {".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"}
    ),
    "typescript": frozenset({".ts", ".tsx", ".mts", ".cts"}),
}
_NON_SOURCE_EXTENSIONS = frozenset(
    {
        ".adoc",
        ".bz2",
        ".cer",
        ".cfg",
        ".conf",
        ".crt",
        ".csv",
        ".diff",
        ".dockerignore",
        ".eot",
        ".env",
        ".example",
        ".gif",
        ".gz",
        ".ico",
        ".ini",
        ".jpeg",
        ".jpg",
        ".json",
        ".jsonl",
        ".key",
        ".lock",
        ".log",
        ".map",
        ".md",
        ".mod",
        ".otf",
        ".patch",
        ".pdf",
        ".pem",
        ".png",
        ".properties",
        ".rst",
        ".snap",
        ".svg",
        ".sum",
        ".tar",
        ".tgz",
        ".toml",
        ".tsv",
        ".ttf",
        ".txt",
        ".typed",
        ".webp",
        ".woff",
        ".woff2",
        ".xml",
        ".xz",
        ".yaml",
        ".yml",
        ".zip",
    }
)
_NON_SOURCE_BASENAMES = frozenset(
    {
        ".dockerignore",
        ".editorconfig",
        ".eslintignore",
        ".gitattributes",
        ".gitignore",
        ".npmignore",
        ".nvmrc",
        ".prettierignore",
        ".python-version",
        ".tool-versions",
        "authors",
        "changelog",
        "code_of_conduct",
        "contributors",
        "license",
        "notice",
        "readme",
        "security",
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
    unsupported_files: tuple[tuple[str, str], ...] = ()


class StaticCandidateLimitError(Exception):
    """A scan cannot retain all candidate evidence within the finite budget."""

    def __init__(self) -> None:
        super().__init__("STATIC_CANDIDATES_TOO_LARGE")


@dataclass(slots=True)
class StaticCandidateBudget:
    """Charge each retained scan, including repeated evaluation of one raw result."""

    max_results: int | None = None
    max_raw_bytes: int = _MAX_STATIC_CANDIDATE_RAW_BYTES
    used_results: int = field(default=0, init=False)
    used_raw_bytes: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if (
            self.max_results is not None and self.max_results < 0
        ) or self.max_raw_bytes < 0:
            raise ValueError("STATIC_CANDIDATE_BUDGET_INVALID")

    def reserve_raw(self, size: int) -> None:
        if size > self.max_raw_bytes - self.used_raw_bytes:
            raise StaticCandidateLimitError()
        self.used_raw_bytes += size

    def release_raw(self, size: int) -> None:
        self.used_raw_bytes -= size

    def require_results(self, additional: int) -> None:
        if (
            self.max_results is not None
            and additional > self.max_results - self.used_results
        ):
            raise StaticCandidateLimitError()

    def claim_results(self, count: int) -> None:
        self.require_results(count)
        self.used_results += count


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
    unsupported_files: tuple[tuple[str, str], ...] = ()

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
            "unsupported_files": [
                {"path": path, "reason": reason}
                for path, reason in self.unsupported_files
            ],
            "excluded_paths": list(self.excluded_paths),
        }


def _safe_relative_from_root(root: Path, raw: str) -> str | None:
    if not raw or "\x00" in raw:
        return None
    supplied = Path(raw)
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


def static_coverage_fingerprint(
    tracked: Sequence[str],
    commit_id: str,
    rules: RuleBatchPlan,
    *,
    fallback_tool_fingerprint: str | None = None,
    scope_fingerprint: str | None = None,
) -> str:
    """Hash the coverage identity without rechecking the pinned checkout."""

    data: dict[str, object] = {
        "version": _POLICY_VERSION,
        "commit_id": commit_id,
        "tracked": sorted(set(tracked)),
        "rules_fingerprint": rules.fingerprint,
        "fallback_tool_fingerprint": fallback_tool_fingerprint,
        "language_extensions": {
            key: sorted(value) for key, value in sorted(_LANGUAGE_EXTENSIONS.items())
        },
    }
    if scope_fingerprint is not None:
        data["scope_fingerprint"] = scope_fingerprint
    return hashlib.sha256(canonical_bytes(data)).hexdigest()


def plan_static_coverage(
    workspace: Path,
    tracked: Sequence[str],
    commit_id: str,
    rules: RuleBatchPlan,
    *,
    fallback_tool_fingerprint: str | None = None,
    scope_fingerprint: str | None = None,
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
    unsupported_files: set[tuple[str, str]] = set()
    root = workspace.resolve()
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
        relative = _safe_relative_from_root(root, raw)
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
        if (
            not matched
            and extension not in _NON_SOURCE_EXTENSIONS
            and Path(relative).name.lower() not in _NON_SOURCE_BASENAMES
            and not Path(relative).name.lower().startswith(".env.")
            and Path(relative).name.lower() != ".env"
        ):
            unsupported[extension] += 1
            unsupported_files.add((relative, "no_applicable_rule"))
    fingerprint = static_coverage_fingerprint(
        tracked,
        commit_id,
        rules,
        fallback_tool_fingerprint=fallback_tool_fingerprint,
        scope_fingerprint=scope_fingerprint,
    )
    return StaticCoveragePlan(
        workspace=root,
        fingerprint=fingerprint,
        expected_pairs=frozenset(pairs),
        unavailable_pairs=frozenset(unavailable_pairs),
        unsupported=tuple(sorted(unsupported.items())),
        excluded_paths=tuple(sorted(excluded)),
        unsupported_files=tuple(sorted(unsupported_files)),
    )


def _paths(value: object, root: Path) -> set[str]:
    if not isinstance(value, list):
        raise ValueError("STATIC_SCAN_PATHS_INVALID")
    paths: set[str] = set()
    for item in value:
        raw = item.get("path") if isinstance(item, dict) else item
        if not isinstance(raw, str):
            raise ValueError("STATIC_SCAN_PATHS_INVALID")
        path = _safe_relative_from_root(root, raw)
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
    candidate_budget: StaticCandidateBudget | None = None,
) -> CoverageSlice:
    """Only explicit, error-free scanned paths earn this batch's rule coverage."""

    budget = (
        candidate_budget if candidate_budget is not None else StaticCandidateBudget()
    )
    budget.reserve_raw(len(raw))
    try:
        return _assess_scan(
            plan, batch, raw, engine=engine, targets=targets, budget=budget
        )
    except Exception:
        budget.release_raw(len(raw))
        raise


def _assess_scan(
    plan: StaticCoveragePlan,
    batch: RuleBatch,
    raw: bytes,
    *,
    engine: Literal["opengrep", "semgrep"],
    targets: Sequence[str] | None,
    budget: StaticCandidateBudget,
) -> CoverageSlice:

    parsed = parse_rule_batch(raw, batch, allow_errors=True)
    paths = parsed.get("paths")
    if not isinstance(paths, dict):
        raise ValueError("STATIC_SCAN_PATHS_INVALID")
    scanned = _paths(paths.get("scanned"), plan.workspace)
    skipped = _paths(paths.get("skipped", []), plan.workspace)
    target_set = _paths(list(targets), plan.workspace) if targets is not None else None
    if target_set is not None and not (scanned | skipped) <= target_set:
        raise ValueError("STATIC_SCAN_SCOPE_MISMATCH")
    if target_set is None:
        allowed = {
            pair
            for pair in plan.expected_pairs
            if pair not in plan.unavailable_pairs and pair[1] in batch.rule_ids
        }
    else:
        # A fallback node names at most a small target chunk. Probe only those
        # file/rule combinations rather than walking the entire repository plan
        # again for every retry and replayed artifact.
        allowed = {
            (path, rule_id)
            for path in target_set
            for rule_id in batch.rule_ids
            if (path, rule_id) in plan.expected_pairs
            and (path, rule_id) not in plan.unavailable_pairs
        }
    reasons: dict[Pair, str] = {}
    errors = parsed.get("errors", [])
    assert isinstance(errors, list)
    for raw_error in errors:
        error = cast(dict[str, object], raw_error)
        path_value = error.get("path")
        path = (
            _safe_relative_from_root(plan.workspace, path_value)
            if isinstance(path_value, str)
            else None
        )
        if path is None:
            for pair in allowed:
                reasons[pair] = "unlocated_scan_error"
            continue
        if target_set is not None and path not in target_set:
            raise ValueError("STATIC_SCAN_SCOPE_MISMATCH")
        for pair in allowed:
            if pair[0] == path:
                if error.get("type") == "Timeout":
                    reasons[pair] = "scan_timeout"
                elif reasons.get(pair) != "scan_timeout":
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
    result_paths: dict[str, str] = {}
    for result in cast(list[dict[str, object]], parsed["results"]):
        path_value = result["path"]
        if not isinstance(path_value, str):
            raise ValueError("STATIC_SCAN_RESULT_PATH_INVALID")
        relative = result_paths.get(path_value)
        if relative is None:
            relative = _safe_relative_from_root(plan.workspace, path_value)
            if relative is None:
                raise ValueError("STATIC_SCAN_RESULT_PATH_INVALID")
            result_paths[path_value] = relative
        pair = (relative, cast(str, result["check_id"]))
        if target_set is not None and relative not in target_set:
            raise ValueError("STATIC_SCAN_SCOPE_MISMATCH")
        if pair in allowed:
            budget.require_results(len(normalized_results) + 1)
            normalized_results.append(
                {
                    **result,
                    "path": relative,
                    "scan_incomplete": pair not in verified,
                }
            )
    for raw_path, relative in result_paths.items():
        if _safe_relative_from_root(plan.workspace, raw_path) != relative:
            raise ValueError("STATIC_SCAN_RESULT_PATH_INVALID")
    # The immutable raw artifact retains every hit. Keep only normalized hits in
    # memory; downstream coverage/merge consumers need parsed scan metadata only.
    parsed["results"] = []
    slice_ = CoverageSlice(
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
    budget.claim_results(len(normalized_results))
    return slice_


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
        unsupported_files=plan.unsupported_files,
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
    seen: dict[str, dict[str, object]] = {}
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
            if (path, rule_id) not in slice_.verified_pairs:
                continue
            # A location can hold multiple independent source-to-sink paths.
            # Only identical normalized evidence may merge across engines.
            key = json.dumps(
                {k: v for k, v in item.items() if k != "scan_incomplete"},
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
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


def merge_static_candidates_preview(
    plan: RuleBatchPlan,
    slices: Sequence[CoverageSlice],
    *,
    limit: int = _SNIPPET_LIMIT,
) -> bytes:
    """Bound only the UI/agent preview; exact per-engine raw refs remain separate."""

    if limit < 1:
        raise ValueError("STATIC_CANDIDATE_PREVIEW_LIMIT_INVALID")
    known_rules = frozenset(plan.rule_ids)

    def verified_hits() -> Iterator[
        tuple[CoverageSlice, dict[str, object], str, str, int]
    ]:
        for slice_ in slices:
            for item in slice_.normalized_results:
                rule_id = item.get("check_id")
                path = item.get("path")
                start = item.get("start")
                line = start.get("line") if isinstance(start, dict) else None
                if (
                    not isinstance(rule_id, str)
                    or rule_id not in known_rules
                    or not isinstance(path, str)
                    or type(line) is not int
                ):
                    raise ValueError("STATIC_CANDIDATE_INVALID")
                if (path, rule_id) in slice_.verified_pairs:
                    yield slice_, item, rule_id, path, line

    active = {rule_id for _, _, rule_id, _, _ in verified_hits()}
    visible_rules = [rule_id for rule_id in plan.rule_ids if rule_id in active][:limit]
    visible_set = frozenset(visible_rules)
    per_rule_limit = max(1, limit // len(visible_rules)) if visible_rules else 0
    buckets: dict[str, list[dict[str, object]]] = {
        rule_id: [] for rule_id in visible_rules
    }
    selected: dict[str, dict[str, object]] = {}

    def collect(*, per_rule_cap: int | None) -> bool:
        omitted = False
        for slice_, item, rule_id, path, line in verified_hits():
            if rule_id not in visible_set:
                omitted = True
                continue
            try:
                canonical = json.dumps(
                    {
                        key: value
                        for key, value in item.items()
                        if key != "scan_incomplete"
                    },
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            except (TypeError, ValueError) as error:
                raise ValueError("STATIC_CANDIDATE_INVALID") from error
            digest = hashlib.sha256(canonical).hexdigest()
            previous = selected.get(digest)
            if previous is not None:
                engines = cast(list[str], previous["engines"])
                if slice_.engine not in engines:
                    engines.append(slice_.engine)
                if previous.get("scan_incomplete") and not item.get("scan_incomplete"):
                    previous["engine"] = slice_.engine
                    previous["scan_incomplete"] = False
                continue
            if (
                len(selected) >= limit
                or per_rule_cap is not None
                and len(buckets[rule_id]) >= per_rule_cap
            ):
                omitted = True
                continue
            start = item["start"]
            assert isinstance(start, dict)
            position: dict[str, int] = {"line": line}
            column = start.get("col")
            if type(column) is int:
                position["col"] = column
            candidate: dict[str, object] = {
                "check_id": rule_id,
                "path": path,
                "start": position,
                "engine": slice_.engine,
                "engines": [slice_.engine],
                "scan_incomplete": bool(item.get("scan_incomplete", False)),
                "candidate_digest": digest,
            }
            selected[digest] = candidate
            buckets[rule_id].append(candidate)
        return omitted

    omitted = collect(per_rule_cap=per_rule_limit)
    if omitted and len(selected) < limit:
        omitted = collect(per_rule_cap=None)

    merged: list[dict[str, object]] = []
    offsets = {rule_id: 0 for rule_id in visible_rules}
    while len(merged) < len(selected):
        for rule_id in visible_rules:
            index = offsets[rule_id]
            if index < len(buckets[rule_id]):
                merged.append(buckets[rule_id][index])
                offsets[rule_id] += 1

    batches = [
        {
            "key": slice_.batch_key,
            "rule_ids": slice_.rule_ids,
            "engine": slice_.engine,
            "raw_ref": (
                slice_.raw_ref.model_dump(mode="json")
                if slice_.raw_ref is not None
                else None
            ),
        }
        for slice_ in slices[:limit]
    ]
    return json.dumps(
        {
            "kind": "simple_static_merged_candidates_v1",
            "preview_only": True,
            "plan_fingerprint": plan.fingerprint,
            "rule_ids": plan.rule_ids[:limit],
            "rule_ids_truncated": len(plan.rule_ids) > limit,
            "results": merged,
            "errors": [],
            "batches": batches,
            "batches_truncated": len(slices) > limit,
            "candidate_snippet_limit": limit,
            "candidate_snippets_truncated": omitted,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
