"""Deterministic OpenGrep rule partitioning and verified result aggregation."""

from __future__ import annotations

import hashlib
import json
import re
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

import yaml  # type: ignore[import-untyped]
from yaml.nodes import MappingNode  # type: ignore[import-untyped]

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

if TYPE_CHECKING:
    from .static_coverage import CoverageSlice

_PLAN_VERSION = 1
_SNIPPET_LIMIT = 500
_RULE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z")


class _UniqueSafeLoader(yaml.SafeLoader):  # type: ignore[misc]
    pass


def _unique_mapping(
    loader: _UniqueSafeLoader, node: MappingNode, deep: bool = False
) -> dict[str, object]:
    values: dict[str, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str) or key in values:
            raise ValueError("OPENGREP_RULE_CATALOG_INVALID")
        values[key] = loader.construct_object(value_node, deep=deep)
    return values


_UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping
)


def _unique_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    values: dict[str, object] = {}
    for key, value in pairs:
        if key in values:
            raise ValueError("OPENGREP_RESULT_INVALID")
        values[key] = value
    return values


def _reject_json_constant(_value: str) -> None:
    raise ValueError("OPENGREP_RESULT_INVALID")


@dataclass(frozen=True, slots=True)
class RuleBatch:
    index: int
    rule_ids: tuple[str, ...]
    excluded_rule_ids: tuple[str, ...]
    key: str


@dataclass(frozen=True, slots=True)
class RuleBatchPlan:
    fingerprint: str
    rule_ids: tuple[str, ...]
    rule_languages: tuple[tuple[str, ...], ...]
    batches: tuple[RuleBatch, ...]


def plan_rule_batches(
    raw: bytes,
    *,
    tool_version: str,
    executable_sha256: str,
    batch_size: int = 3,
) -> RuleBatchPlan:
    """Partition each configured rule exactly once without rewriting the YAML."""

    try:
        document = yaml.load(raw, Loader=_UniqueSafeLoader)
    except (yaml.YAMLError, ValueError) as error:
        raise ValueError("OPENGREP_RULE_CATALOG_INVALID") from error
    if (
        not isinstance(document, dict)
        or not isinstance(document.get("rules"), list)
        or not document["rules"]
        or batch_size < 1
    ):
        raise ValueError("OPENGREP_RULE_CATALOG_INVALID")
    ids: list[str] = []
    languages: list[tuple[str, ...]] = []
    for rule in document["rules"]:
        if not isinstance(rule, dict):
            raise ValueError("OPENGREP_RULE_CATALOG_INVALID")
        rule_id = rule.get("id")
        if (
            not isinstance(rule_id, str)
            or _RULE_ID.fullmatch(rule_id) is None
            or rule_id in ids
        ):
            raise ValueError("OPENGREP_RULE_CATALOG_INVALID")
        ids.append(rule_id)
        raw_languages = rule.get("languages")
        if (
            not isinstance(raw_languages, list)
            or not raw_languages
            or any(not isinstance(item, str) or not item for item in raw_languages)
            or len(set(raw_languages)) != len(raw_languages)
        ):
            raise ValueError("OPENGREP_RULE_CATALOG_INVALID")
        languages.append(tuple(raw_languages))
    rule_ids = tuple(ids)
    fingerprint = hashlib.sha256(
        canonical_bytes(
            {
                "version": _PLAN_VERSION,
                "batch_size": batch_size,
                "rules_sha256": hashlib.sha256(raw).hexdigest(),
                "rule_ids": rule_ids,
                "tool_version": tool_version,
                "executable_sha256": executable_sha256,
            }
        )
    ).hexdigest()
    batches: list[RuleBatch] = []
    for index, start in enumerate(range(0, len(rule_ids), batch_size)):
        selected = rule_ids[start : start + batch_size]
        chosen = set(selected)
        key = hashlib.sha256(
            canonical_bytes(
                {"version": _PLAN_VERSION, "index": index, "rule_ids": selected}
            )
        ).hexdigest()
        batches.append(
            RuleBatch(
                index=index,
                rule_ids=selected,
                excluded_rule_ids=tuple(
                    rule_id for rule_id in rule_ids if rule_id not in chosen
                ),
                key=key,
            )
        )
    return RuleBatchPlan(
        fingerprint=fingerprint,
        rule_ids=rule_ids,
        rule_languages=tuple(languages),
        batches=tuple(batches),
    )


def parse_rule_batch(
    raw: bytes, batch: RuleBatch, *, allow_errors: bool = False
) -> dict[str, object]:
    """Accept only a complete JSON result whose findings belong to this batch."""

    try:
        value = json.loads(
            raw,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, ValueError) as error:
        raise ValueError("OPENGREP_RESULT_INVALID") from error
    if not isinstance(value, dict):
        raise ValueError("OPENGREP_RESULT_INVALID")
    results = value.get("results")
    errors = value.get("errors", [])
    if (
        not isinstance(results, list)
        or not all(isinstance(item, dict) for item in results)
        or not isinstance(errors, list)
        or not all(isinstance(item, dict) for item in errors)
    ):
        raise ValueError("OPENGREP_RESULT_INVALID")
    if errors and not allow_errors:
        raise ValueError("OPENGREP_PARTIAL_SCAN")
    allowed = set(batch.rule_ids)
    for item in results:
        rule_id = item.get("check_id")
        if not isinstance(rule_id, str) or rule_id not in allowed:
            raise ValueError("OPENGREP_BATCH_RULE_MISMATCH")
        path = item.get("path")
        start = item.get("start")
        line = start.get("line") if isinstance(start, dict) else None
        if not isinstance(path, str) or not path or type(line) is not int or line < 1:
            raise ValueError("OPENGREP_RESULT_INVALID")
    return cast(dict[str, object], value)


def _hit_key(item: dict[str, object]) -> tuple[str, int, str]:
    raw_path = item.get("path")
    path = raw_path if isinstance(raw_path, str) else ""
    raw_start = item.get("start")
    raw_line = raw_start.get("line") if isinstance(raw_start, dict) else None
    line = raw_line if type(raw_line) is int else 0
    encoded = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
    return path, line, encoded


def aggregate_rule_batches(
    plan: RuleBatchPlan,
    accepted: Sequence[tuple[RuleBatch, StoredDataRef, dict[str, object]]],
) -> bytes:
    """Preserve all accepted hits while sharing the first 500 across rules."""

    if len(accepted) != len(plan.batches) or any(
        item[0] != plan.batches[index] for index, item in enumerate(accepted)
    ):
        raise ValueError("OPENGREP_BATCH_SET_INCOMPLETE")
    buckets: dict[str, deque[dict[str, object]]] = {
        rule_id: deque() for rule_id in plan.rule_ids
    }
    batch_records: list[dict[str, object]] = []
    for batch, ref, parsed in accepted:
        batch_results = parsed.get("results")
        if not isinstance(batch_results, list):
            raise ValueError("OPENGREP_RESULT_INVALID")
        for raw_item in batch_results:
            if not isinstance(raw_item, dict):
                raise ValueError("OPENGREP_RESULT_INVALID")
            item = cast(dict[str, object], raw_item)
            rule_id = item.get("check_id")
            if not isinstance(rule_id, str) or rule_id not in batch.rule_ids:
                raise ValueError("OPENGREP_BATCH_RULE_MISMATCH")
            buckets[rule_id].append(item)
        batch_records.append(
            {
                "key": batch.key,
                "rule_ids": batch.rule_ids,
                "raw_ref": ref.model_dump(mode="json"),
                "paths": parsed.get("paths", {}),
                "errors": [],
            }
        )
    for rule_id in plan.rule_ids:
        buckets[rule_id] = deque(sorted(buckets[rule_id], key=_hit_key))
    merged_results: list[dict[str, object]] = []
    active = list(plan.rule_ids)
    while active:
        next_active: list[str] = []
        for rule_id in active:
            bucket = buckets[rule_id]
            if bucket:
                merged_results.append(bucket.popleft())
            if bucket:
                next_active.append(rule_id)
        active = next_active
    aggregate = {
        "kind": "simple_opengrep_rule_batches_v1",
        "plan_fingerprint": plan.fingerprint,
        "rule_ids": plan.rule_ids,
        "results": merged_results,
        "errors": [],
        "batches": batch_records,
        "candidate_snippet_limit": _SNIPPET_LIMIT,
        "candidate_snippets_truncated": len(merged_results) > _SNIPPET_LIMIT,
    }
    return json.dumps(
        aggregate, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def merge_static_candidates(
    plan: RuleBatchPlan, slices: Sequence[CoverageSlice]
) -> bytes:
    """Deduplicate verified hits while preserving fair per-rule visibility."""

    buckets: dict[str, deque[dict[str, object]]] = {
        rule_id: deque() for rule_id in plan.rule_ids
    }
    seen: set[tuple[str, str, int]] = set()
    batches: list[dict[str, object]] = []
    for slice_ in slices:
        for item in sorted(slice_.normalized_results, key=_hit_key):
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
            key = (rule_id, path, line)
            if key not in seen:
                seen.add(key)
                buckets[rule_id].append({**item, "engine": slice_.engine})
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
