"""Attach evidence for static file/rule gaps."""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import cast

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.store import StaticScanExecution

_MAX_REQUEST_BYTES = 1024 * 1024


def enrich_gap_provenance(
    gaps: list[dict[str, object]],
    executions: Sequence[StaticScanExecution],
    artifacts: SimpleArtifactRepository,
    *,
    batch_rules: Mapping[str, tuple[str, ...]],
    expected_pairs: frozenset[tuple[str, str]],
    legacy_history_incomplete: bool,
) -> list[dict[str, object]]:
    """Count recorded calls, never mistaking an incomplete legacy log for zero."""

    full_counts: dict[str, int] = defaultdict(int)
    targeted_counts: dict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: {"opengrep": 0, "semgrep": 0}
    )
    full_errors: dict[str, tuple[int, str, object]] = {}
    targeted_errors: dict[tuple[str, str], tuple[int, str, object]] = {}
    incomplete = legacy_history_incomplete
    incomplete_pairs: set[tuple[str, str]] = set()

    for execution in executions:
        if execution.status not in {"SUCCEEDED", "BLOCKED", "STARTED"}:
            incomplete = True
            continue
        if execution.request_ref is None or execution.tool not in {
            "opengrep",
            "semgrep",
        }:
            incomplete = True
            continue
        try:
            descriptor = json.loads(
                artifacts.read_bounded(execution.request_ref, _MAX_REQUEST_BYTES)
            )
        except (OSError, ValueError):
            incomplete = True
            continue
        if not isinstance(descriptor, dict):
            incomplete = True
            continue
        batch_key = descriptor.get("batch_key")
        rule_ids = descriptor.get("rule_ids")
        source_rules = (
            batch_rules.get(batch_key) if isinstance(batch_key, str) else None
        )
        if (
            source_rules is None
            or not isinstance(rule_ids, list)
            or not rule_ids
            or not all(isinstance(rule_id, str) for rule_id in rule_ids)
        ):
            incomplete = True
            continue
        selected = tuple(cast(list[str], rule_ids))
        kind = descriptor.get("kind")
        full = kind == "opengrep_full_scan_request_v1"
        if full:
            if (
                execution.tool != "opengrep"
                or execution.run_key != batch_key
                or selected != source_rules
            ):
                incomplete = True
                continue
            targets: tuple[str, ...] = ()
        else:
            if (
                kind == "opengrep_scan_request_v1"
                and (execution.tool != "opengrep" or selected != source_rules)
                or kind == "semgrep_scan_request_v1"
                and (
                    execution.tool != "semgrep"
                    or not set(selected) <= set(source_rules)
                )
                or kind
                not in {
                    "opengrep_scan_request_v1",
                    "semgrep_scan_request_v1",
                }
            ):
                incomplete = True
                continue
            raw_targets = descriptor.get("targets")
            if (
                not isinstance(raw_targets, list)
                or not raw_targets
                or not all(isinstance(path, str) for path in raw_targets)
                or raw_targets != sorted(set(raw_targets))
            ):
                incomplete = True
                continue
            targets = tuple(cast(list[str], raw_targets))
            if not all(
                any((path, rule_id) in expected_pairs for rule_id in selected)
                for path in targets
            ):
                incomplete = True
                continue
            if kind == "opengrep_scan_request_v1":
                key_data: dict[str, object] = {
                    "kind": kind,
                    "batch_key": batch_key,
                    "rule_ids": selected,
                    "targets": targets,
                }
                matching_keys = {hashlib.sha256(canonical_bytes(key_data)).hexdigest()}
            else:
                timeout = descriptor.get("per_file_timeout_seconds")
                if (
                    "per_file_timeout_seconds" not in descriptor
                    or (
                        timeout is not None
                        and (type(timeout) is not int or timeout != 30)
                    )
                    or selected != tuple(sorted(set(selected)))
                ):
                    incomplete = True
                    continue
                key_data = {"batch": batch_key, "rules": selected, "targets": targets}
                if timeout is not None:
                    key_data["per_file_timeout_seconds"] = timeout
                matching_keys = {hashlib.sha256(canonical_bytes(key_data)).hexdigest()}
                key_data["adaptive"] = 1
                matching_keys.add(hashlib.sha256(canonical_bytes(key_data)).hexdigest())
            if execution.run_key not in matching_keys:
                incomplete = True
                continue
        if "raw_content_hash" in descriptor and (
            execution.raw_ref is None
            or descriptor["raw_content_hash"] != execution.raw_ref.content_hash
        ):
            incomplete = True
            continue

        if execution.status == "STARTED":
            if full:
                incomplete_pairs.update(
                    pair for pair in expected_pairs if pair[1] in selected
                )
            else:
                incomplete_pairs.update(
                    (path, rule_id)
                    for path in targets
                    for rule_id in selected
                    if (path, rule_id) in expected_pairs
                )
            continue

        error_ref = execution.error_ref or execution.raw_ref
        error_value = (
            error_ref.model_dump(mode="json") if error_ref is not None else None
        )
        if full:
            for rule_id in selected:
                full_counts[rule_id] += 1
                prior_error = full_errors.get(rule_id)
                if execution.error_code is not None and (
                    prior_error is None or execution.execution_id > prior_error[0]
                ):
                    full_errors[rule_id] = (
                        execution.execution_id,
                        execution.error_code,
                        error_value,
                    )
        else:
            for path in targets:
                for rule_id in selected:
                    pair = (path, rule_id)
                    if pair not in expected_pairs:
                        continue
                    targeted_counts[pair][execution.tool] += 1
                    prior_error = targeted_errors.get(pair)
                    if execution.error_code is not None and (
                        prior_error is None or execution.execution_id > prior_error[0]
                    ):
                        targeted_errors[pair] = (
                            execution.execution_id,
                            execution.error_code,
                            error_value,
                        )

    enriched: list[dict[str, object]] = []
    for gap in gaps:
        gap_path = gap.get("path")
        gap_rule_id = gap.get("rule_id")
        if not isinstance(gap_path, str) or not isinstance(gap_rule_id, str):
            raise ValueError("STATIC_SCAN_GAP_INVALID")
        pair = (gap_path, gap_rule_id)
        per_engine = {
            "opengrep": full_counts[gap_rule_id] + targeted_counts[pair]["opengrep"],
            "semgrep": targeted_counts[pair]["semgrep"],
        }
        known = sum(per_engine.values())
        error_choices = (full_errors.get(gap_rule_id), targeted_errors.get(pair))
        latest = max(
            (entry for entry in error_choices if entry is not None),
            default=None,
            key=lambda entry: entry[0],
        )
        history_complete = not incomplete and pair not in incomplete_pairs
        history_status = (
            "INVALID"
            if incomplete
            else "INTERRUPTED"
            if pair in incomplete_pairs
            else "COMPLETE"
        )
        enriched.append(
            {
                **gap,
                "known_attempt_count": known,
                "attempt_count": known if history_complete else None,
                "history_complete": history_complete,
                "history_status": history_status,
                "known_attempts_by_engine": per_engine,
                "latest_error_code": latest[1] if latest is not None else None,
                "latest_error_ref": latest[2] if latest is not None else None,
            }
        )
    return enriched
