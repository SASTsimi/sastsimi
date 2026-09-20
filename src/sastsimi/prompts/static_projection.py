"""Deterministic, bounded prompt views of large static-analysis bundles."""

from __future__ import annotations

from collections import Counter
from typing import cast

from pydantic import JsonValue

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import StaticFactBundle
from sastsimi.ports.dto import Record

_MAX_PROJECTION_BYTES = 600_000
_STRUCTURAL_LIMIT = 64
_EVIDENCE_LIMIT = 128

_STRUCTURAL_FIELDS = (
    "entities",
    "locations",
    "call_edges",
    "data_flow_candidates",
    "route_bindings",
)
_EVIDENCE_FIELDS = (
    "source_candidates",
    "sink_candidates",
    "sanitizer_candidates",
    "validator_candidates",
    "auth_and_permission_checks",
    "other_facts",
)


def project_hypothesis_static_bundle(bundle: StaticFactBundle) -> dict[str, JsonValue]:
    """Keep one deterministic bounded static view for every LLM analysis role.

    Downstream roles receive the same evidence universe that the Hypothesis
    Agent used.  The durable call still cites the exact full bundle reference;
    only the provider-facing JSON is bounded.
    """

    raw = bundle.model_dump(mode="json")
    source_ref = reference(cast(Record, bundle))
    if not isinstance(source_ref, StoredDataRef):
        raise ValueError("HYPOTHESIS_STATIC_PROJECTION_INVALID")
    structural_limit = _STRUCTURAL_LIMIT
    evidence_limit = _EVIDENCE_LIMIT
    while True:
        projected = _projection(
            raw,
            source_ref=cast(JsonValue, source_ref.model_dump(mode="json")),
            structural_limit=structural_limit,
            evidence_limit=evidence_limit,
        )
        if len(canonical_bytes(projected)) <= _MAX_PROJECTION_BYTES:
            return projected
        if structural_limit == 1 and evidence_limit == 1:
            raise ValueError("HYPOTHESIS_STATIC_PROJECTION_TOO_LARGE")
        structural_limit = max(1, structural_limit // 2)
        evidence_limit = max(1, evidence_limit // 2)


def _projection(
    raw: dict[str, object],
    *,
    source_ref: JsonValue,
    structural_limit: int,
    evidence_limit: int,
) -> dict[str, JsonValue]:
    included: dict[str, JsonValue] = {"source_ref": source_ref}
    total_counts: dict[str, int] = {}
    included_counts: dict[str, int] = {}
    for field in (*_STRUCTURAL_FIELDS, *_EVIDENCE_FIELDS):
        values = raw[field]
        if not isinstance(values, list):
            raise ValueError("HYPOTHESIS_STATIC_PROJECTION_INVALID")
        limit = structural_limit if field in _STRUCTURAL_FIELDS else evidence_limit
        selected = values[:limit]
        included[field] = cast(JsonValue, selected)
        total_counts[field] = len(values)
        included_counts[field] = len(selected)

    tool_runs = raw["tool_runs"]
    gaps = raw["gaps"]
    errors = raw["errors"]
    if not all(isinstance(items, list) for items in (tool_runs, gaps, errors)):
        raise ValueError("HYPOTHESIS_STATIC_PROJECTION_INVALID")
    included["tool_run_summary"] = cast(
        JsonValue,
        [
            {
                key: item.get(key)
                for key in ("tool_name", "tool_version", "tool_kind", "status")
            }
            for item in tool_runs
            if isinstance(item, dict)
        ],
    )
    included["gap_summary"] = cast(
        JsonValue,
        dict(
            sorted(
                Counter(
                    str(item.get("code", "UNKNOWN"))
                    for item in gaps
                    if isinstance(item, dict)
                ).items()
            )
        ),
    )
    included["error_summary"] = cast(
        JsonValue,
        dict(
            sorted(
                Counter(
                    str(item.get("code", "UNKNOWN"))
                    for item in errors
                    if isinstance(item, dict)
                ).items()
            )
        ),
    )
    metadata = raw.get("meta")
    source_record_id = (
        metadata.get("record_id") if isinstance(metadata, dict) else None
    )
    included["projection_summary"] = cast(
        JsonValue,
        {
            "source_record_id": str(source_record_id) if source_record_id else None,
            "total_counts": total_counts,
            "included_counts": included_counts,
            "truncated_fields": sorted(
                field
                for field in total_counts
                if included_counts[field] < total_counts[field]
            ),
        },
    )
    return included


__all__ = ["project_hypothesis_static_bundle"]
