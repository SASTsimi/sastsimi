"""Dependency-light snapshot binding for a completed v9 surface review."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping

from sastsimi.contracts.canonical_json import canonical_bytes

from .surface_enrichment_v7_bindings import SurfaceProgressRow
from .surface_enrichment_v9_bindings import prior_v8_progress_snapshot_hash

_STATUSES = frozenset(
    {"HYPOTHESES", "NO_HYPOTHESIS", "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"}
)


def v9_progress_snapshot_hash(
    v9_plan: Mapping[str, object],
    progress: Mapping[tuple[str, str], SurfaceProgressRow],
) -> str:
    """Hash the entire completed v9 review ledger; reject absent/extra parts."""

    expected = v9_plan.get("expected_parts")
    if v9_plan.get("kind") != "simple_surface_enrichment_plan_v9" or not isinstance(
        expected, list
    ):
        raise ValueError("SURFACE_ENRICHMENT_V10_PROGRESS_INVALID")
    seen: set[tuple[str, str]] = set()
    for part in expected:
        if not isinstance(part, dict) or not isinstance(part.get("context_part"), dict):
            raise ValueError("SURFACE_ENRICHMENT_V10_PROGRESS_INVALID")
        surface_id = part.get("surface_id")
        context_id = part.get("context_id")
        if (
            not isinstance(surface_id, str)
            or not surface_id
            or not isinstance(context_id, str)
            or not context_id
        ):
            raise ValueError("SURFACE_ENRICHMENT_V10_PROGRESS_INVALID")
        key = (surface_id, context_id)
        if key in seen:
            raise ValueError("SURFACE_ENRICHMENT_V10_PROGRESS_INVALID")
        seen.add(key)
        row = progress.get(key)
        if row is None:
            raise ValueError("SURFACE_ENRICHMENT_V10_PROGRESS_INCOMPLETE")
        if (
            row.proposal_version != 9
            or row.context_hash != part.get("context_hash")
            or row.source_sha256 != part["context_part"].get("source_sha256")
            or row.index_hash != v9_plan.get("index_hash")
            or row.static_bundle_hash != v9_plan.get("static_bundle_hash")
            or row.status not in _STATUSES
            or (row.status == "HYPOTHESES") != bool(row.hypothesis_ids)
            or len(set(row.hypothesis_ids)) != len(row.hypothesis_ids)
        ):
            raise ValueError("SURFACE_ENRICHMENT_V10_PROGRESS_INVALID")
    if any(
        key != (row.surface_id, row.context_id)
        or row.proposal_version == 9
        and key not in seen
        or row.proposal_version not in range(1, 10)
        for key, row in progress.items()
    ):
        raise ValueError("SURFACE_ENRICHMENT_V10_PROGRESS_INVALID")
    old = {key: row for key, row in progress.items() if row.proposal_version <= 8}
    if prior_v8_progress_snapshot_hash(old) != v9_plan.get("prior_v8_progress_hash"):
        raise ValueError("SURFACE_ENRICHMENT_V10_PROGRESS_INVALID")
    rows = [
        {
            "surface_id": row.surface_id,
            "context_id": row.context_id,
            "static_bundle_hash": row.static_bundle_hash,
            "index_hash": row.index_hash,
            "context_hash": row.context_hash,
            "source_sha256": row.source_sha256,
            "status": row.status,
            "proposal_version": row.proposal_version,
            "result_ref": row.result_ref.model_dump(mode="json"),
            "hypothesis_ids": list(row.hypothesis_ids),
        }
        for _key, row in sorted(progress.items())
    ]
    return hashlib.sha256(canonical_bytes(rows)).hexdigest()
