"""Pure v8 predecessor checks shared by the planner and transactional store."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping

from sastsimi.contracts.canonical_json import canonical_bytes

from .surface_enrichment_v7_bindings import SurfaceProgressRow


def prior_v7_progress_snapshot_hash(
    progress: Mapping[tuple[str, str], SurfaceProgressRow],
) -> str:
    """Bind all prior exploration rows, including finished v7 parts."""

    rows: list[dict[str, object]] = []
    for key, row in sorted(progress.items()):
        if (
            key != (row.surface_id, row.context_id)
            or row.proposal_version not in {1, 2, 3, 4, 5, 6, 7}
            or row.status
            not in {
                "HYPOTHESES",
                "NO_HYPOTHESIS",
                "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
            }
            or (row.status == "HYPOTHESES") != bool(row.hypothesis_ids)
            or len(set(row.hypothesis_ids)) != len(row.hypothesis_ids)
        ):
            raise ValueError("SURFACE_ENRICHMENT_V8_PROGRESS_INVALID")
        rows.append(
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
        )
    return hashlib.sha256(canonical_bytes(rows)).hexdigest()


def missing_v7_part_set(
    v7_plan: Mapping[str, object],
    progress: Mapping[tuple[str, str], SurfaceProgressRow],
) -> list[dict[str, str]]:
    """List exact v7 parts not durably present; never infer completion."""

    raw_parts = v7_plan.get("expected_parts")
    if not isinstance(raw_parts, list):
        raise ValueError("SURFACE_ENRICHMENT_V8_V7_PARTS_INVALID")
    seen: set[tuple[str, str]] = set()
    missing: list[dict[str, str]] = []
    for raw in raw_parts:
        if not isinstance(raw, dict):
            raise ValueError("SURFACE_ENRICHMENT_V8_V7_PARTS_INVALID")
        surface_id, context_id = raw.get("surface_id"), raw.get("context_id")
        if (
            not isinstance(surface_id, str)
            or not surface_id
            or not isinstance(context_id, str)
            or not context_id
            or (surface_id, context_id) in seen
        ):
            raise ValueError("SURFACE_ENRICHMENT_V8_V7_PARTS_INVALID")
        key = (surface_id, context_id)
        seen.add(key)
        row = progress.get(key)
        if row is None:
            missing.append({"surface_id": surface_id, "context_id": context_id})
        elif (
            row.proposal_version != 7
            or row.context_hash != raw.get("context_hash")
            or row.source_sha256 != raw.get("source_sha256")
        ):
            raise ValueError("SURFACE_ENRICHMENT_V8_V7_PART_CHANGED")
    if any(
        row.proposal_version == 7 and key not in seen for key, row in progress.items()
    ):
        raise ValueError("SURFACE_ENRICHMENT_V8_V7_PART_CHANGED")
    return missing
