"""Pure snapshot checks shared by the v7 planner and transactional store."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Protocol

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef


class SurfaceProgressRow(Protocol):
    """The read-only fields needed to bind a saved exploration row."""

    @property
    def surface_id(self) -> str: ...

    @property
    def context_id(self) -> str: ...

    @property
    def static_bundle_hash(self) -> str: ...

    @property
    def index_hash(self) -> str: ...

    @property
    def context_hash(self) -> str: ...

    @property
    def source_sha256(self) -> str | None: ...

    @property
    def status(self) -> str: ...

    @property
    def result_ref(self) -> StoredDataRef: ...

    @property
    def hypothesis_ids(self) -> tuple[str, ...]: ...

    @property
    def proposal_version(self) -> int: ...


def prior_progress_snapshot_hash(
    progress: Mapping[tuple[str, str], SurfaceProgressRow],
) -> str:
    """Hash every field that gives an existing exploration row its meaning."""

    rows: list[dict[str, object]] = []
    for key, row in sorted(progress.items()):
        if (
            key != (row.surface_id, row.context_id)
            or row.proposal_version not in {1, 2, 3, 4, 5, 6}
            or row.status
            not in {
                "HYPOTHESES",
                "NO_HYPOTHESIS",
                "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
            }
            or (row.status == "HYPOTHESES") != bool(row.hypothesis_ids)
            or len(set(row.hypothesis_ids)) != len(row.hypothesis_ids)
        ):
            raise ValueError("SURFACE_ENRICHMENT_V7_PROGRESS_INVALID")
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


def missing_v6_part_set(
    v6_plan: Mapping[str, object],
    progress: Mapping[tuple[str, str], SurfaceProgressRow],
) -> list[dict[str, str]]:
    """Return the exact v6 part keys absent at the moment of v7 planning."""

    raw_parts = v6_plan.get("expected_parts")
    if not isinstance(raw_parts, list):
        raise ValueError("SURFACE_ENRICHMENT_V7_V6_PARTS_INVALID")
    seen: set[tuple[str, str]] = set()
    missing: list[dict[str, str]] = []
    for raw in raw_parts:
        if not isinstance(raw, dict):
            raise ValueError("SURFACE_ENRICHMENT_V7_V6_PARTS_INVALID")
        surface_id, context_id = raw.get("surface_id"), raw.get("context_id")
        if (
            not isinstance(surface_id, str)
            or not surface_id
            or not isinstance(context_id, str)
            or not context_id
            or (surface_id, context_id) in seen
        ):
            raise ValueError("SURFACE_ENRICHMENT_V7_V6_PARTS_INVALID")
        key = (surface_id, context_id)
        seen.add(key)
        row = progress.get(key)
        if row is None:
            missing.append({"surface_id": surface_id, "context_id": context_id})
        elif (
            row.proposal_version != 6
            or row.context_hash != raw.get("context_hash")
            or row.source_sha256 != raw.get("source_sha256")
        ):
            raise ValueError("SURFACE_ENRICHMENT_V7_V6_PART_CHANGED")
    if any(
        row.proposal_version == 6 and key not in seen for key, row in progress.items()
    ):
        raise ValueError("SURFACE_ENRICHMENT_V7_V6_PART_CHANGED")
    return missing
