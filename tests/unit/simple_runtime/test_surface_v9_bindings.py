"""A v9 successor binds every completed v8 part without rewriting it."""

from dataclasses import replace
from pathlib import Path

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.store import SurfaceExplorationProgressRecord
from sastsimi.simple_runtime.surface_enrichment_v9_bindings import (
    missing_v8_part_set,
    prior_v8_progress_snapshot_hash,
)


def _case(tmp_path: Path) -> tuple[dict[str, object], SurfaceExplorationProgressRecord]:
    identity = CheckpointIdentity(
        analysis_id="analysis-v9",
        workspace_id="workspace-v9",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    result_ref = SimpleArtifactRepository(tmp_path, identity).put_json({"result": 1})
    row = SurfaceExplorationProgressRecord(
        surface_id="surface-1",
        context_id="context-1",
        static_bundle_hash="b" * 64,
        index_hash="c" * 64,
        context_hash="d" * 64,
        source_sha256="e" * 64,
        status="NO_HYPOTHESIS",
        result_ref=result_ref,
        hypothesis_ids=(),
        proposal_version=8,
    )
    plan: dict[str, object] = {
        "expected_parts": [
            {
                "surface_id": row.surface_id,
                "context_id": row.context_id,
                "context_hash": row.context_hash,
                "source_sha256": row.source_sha256,
            }
        ]
    }
    return plan, row


def test_v9_parent_hash_and_missing_parts_are_exact(tmp_path: Path) -> None:
    plan, row = _case(tmp_path)
    progress = {(row.surface_id, row.context_id): row}
    digest = prior_v8_progress_snapshot_hash(progress)
    assert len(digest) == 64
    assert missing_v8_part_set(plan, progress) == []
    assert missing_v8_part_set(plan, {}) == [
        {"surface_id": row.surface_id, "context_id": row.context_id}
    ]
    assert digest != prior_v8_progress_snapshot_hash(
        {
            (row.surface_id, row.context_id): replace(
                row,
                result_ref=row.result_ref.model_copy(update={"content_hash": "0" * 64}),
            )
        }
    )


def test_v9_parent_rejects_changed_or_extra_v8_part(tmp_path: Path) -> None:
    plan, row = _case(tmp_path)
    with pytest.raises(ValueError):
        missing_v8_part_set(
            plan,
            {(row.surface_id, row.context_id): replace(row, context_hash="f" * 64)},
        )
    with pytest.raises(ValueError):
        missing_v8_part_set(
            plan,
            {(row.surface_id, "extra"): replace(row, context_id="extra")},
        )
    with pytest.raises(ValueError):
        prior_v8_progress_snapshot_hash(
            {(row.surface_id, row.context_id): replace(row, proposal_version=9)}
        )
