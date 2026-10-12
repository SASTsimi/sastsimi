"""A bounded second look must not mistake a partial negative review for coverage."""

from __future__ import annotations

from pathlib import Path

import pytest

from sastsimi.simple_runtime.application import SimpleAnalysisApplication
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attack_surfaces import AttackSurface, SurfaceIndex
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.store import SurfaceExplorationProgressRecord
from sastsimi.simple_runtime.surface_contexts import SurfaceContext


@pytest.mark.parametrize(
    ("parts", "omitted_lines", "expected"),
    [
        (["SENSITIVE_OPERATION", "TRUST_BOUNDARY"], 12, True),
        (["ENTRY", "SENSITIVE_OPERATION", "TRUST_BOUNDARY"], 12, False),
        (["SENSITIVE_OPERATION", "TRUST_BOUNDARY"], 0, False),
    ],
)
def test_saved_no_hypothesis_second_look_requires_missing_role_and_source(
    tmp_path: Path,
    parts: list[str],
    omitted_lines: int,
    expected: bool,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    surface = AttackSurface(
        surface_id="surface-1",
        type="SQL_EXECUTION",
        path="app.py",
        symbol="cursor.execute",
        line=7,
        linked_candidate_ids=(),
        evidence_refs=(),
        detector="fixture",
    )
    index = SurfaceIndex(
        scope_fingerprint="scope-1",
        static_bundle_hash="b" * 64,
        ast_manifest_hash="c" * 64,
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        candidate_inventory_hash="d" * 64,
        candidate_count=0,
        surfaces=(surface,),
        static_gaps=(),
        index_version=2,
    )
    context_ref = artifacts.put_json({"kind": "simple_surface_context_v1"})
    result_ref = artifacts.put_json({"reviewed_parts": parts})
    context = SurfaceContext(
        surface_id=surface.surface_id,
        context_id="context-1",
        context_hash=context_ref.content_hash,
        context_ref=context_ref,
        part_index=0,
        part_count=1,
        prompt_bytes=100,
        source_sha256="e" * 64,
        source_unavailable_reason=None,
        ast_unavailable_reason=None,
        omitted_source_line_count=omitted_lines,
        omitted_ast_fact_count=0,
    )
    progress = SurfaceExplorationProgressRecord(
        surface_id=surface.surface_id,
        context_id=context.context_id,
        static_bundle_hash=index.static_bundle_hash,
        index_hash="f" * 64,
        context_hash=context.context_hash,
        source_sha256=context.source_sha256,
        status="NO_HYPOTHESIS",
        result_ref=result_ref,
        hypothesis_ids=(),
        proposal_version=1,
    )

    assert (
        SimpleAnalysisApplication._surface_expansion_needed(
            index,
            (context,),
            {(surface.surface_id, context.context_id): progress},
            artifacts=artifacts,
        )
        is expected
    )
