"""Shared v9 proof recomputation must preserve the full pinned inventory."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attack_surfaces import (
    AttackSurface,
    SurfaceIndex,
    candidate_inventory_hash,
)
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_v9_runtime_evidence import (
    recompute_v9_runtime_evidence,
)


def _case(
    tmp_path: Path, *, candidate_count: int, surfaces: tuple[AttackSurface, ...]
) -> tuple[
    CheckpointIdentity, SurfaceIndex, SimpleArtifactRepository, SimpleCheckpointStore
]:
    identity = CheckpointIdentity(
        analysis_id="analysis-v9-evidence",
        workspace_id="workspace-v9-evidence",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    index = SurfaceIndex(
        scope_fingerprint="s" * 64,
        static_bundle_hash="b" * 64,
        ast_manifest_hash="c" * 64,
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        candidate_inventory_hash=candidate_inventory_hash(())
        if candidate_count == 0
        else "d" * 64,
        candidate_count=candidate_count,
        surfaces=surfaces,
        static_gaps=(),
        index_version=2,
        ast_source_hashes=(("app.py", "e" * 64),),
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    store = SimpleCheckpointStore(tmp_path / "data" / "db" / "sastsimi.sqlite3")
    return identity, index, artifacts, store


def test_v9_recompute_refuses_missing_candidate_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity, index, artifacts, store = _case(tmp_path, candidate_count=1, surfaces=())
    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_v9_runtime_evidence.index_ast_manifest",
        lambda *_args: {"app.py": {"source_sha256": "e" * 64}},
    )

    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V9_CANDIDATE_CHANGED"):
        recompute_v9_runtime_evidence(identity, index, tmp_path, artifacts, store, {})


def test_v9_recompute_reuses_one_call_index_for_all_surfaces(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = AttackSurface(
        surface_id="first",
        type="SQL_EXECUTION",
        path="app.py",
        symbol="execute",
        line=1,
        linked_candidate_ids=(),
        evidence_refs=(),
        detector="test",
    )
    second = replace(first, surface_id="second", line=2)
    identity, index, artifacts, store = _case(
        tmp_path, candidate_count=0, surfaces=(first, second)
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_v9_runtime_evidence.index_ast_manifest",
        lambda *_args: {"app.py": {"source_sha256": "e" * 64}},
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_v9_runtime_evidence.assess_optional_analyzers",
        lambda *_args: object(),
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_v9_runtime_evidence.discover_operational_route_maps",
        lambda *_args: object(),
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_v9_runtime_evidence.verify_operational_routes_v5",
        lambda *_args: object(),
    )
    shared_index = object()
    calls: list[tuple[object, ...]] = []

    def call_index(*args: object) -> object:
        calls.append(args)
        return shared_index

    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_v9_runtime_evidence.build_python_call_path_index",
        call_index,
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_v9_runtime_evidence.extract_surface_graph_v5",
        lambda _index, surface, *_args, **kwargs: (
            {"surface": surface.surface_id}
            if kwargs["call_index"] is shared_index
            else pytest.fail("call index was not shared")
        ),
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_v9_runtime_evidence.prove_intrinsic_surface",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_v9_runtime_evidence.certify_surface_paths",
        lambda *_args, **kwargs: (
            object()
            if kwargs["call_index"] is shared_index
            else pytest.fail("call index was not shared")
        ),
    )

    _applicability, _intrinsic, paths, graphs, candidates = (
        recompute_v9_runtime_evidence(identity, index, tmp_path, artifacts, store, {})
    )

    assert len(calls) == 1
    assert set(paths) == {"first", "second"}
    assert set(graphs) == {"first", "second"}
    assert candidates == {}
