"""The existing resume route finishes v9 before the deterministic successor."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path

import pytest

from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_enrichment_v9_bindings import (
    prior_v8_progress_snapshot_hash,
)
from tests.unit.simple_runtime.test_surface_coverage_v8 import _fixture
from tests.unit.simple_runtime.test_surface_v9_model_dispatch import _partial_v8_run


def _v9_run(tmp_path: Path) -> SimpleAnalysisRun:
    prior = _partial_v8_run(tmp_path)
    assert prior.candidate_terminal is not None
    assert prior.surface_enrichment_v8_plan_ref is not None
    return prior.model_copy(
        update={
            "surface_enrichment_v9_plan_ref": prior.surface_enrichment_v8_plan_ref,
            "candidate_terminal": prior.candidate_terminal.model_copy(
                update={"surface_proof_version": 7}
            ),
        }
    )


def test_completed_v9_selects_successor_round(tmp_path: Path) -> None:
    run = _v9_run(tmp_path)

    assert SimpleAnalysisApplication._surface_enrichment_round(run) == "v10"


def test_completed_v9_resume_dispatches_successor_without_repeating_v9(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run = _v9_run(tmp_path)
    identity = CheckpointIdentity(
        analysis_id=run.analysis_id,
        workspace_id=run.workspace_id,
        commit_id=run.commit_id,
        hypothesis_id=None,
    )
    app = object.__new__(SimpleAnalysisApplication)
    app._data_dir = tmp_path
    calls: list[str] = []
    result = SimpleAnalysisOutcome(
        identity=identity,
        display_analysis_id=run.display_analysis_id,
        status="PARTIAL",
        current_stage=SimpleStage.HYPOTHESIS_DONE,
    )

    class _Store:
        def clear_stale_hypothesis_claims(self, root: CheckpointIdentity) -> None:
            assert root == identity
            calls.append("clear-claims")

        def require_analysis_run(self, analysis_id: str) -> SimpleAnalysisRun:
            assert analysis_id == run.analysis_id
            return run

    monkeypatch.setattr(app, "_store", _Store(), raising=False)

    def saved_v9(*_args: object) -> tuple[dict[str, str], tuple[()]]:
        calls.append("saved-v9")
        return {"kind": "simple_surface_enrichment_plan_v9"}, ()

    async def run_v9(*_args: object) -> SimpleAnalysisOutcome:
        calls.append("run-v9")
        return result

    async def run_v10(*_args: object) -> SimpleAnalysisOutcome:
        calls.append("run-v10")
        return result

    monkeypatch.setattr(app, "_saved_surface_enrichment_v9", saved_v9)
    monkeypatch.setattr(app, "_run_v9_surface_enrichment", run_v9)
    monkeypatch.setattr(app, "_run_v10_surface_enrichment", run_v10, raising=False)
    assert run.surface_enrichment_v8_plan_ref is not None
    static = StaticBootstrapResult(
        repository_profile_ref=run.surface_enrichment_v8_plan_ref,
        static_bundle_ref=run.surface_enrichment_v8_plan_ref,
        workspace_path=tmp_path,
    )

    outcome = asyncio.run(app._run_candidate_pipeline(run, identity, static))

    assert outcome == result
    assert calls == ["clear-claims", "run-v10"]


def test_unfinished_v9_resume_runs_successor_only_after_v9_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    completed = _v9_run(tmp_path)
    assert completed.candidate_terminal is not None
    unfinished = completed.model_copy(
        update={
            "candidate_terminal": completed.candidate_terminal.model_copy(
                update={"surface_proof_version": 6}
            )
        }
    )
    identity = CheckpointIdentity(
        analysis_id=completed.analysis_id,
        workspace_id=completed.workspace_id,
        commit_id=completed.commit_id,
        hypothesis_id=None,
    )
    app = object.__new__(SimpleAnalysisApplication)
    app._data_dir = tmp_path
    calls: list[str] = []
    result = SimpleAnalysisOutcome(
        identity=identity,
        display_analysis_id=completed.display_analysis_id,
        status="PARTIAL",
        current_stage=SimpleStage.HYPOTHESIS_DONE,
    )

    class _Store:
        current = unfinished

        def clear_stale_hypothesis_claims(self, root: CheckpointIdentity) -> None:
            assert root == identity
            calls.append("clear-claims")

        def require_analysis_run(self, _analysis_id: str) -> SimpleAnalysisRun:
            return self.current

    store = _Store()
    monkeypatch.setattr(app, "_store", store, raising=False)

    def saved_v9(*_args: object) -> tuple[dict[str, str], tuple[()]]:
        calls.append("saved-v9")
        return {"kind": "simple_surface_enrichment_plan_v9"}, ()

    async def run_v9(*_args: object) -> SimpleAnalysisOutcome:
        calls.append("run-v9")
        store.current = completed
        return result

    async def run_v10(*_args: object) -> SimpleAnalysisOutcome:
        calls.append("run-v10")
        return result

    monkeypatch.setattr(app, "_saved_surface_enrichment_v9", saved_v9)
    monkeypatch.setattr(app, "_run_v9_surface_enrichment", run_v9)
    monkeypatch.setattr(app, "_run_v10_surface_enrichment", run_v10, raising=False)
    assert unfinished.surface_enrichment_v8_plan_ref is not None
    static = StaticBootstrapResult(
        repository_profile_ref=unfinished.surface_enrichment_v8_plan_ref,
        static_bundle_ref=unfinished.surface_enrichment_v8_plan_ref,
        workspace_path=tmp_path,
    )

    assert (
        asyncio.run(app._run_candidate_pipeline(unfinished, identity, static)) == result
    )
    assert calls == ["clear-claims", "saved-v9", "run-v9", "run-v10"]


def test_v10_failure_after_v9_is_reported_as_v10(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    completed = _v9_run(tmp_path)
    assert completed.candidate_terminal is not None
    unfinished = completed.model_copy(
        update={
            "candidate_terminal": completed.candidate_terminal.model_copy(
                update={"surface_proof_version": 6}
            )
        }
    )
    identity = CheckpointIdentity(
        analysis_id=completed.analysis_id,
        workspace_id=completed.workspace_id,
        commit_id=completed.commit_id,
        hypothesis_id=None,
    )
    app = object.__new__(SimpleAnalysisApplication)
    app._data_dir = tmp_path

    class _Store:
        def clear_stale_hypothesis_claims(self, root: CheckpointIdentity) -> None:
            assert root == identity

        def require_analysis_run(self, _analysis_id: str) -> SimpleAnalysisRun:
            return completed

    monkeypatch.setattr(app, "_store", _Store(), raising=False)
    monkeypatch.setattr(app, "_saved_surface_enrichment_v9", lambda *_args: ({}, ()))

    async def run_v9(*_args: object) -> SimpleAnalysisOutcome:
        return SimpleAnalysisOutcome(
            identity=identity,
            display_analysis_id=completed.display_analysis_id,
            status="PARTIAL",
            current_stage=SimpleStage.HYPOTHESIS_DONE,
        )

    async def run_v10(*_args: object) -> SimpleAnalysisOutcome:
        raise RuntimeError("unexpected v10 failure")

    monkeypatch.setattr(app, "_run_v9_surface_enrichment", run_v9)
    monkeypatch.setattr(app, "_run_v10_surface_enrichment", run_v10)
    monkeypatch.setattr(app, "_v4_failure_outcome", lambda _run, outcome: outcome)
    assert unfinished.surface_enrichment_v8_plan_ref is not None
    static = StaticBootstrapResult(
        repository_profile_ref=unfinished.surface_enrichment_v8_plan_ref,
        static_bundle_ref=unfinished.surface_enrichment_v8_plan_ref,
        workspace_path=tmp_path,
    )

    outcome = asyncio.run(app._run_candidate_pipeline(unfinished, identity, static))

    assert outcome.status == "BLOCKED"
    assert outcome.error_code == "SURFACE_ENRICHMENT_V10_REPLAY_INVALID"


def test_v10_runtime_pins_and_promotes_same_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity, index, parent, terminal, proof = _fixture()
    data_dir = tmp_path / "data"
    artifacts = SimpleArtifactRepository(data_dir, identity)
    bundle_ref = artifacts.put_json({"ast_summary": {}})
    index = replace(index, static_bundle_hash=bundle_ref.content_hash)
    index_ref = artifacts.put_json(index.to_json())
    v9_plan_ref = artifacts.put_json(
        {
            "kind": "simple_surface_enrichment_plan_v9",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "scope_fingerprint": index.scope_fingerprint,
            "static_bundle_hash": index.static_bundle_hash,
            "index_hash": index_ref.content_hash,
            "prior_v8_progress_hash": prior_v8_progress_snapshot_hash({}),
            "expected_parts": [],
        }
    )
    parent = replace(
        parent,
        static_bundle_hash=index.static_bundle_hash,
        index_hash=index_ref.content_hash,
        v9_plan_ref=v9_plan_ref,
    )
    coverage_ref = artifacts.put_json(parent.to_json())
    terminal = terminal.model_copy(
        update={
            "bundle_hash": index.static_bundle_hash,
            "surface_index_hash": index_ref.content_hash,
            "surface_coverage_hash": coverage_ref.content_hash,
            "scope_certificate_hash": parent.scope_certificate_ref.content_hash,
        }
    )
    proof = replace(proof, source_hashes=index.ast_source_hashes)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    dummy_ref = artifacts.put_json({"kind": "prior-plan"})
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/repository",
        workspace_path=workspace,
        repository_profile_ref=dummy_ref,
        static_bundle_ref=bundle_ref,
        candidate_scope_fingerprint=index.scope_fingerprint,
        candidate_terminal=terminal,
        surface_enrichment_plan_ref=dummy_ref,
        surface_enrichment_v5_plan_ref=dummy_ref,
        surface_enrichment_v6_plan_ref=dummy_ref,
        surface_enrichment_v7_plan_ref=dummy_ref,
        surface_enrichment_v8_plan_ref=dummy_ref,
        surface_enrichment_v9_plan_ref=v9_plan_ref,
        python_scope_certificate_ref=dummy_ref,
    )
    store = SimpleCheckpointStore(
        data_dir / "db" / "ledger.sqlite3", artifact_data_dir=data_dir
    )
    store.save_analysis_run(run)
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.HYPOTHESIS_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(bundle_ref,),
            input_hash=input_reference_hash((bundle_ref,)),
            output_refs=(index_ref, coverage_ref),
        )
    )
    app = object.__new__(SimpleAnalysisApplication)
    app._data_dir = data_dir
    app._store = store
    monkeypatch.setattr(
        "sastsimi.simple_runtime.application.verified_saved_coverage_v7",
        lambda *_args: parent,
        raising=False,
    )
    monkeypatch.setattr(
        app,
        "_v9_evidence_from_pinned_source",
        lambda *_args: (None, {}, {}, {}, {}),
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.application.prove_route_boundaries_v10",
        lambda *_args: {proof.surface_id: proof},
        raising=False,
    )
    static = StaticBootstrapResult(
        repository_profile_ref=dummy_ref,
        static_bundle_ref=bundle_ref,
        workspace_path=workspace,
    )
    promote = store.promote_surface_enrichment_v10_coverage

    def interrupted_promote(*_args: object) -> bool:
        raise RuntimeError("synthetic interruption before atomic promotion")

    monkeypatch.setattr(
        store, "promote_surface_enrichment_v10_coverage", interrupted_promote
    )

    with pytest.raises(RuntimeError, match="synthetic interruption"):
        asyncio.run(app._run_v10_surface_enrichment(run, identity, static, artifacts))
    interrupted = store.require_analysis_run(identity.analysis_id)
    assert interrupted.surface_enrichment_v10_plan_ref is not None
    assert interrupted.candidate_terminal == terminal
    monkeypatch.setattr(store, "promote_surface_enrichment_v10_coverage", promote)

    outcome = asyncio.run(
        app._run_v10_surface_enrichment(interrupted, identity, static, artifacts)
    )

    assert outcome.status == "COMPLETE"
    latest = store.require_analysis_run(identity.analysis_id)
    assert latest.analysis_id == run.analysis_id
    assert latest.surface_enrichment_v9_plan_ref == v9_plan_ref
    assert latest.surface_enrichment_v10_plan_ref is not None
    assert latest.candidate_terminal is not None
    assert latest.candidate_terminal.surface_proof_version == 8
    root = store.get(identity, SimpleStage.HYPOTHESIS_DONE)
    assert root is not None
    assert root.output_refs[0] == index_ref
    assert (
        root.output_refs[1].content_hash
        == latest.candidate_terminal.surface_coverage_hash
    )
    artifact_paths = {
        path.relative_to(artifacts.paths.artifacts)
        for path in artifacts.paths.artifacts.rglob("*")
        if path.is_file()
    }
    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_coverage_v8_read.verified_saved_coverage_v8",
        lambda *_args: None,
    )

    resumed = asyncio.run(
        app._run_v10_surface_enrichment(latest, identity, static, artifacts)
    )

    assert resumed == outcome
    assert store.require_analysis_run(identity.analysis_id) == latest
    assert store.get(identity, SimpleStage.HYPOTHESIS_DONE) == root
    assert {
        path.relative_to(artifacts.paths.artifacts)
        for path in artifacts.paths.artifacts.rglob("*")
        if path.is_file()
    } == artifact_paths
