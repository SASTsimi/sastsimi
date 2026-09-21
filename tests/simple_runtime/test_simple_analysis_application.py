from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.application import (
    HypothesisSeed,
    SimpleAnalysisApplication,
    SimpleAnalysisRequest,
    SimpleAnalysisRun,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.runner import SimpleRuntimeRunner
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _ref(name: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(f"stored-{name}"),
        data_kind=name,
        content_hash=hashlib.sha256(name.encode()).hexdigest(),
        workspace_id=WorkspaceId("workspace-1"),
        commit_id=CommitId("a" * 40),
        record_id=None,
    )


class _Static:
    async def run(
        self,
        request: SimpleAnalysisRequest,
        identity: CheckpointIdentity,
    ) -> StaticBootstrapResult:
        assert request.repository == "https://example.invalid/repo.git"
        return StaticBootstrapResult(
            repository_profile_ref=_ref("repository-profile"),
            static_bundle_ref=_ref("static-bundle"),
            workspace_path=request.data_dir / "workspaces" / identity.workspace_id,
        )


class _Hypotheses:
    async def propose(
        self,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> tuple[HypothesisSeed, ...]:
        del identity
        assert static.static_bundle_ref == _ref("static-bundle")
        return (
            HypothesisSeed(
                hypothesis_id="hypothesis-1",
                proposal_ref=_ref("hypothesis"),
            ),
        )


def _runner(
    store: SimpleCheckpointStore,
    identity: CheckpointIdentity,
    _static: StaticBootstrapResult,
) -> SimpleRuntimeRunner:
    del identity, _static
    handlers: dict[SimpleStage, Any] = {}
    for stage in tuple(SimpleStage)[2:]:

        async def handle(
            _checkpoint: StageCheckpoint,
            _prior: Mapping[SimpleStage, StageCheckpoint],
            *,
            current: SimpleStage = stage,
        ) -> StageResult:
            return StageResult(
                output_refs=(_ref(current.value.lower()),),
                verdict="FALSE"
                if current is SimpleStage.VERIFICATION_FINAL_DONE
                else None,
            )

        handlers[stage] = handle
    return SimpleRuntimeRunner(store, handlers)


@pytest.mark.asyncio
async def test_new_analysis_persists_bootstrap_then_runs_hypotheses(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=_runner,
        id_factory=iter(("analysis-1", "workspace-1")).__next__,
    )

    outcome = await application.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )

    assert outcome.status == "COMPLETE"
    assert outcome.display_analysis_id == "A-001"
    analysis_identity = outcome.identity.model_copy(update={"hypothesis_id": None})
    assert store.require(analysis_identity, SimpleStage.STATIC_DONE).status == (
        StageStatus.SUCCEEDED
    )
    hypothesis_checkpoint = store.require(
        analysis_identity,
        SimpleStage.HYPOTHESIS_DONE,
    )
    assert hypothesis_checkpoint.output_refs == (_ref("hypothesis"),)
    hypothesis_identity = outcome.identity.model_copy(
        update={"hypothesis_id": "hypothesis-1"}
    )
    assert (
        store.require(hypothesis_identity, SimpleStage.VERIFICATION_FINAL_DONE).verdict
        == "FALSE"
    )


class _BlockedStatic:
    calls = 0

    async def run(
        self,
        _request: SimpleAnalysisRequest,
        _identity: CheckpointIdentity,
    ) -> StaticBootstrapResult:
        self.calls += 1
        if self.calls == 1:
            raise RuntimeError("OPENGREP_EXECUTION_FAILED")
        return StaticBootstrapResult(
            repository_profile_ref=_ref("repository-profile"),
            static_bundle_ref=_ref("static-bundle"),
            workspace_path=_request.data_dir / "workspaces" / _identity.workspace_id,
        )


@pytest.mark.asyncio
async def test_bootstrap_failure_is_visible_and_never_false(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=(static := _BlockedStatic()),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=_runner,
        id_factory=iter(("analysis-1", "workspace-1")).__next__,
    )

    outcome = await application.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )

    assert outcome.status == "BLOCKED"
    failed = store.require(outcome.identity, SimpleStage.STATIC_DONE)
    assert failed.status == StageStatus.BLOCKED
    assert failed.error_code == "OPENGREP_EXECUTION_FAILED"
    assert failed.verdict is None
    assert store.list_checkpoints("analysis-1") == (failed,)

    resumed = await application.resume(outcome.display_analysis_id)

    assert resumed.identity.analysis_id == "analysis-1"
    assert resumed.status == "COMPLETE"
    assert static.calls == 2


@pytest.mark.asyncio
async def test_resume_reuses_static_and_hypothesis_results(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    static = _Static()
    hypotheses = _Hypotheses()
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=static,
        hypothesis_bootstrap=hypotheses,
        runner_factory=_runner,
        id_factory=iter(("analysis-1", "workspace-1")).__next__,
    )
    first = await application.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )

    resumed = await application.resume(first.display_analysis_id)

    assert resumed.status == "COMPLETE"
    assert len(store.list_checkpoints("analysis-1")) >= 4


def test_chaining_child_is_added_once_to_durable_analysis_queue(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    application = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=_runner,
    )
    identity = application_identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    chaining_ref = artifacts.put_json(
        {
            "kind": "simple_chaining_result",
            "children": [
                {
                    "title": "compound finding",
                    "parent_hypothesis_ids": ["hypothesis-1", "hypothesis-2"],
                }
            ],
        }
    )
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.CHAINING_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(chaining_ref,),
        )
    )
    run = SimpleAnalysisRun(
        analysis_id="analysis-1",
        display_analysis_id="A-001",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        repository="repo",
        hypothesis_ids=("hypothesis-1", "hypothesis-2"),
    )
    static = StaticBootstrapResult(
        repository_profile_ref=_ref("repository-profile"),
        static_bundle_ref=_ref("static-bundle"),
        workspace_path=tmp_path / "workspace",
    )

    updated = application._register_chain_children(run, application_identity, static)
    repeated = application._register_chain_children(
        updated,
        application_identity,
        static,
    )

    assert len(updated.hypothesis_ids) == 3
    assert repeated.hypothesis_ids == updated.hypothesis_ids
    child_id = updated.hypothesis_ids[-1]
    assert updated.chain_depths[child_id] == 1
