"""Explicit resume of a fixed anchor validator retains prior child work."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pytest

from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime.application import (
    HypothesisBootstrap,
    SimpleAnalysisApplication,
    StaticBootstrap,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.runner import (
    SimpleRuntimeRunner,
    SimpleStageHandler,
    StageFailed,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _child(name: str) -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="analysis-anchor-resume",
        workspace_id="workspace-anchor-resume",
        commit_id="a" * 40,
        hypothesis_id=name,
    )


def _seed_pro_con(
    store: SimpleCheckpointStore, data_dir: Path, identity: CheckpointIdentity
) -> StageCheckpoint:
    artifacts = SimpleArtifactRepository(data_dir, identity)
    proposal = artifacts.put_json({"kind": "proposal", "child": identity.hypothesis_id})
    context = artifacts.put_json({"kind": "context", "child": identity.hypothesis_id})
    pro = artifacts.put_json({"kind": "pro", "child": identity.hypothesis_id})
    con = artifacts.put_json({"kind": "con", "child": identity.hypothesis_id})
    inputs = (proposal, context)
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        stage_version=STAGE_VERSION[SimpleStage.PRO_CON_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=inputs,
        input_hash=input_reference_hash(inputs),
        output_refs=(pro, con),
        attempt_id=f"{identity.hypothesis_id}-pro-con",
    )
    store.save_checkpoint(checkpoint)
    return checkpoint


def _fail_stage(
    store: SimpleCheckpointStore,
    identity: CheckpointIdentity,
    stage: SimpleStage,
    code: str,
    *,
    status: StageStatus = StageStatus.FAILED,
) -> StageCheckpoint:
    started = store.mark_running(
        identity,
        stage,
        store.input_refs_for(identity, stage),
        attempt_id=f"{identity.hypothesis_id}-{stage.value}-first",
    )
    return store.mark_failure(
        started,
        StageFailure(code=code, retryable=False, safe_message="saved failure"),
        status,
    )


def _seed_initial(
    store: SimpleCheckpointStore,
    data_dir: Path,
    identity: CheckpointIdentity,
    *,
    terminal: bool,
) -> StageCheckpoint:
    artifacts = SimpleArtifactRepository(data_dir, identity)
    result = artifacts.put_json(
        {
            "kind": "simple_initial_verification",
            "attempt_id": f"{identity.hypothesis_id}-initial",
            "result": {"unmet_external_prerequisites": ["external service absent"]},
        }
    )
    inputs = store.input_refs_for(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=inputs,
        input_hash=input_reference_hash(inputs),
        output_refs=(result,),
        attempt_id=f"{identity.hypothesis_id}-initial",
        verdict="HOLD" if terminal else None,
        external_prerequisites_ref=result if terminal else None,
    )
    store.save_checkpoint(checkpoint)
    return checkpoint


def _application(
    data_dir: Path,
    store: SimpleCheckpointStore,
    children: tuple[CheckpointIdentity, ...],
    handlers: Mapping[SimpleStage, SimpleStageHandler],
) -> SimpleAnalysisApplication:
    root = children[0].model_copy(update={"hypothesis_id": None})
    artifacts = SimpleArtifactRepository(data_dir, root)
    static = artifacts.put_json({"kind": "legacy-static"})
    profile = artifacts.put_json({"kind": "repository-profile"})
    display = AnalysisDisplayIdStore(store.database_path).get_or_allocate(
        root.analysis_id
    )
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=root.analysis_id,
            display_analysis_id=display,
            workspace_id=root.workspace_id,
            commit_id=root.commit_id,
            repository="https://example.invalid/repository.git",
            workspace_path=data_dir / "workspace",
            repository_profile_ref=profile,
            static_bundle_ref=static,
            hypothesis_ids=tuple(child.hypothesis_id or "" for child in children),
        )
    )

    def runner_factory(
        current_store: SimpleCheckpointStore,
        identity: CheckpointIdentity,
        _static: StaticBootstrapResult,
    ) -> SimpleRuntimeRunner:
        return SimpleRuntimeRunner(
            current_store,
            handlers,
            cleanup_artifacts=SimpleArtifactRepository(data_dir, identity),
        )

    return SimpleAnalysisApplication(
        data_dir=data_dir,
        store=store,
        static_bootstrap=cast(StaticBootstrap, object()),
        hypothesis_bootstrap=cast(HypothesisBootstrap, object()),
        runner_factory=runner_factory,
    )


@pytest.mark.asyncio
async def test_resume_retries_only_failed_anchor_child_and_keeps_completed_work(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    failed, complete, poc_blocked = (
        _child("hypothesis-anchor"),
        _child("hypothesis-complete"),
        _child("hypothesis-poc-blocked"),
    )
    pro_con = _seed_pro_con(store, data_dir, failed)
    initial_failure = _fail_stage(
        store,
        failed,
        SimpleStage.VERIFICATION_INITIAL_DONE,
        "HYPOTHESIS_ANCHOR_INVALID",
    )
    _seed_pro_con(store, data_dir, complete)
    complete_initial = _seed_initial(store, data_dir, complete, terminal=True)
    _seed_pro_con(store, data_dir, poc_blocked)
    poc_initial = _seed_initial(store, data_dir, poc_blocked, terminal=False)
    candidate_ref = SimpleArtifactRepository(data_dir, poc_blocked).put_json(
        {"kind": "poc-candidate", "child": poc_blocked.hypothesis_id}
    )
    candidate_inputs = poc_initial.output_refs
    store.save_checkpoint(
        StageCheckpoint(
            identity=poc_blocked,
            stage=SimpleStage.POC_CANDIDATE_DONE,
            stage_version=STAGE_VERSION[SimpleStage.POC_CANDIDATE_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=candidate_inputs,
            input_hash=input_reference_hash(candidate_inputs),
            output_refs=(candidate_ref,),
            attempt_id="poc-candidate-first",
        )
    )
    # A separate PoC failure may exist after initial verification succeeds.
    poc_failure = _fail_stage(
        store,
        poc_blocked,
        SimpleStage.POC_EXECUTION_DONE,
        "POC_ENVIRONMENT_UNVERIFIED",
        status=StageStatus.BLOCKED,
    )
    calls: list[str] = []

    async def initial(
        checkpoint: StageCheckpoint, prior: Mapping[SimpleStage, StageCheckpoint]
    ) -> StageResult:
        calls.append(checkpoint.identity.hypothesis_id or "")
        artifacts = SimpleArtifactRepository(data_dir, checkpoint.identity)
        result = artifacts.put_json(
            {
                "kind": "simple_initial_verification",
                "attempt_id": checkpoint.attempt_id,
                "result": {"unmet_external_prerequisites": ["external service absent"]},
            }
        )
        return StageResult(
            output_refs=(result,), verdict="HOLD", external_prerequisites_ref=result
        )

    app = _application(
        data_dir,
        store,
        (failed, complete, poc_blocked),
        {SimpleStage.VERIFICATION_INITIAL_DONE: initial},
    )
    outcome = await app.resume(failed.analysis_id)

    assert outcome.status == "BLOCKED"
    assert outcome.error_code == "POC_ENVIRONMENT_UNVERIFIED"
    assert calls == ["hypothesis-anchor"]
    retried = store.require(failed, SimpleStage.VERIFICATION_INITIAL_DONE)
    assert retried.status is StageStatus.SUCCEEDED
    assert retried.attempt_number == 2
    assert retried.attempt_id != initial_failure.attempt_id
    assert store.require(failed, SimpleStage.PRO_CON_DONE) == pro_con
    assert (
        store.require(complete, SimpleStage.VERIFICATION_INITIAL_DONE)
        == complete_initial
    )
    assert (
        store.require(poc_blocked, SimpleStage.VERIFICATION_INITIAL_DONE) == poc_initial
    )
    assert store.require(poc_blocked, SimpleStage.POC_EXECUTION_DONE) == poc_failure


@pytest.mark.asyncio
async def test_resume_caps_repeated_anchor_failure_without_reopening_other_codes(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    anchor, other = _child("hypothesis-anchor"), _child("hypothesis-other")
    _seed_pro_con(store, data_dir, anchor)
    _fail_stage(
        store,
        anchor,
        SimpleStage.VERIFICATION_INITIAL_DONE,
        "HYPOTHESIS_ANCHOR_INVALID",
    )
    _seed_pro_con(store, data_dir, other)
    other_failure = _fail_stage(
        store,
        other,
        SimpleStage.VERIFICATION_INITIAL_DONE,
        "HYPOTHESIS_EVIDENCE_INVALID",
    )
    calls = 0

    async def still_invalid(
        checkpoint: StageCheckpoint, prior: Mapping[SimpleStage, StageCheckpoint]
    ) -> StageResult:
        nonlocal calls
        calls += 1
        raise StageFailed(
            StageFailure(
                code="HYPOTHESIS_ANCHOR_INVALID",
                retryable=False,
                safe_message="anchor remains invalid",
            )
        )

    app = _application(
        data_dir,
        store,
        (anchor, other),
        {SimpleStage.VERIFICATION_INITIAL_DONE: still_invalid},
    )
    await app.resume(anchor.analysis_id)
    await app.resume(anchor.analysis_id)
    await app.resume(anchor.analysis_id)

    assert calls == 2
    final = store.require(anchor, SimpleStage.VERIFICATION_INITIAL_DONE)
    assert final.status is StageStatus.FAILED
    assert final.error_code == "HYPOTHESIS_ANCHOR_INVALID"
    assert final.attempt_number == 3
    assert store.require(other, SimpleStage.VERIFICATION_INITIAL_DONE) == other_failure

    # A later stage-version change must not reset the exhausted attempt count.
    store.save_checkpoint(final.model_copy(update={"stage_version": "legacy"}))
    await app.resume(anchor.analysis_id)
    assert calls == 2
    assert (
        store.require(anchor, SimpleStage.VERIFICATION_INITIAL_DONE).attempt_number == 3
    )


@pytest.mark.asyncio
async def test_resume_retries_final_anchor_without_repeating_completed_poc(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    child = _child("hypothesis-final")
    saved: dict[SimpleStage, StageCheckpoint] = {
        SimpleStage.PRO_CON_DONE: _seed_pro_con(store, data_dir, child)
    }
    artifacts = SimpleArtifactRepository(data_dir, child)
    for stage in (
        SimpleStage.VERIFICATION_INITIAL_DONE,
        SimpleStage.POC_CANDIDATE_DONE,
        SimpleStage.POC_EXECUTION_DONE,
    ):
        inputs = store.input_refs_for(child, stage)
        result = artifacts.put_json({"kind": stage.value, "child": child.hypothesis_id})
        checkpoint = StageCheckpoint(
            identity=child,
            stage=stage,
            stage_version=STAGE_VERSION[stage],
            status=StageStatus.SUCCEEDED,
            input_refs=inputs,
            input_hash=input_reference_hash(inputs),
            output_refs=(result,),
            attempt_id=f"{stage.value}-first",
        )
        store.save_checkpoint(checkpoint)
        saved[stage] = checkpoint
    failed = _fail_stage(
        store, child, SimpleStage.VERIFICATION_FINAL_DONE, "HYPOTHESIS_ANCHOR_INVALID"
    )
    calls: list[SimpleStage] = []

    async def final(
        checkpoint: StageCheckpoint, prior: Mapping[SimpleStage, StageCheckpoint]
    ) -> StageResult:
        calls.append(checkpoint.stage)
        ref = artifacts.put_json({"kind": "final", "attempt_id": checkpoint.attempt_id})
        return StageResult(output_refs=(ref,), verdict="FALSE")

    app = _application(
        data_dir,
        store,
        (child,),
        {SimpleStage.VERIFICATION_FINAL_DONE: final},
    )
    outcome = await app.resume(child.analysis_id)

    assert outcome.status == "COMPLETE"
    assert calls == [SimpleStage.VERIFICATION_FINAL_DONE]
    retried = store.require(child, SimpleStage.VERIFICATION_FINAL_DONE)
    assert retried.status is StageStatus.SUCCEEDED
    assert retried.attempt_number == 2
    assert retried.attempt_id != failed.attempt_id
    for stage, checkpoint in saved.items():
        assert store.require(child, stage) == checkpoint
