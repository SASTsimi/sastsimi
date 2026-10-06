"""Every Final v2 verdict is rechecked without replaying saved Pro/Con or PoC."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.runner import SimpleRuntimeRunner
from sastsimi.simple_runtime.store import SimpleCheckpointStore


@pytest.mark.asyncio
@pytest.mark.parametrize("legacy_verdict", ["HOLD", "TRUE", "FALSE"])
async def test_legacy_final_verdict_resumes_from_final_with_saved_poc(
    tmp_path: Path,
    legacy_verdict: Literal["HOLD", "TRUE", "FALSE"],
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-resume",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    proposal_ref = artifacts.put_json({"kind": "simple_hypothesis_proposal"})
    source_ref = artifacts.put_json({"kind": "simple_candidate_file_context_v1"})
    pro_ref = artifacts.put_json({"kind": "simple_pro_evidence"})
    con_ref = artifacts.put_json({"kind": "simple_con_evidence"})
    initial_ref = artifacts.put_json({"kind": "simple_initial_verification"})
    candidate_ref = artifacts.put_json({"kind": "simple_poc_candidate"})
    script_ref = artifacts.put_bytes(b"#!/bin/sh\nexit 0\n", "text/x-shellscript")
    execution_ref = artifacts.put_json({"kind": "simple_poc_execution"})
    validated_ref = artifacts.put_json({"kind": "simple_validated_poc"})
    old_final_ref = artifacts.put_json(
        {
            "kind": "simple_verification_result",
            "result": {"verdict": legacy_verdict},
        }
    )
    new_final_ref = artifacts.put_json(
        {
            "kind": "simple_verification_result",
            "result": {"verdict": "HOLD", "rechecked": True},
        }
    )

    def save(
        stage: SimpleStage,
        inputs: tuple[StoredDataRef, ...] = (),
        outputs: tuple[StoredDataRef, ...] = (),
        *,
        version: str | None = None,
        verdict: Literal["TRUE", "FALSE", "HOLD"] | None = None,
        validated: StoredDataRef | None = None,
    ) -> StageCheckpoint:
        checkpoint = StageCheckpoint(
            identity=identity,
            stage=stage,
            stage_version=version or STAGE_VERSION[stage],
            status=StageStatus.SUCCEEDED,
            input_refs=inputs,
            input_hash=input_reference_hash(inputs),
            output_refs=outputs,
            verdict=verdict,
            validated_poc_ref=validated,
        )
        store.save_checkpoint(checkpoint)
        return checkpoint

    pro = save(
        SimpleStage.PRO_CON_DONE,
        (proposal_ref, source_ref),
        (pro_ref, con_ref),
    )
    save(SimpleStage.VERIFICATION_INITIAL_DONE, pro.output_refs, (initial_ref,))
    candidate = save(
        SimpleStage.POC_CANDIDATE_DONE, (initial_ref,), (candidate_ref, script_ref)
    )
    poc = save(
        SimpleStage.POC_EXECUTION_DONE,
        candidate.output_refs,
        (execution_ref, validated_ref),
        validated=validated_ref,
    )
    old_final = save(
        SimpleStage.VERIFICATION_FINAL_DONE,
        poc.output_refs,
        (old_final_ref,),
        version="2",
        verdict=legacy_verdict,
        validated=validated_ref,
    )

    calls: list[SimpleStage] = []

    async def final_handler(checkpoint: StageCheckpoint, prior: object) -> StageResult:
        calls.append(checkpoint.stage)
        assert store.require(identity, SimpleStage.PRO_CON_DONE) == pro
        assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == poc
        assert (
            store.require(identity, SimpleStage.POC_EXECUTION_DONE).validated_poc_ref
            == validated_ref
        )
        return StageResult(
            output_refs=(new_final_ref,),
            verdict="HOLD",
            validated_poc_ref=validated_ref,
        )

    async def harmless_handler(
        checkpoint: StageCheckpoint, prior: object
    ) -> StageResult:
        calls.append(checkpoint.stage)
        return StageResult(output_refs=())

    runner = SimpleRuntimeRunner(
        store,
        {
            SimpleStage.VERIFICATION_FINAL_DONE: final_handler,
            SimpleStage.PRIMITIVE_ADMISSION_DONE: harmless_handler,
            SimpleStage.CHAINING_DONE: harmless_handler,
        },
    )
    assert old_final.verdict == legacy_verdict
    assert old_final.output_refs == (old_final_ref,)
    await runner.resume_hypothesis(identity)

    assert calls[0] is SimpleStage.VERIFICATION_FINAL_DONE
    assert store.require(identity, SimpleStage.PRO_CON_DONE) == pro
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == poc
    updated = store.require(identity, SimpleStage.VERIFICATION_FINAL_DONE)
    assert updated.output_refs == (new_final_ref,)
    assert updated.verdict == "HOLD"
    assert updated.validated_poc_ref == validated_ref


@pytest.mark.asyncio
async def test_redacted_anchor_failure_retries_initial_stage_without_replaying_pro_con(
    tmp_path: Path,
) -> None:
    """A known-safe redaction migration retries only the failed anchor stage."""

    identity = CheckpointIdentity(
        analysis_id="analysis-redacted-anchor-resume",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    proposal_ref = artifacts.put_json({"kind": "simple_hypothesis_proposal"})
    source_ref = artifacts.put_json({"kind": "simple_candidate_file_context_v1"})
    pro_ref = artifacts.put_json({"kind": "simple_pro_evidence"})
    con_ref = artifacts.put_json({"kind": "simple_con_evidence"})
    initial_ref = artifacts.put_json({"kind": "simple_initial_verification"})
    pro_con = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        stage_version=STAGE_VERSION[SimpleStage.PRO_CON_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=(proposal_ref, source_ref),
        input_hash=input_reference_hash((proposal_ref, source_ref)),
        output_refs=(pro_ref, con_ref),
        attempt_number=1,
    )
    store.save_checkpoint(pro_con)
    failed = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE],
        status=StageStatus.FAILED,
        input_refs=pro_con.output_refs,
        input_hash=input_reference_hash(pro_con.output_refs),
        attempt_number=1,
        error_code="HYPOTHESIS_ANCHOR_INVALID",
        retryable=False,
    )
    store.save_checkpoint(failed)
    calls: list[SimpleStage] = []

    async def initial_handler(
        checkpoint: StageCheckpoint, _prior: object
    ) -> StageResult:
        calls.append(checkpoint.stage)
        assert checkpoint.attempt_number == 2
        assert store.require(identity, SimpleStage.PRO_CON_DONE) == pro_con
        return StageResult(output_refs=(initial_ref,))

    async def remaining_handler(
        checkpoint: StageCheckpoint, _prior: object
    ) -> StageResult:
        calls.append(checkpoint.stage)
        return StageResult(output_refs=())

    handlers = {
        stage: remaining_handler
        for stage in HYPOTHESIS_STAGES
        if stage
        not in {SimpleStage.PRO_CON_DONE, SimpleStage.VERIFICATION_INITIAL_DONE}
    }
    handlers[SimpleStage.VERIFICATION_INITIAL_DONE] = initial_handler
    outcome = await SimpleRuntimeRunner(
        store,
        handlers,
        redacted_anchor_resume=True,
    ).resume_hypothesis(identity)

    assert outcome.status is StageStatus.SUCCEEDED
    assert calls[0] is SimpleStage.VERIFICATION_INITIAL_DONE
    assert SimpleStage.PRO_CON_DONE not in calls
    restored = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
    assert restored.status is StageStatus.SUCCEEDED
    assert restored.attempt_number == 2
    assert store.require(identity, SimpleStage.PRO_CON_DONE) == pro_con


@pytest.mark.asyncio
async def test_redacted_anchor_failure_retries_final_stage_without_replaying_poc(
    tmp_path: Path,
) -> None:
    """The same safe migration replays a failed final anchor check only."""

    identity = CheckpointIdentity(
        analysis_id="analysis-redacted-final-anchor-resume",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    proposal_ref = artifacts.put_json({"kind": "simple_hypothesis_proposal"})
    source_ref = artifacts.put_json({"kind": "simple_candidate_file_context_v1"})
    pro_ref = artifacts.put_json({"kind": "simple_pro_evidence"})
    con_ref = artifacts.put_json({"kind": "simple_con_evidence"})
    initial_ref = artifacts.put_json({"kind": "simple_initial_verification"})
    candidate_ref = artifacts.put_json({"kind": "simple_poc_candidate"})
    script_ref = artifacts.put_bytes(b"#!/bin/sh\nexit 0\n", "text/x-shellscript")
    execution_ref = artifacts.put_json({"kind": "simple_poc_execution"})
    validated_ref = artifacts.put_json({"kind": "simple_validated_poc"})
    final_ref = artifacts.put_json({"kind": "simple_verification_result"})

    def save(
        stage: SimpleStage,
        inputs: tuple[StoredDataRef, ...] = (),
        outputs: tuple[StoredDataRef, ...] = (),
        *,
        validated: StoredDataRef | None = None,
    ) -> StageCheckpoint:
        checkpoint = StageCheckpoint(
            identity=identity,
            stage=stage,
            stage_version=STAGE_VERSION[stage],
            status=StageStatus.SUCCEEDED,
            input_refs=inputs,
            input_hash=input_reference_hash(inputs),
            output_refs=outputs,
            validated_poc_ref=validated,
            attempt_number=1,
        )
        store.save_checkpoint(checkpoint)
        return checkpoint

    pro_con = save(
        SimpleStage.PRO_CON_DONE,
        (proposal_ref, source_ref),
        (pro_ref, con_ref),
    )
    initial = save(
        SimpleStage.VERIFICATION_INITIAL_DONE,
        pro_con.output_refs,
        (initial_ref,),
    )
    candidate = save(
        SimpleStage.POC_CANDIDATE_DONE,
        initial.output_refs,
        (candidate_ref, script_ref),
    )
    poc = save(
        SimpleStage.POC_EXECUTION_DONE,
        candidate.output_refs,
        (execution_ref, validated_ref),
        validated=validated_ref,
    )
    failed = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.VERIFICATION_FINAL_DONE,
        stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_FINAL_DONE],
        status=StageStatus.FAILED,
        input_refs=poc.output_refs,
        input_hash=input_reference_hash(poc.output_refs),
        attempt_number=1,
        error_code="HYPOTHESIS_ANCHOR_INVALID",
        retryable=False,
    )
    store.save_checkpoint(failed)
    calls: list[SimpleStage] = []

    async def final_handler(
        checkpoint: StageCheckpoint, _prior: object
    ) -> StageResult:
        calls.append(checkpoint.stage)
        assert checkpoint.attempt_number == 2
        assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == poc
        return StageResult(
            output_refs=(final_ref,),
            verdict="FALSE",
            validated_poc_ref=validated_ref,
        )

    outcome = await SimpleRuntimeRunner(
        store,
        {SimpleStage.VERIFICATION_FINAL_DONE: final_handler},
        redacted_anchor_resume=True,
    ).resume_hypothesis(identity)

    assert outcome.status is StageStatus.SUCCEEDED
    assert calls == [SimpleStage.VERIFICATION_FINAL_DONE]
    restored = store.require(identity, SimpleStage.VERIFICATION_FINAL_DONE)
    assert restored.status is StageStatus.SUCCEEDED
    assert restored.attempt_number == 2
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == poc


@pytest.mark.asyncio
async def test_redacted_anchor_failure_stays_terminal_after_three_attempts(
    tmp_path: Path,
) -> None:
    """The migration does not reopen an anchor failure beyond its bound."""

    identity = CheckpointIdentity(
        analysis_id="analysis-redacted-anchor-bound",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.PRO_CON_DONE,
            stage_version=STAGE_VERSION[SimpleStage.PRO_CON_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(),
            attempt_number=1,
        )
    )
    failed = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE],
        status=StageStatus.FAILED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_number=3,
        error_code="HYPOTHESIS_ANCHOR_INVALID",
        retryable=False,
    )
    store.save_checkpoint(failed)
    calls: list[SimpleStage] = []

    async def handler(
        checkpoint: StageCheckpoint, _prior: object
    ) -> StageResult:
        calls.append(checkpoint.stage)
        return StageResult(output_refs=())

    outcome = await SimpleRuntimeRunner(
        store,
        {SimpleStage.VERIFICATION_INITIAL_DONE: handler},
        redacted_anchor_resume=True,
    ).resume_hypothesis(identity)

    assert outcome.status is StageStatus.FAILED
    assert outcome.error_code == "HYPOTHESIS_ANCHOR_INVALID"
    assert calls == []
