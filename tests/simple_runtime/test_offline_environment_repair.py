from __future__ import annotations

import hashlib

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.observability.agent_activity import ActivityKind
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime.application import (
    OfflineRepairPreflight,
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
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
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore

OLD_BASE = "sha256:" + "1" * 64
NEW_BASE = "sha256:" + "2" * 64


def _checkpoint(
    identity: CheckpointIdentity,
    stage: SimpleStage,
    *,
    status: StageStatus,
    inputs: tuple = (),
    outputs: tuple = (),
    **extra: object,
) -> StageCheckpoint:
    return StageCheckpoint(
        identity=identity,
        stage=stage,
        stage_version=STAGE_VERSION[stage],
        status=status,
        input_refs=inputs,
        input_hash=input_reference_hash(inputs),
        output_refs=outputs,
        **extra,
    )


def _exhausted_poc(tmp_path, *, recipe_source: str = "GENERATED_OFFLINE_WHEELS"):
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(data_dir, identity)
    pro_con_ref = artifacts.put_json({"kind": "pro_con"})
    initial_ref = artifacts.put_json({"kind": "initial"})
    wheel_archive_ref = artifacts.put_bytes(b"wheel archive", "application/zip")
    recipe_ref = artifacts.put_json(
        {
            "kind": "simple_environment_recipe",
            "dockerfile_source": recipe_source,
            "build_network": "none",
            "base_image_digest": OLD_BASE,
            "wheel_archive_ref": wheel_archive_ref.model_dump(mode="json"),
            "wheel_archive_sha256": wheel_archive_ref.content_hash,
        }
    )
    candidate_ref = artifacts.put_json({"kind": "candidate"})
    execution_ref = artifacts.put_json({"kind": "execution", "exit_code": 2})
    pro_con = _checkpoint(
        identity,
        SimpleStage.PRO_CON_DONE,
        status=StageStatus.SUCCEEDED,
        outputs=(pro_con_ref,),
    )
    initial = _checkpoint(
        identity,
        SimpleStage.VERIFICATION_INITIAL_DONE,
        status=StageStatus.SUCCEEDED,
        inputs=(pro_con_ref,),
        outputs=(initial_ref,),
        recipe_ref=recipe_ref,
        image_digest="sha256:" + "3" * 64,
    )
    candidate = _checkpoint(
        identity,
        SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.SUCCEEDED,
        inputs=(initial_ref,),
        outputs=(candidate_ref,),
        attempt_id="attempt-3",
        attempt_number=3,
        recovery_lineage_id="4" * 64,
        recovery_origin_stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        recipe_ref=recipe_ref,
        image_digest="sha256:" + "3" * 64,
    )
    exhausted = _checkpoint(
        identity,
        SimpleStage.POC_EXECUTION_DONE,
        status=StageStatus.BLOCKED,
        inputs=(candidate_ref,),
        outputs=(execution_ref,),
        attempt_id="attempt-3",
        attempt_number=3,
        recovery_lineage_id="4" * 64,
        recovery_origin_stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        error_code="RECOVERY_EXHAUSTED",
        retryable=False,
        recipe_ref=recipe_ref,
        image_digest="sha256:" + "3" * 64,
    )
    for checkpoint in (pro_con, initial, candidate, exhausted):
        store.save_checkpoint(checkpoint)
    proof_ref = artifacts.put_json(
        {
            "kind": "simple_offline_environment_repair",
            "identity": identity.model_dump(mode="json"),
            "stage": SimpleStage.POC_EXECUTION_DONE.value,
            "exhausted_attempt_id": exhausted.attempt_id,
            "exhausted_attempt_number": exhausted.attempt_number,
            "exhausted_checkpoint_hash": hashlib.sha256(
                canonical_bytes(exhausted.model_dump(mode="json"))
            ).hexdigest(),
            "old_base_image_digest": OLD_BASE,
            "new_base_image_digest": NEW_BASE,
            "browser_command": "/usr/bin/chromium",
            "python_version": "3.12.15",
            "smoke_output_digest": "sha256:" + "5" * 64,
        }
    )
    return store, artifacts, pro_con, initial, candidate, exhausted, proof_ref


def test_repair_resets_only_child_stages_and_keeps_attempt_lineage(tmp_path) -> None:
    store, artifacts, pro_con, _initial, _candidate, exhausted, proof_ref = (
        _exhausted_poc(tmp_path)
    )
    identity = exhausted.identity
    other = identity.model_copy(update={"hypothesis_id": "other"})
    other_checkpoint = _checkpoint(
        other, SimpleStage.PRO_CON_DONE, status=StageStatus.SUCCEEDED
    )
    store.save_checkpoint(other_checkpoint)

    pending = store.prepare_offline_environment_repair(exhausted, proof_ref, artifacts)

    assert store.require(identity, SimpleStage.PRO_CON_DONE) == pro_con
    assert store.require(other, SimpleStage.PRO_CON_DONE) == other_checkpoint
    assert store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE) == pending
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 3
    assert pending.recovery_lineage_id == exhausted.recovery_lineage_id
    assert pending.recipe_ref is None
    assert pending.image_digest is None
    assert proof_ref in pending.input_refs
    assert proof_ref in pending.recovery_decision_refs
    assert exhausted.output_refs[0] in pending.input_refs
    assert store.get(identity, SimpleStage.POC_CANDIDATE_DONE) is None
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    events = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    assert any(
        event.kind is ActivityKind.EVIDENCE_RECORDED
        and proof_ref in event.output_refs
        and exhausted.output_refs[0] in event.input_refs
        for event in events
    )
    running = store.mark_running(
        identity,
        SimpleStage.VERIFICATION_INITIAL_DONE,
        pro_con.output_refs,
        attempt_id="attempt-4",
    )
    assert running.attempt_number == 4
    assert proof_ref in running.input_refs


@pytest.mark.parametrize("tamper", ["wrong_old_base", "same_base", "wrong_attempt"])
def test_repair_rejects_unverified_proof(tmp_path, tamper: str) -> None:
    store, artifacts, _pro_con, initial, _candidate, exhausted, _proof_ref = (
        _exhausted_poc(tmp_path)
    )
    proof = {
        "kind": "simple_offline_environment_repair",
        "identity": exhausted.identity.model_dump(mode="json"),
        "stage": SimpleStage.POC_EXECUTION_DONE.value,
        "exhausted_attempt_id": exhausted.attempt_id,
        "exhausted_attempt_number": exhausted.attempt_number,
        "exhausted_checkpoint_hash": hashlib.sha256(
            canonical_bytes(exhausted.model_dump(mode="json"))
        ).hexdigest(),
        "old_base_image_digest": OLD_BASE,
        "new_base_image_digest": NEW_BASE,
        "browser_command": "/usr/bin/chromium",
        "python_version": "3.12.15",
        "smoke_output_digest": "sha256:" + "5" * 64,
    }
    if tamper == "wrong_old_base":
        proof["old_base_image_digest"] = "sha256:" + "6" * 64
    elif tamper == "same_base":
        proof["new_base_image_digest"] = OLD_BASE
    else:
        proof["exhausted_attempt_id"] = "other-attempt"
    bad_ref = artifacts.put_json(proof)

    with pytest.raises(ValueError, match="OFFLINE_REPAIR_"):
        store.prepare_offline_environment_repair(exhausted, bad_ref, artifacts)

    assert (
        store.require(exhausted.identity, SimpleStage.VERIFICATION_INITIAL_DONE)
        == initial
    )
    assert (
        store.require(exhausted.identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    )


def test_repair_refuses_duplicate_and_stale_requests(tmp_path) -> None:
    store, artifacts, _pro_con, _initial, _candidate, exhausted, proof_ref = (
        _exhausted_poc(tmp_path)
    )
    store.prepare_offline_environment_repair(exhausted, proof_ref, artifacts)

    with pytest.raises(ValueError, match="OFFLINE_REPAIR_STALE"):
        store.prepare_offline_environment_repair(exhausted, proof_ref, artifacts)


def test_repair_rejects_online_recipe_despite_valid_new_base(tmp_path) -> None:
    store, artifacts, _pro_con, initial, _candidate, exhausted, proof_ref = (
        _exhausted_poc(tmp_path, recipe_source="GENERATED")
    )

    with pytest.raises(ValueError, match="OFFLINE_REPAIR_"):
        store.prepare_offline_environment_repair(exhausted, proof_ref, artifacts)

    assert (
        store.require(exhausted.identity, SimpleStage.VERIFICATION_INITIAL_DONE)
        == initial
    )
    assert (
        store.require(exhausted.identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    )


def test_repair_keeps_attempt_four_through_execution_and_cannot_reopen(
    tmp_path,
) -> None:
    store, artifacts, pro_con, _initial, _candidate, exhausted, proof_ref = (
        _exhausted_poc(tmp_path)
    )
    identity = exhausted.identity
    store.prepare_offline_environment_repair(exhausted, proof_ref, artifacts)
    rebuilt_recipe_ref = artifacts.put_json(
        {"kind": "simple_environment_recipe", "base_image_digest": NEW_BASE}
    )
    initial_running = store.mark_running(
        identity,
        SimpleStage.VERIFICATION_INITIAL_DONE,
        pro_con.output_refs,
        attempt_id="initial-attempt-4",
    )
    initial = store.complete(
        initial_running,
        StageResult(
            output_refs=(artifacts.put_json({"kind": "new_initial"}),),
            recipe_ref=rebuilt_recipe_ref,
            image_digest="sha256:" + "6" * 64,
        ),
    )
    candidate_running = store.mark_running(
        identity,
        SimpleStage.POC_CANDIDATE_DONE,
        initial.output_refs,
        attempt_id="poc-attempt-4",
        inherit_from=initial,
    )
    candidate = store.complete(
        candidate_running,
        StageResult(output_refs=(artifacts.put_json({"kind": "new_candidate"}),)),
    )
    execution = store.mark_running(
        identity,
        SimpleStage.POC_EXECUTION_DONE,
        candidate.output_refs,
        attempt_id="poc-attempt-4",
        inherit_from=candidate,
    )
    assert [
        initial.attempt_number,
        candidate.attempt_number,
        execution.attempt_number,
    ] == [
        4,
        4,
        4,
    ]
    assert proof_ref in execution.recovery_decision_refs

    failed = store.mark_failure(
        execution,
        StageFailure(
            code="POC_EXECUTION_FAILED", retryable=True, safe_message="failed"
        ),
        StageStatus.BLOCKED,
    )
    exhausted_again = store.mark_recovery_exhausted(failed)
    with pytest.raises(ValueError, match="OFFLINE_REPAIR_EXHAUSTION_INVALID"):
        store.prepare_offline_environment_repair(exhausted_again, proof_ref, artifacts)


def test_repair_rolls_back_checkpoint_and_event_on_crash(tmp_path) -> None:
    store, artifacts, _pro_con, initial, candidate, exhausted, proof_ref = (
        _exhausted_poc(tmp_path)
    )
    events_before = AgentActivityStore(store.database_path).list_analysis(
        exhausted.identity.analysis_id, hypothesis_id=exhausted.identity.hypothesis_id
    )

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_offline_environment_repair(
            exhausted, proof_ref, artifacts, fail_before_commit=True
        )

    assert (
        store.require(exhausted.identity, SimpleStage.VERIFICATION_INITIAL_DONE)
        == initial
    )
    assert (
        store.require(exhausted.identity, SimpleStage.POC_CANDIDATE_DONE) == candidate
    )
    assert (
        store.require(exhausted.identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    )
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            exhausted.identity.analysis_id,
            hypothesis_id=exhausted.identity.hypothesis_id,
        )
        == events_before
    )


@pytest.mark.parametrize("registered_candidate", [False, True])
@pytest.mark.asyncio
async def test_application_repairs_only_on_explicit_resume_request(
    tmp_path, monkeypatch, registered_candidate: bool
) -> None:
    store, _artifacts, _pro_con, _initial, _candidate, exhausted, _proof_ref = (
        _exhausted_poc(tmp_path)
    )
    identity = exhausted.identity
    display_id = AnalysisDisplayIdStore(store.database_path).get_or_allocate(
        identity.analysis_id
    )
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id=display_id,
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="https://example.invalid/repo.git",
            hypothesis_ids=() if registered_candidate else (identity.hypothesis_id,),
            candidate_pipeline_version=2 if registered_candidate else None,
        )
    )
    if registered_candidate:
        store.upsert_hypothesis(
            identity.model_copy(update={"hypothesis_id": None}),
            identity.hypothesis_id,
        )
    preflight_calls: list[CheckpointIdentity] = []

    async def preflight(child: CheckpointIdentity) -> OfflineRepairPreflight:
        preflight_calls.append(child)
        return OfflineRepairPreflight(
            base_image_digest=NEW_BASE,
            browser_command="/usr/bin/chromium",
            python_version="3.12.15",
            smoke_output_digest="sha256:" + "5" * 64,
        )

    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=None,  # type: ignore[arg-type]
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
        offline_repair_preflight=preflight,
    )

    async def completed(_exact: str) -> SimpleAnalysisOutcome:
        return SimpleAnalysisOutcome(
            identity=identity.model_copy(update={"hypothesis_id": None}),
            display_analysis_id=display_id,
            status="BLOCKED",
            current_stage=SimpleStage.POC_EXECUTION_DONE,
            error_code="RECOVERY_EXHAUSTED",
        )

    monkeypatch.setattr(application, "_resume_locked", completed)
    await application.resume(identity.analysis_id)
    assert preflight_calls == []
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted

    await application.resume(
        identity.analysis_id, repair_exhausted_hypothesis=identity.hypothesis_id
    )

    assert preflight_calls == [identity]
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    assert (
        store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE).status
        is StageStatus.PENDING
    )
    with pytest.raises(ValueError, match="OFFLINE_REPAIR_"):
        await application.resume(
            identity.analysis_id, repair_exhausted_hypothesis=identity.hypothesis_id
        )
    assert preflight_calls == [identity]


@pytest.mark.asyncio
async def test_application_rejects_wrong_hypothesis_before_smoke(tmp_path) -> None:
    store, _artifacts, _pro_con, _initial, _candidate, exhausted, _proof_ref = (
        _exhausted_poc(tmp_path)
    )
    identity = exhausted.identity
    display_id = AnalysisDisplayIdStore(store.database_path).get_or_allocate(
        identity.analysis_id
    )
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id=display_id,
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="https://example.invalid/repo.git",
            hypothesis_ids=(identity.hypothesis_id,),
        )
    )
    calls = 0

    async def preflight(_child: CheckpointIdentity) -> OfflineRepairPreflight:
        nonlocal calls
        calls += 1
        raise AssertionError("should not probe Docker")

    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=None,  # type: ignore[arg-type]
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
        offline_repair_preflight=preflight,
    )
    with pytest.raises(ValueError, match="OFFLINE_REPAIR_HYPOTHESIS_INVALID"):
        await application.resume(
            identity.analysis_id, repair_exhausted_hypothesis="other"
        )
    assert calls == 0
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
