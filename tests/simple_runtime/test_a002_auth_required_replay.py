"""Explicit, one-shot replay of an authenticated PoC candidate call."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.observability.agent_activity import ActivityKind
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
from sastsimi.simple_runtime.runner import SimpleRuntimeRunner, StageFailed
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore

ANALYSIS_ID = "f83c319e988b488d83d09dc1928d755b"
HYPOTHESIS_ID = "hypothesis-dca79495fbbbc2c1e3c10993a665ddd5"


def _checkpoint(
    identity: CheckpointIdentity,
    stage: SimpleStage,
    inputs: tuple[StoredDataRef, ...] = (),
    outputs: tuple[StoredDataRef, ...] = (),
    recipe_ref: StoredDataRef | None = None,
    image_digest: str | None = None,
) -> StageCheckpoint:
    return StageCheckpoint(
        identity=identity,
        stage=stage,
        stage_version=STAGE_VERSION[stage],
        status=StageStatus.SUCCEEDED,
        input_refs=inputs,
        input_hash=input_reference_hash(inputs),
        output_refs=outputs,
        recipe_ref=recipe_ref,
        image_digest=image_digest,
    )


def _failed_auth_candidate(
    tmp_path: Path,
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    child = CheckpointIdentity(
        analysis_id=ANALYSIS_ID,
        workspace_id="workspace-a002",
        commit_id="a" * 40,
        hypothesis_id=HYPOTHESIS_ID,
    )
    root = child.model_copy(update={"hypothesis_id": None})
    artifacts = SimpleArtifactRepository(data_dir, child)
    workspace = data_dir / "workspaces" / child.workspace_id
    workspace.mkdir(parents=True)
    profile_ref = artifacts.put_json({"kind": "simple_repository_profile"})
    static_ref = artifacts.put_json({"kind": "simple_static_fact_bundle"})
    coverage_ref = artifacts.put_json({"kind": "simple_static_coverage_v1"})
    proposal_ref = artifacts.put_prompt_proposal(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": ANALYSIS_ID,
            "hypothesis_id": HYPOTHESIS_ID,
            "proposal": {"title": "ticket hold authorization"},
        }
    )
    pro_con_ref = artifacts.put_json({"kind": "pro_con"})
    initial_ref = artifacts.put_json({"kind": "initial"})
    recipe_ref = artifacts.put_json({"kind": "simple_environment_recipe"})
    request_ref = artifacts.put_json({"kind": "simple_llm_request"})
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=ANALYSIS_ID,
            display_analysis_id="A-002",
            workspace_id=child.workspace_id,
            commit_id=child.commit_id,
            repository="https://github.com/django-helpdesk/django-helpdesk.git",
            workspace_path=workspace,
            repository_profile_ref=profile_ref,
            static_bundle_ref=static_ref,
            static_coverage_ref=coverage_ref,
            candidate_pipeline_version=2,
            candidate_scope_fingerprint="scope-a002",
        )
    )
    store.save_checkpoint(
        _checkpoint(root, SimpleStage.STATIC_DONE, outputs=(profile_ref, static_ref))
    )
    store.upsert_hypothesis(root, HYPOTHESIS_ID, proposal_ref)
    store.save_checkpoint(
        _checkpoint(
            child,
            SimpleStage.PRO_CON_DONE,
            inputs=(proposal_ref, static_ref),
            outputs=(pro_con_ref,),
        )
    )
    initial = _checkpoint(
        child,
        SimpleStage.VERIFICATION_INITIAL_DONE,
        inputs=(pro_con_ref,),
        outputs=(initial_ref,),
        recipe_ref=recipe_ref,
        image_digest="sha256:" + "1" * 64,
    )
    store.save_checkpoint(initial)
    first = store.mark_running(
        child,
        SimpleStage.POC_CANDIDATE_DONE,
        (initial_ref, recipe_ref),
        attempt_id="first-poc-attempt",
        inherit_from=initial,
    )
    first_failed = store.mark_failure(
        first,
        StageFailure(code="TIMED_OUT", retryable=True, safe_message="Timed out"),
        StageStatus.BLOCKED,
    )
    store.replace_from(
        first_failed.model_copy(
            update={
                "status": StageStatus.PENDING,
                "output_refs": (),
                "attempt_id": None,
                "error_code": None,
                "retryable": False,
            }
        )
    )
    second = store.mark_running(
        child,
        SimpleStage.POC_CANDIDATE_DONE,
        (initial_ref, recipe_ref),
        attempt_id="second-poc-attempt",
        inherit_from=initial,
    )
    stopped = store.mark_failure(
        second,
        StageFailure(
            code="AUTH_REQUIRED",
            retryable=False,
            safe_message="Codex login required",
            evidence_refs=(request_ref,),
        ),
        StageStatus.FAILED,
    )
    root_running = store.mark_running(
        root,
        SimpleStage.HYPOTHESIS_DONE,
        (static_ref,),
        attempt_id="root-a002-attempt",
    )
    store.mark_failure(
        root_running,
        StageFailure(
            code=(
                "CANDIDATE_CHILD_ERROR_BOUND:AUTH_REQUIRED:"
                f"{HYPOTHESIS_ID}:{stopped.attempt_id}"
            ),
            retryable=False,
            safe_message="Child did not complete",
        ),
        StageStatus.FAILED,
    )
    return store, artifacts, stopped


def test_explicit_a002_auth_replay_reopens_only_failed_child(tmp_path: Path) -> None:
    store, artifacts, stopped = _failed_auth_candidate(tmp_path)
    child = stopped.identity
    root = child.model_copy(update={"hypothesis_id": None})
    initial = store.require(child, SimpleStage.VERIFICATION_INITIAL_DONE)
    pro_con = store.require(child, SimpleStage.PRO_CON_DONE)
    root_failure = store.require(root, SimpleStage.HYPOTHESIS_DONE)
    before = AgentActivityStore(store.database_path).list_analysis(
        ANALYSIS_ID, hypothesis_id=HYPOTHESIS_ID
    )

    pending = store.prepare_auth_required_replay(stopped, artifacts)

    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 2
    assert pending.output_refs == ()
    assert pending.attempt_id is None
    assert pending.recipe_ref == stopped.recipe_ref
    assert pending.image_digest == stopped.image_digest
    assert store.require(child, SimpleStage.VERIFICATION_INITIAL_DONE) == initial
    assert store.require(child, SimpleStage.PRO_CON_DONE) == pro_con
    reopened_root = store.require(root, SimpleStage.HYPOTHESIS_DONE)
    assert reopened_root.status is StageStatus.PENDING
    assert reopened_root.attempt_number == root_failure.attempt_number
    assert reopened_root.attempt_id is None
    assert reopened_root.error_code is None
    assert reopened_root.input_refs == root_failure.input_refs
    after = AgentActivityStore(store.database_path).list_analysis(
        ANALYSIS_ID, hypothesis_id=HYPOTHESIS_ID
    )
    assert len(after) == len(before) + 1
    assert after[-1].kind is ActivityKind.DECISION_RECORDED
    assert after[-1].error_code == "AUTH_REQUIRED_REPLAYED"
    marker = json.loads(artifacts.read(after[-1].output_refs[0]))
    assert marker["old_attempt_id"] == stopped.attempt_id
    assert marker["old_checkpoint_hash"]
    assert marker["old_root_attempt_id"] == root_failure.attempt_id
    assert marker["old_root_checkpoint_hash"]
    assert "prompt" not in marker
    assert "content" not in marker
    third = store.mark_running(
        child,
        SimpleStage.POC_CANDIDATE_DONE,
        pending.input_refs,
        attempt_id="third-poc-attempt",
    )
    assert third.attempt_number == 3


def test_a002_auth_replay_is_one_shot(tmp_path: Path) -> None:
    store, artifacts, stopped = _failed_auth_candidate(tmp_path)
    store.prepare_auth_required_replay(stopped, artifacts)

    with pytest.raises(ValueError, match="AUTH_REQUIRED_REPLAY_"):
        store.prepare_auth_required_replay(stopped, artifacts)


def test_a002_auth_replay_rejects_unresolved_codex_call(tmp_path: Path) -> None:
    store, artifacts, stopped = _failed_auth_candidate(tmp_path)
    assert store.begin_codex_call("unresolved-call", ANALYSIS_ID)

    with pytest.raises(ValueError, match="AUTH_REQUIRED_REPLAY_CODEX_UNRESOLVED"):
        store.prepare_auth_required_replay(stopped, artifacts)
    assert store.require(stopped.identity, stopped.stage) == stopped


def test_auth_replay_requires_exact_bound_root(tmp_path: Path) -> None:
    store, artifacts, stopped = _failed_auth_candidate(tmp_path)
    root = stopped.identity.model_copy(update={"hypothesis_id": None})
    original = store.require(root, SimpleStage.HYPOTHESIS_DONE)
    store.save_checkpoint(original.model_copy(update={"error_code": "OTHER_FAILURE"}))

    with pytest.raises(ValueError, match="AUTH_REQUIRED_REPLAY_ROOT_BOUND_INVALID"):
        store.prepare_auth_required_replay(stopped, artifacts)
    assert store.require(stopped.identity, stopped.stage) == stopped


def test_auth_replay_respects_attempt_budget(tmp_path: Path) -> None:
    store, artifacts, stopped = _failed_auth_candidate(tmp_path)
    exhausted = stopped.model_copy(update={"attempt_number": 3})

    with pytest.raises(ValueError, match="AUTH_REQUIRED_REPLAY_INVALID"):
        store.prepare_auth_required_replay(exhausted, artifacts)
    assert store.require(stopped.identity, stopped.stage) == stopped


def test_auth_replay_rejects_downstream_checkpoint(tmp_path: Path) -> None:
    store, artifacts, stopped = _failed_auth_candidate(tmp_path)
    store.save_checkpoint(_checkpoint(stopped.identity, SimpleStage.POC_EXECUTION_DONE))

    with pytest.raises(ValueError, match="AUTH_REQUIRED_REPLAY_DOWNSTREAM_EXISTS"):
        store.prepare_auth_required_replay(stopped, artifacts)
    assert store.require(stopped.identity, stopped.stage) == stopped


def test_auth_replay_rejects_active_candidate_child_claim(tmp_path: Path) -> None:
    store, artifacts, stopped = _failed_auth_candidate(tmp_path)
    root = stopped.identity.model_copy(update={"hypothesis_id": None})
    assert store.claim_hypothesis(root, HYPOTHESIS_ID, "old-turn")

    with pytest.raises(ValueError, match="AUTH_REQUIRED_REPLAY_CHILD_CLAIM_ACTIVE"):
        store.prepare_auth_required_replay(stopped, artifacts)
    assert store.require(stopped.identity, stopped.stage) == stopped


def test_auth_replay_transaction_rolls_back(tmp_path: Path) -> None:
    store, artifacts, stopped = _failed_auth_candidate(tmp_path)
    root = stopped.identity.model_copy(update={"hypothesis_id": None})
    root_failure = store.require(root, SimpleStage.HYPOTHESIS_DONE)
    before = AgentActivityStore(store.database_path).list_analysis(
        ANALYSIS_ID, hypothesis_id=HYPOTHESIS_ID
    )

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_auth_required_replay(stopped, artifacts, fail_before_commit=True)
    assert store.require(stopped.identity, stopped.stage) == stopped
    assert store.require(root, SimpleStage.HYPOTHESIS_DONE) == root_failure
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            ANALYSIS_ID, hypothesis_id=HYPOTHESIS_ID
        )
        == before
    )


def test_real_runner_reuses_prior_success_and_executes_attempt_three(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped = _failed_auth_candidate(tmp_path)
    child = stopped.identity
    pro_con = store.require(child, SimpleStage.PRO_CON_DONE)
    initial = store.require(child, SimpleStage.VERIFICATION_INITIAL_DONE)
    pending = store.prepare_auth_required_replay(stopped, artifacts)
    replay_marker = pending.input_refs[-1]
    candidate_result = artifacts.put_json({"kind": "bounded_test_candidate"})
    seen: list[StageCheckpoint] = []

    async def candidate(
        checkpoint: StageCheckpoint,
        prior: Mapping[SimpleStage, StageCheckpoint],
    ) -> StageResult:
        assert prior[SimpleStage.PRO_CON_DONE] == pro_con
        assert prior[SimpleStage.VERIFICATION_INITIAL_DONE] == initial
        seen.append(checkpoint)
        return StageResult(output_refs=(candidate_result,))

    async def stop_before_execution(
        checkpoint: StageCheckpoint,
        prior: Mapping[SimpleStage, StageCheckpoint],
    ) -> StageResult:
        raise StageFailed(
            StageFailure(
                code="TEST_EXECUTION_BOUNDARY",
                retryable=False,
                safe_message="No container or LLM is used by this test",
            )
        )

    runner = SimpleRuntimeRunner(
        store,
        {
            SimpleStage.POC_CANDIDATE_DONE: candidate,
            SimpleStage.POC_EXECUTION_DONE: stop_before_execution,
        },
    )
    # This bounded path has no real suspension; driving it directly avoids
    # Windows event-loop socket creation in the test sandbox.
    operation = runner.resume_hypothesis(child)
    try:
        operation.send(None)
    except StopIteration as finished:
        outcome = finished.value
    else:
        operation.close()
        raise AssertionError("Mock runner unexpectedly awaited external work")

    assert outcome.current_stage is SimpleStage.POC_EXECUTION_DONE
    assert outcome.error_code == "TEST_EXECUTION_BOUNDARY"
    assert len(seen) == 1
    assert seen[0].attempt_number == 3
    assert replay_marker in seen[0].input_refs
    completed_candidate = store.require(child, SimpleStage.POC_CANDIDATE_DONE)
    assert completed_candidate.status is StageStatus.SUCCEEDED
    assert completed_candidate.attempt_number == 3
    assert replay_marker in completed_candidate.input_refs
    assert store.require(child, SimpleStage.PRO_CON_DONE) == pro_con
    assert store.require(child, SimpleStage.VERIFICATION_INITIAL_DONE) == initial
