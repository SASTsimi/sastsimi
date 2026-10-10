"""Pre-provider anchor failures may be replayed only with bound evidence."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.observability.agent_activity import ActivityKind
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.recovery import migration_settings_replay_binding
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_poc_django_migration_settings_replay import (
    _blocked_migration_candidate_attempt,
    _exhausted_migration_attempt,
)
from tests.simple_runtime.test_poc_sensitive_replay import _sensitive_stop


def _failed_anchor(
    tmp_path: Path,
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store, artifacts, stopped = _sensitive_stop(tmp_path, new_diagnostic=True)
    pending = store.prepare_poc_sensitive_content_replay(stopped, artifacts)
    third = store.mark_running(
        stopped.identity,
        SimpleStage.POC_CANDIDATE_DONE,
        pending.input_refs,
        attempt_id="anchor-attempt-3",
    )
    failed = store.mark_failure(
        third,
        StageFailure(
            code="HYPOTHESIS_ANCHOR_INVALID",
            retryable=False,
            safe_message="Exact hypothesis and pinned source context are unavailable",
        ),
        StageStatus.FAILED,
    )
    root_id = stopped.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_id, SimpleStage.HYPOTHESIS_DONE)
    running_root = root.model_copy(
        update={
            "status": StageStatus.RUNNING,
            "attempt_id": "root-anchor-attempt",
            "error_code": None,
            "retryable": False,
        }
    )
    store.save_checkpoint(running_root)
    store.mark_failure(
        running_root,
        StageFailure(
            code=(
                "CANDIDATE_CHILD_ERROR_BOUND:HYPOTHESIS_ANCHOR_INVALID:"
                f"{stopped.identity.hypothesis_id}:{failed.attempt_id}"
            ),
            retryable=False,
            safe_message="Candidate child analysis stopped",
        ),
        StageStatus.FAILED,
    )
    return store, artifacts, failed


def test_pre_provider_anchor_failure_reopens_only_candidate_once(
    tmp_path: Path,
) -> None:
    store, artifacts, failed = _failed_anchor(tmp_path)
    initial = store.require(failed.identity, SimpleStage.VERIFICATION_INITIAL_DONE)

    pending = store.prepare_poc_anchor_failure_replay(failed, artifacts)

    assert pending.status is StageStatus.PENDING
    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.attempt_number == 3
    assert pending.input_refs == failed.input_refs
    assert pending.output_refs == ()
    assert (
        store.require(failed.identity, SimpleStage.VERIFICATION_INITIAL_DONE) == initial
    )
    assert store.get(failed.identity, SimpleStage.POC_EXECUTION_DONE) is None
    events = AgentActivityStore(store.database_path).list_analysis(
        failed.identity.analysis_id, hypothesis_id=failed.identity.hypothesis_id
    )
    assert any(
        event.kind is ActivityKind.DECISION_RECORDED
        and event.error_code == "POC_ANCHOR_REPLAYED"
        for event in events
    )
    with pytest.raises(ValueError, match="POC_ANCHOR_REPLAY_"):
        store.prepare_poc_anchor_failure_replay(failed, artifacts)
    store.save_checkpoint(failed)
    with pytest.raises(ValueError, match="POC_ANCHOR_REPLAY_ALREADY_REPLAYED"):
        store.prepare_poc_anchor_failure_replay(failed, artifacts)


def test_anchor_replay_refuses_unresolved_codex_call(tmp_path: Path) -> None:
    store, artifacts, failed = _failed_anchor(tmp_path)
    assert store.begin_codex_call("unresolved-anchor-call", failed.identity.analysis_id)

    with pytest.raises(ValueError, match="POC_ANCHOR_REPLAY_CODEX_UNRESOLVED"):
        store.prepare_poc_anchor_failure_replay(failed, artifacts)
    assert store.require(failed.identity, failed.stage) == failed


def test_anchor_replay_refuses_resolved_call_overlapping_failure(
    tmp_path: Path,
) -> None:
    store, artifacts, failed = _failed_anchor(tmp_path)
    events = AgentActivityStore(store.database_path).list_analysis(
        failed.identity.analysis_id, hypothesis_id=failed.identity.hypothesis_id
    )
    attempt = [
        event
        for event in events
        if event.stage == failed.stage.value and event.attempt_id == failed.attempt_id
    ]
    assert len(attempt) == 2
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "INSERT INTO simple_codex_calls "
            "(call_id, analysis_id, status, started_at, resolved_at) "
            "VALUES (?, ?, 'SAFE', ?, ?)",
            (
                "overlapping-call",
                failed.identity.analysis_id,
                attempt[0].started_at.isoformat(),
                attempt[1].started_at.isoformat(),
            ),
        )

    with pytest.raises(ValueError, match="POC_ANCHOR_REPLAY_CALL_INVALID"):
        store.prepare_poc_anchor_failure_replay(failed, artifacts)
    assert store.require(failed.identity, failed.stage) == failed


def test_anchor_replay_refuses_any_attributed_llm_attempt(tmp_path: Path) -> None:
    store, artifacts, failed = _failed_anchor(tmp_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "INSERT INTO simple_llm_attempt_metadata "
            "(attempt_id, analysis_id, checkpoint_attempt_id) VALUES (?, ?, ?)",
            ("attributed-call", failed.identity.analysis_id, failed.attempt_id),
        )

    with pytest.raises(ValueError, match="POC_ANCHOR_REPLAY_CALL_INVALID"):
        store.prepare_poc_anchor_failure_replay(failed, artifacts)


def test_anchor_replay_refuses_wrong_bound_root(tmp_path: Path) -> None:
    store, artifacts, failed = _failed_anchor(tmp_path)
    root_identity = failed.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    store.save_checkpoint(root.model_copy(update={"error_code": "OTHER_FAILURE"}))

    with pytest.raises(ValueError, match="POC_ANCHOR_REPLAY_ROOT_BOUND_INVALID"):
        store.prepare_poc_anchor_failure_replay(failed, artifacts)
    assert store.require(failed.identity, failed.stage) == failed


def test_anchor_replay_refuses_existing_execution(tmp_path: Path) -> None:
    store, artifacts, failed = _failed_anchor(tmp_path)
    store.save_checkpoint(
        failed.model_copy(
            update={
                "stage": SimpleStage.POC_EXECUTION_DONE,
                "status": StageStatus.SUCCEEDED,
                "error_code": None,
                "attempt_id": "execution-attempt",
            }
        )
    )

    with pytest.raises(ValueError, match="POC_ANCHOR_REPLAY_LINEAGE_INVALID"):
        store.prepare_poc_anchor_failure_replay(failed, artifacts)


def test_anchor_replay_is_atomic_on_interruption(tmp_path: Path) -> None:
    store, artifacts, failed = _failed_anchor(tmp_path)
    before = AgentActivityStore(store.database_path).list_analysis(
        failed.identity.analysis_id, hypothesis_id=failed.identity.hypothesis_id
    )

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_poc_anchor_failure_replay(
            failed, artifacts, fail_before_commit=True
        )

    assert store.require(failed.identity, failed.stage) == failed
    after = AgentActivityStore(store.database_path).list_analysis(
        failed.identity.analysis_id, hypothesis_id=failed.identity.hypothesis_id
    )
    assert after == before


def test_candidate_scope_replay_is_not_migration_settings_replay(
    tmp_path: Path,
) -> None:
    store, artifacts, failed = _failed_anchor(tmp_path)
    events = AgentActivityStore(store.database_path).list_analysis(
        failed.identity.analysis_id, hypothesis_id=failed.identity.hypothesis_id
    )
    decision_ref = next(
        event.output_refs[0]
        for event in events
        if event.kind is ActivityKind.DECISION_RECORDED
        and event.error_code == "POC_SENSITIVE_CONTENT"
    )
    assert decision_ref in failed.input_refs
    failed = failed.model_copy(update={"recovery_decision_refs": (decision_ref,)})
    store.save_checkpoint(failed)
    pending = store.prepare_poc_anchor_failure_replay(failed, artifacts)
    fourth = store.mark_running(
        failed.identity,
        failed.stage,
        pending.input_refs,
        attempt_id="unrelated-candidate-attempt-4",
    )
    assert fourth.recovery_origin_stage is SimpleStage.POC_CANDIDATE_DONE
    decision_ref = fourth.recovery_decision_refs[-1]
    decision = json.loads(artifacts.read_bounded(decision_ref, 64 * 1024))
    assert decision_ref in fourth.input_refs
    assert decision["kind"] == "simple_recovery_decision"
    assert decision["identity"] == fourth.identity.model_dump(mode="json")
    assert decision["stage"] == SimpleStage.POC_CANDIDATE_DONE.value
    assert decision["original_error"]["code"] == "POC_SENSITIVE_CONTENT"
    assert decision["decision"]["category"] == "GENERATED_INPUT"
    assert migration_settings_replay_binding(fourth, artifacts) is None


def test_corrupt_migration_replay_cannot_be_disguised_as_candidate_replay(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_migration_attempt(tmp_path)
    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        exhausted, artifacts
    )
    fourth = store.mark_running(
        pending.identity,
        pending.stage,
        pending.input_refs,
        attempt_id="migration-attempt-4",
    )
    assert migration_settings_replay_binding(fourth, artifacts) is not None

    disguised = fourth.model_copy(
        update={"recovery_origin_stage": SimpleStage.POC_CANDIDATE_DONE}
    )
    with pytest.raises(
        ValueError, match="POC_DJANGO_MIGRATION_SETTINGS_REPLAY_UNBOUND"
    ):
        migration_settings_replay_binding(disguised, artifacts)


def _failed_second_anchor(
    tmp_path: Path,
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store, artifacts, first = _failed_anchor(tmp_path)
    events = AgentActivityStore(store.database_path).list_analysis(
        first.identity.analysis_id, hypothesis_id=first.identity.hypothesis_id
    )
    decision_ref = next(
        event.output_refs[0]
        for event in events
        if event.kind is ActivityKind.DECISION_RECORDED
        and event.error_code == "POC_SENSITIVE_CONTENT"
    )
    first = first.model_copy(update={"recovery_decision_refs": (decision_ref,)})
    store.save_checkpoint(first)
    pending = store.prepare_poc_anchor_failure_replay(first, artifacts)
    fourth = store.mark_running(
        first.identity, first.stage, pending.input_refs, attempt_id="anchor-attempt-4"
    )
    failed = store.mark_failure(
        fourth,
        StageFailure(
            code="HYPOTHESIS_ANCHOR_INVALID",
            retryable=False,
            safe_message="Pre-provider replay binding failed",
        ),
        StageStatus.FAILED,
    )
    root_id = first.identity.model_copy(update={"hypothesis_id": None})
    old_root = store.require(root_id, SimpleStage.HYPOTHESIS_DONE)
    root_running = old_root.model_copy(
        update={
            "status": StageStatus.RUNNING,
            "attempt_id": "root-anchor-attempt-4",
            "error_code": None,
        }
    )
    store.save_checkpoint(root_running)
    store.mark_failure(
        root_running,
        StageFailure(
            code=(
                "CANDIDATE_CHILD_ERROR_BOUND:HYPOTHESIS_ANCHOR_INVALID:"
                f"{first.identity.hypothesis_id}:{failed.attempt_id}"
            ),
            retryable=False,
            safe_message="Candidate child analysis stopped",
        ),
        StageStatus.FAILED,
    )
    return store, artifacts, failed


def test_candidate_scope_anchor_failure_gets_only_one_additional_retry(
    tmp_path: Path,
) -> None:
    store, artifacts, failed = _failed_second_anchor(tmp_path)
    assert failed.attempt_number == 4
    assert migration_settings_replay_binding(failed, artifacts) is None

    pending = store.prepare_poc_anchor_failure_replay(failed, artifacts)

    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 4
    events = AgentActivityStore(store.database_path).list_analysis(
        failed.identity.analysis_id, hypothesis_id=failed.identity.hypothesis_id
    )
    assert (
        sum(event.error_code == "POC_ANCHOR_DISCRIMINATOR_REPLAYED" for event in events)
        == 1
    )
    with pytest.raises(ValueError, match="POC_ANCHOR_REPLAY_"):
        store.prepare_poc_anchor_failure_replay(failed, artifacts)


def test_candidate_scope_attempt_five_is_not_migration_candidate_replay(
    tmp_path: Path,
) -> None:
    store, artifacts, failed = _failed_second_anchor(tmp_path)
    pending = store.prepare_poc_anchor_failure_replay(failed, artifacts)
    fifth = store.mark_running(
        pending.identity,
        pending.stage,
        pending.input_refs,
        attempt_id="anchor-attempt-5",
    )

    assert fifth.attempt_number == 5
    assert fifth.recovery_origin_stage is SimpleStage.POC_CANDIDATE_DONE
    assert migration_settings_replay_binding(fifth, artifacts) is None


def test_attempt_five_forged_migration_origin_still_fails_closed(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, _ = _blocked_migration_candidate_attempt(tmp_path)
    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        stopped, artifacts
    )
    fifth = store.mark_running(
        pending.identity,
        pending.stage,
        pending.input_refs,
        attempt_id="migration-attempt-5",
    )
    assert migration_settings_replay_binding(fifth, artifacts) is not None

    disguised = fifth.model_copy(
        update={"recovery_origin_stage": SimpleStage.POC_CANDIDATE_DONE}
    )
    with pytest.raises(
        ValueError, match="POC_DJANGO_MIGRATION_SETTINGS_REPLAY_UNBOUND"
    ):
        migration_settings_replay_binding(disguised, artifacts)


def test_attempt_five_malformed_candidate_marker_still_fails_closed(
    tmp_path: Path,
) -> None:
    store, artifacts, failed = _failed_second_anchor(tmp_path)
    pending = store.prepare_poc_anchor_failure_replay(failed, artifacts)
    fifth = store.mark_running(
        pending.identity,
        pending.stage,
        pending.input_refs,
        attempt_id="anchor-attempt-5",
    )
    decision_ref = fifth.recovery_decision_refs[-1]
    decision = json.loads(artifacts.read_bounded(decision_ref, 64 * 1024))
    decision["attempt"] = 5
    malformed_ref = artifacts.put_json(decision)
    inputs = tuple(
        malformed_ref if ref == decision_ref else ref for ref in fifth.input_refs
    )
    malformed = fifth.model_copy(
        update={
            "input_refs": inputs,
            "input_hash": input_reference_hash(inputs),
            "recovery_decision_refs": (
                *fifth.recovery_decision_refs[:-1],
                malformed_ref,
            ),
        }
    )
    with pytest.raises(
        ValueError, match="POC_DJANGO_MIGRATION_SETTINGS_REPLAY_UNBOUND"
    ):
        migration_settings_replay_binding(malformed, artifacts)


def test_second_anchor_replay_refuses_missing_candidate_recovery_marker(
    tmp_path: Path,
) -> None:
    store, artifacts, failed = _failed_second_anchor(tmp_path)
    altered = failed.model_copy(update={"recovery_decision_refs": ()})
    store.save_checkpoint(altered)

    with pytest.raises(ValueError, match="POC_ANCHOR_REPLAY_"):
        store.prepare_poc_anchor_failure_replay(altered, artifacts)
    assert store.require(failed.identity, failed.stage) == altered


def _failed_third_anchor(
    tmp_path: Path,
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store, artifacts, fourth = _failed_second_anchor(tmp_path)
    pending = store.prepare_poc_anchor_failure_replay(fourth, artifacts)
    fifth = store.mark_running(
        fourth.identity,
        fourth.stage,
        pending.input_refs,
        attempt_id="anchor-attempt-5",
    )
    failed = store.mark_failure(
        fifth,
        StageFailure(
            code="HYPOTHESIS_ANCHOR_INVALID",
            retryable=False,
            safe_message="Pre-provider migration binding collision",
        ),
        StageStatus.FAILED,
    )
    root_id = fourth.identity.model_copy(update={"hypothesis_id": None})
    old_root = store.require(root_id, SimpleStage.HYPOTHESIS_DONE)
    root_running = old_root.model_copy(
        update={
            "status": StageStatus.RUNNING,
            "attempt_id": "root-anchor-attempt-5",
            "error_code": None,
        }
    )
    store.save_checkpoint(root_running)
    store.mark_failure(
        root_running,
        StageFailure(
            code=(
                "CANDIDATE_CHILD_ERROR_BOUND:HYPOTHESIS_ANCHOR_INVALID:"
                f"{fourth.identity.hypothesis_id}:{failed.attempt_id}"
            ),
            retryable=False,
            safe_message="Candidate child analysis stopped",
        ),
        StageStatus.FAILED,
    )
    return store, artifacts, failed


def test_attempt_five_pre_provider_collision_replays_once_and_caps(
    tmp_path: Path,
) -> None:
    store, artifacts, failed = _failed_third_anchor(tmp_path)
    assert failed.attempt_number == 5
    assert failed.recovery_origin_stage is SimpleStage.POC_CANDIDATE_DONE

    pending = store.prepare_poc_anchor_failure_replay(failed, artifacts)

    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 5
    assert pending.input_refs == failed.input_refs
    events = AgentActivityStore(store.database_path).list_analysis(
        failed.identity.analysis_id, hypothesis_id=failed.identity.hypothesis_id
    )
    assert (
        sum(
            event.error_code == "POC_ANCHOR_MIGRATION_COLLISION_REPLAYED"
            for event in events
        )
        == 1
    )
    store.save_checkpoint(failed)
    with pytest.raises(ValueError, match="POC_ANCHOR_REPLAY_ALREADY_REPLAYED"):
        store.prepare_poc_anchor_failure_replay(failed, artifacts)


def test_attempt_five_replay_refuses_any_attributed_llm(
    tmp_path: Path,
) -> None:
    store, artifacts, failed = _failed_third_anchor(tmp_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "INSERT INTO simple_llm_attempt_metadata "
            "(attempt_id, analysis_id, checkpoint_attempt_id) VALUES (?, ?, ?)",
            ("attributed-call-five", failed.identity.analysis_id, failed.attempt_id),
        )

    with pytest.raises(ValueError, match="POC_ANCHOR_REPLAY_CALL_INVALID"):
        store.prepare_poc_anchor_failure_replay(failed, artifacts)
    assert store.require(failed.identity, failed.stage) == failed


def test_attempt_five_replay_refuses_missing_prior_discriminator(
    tmp_path: Path,
) -> None:
    store, artifacts, failed = _failed_third_anchor(tmp_path)
    events = AgentActivityStore(store.database_path).list_analysis(
        failed.identity.analysis_id, hypothesis_id=failed.identity.hypothesis_id
    )
    prior = next(
        event
        for event in events
        if event.error_code == "POC_ANCHOR_DISCRIMINATOR_REPLAYED"
    )
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "DELETE FROM agent_activity_events WHERE event_id = ?", (prior.event_id,)
        )

    with pytest.raises(ValueError, match="POC_ANCHOR_REPLAY_DISCRIMINATOR_INVALID"):
        store.prepare_poc_anchor_failure_replay(failed, artifacts)
    assert store.require(failed.identity, failed.stage) == failed


def test_attempt_five_replay_refuses_boolean_sensitive_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, artifacts, failed = _failed_third_anchor(tmp_path)
    decision_ref = failed.recovery_decision_refs[-1]
    original_read = artifacts.read_bounded
    decision = json.loads(original_read(decision_ref, 64 * 1024))
    decision["attempt"] = True

    def corrupted_read(ref: StoredDataRef, max_bytes: int) -> bytes:
        if ref == decision_ref:
            return json.dumps(decision).encode("utf-8")
        return original_read(ref, max_bytes)

    monkeypatch.setattr(artifacts, "read_bounded", corrupted_read)
    with pytest.raises(ValueError, match="POC_ANCHOR_REPLAY_DISCRIMINATOR_INVALID"):
        store.prepare_poc_anchor_failure_replay(failed, artifacts)
    assert store.require(failed.identity, failed.stage) == failed


def test_attempt_five_replay_refuses_reordered_prior_marker(
    tmp_path: Path,
) -> None:
    store, artifacts, failed = _failed_third_anchor(tmp_path)
    events = AgentActivityStore(store.database_path).list_analysis(
        failed.identity.analysis_id, hypothesis_id=failed.identity.hypothesis_id
    )
    prior = next(
        event
        for event in events
        if event.error_code == "POC_ANCHOR_DISCRIMINATOR_REPLAYED"
    )
    started = next(
        event
        for event in events
        if event.kind is ActivityKind.STAGE_STARTED
        and event.stage == failed.stage.value
        and event.attempt_id == failed.attempt_id
    )
    with sqlite3.connect(store.database_path) as connection:
        row = connection.execute(
            "SELECT event_json FROM agent_activity_events WHERE event_id = ?",
            (started.event_id,),
        ).fetchone()
        assert row is not None
        reordered = json.loads(row[0])
        reordered["started_at"] = prior.started_at.isoformat()
        connection.execute(
            "UPDATE agent_activity_events SET event_json = ? WHERE event_id = ?",
            (json.dumps(reordered), started.event_id),
        )

    with pytest.raises(ValueError, match="POC_ANCHOR_REPLAY_EVENT_INVALID"):
        store.prepare_poc_anchor_failure_replay(failed, artifacts)
    assert store.require(failed.identity, failed.stage) == failed
