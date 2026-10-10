"""An explicit replay of a historical, transient initial environment failure."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.observability.agent_activity import ActivityKind, AgentActivityEvent
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageStatus,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_legacy_import_stop_replan import _seed


def _corrupt_event_refs(
    store: SimpleCheckpointStore,
    event: AgentActivityEvent,
    *,
    field: str,
    refs: tuple[StoredDataRef, ...],
) -> None:
    corrupted = event.model_copy(update={field: refs})
    with sqlite3.connect(store.database_path) as connection:
        cursor = connection.execute(
            "UPDATE agent_activity_events SET event_json = ? WHERE event_id = ?",
            (corrupted.model_dump_json(), event.event_id),
        )
        assert cursor.rowcount == 1


def _bind_root(
    store: SimpleCheckpointStore,
    exhausted: StageCheckpoint,
    *,
    hypothesis_id: str,
    attempt_id: str,
) -> None:
    root_identity = exhausted.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    running_root = root.model_copy(
        update={
            "status": StageStatus.RUNNING,
            "attempt_id": f"root-{attempt_id}",
            "error_code": None,
            "retryable": False,
        }
    )
    store.save_checkpoint(running_root)
    store.mark_failure(
        running_root,
        StageFailure(
            code=(
                "CANDIDATE_CHILD_ERROR_BOUND:RECOVERY_EXHAUSTED:"
                f"{hypothesis_id}:{attempt_id}"
            ),
            retryable=False,
            safe_message="Child initial verification exhausted",
        ),
        StageStatus.BLOCKED,
    )


def _exhausted_initial(
    tmp_path: Path, *, error_code: str = "PINNED_CONTEXT_UNAVAILABLE"
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store, artifacts, old_stop, _ = _seed(tmp_path)
    identity = old_stop.identity
    initial = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
    pending = initial.model_copy(
        update={
            "status": StageStatus.PENDING,
            "output_refs": (),
            "attempt_id": None,
            "attempt_number": 2,
            "error_code": None,
            "retryable": False,
            "recipe_ref": None,
            "image_digest": None,
        }
    )
    store.replace_from(pending)
    running = store.mark_running(
        identity,
        SimpleStage.VERIFICATION_INITIAL_DONE,
        pending.input_refs,
        attempt_id="initial-attempt-3",
    )
    draft_ref = (
        artifacts.put_json(
            {"kind": "simple_initial_verification", "attempt_id": running.attempt_id}
        )
        if error_code == "PINNED_CONTEXT_UNAVAILABLE"
        else None
    )
    failed = store.mark_failure(
        running,
        StageFailure(
            code=error_code,
            retryable=True,
            safe_message="Pinned environment could not be prepared",
            evidence_refs=(draft_ref,) if draft_ref is not None else (),
        ),
        StageStatus.BLOCKED,
    )
    exhausted = store.mark_recovery_exhausted(failed)
    _bind_root(
        store,
        exhausted,
        hypothesis_id=identity.hypothesis_id or "",
        attempt_id=exhausted.attempt_id or "",
    )
    return store, artifacts, exhausted


def test_explicit_initial_replay_preserves_history_and_retries_once(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_initial(
        tmp_path, error_code="PINNED_CONTEXT_UNAVAILABLE"
    )
    identity = exhausted.identity
    pro_con = store.require(identity, SimpleStage.PRO_CON_DONE)
    before = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    pending = store.prepare_initial_environment_exhaustion_replay(exhausted, artifacts)

    assert pending.stage is SimpleStage.VERIFICATION_INITIAL_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 3
    assert pending.output_refs == ()
    assert store.require(identity, SimpleStage.PRO_CON_DONE) == pro_con
    assert store.get(identity, SimpleStage.POC_CANDIDATE_DONE) is None
    after = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    assert len(after) == len(before) + 1
    assert after[-1].kind is ActivityKind.DECISION_RECORDED
    assert after[-1].error_code == "INITIAL_ENVIRONMENT_EXHAUSTION_REPLAYED"
    with pytest.raises(ValueError, match="INITIAL_ENVIRONMENT_EXHAUSTION_"):
        store.prepare_initial_environment_exhaustion_replay(exhausted, artifacts)


def test_old_initial_environment_flag_cannot_add_fourth_interrupted_attempt(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_initial(
        tmp_path, error_code="STAGE_INTERRUPTED"
    )

    with pytest.raises(
        ValueError, match="INITIAL_ENVIRONMENT_EXHAUSTION_EVENT_INVALID"
    ):
        store.prepare_initial_environment_exhaustion_replay(exhausted, artifacts)

    assert store.require(exhausted.identity, exhausted.stage) == exhausted


def test_initial_replay_rejects_unrelated_failure_without_mutation(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_initial(
        tmp_path, error_code="AUTHENTICATION_FAILED"
    )
    identity = exhausted.identity
    before = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)

    with pytest.raises(ValueError, match="INITIAL_ENVIRONMENT_EXHAUSTION_"):
        store.prepare_initial_environment_exhaustion_replay(exhausted, artifacts)

    assert store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE) == before


def test_initial_replay_rejects_root_bound_to_another_child(tmp_path: Path) -> None:
    store, artifacts, exhausted = _exhausted_initial(tmp_path)
    _bind_root(
        store,
        exhausted,
        hypothesis_id="hypothesis-other",
        attempt_id="other-attempt-3",
    )
    identity = exhausted.identity
    before = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
    events_before = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    with pytest.raises(ValueError, match="INITIAL_ENVIRONMENT_EXHAUSTION_"):
        store.prepare_initial_environment_exhaustion_replay(exhausted, artifacts)

    assert store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE) == before
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            identity.analysis_id, hypothesis_id=identity.hypothesis_id
        )
        == events_before
    )


def test_initial_replay_rejects_unresolved_codex_call(tmp_path: Path) -> None:
    store, artifacts, exhausted = _exhausted_initial(tmp_path)
    identity = exhausted.identity
    assert store.begin_codex_call("still-in-flight", identity.analysis_id)
    before = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
    events_before = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    with pytest.raises(ValueError, match="INITIAL_ENVIRONMENT_EXHAUSTION_"):
        store.prepare_initial_environment_exhaustion_replay(exhausted, artifacts)

    assert store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE) == before
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            identity.analysis_id, hypothesis_id=identity.hypothesis_id
        )
        == events_before
    )


def test_initial_replay_rejects_second_replay_after_attempt_four(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_initial(tmp_path)
    identity = exhausted.identity
    pending = store.prepare_initial_environment_exhaustion_replay(exhausted, artifacts)
    running = store.mark_running(
        identity,
        SimpleStage.VERIFICATION_INITIAL_DONE,
        pending.input_refs,
        attempt_id="initial-attempt-4",
    )
    assert running.attempt_number == 4
    failed = store.mark_failure(
        running,
        StageFailure(
            code="PINNED_CONTEXT_UNAVAILABLE",
            retryable=True,
            safe_message="Pinned environment could not be prepared",
        ),
        StageStatus.BLOCKED,
    )
    exhausted_again = store.mark_recovery_exhausted(failed)
    _bind_root(
        store,
        exhausted_again,
        hypothesis_id=identity.hypothesis_id or "",
        attempt_id=exhausted_again.attempt_id or "",
    )
    before = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
    events_before = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    with pytest.raises(ValueError, match="INITIAL_ENVIRONMENT_EXHAUSTION_"):
        store.prepare_initial_environment_exhaustion_replay(exhausted_again, artifacts)

    assert store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE) == before
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            identity.analysis_id, hypothesis_id=identity.hypothesis_id
        )
        == events_before
    )


def test_initial_replay_rolls_back_checkpoint_and_marker_on_crash(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_initial(tmp_path)
    identity = exhausted.identity
    before = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
    events_before = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_initial_environment_exhaustion_replay(
            exhausted, artifacts, fail_before_commit=True
        )

    assert store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE) == before
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            identity.analysis_id, hypothesis_id=identity.hypothesis_id
        )
        == events_before
    )


@pytest.mark.parametrize("field", ["input_refs", "output_refs"])
def test_initial_replay_rejects_root_event_reference_mismatch(
    tmp_path: Path, field: str
) -> None:
    store, artifacts, exhausted = _exhausted_initial(tmp_path)
    identity = exhausted.identity
    root = store.require(
        identity.model_copy(update={"hypothesis_id": None}),
        SimpleStage.HYPOTHESIS_DONE,
    )
    events = AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)
    root_event = next(
        event
        for event in events
        if event.hypothesis_id is None
        and event.stage == SimpleStage.HYPOTHESIS_DONE.value
        and event.attempt_id == root.attempt_id
        and event.kind is ActivityKind.STAGE_BLOCKED
    )
    alien_ref = artifacts.put_json({"kind": "unrelated_root_event_reference"})
    _corrupt_event_refs(store, root_event, field=field, refs=(alien_ref,))
    before = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)

    with pytest.raises(
        ValueError, match="INITIAL_ENVIRONMENT_EXHAUSTION_ROOT_BOUND_INVALID"
    ):
        store.prepare_initial_environment_exhaustion_replay(exhausted, artifacts)

    assert store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE) == before


@pytest.mark.parametrize(
    "cause,corrupted_refs",
    [("PINNED_CONTEXT_UNAVAILABLE", "empty"), ("STAGE_INTERRUPTED", "alien")],
)
def test_initial_replay_rejects_original_failure_output_mismatch(
    tmp_path: Path, cause: str, corrupted_refs: str
) -> None:
    store, artifacts, exhausted = _exhausted_initial(tmp_path, error_code=cause)
    identity = exhausted.identity
    failure_event = next(
        event
        for event in AgentActivityStore(store.database_path).list_analysis(
            identity.analysis_id, hypothesis_id=identity.hypothesis_id
        )
        if event.stage == SimpleStage.VERIFICATION_INITIAL_DONE.value
        and event.attempt_id == exhausted.attempt_id
        and event.kind is ActivityKind.STAGE_BLOCKED
        and event.error_code == cause
    )
    refs = (
        (artifacts.put_json({"kind": "unrelated_initial_failure_reference"}),)
        if corrupted_refs == "alien"
        else ()
    )
    _corrupt_event_refs(store, failure_event, field="output_refs", refs=refs)
    before = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)

    with pytest.raises(
        ValueError, match="INITIAL_ENVIRONMENT_EXHAUSTION_EVENT_INVALID"
    ):
        store.prepare_initial_environment_exhaustion_replay(exhausted, artifacts)

    assert store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE) == before


def test_initial_replay_rejects_started_event_with_output_refs(tmp_path: Path) -> None:
    store, artifacts, exhausted = _exhausted_initial(tmp_path)
    identity = exhausted.identity
    started_event = next(
        event
        for event in AgentActivityStore(store.database_path).list_analysis(
            identity.analysis_id, hypothesis_id=identity.hypothesis_id
        )
        if event.stage == SimpleStage.VERIFICATION_INITIAL_DONE.value
        and event.attempt_id == exhausted.attempt_id
        and event.kind is ActivityKind.STAGE_STARTED
    )
    alien_ref = artifacts.put_json({"kind": "unrelated_initial_start_reference"})
    _corrupt_event_refs(store, started_event, field="output_refs", refs=(alien_ref,))
    before = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)

    with pytest.raises(
        ValueError, match="INITIAL_ENVIRONMENT_EXHAUSTION_EVENT_INVALID"
    ):
        store.prepare_initial_environment_exhaustion_replay(exhausted, artifacts)

    assert store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE) == before
