"""One bounded replay when initial verification stopped before any work."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from sastsimi.observability.agent_activity import ActivityKind
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageStatus,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_initial_exhaustion_replay import (
    _bind_root,
    _corrupt_event_refs,
    _exhausted_initial,
)


def _interrupted_exhausted(
    tmp_path: Path,
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store, artifacts, exhausted = _exhausted_initial(
        tmp_path, error_code="STAGE_INTERRUPTED"
    )
    run = store.require_analysis_run(exhausted.identity.analysis_id)
    store.save_analysis_run(
        run.model_copy(update={"provider": "codex", "llm_provider": "codex"})
    )
    return store, artifacts, exhausted


def test_empty_interrupted_initial_reuses_only_the_third_attempt_budget(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _interrupted_exhausted(tmp_path)
    identity = exhausted.identity
    pro_con = store.require(identity, SimpleStage.PRO_CON_DONE)

    pending = store.prepare_interrupted_initial_exhaustion_replay(exhausted, artifacts)

    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 2
    assert pending.attempt_id is None
    assert store.require(identity, SimpleStage.PRO_CON_DONE) == pro_con
    events = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    assert (
        len(
            [
                event
                for event in events
                if event.kind is ActivityKind.DECISION_RECORDED
                and event.error_code == "INTERRUPTED_INITIAL_EXHAUSTION_REPLAYED"
            ]
        )
        == 1
    )
    replacement = store.mark_running(
        identity,
        SimpleStage.VERIFICATION_INITIAL_DONE,
        pending.input_refs,
        attempt_id="replacement-third-attempt",
    )
    assert replacement.attempt_number == 3


def test_recorded_llm_result_cannot_reuse_interrupted_budget(tmp_path: Path) -> None:
    store, artifacts, exhausted = _interrupted_exhausted(tmp_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "INSERT INTO simple_llm_attempts "
            "(attempt_id, analysis_id, agent, model, attempt_number, status, "
            "elapsed_ms, artifact_ref_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                exhausted.attempt_id,
                exhausted.identity.analysis_id,
                "initial_verification",
                "gpt-6-sol",
                1,
                "SUCCEEDED",
                100,
                "{}",
            ),
        )

    with pytest.raises(ValueError, match="INTERRUPTED_INITIAL_EXHAUSTION_CALL_INVALID"):
        store.prepare_interrupted_initial_exhaustion_replay(exhausted, artifacts)

    assert store.require(exhausted.identity, exhausted.stage) == exhausted


def test_interrupted_budget_reuse_is_one_shot(tmp_path: Path) -> None:
    store, artifacts, exhausted = _interrupted_exhausted(tmp_path)
    pending = store.prepare_interrupted_initial_exhaustion_replay(exhausted, artifacts)
    running = store.mark_running(
        exhausted.identity,
        exhausted.stage,
        pending.input_refs,
        attempt_id="replacement-third-attempt",
    )
    failed = store.mark_failure(
        running,
        StageFailure(
            code="STAGE_INTERRUPTED", retryable=True, safe_message="Interrupted"
        ),
        StageStatus.BLOCKED,
    )
    exhausted_again = store.mark_recovery_exhausted(failed)
    _bind_root(
        store,
        exhausted_again,
        hypothesis_id=exhausted.identity.hypothesis_id or "",
        attempt_id=exhausted_again.attempt_id or "",
    )

    with pytest.raises(
        ValueError, match="INITIAL_ENVIRONMENT_EXHAUSTION_ALREADY_REPLAYED"
    ):
        store.prepare_interrupted_initial_exhaustion_replay(exhausted_again, artifacts)

    assert store.require(exhausted.identity, exhausted.stage) == exhausted_again


def test_real_initial_failure_cannot_reuse_interrupted_budget(tmp_path: Path) -> None:
    store, artifacts, exhausted = _exhausted_initial(tmp_path)
    run = store.require_analysis_run(exhausted.identity.analysis_id)
    store.save_analysis_run(
        run.model_copy(update={"provider": "codex", "llm_provider": "codex"})
    )

    with pytest.raises(
        ValueError, match="INITIAL_ENVIRONMENT_EXHAUSTION_EVENT_INVALID"
    ):
        store.prepare_interrupted_initial_exhaustion_replay(exhausted, artifacts)

    assert store.require(exhausted.identity, exhausted.stage) == exhausted


def test_interrupted_budget_reuse_rejects_tool_output_refs(tmp_path: Path) -> None:
    store, artifacts, exhausted = _interrupted_exhausted(tmp_path)
    events = AgentActivityStore(store.database_path).list_analysis(
        exhausted.identity.analysis_id,
        hypothesis_id=exhausted.identity.hypothesis_id,
    )
    interrupted = next(
        event
        for event in events
        if event.stage == exhausted.stage.value
        and event.attempt_id == exhausted.attempt_id
        and event.error_code == "STAGE_INTERRUPTED"
    )
    output = artifacts.put_json({"kind": "attempt_tool_output"})
    _corrupt_event_refs(store, interrupted, field="tool_result_refs", refs=(output,))

    with pytest.raises(
        ValueError, match="INTERRUPTED_INITIAL_EXHAUSTION_OUTPUT_INVALID"
    ):
        store.prepare_interrupted_initial_exhaustion_replay(exhausted, artifacts)

    assert store.require(exhausted.identity, exhausted.stage) == exhausted


@pytest.mark.parametrize("call_started_at_event_index", [0, 2])
def test_interrupted_budget_reuse_rejects_overlapping_codex_call(
    tmp_path: Path,
    call_started_at_event_index: int,
) -> None:
    store, artifacts, exhausted = _interrupted_exhausted(tmp_path)
    events = AgentActivityStore(store.database_path).list_analysis(
        exhausted.identity.analysis_id,
        hypothesis_id=exhausted.identity.hypothesis_id,
    )
    stage_events = [
        event
        for event in events
        if event.stage == exhausted.stage.value
        and event.attempt_id == exhausted.attempt_id
    ]
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "INSERT INTO simple_codex_calls "
            "(call_id, analysis_id, status, started_at, resolved_at) "
            "VALUES (?, ?, 'SAFE', ?, ?)",
            (
                "overlapping-call",
                exhausted.identity.analysis_id,
                stage_events[call_started_at_event_index].started_at.isoformat(),
                stage_events[2].started_at.isoformat(),
            ),
        )

    with pytest.raises(ValueError, match="INTERRUPTED_INITIAL_EXHAUSTION_CALL_INVALID"):
        store.prepare_interrupted_initial_exhaustion_replay(exhausted, artifacts)

    assert store.require(exhausted.identity, exhausted.stage) == exhausted


def test_interrupted_budget_reuse_rolls_back_on_crash(tmp_path: Path) -> None:
    store, artifacts, exhausted = _interrupted_exhausted(tmp_path)
    before = AgentActivityStore(store.database_path).list_analysis(
        exhausted.identity.analysis_id,
        hypothesis_id=exhausted.identity.hypothesis_id,
    )

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_interrupted_initial_exhaustion_replay(
            exhausted, artifacts, fail_before_commit=True
        )

    assert store.require(exhausted.identity, exhausted.stage) == exhausted
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            exhausted.identity.analysis_id,
            hypothesis_id=exhausted.identity.hypothesis_id,
        )
        == before
    )
