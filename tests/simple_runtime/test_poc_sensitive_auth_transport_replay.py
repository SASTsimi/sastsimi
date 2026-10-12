"""Attempt-eight authorization-transport retry is one-shot and evidence-bound."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

import sastsimi.simple_runtime.recovery as recovery_module
from sastsimi.contracts.canonical_json import canonical_bytes
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
from sastsimi.simple_runtime.recovery import closed_poc_sensitive_diagnostic
from sastsimi.simple_runtime.stages import PoCCandidateStage
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_poc_sensitive_exhaustion_replay import (
    _attempt_six,
    _bound_root,
)
from tests.unit.simple_runtime.test_poc_candidate import _RepairClient


def _attempt_seven(
    tmp_path: Path,
    *,
    diagnostic_additions: dict[str, str] | None = None,
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store, artifacts, sixth = _attempt_six(tmp_path)
    pending = store.prepare_poc_sensitive_exhaustion_replay(sixth, artifacts)
    seventh = store.mark_running(
        sixth.identity,
        sixth.stage,
        pending.input_refs,
        attempt_id="credential-attempt-7",
    )
    for index in (1, 2):
        call_id = f"safe-candidate-call-{index}"
        assert store.begin_codex_call(call_id, seventh.identity.analysis_id)
        for phase in ("VERSION", "LOGIN", "EXEC"):
            pid = 700 + index
            start_identity = f"synthetic-{index}-{phase}"
            store.begin_codex_child_spawn(
                call_id=call_id,
                analysis_id=seventh.identity.analysis_id,
                phase=phase,
            )
            store.record_codex_child_spawn(
                call_id=call_id,
                analysis_id=seventh.identity.analysis_id,
                phase=phase,
                pid=pid,
                start_identity=start_identity,
            )
            store.mark_codex_child_exited(
                call_id=call_id,
                analysis_id=seventh.identity.analysis_id,
                phase=phase,
                pid=pid,
                start_identity=start_identity,
            )
        store.record_llm_attempt(
            attempt_id=call_id,
            analysis_id=seventh.identity.analysis_id,
            agent="poc_candidate",
            model="synthetic-model",
            attempt_number=1,
            status="SUCCEEDED",
            elapsed_ms=100,
            input_tokens=1,
            output_tokens=1,
            cost_cents=0.0,
            artifact_ref=artifacts.put_json({"kind": "synthetic_llm_result"}),
        )
        store.mark_codex_call_safe(call_id, seventh.identity.analysis_id)
    diagnostic_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate_rejection_diagnostic",
            "reason": "SENSITIVE_CONTENT",
            "line_count": 182,
            "branch_count": 1,
            "inconclusive_line_count": 1,
            "exit_two_line_count": 0,
            "exit_zero_line_count": 0,
            "sensitive_category": "CREDENTIAL",
            "sensitive_line": 80,
            "sensitive_rule_id": "CREDENTIAL_ASSIGNMENT",
            **(diagnostic_additions or {}),
        }
    )
    blocked = store.mark_failure(
        seventh,
        StageFailure(
            code="POC_SENSITIVE_CONTENT",
            retryable=True,
            safe_message="PoC candidate is not self-contained",
            evidence_refs=(diagnostic_ref,),
        ),
        StageStatus.BLOCKED,
    )
    exhausted = store.mark_recovery_exhausted(blocked)
    _bound_root(store, exhausted)
    return store, artifacts, exhausted


def test_exact_attempt_seven_reopens_once_for_auth_transport_prompt(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_seven(tmp_path)
    identity = exhausted.identity
    root_id = identity.model_copy(update={"hypothesis_id": None})
    root_before = store.require(root_id, SimpleStage.HYPOTHESIS_DONE)
    initial_before = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
    events_before = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    pending = store.prepare_poc_sensitive_auth_transport_replay(exhausted, artifacts)

    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 7
    assert pending.output_refs == ()
    assert exhausted.output_refs[0] in pending.input_refs
    assert store.require(root_id, SimpleStage.HYPOTHESIS_DONE) == root_before
    assert (
        store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE) == initial_before
    )
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    events_after = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    assert events_after[:-1] == events_before
    marker_event = events_after[-1]
    assert marker_event.kind is ActivityKind.DECISION_RECORDED
    assert marker_event.error_code == "POC_SENSITIVE_AUTH_TRANSPORT_REPLAYED"
    marker = json.loads(artifacts.read_bounded(marker_event.output_refs[0], 4096))
    assert marker["old_attempt_id"] == exhausted.attempt_id
    assert marker["old_attempt_number"] == 7
    assert (
        marker["old_checkpoint_hash"]
        == hashlib.sha256(
            canonical_bytes(exhausted.model_dump(mode="json"))
        ).hexdigest()
    )
    assert marker["diagnostic_ref"] == exhausted.output_refs[0].model_dump(mode="json")
    assert marker["prompt_revision"] == "2026-10-11-a002-auth-transport-2"
    assert "content" not in marker and "candidate" not in marker

    running = store.mark_running(
        identity,
        exhausted.stage,
        pending.input_refs,
        attempt_id="auth-transport-attempt-8",
    )
    assert running.attempt_number == 8
    assert running.input_refs[-1] == marker_event.output_refs[0]


def test_attempt_eight_binding_exposes_only_closed_diagnostic(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_seven(tmp_path)
    pending = store.prepare_poc_sensitive_auth_transport_replay(exhausted, artifacts)
    running = store.mark_running(
        exhausted.identity,
        exhausted.stage,
        pending.input_refs,
        attempt_id="auth-transport-attempt-8",
    )

    assert recovery_module.sensitive_auth_transport_replay_binding(
        running, artifacts
    ) == {
        "reason": "SENSITIVE_CONTENT",
        "sensitive_category": "CREDENTIAL",
        "sensitive_line": 80,
        "sensitive_rule_id": "CREDENTIAL_ASSIGNMENT",
    }


def test_attempt_eight_binding_rejects_forged_prior_replay(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_seven(tmp_path)
    pending = store.prepare_poc_sensitive_auth_transport_replay(exhausted, artifacts)
    running = store.mark_running(
        exhausted.identity,
        exhausted.stage,
        pending.input_refs,
        attempt_id="auth-transport-attempt-8",
    )
    marker = json.loads(artifacts.read_bounded(running.input_refs[-1], 4096))
    old_prior_ref = StoredDataRef.model_validate(marker["prior_replay_ref"])
    prior = json.loads(artifacts.read_bounded(old_prior_ref, 4096))
    forged_prior_ref = artifacts.put_json(
        prior | {"old_attempt_id": "wrong-old-attempt"}
    )
    forged_marker_ref = artifacts.put_json(
        marker | {"prior_replay_ref": forged_prior_ref.model_dump(mode="json")}
    )
    inputs = list(running.input_refs)
    inputs[inputs.index(old_prior_ref)] = forged_prior_ref
    inputs[-1] = forged_marker_ref
    forged = running.model_copy(
        update={
            "input_refs": tuple(inputs),
            "input_hash": input_reference_hash(tuple(inputs)),
        }
    )

    assert (
        recovery_module.sensitive_auth_transport_replay_binding(forged, artifacts)
        is None
    )


def test_attempt_eight_binding_rejects_forged_prior_diagnostic(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_seven(tmp_path)
    pending = store.prepare_poc_sensitive_auth_transport_replay(exhausted, artifacts)
    running = store.mark_running(
        exhausted.identity,
        exhausted.stage,
        pending.input_refs,
        attempt_id="auth-transport-attempt-8",
    )
    marker = json.loads(artifacts.read_bounded(running.input_refs[-1], 4096))
    old_prior_ref = StoredDataRef.model_validate(marker["prior_replay_ref"])
    prior = json.loads(artifacts.read_bounded(old_prior_ref, 4096))
    forged_prior_ref = artifacts.put_json(
        prior | {"diagnostic_ref": marker["diagnostic_ref"]}
    )
    forged_marker_ref = artifacts.put_json(
        marker | {"prior_replay_ref": forged_prior_ref.model_dump(mode="json")}
    )
    inputs = list(running.input_refs)
    inputs[inputs.index(old_prior_ref)] = forged_prior_ref
    inputs[-1] = forged_marker_ref
    forged = running.model_copy(
        update={
            "input_refs": tuple(inputs),
            "input_hash": input_reference_hash(tuple(inputs)),
        }
    )

    assert (
        recovery_module.sensitive_auth_transport_replay_binding(forged, artifacts)
        is None
    )


@pytest.mark.asyncio
async def test_store_marker_reaches_stage_initial_prompt_without_rejected_value(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_seven(
        tmp_path,
        diagnostic_additions={
            "sensitive_field_kind": "AUTH",
            "sensitive_site_kind": "KEYWORD_ARGUMENT",
        },
    )
    pending = store.prepare_poc_sensitive_auth_transport_replay(exhausted, artifacts)
    running = store.mark_running(
        exhausted.identity,
        exhausted.stage,
        pending.input_refs,
        attempt_id="auth-transport-attempt-8",
    )
    client = _RepairClient()

    result = await PoCCandidateStage(client=client, artifacts=artifacts)(running, {})

    assert result.output_refs
    assert client.prompts
    assert b"2026-10-11-a002-auth-transport-2" in client.prompts[0]
    assert b"CREDENTIAL_ASSIGNMENT" in client.prompts[0]
    assert b"line 80" in client.prompts[0]
    assert b"AUTH" in client.prompts[0]
    assert b"KEYWORD_ARGUMENT" in client.prompts[0]
    assert b"never-print-this-cookie" not in client.prompts[0]


def test_closed_diagnostic_accepts_only_enum_field_and_site_pair(
    tmp_path: Path,
) -> None:
    _store, artifacts, exhausted = _attempt_seven(tmp_path)
    base = json.loads(artifacts.read_bounded(exhausted.output_refs[0], 4096))
    enriched = base | {
        "sensitive_field_kind": "AUTH",
        "sensitive_site_kind": "KEYWORD_ARGUMENT",
    }
    assert closed_poc_sensitive_diagnostic(artifacts.put_json(enriched), artifacts) == {
        "reason": "SENSITIVE_CONTENT",
        "line_count": 182,
        "sensitive_category": "CREDENTIAL",
        "sensitive_line": 80,
        "sensitive_rule_id": "CREDENTIAL_ASSIGNMENT",
        "sensitive_field_kind": "AUTH",
        "sensitive_site_kind": "KEYWORD_ARGUMENT",
    }
    assert (
        closed_poc_sensitive_diagnostic(
            artifacts.put_json(base | {"sensitive_field_kind": "AUTH"}), artifacts
        )
        is None
    )
    assert (
        closed_poc_sensitive_diagnostic(
            artifacts.put_json(enriched | {"sensitive_site_kind": "VALUE"}), artifacts
        )
        is None
    )
    assert (
        closed_poc_sensitive_diagnostic(
            artifacts.put_json(enriched | {"sensitive_field_kind": "RAW_KEY"}),
            artifacts,
        )
        is None
    )


def test_auth_transport_replay_rejects_altered_diagnostic(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_seven(tmp_path)
    old = json.loads(artifacts.read_bounded(exhausted.output_refs[0], 4096))
    changed_ref = artifacts.put_json(old | {"sensitive_rule_id": "TOKEN_ASSIGNMENT"})
    changed = exhausted.model_copy(update={"output_refs": (changed_ref,)})
    store.save_checkpoint(changed)

    with pytest.raises(ValueError, match="AUTH_TRANSPORT_REPLAY_DIAGNOSTIC_INVALID"):
        store.prepare_poc_sensitive_auth_transport_replay(changed, artifacts)
    assert store.require(exhausted.identity, exhausted.stage) == changed


def test_auth_transport_replay_rejects_valid_but_unlinked_diagnostic(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_seven(tmp_path)
    old = json.loads(artifacts.read_bounded(exhausted.output_refs[0], 4096))
    changed_ref = artifacts.put_json(old | {"sensitive_line": 81})
    changed = exhausted.model_copy(update={"output_refs": (changed_ref,)})
    store.save_checkpoint(changed)

    with pytest.raises(ValueError, match="AUTH_TRANSPORT_REPLAY_EVENT_INVALID"):
        store.prepare_poc_sensitive_auth_transport_replay(changed, artifacts)


def test_auth_transport_replay_rejects_diagnostic_already_in_inputs(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_seven(tmp_path)
    inputs = (*exhausted.input_refs, exhausted.output_refs[0])
    changed = exhausted.model_copy(
        update={
            "input_refs": inputs,
            "input_hash": input_reference_hash(inputs),
        }
    )

    with pytest.raises(ValueError, match="AUTH_TRANSPORT_REPLAY_INVALID"):
        store.prepare_poc_sensitive_auth_transport_replay(changed, artifacts)


@pytest.mark.parametrize("field", ["stage", "identity", "attempt_number"])
def test_auth_transport_replay_rejects_wrong_target(tmp_path: Path, field: str) -> None:
    store, artifacts, exhausted = _attempt_seven(tmp_path)
    if field == "stage":
        changed = exhausted.model_copy(update={"stage": SimpleStage.POC_EXECUTION_DONE})
    elif field == "identity":
        changed = exhausted.model_copy(
            update={
                "identity": exhausted.identity.model_copy(
                    update={"analysis_id": "another-analysis"}
                )
            }
        )
    else:
        changed = exhausted.model_copy(update={"attempt_number": 6})

    with pytest.raises(ValueError, match="AUTH_TRANSPORT_REPLAY_INVALID"):
        store.prepare_poc_sensitive_auth_transport_replay(changed, artifacts)
    assert store.require(exhausted.identity, exhausted.stage) == exhausted


def test_auth_transport_replay_requires_both_settled_candidate_calls(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_seven(tmp_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE simple_codex_calls SET status = 'CONFIRMED' "
            "WHERE call_id = 'safe-candidate-call-2'"
        )

    with pytest.raises(ValueError, match="AUTH_TRANSPORT_REPLAY_CALL_LINEAGE_INVALID"):
        store.prepare_poc_sensitive_auth_transport_replay(exhausted, artifacts)


def test_auth_transport_replay_rejects_overlapping_sibling_stage(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_seven(tmp_path)
    activity = AgentActivityStore(store.database_path)
    target_start = next(
        event
        for event in reversed(
            activity.list_analysis(
                exhausted.identity.analysis_id,
                hypothesis_id=exhausted.identity.hypothesis_id,
            )
        )
        if event.kind is ActivityKind.STAGE_STARTED
        and event.stage == SimpleStage.POC_CANDIDATE_DONE.value
    )
    activity.append(
        target_start.model_copy(
            update={
                "event_id": "foreign-stage-start",
                "hypothesis_id": "sibling-hypothesis",
                "attempt_id": "sibling-attempt",
            }
        )
    )

    with pytest.raises(ValueError, match="AUTH_TRANSPORT_REPLAY_CALL_LINEAGE_INVALID"):
        store.prepare_poc_sensitive_auth_transport_replay(exhausted, artifacts)


def test_auth_transport_replay_rejects_active_call_and_spawn(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_seven(tmp_path)
    assert store.begin_codex_call(
        "unresolved-auth-call", exhausted.identity.analysis_id
    )
    with pytest.raises(ValueError, match="AUTH_TRANSPORT_REPLAY_CODEX_UNRESOLVED"):
        store.prepare_poc_sensitive_auth_transport_replay(exhausted, artifacts)

    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE simple_codex_calls SET status = 'SAFE', resolved_at = started_at "
            "WHERE call_id = 'unresolved-auth-call'"
        )
        connection.execute(
            "INSERT INTO simple_codex_child_spawns "
            "(call_id, analysis_id, phase, status) VALUES (?, ?, 'EXEC', 'SPAWNING')",
            ("unexited-auth-child", exhausted.identity.analysis_id),
        )
    with pytest.raises(ValueError, match="AUTH_TRANSPORT_REPLAY_CODEX_UNRESOLVED"):
        store.prepare_poc_sensitive_auth_transport_replay(exhausted, artifacts)


def test_auth_transport_replay_rejects_downstream_checkpoint(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_seven(tmp_path)
    store.save_checkpoint(
        exhausted.model_copy(
            update={
                "stage": SimpleStage.POC_EXECUTION_DONE,
                "status": StageStatus.SUCCEEDED,
                "output_refs": (),
                "error_code": None,
                "attempt_id": "unexpected-downstream",
            }
        )
    )

    with pytest.raises(ValueError, match="AUTH_TRANSPORT_REPLAY_LINEAGE_INVALID"):
        store.prepare_poc_sensitive_auth_transport_replay(exhausted, artifacts)


def test_auth_transport_replay_is_one_shot_even_after_checkpoint_restore(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_seven(tmp_path)
    store.prepare_poc_sensitive_auth_transport_replay(exhausted, artifacts)
    with pytest.raises(ValueError, match="AUTH_TRANSPORT_REPLAY_STALE"):
        store.prepare_poc_sensitive_auth_transport_replay(exhausted, artifacts)
    store.save_checkpoint(exhausted)
    with pytest.raises(ValueError, match="AUTH_TRANSPORT_REPLAY_ALREADY_REPLAYED"):
        store.prepare_poc_sensitive_auth_transport_replay(exhausted, artifacts)


def test_auth_transport_replay_preserves_sibling(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_seven(tmp_path)
    sibling = store.require(
        exhausted.identity, SimpleStage.VERIFICATION_INITIAL_DONE
    ).model_copy(
        update={
            "identity": exhausted.identity.model_copy(
                update={"hypothesis_id": "sibling-hypothesis"}
            )
        }
    )
    store.save_checkpoint(sibling)

    store.prepare_poc_sensitive_auth_transport_replay(exhausted, artifacts)

    assert store.require(sibling.identity, sibling.stage) == sibling


def test_auth_transport_replay_rolls_back_checkpoint_and_marker(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_seven(tmp_path)
    before = AgentActivityStore(store.database_path).list_analysis(
        exhausted.identity.analysis_id, hypothesis_id=exhausted.identity.hypothesis_id
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_poc_sensitive_auth_transport_replay(
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
