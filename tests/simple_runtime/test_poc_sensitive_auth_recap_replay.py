"""A ninth PoC attempt is a single evidence-bound safety-prompt revision."""

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
from sastsimi.simple_runtime.stages import PoCCandidateStage
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_poc_sensitive_auth_transport_replay import (
    _attempt_seven,
)
from tests.simple_runtime.test_poc_sensitive_exhaustion_replay import _bound_root
from tests.unit.simple_runtime.test_poc_candidate import _RepairClient


def _attempt_eight(
    tmp_path: Path,
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store, artifacts, seventh = _attempt_seven(tmp_path)
    pending = store.prepare_poc_sensitive_auth_transport_replay(seventh, artifacts)
    eighth = store.mark_running(
        seventh.identity,
        seventh.stage,
        pending.input_refs,
        attempt_id="auth-recap-attempt-8",
    )
    for index in (1, 2):
        call_id = f"auth-recap-safe-call-{index}"
        assert store.begin_codex_call(call_id, eighth.identity.analysis_id)
        for phase in ("VERSION", "LOGIN", "EXEC"):
            pid = 800 + index
            start_identity = f"synthetic-eight-{index}-{phase}"
            store.begin_codex_child_spawn(
                call_id=call_id,
                analysis_id=eighth.identity.analysis_id,
                phase=phase,
            )
            store.record_codex_child_spawn(
                call_id=call_id,
                analysis_id=eighth.identity.analysis_id,
                phase=phase,
                pid=pid,
                start_identity=start_identity,
            )
            store.mark_codex_child_exited(
                call_id=call_id,
                analysis_id=eighth.identity.analysis_id,
                phase=phase,
                pid=pid,
                start_identity=start_identity,
            )
        store.record_llm_attempt(
            attempt_id=call_id,
            analysis_id=eighth.identity.analysis_id,
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
        store.mark_codex_call_safe(call_id, eighth.identity.analysis_id)
    diagnostic_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate_rejection_diagnostic",
            "reason": "SENSITIVE_CONTENT",
            "line_count": 187,
            "branch_count": 0,
            "inconclusive_line_count": 0,
            "exit_two_line_count": 0,
            "exit_zero_line_count": 0,
            "sensitive_category": "CREDENTIAL",
            "sensitive_line": 102,
            "sensitive_rule_id": "CREDENTIAL_ASSIGNMENT",
            "sensitive_field_kind": "AUTH",
            "sensitive_site_kind": "UNKNOWN",
        }
    )
    blocked = store.mark_failure(
        eighth,
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


def test_attempt_eight_reopens_once_with_closed_recap_marker(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_eight(tmp_path)
    identity = exhausted.identity
    root_id = identity.model_copy(update={"hypothesis_id": None})
    root_before = store.require(root_id, SimpleStage.HYPOTHESIS_DONE)
    events_before = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    pending = store.prepare_poc_sensitive_auth_recap_replay(exhausted, artifacts)

    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 8
    assert pending.output_refs == ()
    assert exhausted.output_refs[0] in pending.input_refs
    assert store.require(root_id, SimpleStage.HYPOTHESIS_DONE) == root_before
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    events_after = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    assert events_after[:-1] == events_before
    marker_event = events_after[-1]
    assert marker_event.kind is ActivityKind.DECISION_RECORDED
    assert marker_event.error_code == "POC_SENSITIVE_AUTH_RECAP_REPLAYED"
    marker = json.loads(artifacts.read_bounded(marker_event.output_refs[0], 4096))
    assert marker["old_attempt_id"] == exhausted.attempt_id
    assert marker["old_attempt_number"] == 8
    assert (
        marker["old_checkpoint_hash"]
        == hashlib.sha256(
            canonical_bytes(exhausted.model_dump(mode="json"))
        ).hexdigest()
    )
    assert marker["diagnostic_ref"] == exhausted.output_refs[0].model_dump(mode="json")
    assert marker["prior_replay_ref"] == exhausted.input_refs[-1].model_dump(
        mode="json"
    )
    assert marker["prompt_revision"] == "2026-10-11-poc-safety-recap-1"
    assert "content" not in marker and "candidate" not in marker

    running = store.mark_running(
        identity,
        exhausted.stage,
        pending.input_refs,
        attempt_id="auth-recap-attempt-9",
    )
    assert running.attempt_number == 9
    assert running.input_refs[-1] == marker_event.output_refs[0]
    assert recovery_module.sensitive_auth_recap_replay_binding(running, artifacts) == {
        "reason": "SENSITIVE_CONTENT",
        "sensitive_category": "CREDENTIAL",
        "sensitive_line": 102,
        "sensitive_rule_id": "CREDENTIAL_ASSIGNMENT",
        "sensitive_field_kind": "AUTH",
        "sensitive_site_kind": "UNKNOWN",
    }


def test_attempt_nine_replay_is_one_shot_after_checkpoint_restore(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_eight(tmp_path)
    store.prepare_poc_sensitive_auth_recap_replay(exhausted, artifacts)
    with pytest.raises(ValueError, match="AUTH_RECAP_REPLAY_STALE"):
        store.prepare_poc_sensitive_auth_recap_replay(exhausted, artifacts)
    store.save_checkpoint(exhausted)
    with pytest.raises(ValueError, match="AUTH_RECAP_REPLAY_ALREADY_REPLAYED"):
        store.prepare_poc_sensitive_auth_recap_replay(exhausted, artifacts)


def test_attempt_nine_requires_bound_closed_diagnostic(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_eight(tmp_path)
    prior = json.loads(artifacts.read_bounded(exhausted.output_refs[0], 4096))
    changed_ref = artifacts.put_json(prior | {"sensitive_rule_id": "TOKEN_ASSIGNMENT"})
    changed = exhausted.model_copy(update={"output_refs": (changed_ref,)})
    store.save_checkpoint(changed)
    with pytest.raises(ValueError, match="AUTH_RECAP_REPLAY_DIAGNOSTIC_INVALID"):
        store.prepare_poc_sensitive_auth_recap_replay(changed, artifacts)


def test_attempt_nine_requires_two_settled_calls(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_eight(tmp_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE simple_codex_calls SET status = 'CONFIRMED' "
            "WHERE call_id = 'auth-recap-safe-call-2'"
        )
    with pytest.raises(ValueError, match="AUTH_RECAP_REPLAY_CALL_LINEAGE_INVALID"):
        store.prepare_poc_sensitive_auth_recap_replay(exhausted, artifacts)


def test_attempt_nine_binding_rejects_forged_prior_marker(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_eight(tmp_path)
    pending = store.prepare_poc_sensitive_auth_recap_replay(exhausted, artifacts)
    running = store.mark_running(
        exhausted.identity,
        exhausted.stage,
        pending.input_refs,
        attempt_id="auth-recap-attempt-9",
    )
    marker = json.loads(artifacts.read_bounded(running.input_refs[-1], 4096))
    prior_ref = StoredDataRef.model_validate(marker["prior_replay_ref"])
    prior = json.loads(artifacts.read_bounded(prior_ref, 4096))
    forged_prior_ref = artifacts.put_json(prior | {"old_attempt_id": "wrong"})
    forged_marker_ref = artifacts.put_json(
        marker | {"prior_replay_ref": forged_prior_ref.model_dump(mode="json")}
    )
    inputs = list(running.input_refs)
    inputs[inputs.index(prior_ref)] = forged_prior_ref
    inputs[-1] = forged_marker_ref
    forged = running.model_copy(
        update={
            "input_refs": tuple(inputs),
            "input_hash": input_reference_hash(tuple(inputs)),
        }
    )
    assert (
        recovery_module.sensitive_auth_recap_replay_binding(forged, artifacts) is None
    )


def test_attempt_nine_transaction_rolls_back(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_eight(tmp_path)
    before = AgentActivityStore(store.database_path).list_analysis(
        exhausted.identity.analysis_id, hypothesis_id=exhausted.identity.hypothesis_id
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_poc_sensitive_auth_recap_replay(
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


@pytest.mark.asyncio
async def test_attempt_nine_closed_guidance_reaches_initial_candidate_prompt(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_eight(tmp_path)
    pending = store.prepare_poc_sensitive_auth_recap_replay(exhausted, artifacts)
    running = store.mark_running(
        exhausted.identity,
        exhausted.stage,
        pending.input_refs,
        attempt_id="auth-recap-attempt-9",
    )
    client = _RepairClient()

    result = await PoCCandidateStage(client=client, artifacts=artifacts)(running, {})

    assert result.output_refs
    assert client.prompts
    prompt = client.prompts[0]
    assert b"2026-10-11-poc-safety-recap-1" in prompt
    assert b"CREDENTIAL_ASSIGNMENT" in prompt
    assert b"AUTH" in prompt and b"UNKNOWN" in prompt
    assert b"line 102" in prompt
    assert prompt.endswith(b"</POC_SAFETY_RECAP>\n")
    assert b"never-print-this-cookie" not in prompt
