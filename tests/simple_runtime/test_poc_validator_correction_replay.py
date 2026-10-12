"""One bounded candidate replay after corrected replay validators."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from sastsimi.contracts.poc_candidate import PoCCandidateRejected
from sastsimi.observability.agent_activity import ActivityKind
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.poc_layout import pinned_layout_replay_binding
from sastsimi.simple_runtime.recovery import (
    candidate_app_replay_unsupported_app,
    urlconf_replay_binding,
)
from sastsimi.simple_runtime.runner import StageBlocked
from sastsimi.simple_runtime.stages import (
    _reject_candidate_app_replay_content,
    _reject_urlconf_replay_content,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_legacy_import_stop_replan import _PinnedStaticStub
from tests.simple_runtime.test_poc_urlconf_exhaustion_replay import (
    _LAYOUT_CANDIDATE,
    _blocked_layout_execution,
)


def _blocked_validator_candidate(
    tmp_path: Path, *, file_changes: dict[str, str] | None = None
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store, artifacts, stopped8 = _blocked_layout_execution(
        tmp_path, file_changes=file_changes
    )
    pending = store.prepare_poc_generated_input_replay(stopped8, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-9"
    )
    diagnostic_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate_rejection_diagnostic",
            "reason": "OTHER_VALIDATOR_REJECTION",
            "line_count": 2,
            "branch_count": 0,
            "inconclusive_line_count": 0,
            "exit_two_line_count": 0,
            "exit_zero_line_count": 0,
        }
    )
    failed = store.mark_failure(
        running,
        StageFailure(
            code="POC_URLCONF_REPLAY_UNSUPPORTED",
            retryable=True,
            safe_message="Candidate rejected by replay validator",
            evidence_refs=(diagnostic_ref,),
        ),
        StageStatus.BLOCKED,
    )
    stopped9 = store.mark_recovery_exhausted(failed)
    root_identity = stopped9.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    root_running = root.model_copy(
        update={
            "status": StageStatus.RUNNING,
            "attempt_id": "root-attempt-9",
            "error_code": None,
            "retryable": False,
        }
    )
    store.save_checkpoint(root_running)
    store.mark_failure(
        root_running,
        StageFailure(
            code=(
                "CANDIDATE_CHILD_ERROR_BOUND:RECOVERY_EXHAUSTED:"
                f"{stopped9.identity.hypothesis_id}:{stopped9.attempt_id}"
            ),
            retryable=False,
            safe_message="Ninth candidate exhausted recovery",
        ),
        StageStatus.BLOCKED,
    )
    return store, artifacts, stopped9


def test_validator_correction_replay_is_one_shot_and_keeps_prior_bindings(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped9 = _blocked_validator_candidate(tmp_path)
    identity = stopped9.identity
    initial = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
    events_before = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id
    )

    pending = store.prepare_poc_generated_input_replay(stopped9, artifacts)

    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 9
    assert pending.recovery_decision_refs[:-1] == stopped9.recovery_decision_refs
    assert all(ref in pending.input_refs for ref in stopped9.input_refs)
    assert all(ref in pending.input_refs for ref in stopped9.output_refs)
    assert store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE) == initial
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    marker = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert marker["kind"] == "simple_poc_validator_correction_replay"
    assert marker["old_attempt_id"] == stopped9.attempt_id
    events_after = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id
    )
    assert len(events_after) == len(events_before) + 1
    replay_events = [
        event
        for event in events_after
        if event.error_code == "POC_VALIDATOR_CORRECTION_REPLAYED"
    ]
    assert len(replay_events) == 1
    assert replay_events[0].kind is ActivityKind.DECISION_RECORDED
    assert replay_events[0].output_refs == (pending.recovery_decision_refs[-1],)

    running = store.mark_running(
        identity, pending.stage, pending.input_refs, attempt_id="attempt-10"
    )
    assert running.attempt_number == 10
    assert urlconf_replay_binding(running, artifacts) is not None
    assert pinned_layout_replay_binding(running, artifacts) is not None
    assert candidate_app_replay_unsupported_app(running, artifacts) == "django_mailbox"
    corrected = _LAYOUT_CANDIDATE.replace(
        b"root = '/workspace/src'", b"root = '/workspace'"
    )
    _reject_candidate_app_replay_content(running, artifacts, corrected)
    with pytest.raises(StageBlocked) as blocked:
        _reject_urlconf_replay_content(running, artifacts, corrected)
    assert blocked.value.failure.code == "POC_URLCONF_ORIGIN_UNVERIFIED"
    with pytest.raises(
        PoCCandidateRejected, match="POC_CANDIDATE_APP_REPLAY_UNSUPPORTED"
    ):
        _reject_candidate_app_replay_content(
            running,
            artifacts,
            corrected.replace(b"import os", b"import os\nimport django_mailbox"),
        )
    with pytest.raises(StageBlocked) as blocked:
        _reject_urlconf_replay_content(
            running,
            artifacts,
            corrected.replace(
                b"settings.configure(ROOT_URLCONF='standalone.config.urls')",
                b"settings.configure(ROOT_URLCONF='standalone.config.urls')\n"
                b"from django import conf\n"
                b"setattr(conf.settings, 'ROOT_' + 'URLCONF', 'helpdesk.urls')",
            ),
        )
    assert blocked.value.failure.code == "POC_URLCONF_ORIGIN_UNVERIFIED"
    with pytest.raises(ValueError, match="POC_URLCONF_REPLAY_UNBOUND"):
        forged_marker = dict(marker, old_checkpoint_hash="0" * 64)
        forged_ref = artifacts.put_json(forged_marker)
        forged_inputs = (*running.input_refs[:-1], forged_ref)
        forged = running.model_copy(
            update={
                "input_refs": forged_inputs,
                "input_hash": input_reference_hash(forged_inputs),
                "recovery_decision_refs": (
                    *running.recovery_decision_refs[:-1],
                    forged_ref,
                ),
            }
        )
        urlconf_replay_binding(forged, artifacts)
    with pytest.raises(ValueError, match="POC_GENERATED_INPUT_REPLAY_"):
        store.prepare_poc_generated_input_replay(stopped9, artifacts)


def test_validator_correction_replay_rejects_stale_events_root_and_downstream(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped9 = _blocked_validator_candidate(tmp_path)
    identity = stopped9.identity
    before = AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)

    with pytest.raises(ValueError, match="POC_GENERATED_INPUT_REPLAY_STALE"):
        store.prepare_poc_generated_input_replay(
            stopped9.model_copy(update={"attempt_id": "stale-attempt"}), artifacts
        )
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_poc_generated_input_replay(
            stopped9, artifacts, fail_before_commit=True
        )
    assert store.require(identity, stopped9.stage) == stopped9
    assert (
        AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)
        == before
    )

    failed_event = next(
        event
        for event in before
        if event.hypothesis_id == identity.hypothesis_id
        and event.attempt_id == stopped9.attempt_id
        and event.error_code == "POC_URLCONF_REPLAY_UNSUPPORTED"
    )
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE agent_activity_events SET event_json = ? WHERE event_id = ?",
            (
                failed_event.model_copy(
                    update={"error_code": "OTHER_VALIDATOR_REJECTION"}
                ).model_dump_json(),
                failed_event.event_id,
            ),
        )
    with pytest.raises(ValueError, match="POC_GENERATED_INPUT_REPLAY_EVENT_INVALID"):
        store.prepare_poc_generated_input_replay(stopped9, artifacts)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE agent_activity_events SET event_json = ? WHERE event_id = ?",
            (failed_event.model_dump_json(), failed_event.event_id),
        )

    root_identity = identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    store.save_checkpoint(root.model_copy(update={"error_code": "UNRELATED"}))
    with pytest.raises(ValueError, match="POC_GENERATED_INPUT_REPLAY_ROOT_INVALID"):
        store.prepare_poc_generated_input_replay(stopped9, artifacts)
    store.save_checkpoint(root)

    downstream = stopped9.model_copy(
        update={
            "stage": SimpleStage.POC_EXECUTION_DONE,
            "status": StageStatus.BLOCKED,
            "error_code": "UNRELATED",
        }
    )
    store.save_checkpoint(downstream)
    with pytest.raises(ValueError, match="POC_GENERATED_INPUT_REPLAY_LINEAGE_INVALID"):
        store.prepare_poc_generated_input_replay(stopped9, artifacts)
    assert store.require(identity, stopped9.stage) == stopped9


def test_validator_correction_replay_rejects_unresolved_codex_child(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped9 = _blocked_validator_candidate(tmp_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "INSERT INTO simple_codex_child_spawns "
            "(call_id, analysis_id, phase, status, pid, start_identity) "
            "VALUES (?, ?, 'EXEC', 'CAPTURED', ?, ?)",
            ("call-unexited", stopped9.identity.analysis_id, 12345, "start-1"),
        )
    with pytest.raises(ValueError, match="POC_GENERATED_INPUT_REPLAY_CODEX_UNRESOLVED"):
        store.prepare_poc_generated_input_replay(stopped9, artifacts)
    assert store.require(stopped9.identity, stopped9.stage) == stopped9


@pytest.mark.asyncio
async def test_generated_input_public_flag_routes_blocked_attempt9(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _artifacts, stopped9 = _blocked_validator_candidate(tmp_path)
    identity = stopped9.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=_PinnedStaticStub(tmp_path / "data" / "workspaces"),
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )

    async def static_scope(*_args: object) -> None:
        return None

    async def resume_locked(_analysis_id: str) -> SimpleAnalysisOutcome:
        return SimpleAnalysisOutcome(
            identity=identity.model_copy(update={"hypothesis_id": None}),
            display_analysis_id="A-001",
            status="RUNNING",
            current_stage=SimpleStage.POC_CANDIDATE_DONE,
        )

    monkeypatch.setattr(application, "_assert_completed_static_scope", static_scope)
    monkeypatch.setattr(application, "_resume_locked", resume_locked)
    monkeypatch.setattr(
        application, "_verify_registered_candidate_proposals", lambda _root: None
    )
    await application.resume(identity.analysis_id)
    assert store.require(identity, stopped9.stage) == stopped9
    await application.resume(
        identity.analysis_id,
        repair_poc_generated_input_hypothesis=identity.hypothesis_id,
    )
    pending = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 9
