"""One-shot replay of a CAS-bound, closed PoC runtime failure."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest

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
)
from sastsimi.simple_runtime.runner import StageFailed
from sastsimi.simple_runtime.stages import PoCCandidateStage
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_legacy_import_stop_replan import _PinnedStaticStub
from tests.simple_runtime.test_poc_extract_exhaustion_replay import _exhausted_extract

_CLOSED_ERROR = (
    b"ValueError: api_key=private-example\n"
    b"Traceback: foreign_related_fields > related_fields > resolve_related_fields\n"
)


def _failed_closed_runtime_anchor(
    tmp_path: Path,
) -> tuple[SimpleArtifactRepository, StageCheckpoint, SimpleCheckpointStore]:
    store, artifacts, exhausted = _exhausted_extract(
        tmp_path,
        stderr=_CLOSED_ERROR,
        execution_patch={"exit_code": 2},
    )
    pending = store.prepare_poc_closed_runtime_exhaustion_replay(exhausted, artifacts)
    running = store.mark_running(
        pending.identity,
        SimpleStage.POC_CANDIDATE_DONE,
        pending.input_refs,
        attempt_id="closed-runtime-anchor-attempt-4",
    )
    assert running.attempt_number == 4
    failed = store.mark_failure(
        running,
        StageFailure(
            code="HYPOTHESIS_ANCHOR_INVALID",
            retryable=False,
            safe_message="Pinned evidence could not be validated",
        ),
        StageStatus.FAILED,
    )
    root_identity = pending.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    root_running = store.mark_running(
        root_identity,
        SimpleStage.HYPOTHESIS_DONE,
        root.input_refs,
        attempt_id="root-closed-runtime-anchor-failed",
    )
    store.mark_failure(
        root_running,
        StageFailure(
            code=(
                "CANDIDATE_CHILD_ERROR_BOUND:HYPOTHESIS_ANCHOR_INVALID:"
                f"{pending.identity.hypothesis_id}:{failed.attempt_id}"
            ),
            retryable=False,
            safe_message="Child PoC candidate could not validate pinned evidence",
        ),
        StageStatus.FAILED,
    )
    return artifacts, failed, store


def test_closed_runtime_anchor_reopens_same_decision_once_without_new_poc_rule(
    tmp_path: Path,
) -> None:
    artifacts, failed, store = _failed_closed_runtime_anchor(tmp_path)
    old_refs = failed.recovery_decision_refs
    old_inputs = failed.input_refs
    old_candidate_events = AgentActivityStore(store.database_path).list_analysis(
        failed.identity.analysis_id, hypothesis_id=failed.identity.hypothesis_id
    )

    pending = store.prepare_poc_anchor_failure_replay(failed, artifacts)

    assert pending.status is StageStatus.PENDING
    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.attempt_number == 4
    assert pending.input_refs == old_inputs
    assert pending.recovery_decision_refs == old_refs
    assert json.loads(artifacts.read(old_refs[-1]))["attempt"] == 3
    assert pending.output_refs == ()
    assert store.get(failed.identity, SimpleStage.POC_EXECUTION_DONE) is None
    events = AgentActivityStore(store.database_path).list_analysis(
        failed.identity.analysis_id, hypothesis_id=failed.identity.hypothesis_id
    )
    new_events = events[len(old_candidate_events) :]
    assert len(new_events) == 1
    assert new_events[0].error_code == "POC_CLOSED_RUNTIME_ANCHOR_REPLAYED"
    assert (
        sum(
            event.error_code == "POC_CLOSED_RUNTIME_EXHAUSTION_REPLAYED"
            for event in events
        )
        == 1
    )
    with pytest.raises(ValueError):
        store.prepare_poc_anchor_failure_replay(failed, artifacts)


@pytest.mark.asyncio
async def test_closed_runtime_anchor_replay_reaches_provider_on_attempt_five(
    tmp_path: Path,
) -> None:
    artifacts, failed, store = _failed_closed_runtime_anchor(tmp_path)
    pending = store.prepare_poc_anchor_failure_replay(failed, artifacts)
    running = store.mark_running(
        pending.identity,
        SimpleStage.POC_CANDIDATE_DONE,
        pending.input_refs,
        attempt_id="closed-runtime-anchor-attempt-5",
    )
    assert running.attempt_number == 5
    assert running.recovery_decision_refs == failed.recovery_decision_refs

    class BoundaryClient:
        async def call(self, **_kwargs: Any) -> StageFailure:
            return StageFailure(
                code="AUTH_REQUIRED", retryable=False, safe_message="test stop"
            )

    with pytest.raises(StageFailed) as error:
        await PoCCandidateStage(client=BoundaryClient(), artifacts=artifacts)(
            running, {}
        )
    assert error.value.failure.code == "AUTH_REQUIRED"


def test_closed_runtime_anchor_rejects_unrelated_recovery_rule_without_mutation(
    tmp_path: Path,
) -> None:
    artifacts, failed, store = _failed_closed_runtime_anchor(tmp_path)
    current_events = AgentActivityStore(store.database_path).list_analysis(
        failed.identity.analysis_id, hypothesis_id=failed.identity.hypothesis_id
    )
    wrong = failed.model_copy(
        update={"recovery_decision_refs": failed.recovery_decision_refs[:-1]}
    )
    store.save_checkpoint(wrong)

    with pytest.raises(ValueError):
        store.prepare_poc_anchor_failure_replay(wrong, artifacts)

    assert store.require(wrong.identity, wrong.stage) == wrong
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            failed.identity.analysis_id, hypothesis_id=failed.identity.hypothesis_id
        )
        == current_events
    )


def test_closed_runtime_replay_preserves_old_evidence_and_reopens_only_candidate(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_extract(
        tmp_path,
        stderr=_CLOSED_ERROR,
        execution_patch={"exit_code": 2},
    )
    identity = exhausted.identity
    old_candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    old_evidence = tuple(artifacts.read(ref) for ref in exhausted.output_refs)

    pending = store.prepare_poc_closed_runtime_exhaustion_replay(exhausted, artifacts)

    assert pending.status is StageStatus.PENDING
    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.attempt_number == exhausted.attempt_number
    assert old_candidate.output_refs[0] in pending.input_refs
    assert all(ref in pending.input_refs for ref in exhausted.output_refs)
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    assert tuple(artifacts.read(ref) for ref in exhausted.output_refs) == old_evidence
    rule = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert rule["closed_runtime_replay"] is True
    assert rule["closed_runtime_policy_revision"] == 1
    assert rule["decision_origin"] == "RULE"
    assert rule["original_error"]["code"] == "POC_EXECUTION_FAILED"
    assert rule["original_error"]["evidence_refs"] == [
        ref.model_dump(mode="json") for ref in exhausted.output_refs
    ]
    assert json.loads(rule["diagnostic_excerpt"]) == {
        "kind": "simple_poc_runtime_diagnostic_v1",
        "exception_class": "ValueError",
        "phase": "POC_EXECUTION",
        "function_frames": [
            "foreign_related_fields",
            "related_fields",
            "resolve_related_fields",
        ],
    }
    assert "private-example" not in json.dumps(rule)
    events = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    assert events[-1].kind is ActivityKind.DECISION_RECORDED
    assert events[-1].error_code == "POC_CLOSED_RUNTIME_EXHAUSTION_REPLAYED"

    with pytest.raises(ValueError):
        store.prepare_poc_closed_runtime_exhaustion_replay(exhausted, artifacts)


@pytest.mark.asyncio
async def test_explicit_fallback_resume_routes_closed_runtime_without_new_analysis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, exhausted = _exhausted_extract(
        tmp_path,
        stderr=_CLOSED_ERROR,
        execution_patch={"exit_code": 2},
        stdout=b"setup log without observed success\n",
    )
    identity = exhausted.identity
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
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted

    await application.resume(
        identity.analysis_id,
        repair_fallback_poc_stop_hypothesis=identity.hypothesis_id,
    )
    pending = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    assert pending.status is StageStatus.PENDING
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    rule = json.loads(_artifacts.read(pending.recovery_decision_refs[-1]))
    assert rule["closed_runtime_replay"] is True


@pytest.mark.parametrize(
    ("execution_patch", "cleanup_status", "stderr", "stdout"),
    [
        ({"exit_code": 1}, "REMOVED", _CLOSED_ERROR, b""),
        ({"exit_code": 2, "candidate_ref": None}, "REMOVED", _CLOSED_ERROR, b""),
        ({"exit_code": 2}, "UNKNOWN", _CLOSED_ERROR, b""),
        ({"exit_code": 2}, "REMOVED", b"ValueError: raw detail\n", b""),
        ({"exit_code": 2}, "REMOVED", _CLOSED_ERROR, b"REPRODUCED\n"),
    ],
)
def test_closed_runtime_replay_rejects_unverified_failure_without_mutation(
    tmp_path: Path,
    execution_patch: dict[str, object],
    cleanup_status: str,
    stderr: bytes,
    stdout: bytes,
) -> None:
    store, artifacts, exhausted = _exhausted_extract(
        tmp_path,
        stderr=stderr,
        stdout=stdout,
        execution_patch=execution_patch,
        cleanup_status=cleanup_status,
    )
    identity = exhausted.identity
    old_candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    old_events = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    with pytest.raises(ValueError, match="POC_EXTRACT_EXHAUSTION_EVIDENCE_INVALID"):
        store.prepare_poc_closed_runtime_exhaustion_replay(exhausted, artifacts)

    assert store.require(identity, SimpleStage.POC_CANDIDATE_DONE) == old_candidate
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            identity.analysis_id, hypothesis_id=identity.hypothesis_id
        )
        == old_events
    )


def test_closed_runtime_replay_marker_and_checkpoint_commit_atomically(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_extract(
        tmp_path,
        stderr=_CLOSED_ERROR,
        execution_patch={"exit_code": 2},
    )
    identity = exhausted.identity
    old_candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    old_events = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_poc_closed_runtime_exhaustion_replay(
            exhausted, artifacts, fail_before_commit=True
        )

    assert store.require(identity, SimpleStage.POC_CANDIDATE_DONE) == old_candidate
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            identity.analysis_id, hypothesis_id=identity.hypothesis_id
        )
        == old_events
    )


def test_closed_runtime_replay_rejects_other_hypothesis_and_existing_marker(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_extract(
        tmp_path,
        stderr=_CLOSED_ERROR,
        execution_patch={"exit_code": 2},
    )
    identity = exhausted.identity
    other = identity.model_copy(update={"hypothesis_id": "different-hypothesis"})
    foreign_artifacts = SimpleArtifactRepository(
        tmp_path / "data", other, create_dirs=False
    )
    with pytest.raises(ValueError, match="POC_EXTRACT_EXHAUSTION_INVALID"):
        store.prepare_poc_closed_runtime_exhaustion_replay(exhausted, foreign_artifacts)

    anchor = store.stage_activity(
        identity, SimpleStage.POC_EXECUTION_DONE, exhausted.attempt_id or ""
    )[-1]
    AgentActivityStore(store.database_path).append(
        anchor.model_copy(
            update={
                "event_id": uuid4().hex,
                "sequence": 9_999,
                "kind": ActivityKind.DECISION_RECORDED,
                "error_code": "POC_CLOSED_RUNTIME_EXHAUSTION_REPLAYED",
                "output_refs": (),
            }
        )
    )
    old_candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    with pytest.raises(ValueError, match="POC_EXTRACT_EXHAUSTION_ALREADY_REPLAYED"):
        store.prepare_poc_closed_runtime_exhaustion_replay(exhausted, artifacts)
    assert store.require(identity, SimpleStage.POC_CANDIDATE_DONE) == old_candidate
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted


@pytest.mark.asyncio
async def test_closed_runtime_repair_prompt_uses_only_closed_diagnostic(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_extract(
        tmp_path,
        stderr=_CLOSED_ERROR,
        stdout=b"setup log without observed success\n",
        execution_patch={"exit_code": 2},
    )
    pending = store.prepare_poc_closed_runtime_exhaustion_replay(exhausted, artifacts)

    class RejectingClient:
        def __init__(self) -> None:
            self.prompts: list[bytes] = []

        async def call(self, **kwargs: Any) -> StageFailure:
            self.prompts.append(kwargs["prompt"])
            return StageFailure(
                code="AUTH_REQUIRED", retryable=False, safe_message="test stop"
            )

    client = RejectingClient()
    with pytest.raises(StageFailed):
        await PoCCandidateStage(client=client, artifacts=artifacts)(pending, {})

    assert len(client.prompts) == 1
    assert b"foreign_related_fields" in client.prompts[0]
    assert b"private-example" not in client.prompts[0]
    assert b"setup log without observed success" not in client.prompts[0]
