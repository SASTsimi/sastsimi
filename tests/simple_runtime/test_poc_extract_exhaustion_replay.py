"""An explicit repair of an exhausted, sanitized PoC extraction failure."""

from __future__ import annotations

import hashlib
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
    input_reference_hash,
)
from sastsimi.simple_runtime.runner import StageFailed
from sastsimi.simple_runtime.stages import PoCCandidateStage
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_legacy_import_stop_replan import (
    _checkpoint,
    _PinnedStaticStub,
    _seed,
)


def _exhausted_extract(
    tmp_path: Path,
    *,
    stderr: bytes = b"Traceback (sanitized): extract\nRuntimeError\n",
    stdout: bytes = b"",
    execution_patch: dict[str, object] | None = None,
    cleanup_status: str = "REMOVED",
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store, artifacts, old_stop, _ = _seed(
        tmp_path, stderr=b"TypeError: earlier PoC harness failure\n"
    )
    identity = old_stop.identity
    candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    content_ref = candidate.output_refs[1]
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "attempt_id": "attempt-3",
            "content_ref": content_ref.model_dump(mode="json"),
            "content_digest": hashlib.sha256(artifacts.read(content_ref)).hexdigest(),
        }
    )
    candidate = candidate.model_copy(
        update={
            "attempt_id": "attempt-3",
            "attempt_number": 3,
            "output_refs": (candidate_ref, content_ref),
            "container_id": None,
        }
    )
    store.save_checkpoint(candidate)
    inputs = (candidate_ref, content_ref)
    store.save_checkpoint(
        _checkpoint(
            identity,
            SimpleStage.POC_EXECUTION_DONE,
            status=StageStatus.PENDING,
            inputs=inputs,
            attempt_number=2,
            recipe_ref=candidate.recipe_ref,
            image_digest=candidate.image_digest,
        )
    )
    running = store.mark_running(
        identity,
        SimpleStage.POC_EXECUTION_DONE,
        inputs,
        attempt_id="attempt-3",
        inherit_from=candidate,
    )
    stdout_ref = artifacts.put_bytes(stdout, "text/plain")
    stderr_ref = artifacts.put_bytes(stderr, "text/plain")
    receipt: dict[str, object] = {
        "kind": "simple_poc_execution",
        "attempt_id": running.attempt_id,
        "candidate_ref": candidate_ref.model_dump(mode="json"),
        "content_ref": content_ref.model_dump(mode="json"),
        "stdout_ref": stdout_ref.model_dump(mode="json"),
        "stderr_ref": stderr_ref.model_dump(mode="json"),
        "exit_code": 1,
        "timed_out": False,
        "container_id": "owned-container-3",
        "image_digest": running.image_digest,
    }
    receipt.update(execution_patch or {})
    execution_ref = artifacts.put_json(
        receipt
    )
    cleanup_ref = artifacts.put_json(
        {
            "kind": "simple_container_cleanup",
            "attempt_id": running.attempt_id,
            "container_id": "owned-container-3",
            "status": cleanup_status,
        }
    )
    evidence = (execution_ref, stdout_ref, stderr_ref, cleanup_ref)
    failed = store.mark_failure(
        running,
        StageFailure(
            code="POC_EXECUTION_FAILED",
            retryable=True,
            safe_message="PoC execution failed",
            evidence_refs=evidence,
        ),
        StageStatus.BLOCKED,
    )
    exhausted = store.mark_recovery_exhausted(failed)
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    root_running = root.model_copy(
        update={
            "status": StageStatus.RUNNING,
            "attempt_id": "root-attempt-3",
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
                f"{identity.hypothesis_id}:{running.attempt_id}"
            ),
            retryable=False,
            safe_message="Child PoC exhausted automatic recovery",
        ),
        StageStatus.BLOCKED,
    )
    return store, artifacts, exhausted


def test_explicit_extract_replay_reseeds_only_candidate_with_safe_guidance(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_extract(tmp_path)
    identity = exhausted.identity
    initial = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
    old_candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    old_content = artifacts.read(old_candidate.output_refs[1])
    old_stderr = artifacts.read(exhausted.output_refs[2])
    before = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    pending = store.prepare_poc_extract_exhaustion_replay(exhausted, artifacts)

    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 3
    assert pending.recipe_ref == exhausted.recipe_ref
    assert pending.image_digest == exhausted.image_digest
    assert pending.container_id is None
    assert pending.input_hash == input_reference_hash(pending.input_refs)
    assert store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE) == initial
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    assert old_candidate.output_refs[0] in pending.input_refs
    assert all(ref in pending.input_refs for ref in exhausted.output_refs)
    repair_stage = PoCCandidateStage(client=None, artifacts=artifacts)  # type: ignore[arg-type]
    assert repair_stage._current_repair_refs(pending.input_refs) == (
        old_candidate.output_refs[0],
        exhausted.output_refs[0],
    )
    rule = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert rule["decision_origin"] == "RULE"
    assert rule["diagnostic_excerpt"] == "Traceback (sanitized): extract\nRuntimeError"
    assert rule["recovery_revision"] == 1
    assert rule["explicit_exhaustion_replay"] is True
    assert "actual AST" in rule["decision"]["guidance"]
    assert "fixed node count" in rule["decision"]["guidance"]
    assert artifacts.read(old_candidate.output_refs[1]) == old_content
    assert artifacts.read(exhausted.output_refs[2]) == old_stderr
    after = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    assert len(after) == len(before) + 1
    blocked_codes = [
        event.error_code for event in after if event.kind is ActivityKind.STAGE_BLOCKED
    ]
    assert blocked_codes[-2:] == ["POC_EXECUTION_FAILED", "RECOVERY_EXHAUSTED"]
    assert after[-1].error_code == "POC_EXTRACT_EXHAUSTION_REPLAYED"
    with pytest.raises(ValueError, match="POC_EXTRACT_EXHAUSTION_"):
        store.prepare_poc_extract_exhaustion_replay(exhausted, artifacts)
    next_candidate = store.mark_running(
        identity,
        SimpleStage.POC_CANDIDATE_DONE,
        pending.input_refs,
        attempt_id="replay-attempt-4",
    )
    assert next_candidate.attempt_number == 4
    assert next_candidate.attempt_id != exhausted.attempt_id


@pytest.mark.parametrize(
    "exception_name",
    ["AssertionError", "RuntimeError", "TypeError", "ValueError"],
)
def test_extract_replay_accepts_each_exact_sanitized_exception_once(
    tmp_path: Path, exception_name: str
) -> None:
    stderr = f"Traceback (sanitized): extract\n{exception_name}\n".encode("ascii")
    store, artifacts, exhausted = _exhausted_extract(tmp_path, stderr=stderr)

    pending = store.prepare_poc_extract_exhaustion_replay(exhausted, artifacts)

    rule = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert rule["diagnostic_excerpt"] == stderr.decode("ascii").strip()
    assert rule["decision"]["action"] == "REGENERATE_INPUT"
    assert artifacts.read(exhausted.output_refs[2]) == stderr
    with pytest.raises(ValueError, match="POC_EXTRACT_EXHAUSTION_"):
        store.prepare_poc_extract_exhaustion_replay(exhausted, artifacts)


@pytest.mark.parametrize(
    "fixture_changes",
    [
        {"stderr": b"Traceback (sanitized): extract\nRuntimeError: source text\n"},
        {"stderr": b"Traceback (sanitized): unrelated\nAssertionError\n"},
        {"stderr": b"Traceback (most recent call last):\nValueError\n"},
        {"stderr": b"Traceback (sanitized): extract\nOSError\n"},
        {"stderr": b"Traceback (sanitized): extract\nValueError\nother failure\n"},
        {"stdout": b"unexpected output\n"},
        {"execution_patch": {"candidate_ref": None}},
        {"execution_patch": {"image_digest": "sha256:" + "f" * 64}},
        {"execution_patch": {"timed_out": True}},
        {"execution_patch": {"exit_code": 0}},
        {"cleanup_status": "UNKNOWN"},
    ],
)
def test_extract_replay_refuses_nonexact_execution_or_diagnostic_without_mutation(
    tmp_path: Path, fixture_changes: dict[str, object]
) -> None:
    store, artifacts, exhausted = _exhausted_extract(tmp_path, **fixture_changes)  # type: ignore[arg-type]
    identity = exhausted.identity
    old_candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    old_events = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    with pytest.raises(ValueError, match="POC_EXTRACT_EXHAUSTION_EVIDENCE_INVALID"):
        store.prepare_poc_extract_exhaustion_replay(exhausted, artifacts)

    assert store.require(identity, SimpleStage.POC_CANDIDATE_DONE) == old_candidate
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    assert AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    ) == old_events


def test_extract_replay_refuses_changed_root_or_unresolved_codex_call(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_extract(tmp_path)
    identity = exhausted.identity
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    store.save_checkpoint(root.model_copy(update={"error_code": "other-child"}))
    with pytest.raises(ValueError, match="POC_EXTRACT_EXHAUSTION_ROOT_BOUND_INVALID"):
        store.prepare_poc_extract_exhaustion_replay(exhausted, artifacts)
    store.save_checkpoint(root)

    assert store.begin_codex_call("unfinished-call", identity.analysis_id)
    with pytest.raises(ValueError, match="POC_EXTRACT_EXHAUSTION_CODEX_UNRESOLVED"):
        store.prepare_poc_extract_exhaustion_replay(exhausted, artifacts)
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted


def test_extract_replay_rolls_back_checkpoint_and_marker_together(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_extract(tmp_path)
    identity = exhausted.identity
    candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    events = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_poc_extract_exhaustion_replay(
            exhausted, artifacts, fail_before_commit=True
        )
    assert store.require(identity, SimpleStage.POC_CANDIDATE_DONE) == candidate
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    assert AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    ) == events


@pytest.mark.parametrize("extra_kind", ["old_attempt_decision", "prior_replay"])
def test_extract_replay_refuses_ambiguous_or_already_replayed_history(
    tmp_path: Path, extra_kind: str
) -> None:
    store, artifacts, exhausted = _exhausted_extract(tmp_path)
    identity = exhausted.identity
    before_candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    anchor = store.stage_activity(
        identity, SimpleStage.POC_EXECUTION_DONE, exhausted.attempt_id or ""
    )[-1]
    AgentActivityStore(store.database_path).append(
        anchor.model_copy(
            update={
                "event_id": uuid4().hex,
                "sequence": 9_999,
                "kind": ActivityKind.DECISION_RECORDED,
                "error_code": (
                    "POC_EXTRACT_EXHAUSTION_REPLAYED"
                    if extra_kind == "prior_replay"
                    else "OTHER_DECISION"
                ),
                "output_refs": (),
            }
        )
    )

    with pytest.raises(
        ValueError,
        match=(
            "POC_EXTRACT_EXHAUSTION_ALREADY_REPLAYED"
            if extra_kind == "prior_replay"
            else "POC_EXTRACT_EXHAUSTION_EVENT_INVALID"
        ),
    ):
        store.prepare_poc_extract_exhaustion_replay(exhausted, artifacts)
    assert store.require(identity, SimpleStage.POC_CANDIDATE_DONE) == before_candidate
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted


@pytest.mark.asyncio
async def test_replayed_candidate_receives_neutral_ast_cardinality_guidance(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_extract(tmp_path)
    pending = store.prepare_poc_extract_exhaustion_replay(exhausted, artifacts)

    class RejectingClient:
        def __init__(self) -> None:
            self.prompts: list[bytes] = []

        async def call(self, **kwargs: Any) -> StageFailure:
            self.prompts.append(kwargs["prompt"])
            return StageFailure(
                code="AUTH_REQUIRED", retryable=False, safe_message="test stop"
            )

    client = RejectingClient()
    stage = PoCCandidateStage(client=client, artifacts=artifacts)
    with pytest.raises(StageFailed):
        await stage(pending, {})

    assert len(client.prompts) == 1
    assert b"actual AST route or handler selection" in client.prompts[0]
    assert b"fixed node count" in client.prompts[0]
    assert b"Traceback (sanitized): extract" in client.prompts[0]


@pytest.mark.asyncio
async def test_application_requires_explicit_extract_repair_and_pinned_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, exhausted = _exhausted_extract(tmp_path)
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
    assert store.require(identity, SimpleStage.POC_CANDIDATE_DONE).status is (
        StageStatus.PENDING
    )
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
