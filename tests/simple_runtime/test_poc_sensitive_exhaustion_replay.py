"""One exact terminal sensitive-content lineage can use a revised prompt once."""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

import pytest

import sastsimi.composition.simple_runtime_composition as composition
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.poc_candidate import PoCCandidateRejected, validate_candidate
from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.interfaces.cli.main import main
from sastsimi.observability.agent_activity import ActivityKind
from sastsimi.progress.models import ProgressSnapshot
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageStatus,
)
from sastsimi.simple_runtime.recovery import sensitive_exhaustion_replay_binding
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_legacy_import_stop_replan import _PinnedStaticStub
from tests.simple_runtime.test_poc_anchor_failure_replay import _failed_second_anchor
from tests.unit.interfaces.test_public_simple_cli import _config, _PublicApplication
from tests.unit.simple_runtime.test_recovery_composition import (
    _config as _composition_config,
)
from tests.unit.simple_runtime.test_recovery_composition import _profile


def _bound_root(store: SimpleCheckpointStore, child: StageCheckpoint) -> None:
    root_identity = child.identity.model_copy(update={"hypothesis_id": None})
    previous = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    running = store.mark_running(
        root_identity,
        SimpleStage.HYPOTHESIS_DONE,
        previous.input_refs,
        attempt_id=f"root-for-{child.attempt_id}",
    )
    store.mark_failure(
        running,
        StageFailure(
            code=(
                "CANDIDATE_CHILD_ERROR_BOUND:"
                f"{child.error_code}:{child.identity.hypothesis_id}:{child.attempt_id}"
            ),
            retryable=False,
            safe_message="Candidate child analysis stopped",
        ),
        StageStatus.BLOCKED
        if child.status is StageStatus.BLOCKED
        else StageStatus.FAILED,
    )


def _attempt_six(
    tmp_path: Path,
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store, artifacts, fourth = _failed_second_anchor(tmp_path)
    fifth_pending = store.prepare_poc_anchor_failure_replay(fourth, artifacts)
    fifth = store.mark_running(
        fourth.identity,
        fourth.stage,
        fifth_pending.input_refs,
        attempt_id="anchor-attempt-5",
    )
    fifth_failed = store.mark_failure(
        fifth,
        StageFailure(
            code="HYPOTHESIS_ANCHOR_INVALID",
            retryable=False,
            safe_message="Pre-provider anchor failed",
        ),
        StageStatus.FAILED,
    )
    _bound_root(store, fifth_failed)

    sixth_pending = store.prepare_poc_anchor_failure_replay(fifth_failed, artifacts)
    sixth = store.mark_running(
        fourth.identity,
        fourth.stage,
        sixth_pending.input_refs,
        attempt_id="sensitive-attempt-6",
    )
    diagnostic_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate_rejection_diagnostic",
            "reason": "SENSITIVE_CONTENT",
            "line_count": 210,
            "branch_count": 1,
            "inconclusive_line_count": 1,
            "exit_two_line_count": 0,
            "exit_zero_line_count": 0,
            "sensitive_category": "MULTIPLE_RULES",
            "sensitive_line": 64,
        }
    )
    sixth_failed = store.mark_failure(
        sixth,
        StageFailure(
            code="POC_SENSITIVE_CONTENT",
            retryable=True,
            safe_message="PoC candidate is not self-contained",
            evidence_refs=(diagnostic_ref,),
        ),
        StageStatus.BLOCKED,
    )
    exhausted = store.mark_recovery_exhausted(sixth_failed)
    _bound_root(store, exhausted)
    return store, artifacts, exhausted


def test_exact_attempt_six_replay_keeps_history_and_reopens_only_child(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_six(tmp_path)
    identity = exhausted.identity
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    root_before = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    initial_before = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
    events_before = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    pending = store.prepare_poc_sensitive_exhaustion_replay(exhausted, artifacts)

    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 6
    assert pending.output_refs == ()
    assert exhausted.output_refs[0] in pending.input_refs
    assert store.require(root_identity, SimpleStage.HYPOTHESIS_DONE) == root_before
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
    assert marker_event.error_code == "POC_SENSITIVE_EXHAUSTION_REPLAYED"
    marker = json.loads(artifacts.read(marker_event.output_refs[0]))
    assert marker["old_attempt_id"] == exhausted.attempt_id
    assert marker["old_attempt_number"] == 6
    assert (
        marker["old_checkpoint_hash"]
        == hashlib.sha256(
            canonical_bytes(exhausted.model_dump(mode="json"))
        ).hexdigest()
    )
    assert marker["diagnostic_ref"] == exhausted.output_refs[0].model_dump(mode="json")
    assert marker["prompt_revision"] == "2026-10-11-a002-sensitive-1"
    assert "content" not in marker
    assert "candidate" not in marker

    running = store.mark_running(
        identity, exhausted.stage, pending.input_refs, attempt_id="sensitive-attempt-7"
    )
    assert running.attempt_number == 7
    assert running.input_refs[-1] == marker_event.output_refs[0]
    assert sensitive_exhaustion_replay_binding(running, artifacts) == {
        "reason": "SENSITIVE_CONTENT",
        "sensitive_category": "MULTIPLE_RULES",
        "sensitive_line": 64,
    }


def test_replay_rejects_altered_diagnostic(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_six(tmp_path)
    altered = artifacts.put_json(
        {
            "kind": "simple_poc_candidate_rejection_diagnostic",
            "reason": "SENSITIVE_CONTENT",
            "line_count": 210,
            "branch_count": 1,
            "inconclusive_line_count": 1,
            "exit_two_line_count": 0,
            "exit_zero_line_count": 0,
            "sensitive_category": "MULTIPLE_RULES",
            "sensitive_line": 65,
        }
    )
    changed = exhausted.model_copy(update={"output_refs": (altered,)})
    store.save_checkpoint(changed)

    with pytest.raises(
        ValueError, match="POC_SENSITIVE_EXHAUSTION_REPLAY_EVENT_INVALID"
    ):
        store.prepare_poc_sensitive_exhaustion_replay(changed, artifacts)
    assert store.require(exhausted.identity, exhausted.stage) == changed


@pytest.mark.parametrize("field", ["stage", "identity", "attempt_number"])
def test_replay_rejects_unrelated_stage_analysis_or_attempt(
    tmp_path: Path, field: str
) -> None:
    store, artifacts, exhausted = _attempt_six(tmp_path)
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
        changed = exhausted.model_copy(update={"attempt_number": 5})

    with pytest.raises(ValueError, match="POC_SENSITIVE_EXHAUSTION_REPLAY_INVALID"):
        store.prepare_poc_sensitive_exhaustion_replay(changed, artifacts)
    assert store.require(exhausted.identity, exhausted.stage) == exhausted


def test_replay_rejects_active_codex_call(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_six(tmp_path)
    assert store.begin_codex_call(
        "active-sensitive-call", exhausted.identity.analysis_id
    )

    with pytest.raises(
        ValueError, match="POC_SENSITIVE_EXHAUSTION_REPLAY_CODEX_UNRESOLVED"
    ):
        store.prepare_poc_sensitive_exhaustion_replay(exhausted, artifacts)


def test_replay_rejects_unexited_child_spawn(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_six(tmp_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "INSERT INTO simple_codex_child_spawns "
            "(call_id, analysis_id, phase, status) VALUES (?, ?, 'EXEC', 'SPAWNING')",
            ("unexited-sensitive-child", exhausted.identity.analysis_id),
        )

    with pytest.raises(
        ValueError, match="POC_SENSITIVE_EXHAUSTION_REPLAY_CODEX_UNRESOLVED"
    ):
        store.prepare_poc_sensitive_exhaustion_replay(exhausted, artifacts)


def test_replay_rejects_downstream_checkpoint(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_six(tmp_path)
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

    with pytest.raises(
        ValueError, match="POC_SENSITIVE_EXHAUSTION_REPLAY_LINEAGE_INVALID"
    ):
        store.prepare_poc_sensitive_exhaustion_replay(exhausted, artifacts)


def test_replay_cannot_repeat_even_if_old_checkpoint_is_restored(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_six(tmp_path)
    store.prepare_poc_sensitive_exhaustion_replay(exhausted, artifacts)
    with pytest.raises(ValueError, match="POC_SENSITIVE_EXHAUSTION_REPLAY_STALE"):
        store.prepare_poc_sensitive_exhaustion_replay(exhausted, artifacts)
    store.save_checkpoint(exhausted)
    with pytest.raises(
        ValueError, match="POC_SENSITIVE_EXHAUSTION_REPLAY_ALREADY_REPLAYED"
    ):
        store.prepare_poc_sensitive_exhaustion_replay(exhausted, artifacts)


def test_replay_preserves_completed_sibling(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_six(tmp_path)
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

    store.prepare_poc_sensitive_exhaustion_replay(exhausted, artifacts)

    assert store.require(sibling.identity, sibling.stage) == sibling


def test_replay_marker_is_atomic_on_failure(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_six(tmp_path)
    before = AgentActivityStore(store.database_path).list_analysis(
        exhausted.identity.analysis_id, hypothesis_id=exhausted.identity.hypothesis_id
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_poc_sensitive_exhaustion_replay(
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


def test_replay_does_not_relax_candidate_secret_rejection() -> None:
    with pytest.raises(PoCCandidateRejected, match="POC_SENSITIVE_CONTENT"):
        validate_candidate(
            b"#!/bin/sh\ncookie=never-print-this-cookie\nprintf x\n",
            allowed_environment_names=frozenset(),
        )


@pytest.mark.asyncio
async def test_application_replay_requires_explicit_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, exhausted = _attempt_six(tmp_path)
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
    assert store.require(identity, exhausted.stage) == exhausted
    await application.resume(
        identity.analysis_id,
        repair_poc_sensitive_exhaustion_hypothesis=identity.hypothesis_id,
    )
    assert store.require(identity, exhausted.stage).status is StageStatus.PENDING


def test_cli_forwards_explicit_sensitive_exhaustion_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class _Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_sensitive_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("plain", repair_poc_sensitive_exhaustion_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_poc_sensitive_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("progress", repair_poc_sensitive_exhaustion_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = _Application()
    for extra, label in [(["--format", "json"], "plain"), ([], "progress")]:
        assert main(
            [
                "resume",
                "A-002",
                "--repair-poc-sensitive-exhaustion",
                "hypothesis-1",
                *extra,
            ],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (label, "hypothesis-1")
        capsys.readouterr()


@pytest.mark.parametrize("with_progress", [False, True])
def test_public_adapter_forwards_sensitive_exhaustion_to_application(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_progress: bool
) -> None:
    public = composition.PublicSimpleRuntimeApplication(
        _composition_config(tmp_path), _profile(tmp_path)
    )
    seen: list[tuple[str, str | None]] = []
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    outcome = SimpleAnalysisOutcome(
        identity=identity,
        display_analysis_id="A-001",
        status="BLOCKED",
        current_stage=SimpleStage.POC_CANDIDATE_DONE,
    )

    class Application:
        async def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_sensitive_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> SimpleAnalysisOutcome:
            seen.append((analysis_id, repair_poc_sensitive_exhaustion_hypothesis))
            return outcome

    async def track(
        task: asyncio.Task[SimpleAnalysisOutcome],
        _started: list[str],
        _callback: Callable[[ProgressSnapshot], None],
    ) -> SimpleAnalysisOutcome:
        return await task

    monkeypatch.setattr(
        composition, "build_analysis_application", lambda *_args: Application()
    )
    monkeypatch.setattr(public._display, "resolve", lambda _id: "analysis-1")
    monkeypatch.setattr(
        public._store,
        "require_analysis_run",
        lambda _id: SimpleNamespace(
            repository="https://example.invalid/repo", commit_id="a" * 40
        ),
    )
    monkeypatch.setattr(public, "_resume_outcome", lambda *_args: {"status": "BLOCKED"})
    monkeypatch.setattr(public, "_track", track)

    if with_progress:
        public.resume_with_progress(
            "A-001",
            lambda _snapshot: None,
            repair_poc_sensitive_exhaustion_hypothesis="hypothesis-1",
        )
    else:
        public.resume(
            "A-001", repair_poc_sensitive_exhaustion_hypothesis="hypothesis-1"
        )
    assert seen == [("analysis-1" if with_progress else "A-001", "hypothesis-1")]
