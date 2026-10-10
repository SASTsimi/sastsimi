"""A corrected sensitive-content diagnostic may reopen one exact old PoC stop."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sastsimi.contracts.poc_candidate import POC_CANDIDATE_VALIDATOR_REVISION
from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.interfaces.cli.main import main
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
from sastsimi.simple_runtime.recovery import (
    RecoveryAction,
    RecoveryCategory,
    RecoveryDecision,
    RecoveryResolution,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_legacy_import_stop_replan import _PinnedStaticStub, _seed
from tests.unit.interfaces.test_public_simple_cli import _config, _PublicApplication


def _diagnostic(*, new: bool = False) -> dict[str, object]:
    value: dict[str, object] = {
        "kind": "simple_poc_candidate_rejection_diagnostic",
        "reason": "SENSITIVE_CONTENT",
        "line_count": 98,
        "branch_count": 0,
        "inconclusive_line_count": 2,
        "exit_two_line_count": 0,
        "exit_zero_line_count": 0,
    }
    if new:
        value.update(sensitive_category="COOKIE", sensitive_line=8)
    return value


def _sensitive_stop(
    tmp_path: Path,
    *,
    new_diagnostic: bool = False,
    diagnostic_override: dict[str, object] | None = None,
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store, artifacts, previous, _ = _seed(tmp_path)
    identity = previous.identity
    candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    store.replace_from(
        candidate.model_copy(
            update={
                "status": StageStatus.PENDING,
                "attempt_id": None,
                "attempt_number": 0,
                "output_refs": (),
                "error_code": None,
                "retryable": False,
            }
        )
    )
    first = store.mark_running(
        identity,
        SimpleStage.POC_CANDIDATE_DONE,
        candidate.input_refs,
        attempt_id="sensitive-attempt-1",
    )
    diagnostic = diagnostic_override or _diagnostic(new=new_diagnostic)
    first_diag = artifacts.put_json(diagnostic)
    first_failed = store.mark_failure(
        first,
        StageFailure(
            code="POC_SENSITIVE_CONTENT",
            retryable=True,
            safe_message="PoC candidate is not self-contained",
            evidence_refs=(first_diag,),
        ),
        StageStatus.BLOCKED,
    )
    first_decision = RecoveryDecision(
        category=RecoveryCategory.GENERATED_INPUT,
        action=RecoveryAction.REGENERATE_INPUT,
        diagnosis="Rejected candidate input",
        guidance="Use a harmless local fixture",
    )
    first_ref = artifacts.put_json(
        {
            "kind": "simple_recovery_decision",
            "identity": identity.model_dump(mode="json"),
            "stage": first.stage.value,
            "attempt": 1,
            "attempt_id": first.attempt_id,
            "original_error": StageFailure(
                code="POC_SENSITIVE_CONTENT",
                retryable=True,
                safe_message="PoC candidate is not self-contained",
                evidence_refs=(first_diag,),
            ).model_dump(mode="json"),
            "decision": first_decision.model_dump(mode="json"),
            "decision_origin": "AGENT",
        }
    )
    store.record_recovery_decision(
        first_failed,
        RecoveryResolution(decision=first_decision, decision_ref=first_ref),
    )
    inputs = (*candidate.input_refs, first_diag, first_ref)
    store.save_checkpoint(
        first_failed.model_copy(
            update={
                "status": StageStatus.PENDING,
                "input_refs": inputs,
                "input_hash": input_reference_hash(inputs),
                "output_refs": (),
                "attempt_id": None,
                "error_code": None,
                "retryable": False,
            }
        )
    )
    second = store.mark_running(
        identity,
        SimpleStage.POC_CANDIDATE_DONE,
        inputs,
        attempt_id="sensitive-attempt-2",
    )
    second_diag = artifacts.put_json(diagnostic)
    second_failed = store.mark_failure(
        second,
        StageFailure(
            code="POC_SENSITIVE_CONTENT",
            retryable=True,
            safe_message="PoC candidate is not self-contained",
            evidence_refs=(second_diag,),
        ),
        StageStatus.BLOCKED,
    )
    second_decision = RecoveryDecision(
        category=RecoveryCategory.GENERATED_INPUT,
        action=RecoveryAction.STOP,
        diagnosis="Repeated content validation failure",
        guidance="No safe further automatic attempt",
    )
    second_ref = artifacts.put_json(
        {
            "kind": "simple_recovery_decision",
            "identity": identity.model_dump(mode="json"),
            "stage": second.stage.value,
            "attempt": 2,
            "attempt_id": second.attempt_id,
            "original_error": StageFailure(
                code="POC_SENSITIVE_CONTENT",
                retryable=True,
                safe_message="PoC candidate is not self-contained",
                evidence_refs=(second_diag,),
            ).model_dump(mode="json"),
            "decision": second_decision.model_dump(mode="json"),
            "decision_origin": "AGENT",
        }
    )
    stopped = store.record_recovery_stop(
        second_failed,
        RecoveryResolution(decision=second_decision, decision_ref=second_ref),
    )
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    old_root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    running_root = old_root.model_copy(
        update={
            "status": StageStatus.RUNNING,
            "attempt_id": "root-sensitive-attempt",
            "error_code": None,
            "retryable": False,
        }
    )
    store.save_checkpoint(running_root)
    store.mark_failure(
        running_root,
        StageFailure(
            code=(
                "CANDIDATE_CHILD_ERROR_BOUND:POC_SENSITIVE_CONTENT:"
                f"{identity.hypothesis_id}:{stopped.attempt_id}"
            ),
            retryable=False,
            safe_message="Candidate child analysis stopped",
        ),
        StageStatus.BLOCKED,
    )
    return store, artifacts, stopped


def test_replay_only_sensitive_stopped_candidate_preserves_completed_work(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped = _sensitive_stop(tmp_path)
    identity = stopped.identity
    prior = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
    before = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    pending = store.prepare_poc_sensitive_content_replay(stopped, artifacts)

    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 2
    assert pending.input_refs[: len(stopped.input_refs)] == stopped.input_refs
    assert pending.output_refs == ()
    assert pending.recipe_ref == stopped.recipe_ref
    assert pending.image_digest == stopped.image_digest
    assert store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE) == prior
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    after = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    assert len(after) == len(before) + 1
    replay = after[-1]
    assert replay.kind is ActivityKind.DECISION_RECORDED
    assert replay.error_code == "POC_SENSITIVE_CONTENT_REPLAYED"
    assert len(replay.output_refs) == 1
    marker = json.loads(artifacts.read(replay.output_refs[0]))
    assert marker["validator_revision"] == POC_CANDIDATE_VALIDATOR_REVISION
    assert marker["old_attempt_id"] == "sensitive-attempt-2"
    assert "content" not in marker
    assert "prompt" not in marker


def test_replay_accepts_bounded_current_sensitive_diagnostic(tmp_path: Path) -> None:
    store, artifacts, stopped = _sensitive_stop(tmp_path, new_diagnostic=True)

    pending = store.prepare_poc_sensitive_content_replay(stopped, artifacts)

    assert pending.status is StageStatus.PENDING
    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE


def test_replay_accepts_closed_optional_sensitive_rule_id(tmp_path: Path) -> None:
    diagnostic = _diagnostic(new=True) | {"sensitive_rule_id": "COOKIE_ASSIGNMENT"}
    store, artifacts, stopped = _sensitive_stop(
        tmp_path, diagnostic_override=diagnostic
    )

    pending = store.prepare_poc_sensitive_content_replay(stopped, artifacts)

    assert pending.status is StageStatus.PENDING
    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE


@pytest.mark.parametrize(
    "update",
    [
        {"sensitive_category": "UNRECOGNIZED"},
        {"sensitive_category": {"untrusted": "object"}},
        {"sensitive_line": -1},
        {"sensitive_line": 99},
        {"sensitive_line": True},
        {"sensitive_rule_id": "UNTRUSTED_RULE"},
        {"sensitive_rule_id": {"untrusted": "object"}},
        {"sensitive_rule_id": "CREDENTIAL_ASSIGNMENT"},
        {"sensitive_rule_id": "UNCLASSIFIED"},
        {"extra_field": "not allowed"},
    ],
)
def test_replay_refuses_unbounded_current_diagnostic(
    tmp_path: Path, update: dict[str, object]
) -> None:
    diagnostic = _diagnostic(new=True) | update
    store, artifacts, stopped = _sensitive_stop(
        tmp_path, diagnostic_override=diagnostic
    )

    with pytest.raises(ValueError, match="POC_SENSITIVE_CONTENT_REPLAY_EVENT_INVALID"):
        store.prepare_poc_sensitive_content_replay(stopped, artifacts)


def test_replay_refuses_second_use_and_unresolved_codex_child(tmp_path: Path) -> None:
    store, artifacts, stopped = _sensitive_stop(tmp_path)
    store.prepare_poc_sensitive_content_replay(stopped, artifacts)
    with pytest.raises(ValueError, match="POC_SENSITIVE_CONTENT_REPLAY_"):
        store.prepare_poc_sensitive_content_replay(stopped, artifacts)

    other_store, other_artifacts, other_stop = _sensitive_stop(tmp_path / "other")
    assert other_store.begin_codex_call(
        "unresolved-call", other_stop.identity.analysis_id
    )
    with pytest.raises(
        ValueError, match="POC_SENSITIVE_CONTENT_REPLAY_CODEX_UNRESOLVED"
    ):
        other_store.prepare_poc_sensitive_content_replay(other_stop, other_artifacts)
    assert other_store.require(other_stop.identity, other_stop.stage) == other_stop


def test_replay_refuses_new_diagnostic_or_unbound_root(tmp_path: Path) -> None:
    store, artifacts, stopped = _sensitive_stop(tmp_path)
    new_ref = artifacts.put_json(_diagnostic(new=True))
    tampered = stopped.model_copy(update={"output_refs": (new_ref,)})
    with pytest.raises(ValueError, match="POC_SENSITIVE_CONTENT_REPLAY_"):
        store.prepare_poc_sensitive_content_replay(tampered, artifacts)

    root_id = stopped.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_id, SimpleStage.HYPOTHESIS_DONE)
    store.save_checkpoint(root.model_copy(update={"error_code": "OTHER_FAILURE"}))
    with pytest.raises(
        ValueError, match="POC_SENSITIVE_CONTENT_REPLAY_ROOT_BOUND_INVALID"
    ):
        store.prepare_poc_sensitive_content_replay(stopped, artifacts)


def test_replay_refuses_disconnected_first_attempt_evidence(tmp_path: Path) -> None:
    store, artifacts, stopped = _sensitive_stop(tmp_path)
    disconnected_inputs = stopped.input_refs[:1]
    disconnected = stopped.model_copy(
        update={
            "input_refs": disconnected_inputs,
            "input_hash": input_reference_hash(disconnected_inputs),
        }
    )
    store.save_checkpoint(disconnected)

    with pytest.raises(ValueError, match="POC_SENSITIVE_CONTENT_REPLAY_EVENT_INVALID"):
        store.prepare_poc_sensitive_content_replay(disconnected, artifacts)


def test_replay_rolls_back_checkpoint_and_event_together(tmp_path: Path) -> None:
    store, artifacts, stopped = _sensitive_stop(tmp_path)
    before = AgentActivityStore(store.database_path).list_analysis(
        stopped.identity.analysis_id, hypothesis_id=stopped.identity.hypothesis_id
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_poc_sensitive_content_replay(
            stopped, artifacts, fail_before_commit=True
        )
    assert store.require(stopped.identity, stopped.stage) == stopped
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            stopped.identity.analysis_id, hypothesis_id=stopped.identity.hypothesis_id
        )
        == before
    )


@pytest.mark.asyncio
async def test_application_requires_explicit_sensitive_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, stopped = _sensitive_stop(tmp_path)
    identity = stopped.identity
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
    assert store.require(identity, stopped.stage) == stopped
    await application.resume(
        identity.analysis_id,
        repair_poc_sensitive_content_hypothesis=identity.hypothesis_id,
    )
    assert store.require(identity, stopped.stage).status is StageStatus.PENDING


def test_cli_forwards_explicit_sensitive_replay_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class _Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_sensitive_content_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("plain", repair_poc_sensitive_content_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_poc_sensitive_content_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("progress", repair_poc_sensitive_content_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = _Application()
    for extra, label in [(["--format", "json"], "plain"), ([], "progress")]:
        assert main(
            [
                "resume",
                "A-001",
                "--repair-poc-sensitive-content",
                "hypothesis-1",
                *extra,
            ],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (label, "hypothesis-1")
        capsys.readouterr()
