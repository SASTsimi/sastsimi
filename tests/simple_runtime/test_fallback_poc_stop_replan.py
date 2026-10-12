"""An explicit repair may supersede only an evidence-bound non-import fallback STOP."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.interfaces.cli.main import main
from sastsimi.observability.agent_activity import ActivityKind
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
)
from sastsimi.simple_runtime.models import (
    SimpleStage,
    StageFailure,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.recovery import RecoveryDecision, RecoveryResolution
from sastsimi.simple_runtime.stages import PoCCandidateStage
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_legacy_import_stop_replan import (
    _checkpoint,
    _PinnedStaticStub,
    _seed,
)
from tests.unit.interfaces.test_public_simple_cli import _config, _PublicApplication


def test_policy_fallback_stop_reseeds_only_poc_candidate(tmp_path: Path) -> None:
    store, artifacts, stopped, stop_ref = _seed(
        tmp_path,
        stderr=b"TypeError: cookie_bytes_incompatible\nTraceback: __call__ > handler",
    )
    identity = stopped.identity
    original_initial = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
    original_pro_con = store.require(identity, SimpleStage.PRO_CON_DONE)
    original_candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    before_events = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    pending = store.prepare_fallback_poc_stop_replan(stopped, artifacts)

    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == stopped.attempt_number
    assert pending.recipe_ref == stopped.recipe_ref
    assert pending.image_digest == stopped.image_digest
    assert store.require(identity, SimpleStage.PRO_CON_DONE) == original_pro_con
    assert (
        store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
        == original_initial
    )
    assert store.require(identity, SimpleStage.POC_CANDIDATE_DONE) == pending
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    assert original_candidate.output_refs[0] in pending.input_refs
    assert all(ref in pending.input_refs for ref in stopped.output_refs)
    assert stop_ref in pending.input_refs
    decision_ref = pending.recovery_decision_refs[-1]
    decision = json.loads(artifacts.read(decision_ref))
    assert decision["decision_origin"] == "RULE"
    assert decision["decision"]["category"] == "GENERATED_INPUT"
    assert decision["decision"]["action"] == "REGENERATE_INPUT"
    assert decision["decision"]["environment_patch"] == ""
    assert decision["original_error"]["code"] == "POC_EXECUTION_FAILED"
    assert decision["supersedes_stop_ref"] == stop_ref.model_dump(mode="json")
    assert decision["diagnostic_excerpt"] == (
        "TypeError: cookie_bytes_incompatible\nTraceback: __call__ > handler"
    )
    after_events = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    assert len(after_events) == len(before_events) + 1
    assert any(
        event.kind is ActivityKind.DECISION_RECORDED
        and event.output_refs == (stop_ref,)
        for event in after_events
    )
    assert any(
        event.kind is ActivityKind.DECISION_RECORDED
        and event.output_refs == (decision_ref,)
        for event in after_events
    )
    with pytest.raises(ValueError, match="FALLBACK_POC_STOP_STALE"):
        store.prepare_fallback_poc_stop_replan(stopped, artifacts)
    next_attempt = store.mark_running(
        identity,
        SimpleStage.POC_CANDIDATE_DONE,
        pending.input_refs,
        attempt_id="attempt-2",
    )
    assert next_attempt.attempt_number == 2


def test_repaired_candidate_receives_gate_feedback_first_and_latest_execution(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, old_stop_ref = _seed(
        tmp_path, stderr=b"TypeError: framework_mismatch\nTraceback: handler"
    )
    identity = stopped.identity
    candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    gate_ref = artifacts.put_json({"kind": "simple_technical_gate", "status": "REVISE"})
    older_candidate_ref = artifacts.put_json(
        {"kind": "simple_poc_candidate", "attempt_id": "attempt-old"}
    )
    older_execution_ref = artifacts.put_json(
        {
            "kind": "simple_poc_execution",
            "attempt_id": "attempt-old",
            "candidate_ref": older_candidate_ref.model_dump(mode="json"),
        }
    )
    content_ref = candidate.output_refs[1]
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "attempt_id": stopped.attempt_id,
            "content_ref": content_ref.model_dump(mode="json"),
            "content_digest": hashlib.sha256(artifacts.read(content_ref)).hexdigest(),
            "gate_revision_count": 1,
        }
    )
    candidate_inputs = (
        gate_ref,
        older_candidate_ref,
        older_execution_ref,
        *candidate.input_refs,
    )
    store.save_checkpoint(
        candidate.model_copy(
            update={
                "input_refs": candidate_inputs,
                "input_hash": input_reference_hash(candidate_inputs),
                "output_refs": (candidate_ref, content_ref),
                "gate_revision_count": 1,
            }
        )
    )
    receipt = json.loads(artifacts.read(stopped.output_refs[0]))
    receipt["candidate_ref"] = candidate_ref.model_dump(mode="json")
    execution_ref = artifacts.put_json(receipt)
    evidence = (execution_ref, *stopped.output_refs[1:])
    stopped_inputs = (candidate_ref, content_ref)
    stopped = stopped.model_copy(
        update={
            "input_refs": stopped_inputs,
            "input_hash": input_reference_hash(stopped_inputs),
            "output_refs": evidence,
            "gate_revision_count": 1,
            "retryable": True,
        }
    )
    store.save_checkpoint(stopped)
    old_stop = json.loads(artifacts.read(old_stop_ref))
    old_stop["original_error"] = StageFailure(
        code="POC_EXECUTION_FAILED",
        retryable=True,
        safe_message="PoC runtime failure",
        evidence_refs=evidence,
    ).model_dump(mode="json")
    stop_ref = artifacts.put_json(old_stop)
    stopped = store.record_recovery_stop(
        stopped,
        RecoveryResolution(
            decision=RecoveryDecision.model_validate_json(
                json.dumps(old_stop["decision"])
            ),
            decision_ref=stop_ref,
        ),
    )

    pending = store.prepare_fallback_poc_stop_replan(stopped, artifacts)

    assert pending.gate_revision_count == 1
    assert pending.input_refs[0] == gate_ref
    repair_stage = PoCCandidateStage(client=None, artifacts=artifacts)  # type: ignore[arg-type]
    assert repair_stage._current_repair_refs(pending.input_refs) == (
        candidate_ref,
        execution_ref,
    )


@pytest.mark.parametrize("field", ["content_ref", "image_digest"])
def test_fallback_poc_repair_rejects_execution_receipt_not_bound_to_candidate(
    tmp_path: Path, field: str
) -> None:
    store, artifacts, stopped, old_stop_ref = _seed(
        tmp_path, stderr=b"TypeError: runtime\nTraceback: handler"
    )
    receipt = json.loads(artifacts.read(stopped.output_refs[0]))
    if field == "content_ref":
        receipt[field] = artifacts.put_bytes(
            b"#!/bin/sh\nexit 0\n", "text/x-shellscript"
        ).model_dump(mode="json")
    else:
        receipt[field] = "sha256:" + "f" * 64
    wrong_ref = artifacts.put_json(receipt)
    evidence = (wrong_ref, *stopped.output_refs[1:])
    stopped = stopped.model_copy(update={"output_refs": evidence, "retryable": True})
    store.save_checkpoint(stopped)
    old_stop = json.loads(artifacts.read(old_stop_ref))
    old_stop["original_error"] = StageFailure(
        code="POC_EXECUTION_FAILED",
        retryable=True,
        safe_message="PoC runtime failure",
        evidence_refs=evidence,
    ).model_dump(mode="json")
    stop_ref = artifacts.put_json(old_stop)
    stopped = store.record_recovery_stop(
        stopped,
        RecoveryResolution(
            decision=RecoveryDecision.model_validate_json(
                json.dumps(old_stop["decision"])
            ),
            decision_ref=stop_ref,
        ),
    )

    with pytest.raises(ValueError, match="FALLBACK_POC_STOP_EVIDENCE_INVALID"):
        store.prepare_fallback_poc_stop_replan(stopped, artifacts)
    assert store.require(stopped.identity, stopped.stage) == stopped


@pytest.mark.parametrize(
    ("stderr", "stdout"),
    [
        (b"ModuleNotFoundError: jwt\nTraceback: frame -> exec_module", b""),
        (b"python: No module named jwt\n", b""),
        (
            b"TypeError: failed",
            b"ModuleNotFoundError: jwt\nTraceback: frame -> exec_module",
        ),
        (b"", b""),
    ],
)
def test_policy_fallback_stop_rejects_import_or_empty_diagnostic(
    tmp_path: Path, stderr: bytes, stdout: bytes
) -> None:
    store, artifacts, stopped, _ = _seed(tmp_path, stderr=stderr, stdout=stdout)

    with pytest.raises(ValueError, match="FALLBACK_POC_STOP_DIAGNOSTIC_INVALID"):
        store.prepare_fallback_poc_stop_replan(stopped, artifacts)

    assert store.require(stopped.identity, stopped.stage) == stopped


@pytest.mark.parametrize(
    ("change", "expected_code"),
    [
        ("agent_stop", "FALLBACK_POC_STOP_FALLBACK_UNVERIFIED"),
        ("unclean", "FALLBACK_POC_STOP_EVIDENCE_INVALID"),
        ("wrong_exit", "FALLBACK_POC_STOP_EVIDENCE_INVALID"),
        ("attempt_exhausted", "FALLBACK_POC_STOP_INVALID"),
        ("recipe_changed", "FALLBACK_POC_STOP_LINEAGE_INVALID"),
        ("candidate_changed", "FALLBACK_POC_STOP_EVIDENCE_INVALID"),
    ],
)
def test_policy_fallback_stop_fails_closed_on_unbound_evidence(
    tmp_path: Path, change: str, expected_code: str
) -> None:
    store, artifacts, stopped, _ = _seed(
        tmp_path,
        stderr=b"TypeError: runtime\nTraceback: handler",
        decision_origin="AGENT" if change == "agent_stop" else "FALLBACK",
        cleanup_status="UNKNOWN" if change == "unclean" else "REMOVED",
        exit_code=1 if change == "wrong_exit" else 2,
    )
    if change == "attempt_exhausted":
        stopped = stopped.model_copy(update={"attempt_number": 3})
        store.save_checkpoint(stopped)
    elif change == "recipe_changed":
        candidate = store.require(stopped.identity, SimpleStage.POC_CANDIDATE_DONE)
        store.save_checkpoint(
            candidate.model_copy(update={"recipe_ref": artifacts.put_json({"x": 2})})
        )
    elif change == "candidate_changed":
        execution, stdout, stderr, cleanup = stopped.output_refs
        receipt = json.loads(artifacts.read(execution))
        receipt["candidate_ref"] = artifacts.put_json({"other": True}).model_dump(
            mode="json"
        )
        wrong_execution = artifacts.put_json(receipt)
        stopped = stopped.model_copy(
            update={"output_refs": (wrong_execution, stdout, stderr, cleanup)}
        )
        store.save_checkpoint(stopped)

    with pytest.raises(ValueError, match=expected_code):
        store.prepare_fallback_poc_stop_replan(stopped, artifacts)
    assert store.require(stopped.identity, stopped.stage) == stopped


def test_policy_fallback_stop_atomic_rollback_preserves_prior_stop(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, stop_ref = _seed(
        tmp_path, stderr=b"TypeError: runtime\nTraceback: handler"
    )
    before_events = AgentActivityStore(store.database_path).list_analysis(
        stopped.identity.analysis_id, hypothesis_id=stopped.identity.hypothesis_id
    )

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_fallback_poc_stop_replan(
            stopped, artifacts, fail_before_commit=True
        )

    assert store.require(stopped.identity, stopped.stage) == stopped
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            stopped.identity.analysis_id,
            hypothesis_id=stopped.identity.hypothesis_id,
        )
        == before_events
    )
    assert json.loads(artifacts.read(stop_ref))["decision"]["action"] == "STOP"


@pytest.mark.parametrize(
    ("tamper", "error_code"),
    [
        ("codex_in_flight", "FALLBACK_POC_STOP_CODEX_UNRESOLVED"),
        ("downstream", "FALLBACK_POC_STOP_LINEAGE_INVALID"),
        ("wrong_root", "FALLBACK_POC_STOP_ROOT_BOUND_INVALID"),
    ],
)
def test_policy_fallback_stop_refuses_unresolved_or_changed_lineage(
    tmp_path: Path, tamper: str, error_code: str
) -> None:
    store, artifacts, stopped, _ = _seed(
        tmp_path, stderr=b"TypeError: runtime\nTraceback: handler"
    )
    identity = stopped.identity
    if tamper == "codex_in_flight":
        assert store.begin_codex_call("call-1", identity.analysis_id)
    elif tamper == "downstream":
        store.save_checkpoint(
            _checkpoint(
                identity,
                SimpleStage.VERIFICATION_FINAL_DONE,
                status=StageStatus.SUCCEEDED,
            )
        )
    else:
        root = identity.model_copy(update={"hypothesis_id": None})
        prior = store.require(root, SimpleStage.HYPOTHESIS_DONE)
        store.save_checkpoint(
            prior.model_copy(update={"error_code": "CANDIDATE_CHILD_ERROR_BOUND:other"})
        )

    with pytest.raises(ValueError, match=error_code):
        store.prepare_fallback_poc_stop_replan(stopped, artifacts)
    assert store.require(identity, stopped.stage) == stopped


@pytest.mark.asyncio
async def test_application_requires_explicit_repair_and_pinned_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, stopped, _ = _seed(
        tmp_path, stderr=b"TypeError: runtime\nTraceback: handler"
    )
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
        repair_fallback_poc_stop_hypothesis=identity.hypothesis_id,
    )
    assert store.require(identity, SimpleStage.POC_CANDIDATE_DONE).status is (
        StageStatus.PENDING
    )
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None


@pytest.mark.asyncio
async def test_application_rejects_moved_checkout_before_poc_repair(
    tmp_path: Path,
) -> None:
    store, _artifacts, stopped, _ = _seed(
        tmp_path, stderr=b"TypeError: runtime\nTraceback: handler"
    )
    identity = stopped.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    run = store.require_analysis_run(identity.analysis_id)
    store.save_analysis_run(
        run.model_copy(update={"workspace_path": tmp_path / "data" / "other"})
    )
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=_PinnedStaticStub(tmp_path / "data" / "workspaces"),
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )

    with pytest.raises(ValueError, match="FALLBACK_POC_STOP_WORKSPACE_INVALID"):
        await application.resume(
            identity.analysis_id,
            repair_fallback_poc_stop_hypothesis=identity.hypothesis_id,
        )
    assert store.require(identity, stopped.stage) == stopped


def test_public_cli_forwards_explicit_fallback_poc_repair_and_reports_refusal(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class _Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_exhausted_hypothesis: str | None = None,
            repair_legacy_import_stop_hypothesis: str | None = None,
            repair_fallback_poc_stop_hypothesis: str | None = None,
            repair_docker_owned_list_exhaustion_hypothesis: str | None = None,
            repair_poc_placeholder_exhaustion_hypothesis: str | None = None,
            repair_poc_sensitive_content_hypothesis: str | None = None,
            repair_report_validator_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            del (
                repair_exhausted_hypothesis,
                repair_legacy_import_stop_hypothesis,
                repair_docker_owned_list_exhaustion_hypothesis,
                repair_poc_placeholder_exhaustion_hypothesis,
                repair_poc_sensitive_content_hypothesis,
                repair_report_validator_hypothesis,
            )
            self.seen.append(
                ("plain", analysis_id, repair_fallback_poc_stop_hypothesis)
            )
            if repair_fallback_poc_stop_hypothesis == "wrong":
                raise ValueError("FALLBACK_POC_STOP_FALLBACK_UNVERIFIED")
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_exhausted_hypothesis: str | None = None,
            repair_legacy_import_stop_hypothesis: str | None = None,
            repair_fallback_poc_stop_hypothesis: str | None = None,
            repair_docker_owned_list_exhaustion_hypothesis: str | None = None,
        ) -> dict[str, object]:
            del (
                repair_exhausted_hypothesis,
                repair_legacy_import_stop_hypothesis,
                repair_docker_owned_list_exhaustion_hypothesis,
            )
            self.seen.append(
                ("progress", analysis_id, repair_fallback_poc_stop_hypothesis)
            )
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = _Application()
    config = _config(tmp_path)
    arguments = ["resume", "A-001", "--repair-fallback-poc-stop", "hypothesis-1"]

    assert main(
        [*arguments, "--format", "json"],
        public_application=application,
        user_config_store=config,
    ) == int(ExitCode.OK)
    assert json.loads(capsys.readouterr().out)["data"]["status"] == "RUNNING"
    assert main(
        arguments, public_application=application, user_config_store=config
    ) == int(ExitCode.OK)
    capsys.readouterr()
    assert application.seen == [
        ("plain", "A-001", "hypothesis-1"),
        ("progress", "A-001", "hypothesis-1"),
    ]
    assert main(
        ["resume", "A-001", "--repair-fallback-poc-stop", "wrong", "--format", "json"],
        public_application=application,
        user_config_store=config,
    ) == int(ExitCode.INTEGRITY_ERROR)
    assert "FALLBACK_POC_STOP_FALLBACK_UNVERIFIED" in capsys.readouterr().err
