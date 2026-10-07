"""A legacy fallback STOP may be superseded only with exact import evidence."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.observability.agent_activity import ActivityKind
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
    SimpleAnalysisRequest,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CandidateTerminal,
    CheckpointIdentity,
    SimpleAnalysisRun,
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
from sastsimi.simple_runtime.run_lease import analysis_run_lease
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore


class _PinnedStaticStub:
    """Exercise the application's checkout binding without running a scan."""

    def __init__(self, workspace_root: Path) -> None:
        self._profile = SimpleNamespace(workspace_root=workspace_root)

    async def run(
        self, _request: SimpleAnalysisRequest, _identity: CheckpointIdentity
    ) -> StaticBootstrapResult:
        raise AssertionError("Static scanning must not rerun during legacy repair")

    async def coverage_fingerprint(
        self, _request: SimpleAnalysisRequest, _identity: CheckpointIdentity
    ) -> str:
        return "fingerprint-1"

    async def _verify_opengrep_workspace(
        self, workspace: Path, request: SimpleAnalysisRequest
    ) -> None:
        marker = json.loads(
            (workspace / ".sastsimi-ready.json").read_text(encoding="utf-8")
        )
        if marker != {"repository": request.repository, "commit": request.commit}:
            raise RuntimeError("WORKSPACE_IDENTITY_CONFLICT")


def _checkpoint(
    identity: CheckpointIdentity,
    stage: SimpleStage,
    *,
    status: StageStatus,
    inputs: tuple[StoredDataRef, ...] = (),
    outputs: tuple[StoredDataRef, ...] = (),
    attempt_id: str | None = None,
    attempt_number: int = 0,
    recipe_ref: StoredDataRef | None = None,
    image_digest: str | None = None,
    container_id: str | None = None,
    error_code: str | None = None,
    retryable: bool = False,
) -> StageCheckpoint:
    return StageCheckpoint(
        identity=identity,
        stage=stage,
        stage_version=STAGE_VERSION[stage],
        status=status,
        input_refs=inputs,
        input_hash=input_reference_hash(inputs),
        output_refs=outputs,
        attempt_id=attempt_id,
        attempt_number=attempt_number,
        recipe_ref=recipe_ref,
        image_digest=image_digest,
        container_id=container_id,
        error_code=error_code,
        retryable=retryable,
    )


def _seed(
    tmp_path: Path,
    *,
    decision_origin: str = "FALLBACK",
    stopped_code: str = "POC_EXECUTION_FAILED",
    stderr: bytes = b"ModuleNotFoundError: jwt\nTraceback: frame -> exec_module",
    stdout: bytes = b"",
    cleanup_status: str = "REMOVED",
    exit_code: int = 2,
) -> tuple[
    SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint, StoredDataRef
]:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id="A-001",
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="example/vulnerable",
            hypothesis_ids=(identity.hypothesis_id or "",),
            candidate_pipeline_version=2,
        )
    )
    artifacts = SimpleArtifactRepository(data_dir, identity)
    workspace = data_dir / "workspaces" / identity.workspace_id
    workspace.mkdir(parents=True)
    (workspace / ".sastsimi-ready.json").write_text(
        json.dumps({"repository": "example/vulnerable", "commit": identity.commit_id}),
        encoding="utf-8",
    )
    profile_ref = artifacts.put_json({"kind": "simple_repository_profile"})
    coverage_ref = artifacts.put_json(
        {
            "kind": "simple_static_coverage_v1",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "fingerprint": "fingerprint-1",
            "expected_count": 1,
            "verified_count": 1,
            "gaps": [],
            "unsupported": [],
        }
    )
    static_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "static_coverage_ref": coverage_ref.model_dump(mode="json"),
        }
    )
    store.save_analysis_run(
        store.require_analysis_run(identity.analysis_id).model_copy(
            update={
                "workspace_path": workspace,
                "repository_profile_ref": profile_ref,
                "static_bundle_ref": static_ref,
                "static_coverage_ref": coverage_ref,
                "candidate_scope_fingerprint": "fingerprint-1",
            }
        )
    )
    store.save_checkpoint(
        _checkpoint(
            identity.model_copy(update={"hypothesis_id": None}),
            SimpleStage.STATIC_DONE,
            status=StageStatus.SUCCEEDED,
            outputs=(profile_ref, static_ref),
        )
    )
    root = identity.model_copy(update={"hypothesis_id": None})
    proposal_ref = artifacts.put_prompt_proposal(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": identity.analysis_id,
            "hypothesis_id": identity.hypothesis_id,
            "proposal": {"title": "legacy import replan"},
        }
    )
    store.upsert_hypothesis(root, identity.hypothesis_id or "", proposal_ref)
    pro_con_ref = artifacts.put_json({"kind": "pro_con"})
    initial_ref = artifacts.put_json({"kind": "initial"})
    recipe_ref = artifacts.put_json({"kind": "simple_environment_recipe"})
    attempt_id = "attempt-1"
    image_digest = "sha256:" + "1" * 64
    poc_content = b"#!/bin/sh\nexit 2\n"
    content_ref = artifacts.put_bytes(poc_content, "text/x-shellscript")
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "content_ref": content_ref.model_dump(mode="json"),
            "content_digest": hashlib.sha256(poc_content).hexdigest(),
            "attempt_id": attempt_id,
        }
    )
    stdout_ref = artifacts.put_bytes(stdout, "text/plain")
    stderr_ref = artifacts.put_bytes(stderr, "text/plain")
    container_id = "container-1"
    execution_ref = artifacts.put_json(
        {
            "kind": "simple_poc_execution",
            "attempt_id": attempt_id,
            "candidate_ref": candidate_ref.model_dump(mode="json"),
            "content_ref": content_ref.model_dump(mode="json"),
            "stdout_ref": stdout_ref.model_dump(mode="json"),
            "stderr_ref": stderr_ref.model_dump(mode="json"),
            "exit_code": exit_code,
            "timed_out": False,
            "container_id": container_id,
            "image_digest": image_digest,
        }
    )
    cleanup_ref = artifacts.put_json(
        {
            "kind": "simple_container_cleanup",
            "attempt_id": attempt_id,
            "container_id": container_id,
            "status": cleanup_status,
        }
    )
    pro_con = _checkpoint(
        identity,
        SimpleStage.PRO_CON_DONE,
        status=StageStatus.SUCCEEDED,
        inputs=(proposal_ref, static_ref),
        outputs=(pro_con_ref,),
    )
    initial = _checkpoint(
        identity,
        SimpleStage.VERIFICATION_INITIAL_DONE,
        status=StageStatus.SUCCEEDED,
        inputs=(pro_con_ref,),
        outputs=(initial_ref,),
        recipe_ref=recipe_ref,
        image_digest=image_digest,
    )
    candidate = _checkpoint(
        identity,
        SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.SUCCEEDED,
        inputs=(initial_ref,),
        outputs=(candidate_ref, content_ref),
        attempt_id=attempt_id,
        attempt_number=1,
        recipe_ref=recipe_ref,
        image_digest=image_digest,
    )
    failed = _checkpoint(
        identity,
        SimpleStage.POC_EXECUTION_DONE,
        status=StageStatus.BLOCKED,
        inputs=(candidate_ref, content_ref),
        outputs=(execution_ref, stdout_ref, stderr_ref, cleanup_ref),
        attempt_id=attempt_id,
        attempt_number=1,
        recipe_ref=recipe_ref,
        image_digest=image_digest,
        error_code=stopped_code,
        retryable=True,
    )
    for checkpoint in (pro_con, initial, candidate, failed):
        store.save_checkpoint(checkpoint)
    stop_decision = RecoveryDecision(
        category=RecoveryCategory.TERMINAL,
        action=RecoveryAction.STOP,
        diagnosis=(
            "Python import failure lacks isolated terminal evidence"
            if stopped_code == "POC_RUNTIME_IMPORT_FAILED"
            else "recovery output failed policy validation"
        ),
        guidance=(
            "Review both exact PoC output streams; automatic dependency "
            "selection and Dockerfile patching are not justified"
            if stopped_code == "POC_RUNTIME_IMPORT_FAILED"
            else "preserve the failure for manual review"
        ),
    )
    decision_ref = artifacts.put_json(
        {
            "kind": "simple_recovery_decision",
            "identity": identity.model_dump(mode="json"),
            "stage": failed.stage.value,
            "attempt": failed.attempt_number,
            "attempt_id": failed.attempt_id,
            "original_error": StageFailure(
                code=stopped_code,
                retryable=True,
                safe_message="PoC script did not produce a usable observation",
                evidence_refs=failed.output_refs,
            ).model_dump(mode="json"),
            "decision": stop_decision.model_dump(mode="json"),
            "decision_origin": decision_origin,
        }
    )
    stopped = store.record_recovery_stop(
        failed, RecoveryResolution(decision=stop_decision, decision_ref=decision_ref)
    )
    root_running = store.mark_running(
        root, SimpleStage.HYPOTHESIS_DONE, (), attempt_id="root-attempt"
    )
    store.mark_failure(
        root_running,
        StageFailure(
            code=(
                f"CANDIDATE_CHILD_ERROR_BOUND:{stopped_code}:"
                f"{identity.hypothesis_id}:{attempt_id}"
            ),
            retryable=False,
            safe_message="Candidate child analysis did not complete",
        ),
        StageStatus.BLOCKED,
    )
    return store, artifacts, stopped, decision_ref


def test_legacy_import_fallback_stop_replans_only_exact_child(tmp_path: Path) -> None:
    store, artifacts, stopped, stop_ref = _seed(tmp_path)
    identity = stopped.identity
    prior = store.require(identity, SimpleStage.PRO_CON_DONE)
    before_events = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    pending = store.prepare_legacy_import_stop_replan(stopped, artifacts)

    assert store.require(identity, SimpleStage.PRO_CON_DONE) == prior
    assert store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE) == pending
    assert store.get(identity, SimpleStage.POC_CANDIDATE_DONE) is None
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 1
    assert pending.recipe_ref is None
    assert pending.image_digest is None
    assert stop_ref in pending.input_refs
    assert stopped.output_refs[0] in pending.input_refs
    rule_ref = pending.recovery_decision_refs[-1]
    rule = json.loads(artifacts.read(rule_ref))
    assert rule["decision_origin"] == "RULE"
    assert rule["decision"]["action"] == "REPLAN_ENVIRONMENT"
    assert rule["supersedes_stop_ref"] == stop_ref.model_dump(mode="json")
    assert rule["original_error"]["code"] == "POC_RUNTIME_IMPORT_FAILED"
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
        and event.output_refs == (rule_ref,)
        for event in after_events
    )
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_STALE"):
        store.prepare_legacy_import_stop_replan(stopped, artifacts)


def test_rule_import_stop_with_sanitized_frames_replans_exact_child(
    tmp_path: Path,
) -> None:
    stderr = (
        b"ModuleNotFoundError: jwt\nTraceback (most recent call last):\n"
        b"  frame:line 96\n  import_module:line 90\n"
        b"  exec_module:line 999\n  frame:line 4\n"
    )
    store, artifacts, stopped, stop_ref = _seed(
        tmp_path,
        decision_origin="RULE",
        stopped_code="POC_RUNTIME_IMPORT_FAILED",
        stderr=stderr,
    )

    pending = store.prepare_legacy_import_stop_replan(stopped, artifacts)

    assert pending.stage is SimpleStage.VERIFICATION_INITIAL_DONE
    assert pending.status is StageStatus.PENDING
    assert store.get(stopped.identity, SimpleStage.POC_EXECUTION_DONE) is None
    rule = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert rule["decision"]["action"] == "REPLAN_ENVIRONMENT"
    assert rule["supersedes_stop_ref"] == stop_ref.model_dump(mode="json")
    assert rule["original_error"]["code"] == "POC_RUNTIME_IMPORT_FAILED"
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_STALE"):
        store.prepare_legacy_import_stop_replan(stopped, artifacts)


@pytest.mark.parametrize(
    ("decision_origin", "stderr"),
    [
        (
            "FALLBACK",
            b"ModuleNotFoundError: jwt\nTraceback (most recent call last):\n"
            b"  exec_module:line 999\n",
        ),
        (
            "RULE",
            b"ModuleNotFoundError: jwt\nTraceback (most recent call last):\n"
            b"  exec_module:line 999\nextra output after traceback\n",
        ),
    ],
)
def test_rule_import_stop_rejects_wrong_origin_or_nonterminal_output(
    tmp_path: Path, decision_origin: str, stderr: bytes
) -> None:
    store, artifacts, stopped, _ = _seed(
        tmp_path,
        decision_origin=decision_origin,
        stopped_code="POC_RUNTIME_IMPORT_FAILED",
        stderr=stderr,
    )

    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_"):
        store.prepare_legacy_import_stop_replan(stopped, artifacts)
    assert store.require(stopped.identity, stopped.stage) == stopped


def test_legacy_import_stop_replans_standard_sanitized_function_trace(
    tmp_path: Path,
) -> None:
    stderr = (
        b"ModuleNotFoundError: jwt\n"
        b"Traceback (most recent call last):\n"
        b"  in unresolved_frame\n"
        b"  in reproduce\n"
        b"  in unresolved_frame\n"
    )
    store, artifacts, stopped, stop_ref = _seed(tmp_path, stderr=stderr)

    pending = store.prepare_legacy_import_stop_replan(stopped, artifacts)

    assert pending.status is StageStatus.PENDING
    rule = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert rule["decision"]["action"] == "REPLAN_ENVIRONMENT"
    assert rule["original_error"]["code"] == "POC_RUNTIME_IMPORT_FAILED"
    assert json.loads(artifacts.read(stop_ref))["decision"]["action"] == "STOP"
    assert store.get(stopped.identity, stopped.stage) is None


@pytest.mark.parametrize(
    "trailing",
    (b"AssertionError: later fatal failure\n", b"later output\n" * 3_000),
    ids=("later_exception", "long_noise"),
)
def test_legacy_standard_sanitized_import_trace_with_later_output_stays_stopped(
    tmp_path: Path,
    trailing: bytes,
) -> None:
    stderr = (
        b"ModuleNotFoundError: jwt\n"
        b"Traceback (most recent call last):\n"
        b"  in unresolved_frame\n"
        b"  in reproduce\n"
        b"  in unresolved_frame\n" + trailing
    )
    store, artifacts, stopped, _ = _seed(tmp_path, stderr=stderr)

    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_IMPORT_UNVERIFIED"):
        store.prepare_legacy_import_stop_replan(stopped, artifacts)
    assert store.require(stopped.identity, stopped.stage) == stopped


@pytest.mark.parametrize(
    "tamper",
    [
        "agent_stop",
        "not_import",
        "nonterminal",
        "second_import",
        "other_stdout",
        "cleanup",
        "exit",
    ],
)
def test_legacy_import_fallback_stop_fails_closed(tmp_path: Path, tamper: str) -> None:
    store, artifacts, stopped, _ = _seed(
        tmp_path,
        decision_origin="AGENT" if tamper == "agent_stop" else "FALLBACK",
        stderr=b"ValueError: invalid\nTraceback: frame -> execute"
        if tamper == "not_import"
        else (
            b"ModuleNotFoundError: jwt\nTraceback: frame -> exec_module"
            b"\nValueError: after"
        )
        if tamper == "nonterminal"
        else b"ModuleNotFoundError: jwt\nTraceback: frame -> exec_module",
        stdout=(
            b"ModuleNotFoundError: requests\nTraceback: frame -> exec_module"
            if tamper == "second_import"
            else b"fatal: unrelated execution failure"
            if tamper == "other_stdout"
            else b""
        ),
        cleanup_status="BLOCKED" if tamper == "cleanup" else "REMOVED",
        exit_code=1 if tamper == "exit" else 2,
    )
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_"):
        store.prepare_legacy_import_stop_replan(stopped, artifacts)
    assert store.require(stopped.identity, stopped.stage) == stopped


def test_legacy_import_fallback_stop_requires_no_live_codex_call(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, _ = _seed(tmp_path)
    assert store.begin_codex_call("call-1", stopped.identity.analysis_id)
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_CODEX_UNRESOLVED"):
        store.prepare_legacy_import_stop_replan(stopped, artifacts)
    assert store.require(stopped.identity, stopped.stage) == stopped


def test_legacy_import_stop_atomic_rollback_preserves_old_stop(tmp_path: Path) -> None:
    store, artifacts, stopped, _ = _seed(tmp_path)
    before = AgentActivityStore(store.database_path).list_analysis(
        stopped.identity.analysis_id
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_legacy_import_stop_replan(
            stopped, artifacts, fail_before_commit=True
        )
    assert store.require(stopped.identity, stopped.stage) == stopped
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            stopped.identity.analysis_id
        )
        == before
    )


def test_legacy_import_stop_rejects_downstream_success(tmp_path: Path) -> None:
    store, artifacts, stopped, _ = _seed(tmp_path)
    final = _checkpoint(
        stopped.identity,
        SimpleStage.VERIFICATION_FINAL_DONE,
        status=StageStatus.SUCCEEDED,
    )
    store.save_checkpoint(final)
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_LINEAGE_INVALID"):
        store.prepare_legacy_import_stop_replan(stopped, artifacts)
    assert store.require(stopped.identity, final.stage) == final


def test_legacy_import_stop_rejects_unclean_codex_child(tmp_path: Path) -> None:
    store, artifacts, stopped, _ = _seed(tmp_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "INSERT INTO simple_codex_calls "
            "(call_id, analysis_id, status, started_at, resolved_at) "
            "VALUES (?, ?, 'SAFE', ?, ?)",
            (
                "call-1",
                stopped.identity.analysis_id,
                "2026-01-01T00:00:00Z",
                "2026-01-01T00:00:01Z",
            ),
        )
        connection.execute(
            "INSERT INTO simple_codex_child_spawns "
            "(call_id, analysis_id, phase, status, pid, start_identity) "
            "VALUES (?, ?, 'EXEC', 'CAPTURED', ?, ?)",
            ("call-1", stopped.identity.analysis_id, 12345, "start-1"),
        )
    with pytest.raises(
        ValueError, match="LEGACY_IMPORT_STOP_CODEX_CLEANUP_UNCONFIRMED"
    ):
        store.prepare_legacy_import_stop_replan(stopped, artifacts)
    assert store.require(stopped.identity, stopped.stage) == stopped


def test_legacy_import_stop_rejects_pending_other_work(tmp_path: Path) -> None:
    store, artifacts, stopped, _ = _seed(tmp_path)
    sibling = stopped.identity.model_copy(update={"hypothesis_id": "sibling"})
    store.save_checkpoint(
        _checkpoint(sibling, SimpleStage.PRO_CON_DONE, status=StageStatus.PENDING)
    )
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_RUN_ACTIVE"):
        store.prepare_legacy_import_stop_replan(stopped, artifacts)
    assert store.require(stopped.identity, stopped.stage) == stopped


def test_legacy_import_stop_requires_exact_root_block_event(tmp_path: Path) -> None:
    store, artifacts, stopped, _ = _seed(tmp_path)
    root_identity = stopped.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    store.save_checkpoint(root.model_copy(update={"error_code": "UNRELATED_BLOCK"}))
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_ROOT_BOUND_INVALID"):
        store.prepare_legacy_import_stop_replan(stopped, artifacts)
    assert store.require(stopped.identity, stopped.stage) == stopped


def test_legacy_import_stop_rejects_candidate_terminal(tmp_path: Path) -> None:
    store, artifacts, stopped, _ = _seed(tmp_path)
    run = store.require_analysis_run(stopped.identity.analysis_id)
    store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_terminal": CandidateTerminal(
                    status="PARTIAL",
                    bundle_hash="1" * 64,
                    scope_fingerprint="2" * 64,
                    decision_counts={},
                    deep_counts={},
                    hypothesis_count=1,
                )
            }
        )
    )
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_RUN_INVALID"):
        store.prepare_legacy_import_stop_replan(stopped, artifacts)
    assert store.require(stopped.identity, stopped.stage) == stopped


def test_legacy_import_stop_requires_pinned_static_source(tmp_path: Path) -> None:
    store, artifacts, stopped, _ = _seed(tmp_path)
    run = store.require_analysis_run(stopped.identity.analysis_id)
    store.save_analysis_run(run.model_copy(update={"static_coverage_ref": None}))
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_RUN_INVALID"):
        store.prepare_legacy_import_stop_replan(stopped, artifacts)
    assert store.require(stopped.identity, stopped.stage) == stopped


@pytest.mark.parametrize(
    ("stopped_code", "decision_origin", "stderr"),
    [
        (
            "POC_EXECUTION_FAILED",
            "FALLBACK",
            b"ModuleNotFoundError: jwt\nTraceback: frame -> exec_module",
        ),
        (
            "POC_RUNTIME_IMPORT_FAILED",
            "RULE",
            b"ModuleNotFoundError: jwt\nTraceback (most recent call last):\n"
            b"  frame:line 96\n  exec_module:line 999\n",
        ),
    ],
)
@pytest.mark.asyncio
async def test_application_requires_explicit_scope_and_uses_existing_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stopped_code: str,
    decision_origin: str,
    stderr: bytes,
) -> None:
    store, _artifacts, stopped, _ = _seed(
        tmp_path,
        stopped_code=stopped_code,
        decision_origin=decision_origin,
        stderr=stderr,
    )
    identity = stopped.identity
    display = AnalysisDisplayIdStore(store.database_path)
    display.get_or_allocate(identity.analysis_id)
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=_PinnedStaticStub(tmp_path / "data" / "workspaces"),
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )

    async def completed(
        _run: SimpleAnalysisRun, _identity: CheckpointIdentity
    ) -> SimpleAnalysisOutcome:
        return SimpleAnalysisOutcome(
            identity=identity.model_copy(update={"hypothesis_id": None}),
            display_analysis_id="A-001",
            status="BLOCKED",
            current_stage=SimpleStage.POC_EXECUTION_DONE,
            error_code=stopped_code,
        )

    monkeypatch.setattr(application, "_run_static", completed)

    async def static_scope(_run: SimpleAnalysisRun, _root: CheckpointIdentity) -> None:
        return None

    async def candidate_resume(
        _run: SimpleAnalysisRun,
        _root: CheckpointIdentity,
        _static: object,
    ) -> SimpleAnalysisOutcome:
        return await completed(_run, _root)

    monkeypatch.setattr(application, "_assert_completed_static_scope", static_scope)
    monkeypatch.setattr(application, "_run_candidate_pipeline", candidate_resume)
    monkeypatch.setattr(
        application, "_verify_registered_candidate_proposals", lambda _root: None
    )

    async def no_role_repair(_analysis_id: str) -> None:
        return None

    monkeypatch.setattr(application, "_repair_invalid_saved_pro_con", no_role_repair)

    await application.resume(identity.analysis_id)
    assert store.require(identity, stopped.stage) == stopped
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_"):
        await application.resume(
            identity.analysis_id, repair_legacy_import_stop_hypothesis="wrong"
        )
    await application.resume(
        identity.analysis_id,
        repair_legacy_import_stop_hypothesis=identity.hypothesis_id,
    )
    assert store.get(identity, stopped.stage) is None
    assert (
        store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE).status
        is StageStatus.PENDING
    )
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_HYPOTHESIS_INVALID"):
        await application.resume(
            identity.analysis_id,
            repair_legacy_import_stop_hypothesis=identity.hypothesis_id,
        )


@pytest.mark.asyncio
async def test_application_refuses_explicit_replan_while_run_lease_is_held(
    tmp_path: Path,
) -> None:
    store, _artifacts, stopped, _ = _seed(tmp_path)
    identity = stopped.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=None,  # type: ignore[arg-type]
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )
    with analysis_run_lease(tmp_path / "data", identity.analysis_id):
        outcome = await application.resume(
            identity.analysis_id,
            repair_legacy_import_stop_hypothesis=identity.hypothesis_id,
        )
    assert outcome.error_code == "ANALYSIS_ALREADY_RUNNING"
    assert store.require(identity, stopped.stage) == stopped


@pytest.mark.asyncio
async def test_explicit_replan_requires_static_fingerprint_capability(
    tmp_path: Path,
) -> None:
    store, _artifacts, stopped, _ = _seed(tmp_path)
    identity = stopped.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=None,  # type: ignore[arg-type]
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_STATIC_SCOPE_INVALID"):
        await application.resume(
            identity.analysis_id,
            repair_legacy_import_stop_hypothesis=identity.hypothesis_id,
        )
    assert store.require(identity, stopped.stage) == stopped


@pytest.mark.asyncio
async def test_invalid_explicit_scope_cannot_mutate_corrupt_sibling_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, artifacts, stopped, _ = _seed(tmp_path)
    identity = stopped.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    sibling = identity.model_copy(update={"hypothesis_id": "sibling"})
    corrupt_ref = artifacts.put_json({"kind": "wrong_terminal_evidence"})
    sibling_checkpoint = _checkpoint(
        sibling,
        SimpleStage.VERIFICATION_INITIAL_DONE,
        status=StageStatus.SUCCEEDED,
        outputs=(corrupt_ref,),
    ).model_copy(update={"verdict": "HOLD", "environment_block_ref": corrupt_ref})
    store.save_checkpoint(sibling_checkpoint)
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=None,  # type: ignore[arg-type]
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )

    async def static_scope(_run: SimpleAnalysisRun, _root: CheckpointIdentity) -> None:
        return None

    monkeypatch.setattr(application, "_assert_completed_static_scope", static_scope)
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_HYPOTHESIS_INVALID"):
        await application.resume(
            identity.analysis_id,
            repair_legacy_import_stop_hypothesis="wrong",
        )
    assert store.require(sibling, sibling_checkpoint.stage) == sibling_checkpoint
    assert store.require(identity, stopped.stage) == stopped


@pytest.mark.asyncio
@pytest.mark.parametrize("corruption", ["proposal_cas", "static_coverage"])
async def test_explicit_replan_preflights_saved_evidence_before_checkpoint_mutation(
    tmp_path: Path, corruption: str
) -> None:
    store, artifacts, stopped, _ = _seed(tmp_path)
    identity = stopped.identity
    root = identity.model_copy(update={"hypothesis_id": None})
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    if corruption == "proposal_cas":
        invalid_proposal_ref = artifacts.put_json(
            {
                "kind": "simple_hypothesis_proposal",
                "analysis_id": identity.analysis_id,
                "hypothesis_id": identity.hypothesis_id,
                "original_proposal_ref": artifacts.put_json(
                    {"kind": "not_original_proposal"}
                ).model_dump(mode="json"),
            }
        )
        pro_con = store.require(identity, SimpleStage.PRO_CON_DONE)
        inputs = (invalid_proposal_ref, pro_con.input_refs[1])
        store.save_checkpoint(
            pro_con.model_copy(
                update={
                    "input_refs": inputs,
                    "input_hash": input_reference_hash(inputs),
                    "attempt_id": "tampered-pro-con",
                }
            )
        )
    else:
        coverage_ref = artifacts.put_json(
            {
                "kind": "simple_static_coverage_v1",
                "analysis_id": identity.analysis_id,
                "workspace_id": identity.workspace_id,
                "commit_id": identity.commit_id,
                "fingerprint": "fingerprint-1",
                "expected_count": 1,
                "verified_count": 0,
                "gaps": [],
                "unsupported": [],
            }
        )
        bundle_ref = artifacts.put_json(
            {
                "kind": "simple_static_fact_bundle",
                "analysis_id": identity.analysis_id,
                "workspace_id": identity.workspace_id,
                "commit_id": identity.commit_id,
                "static_coverage_ref": coverage_ref.model_dump(mode="json"),
            }
        )
        run = store.require_analysis_run(identity.analysis_id)
        store.save_analysis_run(
            run.model_copy(
                update={
                    "static_bundle_ref": bundle_ref,
                    "static_coverage_ref": coverage_ref,
                }
            )
        )
        static_checkpoint = store.require(root, SimpleStage.STATIC_DONE)
        store.save_checkpoint(
            static_checkpoint.model_copy(
                update={"output_refs": (static_checkpoint.output_refs[0], bundle_ref)}
            )
        )

    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=_PinnedStaticStub(tmp_path / "data" / "workspaces"),
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_"):
        await application.resume(
            identity.analysis_id,
            repair_legacy_import_stop_hypothesis=identity.hypothesis_id,
        )
    assert store.require(identity, stopped.stage) == stopped
    assert (
        store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE).status
        is StageStatus.SUCCEEDED
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("saved_path", ["other_checkout", "missing_checkout"])
async def test_explicit_replan_rejects_saved_path_not_pinned_checkout(
    tmp_path: Path, saved_path: str
) -> None:
    store, _artifacts, stopped, _ = _seed(tmp_path)
    identity = stopped.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    workspace_root = tmp_path / "data" / "workspaces"
    wrong_workspace = workspace_root / saved_path
    if saved_path == "other_checkout":
        wrong_workspace.mkdir()
        (wrong_workspace / ".sastsimi-ready.json").write_text(
            json.dumps(
                {"repository": "example/vulnerable", "commit": identity.commit_id}
            ),
            encoding="utf-8",
        )
    run = store.require_analysis_run(identity.analysis_id)
    store.save_analysis_run(run.model_copy(update={"workspace_path": wrong_workspace}))
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=_PinnedStaticStub(workspace_root),
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_WORKSPACE_INVALID"):
        await application.resume(
            identity.analysis_id,
            repair_legacy_import_stop_hypothesis=identity.hypothesis_id,
        )
    assert store.require(identity, stopped.stage) == stopped
    assert (
        store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE).status
        is StageStatus.SUCCEEDED
    )


@pytest.mark.asyncio
async def test_explicit_replan_rejects_wrong_pinned_checkout_identity(
    tmp_path: Path,
) -> None:
    store, _artifacts, stopped, _ = _seed(tmp_path)
    identity = stopped.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    workspace_root = tmp_path / "data" / "workspaces"
    workspace = workspace_root / identity.workspace_id
    (workspace / ".sastsimi-ready.json").write_text(
        json.dumps({"repository": "example/vulnerable", "commit": "b" * 40}),
        encoding="utf-8",
    )
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=_PinnedStaticStub(workspace_root),
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_WORKSPACE_INVALID"):
        await application.resume(
            identity.analysis_id,
            repair_legacy_import_stop_hypothesis=identity.hypothesis_id,
        )
    assert store.require(identity, stopped.stage) == stopped


@pytest.mark.asyncio
@pytest.mark.parametrize("alias_kind", ["junction", "resolved_outside_root"])
async def test_explicit_replan_rejects_reparse_or_escaped_workspace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, alias_kind: str
) -> None:
    store, _artifacts, stopped, _ = _seed(tmp_path)
    identity = stopped.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    workspace_root = tmp_path / "data" / "workspaces"
    workspace = workspace_root / identity.workspace_id
    if alias_kind == "junction":
        original_is_junction = Path.is_junction

        def fake_is_junction(path: Path) -> bool:
            return path == workspace or original_is_junction(path)

        monkeypatch.setattr(Path, "is_junction", fake_is_junction)
    else:
        original_resolve = Path.resolve
        outside = tmp_path / "outside" / identity.workspace_id

        def fake_resolve(path: Path, strict: bool = False) -> Path:
            if path == workspace:
                return outside
            return original_resolve(path, strict=strict)

        monkeypatch.setattr(Path, "resolve", fake_resolve)
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=_PinnedStaticStub(workspace_root),
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_WORKSPACE_INVALID"):
        await application.resume(
            identity.analysis_id,
            repair_legacy_import_stop_hypothesis=identity.hypothesis_id,
        )
    assert store.require(identity, stopped.stage) == stopped
    assert (
        store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE).status
        is StageStatus.SUCCEEDED
    )
