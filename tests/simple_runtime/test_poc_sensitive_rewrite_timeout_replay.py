"""One exact sensitive candidate followed by a timed-out rewrite may retry once."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.interfaces.cli.main import main
from sastsimi.observability.agent_activity import ActivityKind
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CandidateTerminal,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.recovery import (
    RecoveryAction,
    RecoveryCategory,
    RecoveryDecision,
    RecoveryResolution,
    relation_settings_replay_binding,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_legacy_import_stop_replan import _seed
from tests.simple_runtime.test_poc_sensitive_exhaustion_replay import _bound_root
from tests.unit.interfaces.test_public_simple_cli import _config, _PublicApplication


def _decision(
    artifacts: SimpleArtifactRepository,
    failed: StageCheckpoint,
    code: str,
    *,
    category: RecoveryCategory = RecoveryCategory.GENERATED_INPUT,
    action: RecoveryAction = RecoveryAction.REGENERATE_INPUT,
) -> RecoveryResolution:
    decision = RecoveryDecision(
        category=category,
        action=action,
        diagnosis="Synthetic candidate failure",
        guidance="Retry with local fixture",
    )
    ref = artifacts.put_json(
        {
            "kind": "simple_recovery_decision",
            "identity": failed.identity.model_dump(mode="json"),
            "stage": failed.stage.value,
            "attempt": failed.attempt_number,
            "attempt_id": failed.attempt_id,
            "original_error": StageFailure(
                code=code,
                retryable=True,
                safe_message="Synthetic candidate failure",
                evidence_refs=failed.output_refs,
            ).model_dump(mode="json"),
            "decision": decision.model_dump(mode="json"),
            "decision_origin": "AGENT",
        }
    )
    return RecoveryResolution(decision=decision, decision_ref=ref)


def _receipt(
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
    checkpoint: StageCheckpoint,
    *,
    call_id: str,
    status: str,
) -> None:
    assert store.begin_codex_call(call_id, checkpoint.identity.analysis_id)
    for phase in ("VERSION", "LOGIN", "EXEC"):
        store.begin_codex_child_spawn(
            call_id=call_id,
            analysis_id=checkpoint.identity.analysis_id,
            phase=phase,
        )
        store.record_codex_child_spawn(
            call_id=call_id,
            analysis_id=checkpoint.identity.analysis_id,
            phase=phase,
            pid=777,
            start_identity=f"fixture-{call_id}-{phase}",
        )
        store.mark_codex_child_exited(
            call_id=call_id,
            analysis_id=checkpoint.identity.analysis_id,
            phase=phase,
            pid=777,
            start_identity=f"fixture-{call_id}-{phase}",
        )
    store.record_llm_attempt(
        attempt_id=call_id,
        analysis_id=checkpoint.identity.analysis_id,
        agent="poc_candidate",
        model="synthetic-model",
        attempt_number=1,
        status=status,
        elapsed_ms=100,
        input_tokens=1,
        output_tokens=1,
        cost_cents=0.0,
        artifact_ref=artifacts.put_json({"kind": "synthetic_llm_receipt"}),
    )
    store.mark_codex_call_safe(call_id, checkpoint.identity.analysis_id)


def _attempt_three(
    tmp_path: Path,
    *,
    root_succeeded: bool = False,
    first_transient_retry: bool = False,
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store, artifacts, previous, _ = _seed(tmp_path)
    identity = previous.identity
    if root_succeeded:
        root_identity = identity.model_copy(update={"hypothesis_id": None})
        root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
        store.replace_from(
            root.model_copy(
                update={
                    "status": StageStatus.PENDING,
                    "attempt_id": None,
                    "output_refs": (),
                    "error_code": None,
                    "retryable": False,
                }
            )
        )
        running_root = store.mark_running(
            root_identity,
            SimpleStage.HYPOTHESIS_DONE,
            root.input_refs,
            attempt_id="completed-producer-root",
        )
        store.complete(
            running_root,
            StageResult(
                output_refs=(
                    artifacts.put_json({"kind": "producer-index"}),
                    artifacts.put_json({"kind": "producer-coverage"}),
                )
            ),
        )
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
        identity, candidate.stage, candidate.input_refs, attempt_id="first-candidate"
    )
    first_error_ref = artifacts.put_json({"kind": "synthetic_provider_error"})
    first_failed = store.mark_failure(
        first,
        StageFailure(
            code="FAILED",
            retryable=True,
            safe_message="Synthetic provider error",
            evidence_refs=(first_error_ref,),
        ),
        StageStatus.BLOCKED,
    )
    second_pending = store.prepare_recovery(
        first_failed,
        _decision(
            artifacts,
            first_failed,
            "FAILED",
            category=(
                RecoveryCategory.TRANSIENT_TOOL
                if first_transient_retry
                else RecoveryCategory.GENERATED_INPUT
            ),
            action=(
                RecoveryAction.RETRY_STAGE
                if first_transient_retry
                else RecoveryAction.REGENERATE_INPUT
            ),
        ),
        candidate.stage,
    )
    second = store.mark_running(
        identity,
        candidate.stage,
        second_pending.input_refs,
        attempt_id="sensitive-candidate",
    )
    diagnostic_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate_rejection_diagnostic",
            "reason": "SENSITIVE_CONTENT",
            "line_count": 20,
            "branch_count": 0,
            "inconclusive_line_count": 0,
            "exit_two_line_count": 0,
            "exit_zero_line_count": 0,
            "sensitive_category": "MULTIPLE_RULES",
            "sensitive_line": 9,
            "sensitive_rule_id": "POSIX_HOST_PATH",
            "sensitive_field_kind": "OTHER",
            "sensitive_site_kind": "UNKNOWN",
        }
    )
    second_failed = store.mark_failure(
        second,
        StageFailure(
            code="POC_SENSITIVE_CONTENT",
            retryable=True,
            safe_message="PoC candidate is not self-contained",
            evidence_refs=(diagnostic_ref,),
        ),
        StageStatus.BLOCKED,
    )
    third_pending = store.prepare_recovery(
        second_failed,
        _decision(artifacts, second_failed, "POC_SENSITIVE_CONTENT"),
        candidate.stage,
    )
    third = store.mark_running(
        identity,
        candidate.stage,
        third_pending.input_refs,
        attempt_id="timed-out-rewrite",
    )
    _receipt(store, artifacts, third, call_id="first-poc-call", status="SUCCEEDED")
    _receipt(store, artifacts, third, call_id="rewrite-poc-call", status="TIMED_OUT")
    timeout_ref = artifacts.put_json({"kind": "synthetic_timeout_receipt"})
    third_failed = store.mark_failure(
        third,
        StageFailure(
            code="TIMED_OUT",
            retryable=True,
            safe_message="Candidate rewrite timed out",
            evidence_refs=(timeout_ref,),
        ),
        StageStatus.BLOCKED,
    )
    exhausted = store.mark_recovery_exhausted(third_failed)
    if not root_succeeded:
        _bound_root(store, exhausted)
    return store, artifacts, exhausted


def _with_partial_terminal(
    store: SimpleCheckpointStore,
    exhausted: StageCheckpoint,
    **changes: object,
) -> None:
    run = store.require_analysis_run(exhausted.identity.analysis_id)
    assert run.static_bundle_ref is not None
    assert run.candidate_scope_fingerprint is not None
    root = store.get(
        exhausted.identity.model_copy(update={"hypothesis_id": None}),
        SimpleStage.HYPOTHESIS_DONE,
    )
    completed_refs = (
        root.output_refs
        if root is not None and root.status is StageStatus.SUCCEEDED
        else ()
    )
    terminal = CandidateTerminal(
        status="PARTIAL",
        bundle_hash=run.static_bundle_ref.content_hash,
        scope_fingerprint=run.candidate_scope_fingerprint,
        decision_counts={},
        deep_counts={},
        hypothesis_count=1,
        surface_proof_version=3,
        scope_certificate_hash="c" * 64,
        producer_finished=True,
        pending_child_count=0,
        surface_index_hash=(completed_refs[0].content_hash if completed_refs else None),
        surface_coverage_hash=(
            completed_refs[1].content_hash if completed_refs else None
        ),
    ).model_copy(update=changes)
    store.save_analysis_run(run.model_copy(update={"candidate_terminal": terminal}))


def test_rewrite_timeout_replay_accepts_bound_partial_candidate_terminal(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_three(tmp_path)
    _with_partial_terminal(store, exhausted)
    run_before = store.require_analysis_run(exhausted.identity.analysis_id)

    pending = store.prepare_poc_sensitive_rewrite_timeout_replay(exhausted, artifacts)

    assert pending.status is StageStatus.PENDING
    assert store.require_analysis_run(exhausted.identity.analysis_id) == run_before
    assert store.require(exhausted.identity, exhausted.stage) == pending


def test_completed_sensitive_rewrite_candidate_is_not_relation_settings_replay(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_three(tmp_path)
    _with_partial_terminal(store, exhausted)
    pending = store.prepare_poc_sensitive_rewrite_timeout_replay(exhausted, artifacts)
    running = store.mark_running(
        exhausted.identity,
        exhausted.stage,
        pending.input_refs,
        attempt_id="completed-sensitive-rewrite",
    )
    completed = store.complete(
        running,
        StageResult(
            output_refs=(
                artifacts.put_json({"kind": "synthetic_candidate"}),
                artifacts.put_bytes(b"#!/bin/sh\nexit 0\n", "text/x-shellscript"),
            )
        ),
    )

    assert completed.attempt_number == 4
    assert completed.recovery_origin_stage is None
    assert completed.recovery_decision_refs == ()
    assert relation_settings_replay_binding(completed, artifacts) is None


def test_forged_completed_sensitive_rewrite_marker_fails_closed(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_three(tmp_path)
    _with_partial_terminal(store, exhausted)
    pending = store.prepare_poc_sensitive_rewrite_timeout_replay(exhausted, artifacts)
    running = store.mark_running(
        exhausted.identity,
        exhausted.stage,
        pending.input_refs,
        attempt_id="completed-sensitive-rewrite",
    )
    completed = store.complete(
        running,
        StageResult(
            output_refs=(
                artifacts.put_json({"kind": "synthetic_candidate"}),
                artifacts.put_bytes(b"#!/bin/sh\nexit 0\n", "text/x-shellscript"),
            )
        ),
    )
    marker_ref = completed.input_refs[-1]
    marker = json.loads(artifacts.read(marker_ref))
    marker["old_checkpoint_hash"] = "f" * 64
    forged_ref = artifacts.put_json(marker)
    forged_inputs = (*completed.input_refs[:-1], forged_ref)
    forged = completed.model_copy(
        update={
            "input_refs": forged_inputs,
            "input_hash": input_reference_hash(forged_inputs),
        }
    )

    with pytest.raises(ValueError, match="POC_DJANGO_RELATION_SETTINGS_REPLAY_UNBOUND"):
        relation_settings_replay_binding(forged, artifacts)


def test_rewrite_timeout_replay_accepts_completed_candidate_producer_root(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_three(tmp_path, root_succeeded=True)
    _with_partial_terminal(store, exhausted)
    root_identity = exhausted.identity.model_copy(update={"hypothesis_id": None})
    root_before = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)

    pending = store.prepare_poc_sensitive_rewrite_timeout_replay(exhausted, artifacts)

    assert pending.status is StageStatus.PENDING
    assert store.require(root_identity, SimpleStage.HYPOTHESIS_DONE) == root_before


@pytest.mark.parametrize("field", ["surface_index_hash", "surface_coverage_hash"])
def test_rewrite_timeout_replay_rejects_terminal_proof_hash_mismatch(
    tmp_path: Path, field: str
) -> None:
    store, artifacts, exhausted = _attempt_three(tmp_path, root_succeeded=True)
    _with_partial_terminal(store, exhausted, **{field: "d" * 64})

    with pytest.raises(
        ValueError, match="POC_SENSITIVE_REWRITE_TIMEOUT_REPLAY_ROOT_BOUND_INVALID"
    ):
        store.prepare_poc_sensitive_rewrite_timeout_replay(exhausted, artifacts)

    assert store.require(exhausted.identity, exhausted.stage) == exhausted


def test_rewrite_timeout_replay_accepts_transient_tool_first_decision(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_three(
        tmp_path, root_succeeded=True, first_transient_retry=True
    )
    _with_partial_terminal(store, exhausted)

    pending = store.prepare_poc_sensitive_rewrite_timeout_replay(exhausted, artifacts)

    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 3


def test_rewrite_timeout_replay_rejects_unmatched_root_completion_event(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_three(tmp_path, root_succeeded=True)
    _with_partial_terminal(store, exhausted)
    root_identity = exhausted.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    changed_ref = artifacts.put_json({"kind": "unmatched-root-output"})
    store.save_checkpoint(root.model_copy(update={"output_refs": (changed_ref,)}))

    with pytest.raises(
        ValueError, match="POC_SENSITIVE_REWRITE_TIMEOUT_REPLAY_ROOT_BOUND_INVALID"
    ):
        store.prepare_poc_sensitive_rewrite_timeout_replay(exhausted, artifacts)

    assert store.require(exhausted.identity, exhausted.stage) == exhausted


def test_rewrite_timeout_replay_rejects_unbound_producer_child(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_three(tmp_path, root_succeeded=True)
    _with_partial_terminal(store, exhausted)
    unrelated_ref = artifacts.put_json({"kind": "unrelated_producer_child"})
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE simple_candidate_hypotheses SET hypothesis_ref_json = ? "
            "WHERE analysis_id = ? AND hypothesis_id = ?",
            (
                json.dumps(unrelated_ref.model_dump(mode="json")),
                exhausted.identity.analysis_id,
                exhausted.identity.hypothesis_id,
            ),
        )

    with pytest.raises(
        ValueError, match="POC_SENSITIVE_REWRITE_TIMEOUT_REPLAY_LINEAGE_INVALID"
    ):
        store.prepare_poc_sensitive_rewrite_timeout_replay(exhausted, artifacts)

    assert store.require(exhausted.identity, exhausted.stage) == exhausted


@pytest.mark.parametrize(
    "changes",
    [
        {"status": "COMPLETE"},
        {"bundle_hash": "wrong-bundle"},
        {"scope_fingerprint": "wrong-scope"},
        {"producer_finished": False},
        {"pending_child_count": 1},
    ],
)
def test_rewrite_timeout_replay_rejects_unbound_candidate_terminal(
    tmp_path: Path, changes: dict[str, object]
) -> None:
    store, artifacts, exhausted = _attempt_three(tmp_path)
    _with_partial_terminal(store, exhausted, **changes)

    with pytest.raises(
        ValueError, match="POC_SENSITIVE_REWRITE_TIMEOUT_REPLAY_RUN_INVALID"
    ):
        store.prepare_poc_sensitive_rewrite_timeout_replay(exhausted, artifacts)

    assert store.require(exhausted.identity, exhausted.stage) == exhausted


def test_exact_sensitive_rewrite_timeout_reopens_only_candidate_once(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_three(tmp_path)
    identity = exhausted.identity
    root_id = identity.model_copy(update={"hypothesis_id": None})
    root_before = store.require(root_id, SimpleStage.HYPOTHESIS_DONE)
    initial_before = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
    events_before = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    pending = store.prepare_poc_sensitive_rewrite_timeout_replay(exhausted, artifacts)

    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 3
    assert pending.output_refs == ()
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
    assert marker_event.error_code == "POC_SENSITIVE_REWRITE_TIMEOUT_REPLAYED"
    marker = json.loads(artifacts.read_bounded(marker_event.output_refs[0], 4096))
    assert marker["old_attempt_id"] == exhausted.attempt_id
    assert marker["old_attempt_number"] == 3
    assert (
        marker["old_checkpoint_hash"]
        == hashlib.sha256(
            canonical_bytes(exhausted.model_dump(mode="json"))
        ).hexdigest()
    )
    assert "content" not in marker and "candidate" not in marker

    running = store.mark_running(
        identity,
        exhausted.stage,
        pending.input_refs,
        attempt_id="single-replay-attempt",
    )
    assert running.attempt_number == 4
    failed = store.mark_failure(
        running,
        StageFailure(
            code="TIMED_OUT", retryable=True, safe_message="Synthetic timeout"
        ),
        StageStatus.BLOCKED,
    )
    again_exhausted = store.mark_recovery_exhausted(failed)
    with pytest.raises(ValueError, match="POC_SENSITIVE_REWRITE_TIMEOUT_REPLAY_"):
        store.prepare_poc_sensitive_rewrite_timeout_replay(again_exhausted, artifacts)


def test_rewrite_timeout_replay_transaction_rolls_back(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_three(tmp_path)
    before = AgentActivityStore(store.database_path).list_analysis(
        exhausted.identity.analysis_id, hypothesis_id=exhausted.identity.hypothesis_id
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_poc_sensitive_rewrite_timeout_replay(
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
    assert (
        store.prepare_poc_sensitive_rewrite_timeout_replay(exhausted, artifacts).status
        is StageStatus.PENDING
    )


@pytest.mark.parametrize("receipt_status", ["FAILED", "SUCCEEDED"])
def test_rewrite_timeout_replay_rejects_non_timeout_second_receipt(
    tmp_path: Path, receipt_status: str
) -> None:
    store, artifacts, exhausted = _attempt_three(tmp_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE simple_llm_attempts SET status = ? WHERE attempt_id = ?",
            (receipt_status, "rewrite-poc-call"),
        )
    with pytest.raises(ValueError, match="CALL_LINEAGE_INVALID"):
        store.prepare_poc_sensitive_rewrite_timeout_replay(exhausted, artifacts)
    assert store.require(exhausted.identity, exhausted.stage) == exhausted


def test_rewrite_timeout_replay_requires_exact_attempt_three(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_three(tmp_path)
    wrong = exhausted.model_copy(update={"attempt_number": 4})
    with pytest.raises(ValueError, match="REPLAY_INVALID"):
        store.prepare_poc_sensitive_rewrite_timeout_replay(wrong, artifacts)
    assert store.require(exhausted.identity, exhausted.stage) == exhausted


def test_cli_forwards_explicit_rewrite_timeout_option(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class _Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_sensitive_rewrite_timeout_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("plain", repair_poc_sensitive_rewrite_timeout_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_poc_sensitive_rewrite_timeout_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(
                ("progress", repair_poc_sensitive_rewrite_timeout_hypothesis)
            )
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = _Application()
    for extra, label in [(["--format", "json"], "plain"), ([], "progress")]:
        assert main(
            [
                "resume",
                "A-002",
                "--repair-poc-sensitive-rewrite-timeout",
                "hypothesis-1",
                *extra,
            ],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (label, "hypothesis-1")
        capsys.readouterr()
