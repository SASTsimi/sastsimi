"""A corrected report validator may replay only its exact blocked child."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.interfaces.cli.main import main
from sastsimi.observability.agent_activity import ActivityKind, AgentActivityEvent
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageStatus,
)
from sastsimi.simple_runtime.recovery import (
    RecoveryAction,
    RecoveryCategory,
    RecoveryDecision,
    RecoveryResolution,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_legacy_import_stop_replan import _checkpoint
from tests.unit.interfaces.test_public_simple_cli import _config, _PublicApplication


def _report_content(*, legacy_ipv4: bool = True) -> dict[str, object]:
    prose = {
        "title": "A verified issue",
        "summary": "The saved evidence supports this issue.",
        "details": "The saved PoC reached the risky operation.",
        "impact": "The affected operation can be invoked.",
        "recommendation": "Validate the untrusted input.",
        "limitations": [
            "The local test server defaults to 127.0.0.1."
            if legacy_ipv4
            else "The deployment configuration needs review."
        ],
        "review_items": ["Confirm the affected deployment."],
    }
    return {"schema_version": 2, "en": prose, "ko": prose, "citations": []}


def _blocked_report(
    tmp_path: Path,
) -> tuple[
    SimpleCheckpointStore,
    SimpleArtifactRepository,
    StageCheckpoint,
    StoredDataRef,
    StageCheckpoint,
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
            repository="example/repository",
            hypothesis_ids=(),
            candidate_pipeline_version=2,
        )
    )
    artifacts = SimpleArtifactRepository(data_dir, identity)
    store.upsert_hypothesis(
        identity.model_copy(update={"hypothesis_id": None}),
        identity.hypothesis_id or "",
    )
    source_refs: list[StoredDataRef] = []
    prior: dict[SimpleStage, StageCheckpoint] = {}
    for stage in HYPOTHESIS_STAGES[:-1]:
        output = artifacts.put_json({"kind": stage.value})
        checkpoint = _checkpoint(
            identity,
            stage,
            status=StageStatus.SUCCEEDED,
            inputs=(source_refs[-1],) if source_refs else (),
            outputs=(output,),
            attempt_id=f"{stage.value}-attempt",
            attempt_number=1,
        )
        if stage in {SimpleStage.VERIFICATION_FINAL_DONE, SimpleStage.FINDING_DONE}:
            checkpoint = checkpoint.model_copy(update={"verdict": "TRUE"})
        if stage is SimpleStage.POC_EXECUTION_DONE:
            checkpoint = checkpoint.model_copy(update={"validated_poc_ref": output})
        store.save_checkpoint(checkpoint)
        source_refs.append(output)
        prior[stage] = checkpoint

    stopped = _checkpoint(
        identity,
        SimpleStage.REPORT_DONE,
        status=StageStatus.BLOCKED,
        inputs=(source_refs[-1],),
        attempt_id="report-attempt-2",
        attempt_number=2,
        error_code="STAGE_UNEXPECTED_ERROR",
    )
    store.save_checkpoint(stopped)
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    root = _checkpoint(
        root_identity,
        SimpleStage.HYPOTHESIS_DONE,
        status=StageStatus.BLOCKED,
        attempt_id="root-attempt",
        attempt_number=1,
        error_code=(
            "CANDIDATE_CHILD_ERROR_BOUND:STAGE_UNEXPECTED_ERROR:"
            "hypothesis-1:report-attempt-2"
        ),
    )
    store.save_checkpoint(root)
    draft_ref = artifacts.put_json(
        {
            "kind": "simple_report_draft",
            "source_refs": [ref.model_dump(mode="json") for ref in source_refs],
            "result": _report_content(),
            "prompt_digest": "b" * 64,
            "output_digest": hashlib.sha256(
                canonical_bytes(_report_content())
            ).hexdigest(),
            "attempt_id": stopped.attempt_id,
        }
    )
    other_identity = identity.model_copy(update={"hypothesis_id": "hypothesis-2"})
    other_report = _checkpoint(
        other_identity,
        SimpleStage.REPORT_DONE,
        status=StageStatus.SUCCEEDED,
        outputs=(artifacts.put_json({"kind": "other-report"}),),
        attempt_id="other-report-attempt",
        attempt_number=1,
    )
    store.save_checkpoint(other_report)
    return store, artifacts, stopped, draft_ref, other_report


def test_exact_report_validator_replay_preserves_other_work(tmp_path: Path) -> None:
    store, artifacts, stopped, draft_ref, other_report = _blocked_report(tmp_path)
    identity = stopped.identity
    prior = store.prior(identity, SimpleStage.REPORT_DONE)
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    root_before = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)

    pending = store.prepare_report_validator_replay(stopped, draft_ref, artifacts)

    assert pending.status is StageStatus.PENDING
    assert pending.stage is SimpleStage.REPORT_DONE
    assert pending.attempt_number == 2
    assert pending.attempt_id is None
    assert pending.input_refs == stopped.input_refs
    assert store.require(identity, SimpleStage.REPORT_DONE) == pending
    assert store.prior(identity, SimpleStage.REPORT_DONE) == prior
    assert store.require(root_identity, SimpleStage.HYPOTHESIS_DONE) == root_before
    assert store.require(other_report.identity, SimpleStage.REPORT_DONE) == other_report
    source_hash = hashlib.sha256(
        canonical_bytes(
            {
                "refs": tuple(item.output_refs[0] for item in prior.values()),
                "finding_attempt_id": prior[SimpleStage.FINDING_DONE].attempt_id,
                "poc_attempt_id": prior[SimpleStage.POC_EXECUTION_DONE].attempt_id,
            }
        )
    ).hexdigest()
    assert (
        store.report_draft(
            identity, source_hash, prior[SimpleStage.FINDING_DONE].output_refs[0]
        )
        == draft_ref
    )


def _exhausted_ipv4_report(
    tmp_path: Path, *, record_failure_event: bool = True
) -> tuple[
    SimpleCheckpointStore,
    SimpleArtifactRepository,
    StageCheckpoint,
    StoredDataRef,
]:
    store, artifacts, stopped, _older_draft, _other = _blocked_report(tmp_path)
    identity = stopped.identity
    prior = store.prior(identity, SimpleStage.REPORT_DONE)
    refs = tuple(item.output_refs[0] for item in prior.values())
    content = _report_content()
    en = content["en"]
    assert isinstance(en, dict)
    content["en"] = {
        **en,
        "limitations": [
            "The app defaults to 127.0.0.1; external reachability is unverified."
        ],
    }
    draft_ref = artifacts.put_json(
        {
            "kind": "simple_report_draft",
            "source_refs": [ref.model_dump(mode="json") for ref in refs],
            "result": content,
            "prompt_digest": "b" * 64,
            "output_digest": hashlib.sha256(canonical_bytes(content)).hexdigest(),
            "attempt_id": "report-attempt-3",
        }
    )
    decisions = tuple(
        artifacts.put_json(
            {
                "kind": "simple_recovery_decision",
                "identity": identity.model_dump(mode="json"),
                "stage": SimpleStage.REPORT_DONE.value,
                "attempt": number,
                "attempt_id": f"report-attempt-{number}",
                "original_error": {"code": "REPORT_CONTENT_INVALID"},
            }
        )
        for number in (1, 2)
    )
    exhausted = stopped.model_copy(
        update={
            "error_code": "RECOVERY_EXHAUSTED",
            "attempt_id": "report-attempt-3",
            "attempt_number": 3,
            "output_refs": (draft_ref,),
            "recovery_lineage_id": "a" * 64,
            "recovery_origin_stage": SimpleStage.REPORT_DONE,
            "recovery_decision_refs": decisions,
        }
    )
    store.save_checkpoint(exhausted)
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    store.save_checkpoint(
        root.model_copy(
            update={
                "error_code": (
                    "CANDIDATE_CHILD_ERROR_BOUND:RECOVERY_EXHAUSTED:"
                    "hypothesis-1:report-attempt-3"
                )
            }
        )
    )
    if record_failure_event:
        AgentActivityStore(store.database_path).append(
            AgentActivityEvent(
                event_id="report-attempt-3-content-invalid",
                analysis_id=identity.analysis_id,
                workspace_id=identity.workspace_id,
                commit_id=identity.commit_id,
                hypothesis_id=identity.hypothesis_id,
                stage=SimpleStage.REPORT_DONE.value,
                agent_role="Reporter Agent",
                attempt_id="report-attempt-3",
                sequence=1499,
                kind=ActivityKind.STAGE_BLOCKED,
                status=StageStatus.BLOCKED.value,
                summary_ko="초안 검증이 거절되었습니다.",
                output_refs=(draft_ref,),
                error_code="REPORT_CONTENT_INVALID",
                started_at=datetime.now(UTC),
            )
        )
    return store, artifacts, exhausted, draft_ref


def _stopped_second_report(
    tmp_path: Path,
    *,
    invalid_draft: str | None = None,
    invalid_decision: str | None = None,
    record_stop: bool = True,
) -> tuple[
    SimpleCheckpointStore,
    SimpleArtifactRepository,
    StageCheckpoint,
    StoredDataRef,
    StoredDataRef,
    StoredDataRef,
]:
    store, artifacts, original, _legacy_ref, _other = _blocked_report(tmp_path)
    identity = original.identity
    refs = tuple(
        item.output_refs[0]
        for item in store.prior(identity, SimpleStage.REPORT_DONE).values()
    )

    def draft(attempt_id: str, *, invalid: bool) -> StoredDataRef:
        content = _report_content(legacy_ipv4=False)
        english = content["en"]
        korean = content["ko"]
        assert isinstance(english, dict) and isinstance(korean, dict)
        content["en"] = {
            **english,
            "limitations": [
                "The default listener is 127.0.0.1; remote access is unverified."
            ],
            **({"summary": "Affected versions 1.2.3"} if invalid else {}),
        }
        content["ko"] = {
            **korean,
            "limitations": [
                "기본 수신 주소는 127.0.0.1이므로 외부 접근 여부는 확인되지 않았습니다."
            ],
        }
        return artifacts.put_json(
            {
                "kind": "simple_report_draft",
                "source_refs": [
                    ref.model_dump(mode="json")
                    for ref in (
                        refs[:-1]
                        if invalid_draft == "first_refs" and attempt_id.endswith("-1")
                        else refs
                    )
                ],
                "result": content,
                "prompt_digest": "b" * 64,
                "output_digest": hashlib.sha256(canonical_bytes(content)).hexdigest(),
                "attempt_id": attempt_id,
            }
        )

    first_id = "report-invalid-attempt-1"
    second_id = "report-invalid-attempt-2"
    first_ref = draft(first_id, invalid=invalid_draft == "first")
    second_ref = draft(second_id, invalid=invalid_draft == "second")

    def decision_ref(
        attempt_id: str,
        attempt_number: int,
        draft_ref: StoredDataRef,
        decision: RecoveryDecision,
        *,
        evidence_ref: StoredDataRef | None = None,
        origin: str = "AGENT",
    ) -> StoredDataRef:
        return artifacts.put_json(
            {
                "kind": "simple_recovery_decision",
                "identity": identity.model_dump(mode="json"),
                "stage": SimpleStage.REPORT_DONE.value,
                "attempt": attempt_number,
                "attempt_id": attempt_id,
                "original_error": StageFailure(
                    code="REPORT_CONTENT_INVALID",
                    retryable=True,
                    safe_message="Reporter output failed validation",
                    evidence_refs=(evidence_ref or draft_ref,),
                ).model_dump(mode="json"),
                "decision": decision.model_dump(mode="json"),
                "decision_origin": origin,
            }
        )

    first_running = original.model_copy(
        update={
            "status": StageStatus.RUNNING,
            "attempt_id": first_id,
            "attempt_number": 1,
            "error_code": None,
        }
    )
    store.save_checkpoint(first_running)
    first_failed = store.mark_failure(
        first_running,
        StageFailure(
            code="REPORT_CONTENT_INVALID",
            retryable=True,
            safe_message="Reporter output failed validation",
            evidence_refs=(first_ref,),
        ),
        StageStatus.BLOCKED,
    )
    retry = RecoveryDecision(
        category=RecoveryCategory.GENERATED_INPUT,
        action=RecoveryAction.REGENERATE_INPUT,
        diagnosis="Retry the saved Reporter stage",
        guidance="Use only supported report content",
    )
    retry_ref = decision_ref(
        first_id,
        1,
        first_ref,
        (
            retry.model_copy(update={"action": RecoveryAction.STOP})
            if invalid_decision == "first_action"
            else retry
        ),
        evidence_ref=second_ref if invalid_decision == "first_evidence" else None,
        origin="RULE" if invalid_decision == "first_origin" else "AGENT",
    )
    pending = store.prepare_recovery(
        first_failed,
        RecoveryResolution(decision=retry, decision_ref=retry_ref),
        SimpleStage.REPORT_DONE,
    )
    second_running = store.mark_running(
        identity, SimpleStage.REPORT_DONE, pending.input_refs, attempt_id=second_id
    )
    second_failed = store.mark_failure(
        second_running,
        StageFailure(
            code="REPORT_CONTENT_INVALID",
            retryable=True,
            safe_message="Reporter output failed validation",
            evidence_refs=(second_ref,),
        ),
        StageStatus.BLOCKED,
    )
    stop = RecoveryDecision(
        category=RecoveryCategory.GENERATED_INPUT,
        action=RecoveryAction.STOP,
        diagnosis="Stop after the second report validation failure",
        guidance="Inspect the saved Reporter drafts",
    )
    stop_ref = decision_ref(
        second_id,
        2,
        second_ref,
        (
            stop.model_copy(update={"action": RecoveryAction.REGENERATE_INPUT})
            if invalid_decision == "stop_action"
            else stop
        ),
        evidence_ref=first_ref if invalid_decision == "stop_evidence" else None,
        origin="RULE" if invalid_decision == "stop_origin" else "AGENT",
    )
    if record_stop:
        stopped = store.record_recovery_stop(
            second_failed, RecoveryResolution(decision=stop, decision_ref=stop_ref)
        )
    else:
        stopped = second_failed.model_copy(update={"retryable": False})
        store.save_checkpoint(stopped)
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    store.save_checkpoint(
        root.model_copy(
            update={
                "error_code": (
                    "CANDIDATE_CHILD_ERROR_BOUND:REPORT_CONTENT_INVALID:"
                    f"{identity.hypothesis_id}:{second_id}"
                )
            }
        )
    )
    return store, artifacts, stopped, first_ref, second_ref, stop_ref


def test_second_report_stop_replays_only_when_both_saved_drafts_are_now_valid(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, first_ref, second_ref, stop_ref = _stopped_second_report(
        tmp_path
    )
    prior = store.prior(stopped.identity, SimpleStage.REPORT_DONE)
    root_identity = stopped.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)

    pending = store.prepare_report_validator_replay(stopped, second_ref, artifacts)

    assert first_ref in stopped.input_refs
    assert stop_ref not in stopped.input_refs
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 2
    assert pending.attempt_id is None
    assert pending.output_refs == ()
    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == pending
    assert store.prior(stopped.identity, SimpleStage.REPORT_DONE) == prior
    assert store.require(root_identity, SimpleStage.HYPOTHESIS_DONE) == root
    with pytest.raises(ValueError, match="REPORT_VALIDATOR_REPLAY_STALE"):
        store.prepare_report_validator_replay(stopped, second_ref, artifacts)


@pytest.mark.parametrize("invalid_draft", ["first", "second"])
def test_second_report_stop_rejects_either_still_invalid_draft(
    tmp_path: Path, invalid_draft: str
) -> None:
    store, artifacts, stopped, _first_ref, second_ref, _stop_ref = (
        _stopped_second_report(tmp_path, invalid_draft=invalid_draft)
    )

    with pytest.raises(ValueError, match="REPORT_VALIDATOR_REPLAY_DRAFT_INVALID"):
        store.prepare_report_validator_replay(stopped, second_ref, artifacts)
    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == stopped


def test_second_report_stop_requires_persisted_stop_decision(tmp_path: Path) -> None:
    store, artifacts, stopped, _first_ref, second_ref, _stop_ref = (
        _stopped_second_report(tmp_path, record_stop=False)
    )

    with pytest.raises(ValueError, match="REPORT_VALIDATOR_REPLAY_CAUSE_UNPROVEN"):
        store.prepare_report_validator_replay(stopped, second_ref, artifacts)
    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == stopped


@pytest.mark.parametrize(
    "invalid_decision",
    [
        "first_action",
        "first_evidence",
        "first_origin",
        "stop_action",
        "stop_evidence",
        "stop_origin",
    ],
)
def test_second_report_stop_rejects_mismatched_recovery_proof(
    tmp_path: Path, invalid_decision: str
) -> None:
    store, artifacts, stopped, _first_ref, second_ref, _stop_ref = (
        _stopped_second_report(tmp_path, invalid_decision=invalid_decision)
    )

    with pytest.raises(ValueError, match="REPORT_VALIDATOR_REPLAY_CAUSE_UNPROVEN"):
        store.prepare_report_validator_replay(stopped, second_ref, artifacts)
    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == stopped


def test_second_report_stop_rejects_ambiguous_decision_event(tmp_path: Path) -> None:
    store, artifacts, stopped, _first_ref, second_ref, stop_ref = (
        _stopped_second_report(tmp_path)
    )
    ledger = AgentActivityStore(store.database_path)
    stop_event = next(
        event
        for event in ledger.list_analysis(
            stopped.identity.analysis_id,
            hypothesis_id=stopped.identity.hypothesis_id,
        )
        if event.attempt_id == stopped.attempt_id
        and event.kind is ActivityKind.DECISION_RECORDED
        and event.output_refs == (stop_ref,)
    )
    ledger.append(
        stop_event.model_copy(
            update={
                "event_id": "duplicate-stop-event",
                "sequence": stop_event.sequence + 1,
            }
        )
    )

    with pytest.raises(ValueError, match="REPORT_VALIDATOR_REPLAY_CAUSE_UNPROVEN"):
        store.prepare_report_validator_replay(stopped, second_ref, artifacts)
    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == stopped


def test_second_report_stop_rejects_first_draft_source_mismatch(tmp_path: Path) -> None:
    store, artifacts, stopped, _first_ref, second_ref, _stop_ref = (
        _stopped_second_report(tmp_path, invalid_draft="first_refs")
    )

    with pytest.raises(ValueError, match="REPORT_VALIDATOR_REPLAY_SOURCE_MISMATCH"):
        store.prepare_report_validator_replay(stopped, second_ref, artifacts)
    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == stopped


def test_second_report_stop_rejects_wrong_recovery_lineage(tmp_path: Path) -> None:
    store, artifacts, stopped, _first_ref, second_ref, _stop_ref = (
        _stopped_second_report(tmp_path)
    )
    wrong_lineage = stopped.model_copy(update={"recovery_lineage_id": "f" * 64})
    store.save_checkpoint(wrong_lineage)

    with pytest.raises(ValueError, match="REPORT_VALIDATOR_REPLAY_CAUSE_UNPROVEN"):
        store.prepare_report_validator_replay(wrong_lineage, second_ref, artifacts)
    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == wrong_lineage


@pytest.mark.parametrize("invalid", ["root", "stale", "success"])
def test_second_report_stop_rejects_changed_checkpoint_or_root(
    tmp_path: Path, invalid: str
) -> None:
    store, artifacts, stopped, _first_ref, second_ref, _stop_ref = (
        _stopped_second_report(tmp_path)
    )
    current = stopped
    if invalid == "root":
        root_identity = stopped.identity.model_copy(update={"hypothesis_id": None})
        root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
        store.save_checkpoint(root.model_copy(update={"error_code": "OTHER_CHILD"}))
        expected_error = "REPORT_VALIDATOR_REPLAY_ROOT_UNBOUND"
    else:
        current = stopped.model_copy(
            update={
                "status": (
                    StageStatus.SUCCEEDED
                    if invalid == "success"
                    else StageStatus.BLOCKED
                ),
                "attempt_id": (
                    "later-report-attempt" if invalid == "stale" else stopped.attempt_id
                ),
                "error_code": None if invalid == "success" else stopped.error_code,
                "report_ref": second_ref if invalid == "success" else None,
            }
        )
        store.save_checkpoint(current)
        expected_error = "REPORT_VALIDATOR_REPLAY_STALE"
    with pytest.raises(ValueError, match=expected_error):
        store.prepare_report_validator_replay(stopped, second_ref, artifacts)
    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == current
    if invalid == "success":
        with pytest.raises(ValueError, match="REPORT_VALIDATOR_REPLAY_INVALID"):
            store.prepare_report_validator_replay(current, second_ref, artifacts)
        assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == current


def test_exhausted_ipv4_validator_replay_is_one_shot_and_preserves_prior(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, draft_ref = _exhausted_ipv4_report(tmp_path)
    prior = store.prior(stopped.identity, SimpleStage.REPORT_DONE)
    root_identity = stopped.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)

    pending = store.prepare_report_validator_replay(stopped, draft_ref, artifacts)

    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 3
    assert pending.attempt_id is None
    assert pending.output_refs == ()
    assert store.prior(stopped.identity, SimpleStage.REPORT_DONE) == prior
    assert store.require(root_identity, SimpleStage.HYPOTHESIS_DONE) == root
    with pytest.raises(ValueError, match="REPORT_VALIDATOR_REPLAY_STALE"):
        store.prepare_report_validator_replay(stopped, draft_ref, artifacts)


def test_exhausted_report_replay_requires_exact_invalid_content_event(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, draft_ref = _exhausted_ipv4_report(
        tmp_path, record_failure_event=False
    )

    with pytest.raises(ValueError, match="REPORT_VALIDATOR_REPLAY_CAUSE_UNPROVEN"):
        store.prepare_report_validator_replay(stopped, draft_ref, artifacts)
    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == stopped


def test_exhausted_report_replay_still_rejects_unsupported_claim(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, _draft_ref = _exhausted_ipv4_report(tmp_path)
    prior = store.prior(stopped.identity, SimpleStage.REPORT_DONE)
    refs = tuple(item.output_refs[0] for item in prior.values())
    content = _report_content()
    en = content["en"]
    assert isinstance(en, dict)
    content["en"] = {**en, "summary": "Affected versions 1.2.3"}
    invalid_ref = artifacts.put_json(
        {
            "kind": "simple_report_draft",
            "source_refs": [ref.model_dump(mode="json") for ref in refs],
            "result": content,
            "prompt_digest": "b" * 64,
            "output_digest": hashlib.sha256(canonical_bytes(content)).hexdigest(),
            "attempt_id": stopped.attempt_id,
        }
    )
    stopped = stopped.model_copy(update={"output_refs": (invalid_ref,)})
    store.save_checkpoint(stopped)

    with pytest.raises(ValueError, match="REPORT_VALIDATOR_REPLAY_DRAFT_INVALID"):
        store.prepare_report_validator_replay(stopped, invalid_ref, artifacts)
    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == stopped


def test_exhausted_report_replay_rejects_unrelated_recovery_decision(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, draft_ref = _exhausted_ipv4_report(tmp_path)
    unrelated = artifacts.put_json(
        {
            "kind": "simple_recovery_decision",
            "identity": stopped.identity.model_dump(mode="json"),
            "stage": SimpleStage.REPORT_DONE.value,
            "attempt": 1,
            "attempt_id": "report-attempt-1",
            "original_error": {"code": "REPORT_SENSITIVE_CONTENT"},
        }
    )
    stopped = stopped.model_copy(
        update={
            "recovery_decision_refs": (
                unrelated,
                stopped.recovery_decision_refs[1],
            )
        }
    )
    store.save_checkpoint(stopped)

    with pytest.raises(ValueError, match="REPORT_VALIDATOR_REPLAY_CAUSE_UNPROVEN"):
        store.prepare_report_validator_replay(stopped, draft_ref, artifacts)
    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == stopped


def test_legacy_unexpected_error_rejects_unrelated_valid_report(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, _draft_ref, _ = _blocked_report(tmp_path)
    result = _report_content(legacy_ipv4=False)
    prior = store.prior(stopped.identity, SimpleStage.REPORT_DONE)
    refs = tuple(item.output_refs[0] for item in prior.values())
    draft_ref = artifacts.put_json(
        {
            "kind": "simple_report_draft",
            "source_refs": [ref.model_dump(mode="json") for ref in refs],
            "result": result,
            "prompt_digest": "b" * 64,
            "output_digest": hashlib.sha256(canonical_bytes(result)).hexdigest(),
            "attempt_id": stopped.attempt_id,
        }
    )

    with pytest.raises(
        ValueError, match="REPORT_VALIDATOR_REPLAY_LEGACY_CAUSE_UNPROVEN"
    ):
        store.prepare_report_validator_replay(stopped, draft_ref, artifacts)
    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == stopped


def test_explicit_metadata_claim_error_does_not_need_legacy_ipv4(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, _draft_ref, _ = _blocked_report(tmp_path)
    stopped = stopped.model_copy(
        update={"error_code": "REPORT_UNSUPPORTED_METADATA_CLAIM"}
    )
    store.save_checkpoint(stopped)
    root_identity = stopped.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    store.save_checkpoint(
        root.model_copy(
            update={
                "error_code": (
                    "CANDIDATE_CHILD_ERROR_BOUND:REPORT_UNSUPPORTED_METADATA_CLAIM:"
                    "hypothesis-1:report-attempt-2"
                )
            }
        )
    )
    result = _report_content(legacy_ipv4=False)
    refs = tuple(
        item.output_refs[0]
        for item in store.prior(stopped.identity, SimpleStage.REPORT_DONE).values()
    )
    draft_ref = artifacts.put_json(
        {
            "kind": "simple_report_draft",
            "source_refs": [ref.model_dump(mode="json") for ref in refs],
            "result": result,
            "prompt_digest": "b" * 64,
            "output_digest": hashlib.sha256(canonical_bytes(result)).hexdigest(),
            "attempt_id": stopped.attempt_id,
        }
    )

    pending = store.prepare_report_validator_replay(stopped, draft_ref, artifacts)
    assert pending.status is StageStatus.PENDING


@pytest.mark.parametrize("invalid", ["root", "draft", "inflight", "stale"])
def test_report_validator_replay_rejects_unbound_or_unverified_state(
    tmp_path: Path, invalid: str
) -> None:
    store, artifacts, stopped, draft_ref, _ = _blocked_report(tmp_path)
    original = store.require(stopped.identity, SimpleStage.REPORT_DONE)
    if invalid == "root":
        root_identity = stopped.identity.model_copy(update={"hypothesis_id": None})
        root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
        store.save_checkpoint(root.model_copy(update={"error_code": "OTHER_CHILD"}))
    elif invalid == "draft":
        draft_ref = artifacts.put_json(
            {
                "kind": "simple_report_draft",
                "attempt_id": stopped.attempt_id,
                "source_refs": [],
                "result": _report_content(),
                "prompt_digest": "b" * 64,
                "output_digest": hashlib.sha256(
                    canonical_bytes(_report_content())
                ).hexdigest(),
            }
        )
    elif invalid == "inflight":
        assert store.begin_codex_call("unfinished-call", stopped.identity.analysis_id)
    else:
        store.save_checkpoint(stopped.model_copy(update={"attempt_id": "new-attempt"}))

    with pytest.raises(ValueError, match="REPORT_VALIDATOR_REPLAY_"):
        store.prepare_report_validator_replay(stopped, draft_ref, artifacts)

    current = store.require(stopped.identity, SimpleStage.REPORT_DONE)
    assert current == (
        stopped.model_copy(update={"attempt_id": "new-attempt"})
        if invalid == "stale"
        else original
    )


def test_report_validator_replay_rejects_unsupported_draft_claim(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, _draft_ref, _ = _blocked_report(tmp_path)
    result = _report_content()
    english = result["en"]
    assert isinstance(english, dict)
    result["en"] = {**english, "summary": "Affected versions 1.2.3"}
    prior = store.prior(stopped.identity, SimpleStage.REPORT_DONE)
    refs = tuple(item.output_refs[0] for item in prior.values())
    draft_ref = artifacts.put_json(
        {
            "kind": "simple_report_draft",
            "source_refs": [ref.model_dump(mode="json") for ref in refs],
            "result": result,
            "prompt_digest": "b" * 64,
            "output_digest": hashlib.sha256(canonical_bytes(result)).hexdigest(),
            "attempt_id": stopped.attempt_id,
        }
    )

    with pytest.raises(ValueError, match="REPORT_VALIDATOR_REPLAY_DRAFT_INVALID"):
        store.prepare_report_validator_replay(stopped, draft_ref, artifacts)
    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == stopped


def test_report_validator_replay_rolls_back_cache_checkpoint_and_event(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, draft_ref, _ = _blocked_report(tmp_path)
    ledger = AgentActivityStore(store.database_path)
    before = ledger.list_analysis(
        stopped.identity.analysis_id, hypothesis_id=stopped.identity.hypothesis_id
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_report_validator_replay(
            stopped, draft_ref, artifacts, fail_before_commit=True
        )
    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == stopped
    assert (
        ledger.list_analysis(
            stopped.identity.analysis_id, hypothesis_id=stopped.identity.hypothesis_id
        )
        == before
    )
    prior = store.prior(stopped.identity, SimpleStage.REPORT_DONE)
    source_hash = hashlib.sha256(
        canonical_bytes(
            {
                "refs": tuple(item.output_refs[0] for item in prior.values()),
                "finding_attempt_id": prior[SimpleStage.FINDING_DONE].attempt_id,
                "poc_attempt_id": prior[SimpleStage.POC_EXECUTION_DONE].attempt_id,
            }
        )
    ).hexdigest()
    assert (
        store.report_draft(
            stopped.identity,
            source_hash,
            prior[SimpleStage.FINDING_DONE].output_refs[0],
        )
        is None
    )


@pytest.mark.asyncio
async def test_application_replays_only_unique_bound_report_draft(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, artifacts, stopped, draft_ref, other_report = _blocked_report(tmp_path)
    identity = stopped.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    older = artifacts.put_json(
        {
            "kind": "simple_report_draft",
            "attempt_id": "report-attempt-1",
            "source_refs": [],
            "result": _report_content(),
        }
    )
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=None,  # type: ignore[arg-type]
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )

    async def resume_locked(_analysis_id: str) -> SimpleAnalysisOutcome:
        return SimpleAnalysisOutcome(
            identity=identity.model_copy(update={"hypothesis_id": None}),
            display_analysis_id="A-001",
            status="RUNNING",
            current_stage=SimpleStage.REPORT_DONE,
        )

    monkeypatch.setattr(application, "_resume_locked", resume_locked)
    await application.resume(
        identity.analysis_id,
        repair_report_validator_hypothesis=identity.hypothesis_id,
    )
    assert (
        store.require(identity, SimpleStage.REPORT_DONE).status is StageStatus.PENDING
    )
    assert store.require(other_report.identity, SimpleStage.REPORT_DONE) == other_report
    assert older != draft_ref


@pytest.mark.asyncio
async def test_application_replays_exhausted_report_without_new_llm_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, stopped, draft_ref = _exhausted_ipv4_report(tmp_path)
    identity = stopped.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=None,  # type: ignore[arg-type]
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )

    async def resume_locked(_analysis_id: str) -> SimpleAnalysisOutcome:
        return SimpleAnalysisOutcome(
            identity=identity.model_copy(update={"hypothesis_id": None}),
            display_analysis_id="A-001",
            status="RUNNING",
            current_stage=SimpleStage.REPORT_DONE,
        )

    monkeypatch.setattr(application, "_resume_locked", resume_locked)
    await application.resume(
        identity.analysis_id,
        repair_report_validator_hypothesis=identity.hypothesis_id,
    )
    pending = store.require(identity, SimpleStage.REPORT_DONE)
    assert pending.status is StageStatus.PENDING
    prior = store.prior(identity, SimpleStage.REPORT_DONE)
    source_hash = hashlib.sha256(
        canonical_bytes(
            {
                "refs": tuple(item.output_refs[0] for item in prior.values()),
                "finding_attempt_id": prior[SimpleStage.FINDING_DONE].attempt_id,
                "poc_attempt_id": prior[SimpleStage.POC_EXECUTION_DONE].attempt_id,
            }
        )
    ).hexdigest()
    assert (
        store.report_draft(
            identity, source_hash, prior[SimpleStage.FINDING_DONE].output_refs[0]
        )
        == draft_ref
    )


@pytest.mark.asyncio
async def test_application_rejects_ambiguous_bound_report_drafts(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, _draft_ref, _other_report = _blocked_report(tmp_path)
    identity = stopped.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    artifacts.put_json(
        {
            "kind": "simple_report_draft",
            "attempt_id": stopped.attempt_id,
            "source_refs": [],
            "result": _report_content(),
        }
    )
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=None,  # type: ignore[arg-type]
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )
    with pytest.raises(ValueError, match="REPORT_VALIDATOR_REPLAY_DRAFT_AMBIGUOUS"):
        await application.resume(
            identity.analysis_id,
            repair_report_validator_hypothesis=identity.hypothesis_id,
        )
    assert store.require(identity, SimpleStage.REPORT_DONE) == stopped


def test_cli_forwards_report_validator_replay_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class _Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_report_validator_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("plain", repair_report_validator_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_report_validator_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("progress", repair_report_validator_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = _Application()
    for extra, label in [(["--format", "json"], "plain"), ([], "progress")]:
        assert main(
            [
                "resume",
                "A-001",
                "--repair-report-validator",
                "hypothesis-1",
                *extra,
            ],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (label, "hypothesis-1")
        capsys.readouterr()
