from __future__ import annotations

import hashlib
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import CommitId, RecordId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.observability.agent_activity import ActivityKind
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.poc import PoCCandidateRejected, validate_candidate
from sastsimi.simple_runtime.recovery import (
    RecoveryAction,
    RecoveryCategory,
    RecoveryDecision,
    RecoveryResolution,
)
from sastsimi.simple_runtime.runner import (
    SimpleRuntimeRunner,
    StageBlocked,
    StageFailed,
)
from sastsimi.simple_runtime.stages import internal_report_status
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore


def _ref(name: str) -> StoredDataRef:
    digest = hashlib.sha256(name.encode()).hexdigest()
    return StoredDataRef(
        stored_data_id=StoredDataId(f"{name}-stored"),
        data_kind="simple_runtime_test",
        content_hash=digest,
        workspace_id=WorkspaceId("workspace-1"),
        commit_id=CommitId("commit-1"),
        record_id=RecordId(f"{name}-record"),
    )


def _identity() -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )


def _checkpoint(
    stage: SimpleStage | str,
    *,
    inputs: tuple[StoredDataRef, ...],
    stage_version: str | None = None,
    attempt_id: str | None = None,
) -> StageCheckpoint:
    normalized_stage = SimpleStage(stage)
    return StageCheckpoint(
        identity=_identity(),
        stage=normalized_stage,
        stage_version=stage_version or STAGE_VERSION[normalized_stage],
        status=StageStatus.PENDING,
        input_refs=inputs,
        input_hash=input_reference_hash(inputs),
        attempt_id=attempt_id,
    )


def _seeded_through(
    store: SimpleCheckpointStore,
    final_stage: SimpleStage,
) -> None:
    inputs = (_ref("hypothesis-input"),)
    for stage in HYPOTHESIS_STAGES:
        output = _ref(f"{stage.value.lower()}-output")
        store.save_success(_checkpoint(stage, inputs=inputs), outputs=(output,))
        inputs = (output,)
        if stage is final_stage:
            return
    raise AssertionError(f"stage not in hypothesis flow: {final_stage}")


def _recording_handlers(
    calls: list[SimpleStage],
    *,
    failed_stage: SimpleStage | None = None,
) -> dict[SimpleStage, object]:
    handlers: dict[SimpleStage, object] = {}
    for current_stage in HYPOTHESIS_STAGES:

        async def handle(
            checkpoint: StageCheckpoint,
            _prior: object,
            *,
            stage: SimpleStage = current_stage,
        ) -> StageResult:
            calls.append(stage)
            if stage is failed_stage:
                raise StageBlocked(
                    StageFailure(
                        code="AUTH_REQUIRED",
                        retryable=True,
                        safe_message="login required",
                    )
                )
            return StageResult(output_refs=(_ref(f"{stage.value.lower()}-result"),))

        handlers[current_stage] = handle
    return handlers


@pytest.mark.asyncio
async def test_unmet_external_prerequisite_ends_hypothesis_without_poc_or_report(
    tmp_path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "external-prereq" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.PRO_CON_DONE)
    calls: list[SimpleStage] = []
    handlers = _recording_handlers(calls)
    initial_ref = _ref("unmet-external-prerequisite")

    async def initial(_checkpoint: StageCheckpoint, _prior: object) -> StageResult:
        calls.append(SimpleStage.VERIFICATION_INITIAL_DONE)
        return StageResult(
            output_refs=(initial_ref,),
            verdict="HOLD",
            external_prerequisites_ref=initial_ref,
        )

    handlers[SimpleStage.VERIFICATION_INITIAL_DONE] = initial
    runner = SimpleRuntimeRunner(store, handlers)
    first = await runner.resume_hypothesis(_identity())
    second = await runner.resume_hypothesis(_identity())

    assert first.status is StageStatus.SUCCEEDED
    assert second.status is StageStatus.SUCCEEDED
    assert first.current_stage is SimpleStage.VERIFICATION_INITIAL_DONE
    assert second.current_stage is SimpleStage.VERIFICATION_INITIAL_DONE
    assert calls == [SimpleStage.VERIFICATION_INITIAL_DONE]
    assert store.get(_identity(), SimpleStage.POC_EXECUTION_DONE) is None
    assert store.get(_identity(), SimpleStage.REPORT_DONE) is None


@pytest.mark.asyncio
async def test_initial_terminal_requires_exact_artifact_during_run(tmp_path) -> None:
    store = SimpleCheckpointStore(tmp_path / "invalid-initial" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.PRO_CON_DONE)
    calls: list[SimpleStage] = []
    handlers = _recording_handlers(calls)
    missing_ref = _ref("missing-initial-evidence")

    async def initial(_checkpoint: StageCheckpoint, _prior: object) -> StageResult:
        calls.append(SimpleStage.VERIFICATION_INITIAL_DONE)
        return StageResult(
            output_refs=(missing_ref,),
            verdict="HOLD",
            external_prerequisites_ref=missing_ref,
        )

    handlers[SimpleStage.VERIFICATION_INITIAL_DONE] = initial
    outcome = await SimpleRuntimeRunner(
        store,
        handlers,
        cleanup_artifacts=SimpleArtifactRepository(tmp_path, _identity()),
    ).resume_hypothesis(_identity())

    assert outcome.status is StageStatus.BLOCKED
    assert outcome.error_code == "INITIAL_VERIFICATION_EVIDENCE_INVALID"
    assert calls == [SimpleStage.VERIFICATION_INITIAL_DONE]
    assert store.get(_identity(), SimpleStage.POC_CANDIDATE_DONE) is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stage_version", ("4", STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE])
)
async def test_legacy_mixed_prerequisite_retries_only_initial_stage_once(
    tmp_path,
    stage_version: str,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "mixed-prereq" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.PRO_CON_DONE)
    pro_con = store.require(_identity(), SimpleStage.PRO_CON_DONE)
    running = store.mark_running(
        _identity(),
        SimpleStage.VERIFICATION_INITIAL_DONE,
        store.input_refs_for(_identity(), SimpleStage.VERIFICATION_INITIAL_DONE),
        attempt_id="mixed-prereq-attempt",
    )
    failed = store.mark_failure(
        running,
        StageFailure(
            code="POC_OFFLINE_REQUIREMENT_UNSUPPORTED",
            retryable=False,
            safe_message="unrecognized requirement",
        ),
        StageStatus.BLOCKED,
    ).model_copy(update={"stage_version": stage_version})
    store.save_checkpoint(failed)
    calls: list[SimpleStage] = []
    handlers = _recording_handlers(calls)
    initial_ref = _ref("separated-prerequisite")

    async def initial(_checkpoint: StageCheckpoint, _prior: object) -> StageResult:
        calls.append(SimpleStage.VERIFICATION_INITIAL_DONE)
        return StageResult(
            output_refs=(initial_ref,),
            verdict="HOLD",
            external_prerequisites_ref=initial_ref,
        )

    handlers[SimpleStage.VERIFICATION_INITIAL_DONE] = initial
    runner = SimpleRuntimeRunner(store, handlers)
    first = await runner.resume_hypothesis(_identity())
    second = await runner.resume_hypothesis(_identity())

    assert first.status is second.status is StageStatus.SUCCEEDED
    assert calls == [SimpleStage.VERIFICATION_INITIAL_DONE]
    assert store.require(_identity(), SimpleStage.PRO_CON_DONE) == pro_con
    assert (
        store.require(_identity(), SimpleStage.VERIFICATION_INITIAL_DONE).attempt_number
        == 2
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stage_version", ("4", STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE])
)
async def test_unsupported_requirement_at_attempt_cap_stays_blocked(
    tmp_path, stage_version: str
) -> None:
    store = SimpleCheckpointStore(tmp_path / "unhandled-prereq" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.PRO_CON_DONE)
    running = store.mark_running(
        _identity(),
        SimpleStage.VERIFICATION_INITIAL_DONE,
        store.input_refs_for(_identity(), SimpleStage.VERIFICATION_INITIAL_DONE),
        attempt_id="unhandled-prereq-attempt",
    )
    failed = store.mark_failure(
        running,
        StageFailure(
            code="POC_OFFLINE_REQUIREMENT_UNSUPPORTED",
            retryable=False,
            safe_message="still an unsupported install requirement",
        ),
        StageStatus.BLOCKED,
    ).model_copy(update={"attempt_number": 3, "stage_version": stage_version})
    store.save_checkpoint(failed)
    calls: list[SimpleStage] = []

    outcome = await SimpleRuntimeRunner(
        store, _recording_handlers(calls)
    ).resume_hypothesis(_identity())

    assert outcome.status is StageStatus.BLOCKED
    assert outcome.error_code == "POC_OFFLINE_REQUIREMENT_UNSUPPORTED"
    assert calls == []
    assert store.require(_identity(), SimpleStage.VERIFICATION_INITIAL_DONE) == failed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "attempt_number,in_flight,expected_replay",
    [(1, False, True), (1, True, False), (3, False, False)],
)
@pytest.mark.parametrize(
    "stage_version", ("5", STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE])
)
async def test_wheel_archive_failure_replays_only_bounded_initial_stage(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    attempt_number: int,
    in_flight: bool,
    expected_replay: bool,
    stage_version: str,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "wheel-recovery" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.PRO_CON_DONE)
    pro_con = store.require(_identity(), SimpleStage.PRO_CON_DONE)
    running = store.mark_running(
        _identity(),
        SimpleStage.VERIFICATION_INITIAL_DONE,
        store.input_refs_for(_identity(), SimpleStage.VERIFICATION_INITIAL_DONE),
        attempt_id="wheel-recovery-attempt",
    )
    failed = store.mark_failure(
        running,
        StageFailure(
            code="WHEEL_ARCHIVE_INVALID",
            retryable=False,
            safe_message="Downloaded wheel could not be read by host",
        ),
        StageStatus.BLOCKED,
    ).model_copy(
        update={"attempt_number": attempt_number, "stage_version": stage_version}
    )
    store.save_checkpoint(failed)
    if in_flight:
        monkeypatch.setattr(store, "unresolved_codex_call", lambda _id: object())
    calls: list[SimpleStage] = []
    runner = SimpleRuntimeRunner(store, _recording_handlers(calls))

    outcome = await runner.resume_hypothesis(_identity())

    assert store.require(_identity(), SimpleStage.PRO_CON_DONE) == pro_con
    if expected_replay:
        assert outcome.status is StageStatus.SUCCEEDED
        assert calls[0] is SimpleStage.VERIFICATION_INITIAL_DONE
        assert (
            store.require(
                _identity(), SimpleStage.VERIFICATION_INITIAL_DONE
            ).attempt_number
            == 2
        )
    else:
        assert outcome.status is StageStatus.BLOCKED
        assert outcome.error_code == "WHEEL_ARCHIVE_INVALID"
        assert calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "stage_version", ("4", STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE])
)
async def test_offline_base_failure_retries_initial_stage_after_local_preflight(
    tmp_path, stage_version: str
) -> None:
    store = SimpleCheckpointStore(tmp_path / "base-recovery" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.PRO_CON_DONE)
    pro_con = store.require(_identity(), SimpleStage.PRO_CON_DONE)
    running = store.mark_running(
        _identity(),
        SimpleStage.VERIFICATION_INITIAL_DONE,
        store.input_refs_for(_identity(), SimpleStage.VERIFICATION_INITIAL_DONE),
        attempt_id="missing-base-attempt",
    )
    failed = store.mark_failure(
        running,
        StageFailure(
            code="POC_OFFLINE_BASE_IMAGE_UNAVAILABLE",
            retryable=False,
            safe_message="Local base image probe failed",
        ),
        StageStatus.BLOCKED,
    ).model_copy(update={"stage_version": stage_version})
    store.save_checkpoint(failed)
    calls: list[SimpleStage] = []
    preflight_count = 0

    async def local_base_ready() -> bool:
        nonlocal preflight_count
        preflight_count += 1
        return True

    handlers = _recording_handlers(calls)
    initial_ref = _ref("base-recovery-initial")

    async def initial(_checkpoint: StageCheckpoint, _prior: object) -> StageResult:
        calls.append(SimpleStage.VERIFICATION_INITIAL_DONE)
        return StageResult(
            output_refs=(initial_ref,),
            verdict="HOLD",
            external_prerequisites_ref=initial_ref,
        )

    handlers[SimpleStage.VERIFICATION_INITIAL_DONE] = initial
    outcome = await SimpleRuntimeRunner(
        store, handlers, offline_base_ready=local_base_ready
    ).resume_hypothesis(_identity())

    assert outcome.status is StageStatus.SUCCEEDED
    assert calls == [SimpleStage.VERIFICATION_INITIAL_DONE]
    assert preflight_count == 1
    assert store.require(_identity(), SimpleStage.PRO_CON_DONE) == pro_con
    assert (
        store.require(_identity(), SimpleStage.VERIFICATION_INITIAL_DONE).attempt_number
        == 2
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error_code,attempt_number,probe_result,in_flight,expected_probes",
    [
        ("POC_OFFLINE_BASE_IMAGE_UNAVAILABLE", 1, False, False, 1),
        ("POC_OFFLINE_BASE_IMAGE_UNAVAILABLE", 1, None, False, 0),
        ("POC_OFFLINE_BASE_IMAGE_UNAVAILABLE", 3, True, False, 0),
        ("POC_OFFLINE_BASE_IMAGE_UNAVAILABLE", 1, True, True, 0),
        ("POC_OFFLINE_MANIFEST_UNSUPPORTED", 1, True, False, 0),
    ],
)
async def test_offline_base_recovery_preserves_blocked_checkpoint_without_guard(
    tmp_path,
    error_code: str,
    attempt_number: int,
    probe_result: bool | None,
    in_flight: bool,
    expected_probes: int,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "base-guard" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.PRO_CON_DONE)
    running = store.mark_running(
        _identity(),
        SimpleStage.VERIFICATION_INITIAL_DONE,
        store.input_refs_for(_identity(), SimpleStage.VERIFICATION_INITIAL_DONE),
        attempt_id="base-guard-attempt",
    )
    failed = store.mark_failure(
        running,
        StageFailure(
            code=error_code,
            retryable=False,
            safe_message="Offline preparation failed",
        ),
        StageStatus.BLOCKED,
    ).model_copy(update={"attempt_number": attempt_number})
    store.save_checkpoint(failed)
    if in_flight:
        assert store.begin_codex_call(
            "unresolved-offline-replay", _identity().analysis_id
        )
    probes = 0

    async def local_base_ready() -> bool:
        nonlocal probes
        probes += 1
        assert probe_result is not None
        return probe_result

    calls: list[SimpleStage] = []
    outcome = await SimpleRuntimeRunner(
        store,
        _recording_handlers(calls),
        offline_base_ready=local_base_ready if probe_result is not None else None,
    ).resume_hypothesis(_identity())

    assert outcome.status is StageStatus.BLOCKED
    assert outcome.error_code == error_code
    assert store.require(_identity(), SimpleStage.VERIFICATION_INITIAL_DONE) == failed
    assert calls == []
    assert probes == expected_probes


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_point", ["db", "docker"])
async def test_offline_base_recovery_fails_closed_when_preflight_errors(
    tmp_path, monkeypatch: pytest.MonkeyPatch, failure_point: str
) -> None:
    store = SimpleCheckpointStore(tmp_path / "probe-error" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.PRO_CON_DONE)
    running = store.mark_running(
        _identity(),
        SimpleStage.VERIFICATION_INITIAL_DONE,
        store.input_refs_for(_identity(), SimpleStage.VERIFICATION_INITIAL_DONE),
        attempt_id="probe-error-attempt",
    )
    failed = store.mark_failure(
        running,
        StageFailure(
            code="POC_OFFLINE_BASE_IMAGE_UNAVAILABLE",
            retryable=False,
            safe_message="Local base image probe failed",
        ),
        StageStatus.BLOCKED,
    )
    if failure_point == "db":

        def fail_db(_analysis_id: str) -> str:
            raise sqlite3.OperationalError("database locked")

        monkeypatch.setattr(store, "unresolved_codex_call", fail_db)
    probes = 0

    async def local_base_ready() -> bool:
        nonlocal probes
        probes += 1
        raise RuntimeError("Docker probe failed")

    calls: list[SimpleStage] = []
    outcome = await SimpleRuntimeRunner(
        store,
        _recording_handlers(calls),
        offline_base_ready=local_base_ready,
    ).resume_hypothesis(_identity())

    assert outcome.status is StageStatus.BLOCKED
    assert outcome.error_code == "POC_OFFLINE_BASE_IMAGE_UNAVAILABLE"
    assert store.require(_identity(), SimpleStage.VERIFICATION_INITIAL_DONE) == failed
    assert calls == []
    assert probes == (0 if failure_point == "db" else 1)


def _cleanup_confirmation(
    artifacts: SimpleArtifactRepository,
    checkpoint: StageCheckpoint,
    *,
    call_id: str,
) -> StoredDataRef:
    return artifacts.put_json(
        {
            "kind": "simple_codex_cleanup_confirmation",
            "analysis_id": checkpoint.identity.analysis_id,
            "stage": checkpoint.stage.value,
            "attempt_id": checkpoint.attempt_id,
            "checkpoint_sha256": hashlib.sha256(
                canonical_bytes(checkpoint)
            ).hexdigest(),
            "call_id": call_id,
            "process_tree_stopped": True,
            "verification_method": "windows_process_inventory",
            "former_parent_pid": 12345,
            "observed_matching_process_count": 0,
            "observed_at": (datetime.now(UTC) + timedelta(seconds=1)).isoformat(),
        }
    )


class _Recovery:
    def __init__(
        self,
        data_dir,
        *actions: RecoveryAction,
    ) -> None:
        self.data_dir = data_dir
        self.actions = list(actions)
        self.calls: list[tuple[StageCheckpoint, StageFailure]] = []
        self.refs: list[StoredDataRef] = []

    async def decide(
        self,
        checkpoint: StageCheckpoint,
        failure: StageFailure,
    ) -> RecoveryResolution:
        self.calls.append((checkpoint, failure))
        action = self.actions.pop(0)
        decision = RecoveryDecision(
            category={
                RecoveryAction.RETRY_STAGE: RecoveryCategory.TRANSIENT_TOOL,
                RecoveryAction.REGENERATE_INPUT: RecoveryCategory.GENERATED_INPUT,
                RecoveryAction.REBUILD_ENVIRONMENT: RecoveryCategory.ENVIRONMENT,
                RecoveryAction.STOP: RecoveryCategory.TERMINAL,
            }[action],
            action=action,
            diagnosis="test diagnosis",
            guidance="repair the exact recorded failure",
            environment_patch=(
                "RUN python -m pip install -e '.[test]'"
                if action is RecoveryAction.REBUILD_ENVIRONMENT
                else ""
            ),
        )
        ref = SimpleArtifactRepository(self.data_dir, checkpoint.identity).put_json(
            {
                "kind": "simple_recovery_decision",
                "decision": decision.model_dump(mode="json"),
            }
        )
        self.refs.append(ref)
        return RecoveryResolution(decision=decision, decision_ref=ref)


@pytest.mark.asyncio
async def test_resume_reuses_exact_success_and_invalidates_changed_downstream(
    tmp_path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    first = _checkpoint("POC_EXECUTION_DONE", inputs=(_ref("candidate-a"),))
    store.save_success(first, outputs=(_ref("execution-a"),))
    store.save_success(
        _checkpoint("TECH_GATE_DONE", inputs=(_ref("execution-a"),)),
        outputs=(_ref("gate-a"),),
    )

    assert store.reusable(first.identity, first.stage, first.input_refs)
    store.invalidate_from(
        first.identity,
        SimpleStage.POC_EXECUTION_DONE,
        new_inputs=(_ref("candidate-b"),),
    )

    assert not store.reusable(
        first.identity,
        SimpleStage.POC_EXECUTION_DONE,
        (_ref("candidate-b"),),
    )
    assert store.get(first.identity, SimpleStage.TECH_GATE_DONE) is None

    calls: list[SimpleStage] = []
    resumable_store = SimpleCheckpointStore(tmp_path / "resume" / "sastsimi.sqlite3")
    _seeded_through(resumable_store, SimpleStage.VERIFICATION_INITIAL_DONE)

    outcome = await SimpleRuntimeRunner(
        resumable_store,
        _recording_handlers(calls),
    ).resume_analysis(_identity())

    assert calls[0] is SimpleStage.POC_CANDIDATE_DONE
    assert SimpleStage.STATIC_DONE not in calls
    assert SimpleStage.HYPOTHESIS_DONE not in calls
    assert outcome.current_stage is SimpleStage.REPORT_DONE


@pytest.mark.asyncio
async def test_resume_revalidates_legacy_v2_poc_without_rerunning_upstream(
    tmp_path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "legacy-poc" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.REPORT_DONE)
    old_poc = store.require(_identity(), SimpleStage.POC_EXECUTION_DONE)
    store.save_checkpoint(
        old_poc.model_copy(
            update={
                "stage_version": "2",
                "validated_poc_ref": _ref("legacy-validated-poc"),
            }
        )
    )
    upstream = {
        stage: store.require(_identity(), stage)
        for stage in (
            SimpleStage.PRO_CON_DONE,
            SimpleStage.VERIFICATION_INITIAL_DONE,
            SimpleStage.POC_CANDIDATE_DONE,
        )
    }

    calls: list[SimpleStage] = []
    outcome = await SimpleRuntimeRunner(
        store, _recording_handlers(calls)
    ).resume_hypothesis(_identity())

    assert outcome.status is StageStatus.SUCCEEDED
    assert calls[0] is SimpleStage.POC_EXECUTION_DONE
    assert all(stage not in calls for stage in upstream)
    for stage, old in upstream.items():
        assert store.require(_identity(), stage) == old
    refreshed = store.require(_identity(), SimpleStage.POC_EXECUTION_DONE)
    assert refreshed.stage_version == STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE]
    assert refreshed.validated_poc_ref is None
    assert SimpleStage.REPORT_DONE in calls


@pytest.mark.asyncio
async def test_poc_execution_retry_starts_a_new_candidate_attempt(tmp_path) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.VERIFICATION_INITIAL_DONE)
    candidate_inputs = store.input_refs_for(
        _identity(),
        SimpleStage.POC_CANDIDATE_DONE,
    )
    old_attempt_id = "poc-attempt-old"
    candidate = _checkpoint(
        SimpleStage.POC_CANDIDATE_DONE,
        inputs=candidate_inputs,
        attempt_id=old_attempt_id,
    )
    store.save_success(candidate, outputs=(_ref("candidate-old"),))
    execution = store.mark_running(
        _identity(),
        SimpleStage.POC_EXECUTION_DONE,
        (_ref("candidate-old"),),
        attempt_id=old_attempt_id,
        inherit_from=store.require(_identity(), SimpleStage.POC_CANDIDATE_DONE),
    )
    store.mark_failure(
        execution,
        StageFailure(
            code="POC_INVALID_OUTPUT",
            retryable=True,
            safe_message="retry the PoC attempt",
            evidence_refs=(_ref("execution-failure"),),
        ),
        StageStatus.BLOCKED,
    )
    # Simulate a crash/recovery boundary where the append-only activity log
    # survived but the execution checkpoint was invalidated.
    store.invalidate_from(
        _identity(),
        SimpleStage.POC_EXECUTION_DONE,
        new_inputs=(_ref("candidate-old"),),
        force=True,
    )
    assert store.get(_identity(), SimpleStage.POC_EXECUTION_DONE) is None

    calls: list[SimpleStage] = []
    outcome = await SimpleRuntimeRunner(
        store,
        _recording_handlers(calls),
    ).resume_analysis(_identity())

    retried_candidate = store.require(_identity(), SimpleStage.POC_CANDIDATE_DONE)
    retried_execution = store.require(_identity(), SimpleStage.POC_EXECUTION_DONE)
    assert calls[:2] == [
        SimpleStage.POC_CANDIDATE_DONE,
        SimpleStage.POC_EXECUTION_DONE,
    ]
    assert retried_candidate.attempt_id != old_attempt_id
    assert retried_execution.attempt_id == retried_candidate.attempt_id
    assert _ref("candidate-old") in retried_candidate.input_refs
    assert _ref("execution-failure") in retried_candidate.input_refs
    assert outcome.current_stage is SimpleStage.REPORT_DONE


@pytest.mark.asyncio
async def test_resume_legacy_invalid_output_retries_only_failed_stage(tmp_path) -> None:
    store = SimpleCheckpointStore(tmp_path / "legacy-invalid" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.POC_CANDIDATE_DONE)
    candidate = store.require(_identity(), SimpleStage.POC_CANDIDATE_DONE)
    store.save_checkpoint(
        candidate.model_copy(
            update={"attempt_id": "legacy-attempt-1", "attempt_number": 1}
        )
    )
    prior = store.prior(_identity(), SimpleStage.POC_EXECUTION_DONE)
    execution = store.mark_running(
        _identity(),
        SimpleStage.POC_EXECUTION_DONE,
        store.input_refs_for(_identity(), SimpleStage.POC_EXECUTION_DONE),
        attempt_id="legacy-attempt-1",
    )
    store.mark_failure(
        execution,
        StageFailure(
            code="INVALID_OUTPUT",
            retryable=False,
            safe_message="invalid structured output",
        ),
        StageStatus.FAILED,
    )
    calls: list[SimpleStage] = []

    outcome = await SimpleRuntimeRunner(
        store, _recording_handlers(calls), codex_invalid_output_resume=True
    ).resume_hypothesis(_identity())

    retried = store.require(_identity(), SimpleStage.POC_EXECUTION_DONE)
    assert outcome.status is StageStatus.SUCCEEDED
    assert calls[0] is SimpleStage.POC_EXECUTION_DONE
    assert calls.count(SimpleStage.POC_EXECUTION_DONE) == 1
    assert all(stage not in prior for stage in calls)
    assert store.prior(_identity(), SimpleStage.POC_EXECUTION_DONE) == prior
    assert retried.status is StageStatus.SUCCEEDED
    assert retried.attempt_number == 2
    assert retried.attempt_id != "legacy-attempt-1"


@pytest.mark.asyncio
async def test_resume_pending_legacy_retry_keeps_succeeded_candidate(tmp_path) -> None:
    store = SimpleCheckpointStore(tmp_path / "legacy-pending" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.POC_CANDIDATE_DONE)
    candidate = store.require(_identity(), SimpleStage.POC_CANDIDATE_DONE).model_copy(
        update={"attempt_id": "legacy-attempt-1", "attempt_number": 1}
    )
    store.save_checkpoint(candidate)
    execution = store.mark_running(
        _identity(),
        SimpleStage.POC_EXECUTION_DONE,
        store.input_refs_for(_identity(), SimpleStage.POC_EXECUTION_DONE),
        attempt_id="legacy-attempt-1",
    )
    failed = store.mark_failure(
        execution,
        StageFailure(
            code="INVALID_OUTPUT",
            retryable=False,
            safe_message="invalid structured output",
        ),
        StageStatus.FAILED,
    )
    store.replace_from(
        failed.model_copy(
            update={
                "status": StageStatus.PENDING,
                "output_refs": (),
                "attempt_id": None,
                "error_code": None,
            }
        )
    )
    calls: list[SimpleStage] = []

    outcome = await SimpleRuntimeRunner(
        store, _recording_handlers(calls)
    ).resume_hypothesis(_identity())

    assert outcome.status is StageStatus.SUCCEEDED
    assert calls[0] is SimpleStage.POC_EXECUTION_DONE
    assert store.require(_identity(), SimpleStage.POC_CANDIDATE_DONE) == candidate
    assert (
        store.require(_identity(), SimpleStage.POC_EXECUTION_DONE).attempt_number == 2
    )


@pytest.mark.asyncio
async def test_resume_legacy_invalid_output_stops_after_three_failed_attempts(
    tmp_path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "legacy-exhaust" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.POC_CANDIDATE_DONE)
    candidate = store.require(_identity(), SimpleStage.POC_CANDIDATE_DONE).model_copy(
        update={"attempt_id": "legacy-attempt-1", "attempt_number": 1}
    )
    store.save_checkpoint(candidate)
    execution = store.mark_running(
        _identity(),
        SimpleStage.POC_EXECUTION_DONE,
        store.input_refs_for(_identity(), SimpleStage.POC_EXECUTION_DONE),
        attempt_id="legacy-attempt-1",
    )
    store.mark_failure(
        execution,
        StageFailure(
            code="INVALID_OUTPUT",
            retryable=False,
            safe_message="invalid structured output",
        ),
        StageStatus.FAILED,
    )
    calls: list[SimpleStage] = []
    handlers = _recording_handlers(calls)

    async def invalid_output(
        _checkpoint: StageCheckpoint,
        _prior: object,
    ) -> StageResult:
        calls.append(SimpleStage.POC_EXECUTION_DONE)
        raise StageFailed(
            StageFailure(
                code="INVALID_OUTPUT",
                retryable=False,
                safe_message="still invalid structured output",
            )
        )

    handlers[SimpleStage.POC_EXECUTION_DONE] = invalid_output
    runner = SimpleRuntimeRunner(store, handlers, codex_invalid_output_resume=True)
    outcomes = [await runner.resume_hypothesis(_identity()) for _ in range(3)]

    exhausted = store.require(_identity(), SimpleStage.POC_EXECUTION_DONE)
    assert [outcome.error_code for outcome in outcomes] == [
        "INVALID_OUTPUT",
        "INVALID_OUTPUT",
        "INVALID_OUTPUT",
    ]
    assert calls == [SimpleStage.POC_EXECUTION_DONE] * 2
    assert exhausted.status is StageStatus.FAILED
    assert exhausted.attempt_number == 3
    assert exhausted.retryable is False
    assert store.require(_identity(), SimpleStage.POC_CANDIDATE_DONE) == candidate


@pytest.mark.asyncio
async def test_retryable_codex_invalid_output_resume_keeps_candidate_and_stops_at_three(
    tmp_path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "codex-invalid" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.POC_CANDIDATE_DONE)
    candidate = store.require(_identity(), SimpleStage.POC_CANDIDATE_DONE)
    execution = store.mark_running(
        _identity(),
        SimpleStage.POC_EXECUTION_DONE,
        store.input_refs_for(_identity(), SimpleStage.POC_EXECUTION_DONE),
        attempt_id="codex-invalid-1",
    )
    store.mark_failure(
        execution,
        StageFailure(
            code="INVALID_OUTPUT",
            retryable=True,
            safe_message="Codex returned invalid structured output",
        ),
        StageStatus.BLOCKED,
    )
    calls: list[SimpleStage] = []
    handlers = _recording_handlers(calls)

    async def invalid_output(
        _checkpoint: StageCheckpoint,
        _prior: object,
    ) -> StageResult:
        calls.append(SimpleStage.POC_EXECUTION_DONE)
        raise StageBlocked(
            StageFailure(
                code="INVALID_OUTPUT",
                retryable=True,
                safe_message="Codex returned invalid structured output",
            )
        )

    handlers[SimpleStage.POC_EXECUTION_DONE] = invalid_output
    runner = SimpleRuntimeRunner(store, handlers, codex_invalid_output_resume=True)
    outcomes = [await runner.resume_hypothesis(_identity()) for _ in range(3)]

    failed = store.require(_identity(), SimpleStage.POC_EXECUTION_DONE)
    assert [outcome.error_code for outcome in outcomes] == ["INVALID_OUTPUT"] * 3
    assert calls == [SimpleStage.POC_EXECUTION_DONE] * 2
    assert failed.status is StageStatus.BLOCKED
    assert failed.attempt_number == 3
    assert failed.retryable is False
    assert store.require(_identity(), SimpleStage.POC_CANDIDATE_DONE) == candidate


@pytest.mark.asyncio
async def test_non_codex_terminal_invalid_output_is_not_retried(tmp_path) -> None:
    store = SimpleCheckpointStore(tmp_path / "other-invalid" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.POC_CANDIDATE_DONE)
    execution = store.mark_running(
        _identity(),
        SimpleStage.POC_EXECUTION_DONE,
        store.input_refs_for(_identity(), SimpleStage.POC_EXECUTION_DONE),
        attempt_id="other-invalid-1",
    )
    store.mark_failure(
        execution,
        StageFailure(
            code="INVALID_OUTPUT",
            retryable=False,
            safe_message="Other provider returned invalid output",
        ),
        StageStatus.FAILED,
    )
    calls: list[SimpleStage] = []

    outcome = await SimpleRuntimeRunner(
        store, _recording_handlers(calls)
    ).resume_hypothesis(_identity())

    assert outcome.status is StageStatus.FAILED
    assert outcome.error_code == "INVALID_OUTPUT"
    assert calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "error_code",
    [
        "AUTH_REQUIRED",
        "MODEL_OR_REQUEST_UNSUPPORTED",
        "SIMPLE_RUNTIME_REFERENCE_SCOPE_MISMATCH",
        "RECOVERY_EXHAUSTED",
    ],
)
@pytest.mark.parametrize(
    "stage_version", ("2", STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE])
)
async def test_resume_preserves_other_terminal_poc_failures(
    tmp_path, error_code: str, stage_version: str
) -> None:
    store = SimpleCheckpointStore(
        tmp_path / f"{error_code}-{stage_version}" / "sastsimi.sqlite3"
    )
    _seeded_through(store, SimpleStage.POC_CANDIDATE_DONE)
    candidate = store.require(_identity(), SimpleStage.POC_CANDIDATE_DONE)
    execution = store.mark_running(
        _identity(),
        SimpleStage.POC_EXECUTION_DONE,
        store.input_refs_for(_identity(), SimpleStage.POC_EXECUTION_DONE),
        attempt_id="terminal-attempt-1",
    )
    status = (
        StageStatus.BLOCKED
        if error_code == "RECOVERY_EXHAUSTED"
        else StageStatus.FAILED
    )
    failed = store.mark_failure(
        execution,
        StageFailure(
            code=error_code,
            retryable=False,
            safe_message="terminal failure",
        ),
        status,
    )
    failed = failed.model_copy(update={"stage_version": stage_version})
    store.save_checkpoint(failed)
    calls: list[SimpleStage] = []

    outcome = await SimpleRuntimeRunner(
        store, _recording_handlers(calls)
    ).resume_hypothesis(_identity())

    assert outcome.status is status
    assert outcome.error_code == error_code
    assert calls == []
    assert store.require(_identity(), SimpleStage.POC_CANDIDATE_DONE) == candidate
    assert store.require(_identity(), SimpleStage.POC_EXECUTION_DONE) == failed


@pytest.mark.asyncio
async def test_poc_candidate_stage_version_upgrade_preserves_exhausted_poc(
    tmp_path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "candidate-upgrade" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.POC_CANDIDATE_DONE)
    old_candidate = store.require(_identity(), SimpleStage.POC_CANDIDATE_DONE)
    # A prompt version upgrade must not erase the previous recovery cap.
    stale_candidate = old_candidate.model_copy(update={"stage_version": "5"})
    store.save_checkpoint(stale_candidate)
    execution = store.mark_running(
        _identity(),
        SimpleStage.POC_EXECUTION_DONE,
        store.input_refs_for(_identity(), SimpleStage.POC_EXECUTION_DONE),
        attempt_id="exhausted-attempt",
    )
    exhausted = store.mark_failure(
        execution,
        StageFailure(
            code="RECOVERY_EXHAUSTED",
            retryable=False,
            safe_message="previous candidate could not execute",
        ),
        StageStatus.BLOCKED,
    )
    calls: list[SimpleStage] = []

    outcome = await SimpleRuntimeRunner(
        store, _recording_handlers(calls)
    ).resume_hypothesis(_identity())

    assert outcome.status is StageStatus.BLOCKED
    assert outcome.error_code == "RECOVERY_EXHAUSTED"
    assert calls == []
    assert store.require(_identity(), SimpleStage.POC_CANDIDATE_DONE) == stale_candidate
    assert store.require(_identity(), SimpleStage.POC_EXECUTION_DONE) == exhausted


@pytest.mark.asyncio
async def test_legacy_invalid_output_at_attempt_cap_is_not_replayed(tmp_path) -> None:
    store = SimpleCheckpointStore(tmp_path / "legacy-cap" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.POC_CANDIDATE_DONE)
    running = store.mark_running(
        _identity(),
        SimpleStage.POC_EXECUTION_DONE,
        store.input_refs_for(_identity(), SimpleStage.POC_EXECUTION_DONE),
        attempt_id="legacy-capped-attempt",
    )
    failed = store.mark_failure(
        running,
        StageFailure(
            code="INVALID_OUTPUT", retryable=False, safe_message="invalid output"
        ),
        StageStatus.FAILED,
    ).model_copy(update={"stage_version": "2", "attempt_number": 3})
    store.save_checkpoint(failed)
    calls: list[SimpleStage] = []

    outcome = await SimpleRuntimeRunner(
        store, _recording_handlers(calls), codex_invalid_output_resume=True
    ).resume_hypothesis(_identity())

    assert outcome.status is StageStatus.FAILED
    assert outcome.error_code == "INVALID_OUTPUT"
    assert calls == []
    assert store.require(_identity(), SimpleStage.POC_EXECUTION_DONE) == failed


@pytest.mark.asyncio
async def test_legacy_invalid_output_preserves_attempt_count_during_upgrade(
    tmp_path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "legacy-retry" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.POC_CANDIDATE_DONE)
    running = store.mark_running(
        _identity(),
        SimpleStage.POC_EXECUTION_DONE,
        store.input_refs_for(_identity(), SimpleStage.POC_EXECUTION_DONE),
        attempt_id="legacy-second-attempt",
    )
    failed = store.mark_failure(
        running,
        StageFailure(
            code="INVALID_OUTPUT", retryable=False, safe_message="invalid output"
        ),
        StageStatus.FAILED,
    ).model_copy(update={"stage_version": "2", "attempt_number": 2})
    store.save_checkpoint(failed)
    calls: list[SimpleStage] = []
    handlers = _recording_handlers(calls)

    async def invalid_output(
        _checkpoint: StageCheckpoint,
        _prior: object,
    ) -> StageResult:
        calls.append(SimpleStage.POC_EXECUTION_DONE)
        raise StageFailed(
            StageFailure(
                code="INVALID_OUTPUT",
                retryable=False,
                safe_message="still invalid output",
            )
        )

    handlers[SimpleStage.POC_EXECUTION_DONE] = invalid_output
    runner = SimpleRuntimeRunner(store, handlers, codex_invalid_output_resume=True)
    first = await runner.resume_hypothesis(_identity())
    second = await runner.resume_hypothesis(_identity())

    upgraded = store.require(_identity(), SimpleStage.POC_EXECUTION_DONE)
    assert first.error_code == second.error_code == "INVALID_OUTPUT"
    assert calls == [SimpleStage.POC_EXECUTION_DONE]
    assert upgraded.attempt_number == 3
    assert upgraded.stage_version == STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE]


@pytest.mark.asyncio
async def test_legacy_inconclusive_stop_is_not_replayed_by_version_bump(
    tmp_path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "legacy-stop" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.POC_CANDIDATE_DONE)
    running = store.mark_running(
        _identity(),
        SimpleStage.POC_EXECUTION_DONE,
        store.input_refs_for(_identity(), SimpleStage.POC_EXECUTION_DONE),
        attempt_id="legacy-stop-attempt",
    )
    failed = store.mark_failure(
        running,
        StageFailure(
            code="POC_INCONCLUSIVE",
            retryable=True,
            safe_message="insufficient evidence",
            evidence_refs=(_ref("legacy-execution"), _ref("legacy-interpretation")),
        ),
        StageStatus.BLOCKED,
    ).model_copy(update={"stage_version": "2"})
    store.save_checkpoint(failed)
    recovery = _Recovery(tmp_path, RecoveryAction.STOP)
    resolution = await recovery.decide(
        failed,
        StageFailure(
            code="POC_INCONCLUSIVE",
            retryable=True,
            safe_message="insufficient evidence",
            evidence_refs=failed.output_refs,
        ),
    )
    stopped = store.record_recovery_stop(failed, resolution)
    for upstream in (
        SimpleStage.VERIFICATION_INITIAL_DONE,
        SimpleStage.POC_CANDIDATE_DONE,
    ):
        previous = store.require(_identity(), upstream)
        store.save_checkpoint(previous.model_copy(update={"stage_version": "5"}))
    calls: list[SimpleStage] = []

    outcome = await SimpleRuntimeRunner(
        store,
        _recording_handlers(calls),
        recovery=_Recovery(tmp_path, RecoveryAction.RETRY_STAGE),
        cleanup_artifacts=SimpleArtifactRepository(tmp_path, _identity()),
    ).resume_hypothesis(_identity())

    assert outcome.status is StageStatus.BLOCKED
    assert outcome.error_code == "POC_INCONCLUSIVE"
    assert calls == []
    assert store.require(_identity(), SimpleStage.POC_EXECUTION_DONE) == stopped


@pytest.mark.asyncio
async def test_legacy_poc_import_stop_is_not_replayed_by_new_replan_rule(
    tmp_path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "legacy-import-stop" / "sastsimi.sqlite3")
    artifacts = SimpleArtifactRepository(tmp_path, _identity())
    _seeded_through(store, SimpleStage.POC_CANDIDATE_DONE)
    running = store.mark_running(
        _identity(),
        SimpleStage.POC_EXECUTION_DONE,
        store.input_refs_for(_identity(), SimpleStage.POC_EXECUTION_DONE),
        attempt_id="legacy-import-stop-attempt",
    )
    stderr_ref = artifacts.put_bytes(
        b"ModuleNotFoundError: jwt\nTraceback: frame -> exec_module",
        "text/plain",
    )
    execution_ref = artifacts.put_json(
        {
            "kind": "simple_poc_execution",
            "attempt_id": running.attempt_id,
            "stderr_ref": stderr_ref.model_dump(mode="json"),
        }
    )
    failure = StageFailure(
        code="POC_EXECUTION_FAILED",
        retryable=True,
        safe_message="legacy PoC failed",
        evidence_refs=(execution_ref, stderr_ref),
    )
    failed = store.mark_failure(running, failure, StageStatus.BLOCKED)
    resolution = await _Recovery(tmp_path, RecoveryAction.STOP).decide(failed, failure)
    stopped = store.record_recovery_stop(failed, resolution)
    calls: list[SimpleStage] = []
    attempted_recovery = _Recovery(tmp_path, RecoveryAction.RETRY_STAGE)

    outcome = await SimpleRuntimeRunner(
        store,
        _recording_handlers(calls),
        recovery=attempted_recovery,
        cleanup_artifacts=artifacts,
    ).resume_hypothesis(_identity())

    assert outcome.status is StageStatus.BLOCKED
    assert outcome.error_code == "POC_EXECUTION_FAILED"
    assert calls == []
    assert attempted_recovery.calls == []
    assert store.require(_identity(), SimpleStage.POC_EXECUTION_DONE) == stopped


@pytest.mark.asyncio
async def test_confirmed_running_child_cleanup_replays_without_generic_recovery(
    tmp_path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.VERIFICATION_INITIAL_DONE)
    prior = store.require(_identity(), SimpleStage.VERIFICATION_INITIAL_DONE)
    stage = SimpleStage.POC_CANDIDATE_DONE
    running = store.mark_running(
        _identity(),
        stage,
        store.input_refs_for(_identity(), stage),
        attempt_id="interrupted-child-attempt",
    )
    call_id = "interrupted-child-call"
    assert store.begin_codex_call(call_id, _identity().analysis_id)
    artifacts = SimpleArtifactRepository(tmp_path, _identity())
    confirmation = _cleanup_confirmation(artifacts, running, call_id=call_id)
    store.confirm_codex_cleanup(running, confirmation, artifacts)
    calls: list[SimpleStage] = []
    recovery = _Recovery(tmp_path, RecoveryAction.STOP)
    runner = SimpleRuntimeRunner(
        store,
        _recording_handlers(calls),
        recovery=recovery,
        cleanup_artifacts=artifacts,
    )

    resumed = await runner.resume_hypothesis(_identity())

    replayed = store.require(_identity(), stage)
    assert resumed.status is StageStatus.SUCCEEDED
    assert resumed.current_stage is SimpleStage.REPORT_DONE
    assert calls[0] is stage
    assert recovery.calls == []
    assert store.require(_identity(), SimpleStage.VERIFICATION_INITIAL_DONE) == prior
    assert replayed.status is StageStatus.SUCCEEDED
    assert replayed.attempt_id != running.attempt_id
    assert replayed.attempt_number == running.attempt_number + 1


@pytest.mark.asyncio
async def test_confirmed_child_cleanup_replays_only_failed_stage(tmp_path) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.VERIFICATION_INITIAL_DONE)
    prior = store.require(_identity(), SimpleStage.VERIFICATION_INITIAL_DONE)
    stage = SimpleStage.POC_CANDIDATE_DONE
    running = store.mark_running(
        _identity(),
        stage,
        store.input_refs_for(_identity(), stage),
        attempt_id="cleanup-attempt",
    )
    failed = store.mark_failure(
        running,
        StageFailure(
            code="CODEX_PROCESS_CLEANUP_UNCONFIRMED",
            retryable=False,
            safe_message="Codex process cleanup is unknown",
        ),
        StageStatus.BLOCKED,
    )
    artifacts = SimpleArtifactRepository(tmp_path, _identity())
    calls: list[SimpleStage] = []
    runner = SimpleRuntimeRunner(
        store, _recording_handlers(calls), cleanup_artifacts=artifacts
    )

    unconfirmed = await runner.resume_hypothesis(_identity())
    assert unconfirmed.status is StageStatus.BLOCKED
    assert unconfirmed.error_code == "CODEX_PROCESS_CLEANUP_UNCONFIRMED"
    assert calls == []
    assert store.require(_identity(), stage) == failed

    call_id = "tracked-cleanup-call"
    assert store.begin_codex_call(call_id, _identity().analysis_id)
    confirmation = _cleanup_confirmation(artifacts, failed, call_id=call_id)
    store.confirm_codex_cleanup(failed, confirmation, artifacts)
    resumed = await runner.resume_hypothesis(_identity())

    replayed = store.require(_identity(), stage)
    assert resumed.status is StageStatus.SUCCEEDED
    assert resumed.current_stage is SimpleStage.REPORT_DONE
    assert calls[0] is stage
    assert SimpleStage.PRO_CON_DONE not in calls
    assert SimpleStage.VERIFICATION_INITIAL_DONE not in calls
    assert store.require(_identity(), SimpleStage.VERIFICATION_INITIAL_DONE) == prior
    assert replayed.status is StageStatus.SUCCEEDED
    assert replayed.attempt_id != failed.attempt_id
    assert replayed.attempt_number == failed.attempt_number + 1


@pytest.mark.asyncio
async def test_confirmed_cleanup_replays_sibling_blocked_by_same_call(tmp_path) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    stage = SimpleStage.PRO_CON_DONE
    call_id = "shared-tracked-call"
    assert store.begin_codex_call(call_id, _identity().analysis_id)
    first = store.mark_running(
        _identity(), stage, (_ref("first-proposal"),), attempt_id="first-attempt"
    )
    failed = store.mark_failure(
        first,
        StageFailure(
            code="CODEX_PROCESS_CLEANUP_UNCONFIRMED",
            retryable=False,
            safe_message="Codex process cleanup is unknown",
        ),
        StageStatus.BLOCKED,
    )
    sibling = _identity().model_copy(update={"hypothesis_id": "hypothesis-2"})
    other = store.mark_running(
        sibling, stage, (_ref("sibling-proposal"),), attempt_id="sibling-attempt"
    )
    blocked = store.mark_failure(
        other,
        StageFailure(
            code="CODEX_CALL_IN_FLIGHT_UNRESOLVED",
            retryable=False,
            safe_message="A prior Codex call is unresolved",
        ),
        StageStatus.BLOCKED,
    )
    artifacts = SimpleArtifactRepository(tmp_path, sibling)
    calls: list[SimpleStage] = []
    runner = SimpleRuntimeRunner(
        store, _recording_handlers(calls), cleanup_artifacts=artifacts
    )

    without_confirmation = await runner.resume_hypothesis(sibling)
    assert without_confirmation.status is StageStatus.BLOCKED
    assert without_confirmation.error_code == "CODEX_CALL_IN_FLIGHT_UNRESOLVED"
    assert calls == []
    assert store.require(sibling, stage) == blocked

    source_artifacts = SimpleArtifactRepository(tmp_path, _identity())
    confirmation = _cleanup_confirmation(source_artifacts, failed, call_id=call_id)
    store.confirm_codex_cleanup(failed, confirmation, source_artifacts)
    source_runner = SimpleRuntimeRunner(
        store,
        _recording_handlers([]),
        cleanup_artifacts=source_artifacts,
    )
    source_resumed = await source_runner.resume_hypothesis(_identity())
    assert source_resumed.status is StageStatus.SUCCEEDED
    assert store.require(_identity(), stage).status is StageStatus.SUCCEEDED
    resumed = await runner.resume_hypothesis(sibling)

    replayed = store.require(sibling, stage)
    assert resumed.status is StageStatus.SUCCEEDED
    assert calls[0] is stage
    assert replayed.status is StageStatus.SUCCEEDED
    assert replayed.attempt_id != blocked.attempt_id
    assert replayed.attempt_number == blocked.attempt_number + 1


def test_report_format_upgrade_reuses_earlier_stages_but_not_old_report(
    tmp_path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    inputs = (_ref("finding"),)
    store.save_success(
        _checkpoint(SimpleStage.REPORT_DONE, inputs=inputs, stage_version="1"),
        outputs=(_ref("old-report"),),
    )
    store.save_success(
        _checkpoint(SimpleStage.FINDING_DONE, inputs=inputs),
        outputs=(_ref("finding-output"),),
    )

    assert not store.reusable(_identity(), SimpleStage.REPORT_DONE, inputs)
    assert store.reusable(_identity(), SimpleStage.FINDING_DONE, inputs)


@pytest.mark.asyncio
async def test_failed_transaction_never_publishes_success_or_false(tmp_path) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    current = _checkpoint("POC_EXECUTION_DONE", inputs=(_ref("candidate-a"),))

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.save_success(
            current,
            outputs=(_ref("execution-a"),),
            fail_before_commit=True,
        )

    restored = store.get(current.identity, current.stage)
    assert restored is None or restored.status != StageStatus.SUCCEEDED
    assert store.validated_poc(current.identity) is None
    assert store.verdict(current.identity) is None

    resumable_store = SimpleCheckpointStore(tmp_path / "failure" / "sastsimi.sqlite3")
    _seeded_through(resumable_store, SimpleStage.VERIFICATION_INITIAL_DONE)
    outcome = await SimpleRuntimeRunner(
        resumable_store,
        _recording_handlers([], failed_stage=SimpleStage.POC_CANDIDATE_DONE),
    ).resume_analysis(_identity())

    assert outcome.status is StageStatus.BLOCKED
    assert resumable_store.verdict(_identity()) is None
    assert resumable_store.validated_poc(_identity()) is None
    assert resumable_store.get(_identity(), SimpleStage.TECH_GATE_DONE) is None
    assert resumable_store.get(_identity(), SimpleStage.REPORT_DONE) is None

    with pytest.raises(PoCCandidateRejected, match="POC_UNDECLARED_INPUT"):
        validate_candidate(
            b'#!/bin/sh\n: "${POC_URL:?required}"\n',
            allowed_environment_names=frozenset(),
        )

    assert validate_candidate(
        b"#!/bin/sh\nset -eu\npython - <<'PY'\nprint('supported')\nPY\n",
        allowed_environment_names=frozenset(),
    )
    assert validate_candidate(
        b'#!/bin/sh\nset -eu\nfixture=/tmp/input\nprintf x > "$fixture"\n',
        allowed_environment_names=frozenset(),
    )


def test_poc_candidate_validator_allows_localhost_url() -> None:
    assert validate_candidate(
        b"#!/bin/sh\nset -eu\nprintf '%s\\n' 'http://localhost/test'\n",
        allowed_environment_names=frozenset(),
    )


def test_poc_candidate_validator_rejects_shell_literal_dollar() -> None:
    with pytest.raises(PoCCandidateRejected, match="POC_UNDECLARED_INPUT"):
        validate_candidate(
            b"#!/bin/sh\nset -eu\nprintf '%s\\n' '{\"name\":{\"$ne\":null}}'\n",
            allowed_environment_names=frozenset(),
        )
    with pytest.raises(PoCCandidateRejected, match="POC_UNDECLARED_INPUT"):
        validate_candidate(
            b"#!/bin/sh\npython - <<'PY'\nquery = {'$ne': None}\nprint(query)\nPY\n",
            allowed_environment_names=frozenset(),
        )
    assert validate_candidate(
        b"#!/bin/sh\npython - <<'PY'\n"
        b"query = {chr(36) + 'ne': None}\nprint(query)\nPY\n",
        allowed_environment_names=frozenset(),
    )


@pytest.mark.parametrize(
    "opener",
    (b"<<'PY'", b'<<"PY"', b"<<\\PY", b"<<-'PY'"),
)
def test_poc_candidate_validator_rejects_literal_dollar_in_quoted_heredoc(
    opener: bytes,
) -> None:
    with pytest.raises(PoCCandidateRejected, match="POC_UNDECLARED_INPUT"):
        validate_candidate(
            b"#!/bin/sh\npython3 - "
            + opener
            + b"\nprint({'$ne': 'fixture_absent'})\nPY\n",
            allowed_environment_names=frozenset(),
        )


def test_poc_candidate_validator_still_rejects_expanded_undeclared_inputs() -> None:
    for script in (
        b'#!/bin/sh\nprintf "%s\\n" "$ne"\n',
        b"#!/bin/sh\ncat <<PY\n$ne\nPY\n",
        b"#!/bin/sh\n# '\nprintf '%s\\n' \"$NE\"\n",
        b"#!/bin/sh\n# <<'EOF'\nprintf '%s\\n' \"$NE\"\n",
        b'#!/bin/sh\nX=\nprintf "%s\\n" "${X:-$NE}"\n',
        b'#!/bin/sh\nprintf "%s\\n" "${NE%foo}"\n',
        b'#!/bin/sh\nprintf "%s\\n" "${NE#foo}"\n',
        b'#!/bin/sh\nprintf "%s\\n" "${#NE}"\n',
    ):
        with pytest.raises(PoCCandidateRejected, match="POC_UNDECLARED_INPUT"):
            validate_candidate(script, allowed_environment_names=frozenset())

    with pytest.raises(PoCCandidateRejected, match="POC_UNDECLARED_INPUT"):
        validate_candidate(
            b'#!/bin/sh\nprintf "%s\\n" "${X:-$NE}"\n',
            allowed_environment_names=frozenset({"NE"}),
        )


@pytest.mark.parametrize(
    "command",
    (b"cat <<'EOF'", b"python3 - <<'EOF' >result.txt"),
)
def test_poc_candidate_validator_keeps_safe_quoted_heredocs_without_dollars(
    command: bytes,
) -> None:
    assert validate_candidate(
        b"#!/bin/sh\n" + command + b"\nhello\nEOF\n",
        allowed_environment_names=frozenset(),
    )


def test_poc_candidate_validator_checks_allowed_variable_in_nested_shell() -> None:
    assert validate_candidate(
        b"#!/bin/sh\nsh <<'EOF'\necho \"$PATH\"\nEOF\n",
        allowed_environment_names=frozenset(),
    )


def test_poc_candidate_validator_allows_nested_shell_local_assignment() -> None:
    assert validate_candidate(
        b"#!/bin/sh\nsh <<'EOF'\nINNER=fixture\nprintf '%s' \"$INNER\"\nEOF\n",
        allowed_environment_names=frozenset(),
    )


def test_poc_candidate_validator_allows_exported_parent_input_in_child() -> None:
    assert validate_candidate(
        b"#!/bin/sh\nexport SHARED=fixture\nsh <<'EOF'\necho \"$SHARED\"\nEOF\n",
        allowed_environment_names=frozenset(),
    )


def test_poc_candidate_validator_allows_separately_exported_input_in_child() -> None:
    assert validate_candidate(
        b"#!/bin/sh\nSHARED=fixture\nexport SHARED\n"
        b"sh <<'EOF'\necho \"$SHARED\"\nEOF\n",
        allowed_environment_names=frozenset(),
    )


def test_poc_candidate_validator_handles_multiple_quoted_heredocs() -> None:
    assert validate_candidate(
        b"#!/bin/sh\npython3 - <<'FIRST' <<'SECOND'\n"
        b"print({chr(36) + 'ne': 1})\nFIRST\n"
        b"print({chr(36) + 'gt': 1})\nSECOND\n",
        allowed_environment_names=frozenset(),
    )


def test_poc_candidate_validator_allows_direct_python_flags_and_argument() -> None:
    assert validate_candidate(
        b"#!/bin/sh\nworkdir=/tmp\n"
        b"python3 -B - \"$workdir\" <<'PY'\n"
        b"print({chr(36) + 'ne': 1})\nPY\n",
        allowed_environment_names=frozenset(),
    )


@pytest.mark.parametrize(
    "body",
    (
        b"import os\nos.system('echo $MISSING')",
        b"import subprocess\nsubprocess.run('echo $MISSING', shell=True)",
        b"import os\ngetattr(os, 'system')('echo $MISSING')",
    ),
)
def test_poc_candidate_validator_rejects_python_spawned_shell_variables(
    body: bytes,
) -> None:
    with pytest.raises(PoCCandidateRejected, match="POC_UNDECLARED_INPUT"):
        validate_candidate(
            b"#!/bin/sh\npython3 - <<'PY'\n" + body + b"\nPY\n",
            allowed_environment_names=frozenset(),
        )


def test_poc_candidate_validator_runtime_mongo_key_with_subprocess() -> None:
    assert validate_candidate(
        b"#!/bin/sh\npython3 - <<'PY'\n"
        b"import subprocess\nquery = {chr(36) + 'ne': 'x'}\n"
        b"subprocess.run(['true'], check=True)\nPY\n",
        allowed_environment_names=frozenset(),
    )


def test_poc_candidate_validator_rejects_dict_key_sent_to_nested_shell() -> None:
    with pytest.raises(PoCCandidateRejected, match="POC_UNDECLARED_INPUT"):
        validate_candidate(
            b"#!/bin/sh\npython3 - <<'PY'\n"
            b"import os\nos.system('echo ' + next(iter({'$MISSING': 1})))\nPY\n",
            allowed_environment_names=frozenset(),
        )


def test_poc_candidate_validator_rejects_aliased_shell_runner() -> None:
    with pytest.raises(PoCCandidateRejected, match="POC_UNDECLARED_INPUT"):
        validate_candidate(
            b"#!/bin/sh\npython3 - <<'PY'\n"
            b"import subprocess\nr = subprocess.run\n"
            b"r(['sh', '-c', 'echo ' + next(iter({'$MISSING': 1}))])\nPY\n",
            allowed_environment_names=frozenset(),
        )


@pytest.mark.parametrize(
    ("command", "body"),
    (
        (b"sh <<'PY'", b'printf "%s" "$MISSING"'),
        (b"bash <<'PY'", b'printf "%s" "$MISSING"'),
        (b"cat <<'PY' | sh", b'printf "%s" "$MISSING"'),
        (b"cat <<'PY' | bash", b'printf "%s" "$MISSING"'),
        (b"python3 - <<'PY' | sh", b"print('echo $MISSING')"),
    ),
)
def test_poc_candidate_validator_rejects_quoted_heredoc_to_shell(
    command: bytes, body: bytes
) -> None:
    with pytest.raises(PoCCandidateRejected, match="POC_UNDECLARED_INPUT"):
        validate_candidate(
            b"#!/bin/sh\n" + command + b"\n" + body + b"\nPY\n",
            allowed_environment_names=frozenset(),
        )


def test_poc_candidate_validator_checks_unquoted_heredoc_expansion() -> None:
    with pytest.raises(PoCCandidateRejected, match="POC_UNDECLARED_INPUT"):
        validate_candidate(
            b"#!/bin/sh\ncat <<PY\n$MISSING\nPY\n",
            allowed_environment_names=frozenset(),
        )


def test_poc_candidate_validator_checks_shell_after_quoted_heredoc() -> None:
    with pytest.raises(PoCCandidateRejected, match="POC_UNDECLARED_INPUT"):
        validate_candidate(
            b"#!/bin/sh\npython3 - <<'PY'\n$ne\nPY\nprintf '%s' \"$MISSING\"\n",
            allowed_environment_names=frozenset(),
        )


def test_poc_candidate_validator_does_not_count_heredoc_assignment() -> None:
    with pytest.raises(PoCCandidateRejected, match="POC_UNDECLARED_INPUT"):
        validate_candidate(
            b"#!/bin/sh\npython3 - <<'PY'\nMISSING=fixture\nPY\n"
            b"printf '%s' \"$MISSING\"\n",
            allowed_environment_names=frozenset(),
        )


def test_poc_candidate_validator_keeps_url_check_inside_quoted_heredoc() -> None:
    with pytest.raises(PoCCandidateRejected, match="POC_EXTERNAL_URL_FORBIDDEN"):
        validate_candidate(
            b"#!/bin/sh\npython3 - <<'PY'\nhttps://example.invalid\nPY\n",
            allowed_environment_names=frozenset(),
        )


def test_poc_candidate_validator_does_not_parse_literal_heredoc_opener() -> None:
    with pytest.raises(PoCCandidateRejected, match="POC_UNDECLARED_INPUT"):
        validate_candidate(
            b"#!/bin/sh\nprintf '%s' \"<<'PY'\"\n"
            b"# <<'OTHER'\nprintf '%s' \"$MISSING\"\nPY\n",
            allowed_environment_names=frozenset(),
        )


def test_poc_candidate_validator_rejects_windows_host_path() -> None:
    with pytest.raises(PoCCandidateRejected, match="POC_HOST_PATH_FORBIDDEN"):
        validate_candidate(
            b"#!/bin/sh\nset -eu\nprintf '%s\\n' 'C:\\\\Users\\\\name\\\\file'\n",
            allowed_environment_names=frozenset(),
        )


@pytest.mark.asyncio
async def test_unexpected_stage_error_is_retryable_blocked_not_orphaned_running(
    tmp_path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "unexpected" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.VERIFICATION_INITIAL_DONE)

    async def broken_handler(
        _checkpoint: StageCheckpoint,
        _prior: object,
    ) -> StageResult:
        raise RuntimeError("provider child exited unexpectedly")

    handlers = _recording_handlers([])
    handlers[SimpleStage.POC_CANDIDATE_DONE] = broken_handler

    outcome = await SimpleRuntimeRunner(store, handlers).resume_analysis(_identity())

    checkpoint = store.require(_identity(), SimpleStage.POC_CANDIDATE_DONE)
    assert outcome.status is StageStatus.BLOCKED
    assert outcome.error_code == "STAGE_UNEXPECTED_ERROR"
    assert checkpoint.status is StageStatus.BLOCKED
    assert checkpoint.retryable is True
    assert checkpoint.verdict is None


@pytest.mark.asyncio
async def test_false_stops_before_cwe_gate_and_report(tmp_path) -> None:
    store = SimpleCheckpointStore(tmp_path / "terminal" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.POC_EXECUTION_DONE)
    calls: list[SimpleStage] = []

    async def final_verification(
        _checkpoint: StageCheckpoint,
        _prior: object,
    ) -> StageResult:
        calls.append(SimpleStage.VERIFICATION_FINAL_DONE)
        return StageResult(
            output_refs=(_ref("final-false"),),
            verdict="FALSE",
        )

    handlers = _recording_handlers(calls)
    handlers[SimpleStage.VERIFICATION_FINAL_DONE] = final_verification
    outcome = await SimpleRuntimeRunner(store, handlers).resume_analysis(_identity())

    assert outcome.status is StageStatus.SUCCEEDED
    assert outcome.current_stage is SimpleStage.VERIFICATION_FINAL_DONE
    assert store.verdict(_identity()) == "FALSE"
    assert store.get(_identity(), SimpleStage.CWE_DONE) is None
    assert store.get(_identity(), SimpleStage.REPORT_DONE) is None


def test_scope_denial_creates_only_a_restricted_internal_report() -> None:
    assert internal_report_status("ALLOW") == ("CONFIRMED", True)
    assert internal_report_status("DENY") == ("CONFIRMED_RESTRICTED", False)
    assert internal_report_status("UNCERTAIN") == (
        "CONFIRMED_RESTRICTED",
        False,
    )

    with pytest.raises(ValueError, match="RULE_SCOPE_STATUS_INVALID"):
        internal_report_status("REVISE")


@pytest.mark.asyncio
async def test_retryable_stage_repairs_automatically_on_attempt_two(tmp_path) -> None:
    store = SimpleCheckpointStore(tmp_path / "retry" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.VERIFICATION_INITIAL_DONE)
    recovery = _Recovery(tmp_path, RecoveryAction.REGENERATE_INPUT)
    calls = 0
    handlers = _recording_handlers([])

    async def candidate(
        _checkpoint: StageCheckpoint,
        _prior: object,
    ) -> StageResult:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise StageBlocked(
                StageFailure(
                    code="POC_GENERATION_FAILED",
                    retryable=True,
                    safe_message="candidate failed",
                    evidence_refs=(_ref("candidate-error"),),
                )
            )
        return StageResult(output_refs=(_ref("candidate-repaired"),))

    handlers[SimpleStage.POC_CANDIDATE_DONE] = candidate
    outcome = await SimpleRuntimeRunner(
        store,
        handlers,
        recovery=recovery,
    ).resume_hypothesis(_identity())

    repaired = store.require(_identity(), SimpleStage.POC_CANDIDATE_DONE)
    assert outcome.status is StageStatus.SUCCEEDED
    assert calls == 2
    assert len(recovery.calls) == 1
    assert repaired.attempt_number == 2
    assert recovery.refs[0] in repaired.input_refs


@pytest.mark.asyncio
async def test_three_failures_become_non_retryable_recovery_exhausted(
    tmp_path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "exhaust" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.POC_CANDIDATE_DONE)
    recovery = _Recovery(
        tmp_path,
        RecoveryAction.RETRY_STAGE,
        RecoveryAction.RETRY_STAGE,
    )
    calls = 0
    handlers = _recording_handlers([])

    async def execution(
        _checkpoint: StageCheckpoint,
        _prior: object,
    ) -> StageResult:
        nonlocal calls
        calls += 1
        raise StageBlocked(
            StageFailure(
                code="POC_EXECUTION_FAILED",
                retryable=True,
                safe_message="execution failed",
                evidence_refs=(_ref(f"execution-error-{calls}"),),
            )
        )

    handlers[SimpleStage.POC_EXECUTION_DONE] = execution
    outcome = await SimpleRuntimeRunner(
        store,
        handlers,
        recovery=recovery,
    ).resume_hypothesis(_identity())

    exhausted = store.require(_identity(), SimpleStage.POC_EXECUTION_DONE)
    assert outcome.status is StageStatus.BLOCKED
    assert outcome.error_code == "RECOVERY_EXHAUSTED"
    assert calls == 3
    assert len(recovery.calls) == 2
    assert exhausted.attempt_number == 3
    assert exhausted.retryable is False
    assert exhausted.verdict is None
    assert store.get(_identity(), SimpleStage.VERIFICATION_FINAL_DONE) is None


@pytest.mark.asyncio
async def test_rebuild_environment_restarts_at_initial_verification(tmp_path) -> None:
    store = SimpleCheckpointStore(tmp_path / "rebuild" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.POC_CANDIDATE_DONE)
    recovery = _Recovery(tmp_path, RecoveryAction.REBUILD_ENVIRONMENT)
    calls: list[SimpleStage] = []
    execution_calls = 0
    handlers = _recording_handlers(calls)

    async def execution(
        checkpoint: StageCheckpoint,
        _prior: object,
    ) -> StageResult:
        nonlocal execution_calls
        calls.append(SimpleStage.POC_EXECUTION_DONE)
        execution_calls += 1
        if execution_calls == 1:
            raise StageBlocked(
                StageFailure(
                    code="POC_EXECUTION_FAILED",
                    retryable=True,
                    safe_message="missing runtime dependency",
                    evidence_refs=(_ref("missing-dependency"),),
                )
            )
        return StageResult(output_refs=(_ref("execution-repaired"),))

    handlers[SimpleStage.POC_EXECUTION_DONE] = execution
    outcome = await SimpleRuntimeRunner(
        store,
        handlers,
        recovery=recovery,
    ).resume_hypothesis(_identity())

    assert outcome.status is StageStatus.SUCCEEDED
    assert calls[:4] == [
        SimpleStage.POC_EXECUTION_DONE,
        SimpleStage.VERIFICATION_INITIAL_DONE,
        SimpleStage.POC_CANDIDATE_DONE,
        SimpleStage.POC_EXECUTION_DONE,
    ]


@pytest.mark.asyncio
async def test_restart_does_not_grant_fourth_attempt(tmp_path) -> None:
    store = SimpleCheckpointStore(tmp_path / "restart" / "sastsimi.sqlite3")
    inputs = (_ref("proposal"),)
    store.save_checkpoint(
        StageCheckpoint(
            identity=_identity(),
            stage=SimpleStage.PRO_CON_DONE,
            status=StageStatus.BLOCKED,
            input_refs=inputs,
            input_hash=input_reference_hash(inputs),
            attempt_id="attempt-3",
            attempt_number=3,
            error_code="TOOL_FAILED",
            retryable=True,
            recovery_lineage_id="a" * 64,
            recovery_origin_stage=SimpleStage.PRO_CON_DONE,
        )
    )
    calls: list[SimpleStage] = []
    recovery = _Recovery(tmp_path)

    outcome = await SimpleRuntimeRunner(
        store,
        _recording_handlers(calls),
        recovery=recovery,
    ).resume_hypothesis(_identity())

    exhausted = store.require(_identity(), SimpleStage.PRO_CON_DONE)
    assert outcome.error_code == "RECOVERY_EXHAUSTED"
    assert exhausted.error_code == "RECOVERY_EXHAUSTED"
    assert exhausted.retryable is False
    assert calls == []
    assert recovery.calls == []


@pytest.mark.asyncio
async def test_stale_exhausted_stage_restarts_at_new_version(tmp_path) -> None:
    store = SimpleCheckpointStore(tmp_path / "stale-version" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.PRO_CON_DONE)
    pro_con = store.require(_identity(), SimpleStage.PRO_CON_DONE)
    inputs = pro_con.output_refs
    store.save_checkpoint(
        StageCheckpoint(
            identity=_identity(),
            stage=SimpleStage.VERIFICATION_INITIAL_DONE,
            stage_version="4",
            status=StageStatus.BLOCKED,
            input_refs=inputs,
            input_hash=input_reference_hash(inputs),
            attempt_id="old-attempt",
            attempt_number=3,
            error_code="RECOVERY_EXHAUSTED",
            retryable=False,
            recovery_lineage_id="c" * 64,
            recovery_origin_stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        )
    )
    store.save_success(
        _checkpoint(SimpleStage.POC_CANDIDATE_DONE, inputs=(_ref("old-input"),)),
        outputs=(_ref("old-candidate"),),
    )
    calls: list[SimpleStage] = []

    outcome = await SimpleRuntimeRunner(
        store,
        _recording_handlers(calls),
        recovery=_Recovery(tmp_path),
    ).resume_hypothesis(_identity())

    initial = store.require(_identity(), SimpleStage.VERIFICATION_INITIAL_DONE)
    candidate = store.require(_identity(), SimpleStage.POC_CANDIDATE_DONE)
    assert outcome.status is StageStatus.SUCCEEDED
    assert outcome.current_stage is SimpleStage.REPORT_DONE
    assert calls[:2] == [
        SimpleStage.VERIFICATION_INITIAL_DONE,
        SimpleStage.POC_CANDIDATE_DONE,
    ]
    assert store.require(_identity(), SimpleStage.PRO_CON_DONE) == pro_con
    assert initial.stage_version == STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE]
    assert initial.attempt_number == 1
    assert initial.recovery_lineage_id is None
    assert initial.input_refs == inputs
    assert candidate.output_refs == (_ref("poc_candidate_done-result"),)


@pytest.mark.asyncio
async def test_old_exhausted_reporter_restarts_without_rerunning_prior_agents(
    tmp_path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "reporter-version" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.FINDING_DONE)
    finding = store.require(_identity(), SimpleStage.FINDING_DONE)
    inputs = finding.output_refs
    store.save_checkpoint(
        StageCheckpoint(
            identity=_identity(),
            stage=SimpleStage.REPORT_DONE,
            stage_version="3",
            status=StageStatus.BLOCKED,
            input_refs=inputs,
            input_hash=input_reference_hash(inputs),
            attempt_id="old-report-attempt",
            attempt_number=3,
            error_code="RECOVERY_EXHAUSTED",
            retryable=False,
        )
    )
    calls: list[SimpleStage] = []

    outcome = await SimpleRuntimeRunner(
        store, _recording_handlers(calls)
    ).resume_hypothesis(_identity())

    assert outcome.status is StageStatus.SUCCEEDED
    assert calls == [SimpleStage.REPORT_DONE]
    assert store.require(_identity(), SimpleStage.FINDING_DONE) == finding
    report = store.require(_identity(), SimpleStage.REPORT_DONE)
    assert report.stage_version == "4"
    assert report.attempt_number == 1


@pytest.mark.asyncio
async def test_current_version_exhausted_stage_stays_blocked(tmp_path) -> None:
    store = SimpleCheckpointStore(tmp_path / "current-version" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.PRO_CON_DONE)
    inputs = store.require(_identity(), SimpleStage.PRO_CON_DONE).output_refs
    exhausted = StageCheckpoint(
        identity=_identity(),
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE],
        status=StageStatus.BLOCKED,
        input_refs=inputs,
        input_hash=input_reference_hash(inputs),
        attempt_id="current-attempt",
        attempt_number=3,
        error_code="RECOVERY_EXHAUSTED",
        retryable=False,
    )
    store.save_checkpoint(exhausted)
    calls: list[SimpleStage] = []

    outcome = await SimpleRuntimeRunner(
        store,
        _recording_handlers(calls),
        recovery=_Recovery(tmp_path),
    ).resume_hypothesis(_identity())

    assert outcome.status is StageStatus.BLOCKED
    assert outcome.current_stage is SimpleStage.VERIFICATION_INITIAL_DONE
    assert outcome.error_code == "RECOVERY_EXHAUSTED"
    assert calls == []
    assert (
        store.require(_identity(), SimpleStage.VERIFICATION_INITIAL_DONE) == exhausted
    )


@pytest.mark.asyncio
async def test_changed_input_starts_a_new_recovery_lineage(tmp_path) -> None:
    store = SimpleCheckpointStore(tmp_path / "changed" / "sastsimi.sqlite3")
    old_inputs = (_ref("proposal-old"),)
    store.save_checkpoint(
        StageCheckpoint(
            identity=_identity(),
            stage=SimpleStage.PRO_CON_DONE,
            status=StageStatus.BLOCKED,
            input_refs=old_inputs,
            input_hash=input_reference_hash(old_inputs),
            attempt_id="attempt-3",
            attempt_number=3,
            error_code="RECOVERY_EXHAUSTED",
            retryable=False,
            recovery_lineage_id="b" * 64,
            recovery_origin_stage=SimpleStage.PRO_CON_DONE,
        )
    )
    new_inputs = (_ref("proposal-new"),)
    store.invalidate_from(
        _identity(),
        SimpleStage.PRO_CON_DONE,
        new_inputs=new_inputs,
        force=True,
    )
    store.save_checkpoint(
        StageCheckpoint(
            identity=_identity(),
            stage=SimpleStage.PRO_CON_DONE,
            status=StageStatus.PENDING,
            input_refs=new_inputs,
            input_hash=input_reference_hash(new_inputs),
        )
    )

    outcome = await SimpleRuntimeRunner(
        store,
        _recording_handlers([]),
        recovery=_Recovery(tmp_path),
    ).resume_hypothesis(_identity())

    assert outcome.status is StageStatus.SUCCEEDED
    restarted = store.require(_identity(), SimpleStage.PRO_CON_DONE)
    assert restarted.attempt_number == 1
    assert restarted.recovery_lineage_id is None


@pytest.mark.asyncio
async def test_environment_restart_carries_one_lineage_through_intermediate_stages(
    tmp_path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "lineage" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.POC_CANDIDATE_DONE)
    recovery = _Recovery(tmp_path, RecoveryAction.REBUILD_ENVIRONMENT)
    observed: list[tuple[SimpleStage, int, str | None]] = []
    execution_calls = 0
    handlers = _recording_handlers([])

    for stage in (
        SimpleStage.VERIFICATION_INITIAL_DONE,
        SimpleStage.POC_CANDIDATE_DONE,
        SimpleStage.POC_EXECUTION_DONE,
    ):

        async def handler(
            checkpoint: StageCheckpoint,
            _prior: object,
            *,
            current_stage: SimpleStage = stage,
        ) -> StageResult:
            nonlocal execution_calls
            if current_stage is SimpleStage.POC_EXECUTION_DONE:
                execution_calls += 1
                if execution_calls == 1:
                    raise StageBlocked(
                        StageFailure(
                            code="POC_EXECUTION_FAILED",
                            retryable=True,
                            safe_message="rebuild required",
                        )
                    )
            observed.append(
                (
                    current_stage,
                    checkpoint.attempt_number,
                    checkpoint.recovery_lineage_id,
                )
            )
            return StageResult(output_refs=(_ref(f"{current_stage.value}-retry"),))

        handlers[stage] = handler

    await SimpleRuntimeRunner(
        store,
        handlers,
        recovery=recovery,
    ).resume_hypothesis(_identity())

    repaired = observed[:3]
    assert [item[0] for item in repaired] == [
        SimpleStage.VERIFICATION_INITIAL_DONE,
        SimpleStage.POC_CANDIDATE_DONE,
        SimpleStage.POC_EXECUTION_DONE,
    ]
    assert {item[1] for item in repaired} == {2}
    assert len({item[2] for item in repaired}) == 1
    assert repaired[0][2] is not None


@pytest.mark.asyncio
async def test_recovery_decision_is_recorded_in_activity(tmp_path) -> None:
    store = SimpleCheckpointStore(tmp_path / "activity" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.VERIFICATION_INITIAL_DONE)
    recovery = _Recovery(tmp_path, RecoveryAction.REGENERATE_INPUT)
    calls = 0
    handlers = _recording_handlers([])

    async def candidate(
        _checkpoint: StageCheckpoint,
        _prior: object,
    ) -> StageResult:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise StageBlocked(
                StageFailure(
                    code="POC_GENERATION_FAILED",
                    retryable=True,
                    safe_message="secret stderr must not be copied",
                )
            )
        return StageResult(output_refs=(_ref("candidate-ok"),))

    handlers[SimpleStage.POC_CANDIDATE_DONE] = candidate
    await SimpleRuntimeRunner(
        store,
        handlers,
        recovery=recovery,
    ).resume_hypothesis(_identity())

    events = AgentActivityStore(store.database_path).list_analysis(
        _identity().analysis_id,
        hypothesis_id=_identity().hypothesis_id,
    )
    decisions = [
        event
        for event in events
        if event.kind is ActivityKind.DECISION_RECORDED
        and recovery.refs[0] in event.output_refs
    ]
    assert len(decisions) == 1
    assert "REGENERATE_INPUT" in decisions[0].summary_ko
    assert "attempt 1/3" in decisions[0].summary_ko
    assert "secret stderr" not in decisions[0].summary_ko


@pytest.mark.asyncio
async def test_prepare_recovery_rolls_back_decision_and_pending_checkpoint(
    tmp_path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "prepare-rollback" / "sastsimi.sqlite3")
    inputs = (_ref("prepare-input"),)
    running = store.mark_running(
        _identity(),
        SimpleStage.POC_CANDIDATE_DONE,
        inputs,
        attempt_id="prepare-attempt-1",
    )
    failed = store.mark_failure(
        running,
        StageFailure(
            code="POC_GENERATION_FAILED",
            retryable=True,
            safe_message="candidate failed",
        ),
        StageStatus.BLOCKED,
    )
    recovery = _Recovery(tmp_path, RecoveryAction.REGENERATE_INPUT)
    resolution = await recovery.decide(
        failed,
        StageFailure(
            code="POC_GENERATION_FAILED",
            retryable=True,
            safe_message="candidate failed",
        ),
    )

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_recovery(
            failed,
            resolution,
            SimpleStage.POC_CANDIDATE_DONE,
            fail_before_commit=True,
        )

    assert store.require(_identity(), failed.stage) == failed
    events = AgentActivityStore(store.database_path).list_analysis(
        _identity().analysis_id,
        hypothesis_id=_identity().hypothesis_id,
    )
    assert all(resolution.decision_ref not in event.output_refs for event in events)


def test_replace_from_rolls_back_invalidation_and_pending_checkpoint(tmp_path) -> None:
    store = SimpleCheckpointStore(tmp_path / "replace-rollback" / "sastsimi.sqlite3")
    _seeded_through(store, SimpleStage.VERIFICATION_FINAL_DONE)
    final = store.require(_identity(), SimpleStage.VERIFICATION_FINAL_DONE)
    running_gate = store.mark_running(
        _identity(),
        SimpleStage.TECH_GATE_DONE,
        final.output_refs,
        attempt_id="gate-attempt-1",
    )
    failed_gate = store.mark_failure(
        running_gate,
        StageFailure(
            code="TECH_GATE_REVISE",
            retryable=True,
            safe_message="revise final verification",
        ),
        StageStatus.BLOCKED,
    )
    pending = final.model_copy(update={"status": StageStatus.PENDING})

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.replace_from(pending, fail_before_commit=True)

    assert store.require(_identity(), SimpleStage.VERIFICATION_FINAL_DONE) == final
    assert store.require(_identity(), SimpleStage.TECH_GATE_DONE) == failed_gate


@pytest.mark.asyncio
async def test_record_recovery_stop_rolls_back_decision_event(tmp_path) -> None:
    store = SimpleCheckpointStore(tmp_path / "stop-rollback" / "sastsimi.sqlite3")
    running = store.mark_running(
        _identity(),
        SimpleStage.PRO_CON_DONE,
        (_ref("stop-input"),),
        attempt_id="stop-attempt-1",
    )
    failed = store.mark_failure(
        running,
        StageFailure(
            code="TOOL_FAILED",
            retryable=True,
            safe_message="tool failed",
        ),
        StageStatus.BLOCKED,
    )
    recovery = _Recovery(tmp_path, RecoveryAction.STOP)
    resolution = await recovery.decide(
        failed,
        StageFailure(
            code="TOOL_FAILED",
            retryable=True,
            safe_message="tool failed",
        ),
    )

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.record_recovery_stop(
            failed,
            resolution,
            fail_before_commit=True,
        )

    events = AgentActivityStore(store.database_path).list_analysis(
        _identity().analysis_id,
        hypothesis_id=_identity().hypothesis_id,
    )
    assert all(resolution.decision_ref not in event.output_refs for event in events)


@pytest.mark.asyncio
async def test_resume_can_record_new_recovery_after_prior_stop_on_same_attempt(
    tmp_path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "resume-stop" / "sastsimi.sqlite3")
    running = store.mark_running(
        _identity(),
        SimpleStage.POC_EXECUTION_DONE,
        (_ref("execution-input"),),
        attempt_id="execution-attempt-2",
    )
    failed = store.mark_failure(
        running,
        StageFailure(
            code="POC_EXECUTION_FAILED",
            retryable=True,
            safe_message="browser missing",
        ),
        StageStatus.BLOCKED,
    )
    stop = await _Recovery(tmp_path, RecoveryAction.STOP).decide(
        failed,
        StageFailure(
            code="POC_EXECUTION_FAILED",
            retryable=True,
            safe_message="browser missing",
        ),
    )
    store.record_recovery_stop(failed, stop)
    store.record_recovery_stop(failed, stop)
    rebuild = await _Recovery(tmp_path, RecoveryAction.REBUILD_ENVIRONMENT).decide(
        failed,
        StageFailure(
            code="POC_EXECUTION_FAILED",
            retryable=True,
            safe_message="browser missing",
        ),
    )

    pending = store.prepare_recovery(
        failed, rebuild, SimpleStage.VERIFICATION_INITIAL_DONE
    )

    assert pending.status is StageStatus.PENDING
    decisions = [
        event
        for event in AgentActivityStore(store.database_path).list_analysis(
            _identity().analysis_id, hypothesis_id=_identity().hypothesis_id
        )
        if event.kind is ActivityKind.DECISION_RECORDED
        and event.stage == SimpleStage.POC_EXECUTION_DONE.value
    ]
    assert len(decisions) == 2
    assert {event.output_refs[0] for event in decisions} == {
        stop.decision_ref,
        rebuild.decision_ref,
    }


@pytest.mark.asyncio
async def test_terminal_inconclusive_poc_skips_final_verification_and_resume(
    tmp_path,
) -> None:
    store = SimpleCheckpointStore(
        tmp_path / "db" / "sastsimi.sqlite3", artifact_data_dir=tmp_path
    )
    artifacts = SimpleArtifactRepository(tmp_path, _identity())
    _seeded_through(store, SimpleStage.POC_CANDIDATE_DONE)
    poc_inputs = store.input_refs_for(_identity(), SimpleStage.POC_EXECUTION_DONE)
    store.save_checkpoint(
        StageCheckpoint(
            identity=_identity(),
            stage=SimpleStage.POC_EXECUTION_DONE,
            stage_version=STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE],
            status=StageStatus.PENDING,
            input_refs=poc_inputs,
            input_hash=input_reference_hash(poc_inputs),
            attempt_number=2,
        )
    )
    calls: list[SimpleStage] = []
    handlers = _recording_handlers(calls)

    async def inconclusive(_checkpoint: StageCheckpoint, _prior: object) -> StageResult:
        calls.append(SimpleStage.POC_EXECUTION_DONE)
        execution_ref = artifacts.put_json(
            {
                "kind": "simple_poc_execution",
                "attempt_id": _checkpoint.attempt_id,
                "timed_out": False,
                "exit_code": 0,
            }
        )
        interpretation_ref = artifacts.put_json(
            {
                "kind": "simple_dynamic_interpretation",
                "execution_ref": execution_ref.model_dump(mode="json"),
                "result": {"outcome": "INCONCLUSIVE"},
            }
        )
        return StageResult(
            output_refs=(execution_ref, interpretation_ref),
            verdict="HOLD",
        )

    handlers[SimpleStage.POC_EXECUTION_DONE] = inconclusive
    runner = SimpleRuntimeRunner(
        store,
        handlers,
        recovery=_Recovery(tmp_path),
        cleanup_artifacts=artifacts,
    )

    first = await runner.resume_hypothesis(_identity())
    second = await runner.resume_hypothesis(_identity())

    assert first.status is second.status is StageStatus.SUCCEEDED
    assert first.current_stage is second.current_stage is SimpleStage.POC_EXECUTION_DONE
    assert calls == [SimpleStage.POC_EXECUTION_DONE]
    assert store.get(_identity(), SimpleStage.VERIFICATION_FINAL_DONE) is None


# mypy: disable-error-code="arg-type,no-untyped-def"
