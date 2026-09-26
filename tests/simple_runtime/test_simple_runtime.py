from __future__ import annotations

import hashlib

import pytest

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


# mypy: disable-error-code="arg-type,no-untyped-def"
