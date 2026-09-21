from __future__ import annotations

import hashlib

import pytest

from sastsimi.contracts.ids import CommitId, RecordId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
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
from sastsimi.simple_runtime.runner import (
    SimpleRuntimeRunner,
    StageBlocked,
)
from sastsimi.simple_runtime.stages import internal_report_status
from sastsimi.simple_runtime.store import SimpleCheckpointStore


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


# mypy: disable-error-code="arg-type,no-untyped-def"
