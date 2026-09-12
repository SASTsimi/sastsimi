"""S1 atomic READY claim and cancellation-latch integration tests."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Barrier

import pytest
from sqlalchemy import func, select

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.actions import ActionRequest, ActionType, RequesterRole
from sastsimi.contracts.budget import BudgetReservation
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.contracts.ids import AnalysisId, TransitionId
from sastsimi.contracts.refs import reference
from sastsimi.contracts.work import StateTransition, TransitionTargetStatus
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.storage import models
from sastsimi.storage.run_control import RunControlStore
from sastsimi.storage.work_dispatch import WorkDispatchStore
from tests.contract.domain.canonical_fixtures import make
from tests.integration.runtime_support import NOW, Harness


def _ready_work(tmp_path: Path, *, parallel: int = 1, count: int = 1):
    harness = Harness(tmp_path)
    execution = harness.execution(max_work=10).model_copy(
        update={"max_parallel_work": parallel}
    )
    assert execution.approval_ref is not None
    harness.evidence.identities[execution.approval_ref] = RequesterRole.ORCHESTRATION
    runtime = build_runtime(
        tmp_path,
        None,
        None,
        harness.clock,
        harness.ids,
        evidence=harness.evidence,
        analysis_finalization_identity_ref=execution.approval_ref,
    )
    scope = harness.pin_execution(runtime.budget_registry, execution)
    runner = WorkflowRunner(runtime, harness.clock, harness.ids)
    ready = tuple(
        runner.enqueue(
            scope,
            execution.meta,
            "WORKSPACE_PREP",
            "ANALYSIS",
            "a1",
            execution.approval_ref,
        )
        for _ in range(count)
    )
    return harness, runtime, ready


def _analysis_result(runtime) -> AnalysisRunResult:
    from sastsimi.contracts.canonical_json import canonical_bytes

    value = make("AnalysisRunResult") | {
        "program_id": "program",
        "started_at": "2026-09-07T00:00:00Z",
        "finished_at": "2026-09-07T00:00:00Z",
        "elapsed_ms": 0,
    }
    value["resources"] = value["resources"] | {
        "elapsed_ms": 0,
        "work_count": 0,
        "attempt_count": 0,
        "retry_count": 0,
        "llm_call_count": 0,
        "dynamic_attempt_count": 0,
    }
    staged = runtime.unit_of_work.artifacts.stage_bytes(b"trace\n", "text/plain")
    value["debug_trace_ref"] = runtime.unit_of_work.artifacts.commit_run(
        staged, AnalysisId("a1")
    ).model_dump()
    return AnalysisRunResult.model_validate_json(canonical_bytes(value))


def _start_attempt_rows(harness: Harness) -> tuple[int, int, int]:
    with harness.database.engine.connect() as connection:
        attempts = connection.execute(
            select(func.count()).select_from(models.work_attempts)
        ).scalar_one()
        reservations = 0
        active = 0
        for row in connection.execute(select(models.budget_reservations)).mappings():
            reservation = BudgetReservation.model_validate_json(row["payload"])
            action = harness.records.get_exact(reservation.action_ref)
            if (
                isinstance(action, ActionRequest)
                and action.action_type == ActionType.START_ATTEMPT
            ):
                reservations += 1
                active += row["status"] == "RESERVED"
    return attempts, reservations, active


def test_ready_claim_publishes_one_exact_attempt_lease_and_work_revision(
    tmp_path: Path,
) -> None:
    harness, runtime, (ready,) = _ready_work(tmp_path)
    dispatch = WorkDispatchStore(runtime.work.store)
    scheduler_runner = WorkflowRunner(
        runtime, harness.clock, harness.ids, scheduler_store=dispatch
    )

    context = scheduler_runner.claim_ready(
        "a1",
        str(ready.work_id),
        ready.state_version,
        "worker-1",
        NOW + timedelta(seconds=30),
    )

    assert context is not None
    assert context.work.status == "RUNNING"
    assert context.work.state_version == ready.state_version + 1
    assert context.work.active_attempt_id == context.attempt.attempt_id
    assert context.attempt.work_id == context.work.work_id
    assert context.attempt.input_hash == context.work.input_hash == ready.input_hash
    with harness.database.engine.connect() as connection:
        row = (
            connection.execute(
                select(models.work_states).where(
                    models.work_states.c.work_id == str(ready.work_id)
                )
            )
            .mappings()
            .one()
        )
        assert row["worker_id"] == "worker-1"
        assert row["lease_expires_at"] == (NOW + timedelta(seconds=30)).isoformat()
        assert row["state_version"] == context.work.state_version
        assert row["active_attempt_id"] == str(context.attempt.attempt_id)
    assert _start_attempt_rows(harness) == (1, 1, 0)
    renewed = dispatch.renew_lease(
        context,
        "worker-1",
        NOW + timedelta(seconds=45),
        elapsed_ms=5,
    )
    assert renewed.work == context.work
    assert renewed.attempt.meta.previous_record_id == context.attempt.meta.record_id
    assert renewed.attempt.elapsed_ms == 5
    with pytest.raises(ValueError, match="LEASE_NOT_ACTIVE"):
        dispatch.renew_lease(
            context,
            "worker-1",
            NOW + timedelta(seconds=60),
            elapsed_ms=6,
        )
    context = renewed

    state = runtime.budget_registry.current_state("a1")
    profile = harness.records.get_exact(state.execution_budget_profile_ref)
    assert profile.approval_ref is not None
    harness.evidence.identities[profile.approval_ref] = RequesterRole.REPOSITORY_LOADER
    runner = WorkflowRunner(runtime, harness.clock, harness.ids)
    scope = runtime.work.registration_scope(str(context.work.work_id))
    action = runner.action(
        context.work,
        profile.approval_ref,
        "REPOSITORY_LOADER",
        "RUN_TOOL",
        tool_name="repository-loader",
        file_paths=("fixture.py",),
    )
    reservation = runner.reserve(
        context.work, scope, action, runner.units(elapsed_ms=1, cost_minor_units=1)
    )
    decision = runner.authorize(context.work, action, reservation)
    runtime.validator.claim_external(
        str(context.work.work_id),
        decision,
        harness.records.stage_record(reservation),
    )
    runtime.validator.mark_dispatched(decision)
    controls = RunControlStore(harness.database, harness.clock)
    first = controls.cancellation_targets("a1")
    restarted = RunControlStore(harness.database, harness.clock).cancellation_targets(
        "a1"
    )
    assert first == restarted
    assert len(first) == 1
    assert first[0].target_kind == "STATIC"
    assert first[0].work == context.work
    assert first[0].attempt == context.attempt
    assert first[0].action_request_ref == reference(action)


def test_blocked_work_claim_records_resume_trigger(tmp_path: Path) -> None:
    harness, runtime, (ready,) = _ready_work(tmp_path)
    dispatch = WorkDispatchStore(runtime.work.store)
    runner = WorkflowRunner(
        runtime, harness.clock, harness.ids, scheduler_store=dispatch
    )
    context = runner.claim_ready(
        "a1",
        str(ready.work_id),
        ready.state_version,
        "worker-1",
        NOW + timedelta(seconds=30),
    )
    assert context is not None
    state = runtime.budget_registry.current_state("a1")
    profile = harness.records.get_exact(state.execution_budget_profile_ref)
    assert profile.approval_ref is not None
    blocked = runner.block(context.work, profile.approval_ref, "WAITING_FOR_INPUT")
    action = runner.action(
        blocked,
        profile.approval_ref,
        "ORCHESTRATION",
        "CHANGE_WORK_STATE",
        input_refs=blocked.input_refs,
        reason="External condition resolved",
    )
    decision = runner.authorize(blocked, action)
    transition = StateTransition.model_validate_json(
        canonical_bytes(
            {
                "meta": runner.metadata(blocked.meta, "state_transition"),
                "transition_id": harness.ids.new(TransitionId),
                "work_id": blocked.work_id,
                "action_decision_ref": decision,
                "from_status": blocked.status,
                "to_status": TransitionTargetStatus.READY,
                "expected_state_version": blocked.state_version,
                "new_state_version": blocked.state_version + 1,
                "attempt_id": None,
                "cause": "EXTERNAL_CONDITION_RESOLVED",
                "output_refs": (),
                "gap_ids": (),
                "error_ids": (),
                "dedupe_key": content_hash(
                    [blocked.work_id, blocked.state_version, "READY"]
                ),
                "created_at": harness.clock.now(),
            }
        )
    )
    resumed_ready = runtime.work.make_ready(transition)

    resumed = dispatch.try_claim_ready(
        "a1",
        str(resumed_ready.work_id),
        resumed_ready.state_version,
        "worker-2",
        NOW + timedelta(seconds=30),
    )

    assert resumed is not None
    assert resumed.attempt.attempt_number == 2
    assert resumed.attempt.trigger == "RESUME"
    assert resumed.attempt.input_hash == context.attempt.input_hash


@pytest.mark.parametrize(
    ("case", "parallel", "work_count", "expected_claims"),
    [
        ("duplicate", 2, 1, 1),
        ("capacity", 1, 2, 1),
        ("cancel", 2, 1, 0),
        ("zero", 0, 1, 0),
        ("stale", 2, 1, 0),
        ("registration", 1, 0, 0),
        ("ready", 1, 0, 0),
        ("result", 1, 1, 1),
        ("finalization", 1, 0, 0),
    ],
)
def test_critical_claim_failure_is_atomic_and_leak_free(
    tmp_path: Path,
    case: str,
    parallel: int,
    work_count: int,
    expected_claims: int,
) -> None:
    harness, runtime, ready = _ready_work(tmp_path, parallel=parallel, count=work_count)
    dispatch = WorkDispatchStore(runtime.work.store)
    runner = WorkflowRunner(runtime, harness.clock, harness.ids)
    controls = RunControlStore(harness.database, harness.clock)

    if case == "registration":
        controls.request_cancel("a1", "USER_REQUEST")
        state = runtime.budget_registry.current_state("a1")
        profile = harness.records.get_exact(state.execution_budget_profile_ref)
        assert profile.approval_ref is not None
        with pytest.raises(ValueError, match="RUN_CANCELLED"):
            runner.enqueue(
                state.execution_budget_profile_ref,
                profile.meta,
                "WORKSPACE_PREP",
                "ANALYSIS",
                "a1",
                profile.approval_ref,
            )
        assert dispatch.work_for_run("a1") == ()
        assert _start_attempt_rows(harness) == (0, 0, 0)
        return

    if case == "ready":
        state = runtime.budget_registry.current_state("a1")
        profile = harness.records.get_exact(state.execution_budget_profile_ref)
        assert profile.approval_ref is not None
        pending = runner._register_pending(
            state.execution_budget_profile_ref,
            runner._pending_work(
                profile.meta,
                "WORKSPACE_PREP",
                "ANALYSIS",
                "a1",
                generation=1,
                inputs=(),
                parent=None,
                trigger_primitive_ref=None,
            ),
            profile.approval_ref,
            role="ORCHESTRATION",
        )
        controls.request_cancel("a1", "USER_REQUEST")
        with pytest.raises(ValueError, match="RUN_CANCELLED"):
            runner.enqueue_registered(
                pending,
                state.execution_budget_profile_ref,
                profile.approval_ref,
            )
        assert runtime.work.get(str(pending.work_id)).status == "PENDING"
        assert _start_attempt_rows(harness) == (0, 0, 0)
        return

    if case == "result":
        context = dispatch.try_claim_ready(
            "a1",
            str(ready[0].work_id),
            ready[0].state_version,
            "worker-0",
            NOW + timedelta(seconds=30),
        )
        assert context is not None
        controls.request_cancel("a1", "USER_REQUEST")
        state = runtime.budget_registry.current_state("a1")
        profile = harness.records.get_exact(state.execution_budget_profile_ref)
        assert profile.approval_ref is not None
        with pytest.raises(ValueError, match="RUN_CANCELLED"):
            runner.block(context.work, profile.approval_ref, "WAITING")
        assert runtime.work.get(str(context.work.work_id)) == context.work
        assert _start_attempt_rows(harness) == (1, 1, 0)
        return

    if case == "finalization":
        controls.request_cancel("a1", "USER_REQUEST")
        result = _analysis_result(runtime)
        with pytest.raises(ValueError, match="RUN_CANCELLED"):
            runtime.finalization.finalize(result)
        cancelled = result.model_copy(update={"status": "CANCELLED"})
        result_ref = runtime.finalization.finalize(cancelled)
        assert (
            runtime.budget_registry.current_state("a1").analysis_result_ref
            == result_ref
        )
        assert runtime.budget_registry.current_state("a1").status == "CANCELLED"
        assert _start_attempt_rows(harness) == (0, 0, 0)
        return

    if case == "cancel":
        controls.request_cancel("a1", "USER_REQUEST")

    barrier = Barrier(2)

    def claim(index: int):
        work = ready[index if case == "capacity" else 0]
        version = work.state_version + (1 if case == "stale" else 0)
        barrier.wait()
        return dispatch.try_claim_ready(
            "a1",
            str(work.work_id),
            version,
            f"worker-{index}",
            NOW + timedelta(seconds=30),
        )

    indexes = (0, 1) if case in {"duplicate", "capacity"} else (0,)
    if len(indexes) == 2:
        with ThreadPoolExecutor(max_workers=2) as pool:
            claims = tuple(pool.map(claim, indexes))
    else:
        barrier.abort()
        work = ready[0]
        claims = (
            dispatch.try_claim_ready(
                "a1",
                str(work.work_id),
                work.state_version + (1 if case == "stale" else 0),
                "worker-0",
                NOW + timedelta(seconds=30),
            ),
        )

    assert sum(item is not None for item in claims) == expected_claims
    assert _start_attempt_rows(harness) == (
        expected_claims,
        expected_claims,
        0,
    )
