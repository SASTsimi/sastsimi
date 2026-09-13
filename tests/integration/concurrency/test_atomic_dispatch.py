"""S1 atomic READY claim and cancellation-latch integration tests."""

import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Barrier

import pytest
from sqlalchemy import Connection, func, select

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.actions import (
    ActionDecision,
    ActionRequest,
    ActionType,
    RequesterRole,
)
from sastsimi.contracts.budget import BudgetReservation, ExecutionBudgetProfile
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.contracts.ids import AnalysisId, TransitionId
from sastsimi.contracts.refs import BudgetScopeRef, RunStoredDataRef, reference
from sastsimi.contracts.work import (
    StateTransition,
    TransitionCommit,
    TransitionTargetStatus,
    WorkAttempt,
    WorkExecutionState,
)
from sastsimi.ports.dto import WorkContext
from sastsimi.ports.scheduler import CancellationObservation, CancellationTarget
from sastsimi.runtime.cancellation_service import CancellationService
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.storage import models
from sastsimi.storage.artifact_store import LocalArtifactStore
from sastsimi.storage.run_control import RunControlStore
from sastsimi.storage.transition_service import TransitionService
from sastsimi.storage.work_dispatch import WorkDispatchStore
from sastsimi.storage.work_service import WorkService as StorageWorkService
from tests.contract.domain.canonical_fixtures import make
from tests.integration.runtime_support import NOW, Harness


def _ready_work(
    tmp_path: Path,
    *,
    parallel: int = 1,
    count: int = 1,
    total_retries: int | None = None,
) -> tuple[Harness, RuntimeServices, tuple[WorkExecutionState, ...]]:
    harness = Harness(tmp_path)
    execution_updates = {"max_parallel_work": parallel}
    if total_retries is not None:
        execution_updates["max_total_retries"] = total_retries
    execution = harness.execution(max_work=10).model_copy(update=execution_updates)
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


def _analysis_result(runtime: RuntimeServices) -> AnalysisRunResult:
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


def _dispatch(runtime: RuntimeServices) -> WorkDispatchStore:
    works = runtime.work.store
    assert isinstance(works, StorageWorkService)
    return WorkDispatchStore(works)


def _run_state_ref(runtime: RuntimeServices) -> RunStoredDataRef:
    ref = reference(runtime.budget_registry.current_state("a1"))
    assert isinstance(ref, RunStoredDataRef)
    return ref


def _running_static_dispatch(
    tmp_path: Path,
) -> tuple[Harness, RuntimeServices, WorkContext, RunControlStore]:
    harness, runtime, (ready,) = _ready_work(tmp_path)
    dispatch = _dispatch(runtime)
    context = dispatch.try_claim_ready(
        "a1",
        str(ready.work_id),
        ready.state_version,
        "dead-worker",
        NOW + timedelta(seconds=30),
    )
    assert context is not None
    state = runtime.budget_registry.current_state("a1")
    profile = harness.records.get_exact(state.execution_budget_profile_ref)
    assert isinstance(profile, ExecutionBudgetProfile)
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
    return harness, runtime, context, controls


def test_cancellation_inventory_rejects_one_stale_dispatch_instead_of_filtering(
    tmp_path: Path,
) -> None:
    harness, _runtime, _context, controls = _running_static_dispatch(tmp_path)
    with harness.database.write() as connection:
        connection.execute(
            models.external_dispatches.update().values(attempt_id="foreign-attempt")
        )

    with pytest.raises(ValueError, match="CANCELLATION_TARGET_SCOPE_MISMATCH"):
        controls.cancellation_targets("a1")


class _ExactStaticCancellation:
    def __init__(self, status: str = "STOPPED") -> None:
        self.status = status
        self.calls = 0

    async def cancel(self, target: CancellationTarget) -> CancellationObservation:
        self.calls += 1
        return CancellationObservation(
            target=target,
            status=self.status,  # type: ignore[arg-type]
            reason_code=None if self.status == "STOPPED" else "STATIC_UNKNOWN",
        )


class _NoReplayCancellation:
    async def cancel(self, target: CancellationTarget) -> CancellationObservation:
        raise AssertionError(f"durable observation replayed externally: {target}")


def _durable_controls(
    harness: Harness, runtime: RuntimeServices
) -> RunControlStore:
    works = runtime.work.store
    assert isinstance(works, StorageWorkService)
    artifacts = runtime.unit_of_work.artifacts
    assert isinstance(artifacts, LocalArtifactStore)
    state = runtime.budget_registry.current_state("a1")
    profile = harness.records.get_exact(state.execution_budget_profile_ref)
    assert isinstance(profile, ExecutionBudgetProfile)
    assert profile.approval_ref is not None
    harness.evidence.identities[profile.approval_ref] = RequesterRole.ORCHESTRATION
    return RunControlStore(
        harness.database,
        harness.clock,
        works=works,
        ids=harness.ids,
        transitions=TransitionService(works, artifacts),
        cancellation_identity_ref=profile.approval_ref,
    )


def test_owner_dead_replays_durable_stop_without_external_redispatch(
    tmp_path: Path,
) -> None:
    harness, runtime, context, _controls = _running_static_dispatch(tmp_path)
    controls = _durable_controls(harness, runtime)
    controls.request_cancel("a1", "OPERATOR_REQUEST")
    target = controls.cancellation_targets("a1")[0]
    stopped = CancellationObservation(target=target, status="STOPPED", reason_code=None)

    # Simulate owner death after the external stop was observed durably but
    # before work/attempt/dispatch reconciliation.
    controls.record_cancellation_observation(stopped)
    restarted = _durable_controls(harness, runtime)
    observations = asyncio.run(
        CancellationService(
            restarted,
            _dispatch(runtime),
            _NoReplayCancellation(),
        ).drain_latched("a1")
    )

    assert observations == (stopped,)
    work = runtime.work.get(str(context.work.work_id))
    attempt = _dispatch(runtime).attempts_for_work(str(context.work.work_id))[-1]
    assert work.status == "CANCELLED"
    assert work.active_attempt_id is None
    assert attempt.status == "CANCELLED"
    assert work.last_transition_ref is not None
    assert work.last_transition_commit_ref is not None
    transition = harness.records.get_exact(work.last_transition_ref)
    commit = harness.records.get_exact(work.last_transition_commit_ref)
    assert isinstance(transition, StateTransition)
    assert transition.from_status == "RUNNING"
    assert transition.to_status == "CANCELLED"
    assert transition.cause == "CANCELLATION_REQUESTED"
    assert isinstance(commit, TransitionCommit)
    assert commit.state == "COMMITTED"
    assert commit.transition_ref == work.last_transition_ref
    issued = harness.records.get_exact(transition.action_decision_ref)
    assert isinstance(issued, ActionDecision)
    assert issued.use_status == "UNUSED"
    action = harness.records.get_exact(issued.action_ref)
    assert isinstance(action, ActionRequest)
    assert action.action_type == ActionType.CANCEL_WORK
    with harness.database.engine.connect() as connection:
        dispatch = (
            connection.execute(select(models.external_dispatches)).mappings().one()
        )
        control = connection.execute(select(models.run_controls)).mappings().one()
    assert dispatch["returned_at"] is None
    assert dispatch["reconciled_at"] is not None
    assert control["quiescent_at"] is not None


def test_global_cancel_converges_mixed_nonterminal_work_with_authorized_commits(
    tmp_path: Path,
) -> None:
    harness, runtime, ready = _ready_work(tmp_path, parallel=2, count=3)
    dispatch = _dispatch(runtime)
    runner = WorkflowRunner(
        runtime, harness.clock, harness.ids, scheduler_store=dispatch
    )
    context = runner.claim_ready(
        "a1",
        str(ready[0].work_id),
        ready[0].state_version,
        "worker-1",
        NOW + timedelta(seconds=30),
    )
    assert context is not None
    state = runtime.budget_registry.current_state("a1")
    profile = harness.records.get_exact(state.execution_budget_profile_ref)
    assert isinstance(profile, ExecutionBudgetProfile)
    assert profile.approval_ref is not None
    blocked = runner.block(
        context.work, profile.approval_ref, "WAITING_FOR_INPUT"
    )
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
    before = {
        str(item.work_id): item
        for item in (blocked, ready[1], ready[2], pending)
    }
    controls = _durable_controls(harness, runtime)

    observations = asyncio.run(
        CancellationService(
            controls, dispatch, _NoReplayCancellation()
        ).request("a1", "OPERATOR_REQUEST")
    )

    assert observations == ()
    cancelled = {
        str(item.work_id): item for item in dispatch.work_for_run("a1")
    }
    assert set(cancelled) == set(before)
    for work_id, prior in before.items():
        current = cancelled[work_id]
        assert current.status == "CANCELLED"
        assert current.output_refs == prior.output_refs
        assert current.gap_ids == prior.gap_ids
        assert current.error_ids == prior.error_ids
        assert current.last_transition_ref is not None
        assert current.last_transition_commit_ref is not None
        committed = harness.records.get_exact(current.last_transition_commit_ref)
        assert isinstance(committed, TransitionCommit)
        assert committed.state == "COMMITTED"
    with harness.database.engine.connect() as connection:
        control = connection.execute(select(models.run_controls)).mappings().one()
        commits = tuple(
            TransitionCommit.model_validate_json(payload)
            for payload in connection.execute(
                select(models.transition_commits.c.payload)
            ).scalars()
        )
    assert control["quiescent_at"] is not None
    cancellation_commits = tuple(
        item for item in commits if item.target_status == "CANCELLED"
    )
    assert len(cancellation_commits) == 4
    assert all(item.state == "COMMITTED" for item in cancellation_commits)


def test_prepared_transition_blocks_cancellation_reconcile(tmp_path: Path) -> None:
    harness, runtime, (ready,) = _ready_work(tmp_path)
    controls = _durable_controls(harness, runtime)
    controls.request_cancel("a1", "OPERATOR_REQUEST")
    with harness.database.write() as connection:
        connection.execute(
            models.transition_commits.insert().values(
                transition_commit_id="unfinished",
                work_id=str(ready.work_id),
                expected_state_version=ready.state_version,
                candidate_binding="f" * 64,
                state="PREPARED",
                payload="{}",
                request="{}",
            )
        )

    with pytest.raises(
        ValueError, match="CANCELLATION_PREPARED_RECOVERY_REQUIRED"
    ):
        controls.reconcile_cancellation("a1", ())

    assert runtime.work.get(str(ready.work_id)) == ready


def test_reconcile_storage_failure_rolls_back_work_attempt_and_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness, runtime, context, _controls = _running_static_dispatch(tmp_path)
    works = runtime.work.store
    artifacts = runtime.unit_of_work.artifacts
    assert isinstance(works, StorageWorkService)
    assert isinstance(artifacts, LocalArtifactStore)
    state = runtime.budget_registry.current_state("a1")
    profile = harness.records.get_exact(state.execution_budget_profile_ref)
    assert isinstance(profile, ExecutionBudgetProfile)
    assert profile.approval_ref is not None
    harness.evidence.identities[profile.approval_ref] = RequesterRole.ORCHESTRATION
    transitions = TransitionService(works, artifacts)
    original = transitions.cancel_in_transaction

    def fail_after_work_cas(
        connection: Connection,
        work: WorkExecutionState,
        identity_ref: BudgetScopeRef,
    ) -> WorkExecutionState:
        original(connection, work, identity_ref)
        raise OSError("simulated durable storage failure")

    monkeypatch.setattr(transitions, "cancel_in_transaction", fail_after_work_cas)
    controls = RunControlStore(
        harness.database,
        harness.clock,
        works=works,
        ids=harness.ids,
        transitions=transitions,
        cancellation_identity_ref=profile.approval_ref,
    )
    adapter = _ExactStaticCancellation()

    with pytest.raises(OSError, match="simulated durable storage failure"):
        asyncio.run(
            CancellationService(controls, _dispatch(runtime), adapter).request(
                "a1", "OPERATOR_REQUEST"
            )
        )

    assert adapter.calls == 1
    assert runtime.work.get(str(context.work.work_id)).status == "RUNNING"
    attempts = _dispatch(runtime).attempts_for_work(str(context.work.work_id))
    assert attempts[-1].status == "RUNNING"
    targets = controls.cancellation_targets("a1")
    persisted = controls.cancellation_observations(targets)
    assert persisted[0] is not None
    assert persisted[0].status == "STOPPED"
    with harness.database.engine.connect() as connection:
        dispatch = (
            connection.execute(select(models.external_dispatches)).mappings().one()
        )
        control = connection.execute(select(models.run_controls)).mappings().one()
    assert dispatch["reconciled_at"] is None
    assert control["quiescent_at"] is None

    restarted = _durable_controls(harness, runtime)
    replayed = asyncio.run(
        CancellationService(
            restarted, _dispatch(runtime), _NoReplayCancellation()
        ).drain_latched("a1")
    )
    assert replayed[0].status == "STOPPED"
    assert runtime.work.get(str(context.work.work_id)).status == "CANCELLED"


def test_unknown_observation_is_durable_and_preserves_uncertain_budget(
    tmp_path: Path,
) -> None:
    harness, runtime, context, _controls = _running_static_dispatch(tmp_path)
    controls = _durable_controls(harness, runtime)
    adapter = _ExactStaticCancellation("UNKNOWN")
    service = CancellationService(controls, _dispatch(runtime), adapter)

    first = asyncio.run(service.request("a1", "OPERATOR_REQUEST"))
    second = asyncio.run(service.drain_latched("a1"))

    assert first == second
    assert first[0].status == "UNKNOWN"
    assert adapter.calls == 1
    assert runtime.work.get(str(context.work.work_id)).status == "RUNNING"
    with harness.database.engine.connect() as connection:
        dispatch = (
            connection.execute(select(models.external_dispatches)).mappings().one()
        )
        control = connection.execute(select(models.run_controls)).mappings().one()
        reservations = connection.execute(
            select(models.budget_reservations.c.status)
        ).scalars().all()
    assert dispatch["reconciled_at"] is None
    assert control["quiescent_at"] is None
    assert "RESERVED" in reservations


def test_mark_quiescent_rejects_live_work(tmp_path: Path) -> None:
    harness, runtime, _context, _controls = _running_static_dispatch(tmp_path)
    controls = _durable_controls(harness, runtime)
    controls.request_cancel("a1", "OPERATOR_REQUEST")

    with pytest.raises(ValueError, match="RUN_NOT_QUIESCENT"):
        controls.mark_quiescent("a1")


def test_ready_claim_publishes_one_exact_attempt_lease_and_work_revision(
    tmp_path: Path,
) -> None:
    harness, runtime, (ready,) = _ready_work(tmp_path)
    dispatch = _dispatch(runtime)
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
    assert isinstance(profile, ExecutionBudgetProfile)
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
    dispatch = _dispatch(runtime)
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
    assert isinstance(profile, ExecutionBudgetProfile)
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


def _block_for_resume(
    harness: Harness,
    runtime: RuntimeServices,
    ready: WorkExecutionState,
    worker_id: str,
    reason: str = "WAITING_FOR_INPUT",
) -> tuple[WorkDispatchStore, WorkExecutionState, WorkAttempt]:
    dispatch = _dispatch(runtime)
    runner = WorkflowRunner(
        runtime, harness.clock, harness.ids, scheduler_store=dispatch
    )
    context = runner.claim_ready(
        "a1",
        str(ready.work_id),
        ready.state_version,
        worker_id,
        NOW + timedelta(seconds=30),
    )
    assert context is not None
    state = runtime.budget_registry.current_state("a1")
    profile = harness.records.get_exact(state.execution_budget_profile_ref)
    assert isinstance(profile, ExecutionBudgetProfile)
    assert profile.approval_ref is not None
    blocked = runner.block(context.work, profile.approval_ref, reason)
    attempts = dispatch.attempts_for_work(str(blocked.work_id))
    assert attempts
    return dispatch, blocked, attempts[-1]


def test_resume_blocked_is_atomic_for_every_candidate(tmp_path: Path) -> None:
    harness, runtime, ready = _ready_work(tmp_path, parallel=2, count=2)
    dispatch, first, first_attempt = _block_for_resume(
        harness, runtime, ready[0], "worker-1"
    )
    _, second, second_attempt = _block_for_resume(
        harness, runtime, ready[1], "worker-2"
    )

    resumed = dispatch.resume_blocked(
        expected_run_state_ref=_run_state_ref(runtime),
        candidates=((first, first_attempt), (second, second_attempt)),
    )

    assert tuple(item.status.value for item in resumed) == ("READY", "READY")
    assert tuple(item.work_id for item in resumed) == (first.work_id, second.work_id)
    assert all(item.last_transition_ref is not None for item in resumed)


@pytest.mark.parametrize("case", ["stale", "cancelled", "budget"])
def test_resume_blocked_failure_opens_no_work(tmp_path: Path, case: str) -> None:
    harness, runtime, (ready,) = _ready_work(
        tmp_path,
        total_retries=0 if case == "budget" else None,
    )
    dispatch, blocked, attempt = _block_for_resume(harness, runtime, ready, "worker-1")
    candidate = blocked
    if case == "stale":
        candidate = blocked.model_copy(update={"input_hash": "f" * 64})
    elif case == "cancelled":
        RunControlStore(harness.database, harness.clock).request_cancel(
            "a1", "USER_REQUEST"
        )

    with pytest.raises(ValueError):
        dispatch.resume_blocked(
            expected_run_state_ref=_run_state_ref(runtime),
            candidates=((candidate, attempt),),
        )

    assert runtime.work.get(str(blocked.work_id)) == blocked


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
    dispatch = _dispatch(runtime)
    runner = WorkflowRunner(runtime, harness.clock, harness.ids)
    controls = RunControlStore(harness.database, harness.clock)

    if case == "registration":
        controls.request_cancel("a1", "USER_REQUEST")
        state = runtime.budget_registry.current_state("a1")
        profile = harness.records.get_exact(state.execution_budget_profile_ref)
        assert isinstance(profile, ExecutionBudgetProfile)
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
        assert isinstance(profile, ExecutionBudgetProfile)
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
        assert isinstance(profile, ExecutionBudgetProfile)
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

    def claim(index: int) -> WorkContext | None:
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
