"""Focused T14 Lane B tests for durable run control and safe CLI leaves."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import cast

import pytest

from sastsimi.contracts.analysis import AnalysisRunState, AnalysisStartRequest
from sastsimi.contracts.evaluation import AnalysisRunResult
from sastsimi.contracts.refs import (
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.work import WorkAttempt, WorkExecutionState
from sastsimi.interfaces.cli import cancel as cancel_command
from sastsimi.interfaces.cli import result as result_command
from sastsimi.interfaces.cli import resume as resume_command
from sastsimi.interfaces.cli import run as run_command
from sastsimi.interfaces.cli import status as status_command
from sastsimi.ports.scheduler import (
    AnalysisStatusView,
    CancellationObservation,
    CancellationTarget,
    RunOutcome,
)
from sastsimi.runtime.cancellation_service import (
    CancellationService,
    ExactCancellationRouter,
)
from sastsimi.runtime.run_control import ProductionRunControl
from tests.contract.domain.canonical_fixtures import make
from tests.unit.contracts.test_core_models import meta, ref, work


def _stored(kind: str = "llm_call_spec") -> StoredDataRef:
    return StoredDataRef.model_validate_json(json.dumps(ref(kind, True)))


def _run_ref(kind: str = "action_request") -> RunStoredDataRef:
    return RunStoredDataRef.model_validate_json(json.dumps(ref(kind)))


def _work(status: str, *, input_hash: str = "a" * 64) -> WorkExecutionState:
    values = work(
        status=status,
        input_hash=input_hash,
        state_version=2 if status != "PENDING" else 1,
        last_transition_ref=ref("state_transition") if status != "PENDING" else None,
    )
    if status == "RUNNING":
        values.update(active_attempt_id="at1", started_at="2026-09-07T00:00:00Z")
    elif status == "BLOCKED":
        values.update(
            waiting_for=["AUTH"],
            stop_reason="AUTH_REQUIRED",
            started_at="2026-09-07T00:00:00Z",
        )
    elif status in {"SUCCEEDED", "FAILED", "CANCELLED"}:
        values.update(
            finished_at="2026-09-07T00:01:00Z",
            stop_reason="COMPLETED" if status == "SUCCEEDED" else status,
        )
        if status == "FAILED":
            values["error_ids"] = ["error-1"]
    return WorkExecutionState.model_validate_json(json.dumps(values))


def _attempt(
    item: WorkExecutionState,
    *,
    status: str = "RUNNING",
    input_hash: str | None = None,
) -> WorkAttempt:
    return WorkAttempt.model_validate_json(
        json.dumps(
            {
                "meta": meta(
                    False,
                    record_id="attempt-record",
                    logical_record_id="attempt-logical",
                    record_type="work_attempt",
                ),
                "work_id": str(item.work_id),
                "attempt_id": "at1",
                "attempt_number": 1,
                "trigger": "INITIAL",
                "input_hash": input_hash or str(item.input_hash),
                "status": status,
                "output_refs": (),
                "gap_ids": (),
                "error_ids": () if status != "FAILED" else ("error-1",),
                "started_at": "2026-09-07T00:00:00Z",
                "finished_at": None if status == "RUNNING" else "2026-09-07T00:01:00Z",
                "elapsed_ms": 0,
            }
        )
    )


def _target(item: WorkExecutionState, attempt: WorkAttempt) -> CancellationTarget:
    return CancellationTarget(
        target_kind="PROVIDER",
        work=item,
        attempt=attempt,
        action_request_ref=cast(RecordRef, _run_ref()),
        action_decision_ref=cast(RecordRef, _run_ref("action_decision")),
        call_spec_ref=_stored(),
        sandbox_resource_refs=(),
    )


def _run_state(status: str = "RUNNING") -> AnalysisRunState:
    result_ref = _run_ref("analysis_run_result") if status != "RUNNING" else None
    return AnalysisRunState.model_validate_json(
        json.dumps(
            {
                "meta": meta(
                    False,
                    record_id="run-state",
                    logical_record_id="run-state",
                    record_type="analysis_run_state",
                ),
                "purpose": "PRODUCTION",
                "eval_config_refs": (),
                "analysis_input_ref": _run_ref("analysis_run_input").model_dump(
                    mode="json"
                ),
                "program_id": "program",
                "execution_budget_profile_ref": _run_ref(
                    "execution_budget_profile"
                ).model_dump(mode="json"),
                "budget_binding_ref": None,
                "workspace_id": None,
                "commit_id": None,
                "workspace_ref": None,
                "run_policy_state_ref": None,
                "status": status,
                "analysis_result_ref": result_ref.model_dump(mode="json")
                if result_ref is not None
                else None,
                "started_at": "2026-09-07T00:00:00Z",
                "finished_at": None if status == "RUNNING" else "2026-09-07T00:01:00Z",
                "elapsed_ms": 0,
            }
        )
    )


def _analysis_result() -> AnalysisRunResult:
    values = make("AnalysisRunResult") | {
        "repository_url": "C:/private/checkout",
        "program_id": "program",
        "started_at": "2026-09-07T00:00:00Z",
        "finished_at": "2026-09-07T00:01:00Z",
        "elapsed_ms": 60_000,
    }
    return AnalysisRunResult.model_validate_json(json.dumps(values))


class _Controls:
    def __init__(self, targets: tuple[CancellationTarget, ...] = ()) -> None:
        self.targets = targets
        self.latched: set[str] = set()
        self.quiescent: set[str] = set()
        self.events: list[str] = []

    def request_cancel(self, analysis_id: str, reason: str) -> None:
        self.events.append("latch")
        self.latched.add(analysis_id)

    def cancel_requested(self, analysis_id: str) -> bool:
        return analysis_id in self.latched

    def mark_quiescent(self, analysis_id: str) -> None:
        self.events.append("quiescent")
        self.quiescent.add(analysis_id)

    def cancellation_targets(self, analysis_id: str) -> tuple[CancellationTarget, ...]:
        self.events.append("targets")
        return self.targets


class _SchedulerStore:
    def __init__(self, works: tuple[WorkExecutionState, ...]) -> None:
        self.works = list(works)
        self.attempts: dict[str, tuple[WorkAttempt, ...]] = {}

    def work_for_run(self, analysis_id: str) -> tuple[WorkExecutionState, ...]:
        return tuple(
            item for item in self.works if str(item.meta.analysis_id) == analysis_id
        )

    def attempts_for_work(self, work_id: str) -> tuple[WorkAttempt, ...]:
        return self.attempts.get(work_id, ())


class _Canceller:
    def __init__(self, controls: _Controls, store: _SchedulerStore) -> None:
        self.controls = controls
        self.store = store
        self.targets: list[CancellationTarget] = []

    async def cancel(self, target: CancellationTarget) -> CancellationObservation:
        assert self.controls.cancel_requested(str(target.work.meta.analysis_id))
        self.controls.events.append("external")
        self.targets.append(target)
        self.store.works = [_work("CANCELLED")]
        return CancellationObservation(target, "STOPPED", None)


def test_cancel_latches_before_exact_target_drain_and_cli_is_safe() -> None:
    running = _work("RUNNING")
    target = _target(running, _attempt(running))
    controls = _Controls((target,))
    store = _SchedulerStore((running,))
    adapter = _Canceller(controls, store)
    router = ExactCancellationRouter(
        static=adapter,
        provider=adapter,
        sandbox=adapter,
    )
    cancellation = CancellationService(controls, store, router)

    observations = asyncio.run(cancellation.request("a1", "USER_REQUEST"))

    assert controls.events == ["latch", "targets", "external", "quiescent"]
    assert observations == (CancellationObservation(target, "STOPPED", None),)
    assert adapter.targets == [target]
    assert controls.quiescent == {"a1"}
    view = AnalysisStatusView(
        "a1", "CANCELLED", (("WORKSPACE_PREP:CANCELLED", 1),), True, (), None
    )
    assert cancel_command.project(view) == {
        "analysis_id": "a1",
        "status": "CANCELLED",
        "cancel_requested": True,
    }


@pytest.mark.parametrize(
    "case",
    [
        "cross-run-target",
        "cross-attempt-target",
        "terminal-resume",
        "changed-input-resume",
        "unresolved-resume",
        "exhausted-budget-resume",
    ],
)
def test_run_control_rejects_unsafe_cancel_or_resume(case: str) -> None:
    running = _work("RUNNING")
    attempt = _attempt(running)
    target = _target(running, attempt)
    if case == "cross-run-target":
        target = CancellationTarget(
            target.target_kind,
            target.work.model_copy(
                update={
                    "meta": target.work.meta.model_copy(update={"analysis_id": "a2"})
                }
            ),
            target.attempt,
            target.action_request_ref,
            target.action_decision_ref,
            target.call_spec_ref,
            target.sandbox_resource_refs,
        )
    if case == "cross-attempt-target":
        target = CancellationTarget(
            target.target_kind,
            target.work,
            attempt.model_copy(update={"attempt_id": "at2"}),
            target.action_request_ref,
            target.action_decision_ref,
            target.call_spec_ref,
            target.sandbox_resource_refs,
        )
    controls = _Controls((target,))
    store = _SchedulerStore((running,))
    adapter = _Canceller(controls, store)
    cancellation = CancellationService(
        controls,
        store,
        ExactCancellationRouter(static=adapter, provider=adapter, sandbox=adapter),
    )
    if case.startswith("cross-"):
        with pytest.raises(ValueError, match="CANCELLATION_TARGET_SCOPE_MISMATCH"):
            asyncio.run(cancellation.request("a1", "USER_REQUEST"))
        assert adapter.targets == []
        return

    blocked = _work("BLOCKED")
    store = _SchedulerStore((blocked,))
    store.attempts[str(blocked.work_id)] = (
        _attempt(
            blocked,
            status="FAILED",
            input_hash="b" * 64 if case == "changed-input-resume" else None,
        ),
    )
    guard_error = {
        "unresolved-resume": "UNRESOLVED_EXTERNAL_DISPATCH",
        "exhausted-budget-resume": "BUDGET_EXCEEDED",
    }.get(case)
    service, resumer = _service(
        store=store,
        run_state=_run_state("FAILED" if case == "terminal-resume" else "RUNNING"),
        resume_error=guard_error,
    )
    with pytest.raises(ValueError):
        asyncio.run(service.resume("a1"))
    assert resumer.resumed == []


class _Recovery:
    def __init__(self) -> None:
        self.calls = 0

    def recover(self) -> object:
        self.calls += 1
        return object()


class _Lifecycle:
    def __init__(self, outcome: RunOutcome | BaseException) -> None:
        self.outcome = outcome
        self.calls: list[str] = []

    def start(self, request: AnalysisStartRequest) -> str:
        assert request.repository_ref == "https://example.invalid/repository"
        assert request.requested_git_ref == "abc123"
        return "a1"

    async def continue_run(self, analysis_id: str) -> RunOutcome:
        self.calls.append(analysis_id)
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome


class _Runs:
    def __init__(self, state: AnalysisRunState) -> None:
        self.state = state

    def current_state(self, analysis_id: str) -> AnalysisRunState:
        if analysis_id != "a1":
            raise LookupError("RUN_NOT_FOUND")
        return self.state


class _Records:
    def __init__(self, result: AnalysisRunResult) -> None:
        self.result = result

    def get_exact(self, exact: RecordRef) -> AnalysisRunResult:
        return self.result


class _Resumer:
    def __init__(
        self,
        store: _SchedulerStore,
        error: str | None = None,
    ) -> None:
        self.store = store
        self.error = error
        self.resumed: list[str] = []

    def resume_blocked(
        self,
        candidates: tuple[tuple[WorkExecutionState, WorkAttempt], ...],
    ) -> tuple[WorkExecutionState, ...]:
        if self.error:
            raise ValueError(self.error)
        ready_items: list[WorkExecutionState] = []
        for index, (item, previous) in enumerate(candidates):
            assert item.input_hash == previous.input_hash
            self.resumed.append(str(item.work_id))
            ready_items.append(
                WorkExecutionState.model_validate_json(
                    json.dumps(
                        item.model_dump(mode="json")
                        | {
                            "meta": item.meta.model_dump(mode="json")
                            | {
                                "record_id": f"ready-record-{index}",
                                "revision_number": item.meta.revision_number + 1,
                                "previous_record_id": str(item.meta.record_id),
                            },
                            "status": "READY",
                            "state_version": item.state_version + 1,
                            "waiting_for": (),
                            "stop_reason": None,
                        }
                    )
                )
            )
        self.store.works = ready_items
        return tuple(ready_items)


def _service(
    *,
    store: _SchedulerStore | None = None,
    run_state: AnalysisRunState | None = None,
    scheduler_outcome: RunOutcome | BaseException | None = None,
    resume_error: str | None = None,
) -> tuple[ProductionRunControl, _Resumer]:
    store = store or _SchedulerStore(())
    controls = _Controls()
    adapter = _Canceller(controls, store)
    cancellation = CancellationService(
        controls,
        store,
        ExactCancellationRouter(static=adapter, provider=adapter, sandbox=adapter),
    )
    resumer = _Resumer(store, resume_error)
    result = _analysis_result()
    if run_state is not None and run_state.status != "RUNNING":
        run_state = AnalysisRunState.model_validate_json(
            json.dumps(
                run_state.model_dump(mode="json")
                | {"analysis_result_ref": reference(result).model_dump(mode="json")}
            )
        )
    return (
        ProductionRunControl(
            lifecycle=_Lifecycle(
                scheduler_outcome or RunOutcome("a1", "BLOCKED", None)
            ),
            scheduler_store=store,
            controls=controls,
            cancellation=cancellation,
            recovery=_Recovery(),
            runs=_Runs(run_state or _run_state()),
            records=_Records(result),
            resumer=resumer,
            shutdown_timeout_seconds=0.1,
        ),
        resumer,
    )


def test_production_run_resume_status_and_result_cli_projections() -> None:
    request = run_command.request(
        repository="https://example.invalid/repository",
        commit="abc123",
        program_id="program",
    )
    service, _ = _service(
        scheduler_outcome=RunOutcome("a1", "TERMINAL", _run_ref("analysis_run_result"))
    )
    outcome = asyncio.run(run_command.run(service, request))
    assert outcome == {
        "analysis_id": "a1",
        "status": "TERMINAL",
        "result_record_id": "r1",
    }

    blocked = _work("BLOCKED")
    store = _SchedulerStore((blocked,))
    store.attempts[str(blocked.work_id)] = (_attempt(blocked, status="FAILED"),)
    service, resumer = _service(store=store)
    status = status_command.run(service, "a1")
    assert status == {
        "analysis_id": "a1",
        "status": "BLOCKED",
        "work_counts": {"WORKSPACE_PREP:BLOCKED": 1},
        "cancel_requested": False,
        "waiting_for": ["AUTH"],
        "result_record_id": None,
    }
    assert asyncio.run(resume_command.run(service, "a1"))["status"] == "BLOCKED"
    assert resumer.resumed == ["w1"]

    terminal, _ = _service(run_state=_run_state("FAILED"))
    summary = result_command.run(terminal, "a1", output_format="summary")
    assert summary["analysis_id"] == "a1"
    assert summary["status"] == "FAILED"
    assert "repository_url" not in summary
    exact = result_command.run(terminal, "a1", output_format="json")
    assert "repository_url" not in exact
    assert exact["program_id"] == "program"


@pytest.mark.parametrize("interrupt", [asyncio.CancelledError(), KeyboardInterrupt()])
def test_foreground_interrupt_persists_latch_before_bounded_drain(
    interrupt: BaseException,
) -> None:
    service, _ = _service(scheduler_outcome=interrupt)
    with pytest.raises(type(interrupt)):
        asyncio.run(
            service.run(
                run_command.request(
                    repository="https://example.invalid/repository",
                    commit="abc123",
                    program_id="program",
                )
            )
        )
    assert service.controls.cancel_requested("a1")


def test_scheduler_cannot_return_an_outcome_for_another_run() -> None:
    service, _ = _service(
        scheduler_outcome=RunOutcome("a2", "BLOCKED", None),
    )
    with pytest.raises(ValueError, match="RUN_OUTCOME_SCOPE_MISMATCH"):
        asyncio.run(
            service.run(
                run_command.request(
                    repository="https://example.invalid/repository",
                    commit="abc123",
                    program_id="program",
                )
            )
        )


@dataclass(frozen=True)
class _Application:
    status_view: AnalysisStatusView
    outcome: RunOutcome
    result_value: AnalysisRunResult

    async def run(self, request: AnalysisStartRequest) -> RunOutcome:
        return self.outcome

    def status(self, analysis_id: str) -> AnalysisStatusView:
        return self.status_view

    async def cancel(self, analysis_id: str) -> AnalysisStatusView:
        return self.status_view

    async def resume(self, analysis_id: str) -> RunOutcome:
        return self.outcome

    def result(self, analysis_id: str) -> AnalysisRunResult:
        return self.result_value


def test_cli_leaf_commands_do_not_echo_input_or_host_paths() -> None:
    app = _Application(
        AnalysisStatusView("a1", "RUNNING", (), False, (), None),
        RunOutcome("a1", "BLOCKED", None),
        _analysis_result(),
    )
    outputs: tuple[dict[str, object], ...] = (
        status_command.run(app, "a1"),
        asyncio.run(cancel_command.run(app, "a1")),
        asyncio.run(resume_command.run(app, "a1")),
        result_command.run(app, "a1", output_format="json"),
    )
    wire = json.dumps(outputs, sort_keys=True)
    assert "C:/private/checkout" not in wire
    assert "https://" not in wire
    assert "credential" not in wire.lower()
