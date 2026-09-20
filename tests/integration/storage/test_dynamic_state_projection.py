"""A dynamic work start must project the exact current request and generation."""

import json
from datetime import timedelta
from pathlib import Path

import pytest

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.budget import BudgetProfileBinding
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.dynamic import (
    AgentLog,
    DynamicReproductionRequest,
    DynamicReproductionResult,
    DynamicReproductionState,
)
from sastsimi.contracts.refs import RecordRef, StoredDataRef
from sastsimi.contracts.work import WorkExecutionState, WorkStatus
from sastsimi.ports.dto import WorkContext, WorkHandlerResult
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.storage.codec import reference
from sastsimi.storage.work_dispatch import WorkDispatchStore
from sastsimi.verification.dynamic_verification_handoff import (
    DynamicParentResumeService,
)
from tests.contract.domain.canonical_fixtures import make
from tests.integration.runtime_support import Harness
from tests.integration.storage.verification_support import prepared_verification


def _authorized_dynamic_request(
    tmp_path: Path,
) -> tuple[
    Harness,
    RuntimeServices,
    WorkflowRunner,
    WorkExecutionState,
    StoredDataRef,
    DynamicReproductionRequest,
    RecordRef,
    RecordRef,
]:
    h, runtime, runner, work, registered, owner, hypothesis, bundle = (
        prepared_verification(tmp_path)
    )
    request = DynamicReproductionRequest.model_validate_json(
        canonical_bytes(
            json.loads(
                json.dumps(make("DynamicReproductionRequest")).replace('"ws1"', '"w1"')
            )
            | dict(
                meta=runner.metadata(
                    work.meta,
                    "dynamic_reproduction_request",
                    attempt_id=work.active_attempt_id,
                ),
                verification_assignment_ref=registered.assignment_ref,
                hypothesis_ref=reference(hypothesis),
                static_evidence_refs=(reference(bundle),),
            )
        )
    )
    save = runner.action(
        work,
        owner,
        "VERIFICATION",
        "SAVE_RESULT",
        result_kind="dynamic_reproduction_request",
        candidate_result_ref=h.records.stage_record(request),
    )
    runtime.intermediate.publish(
        str(work.work_id), runner.authorize(work, save), (request,)
    )
    scope = runtime.budget_registry.current_state("a1").budget_binding_ref
    action = runner.action(
        work,
        owner,
        "VERIFICATION",
        "REQUEST_DYNAMIC_REPRO",
        dynamic_request_ref=reference(request),
    )
    reservation = runner.reserve(work, scope, action, runner.units(work_count=1))
    decision = runner.authorize(work, action, reservation)
    return (
        h,
        runtime,
        runner,
        work,
        owner,
        request,
        decision,
        reference(reservation),
    )


def test_production_handoff_atomically_parks_parent_and_readies_child(
    tmp_path: Path,
) -> None:
    h, runtime, runner, parent, owner, request, decision, reservation_ref = (
        _authorized_dynamic_request(tmp_path)
    )
    original_attempt = runtime.work.store.attempts_for_work(str(parent.work_id))[-1]

    child = runtime.dynamic_registration.register_and_park(
        str(parent.work_id), decision, reservation_ref
    )

    parked = runtime.work.get(str(parent.work_id))
    assert parked.status == "BLOCKED"
    assert parked.waiting_for == ("DEPENDENCY",)
    assert parked.stop_reason == "WAITING_FOR_DYNAMIC_REPRO"
    assert parked.active_attempt_id is None
    assert child.status == "READY"
    assert child.input_refs == (reference(request),)
    (state,) = runtime.queries.current_records("a1", "dynamic_reproduction_state")
    assert isinstance(state, DynamicReproductionState)
    assert state.dynamic_work_ref == reference(child)

    # A replay returns the exact same child and cannot create another work.
    assert (
        runtime.dynamic_registration.register_and_park(
            str(parent.work_id), decision, reservation_ref
        )
        == child
    )
    children = tuple(
        item
        for item in runtime.queries.current_records("a1", "work_execution_state")
        if isinstance(item, WorkExecutionState) and item.work_type == "DYNAMIC_REPRO"
    )
    assert children == (child,)
    claimed = WorkDispatchStore(runtime.work.store).try_claim_ready(
        str(child.meta.analysis_id),
        str(child.work_id),
        child.state_version,
        "dynamic-worker",
        h.clock.now() + timedelta(seconds=30),
    )
    assert claimed is not None
    assert claimed.work.work_id == child.work_id
    (running_state,) = runtime.queries.current_records(
        "a1", "dynamic_reproduction_state"
    )
    assert running_state.dynamic_work_ref == reference(claimed.work)
    # WorkerPool's post-handler observation accepts the parked parent instead
    # of replacing the dependency wait with WORK_HANDLER_DID_NOT_FINALIZE.
    context = WorkContext(parent, original_attempt)
    assert runtime.work.accept_handler_result(
        context, WorkHandlerResult(())
    ).status == (WorkStatus.BLOCKED)


def test_failed_dynamic_child_keeps_parent_blocked_without_a_verdict(
    tmp_path: Path,
) -> None:
    h, runtime, runner, parent, owner, request, decision, reservation_ref = (
        _authorized_dynamic_request(tmp_path)
    )
    child = runtime.dynamic_registration.register_and_park(
        str(parent.work_id), decision, reservation_ref
    )
    scope = runtime.budget_registry.current_state("a1").budget_binding_ref
    assert scope is not None
    child = runner.activate(child, scope, owner, role="VERIFICATION")
    binding = h.records.get_exact(scope)
    assert isinstance(binding, BudgetProfileBinding)
    identity = binding.dynamic_lifecycle_profile_ref
    h.evidence.identities[identity] = RequesterRole.REPRODUCTION_SESSION_MANAGER
    log = AgentLog.model_validate_json(
        canonical_bytes(
            dict(
                meta=runner.metadata(
                    child.meta, "agent_log", attempt_id=child.active_attempt_id
                ),
                request_ref=reference(request),
                events=(),
            )
        )
    )
    save = runner.action(
        child,
        identity,
        "REPRODUCTION_SESSION_MANAGER",
        "SAVE_RESULT",
        result_kind="agent_log",
        candidate_result_ref=h.records.stage_record(log),
    )
    runtime.intermediate.publish(
        str(child.work_id), runner.authorize(child, save), (log,)
    )
    result = DynamicReproductionResult.model_validate_json(
        canonical_bytes(
            make("DynamicReproductionResult")
            | dict(
                meta=runner.metadata(
                    child.meta,
                    "dynamic_reproduction_result",
                    attempt_id=child.active_attempt_id,
                ),
                request_ref=reference(request),
                agent_log_ref=reference(log),
                started_at=h.clock.now(),
                finished_at=h.clock.now(),
                elapsed_ms=0,
            )
        )
    )
    runner.complete(
        child,
        identity,
        "REPRODUCTION_SESSION_MANAGER",
        (result,),
        status="FAILED",
        cause="EXECUTION_FAILED",
        error_ids=("dynamic-error",),
    )

    resumed = DynamicParentResumeService(
        records=h.records,
        queries=runtime.queries,
        runner=runner,
        verification_identity_ref=owner,
    ).resume(str(child.work_id))

    assert resumed.status == WorkStatus.BLOCKED
    assert resumed.stop_reason == "WAITING_FOR_DYNAMIC_REPRO"
    assert not runtime.queries.current_records("a1", "verification_result")


@pytest.mark.parametrize(
    "case",
    [
        "normal",
        "duplicate",
        "revoked",
        "claimed",
        "before_commit",
        "committed",
        "plan_failure",
    ],
)
def test_dynamic_start_projects_current_request_work_and_attempt(
    tmp_path: Path, case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    h, runtime, runner, work, registered, owner, hypothesis, bundle = (
        prepared_verification(tmp_path)
    )
    request = DynamicReproductionRequest.model_validate_json(
        canonical_bytes(
            json.loads(
                json.dumps(make("DynamicReproductionRequest")).replace('"ws1"', '"w1"')
            )
            | dict(
                meta=runner.metadata(
                    work.meta,
                    "dynamic_reproduction_request",
                    attempt_id=work.active_attempt_id,
                ),
                verification_assignment_ref=registered.assignment_ref,
                hypothesis_ref=reference(hypothesis),
                static_evidence_refs=(reference(bundle),),
            )
        )
    )
    action = runner.action(
        work,
        owner,
        "VERIFICATION",
        "SAVE_RESULT",
        result_kind="dynamic_reproduction_request",
        candidate_result_ref=h.records.stage_record(request),
    )
    runtime.intermediate.publish(
        str(work.work_id), runner.authorize(work, action), (request,)
    )
    scope = runtime.budget_registry.current_state("a1").budget_binding_ref
    action = runner.action(
        work,
        owner,
        "VERIFICATION",
        "REQUEST_DYNAMIC_REPRO",
        dynamic_request_ref=reference(request),
    )
    reservation = runner.reserve(work, scope, action, runner.units(work_count=1))
    decision = runner.authorize(work, action, reservation)
    service = getattr(runtime, "dynamic_registration", None)
    assert service is not None, "Exact dynamic handoff service is missing"
    if case == "revoked":
        h.evidence.identities[owner] = RequesterRole.PRO
        with pytest.raises(ValueError, match="AUTHORITY_DENIED"):
            service.register(str(work.work_id), decision, reference(reservation))
        (state,) = runtime.queries.current_records("a1", "dynamic_reproduction_state")
        assert state.status == "NOT_REQUESTED"
        return
    if case in {"claimed", "before_commit", "committed"}:

        class Crash(BaseException):
            pass

        def crash(stage: str) -> None:
            if stage == case:
                raise Crash

        monkeypatch.setattr(service.store, "checkpoint", crash)
        with pytest.raises(Crash):
            service.register(str(work.work_id), decision, reference(reservation))
        (state,) = runtime.queries.current_records("a1", "dynamic_reproduction_state")
        assert state.status == ("RUNNING" if case == "committed" else "NOT_REQUESTED")
        if case != "committed":
            assert not [
                r
                for r in runtime.queries.current_records("a1", "work_execution_state")
                if r.work_type == "DYNAMIC_REPRO"
            ]
        return
    pending = service.register(str(work.work_id), decision, reference(reservation))
    if case == "duplicate":
        counter = h.ids.index
        assert (
            service.register(str(work.work_id), decision, reference(reservation))
            == pending
        )
        assert h.ids.index == counter
    child = runner.activate(pending, scope, owner, role="VERIFICATION")
    (state,) = runtime.queries.current_records("a1", "dynamic_reproduction_state")
    assert state.status == "RUNNING"
    assert state.dynamic_work_ref == reference(child)
    assert state.request_ref == reference(request)
    assert state.verification_generation == 1 and state.dynamic_result_ref is None
    if case == "plan_failure":
        identity = h.records.get_exact(scope).dynamic_lifecycle_profile_ref
        h.evidence.identities[identity] = RequesterRole.REPRODUCTION_SESSION_MANAGER
        log = AgentLog.model_validate_json(
            canonical_bytes(
                dict(
                    meta=runner.metadata(
                        child.meta, "agent_log", attempt_id=child.active_attempt_id
                    ),
                    request_ref=reference(request),
                    events=(),
                )
            )
        )
        save = runner.action(
            child,
            identity,
            "REPRODUCTION_SESSION_MANAGER",
            "SAVE_RESULT",
            result_kind="agent_log",
            candidate_result_ref=h.records.stage_record(log),
        )
        runtime.intermediate.publish(
            str(child.work_id), runner.authorize(child, save), (log,)
        )
        result = DynamicReproductionResult.model_validate_json(
            canonical_bytes(
                make("DynamicReproductionResult")
                | dict(
                    meta=runner.metadata(
                        child.meta,
                        "dynamic_reproduction_result",
                        attempt_id=child.active_attempt_id,
                    ),
                    request_ref=reference(request),
                    agent_log_ref=reference(log),
                    started_at=h.clock.now(),
                    finished_at=h.clock.now(),
                    elapsed_ms=0,
                )
            )
        )
        finished = runner.complete(
            child,
            identity,
            "REPRODUCTION_SESSION_MANAGER",
            (result,),
            status="FAILED",
            cause="PLAN_FAILED",
            error_ids=("plan-error",),
        )
        (returned,) = runtime.queries.current_records(
            "a1", "dynamic_reproduction_state"
        )
        assert returned.status == "FAILED" and returned.dynamic_result_ref == reference(
            result
        )
        assert returned.dynamic_work_ref == reference(finished)
        (process,) = runtime.queries.current_records("a1", "hypothesis_process_state")
        assert process.status == "VERIFYING" and process.verification_result_ref is None
