import json
from datetime import timedelta
from pathlib import Path

import pytest

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.actions import ActionRequest, RequesterRole
from sastsimi.contracts.budget import BudgetLedgerEntry, BudgetReservation
from sastsimi.contracts.work import (
    StateTransition,
    TransitionTargetStatus,
    WorkAttempt,
    WorkStatus,
)
from sastsimi.ports.dto import BudgetCommitRequest, BudgetReservationRequest
from sastsimi.storage.codec import reference
from tests.integration.runtime_support import NOW, metadata, units
from tests.integration.storage.test_work import start_fixture
from tests.unit.contracts.test_core_models import action


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["none", "prepared", "dispatched", "returned"])
async def test_public_recovery_separates_safe_retry_from_unknown_dispatch(
    tmp_path: Path, phase: str
) -> None:
    h, _, attempts, initial_transition, attempt, initial_ref = start_fixture(tmp_path)
    running = attempts.start(
        initial_transition, attempt, initial_ref, "worker", NOW + timedelta(seconds=30)
    )
    initial = h.records.get_exact(initial_ref)
    assert isinstance(initial, BudgetReservation)
    recovery_identity = initial_transition.action_decision_ref
    identity = initial.action_ref
    h.evidence.identities[identity] = RequesterRole.HYPOTHESIS
    runtime = build_runtime(
        tmp_path, None, None, h.clock, h.ids, recovery_identity, h.evidence
    )
    calls = 0

    async def operation() -> None:
        nonlocal calls
        calls += 1
        if phase == "returned":
            return
        raise RuntimeError("simulated lost external outcome")

    request = ActionRequest.model_validate_json(
        json.dumps(
            action(
                meta=metadata("action_request", "public-external"),
                action_id="public-external",
                action_type="READ_CODE",
                requested_by="HYPOTHESIS",
                requester_identity_ref=identity.model_dump(mode="json"),
                work_ref=reference(running).model_dump(mode="json"),
                expected_state_version=running.state_version,
                file_paths=["src/a.py"],
            )
        )
    )
    request_ref = runtime.unit_of_work.records.stage_record(request)
    reservation = BudgetReservation.model_validate(
        initial.model_dump()
        | dict(
            meta=initial.meta.model_copy(
                update={
                    "record_id": "public-external-budget",
                    "logical_record_id": "public-external-budget",
                }
            ),
            reservation_id="public-external-budget",
            action_ref=request_ref,
            work_ref=reference(running),
            requested_units=units(elapsed_ms=1, cost_minor_units=100),
        )
    )
    reserved = runtime.budget.reserve(BudgetReservationRequest(reservation))
    decision = runtime.validator.authorize(request, running, reference(reserved))
    assert decision.decision == "ALLOW", decision.check_results
    if phase == "prepared":
        runtime.validator.claim_external(
            str(running.work_id), reference(decision), reference(reserved)
        )
    elif phase == "dispatched":
        with pytest.raises(RuntimeError):
            await runtime.external.invoke(
                str(running.work_id),
                reference(decision),
                reference(reserved),
                operation,
                provider_request_id="provider-1",
                idempotency_key="idempotency-1",
            )
    elif phase == "returned":
        await runtime.external.invoke(
            str(running.work_id), reference(decision), reference(reserved), operation
        )
        entry = BudgetLedgerEntry.model_validate_json(
            json.dumps(
                dict(
                    meta=metadata("budget_ledger_entry", "returned-usage"),
                    ledger_entry_id="returned-usage",
                    reservation_ref=reference(reserved).model_dump(mode="json"),
                    budget_binding_ref=reserved.budget_binding_ref.model_dump(
                        mode="json"
                    ),
                    action_ref=reserved.action_ref.model_dump(mode="json"),
                    work_ref=reserved.work_ref.model_dump(mode="json"),
                    actual_units=units(),
                    usage_refs=[],
                    sequence=1,
                    committed_at=h.clock.now().isoformat(),
                )
            )
        )
        runtime.budget.commit_usage(BudgetCommitRequest(entry))
    h.clock.wall_time = NOW + timedelta(seconds=31)
    fresh = build_runtime(
        tmp_path, None, None, h.clock, h.ids, recovery_identity, h.evidence
    )
    blocked = fresh.work.get(str(running.work_id))
    assert blocked.status == "BLOCKED"
    assert blocked.waiting_for == (("INPUT",) if phase == "dispatched" else ("RETRY",))
    if phase == "dispatched":
        with pytest.raises(ValueError):
            await fresh.external.invoke(
                str(running.work_id),
                reference(decision),
                reference(reserved),
                operation,
            )
        assert calls == 1
    else:
        assert blocked.stop_reason == "LEASE_EXPIRED"
        assert (
            fresh.budget.remaining(
                initial.budget_binding_ref, "a1"
            ).available_units.cost_minor_units
            == 100
        )
        ready_action = ActionRequest.model_validate_json(
            json.dumps(
                action(
                    meta=metadata("action_request", "recovery-ready"),
                    action_id="recovery-ready",
                    action_type="CHANGE_WORK_STATE",
                    requested_by="RECOVERY",
                    requester_identity_ref=recovery_identity.model_dump(mode="json"),
                    work_ref=reference(blocked).model_dump(mode="json"),
                    expected_state_version=blocked.state_version,
                )
            )
        )
        approved = fresh.validator.authorize(ready_action)
        assert approved.decision == "ALLOW"
        transition = StateTransition.model_validate(
            initial_transition.model_dump()
            | dict(
                meta=initial_transition.meta.model_copy(
                    update={
                        "record_id": "recovery-ready-transition",
                        "logical_record_id": "recovery-ready-transition",
                    }
                ),
                transition_id="recovery-ready",
                action_decision_ref=reference(approved),
                from_status=WorkStatus.BLOCKED,
                to_status=TransitionTargetStatus.READY,
                expected_state_version=blocked.state_version,
                new_state_version=blocked.state_version + 1,
                attempt_id=None,
            )
        )
        ready = fresh.work.make_ready(transition)
        assert ready.status == "READY"
        restart = ActionRequest.model_validate_json(
            json.dumps(
                action(
                    meta=metadata("action_request", "retry-start"),
                    action_id="retry-start",
                    action_type="START_ATTEMPT",
                    requested_by="RECOVERY",
                    requester_identity_ref=recovery_identity.model_dump(mode="json"),
                    work_ref=reference(ready).model_dump(mode="json"),
                    expected_state_version=ready.state_version,
                )
            )
        )
        retry_reservation = BudgetReservation.model_validate_json(
            json.dumps(
                reserved.model_dump(mode="json")
                | dict(
                    meta=metadata("budget_reservation", "retry-budget"),
                    reservation_id="retry-budget",
                    action_ref=fresh.unit_of_work.records.stage_record(
                        restart
                    ).model_dump(mode="json"),
                    work_ref=reference(ready).model_dump(mode="json"),
                    requested_units=units(retry_count=1, cost_minor_units=1),
                )
            )
        )
        retry_budget = fresh.budget.reserve(BudgetReservationRequest(retry_reservation))
        retry_decision = fresh.validator.authorize(
            restart, ready, reference(retry_budget)
        )
        assert retry_decision.decision == "ALLOW", retry_decision.check_results
        new_attempt = WorkAttempt.model_validate_json(
            json.dumps(
                attempt.model_dump(mode="json")
                | dict(
                    meta=metadata("work_attempt", "retry-attempt"),
                    attempt_id="retry-attempt",
                    attempt_number=2,
                    trigger="RETRY",
                    started_at=h.clock.now().isoformat(),
                )
            )
        )
        retry_transition = StateTransition.model_validate_json(
            json.dumps(
                transition.model_dump(mode="json")
                | dict(
                    meta=metadata("state_transition", "retry-transition"),
                    transition_id="retry-transition",
                    action_decision_ref=reference(retry_decision).model_dump(
                        mode="json"
                    ),
                    from_status="READY",
                    to_status="RUNNING",
                    expected_state_version=ready.state_version,
                    new_state_version=ready.state_version + 1,
                    attempt_id="retry-attempt",
                )
            )
        )
        assert (
            fresh.attempts.start(
                retry_transition,
                new_attempt,
                reference(retry_budget),
                "worker",
                h.clock.now() + timedelta(seconds=30),
            ).status
            == "RUNNING"
        )
        if phase == "returned":
            h.clock.wall_time += timedelta(seconds=31)
            recovered_again = build_runtime(
                tmp_path, None, None, h.clock, h.ids, recovery_identity, h.evidence
            )
            later = recovered_again.work.get(str(running.work_id))
            assert later.waiting_for == ("RETRY",)
            assert later.stop_reason == "LEASE_EXPIRED"
            assert calls == 1
        else:
            assert calls == 0
