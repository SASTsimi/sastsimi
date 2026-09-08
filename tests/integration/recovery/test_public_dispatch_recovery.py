import json
from datetime import timedelta
from pathlib import Path

import pytest

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.actions import ActionRequest, RequesterRole
from sastsimi.contracts.budget import BudgetReservation
from sastsimi.contracts.work import StateTransition, TransitionTargetStatus, WorkStatus
from sastsimi.ports.dto import BudgetReservationRequest
from sastsimi.storage.codec import reference
from tests.integration.runtime_support import NOW, metadata, units
from tests.integration.storage.test_work import start_fixture
from tests.unit.contracts.test_core_models import action


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["none", "prepared", "dispatched"])
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
            requested_units=units(elapsed_ms=1, cost_minor_units=1),
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
        assert fresh.work.make_ready(transition).status == "READY"
        assert calls == 0
