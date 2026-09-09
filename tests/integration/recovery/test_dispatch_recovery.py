import json
from datetime import timedelta
from pathlib import Path

import pytest

from sastsimi.contracts.actions import ActionType
from sastsimi.contracts.budget import BudgetReservation
from sastsimi.contracts.refs import RecordRef, RunStoredDataRef, StoredDataRef
from sastsimi.ports.dto import BudgetReservationRequest
from sastsimi.runtime.external_call_service import ExternalCallService
from sastsimi.storage.codec import reference
from tests.integration.runtime_support import NOW, metadata, units
from tests.integration.storage.test_work import (
    authorization,
    decision_action,
    start_fixture,
)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "dispatched,expired,revoked",
    [
        (False, False, False),
        (False, True, False),
        (False, False, True),
        (True, False, False),
    ],
)
async def test_uncertain_dispatch_is_not_invoked_twice(
    tmp_path: Path, dispatched: bool, expired: bool, revoked: bool
) -> None:
    h, works, attempts, transition, attempt, initial_ref = start_fixture(tmp_path)
    running = attempts.start(
        transition, attempt, initial_ref, "worker", NOW + timedelta(seconds=30)
    )
    initial = h.records.get_exact(initial_ref)
    assert isinstance(initial, BudgetReservation)

    def prepare(name: str) -> tuple[RecordRef, RecordRef]:
        decision = authorization(
            h,
            ActionType.READ_CODE,
            name,
            reference(running),
            running.state_version,
            file_paths=["src/a.py"],
        )
        wire = initial.model_dump(mode="json")
        wire.update(
            meta=metadata("budget_reservation", name + "-reservation"),
            reservation_id=name + "-reservation",
            work_ref=reference(running).model_dump(mode="json"),
            action_ref=decision_action(h, decision).model_dump(mode="json"),
            requested_units=units(elapsed_ms=1, cost_minor_units=1),
        )
        reservation = works.validator.budget.reserve(
            BudgetReservationRequest(
                BudgetReservation.model_validate_json(json.dumps(wire))
            )
        )
        return decision, reference(reservation)

    decision, reservation = prepare("first-external")
    calls = 0

    class Crash(BaseException):
        pass

    async def operation() -> str:
        nonlocal calls
        calls += 1
        if dispatched:
            raise Crash
        return "done"

    service = ExternalCallService(works.validator)
    if not dispatched:
        works.validator.claim_external(str(running.work_id), decision, reservation)
        if revoked:
            h.evidence.approvals.clear()
            with pytest.raises(ValueError, match="BUDGET"):
                await service.invoke(
                    str(running.work_id), decision, reservation, operation
                )
            assert calls == 0
            return
        if expired:
            h.clock.wall_time = NOW + timedelta(minutes=2)
            with pytest.raises(ValueError, match="EXPIRED"):
                await service.invoke(
                    str(running.work_id), decision, reservation, operation
                )
            assert calls == 0
            return
        assert (
            await service.invoke(str(running.work_id), decision, reservation, operation)
            == "done"
        )
    else:
        with pytest.raises(Crash):
            await service.invoke(str(running.work_id), decision, reservation, operation)
        new_decision, new_reservation = prepare("second-external")
        with pytest.raises(ValueError, match="BLOCKED.*INPUT"):
            await ExternalCallService(works.validator).invoke(
                str(running.work_id), new_decision, new_reservation, operation
            )
        from sastsimi.bootstrap import build_runtime

        assert isinstance(decision, (RunStoredDataRef, StoredDataRef))

        fresh = build_runtime(
            tmp_path, None, None, h.clock, h.ids, decision, h.evidence
        )
        assert fresh.work.get(str(running.work_id)).status == "BLOCKED"
    assert calls == 1
