import asyncio
import json
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

from sastsimi.contracts.actions import ActionType
from sastsimi.contracts.budget import BudgetReservation
from sastsimi.ports.dto import BudgetReservationRequest
from sastsimi.storage.codec import reference
from tests.integration.runtime_support import NOW, metadata, units
from tests.integration.storage.test_work import (
    authorization,
    decision_action,
    start_fixture,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("port", ["LLM", "STATIC_TOOL", "POLICY_HTTP", "DOCKER"])
async def test_external_wait_has_no_sqlite_write_transaction(
    tmp_path: Path, port: str
) -> None:
    from sastsimi.runtime.external_call_service import ExternalCallService

    h, works, attempts, transition, attempt, prior_reservation = start_fixture(tmp_path)
    work = attempts.start(
        transition, attempt, prior_reservation, "worker", NOW + timedelta(seconds=30)
    )
    # One generic external invocation boundary wraps each later port adapter.
    decision_ref = authorization(
        h,
        ActionType.READ_CODE,
        "external",
        reference(work),
        work.state_version,
        file_paths=["src/fixture.py"],
    )
    initial = h.records.get_exact(prior_reservation)
    assert isinstance(initial, BudgetReservation)
    wire = initial.model_dump(mode="json")
    wire.update(
        meta=metadata("budget_reservation", "external-reservation"),
        reservation_id="external-reservation",
        work_ref=reference(work).model_dump(mode="json"),
        action_ref=decision_action(h, decision_ref).model_dump(mode="json"),
        requested_units=units(),
    )
    reserved = works.validator.budget.reserve(
        BudgetReservationRequest(
            BudgetReservation.model_validate_json(json.dumps(wire))
        )
    )
    entered, release = asyncio.Event(), asyncio.Event()

    async def external_port() -> str:
        entered.set()
        await release.wait()
        return port

    service = ExternalCallService(works.validator)
    with pytest.raises(ValueError, match="BUDGET"):
        await service.invoke(str(work.work_id), decision_ref, None, external_port)
    task = asyncio.create_task(
        service.invoke(
            str(work.work_id), decision_ref, reference(reserved), external_port
        )
    )
    await asyncio.wait_for(entered.wait(), timeout=2)
    try:
        with h.database.write() as connection:
            connection.execute(
                text("INSERT INTO analysis_runs VALUES ('second-connection', '{}')")
            )
    finally:
        release.set()
    assert await task == port
    with pytest.raises(ValueError, match="USED"):
        await service.invoke(
            str(work.work_id), decision_ref, reference(reserved), external_port
        )


def test_unit_of_work_and_concrete_record_store_satisfy_published_ports(
    tmp_path: Path,
) -> None:
    from sastsimi.ports import RecordStore, UnitOfWork
    from sastsimi.storage.unit_of_work import SQLiteUnitOfWork
    from tests.integration.recovery.test_transitions import completion

    h, transitions, request = completion(tmp_path)
    unit = SQLiteUnitOfWork(h.records, transitions.artifacts, transitions)
    assert isinstance(unit, UnitOfWork)
    assert isinstance(unit.records, RecordStore)
    unit.rollback()
    committed = unit.commit(request)
    assert committed.state == "COMMITTED"
    assert unit.records.commit_transition(request) == committed
