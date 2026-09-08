import json
from pathlib import Path

import pytest
from sqlalchemy import text

from sastsimi.contracts.budget import BudgetLedgerEntry, BudgetReservation
from sastsimi.ports.dto import BudgetCommitRequest, BudgetReleaseRequest
from sastsimi.storage.budget_registry import BudgetProfileRegistry
from sastsimi.storage.budget_service import BudgetService
from sastsimi.storage.codec import reference
from tests.integration.runtime_support import Harness, metadata, units


def test_changed_entry_id_cannot_debit_same_reservation_twice(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    registry = BudgetProfileRegistry(h.records)
    scope = registry.pin_execution(h.execution())
    service = BudgetService(h.records, registry, h.clock, h.ids)
    reservation = service.reserve(
        h.reservation(scope.model_dump(mode="json"), work_count=1)
    )
    entry = BudgetLedgerEntry.model_validate_json(
        json.dumps(
            dict(
                meta=metadata("budget_ledger_entry", "entry"),
                ledger_entry_id="entry",
                reservation_ref=reference(reservation).model_dump(mode="json"),
                budget_binding_ref=scope.model_dump(mode="json"),
                action_ref=reservation.action_ref.model_dump(mode="json"),
                work_ref=reservation.work_ref.model_dump(mode="json"),
                actual_units=units(work_count=1),
                usage_refs=[],
                sequence=1,
                committed_at="2026-09-07T00:00:00Z",
            )
        )
    )
    service.commit_usage(BudgetCommitRequest(entry))
    changed = entry.model_dump(mode="json")
    changed.update(
        meta=metadata("budget_ledger_entry", "another-entry"),
        ledger_entry_id="another-entry",
        sequence=2,
    )
    with pytest.raises(ValueError, match="Duplicate debit"):
        service.commit_usage(
            BudgetCommitRequest(
                BudgetLedgerEntry.model_validate_json(json.dumps(changed))
            )
        )
    with h.database.engine.connect() as connection:
        assert (
            connection.execute(
                text("SELECT count(*) FROM budget_ledger_entries")
            ).scalar()
            == 1
        )


def test_claimed_reservation_cannot_be_released_as_unused(tmp_path: Path) -> None:
    from tests.integration.storage.test_work import start_fixture

    h, works, attempts, transition, attempt, ref = start_fixture(tmp_path)
    initial = h.records.get_exact(ref)
    assert isinstance(initial, BudgetReservation)
    # Registration already claimed its own reservation; unknown usage is retained.
    with h.database.engine.connect() as connection:
        payload = connection.execute(
            text(
                "SELECT payload FROM budget_reservations WHERE reservation_id='reserve'"
            )
        ).scalar_one()
    data = BudgetReservation.model_validate_json(payload).model_dump(mode="json")
    data.update(status="RELEASED", finalized_at="2026-09-07T00:00:00Z")
    data["meta"].update(
        record_id="release", previous_record_id="reserve", revision_number=2
    )
    with pytest.raises(ValueError, match="uncertain"):
        works.validator.budget.release(
            BudgetReleaseRequest(
                BudgetReservation.model_validate_json(json.dumps(data))
            )
        )


def test_zero_work_reservation_cannot_authorize_new_work(tmp_path: Path) -> None:
    from sastsimi.contracts.actions import ActionType
    from sastsimi.contracts.work import WorkExecutionState
    from sastsimi.ports.dto import BudgetReservationRequest
    from sastsimi.storage.action_validator import RuntimeValidator
    from sastsimi.storage.work_service import WorkService
    from tests.integration.storage.test_work import authorization, decision_action

    h = Harness(tmp_path)
    registry = BudgetProfileRegistry(h.records)
    scope = registry.pin_execution(h.execution())
    budget = BudgetService(h.records, registry, h.clock, h.ids)
    works = WorkService(
        h.records, RuntimeValidator(h.records, budget, h.clock, h.ids), h.clock, h.ids
    )
    request = h.reservation(scope.model_dump(mode="json"))
    decision = authorization(h, ActionType.REGISTER_WORK, "zero")
    request = BudgetReservationRequest(
        request.reservation.model_copy(
            update={"action_ref": decision_action(h, decision)}
        )
    )
    reserved = budget.reserve(request)
    with h.database.engine.connect() as connection:
        work = h.records.resolve(connection, reserved.work_ref, candidate=True)
    assert isinstance(work, WorkExecutionState)
    with pytest.raises(ValueError, match="BUDGET"):
        works.register(work, decision, reference(reserved))
