import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from sastsimi.contracts.budget import (
    BudgetLedgerEntry,
    BudgetReservation,
    ProfileStatus,
)
from sastsimi.ports.dto import BudgetCommitRequest, BudgetReleaseRequest
from tests.integration.runtime_support import Harness, metadata, units


def test_full_binding_requires_ready_workspace_and_all_active_exact_profiles(
    tmp_path: Path,
) -> None:
    from sastsimi.contracts.refs import RunStoredDataRef
    from sastsimi.storage.budget_registry import BudgetProfileRegistry

    h = Harness(tmp_path)
    registry = BudgetProfileRegistry(h.records)
    execution = registry.pin_execution(h.execution())
    binding, workspace = h.binding(execution.model_dump(mode="json"))
    scope = registry.pin_binding(
        binding, RunStoredDataRef.model_validate_json(json.dumps(workspace))
    )
    with h.database.engine.connect() as connection:
        assert registry.execution(connection, scope, "a1").profile_key == "approved"
    other = binding.model_copy(update={"status": ProfileStatus.RETIRED})
    with pytest.raises(ValueError, match="ACTIVE"):
        registry.pin_binding(
            other, RunStoredDataRef.model_validate_json(json.dumps(workspace))
        )


def test_post_workspace_reservation_denies_execution_only_and_unlisted_operation(
    tmp_path: Path,
) -> None:
    from sastsimi.contracts.refs import RunStoredDataRef
    from sastsimi.contracts.work import WorkExecutionState
    from sastsimi.ports.dto import BudgetReservationRequest
    from sastsimi.storage.budget_registry import BudgetProfileRegistry
    from sastsimi.storage.budget_service import BudgetService
    from tests.unit.contracts.test_core_models import work

    h = Harness(tmp_path)
    registry = BudgetProfileRegistry(h.records)
    execution = registry.pin_execution(h.execution())
    binding, workspace = h.binding(execution.model_dump(mode="json"))
    ledger = BudgetService(h.records, registry, h.clock, h.ids)
    initial = h.reservation(execution.model_dump(mode="json"), work_count=1).reservation
    candidate = WorkExecutionState.model_validate_json(
        json.dumps(
            work(
                meta=metadata("work_execution_state", "static", code=True),
                work_type="STATIC_TOOL",
            )
        )
    )
    exact_work = h.records.stage_record(candidate)
    scope = registry.pin_binding(
        binding, RunStoredDataRef.model_validate_json(json.dumps(workspace))
    )
    data = initial.model_dump(mode="json")
    data.update(
        meta=metadata("budget_reservation", "code-reservation", code=True),
        work_ref=exact_work.model_dump(mode="json"),
        budget_binding_ref=scope.model_dump(mode="json"),
    )
    request = BudgetReservationRequest(
        BudgetReservation.model_validate_json(json.dumps(data))
    )
    assert ledger.reserve(request).status == "RESERVED"
    unsupported = WorkExecutionState.model_validate_json(
        json.dumps(
            work(
                meta=metadata("work_execution_state", "other", code=True),
                work_type="STATIC_NORMALIZE",
            )
        )
    )
    data.update(
        reservation_id="unlisted",
        work_ref=h.records.stage_record(unsupported).model_dump(mode="json"),
    )
    data["meta"] = metadata("budget_reservation", "unlisted", code=True)
    with pytest.raises(ValueError, match="DENY"):
        ledger.reserve(
            BudgetReservationRequest(
                BudgetReservation.model_validate_json(json.dumps(data))
            )
        )


def test_inactive_or_unpinned_budget_cannot_reserve(tmp_path: Path) -> None:
    from sastsimi.storage.budget_registry import BudgetProfileRegistry
    from sastsimi.storage.budget_service import BudgetService

    h = Harness(tmp_path)
    registry = BudgetProfileRegistry(h.records)
    profile = h.execution()
    request = h.reservation(h.publish(profile), work_count=1)
    ledger = BudgetService(h.records, registry, h.clock, h.ids)
    with pytest.raises(ValueError, match="BUDGET"):
        ledger.reserve(request)
    registry.pin_execution(profile)
    assert ledger.reserve(request).status == "RESERVED"


def test_concurrent_reservations_cannot_overbook_and_restart_preserves_unknown(
    tmp_path: Path,
) -> None:
    from sastsimi.storage.budget_registry import BudgetProfileRegistry
    from sastsimi.storage.budget_service import BudgetService

    h = Harness(tmp_path)
    registry = BudgetProfileRegistry(h.records)
    scope = registry.pin_execution(h.execution(max_work=1))
    ledger = BudgetService(h.records, registry, h.clock, h.ids)
    requests = [
        h.reservation(scope.model_dump(mode="json"), name, work_count=1)
        for name in ("r1", "r2")
    ]

    def reserve(index: int) -> bool:
        try:
            ledger.reserve(requests[index])
            return True
        except ValueError as error:
            assert "BUDGET_EXCEEDED" in str(error)
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(reserve, (0, 1))) == [False, True]
    fresh = BudgetService(h.records, registry, h.clock, h.ids)
    remaining = fresh.remaining(scope, "a1")
    assert remaining.active_reservation_count == 1
    assert remaining.available_units.work_count == 0
    with pytest.raises(ValueError, match="analysis"):
        fresh.remaining(scope, "another-analysis")


def test_usage_is_committed_once_and_preexecution_release_restores_units(
    tmp_path: Path,
) -> None:
    from sastsimi.storage.budget_registry import BudgetProfileRegistry
    from sastsimi.storage.budget_service import BudgetService

    h = Harness(tmp_path)
    registry = BudgetProfileRegistry(h.records)
    scope = registry.pin_execution(h.execution())
    ledger = BudgetService(h.records, registry, h.clock, h.ids)
    reserved = ledger.reserve(
        h.reservation(scope.model_dump(mode="json"), work_count=1)
    )
    reservation_ref = h.records.stage_record(reserved)
    data = dict(
        meta=metadata("budget_ledger_entry", "entry"),
        ledger_entry_id="entry",
        reservation_ref=reservation_ref.model_dump(mode="json"),
        budget_binding_ref=scope.model_dump(mode="json"),
        action_ref=reserved.action_ref.model_dump(mode="json"),
        work_ref=reserved.work_ref.model_dump(mode="json"),
        actual_units=units(work_count=1),
        usage_refs=[],
        sequence=1,
        committed_at="2026-09-07T00:00:00Z",
    )
    request = BudgetCommitRequest(
        BudgetLedgerEntry.model_validate_json(json.dumps(data))
    )
    first = ledger.commit_usage(request)
    assert ledger.commit_usage(request) == first
    assert ledger.remaining(scope, "a1").available_units.work_count == 1
    second = ledger.reserve(
        h.reservation(scope.model_dump(mode="json"), "r2", work_count=1)
    )
    released_data = second.model_dump(mode="json")
    released_data.update(status="RELEASED", finalized_at="2026-09-07T00:00:00Z")
    released_data["meta"].update(
        record_id="released", revision_number=2, previous_record_id="r2"
    )
    released = BudgetReleaseRequest(
        BudgetReservation.model_validate_json(json.dumps(released_data))
    )
    assert ledger.release(released).status == "RELEASED"
    assert ledger.release(released).status == "RELEASED"
    assert ledger.remaining(scope, "a1").available_units.work_count == 1
