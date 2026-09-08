import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import pytest

from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
    BudgetReservation,
    DynamicReproductionLifecycleProfile,
    VerificationBudgetProfile,
    WorkBudgetProfile,
)
from sastsimi.contracts.refs import RunStoredDataRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import BudgetReservationRequest
from sastsimi.runtime.budget_service import BudgetService
from sastsimi.storage.budget_registry import BudgetProfileRegistry
from sastsimi.storage.budget_service import BudgetService as SQLiteBudget
from tests.integration.runtime_support import Harness, metadata, units
from tests.unit.contracts.test_core_models import action, work


def capacity_fixture(
    tmp_path: Path,
    work_type: str = "DYNAMIC_REPRO",
    *,
    retries: int = 1,
    items: int = 10,
    parallel: int = 1,
) -> tuple[Harness, BudgetService, Any]:
    h = Harness(tmp_path)
    registry = BudgetProfileRegistry(h.records, h.clock, h.ids)
    execution = h.pin_execution(
        registry,
        h.execution().model_copy(
            update={
                "max_analysis_elapsed_ms": 10000,
                "max_total_retries": 10,
                "max_total_work": 20,
            }
        ),
    )
    binding, workspace = h.binding(execution.model_dump(mode="json"))
    profile = h.records.get_exact(binding.work_budget_profile_ref)
    assert isinstance(profile, WorkBudgetProfile)
    data = profile.model_dump(mode="json")
    data["meta"] = metadata("work_budget_profile", "capacity-limits", code=True)
    role = "DYNAMIC_REPRODUCTION" if work_type == "DYNAMIC_REPRO" else "PRO"
    data["limits"][0].update(
        work_type=work_type,
        operation_kind=work_type,
        agent_role=role,
        max_attempts=10,
        max_calls_per_work=10,
        max_items_per_work=items,
    )
    work_profile_ref = h.publish(
        WorkBudgetProfile.model_validate_json(json.dumps(data))
    )
    lifecycle = h.records.get_exact(binding.dynamic_lifecycle_profile_ref)
    assert isinstance(lifecycle, DynamicReproductionLifecycleProfile)
    data = lifecycle.model_dump(mode="json")
    data.update(
        meta=metadata(
            "dynamic_reproduction_lifecycle_profile", "capacity-dynamic", code=True
        ),
        preflight_budget_ref=work_profile_ref,
        max_new_attempts=retries,
    )
    lifecycle_ref = h.publish(
        DynamicReproductionLifecycleProfile.model_validate_json(json.dumps(data))
    )
    verification = h.records.get_exact(binding.verification_budget_profile_ref)
    assert isinstance(verification, VerificationBudgetProfile)
    data = verification.model_dump(mode="json")
    data.update(
        meta=metadata(
            "verification_budget_profile", "capacity-verification", code=True
        ),
        max_verification_elapsed_ms=10000,
        max_retries_per_work=10,
        max_parallel_evidence_calls=parallel,
    )
    verification_ref = h.publish(
        VerificationBudgetProfile.model_validate_json(json.dumps(data))
    )
    data = binding.model_dump(mode="json")
    data.update(
        work_budget_profile_ref=work_profile_ref,
        dynamic_lifecycle_profile_ref=lifecycle_ref,
        verification_budget_profile_ref=verification_ref,
    )
    scope = h.pin_binding(
        registry,
        BudgetProfileBinding.model_validate_json(json.dumps(data)),
        RunStoredDataRef.model_validate_json(json.dumps(workspace)),
    )
    parent = WorkExecutionState.model_validate_json(
        json.dumps(
            work(
                meta=metadata("work_execution_state", "parent", code=True),
                work_id="parent",
                work_type="VERIFICATION",
            )
        )
    )
    parent_ref = h.publish(parent)

    def reservation(
        name: str,
        action_type: str = "READ_CODE",
        elapsed: int = 1,
        retry: int = 0,
        child: str = "child",
    ) -> BudgetReservationRequest:
        candidate = WorkExecutionState.model_validate_json(
            json.dumps(
                work(
                    meta=metadata("work_execution_state", child, code=True),
                    work_id=child,
                    work_type=work_type,
                    parent_work_ref=parent_ref,
                )
            )
        )
        extra = dict(file_paths=["src/a.py"]) if action_type == "READ_CODE" else {}
        request = ActionRequest.model_validate_json(
            json.dumps(
                action(
                    meta=metadata("action_request", name, code=True),
                    action_id=name,
                    action_type=action_type,
                    **extra,
                )
            )
        )
        return BudgetReservationRequest(
            BudgetReservation.model_validate_json(
                json.dumps(
                    dict(
                        meta=metadata(
                            "budget_reservation", name + "-reservation", code=True
                        ),
                        reservation_id=name + "-reservation",
                        budget_binding_ref=scope.model_dump(mode="json"),
                        action_ref=h.publish(request),
                        work_ref=h.records.stage_record(candidate).model_dump(
                            mode="json"
                        ),
                        requested_units=units(
                            elapsed_ms=elapsed, retry_count=retry, cost_minor_units=1
                        ),
                        status="RESERVED",
                        ledger_entry_ref=None,
                        reserved_at="2026-09-07T00:00:00Z",
                        finalized_at=None,
                    )
                )
            )
        )

    return (
        h,
        BudgetService(SQLiteBudget(h.records, registry, h.clock, h.ids)),
        reservation,
    )


def test_dynamic_initial_does_not_consume_retry_allowance(tmp_path: Path) -> None:
    _, budget, reserve = capacity_fixture(tmp_path, retries=0)
    assert budget.reserve(reserve("initial", "START_ATTEMPT")).status == "RESERVED"


def test_dynamic_last_retry_allowed_next_retry_denied(tmp_path: Path) -> None:
    _, budget, reserve = capacity_fixture(tmp_path, retries=1)
    budget.reserve(reserve("initial", "START_ATTEMPT"))
    assert (
        budget.reserve(reserve("retry", "START_ATTEMPT", retry=1)).status == "RESERVED"
    )
    with pytest.raises(ValueError, match="dynamic attempts"):
        budget.reserve(reserve("extra", "START_ATTEMPT", retry=1))


@pytest.mark.parametrize("second", [0, 450])
def test_dynamic_cumulative_remaining_time_is_enforced(
    tmp_path: Path, second: int
) -> None:
    _, budget, reserve = capacity_fixture(tmp_path)
    budget.reserve(reserve("first", elapsed=1000 if second == 0 else 600))
    with pytest.raises(ValueError, match="BUDGET_EXCEEDED"):
        budget.reserve(reserve("second", elapsed=second))


def test_zero_approved_item_limit_fails_closed(tmp_path: Path) -> None:
    _, budget, reserve = capacity_fixture(tmp_path, items=0)
    with pytest.raises(ValueError, match="BUDGET_EXCEEDED"):
        budget.reserve(reserve("items"))


def test_item_admission_is_cumulative_per_work(tmp_path: Path) -> None:
    _, budget, reserve = capacity_fixture(tmp_path, items=1)
    budget.reserve(reserve("first-item"))
    with pytest.raises(ValueError, match="BUDGET_EXCEEDED.*items"):
        budget.reserve(reserve("second-item"))


def test_parallel_evidence_reservations_are_atomic(tmp_path: Path) -> None:
    _, budget, reserve = capacity_fixture(tmp_path, "PRO_EVIDENCE", parallel=1)
    requests = [reserve("pro-one", child="one"), reserve("pro-two", child="two")]

    def admit(index: int) -> bool:
        try:
            budget.reserve(requests[index])
            return True
        except ValueError as error:
            assert "BUDGET_EXCEEDED" in str(error)
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(admit, (0, 1))) == [False, True]


def test_exhausted_execution_cannot_be_bypassed_with_zero_units(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    registry = BudgetProfileRegistry(h.records, h.clock, h.ids)
    scope = h.pin_execution(
        registry, h.execution().model_copy(update={"max_analysis_elapsed_ms": 0})
    )
    initial = h.reservation(scope.model_dump(mode="json")).reservation.model_dump(
        mode="json"
    )
    request = ActionRequest.model_validate_json(
        json.dumps(
            action(
                meta=metadata("action_request", "external"),
                action_id="external",
                action_type="READ_CODE",
                file_paths=["src/a.py"],
            )
        )
    )
    initial["action_ref"] = h.publish(request)
    with pytest.raises(ValueError, match="BUDGET_EXCEEDED"):
        BudgetService(SQLiteBudget(h.records, registry, h.clock, h.ids)).reserve(
            BudgetReservationRequest(
                BudgetReservation.model_validate_json(json.dumps(initial))
            )
        )
