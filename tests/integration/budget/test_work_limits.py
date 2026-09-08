import json
from pathlib import Path

import pytest

from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
    BudgetReservation,
    WorkBudgetProfile,
)
from sastsimi.contracts.refs import RunStoredDataRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import BudgetReservationRequest
from sastsimi.storage.budget_registry import BudgetProfileRegistry
from sastsimi.storage.budget_service import BudgetService
from tests.integration.runtime_support import Harness, metadata
from tests.unit.contracts.test_core_models import action, work


@pytest.mark.parametrize(
    "action_type,limit_name",
    [("RUN_TOOL", "max_calls_per_work"), ("START_ATTEMPT", "max_attempts")],
)
def test_zero_work_limit_denies_operation(
    tmp_path: Path, action_type: str, limit_name: str
) -> None:
    h = Harness(tmp_path)
    registry = BudgetProfileRegistry(h.records)
    execution = registry.pin_execution(h.execution())
    binding, workspace = h.binding(execution.model_dump(mode="json"))
    limit_record = h.records.get_exact(binding.work_budget_profile_ref)
    assert isinstance(limit_record, WorkBudgetProfile)
    limits = limit_record.model_dump(mode="json")
    limits["meta"] = metadata("work_budget_profile", "deny-calls", code=True)
    limits["limits"][0][limit_name] = 0
    binding_data = binding.model_dump(mode="json")
    binding_data["work_budget_profile_ref"] = h.publish(
        WorkBudgetProfile.model_validate_json(json.dumps(limits))
    )
    binding = BudgetProfileBinding.model_validate_json(json.dumps(binding_data))
    scope = registry.pin_binding(
        binding, RunStoredDataRef.model_validate_json(json.dumps(workspace))
    )
    candidate = WorkExecutionState.model_validate_json(
        json.dumps(
            work(
                meta=metadata("work_execution_state", "static", code=True),
                work_type="STATIC_TOOL",
            )
        )
    )
    work_ref = h.records.stage_record(candidate)
    extra = (
        dict(tool_name="fixture", file_paths=["src/a.py"])
        if action_type == "RUN_TOOL"
        else {}
    )
    request = ActionRequest.model_validate_json(
        json.dumps(
            action(
                meta=metadata("action_request", "tool", code=True),
                action_type=action_type,
                **extra,
            )
        )
    )
    action_ref = h.publish(request)
    initial = h.reservation(execution.model_dump(mode="json")).reservation.model_dump(
        mode="json"
    )
    initial.update(
        meta=metadata("budget_reservation", "code", code=True),
        budget_binding_ref=scope.model_dump(mode="json"),
        work_ref=work_ref.model_dump(mode="json"),
        action_ref=action_ref,
    )
    ledger = BudgetService(h.records, registry, h.clock, h.ids)
    with pytest.raises(ValueError, match="BUDGET_EXCEEDED"):
        ledger.reserve(
            BudgetReservationRequest(
                BudgetReservation.model_validate_json(json.dumps(initial))
            )
        )
