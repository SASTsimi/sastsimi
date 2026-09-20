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
from sastsimi.storage.budget_limits import (
    LOCAL_MANUAL_REPAIR_ATTEMPTS,
    allows_local_manual_repair_scope,
)
from sastsimi.storage.budget_registry import BudgetProfileRegistry
from sastsimi.storage.budget_service import (
    BudgetService,
    _allows_local_manual_repair_attempt,
)
from tests.integration.runtime_support import Harness, metadata
from tests.unit.contracts.test_core_models import action, work


def test_local_manual_resume_allows_bounded_repair_attempts() -> None:
    assert LOCAL_MANUAL_REPAIR_ATTEMPTS == 8
    assert _allows_local_manual_repair_attempt(
        purpose="LOCAL_EVALUATION",
        action_type="START_ATTEMPT",
        action_reason="Claim exact READY work",
        work_status="READY",
        transition_cause="USER_RESUME",
    )
    assert allows_local_manual_repair_scope(
        purpose="LOCAL_EVALUATION",
        work_status="RUNNING",
        transition_cause="STARTED",
        attempt_trigger="RESUME",
    )


def test_repair_attempt_remains_closed_outside_local_manual_resume() -> None:
    assert not _allows_local_manual_repair_attempt(
        purpose="PRODUCTION",
        action_type="START_ATTEMPT",
        action_reason="Claim exact READY work",
        work_status="READY",
        transition_cause="USER_RESUME",
    )
    assert not _allows_local_manual_repair_attempt(
        purpose="LOCAL_EVALUATION",
        action_type="START_ATTEMPT",
        action_reason="Claim exact READY work",
        work_status="READY",
        transition_cause=None,
    )
    assert not allows_local_manual_repair_scope(
        purpose="PRODUCTION",
        work_status="RUNNING",
        transition_cause="STARTED",
        attempt_trigger="RESUME",
    )


@pytest.mark.parametrize(
    "action_type,limit_name",
    [("RUN_TOOL", "max_calls_per_work"), ("START_ATTEMPT", "max_attempts")],
)
def test_zero_work_limit_denies_operation(
    tmp_path: Path, action_type: str, limit_name: str
) -> None:
    h = Harness(tmp_path)
    registry = BudgetProfileRegistry(h.records, h.clock, h.ids)
    execution = h.pin_execution(registry, h.execution())
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
    scope = h.pin_binding(
        registry, binding, RunStoredDataRef.model_validate_json(json.dumps(workspace))
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
    initial["requested_units"].update(elapsed_ms=1, cost_minor_units=1)
    ledger = BudgetService(h.records, registry, h.clock, h.ids)
    with pytest.raises(ValueError, match="BUDGET_EXCEEDED"):
        ledger.reserve(
            BudgetReservationRequest(
                BudgetReservation.model_validate_json(json.dumps(initial))
            )
        )
