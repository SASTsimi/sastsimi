import json
from pathlib import Path

import pytest

from sastsimi.contracts.actions import ActionType
from sastsimi.contracts.budget import BudgetReservation
from sastsimi.contracts.refs import RunStoredDataRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import BudgetReservationRequest
from sastsimi.storage.action_validator import RuntimeValidator
from sastsimi.storage.budget_registry import BudgetProfileRegistry
from sastsimi.storage.budget_service import BudgetService
from sastsimi.storage.codec import reference
from sastsimi.storage.work_service import WorkService
from tests.integration.runtime_support import Harness, metadata
from tests.integration.storage.test_work import authorization, decision_action
from tests.unit.contracts.test_core_models import work


def test_post_workspace_action_must_pin_checked_binding_and_work_profile(
    tmp_path: Path,
) -> None:
    h = Harness(tmp_path)
    registry = BudgetProfileRegistry(h.records)
    execution = registry.pin_execution(h.execution())
    binding, workspace = h.binding(execution.model_dump(mode="json"))
    scope = registry.pin_binding(
        binding, RunStoredDataRef.model_validate_json(json.dumps(workspace))
    )
    budget = BudgetService(h.records, registry, h.clock, h.ids)
    candidate = WorkExecutionState.model_validate_json(
        json.dumps(
            work(
                meta=metadata("work_execution_state", "static", code=True),
                work_type="STATIC_TOOL",
            )
        )
    )
    decision = authorization(h, ActionType.REGISTER_WORK, "register-static")
    initial = h.reservation(
        execution.model_dump(mode="json"), work_count=1
    ).reservation.model_dump(mode="json")
    initial.update(
        meta=metadata("budget_reservation", "code-reserve", code=True),
        reservation_id="code-reserve",
        budget_binding_ref=scope.model_dump(mode="json"),
        work_ref=h.records.stage_record(candidate).model_dump(mode="json"),
        action_ref=decision_action(h, decision).model_dump(mode="json"),
    )
    reserved = budget.reserve(
        BudgetReservationRequest(
            BudgetReservation.model_validate_json(json.dumps(initial))
        )
    )
    service = WorkService(
        h.records, RuntimeValidator(h.records, budget, h.clock, h.ids), h.clock, h.ids
    )
    with pytest.raises(ValueError, match="BUDGET.*checked"):
        service.register(candidate, decision, reference(reserved))
