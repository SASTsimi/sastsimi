import json
from pathlib import Path

import pytest

from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
    BudgetReservation,
    VerificationBudgetProfile,
    WorkBudgetProfile,
)
from sastsimi.contracts.refs import RunStoredDataRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import BudgetReservationRequest
from sastsimi.storage.budget_registry import BudgetProfileRegistry
from sastsimi.storage.budget_service import BudgetService
from tests.integration.runtime_support import Harness, metadata
from tests.unit.contracts.test_core_models import action, work


def test_verification_ancestor_work_budget_blocks_reservation(tmp_path: Path) -> None:
    h = Harness(tmp_path)
    registry = BudgetProfileRegistry(h.records)
    execution = registry.pin_execution(h.execution())
    binding, workspace = h.binding(execution.model_dump(mode="json"))
    profile = h.records.get_exact(binding.work_budget_profile_ref)
    assert isinstance(profile, WorkBudgetProfile)
    limits = profile.model_dump(mode="json")
    limits["meta"] = metadata("work_budget_profile", "verification-limits", code=True)
    limits["limits"][0].update(
        work_type="VERIFICATION",
        operation_kind="VERIFICATION_SYNTHESIS",
        agent_role="VERIFICATION",
    )
    ceiling = h.records.get_exact(binding.verification_budget_profile_ref)
    assert isinstance(ceiling, VerificationBudgetProfile)
    ceiling_data = ceiling.model_dump(mode="json")
    ceiling_data.update(
        meta=metadata("verification_budget_profile", "no-verification-work", code=True),
        max_work_per_verification=0,
    )
    binding_data = binding.model_dump(mode="json")
    binding_data.update(
        work_budget_profile_ref=h.publish(
            WorkBudgetProfile.model_validate_json(json.dumps(limits))
        ),
        verification_budget_profile_ref=h.publish(
            VerificationBudgetProfile.model_validate_json(json.dumps(ceiling_data))
        ),
    )
    binding = BudgetProfileBinding.model_validate_json(json.dumps(binding_data))
    scope = registry.pin_binding(
        binding, RunStoredDataRef.model_validate_json(json.dumps(workspace))
    )
    candidate = WorkExecutionState.model_validate_json(
        json.dumps(
            work(
                meta=metadata("work_execution_state", "verification-work", code=True),
                work_type="VERIFICATION",
            )
        )
    )
    request = ActionRequest.model_validate_json(
        json.dumps(
            action(meta=metadata("action_request", "register-verification", code=True))
        )
    )
    initial = h.reservation(
        execution.model_dump(mode="json"), work_count=1
    ).reservation.model_dump(mode="json")
    initial.update(
        meta=metadata("budget_reservation", "verification-reserve", code=True),
        budget_binding_ref=scope.model_dump(mode="json"),
        work_ref=h.records.stage_record(candidate).model_dump(mode="json"),
        action_ref=h.publish(request),
    )
    budget = BudgetService(h.records, registry, h.clock, h.ids)
    with pytest.raises(ValueError, match="BUDGET_EXCEEDED"):
        budget.reserve(
            BudgetReservationRequest(
                BudgetReservation.model_validate_json(json.dumps(initial))
            )
        )
