from __future__ import annotations

import pytest

from sastsimi.contracts.dynamic import DynamicReproductionResult
from tests.contract.domain.fixtures import dynamic_failure, wire


@pytest.mark.parametrize("failure_category", ["AGENT", "TIMEOUT", "INTERNAL"])
def test_pre_boundary_provider_failure_preserves_its_operational_category(
    failure_category: str,
) -> None:
    result = wire(
        DynamicReproductionResult,
        dynamic_failure()
        | {
            "failure_category": failure_category,
            "failure_reason": "Provider did not complete the planning call",
            "plan_issues": [],
            "plan_execution_status": "EXECUTABLE",
            "limitations": [],
        },
    )

    assert result.action_decision_ref is None
    assert result.failure_category == failure_category
    assert result.hypothesis_outcome == "INCONCLUSIVE"
    assert result.poc_ref is None


def test_post_boundary_failure_category_requires_a_boundary_decision() -> None:
    with pytest.raises(ValueError, match="PRE_BOUNDARY_FAILURE_MISMATCH"):
        wire(
            DynamicReproductionResult,
            dynamic_failure()
            | {
                "failure_category": "EXECUTION",
                "failure_reason": "No boundary decision exists",
                "plan_issues": [],
                "plan_execution_status": "EXECUTABLE",
                "limitations": [],
            },
        )
