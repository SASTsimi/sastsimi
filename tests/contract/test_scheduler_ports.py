from dataclasses import FrozenInstanceError, fields

import pytest

from sastsimi.ports.scheduler import (
    AnalysisStatusView,
    CancellationObservation,
    CancellationTarget,
    RunOutcome,
)


def test_scheduler_transport_dtos_are_small_and_immutable() -> None:
    assert [item.name for item in fields(RunOutcome)] == [
        "analysis_id",
        "disposition",
        "result_ref",
    ]
    assert [item.name for item in fields(AnalysisStatusView)] == [
        "analysis_id",
        "run_status",
        "work_counts",
        "cancel_requested",
        "waiting_for",
        "result_ref",
        "failures",
    ]
    assert [item.name for item in fields(CancellationTarget)] == [
        "target_kind",
        "work",
        "attempt",
        "action_request_ref",
        "action_decision_ref",
        "call_spec_ref",
        "sandbox_resource_refs",
        "issued_action_decision_ref",
        "sandbox_resources",
        "sandbox_inventory_fingerprint",
    ]
    assert [item.name for item in fields(CancellationObservation)] == [
        "target",
        "status",
        "reason_code",
        "resource_observations",
    ]

    outcome = RunOutcome("analysis-1", "BLOCKED", None)
    with pytest.raises(FrozenInstanceError):
        outcome.disposition = "TERMINAL"  # type: ignore[misc]
