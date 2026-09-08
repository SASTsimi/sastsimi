import json
from datetime import timedelta
from pathlib import Path

import pytest

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.actions import ActionRequest, RequesterRole
from sastsimi.contracts.budget import BudgetLedgerEntry, BudgetReservation
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.refs import RecordRef
from sastsimi.ports.dto import BudgetCommitRequest, BudgetReservationRequest
from sastsimi.storage.codec import reference
from tests.integration.runtime_support import NOW, Harness, metadata, units
from tests.integration.storage.test_work import start_fixture
from tests.unit.contracts.test_core_models import action


@pytest.mark.parametrize(
    "field",
    [
        "max_analysis_elapsed_ms",
        "max_total_cost_minor_units",
        "max_total_llm_calls",
        "max_total_work",
    ],
)
@pytest.mark.parametrize("operation", ["REGISTER_WORK", "START_ATTEMPT"])
def test_public_register_cannot_start_analysis_with_zero_execution_capacity(
    tmp_path: Path, field: str, operation: str
) -> None:
    h = Harness(tmp_path)
    profile = h.execution().model_copy(update={field: 0})
    h.evidence.approvals.add(content_hash(profile))
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=h.evidence)
    scope = runtime.budget_registry.pin_execution(profile, h.analysis(profile))
    initial = h.reservation(scope.model_dump(mode="json"), work_count=1)
    action_record = h.records.get_exact(initial.reservation.action_ref)
    assert isinstance(action_record, ActionRequest)
    requested = ActionRequest.model_validate_json(
        json.dumps(
            action_record.model_dump(mode="json")
            | dict(
                meta=metadata("action_request", "zero-capacity-action"),
                action_id="zero-capacity-action",
                action_type=operation,
            )
        )
    )
    reservation = BudgetReservationRequest(
        initial.reservation.model_copy(
            update={"action_ref": h.records.stage_record(requested)}
        )
    )
    with pytest.raises(ValueError, match="BUDGET_EXCEEDED"):
        runtime.budget.reserve(reservation)


@pytest.mark.parametrize("prepared", [False, True])
def test_public_claim_and_dispatch_recheck_full_requested_fit(
    tmp_path: Path, prepared: bool
) -> None:
    h, _, attempts, transition, attempt, initial_ref = start_fixture(tmp_path)
    running = attempts.start(
        transition, attempt, initial_ref, "worker", NOW + timedelta(seconds=30)
    )
    initial = h.records.get_exact(initial_ref)
    assert isinstance(initial, BudgetReservation)
    identity = transition.action_decision_ref
    h.evidence.identities[identity] = RequesterRole.HYPOTHESIS
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=h.evidence)

    def reserve(name: str, cost: int) -> tuple[ActionRequest, BudgetReservation]:
        request = ActionRequest.model_validate_json(
            json.dumps(
                action(
                    meta=metadata("action_request", name),
                    action_id=name,
                    action_type="READ_CODE",
                    requested_by="HYPOTHESIS",
                    requester_identity_ref=identity.model_dump(mode="json"),
                    work_ref=reference(running).model_dump(mode="json"),
                    expected_state_version=running.state_version,
                    file_paths=["src/a.py"],
                )
            )
        )
        action_ref = runtime.unit_of_work.records.stage_record(request)
        reservation = BudgetReservation.model_validate(
            initial.model_dump()
            | dict(
                meta=initial.meta.model_copy(
                    update={
                        "record_id": name + "-budget",
                        "logical_record_id": name + "-budget",
                    }
                ),
                reservation_id=name + "-budget",
                work_ref=reference(running),
                action_ref=action_ref,
                requested_units=units(elapsed_ms=1, cost_minor_units=cost),
            )
        )
        # JSON boundary preserves the exact closed-unit and opaque-ID contracts.
        reservation = BudgetReservation.model_validate_json(
            reservation.model_dump_json()
        )
        return request, runtime.budget.reserve(BudgetReservationRequest(reservation))

    request, large = reserve("large", 80)
    _, small = reserve("small", 1)
    decision = runtime.validator.authorize(request, running, reference(large))
    assert decision.decision == "ALLOW", decision.check_results
    decision_ref: RecordRef = reference(decision)
    if prepared:
        runtime.validator.claim_external(
            str(running.work_id), decision_ref, reference(large)
        )
    entry = BudgetLedgerEntry.model_validate_json(
        json.dumps(
            dict(
                meta=metadata("budget_ledger_entry", "actual-50"),
                ledger_entry_id="actual-50",
                reservation_ref=reference(small).model_dump(mode="json"),
                budget_binding_ref=small.budget_binding_ref.model_dump(mode="json"),
                action_ref=small.action_ref.model_dump(mode="json"),
                work_ref=small.work_ref.model_dump(mode="json"),
                actual_units=units(cost_minor_units=50),
                usage_refs=[],
                sequence=1,
                committed_at="2026-09-07T00:00:00Z",
            )
        )
    )
    runtime.budget.commit_usage(BudgetCommitRequest(entry))
    with pytest.raises(ValueError, match="BUDGET_EXCEEDED"):
        if prepared:
            runtime.validator.mark_dispatched(decision_ref)
        else:
            runtime.validator.claim_external(
                str(running.work_id), decision_ref, reference(large)
            )
