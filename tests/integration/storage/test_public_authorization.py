import json
from pathlib import Path

import pytest

from sastsimi.bootstrap import build_runtime, upgrade_database
from sastsimi.contracts.actions import ActionDecision, ActionRequest, RequesterRole
from sastsimi.contracts.budget import BudgetReservation
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import BudgetReservationRequest
from tests.integration.runtime_support import (
    Harness,
    TestClock,
    TestIds,
    metadata,
    units,
)
from tests.unit.contracts.test_core_models import action, decision, work


def test_public_validator_derives_denial_and_persists_checks(tmp_path: Path) -> None:
    upgrade_database(tmp_path)
    runtime = build_runtime(tmp_path, None, None, TestClock(), TestIds())
    request = ActionRequest.model_validate_json(
        json.dumps(
            action(meta=metadata("action_request", "untrusted"), action_id="untrusted")
        )
    )
    decision = runtime.validator.authorize(request)
    assert decision.decision == "DENY"
    assert any(
        check.check_type == "AUTHORITY" and check.result == "FAIL"
        for check in decision.check_results
    )
    assert runtime.unit_of_work.records.get_exact(decision.action_ref) == request
    assert runtime.validator.authorize(request) == decision


@pytest.mark.parametrize("forged", [False, True])
def test_public_bootstrap_authorizes_work_but_rejects_caller_pass(
    tmp_path: Path, forged: bool
) -> None:
    h = Harness(tmp_path)
    profile = h.execution()
    assert profile.approval_ref is not None
    h.evidence.approvals.add(content_hash(profile))
    h.evidence.identities[profile.approval_ref] = RequesterRole.ORCHESTRATION
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=h.evidence)
    scope = runtime.budget_registry.pin_execution(profile, h.analysis(profile))
    records = runtime.unit_of_work.records
    candidate = WorkExecutionState.model_validate_json(json.dumps(work()))
    request = ActionRequest.model_validate_json(
        json.dumps(
            action(
                meta=metadata("action_request", "public-action"),
                action_id="public-action",
                requester_identity_ref=profile.approval_ref.model_dump(mode="json"),
            )
        )
    )
    action_ref = records.stage_record(request)
    reservation = BudgetReservation.model_validate_json(
        json.dumps(
            dict(
                meta=metadata("budget_reservation", "public-reservation"),
                reservation_id="public-reservation",
                budget_binding_ref=scope.model_dump(mode="json"),
                action_ref=action_ref.model_dump(mode="json"),
                work_ref=records.stage_record(candidate).model_dump(mode="json"),
                requested_units=units(work_count=1),
                status="RESERVED",
                ledger_entry_ref=None,
                reserved_at="2026-09-07T00:00:00Z",
                finalized_at=None,
            )
        )
    )
    reserved = runtime.budget.reserve(BudgetReservationRequest(reservation))
    reserved_ref = records.stage_record(reserved)
    if forged:
        forged_decision = ActionDecision.model_validate_json(
            json.dumps(
                decision(
                    meta=metadata("action_decision", "forged"),
                    action_ref=action_ref.model_dump(mode="json"),
                )
            )
        )
        h.publish(forged_decision)
        with pytest.raises(ValueError, match="AUTHORITY_DENIED"):
            runtime.work.register(
                candidate, records.stage_record(forged_decision), reserved_ref
            )
    else:
        approved = runtime.validator.authorize(request, candidate, reserved_ref)
        assert approved.decision == "ALLOW"
        assert approved.checked_config_refs == (scope,)
        registered = runtime.work.register(
            candidate, records.stage_record(approved), reserved_ref
        )
        assert runtime.work.get(str(candidate.work_id)) == registered
