import json
from pathlib import Path

import pytest
from sqlalchemy import insert

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.actions import ActionRequest, RequesterRole
from sastsimi.contracts.hypothesis import VerificationAssignment
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.storage import models
from sastsimi.storage.codec import reference
from tests.integration.runtime_support import Harness, metadata
from tests.unit.contracts.test_core_models import action, ref, work


def test_hypothesis_process_state_is_a_resolvable_canonical_record(
    tmp_path: Path,
) -> None:
    from sastsimi.contracts.hypothesis import HypothesisProcessState

    h = Harness(tmp_path)
    state = HypothesisProcessState.model_validate_json(
        json.dumps(
            dict(
                meta=metadata("hypothesis_process_state", "process", code=True)
                | {"hypothesis_id": "h1"},
                proposal_ref=ref("hypothesis_proposal", True),
                status="REGISTERED",
                verification_assignment_ref=None,
                verification_generation=0,
                verification_work_ref=None,
                verification_result_ref=None,
                started_at="2026-09-07T00:00:00Z",
                finished_at=None,
                elapsed_ms=0,
            )
        )
    )
    stored = h.records.stage_record(state)
    h.publish(state)
    assert h.records.get_exact(stored) == state


@pytest.mark.parametrize(
    "invalid",
    [
        None,
        "owner",
        "generation",
        "assignment",
        "missing",
        "REQUEST_DYNAMIC_REPRO",
        "RESTART_VERIFICATION_GENERATION",
        "CALL_TECHNICAL_GATE",
        "CALL_RULE_SCOPE_GATE",
        "CREATE_REPORT_DRAFT",
        "r7-control",
    ],
)
def test_public_hypothesis_control_requires_current_owner_and_generation(
    tmp_path: Path, invalid: str | None
) -> None:
    from sastsimi.contracts.hypothesis import HypothesisProcessState

    h = Harness(tmp_path)
    from sastsimi.storage.budget_registry import BudgetProfileRegistry

    h.pin_execution(BudgetProfileRegistry(h.records, h.clock, h.ids), h.execution())
    identity = StoredDataRef.model_validate_json(json.dumps(ref("identity", True)))
    h.evidence.identities[identity] = RequesterRole.VERIFICATION
    target = WorkExecutionState.model_validate_json(
        json.dumps(
            work(
                meta=metadata("work_execution_state", "verification-work", code=True)
                | {"hypothesis_id": "h1"},
                work_id="verification-work",
                work_type="VERIFICATION",
                subject_type="HYPOTHESIS",
                subject_id="h1",
            )
        )
    )
    assignment = VerificationAssignment.model_validate_json(
        json.dumps(
            dict(
                meta=metadata("verification_assignment", "assignment", code=True)
                | {"hypothesis_id": "h1"},
                assignment_id="assignment",
                owner_identity_ref=ref(
                    "other-identity" if invalid == "owner" else "identity", True
                ),
                assignment_generation=1,
                status="SUPERSEDED" if invalid == "assignment" else "ACTIVE",
                previous_assignment_ref=None,
                assigned_at="2026-09-07T00:00:00Z",
            )
        )
    )
    h.publish(assignment)
    state = HypothesisProcessState.model_validate_json(
        json.dumps(
            dict(
                meta=metadata("hypothesis_process_state", "process", code=True)
                | {"hypothesis_id": "h1"},
                proposal_ref=ref("hypothesis_proposal", True),
                status="ASSIGNED",
                verification_assignment_ref=reference(assignment).model_dump(
                    mode="json"
                ),
                verification_generation=2 if invalid == "generation" else 1,
                verification_work_ref=None,
                verification_result_ref=None,
                started_at="2026-09-07T00:00:00Z",
                finished_at=None,
                elapsed_ms=0,
            )
        )
    )
    for record in (target, assignment, state):
        h.publish(record)
        if invalid == "missing" and record == state:
            continue
        with h.database.write() as connection:
            connection.execute(
                insert(models.current_records).values(
                    logical_record_id=str(record.meta.logical_record_id),
                    record_id=str(record.meta.record_id),
                    state_version=1,
                )
            )
    with h.database.write() as connection:
        connection.execute(
            insert(models.work_states).values(
                work_id=str(target.work_id),
                analysis_id="a1",
                registration_key=target.dedupe_key,
                state_version=1,
                status="PENDING",
                payload=target.model_dump_json(),
            )
        )
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=h.evidence)
    from tests.integration.storage.test_action_role_policy import action_shape

    stage = invalid in {
        "REQUEST_DYNAMIC_REPRO",
        "RESTART_VERIFICATION_GENERATION",
        "CALL_TECHNICAL_GATE",
        "CALL_RULE_SCOPE_GATE",
        "CREATE_REPORT_DRAFT",
    }
    role = "REPRODUCTION_SESSION_MANAGER" if invalid == "r7-control" else "VERIFICATION"
    h.evidence.identities[identity] = RequesterRole(role)
    request = ActionRequest.model_validate_json(
        json.dumps(
            (action_shape(str(invalid)) if stage else action())
            | dict(
                meta=metadata("action_request", "cancel", code=True)
                | {"hypothesis_id": "h1"},
                requested_by=role,
                requester_identity_ref=identity.model_dump(mode="json"),
                action_type=str(invalid) if stage else "CANCEL_WORK",
                work_ref=reference(target).model_dump(mode="json"),
                expected_state_version=1,
                **(
                    {
                        "expected_verification_generation": 2,
                        "input_refs": [
                            reference(target).model_dump(mode="json")
                            if item == action_shape(str(invalid))["work_ref"]
                            else item
                            for item in action_shape(str(invalid))["input_refs"]
                        ],
                    }
                    if invalid == "RESTART_VERIFICATION_GENERATION"
                    else {}
                ),
            )
        )
    )
    decision = runtime.validator.authorize(request)
    if invalid == "RESTART_VERIFICATION_GENERATION":
        assert "generation mismatch" in next(
            check.reason_code
            for check in decision.check_results
            if check.check_type == "STATE"
        )
    if stage or invalid == "r7-control":
        assert (
            next(
                check.result
                for check in decision.check_results
                if check.check_type == "STATE"
            )
            == "FAIL"
        )
    assert decision.decision == ("ALLOW" if invalid is None else "DENY"), (
        decision.check_results
    )
