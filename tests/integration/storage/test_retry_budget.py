import json
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

from sastsimi.contracts.actions import ActionType
from sastsimi.contracts.budget import BudgetReservation
from sastsimi.contracts.work import StateTransition, WorkAttempt
from sastsimi.ports.dto import BudgetReservationRequest
from sastsimi.storage.attempt_service import AttemptService
from sastsimi.storage.codec import reference
from sastsimi.storage.recovery_service import RecoveryService
from tests.integration.recovery.test_transitions import completion
from tests.integration.runtime_support import NOW, metadata, units
from tests.integration.storage.test_work import authorization, decision_action


@pytest.mark.parametrize("retry_units", [0, 1])
def test_retry_attempt_requires_a_reserved_retry_unit(
    tmp_path: Path, retry_units: int
) -> None:
    h, transitions, pending = completion(tmp_path)
    with h.database.write() as connection:
        connection.execute(
            text("UPDATE work_states SET lease_expires_at='2026-09-06T00:00:00+00:00'")
        )
    RecoveryService(transitions, pending.transition.action_decision_ref).recover()
    works = transitions.works
    blocked = works.get("reserve-work")
    ready_decision = authorization(
        h, ActionType.CHANGE_WORK_STATE, "retry-ready", reference(blocked), 4
    )
    data = pending.transition.model_dump(mode="json")
    data.update(
        meta=metadata("state_transition", "retry-ready"),
        transition_id="retry-ready",
        action_decision_ref=ready_decision.model_dump(mode="json"),
        from_status="BLOCKED",
        to_status="READY",
        expected_state_version=4,
        new_state_version=5,
        attempt_id=None,
        cause="READY",
        output_refs=[],
    )
    ready = works.make_ready(StateTransition.model_validate_json(json.dumps(data)))
    decision = authorization(h, ActionType.START_ATTEMPT, "retry", reference(ready), 5)
    original = h.reservation(
        works.validator.budget.registry.pin_execution(
            h.execution(max_work=10)
        ).model_dump(mode="json"),
        "retry-reservation",
    ).reservation.model_dump(mode="json")
    original.update(
        work_ref=reference(ready).model_dump(mode="json"),
        action_ref=decision_action(h, decision).model_dump(mode="json"),
        requested_units=units(retry_count=retry_units),
    )
    reserved = works.validator.budget.reserve(
        BudgetReservationRequest(
            BudgetReservation.model_validate_json(json.dumps(original))
        )
    )
    data.update(
        meta=metadata("state_transition", "retry-start"),
        transition_id="retry-start",
        action_decision_ref=decision.model_dump(mode="json"),
        from_status="READY",
        to_status="RUNNING",
        expected_state_version=5,
        new_state_version=6,
        attempt_id="at2",
    )
    transition = StateTransition.model_validate_json(json.dumps(data))
    attempt = WorkAttempt.model_validate_json(
        json.dumps(
            dict(
                meta=metadata("work_attempt", "second-attempt"),
                work_id="reserve-work",
                attempt_id="at2",
                attempt_number=2,
                trigger="RETRY",
                input_hash=ready.input_hash,
                status="RUNNING",
                output_refs=[],
                gap_ids=[],
                error_ids=[],
                started_at="2026-09-07T00:00:00Z",
                finished_at=None,
                elapsed_ms=0,
            )
        )
    )

    def start() -> None:
        AttemptService(works).start(
            transition,
            attempt,
            reference(reserved),
            "retry-worker",
            NOW + timedelta(seconds=30),
        )

    if retry_units == 0:
        with pytest.raises(ValueError, match="BUDGET.*retry"):
            start()
        assert works.get("reserve-work").state_version == 5
    else:
        start()
        assert works.get("reserve-work").state_version == 6
