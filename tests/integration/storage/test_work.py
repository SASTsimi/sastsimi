import json
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from sastsimi.contracts.actions import (
    REQUIRED_CHECKS,
    ActionDecision,
    ActionRequest,
    ActionType,
)
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
)
from sastsimi.contracts.work import StateTransition, WorkAttempt, WorkExecutionState
from sastsimi.ports.dto import BudgetReservationRequest
from sastsimi.storage.attempt_service import AttemptService
from sastsimi.storage.work_service import WorkService
from tests.integration.runtime_support import NOW, Harness, metadata
from tests.unit.contracts.test_core_models import action, decision


def setup_services(h: Harness) -> tuple[object, object, object]:
    from sastsimi.storage.action_validator import RuntimeValidator
    from sastsimi.storage.attempt_service import AttemptService
    from sastsimi.storage.budget_registry import BudgetProfileRegistry
    from sastsimi.storage.budget_service import BudgetService
    from sastsimi.storage.work_service import WorkService

    registry = BudgetProfileRegistry(h.records, h.clock, h.ids)
    h.pin_execution(registry, h.execution(max_work=10))
    budget = BudgetService(h.records, registry, h.clock, h.ids)
    validator = RuntimeValidator(h.records, budget, h.clock, h.ids)
    work_service = WorkService(h.records, validator, h.clock, h.ids)
    return budget, work_service, AttemptService(work_service)


def authorization(
    h: Harness,
    kind: ActionType,
    name: str,
    work_ref: RecordRef | None = None,
    version: int | None = None,
    **changes: Any,
) -> BudgetScopeRef:
    request = ActionRequest.model_validate_json(
        json.dumps(
            action(
                meta=metadata("action_request", name + "-action"),
                action_id=name + "-action",
                action_type=kind.value,
                work_ref=work_ref.model_dump(mode="json") if work_ref else None,
                expected_state_version=version,
                **changes,
            )
        )
    )
    action_ref = h.publish(request)
    checks = sorted(c.value for c in REQUIRED_CHECKS[kind])
    result = ActionDecision.model_validate_json(
        json.dumps(
            decision(
                meta=metadata("action_decision", name + "-decision"),
                decision_id=name + "-decision",
                action_ref=action_ref,
                required_checks=checks,
                checked_state_version=version,
                check_results=[
                    dict(
                        check_type=c,
                        result="PASS",
                        reason_code="OK",
                        safe_message="Passed",
                    )
                    for c in checks
                ],
            )
        )
    )
    ref = h.records.stage_record(result)
    with h.database.write() as connection:
        h.records.publish(connection, ref)
    h.issue_fixture_decision(result)
    assert isinstance(ref, (RunStoredDataRef, StoredDataRef))
    return ref


def decision_action(h: Harness, ref: RecordRef) -> BudgetScopeRef:
    resolved = h.records.get_exact(ref)
    assert isinstance(resolved, ActionDecision)
    return resolved.action_ref


def test_work_requires_reservation_and_duplicate_registration_returns_existing(
    tmp_path: Path,
) -> None:
    from sastsimi.storage.action_validator import RuntimeValidator
    from sastsimi.storage.budget_registry import BudgetProfileRegistry
    from sastsimi.storage.budget_service import BudgetService
    from sastsimi.storage.work_service import WorkService

    h = Harness(tmp_path)
    registry = BudgetProfileRegistry(h.records, h.clock, h.ids)
    scope = h.pin_execution(registry, h.execution())
    budget = BudgetService(h.records, registry, h.clock, h.ids)
    service = WorkService(
        h.records, RuntimeValidator(h.records, budget, h.clock, h.ids), h.clock, h.ids
    )
    reservation = h.reservation(scope.model_dump(mode="json"), work_count=1)
    with h.database.engine.connect() as connection:
        work = h.records.resolve(
            connection, reservation.reservation.work_ref, candidate=True
        )
    assert isinstance(work, WorkExecutionState)
    decision_ref = authorization(h, ActionType.REGISTER_WORK, "register")
    with pytest.raises(ValueError, match="BUDGET"):
        service.register(work, decision_ref, None)
    action_ref = decision_action(h, decision_ref)
    reservation = BudgetReservationRequest(
        reservation.reservation.model_copy(update={"action_ref": action_ref})
    )
    reserved = budget.reserve(reservation)
    ref = h.records.stage_record(reserved)
    assert isinstance(ref, (RunStoredDataRef, StoredDataRef))
    first = service.register(work, decision_ref, ref)
    assert service.register(work, decision_ref, ref) == first
    assert str(first.work_id) == "reserve-work"


def start_fixture(
    tmp_path: Path,
    input_factory: Callable[[Harness], tuple[RecordRef, ...]] | None = None,
) -> tuple[
    Harness, WorkService, AttemptService, StateTransition, WorkAttempt, BudgetScopeRef
]:
    from sastsimi.storage.action_validator import RuntimeValidator
    from sastsimi.storage.attempt_service import AttemptService
    from sastsimi.storage.budget_registry import BudgetProfileRegistry
    from sastsimi.storage.budget_service import BudgetService
    from sastsimi.storage.work_service import WorkService

    h = Harness(tmp_path)
    registry = BudgetProfileRegistry(h.records, h.clock, h.ids)
    scope = h.pin_execution(registry, h.execution(max_work=10))
    budget = BudgetService(h.records, registry, h.clock, h.ids)
    service = WorkService(
        h.records, RuntimeValidator(h.records, budget, h.clock, h.ids), h.clock, h.ids
    )
    reservation = h.reservation(scope.model_dump(mode="json"), work_count=1)
    with h.database.engine.connect() as connection:
        work = h.records.resolve(
            connection, reservation.reservation.work_ref, candidate=True
        )
    assert isinstance(work, WorkExecutionState)
    if input_factory is not None:
        from sastsimi.contracts.canonical_json import content_hash
        from sastsimi.contracts.ids import RecordId

        refs = input_factory(h)
        work = work.model_copy(
            update={
                "meta": work.meta.model_copy(
                    update={"record_id": RecordId("input-work")}
                ),
                "input_refs": refs,
                "input_hash": content_hash(refs),
            }
        )
        reservation = BudgetReservationRequest(
            reservation.reservation.model_copy(
                update={"work_ref": h.records.stage_record(work)}
            )
        )
    decision_ref = authorization(h, ActionType.REGISTER_WORK, "register")
    reserved = budget.reserve(
        BudgetReservationRequest(
            reservation.reservation.model_copy(
                update={"action_ref": decision_action(h, decision_ref)}
            )
        )
    )
    registered = service.register(work, decision_ref, h.records.stage_record(reserved))
    ready_decision = authorization(
        h, ActionType.CHANGE_WORK_STATE, "ready", h.records.stage_record(registered), 1
    )
    transition = StateTransition.model_validate_json(
        json.dumps(
            dict(
                meta=metadata("state_transition", "ready-transition"),
                transition_id="ready-transition",
                work_id=str(work.work_id),
                action_decision_ref=ready_decision.model_dump(mode="json"),
                from_status="PENDING",
                to_status="READY",
                expected_state_version=1,
                new_state_version=2,
                attempt_id=None,
                cause="READY",
                output_refs=[],
                gap_ids=[],
                error_ids=[],
                dedupe_key="d" * 64,
                created_at="2026-09-07T00:00:00Z",
            )
        )
    )
    ready = service.make_ready(transition)
    attempt_service = AttemptService(service)
    decision_ref = authorization(
        h, ActionType.START_ATTEMPT, "start", h.records.stage_record(ready), 2
    )
    request = reservation.reservation.model_dump(mode="json")
    request.update(
        meta=metadata("budget_reservation", "start-reservation"),
        reservation_id="start-reservation",
        action_ref=decision_action(h, decision_ref).model_dump(mode="json"),
        work_ref=h.records.stage_record(ready).model_dump(mode="json"),
    )
    from sastsimi.contracts.budget import BudgetReservation

    reserved = budget.reserve(
        BudgetReservationRequest(
            BudgetReservation.model_validate_json(json.dumps(request))
        )
    )
    reservation_ref = h.records.stage_record(reserved)
    start = transition.model_dump(mode="json")
    start.update(
        meta=metadata("state_transition", "start-transition"),
        transition_id="start-transition",
        action_decision_ref=decision_ref.model_dump(mode="json"),
        from_status="READY",
        to_status="RUNNING",
        expected_state_version=2,
        new_state_version=3,
        attempt_id="at1",
    )
    start_transition = StateTransition.model_validate_json(json.dumps(start))
    attempt = WorkAttempt.model_validate_json(
        json.dumps(
            dict(
                meta=metadata("work_attempt", "attempt"),
                work_id=str(work.work_id),
                attempt_id="at1",
                attempt_number=1,
                trigger="INITIAL",
                input_hash=work.input_hash,
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
    assert isinstance(reservation_ref, (RunStoredDataRef, StoredDataRef))
    return h, service, attempt_service, start_transition, attempt, reservation_ref


def test_two_workers_cannot_start_two_active_attempts(tmp_path: Path) -> None:
    h, service, attempt_service, start_transition, attempt, reservation_ref = (
        start_fixture(tmp_path)
    )

    def claim(worker: str) -> bool:
        try:
            attempt_service.start(
                start_transition,
                attempt,
                reservation_ref,
                worker,
                NOW + timedelta(seconds=30),
            )
            return True
        except ValueError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(claim, ("one", "two"))) == [False, True]
    current = service.get(str(attempt.work_id))
    assert str(current.active_attempt_id) == "at1"
    assert current.state_version == 3
