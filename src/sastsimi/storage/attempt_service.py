"""SQLite adapter: Work/attempt/lease claims share one CAS transaction."""

from contextlib import nullcontext
from datetime import datetime

from sqlalchemy import Connection, insert, select, update

from sastsimi.contracts.actions import ActionType
from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.work import (
    StateTransition,
    WorkAttempt,
    WorkExecutionState,
    WorkStatus,
    validate_attempt_context,
    validate_transition_context,
)
from sastsimi.storage import models
from sastsimi.storage.codec import encode

from .dispatches import reject_uncertain
from .records import next_meta
from .run_control import reject_cancelled
from .work_service import WorkService


class AttemptService:
    def __init__(self, works: WorkService) -> None:
        self.works = works

    def start(
        self,
        transition: StateTransition,
        attempt: WorkAttempt,
        reservation_ref: RecordRef,
        worker_id: str,
        lease_expires_at: datetime,
        *,
        _connection: Connection | None = None,
    ) -> WorkExecutionState:
        service = self.works
        if (
            attempt.status.value != "RUNNING"
            or attempt.finished_at is not None
            or attempt.output_refs
            or attempt.error_ids
            or attempt.gap_ids
        ):
            raise ValueError(
                "ATTEMPT_NOT_ACTIVE: start requires a fresh RUNNING attempt"
            )
        if not worker_id or lease_expires_at <= service.clock.now():
            raise ValueError("Invalid worker lease")
        with (
            service.records.database.write()
            if _connection is None
            else nullcontext(_connection) as connection
        ):
            previous = service.get(str(transition.work_id), connection)
            reject_cancelled(connection, str(previous.meta.analysis_id))
            reject_uncertain(connection, str(previous.work_id))
            validate_transition_context(transition, previous)
            if (
                previous.status != WorkStatus.READY
                or transition.to_status.value != "RUNNING"
                or transition.attempt_id != attempt.attempt_id
            ):
                raise ValueError("ATTEMPT_NOT_ACTIVE")
            _, action = service.validator.check(
                connection,
                transition.action_decision_ref,
                ActionType.START_ATTEMPT,
                previous,
                reservation_ref,
                needs_budget=True,
            )
            reservation = service.validator.check_reservation(
                connection, reservation_ref, action, previous
            )
            profile = service.validator.budget.registry.execution(
                connection,
                reservation.budget_binding_ref,
                str(previous.meta.analysis_id),
            )
            running = connection.execute(
                select(models.work_states.c.work_id).where(
                    models.work_states.c.analysis_id == str(previous.meta.analysis_id),
                    models.work_states.c.status == "RUNNING",
                )
            ).all()
            if len(running) >= profile.max_parallel_work:
                raise ValueError("BUDGET_EXCEEDED: parallel work")
            prior_payload = (
                connection.execute(
                    select(models.work_attempts.c.payload)
                    .where(models.work_attempts.c.work_id == str(previous.work_id))
                    .order_by(models.work_attempts.c.attempt_number.desc())
                )
                .scalars()
                .first()
            )
            prior = (
                WorkAttempt.model_validate_json(prior_payload)
                if prior_payload
                else None
            )
            if prior is None and attempt.attempt_number != 1:
                raise ValueError("Initial attempt must have number one")
            if prior is not None and reservation.requested_units.retry_count < 1:
                raise ValueError("BUDGET requires a reserved retry unit")
            transition_ref = service.records.stage(connection, transition)
            service.records.publish(connection, transition_ref)
            work = WorkExecutionState.model_validate(
                previous.model_dump()
                | dict(
                    meta=next_meta(previous.meta, service.clock, service.ids),
                    status=WorkStatus.RUNNING,
                    state_version=transition.new_state_version,
                    active_attempt_id=attempt.attempt_id,
                    last_transition_ref=transition_ref,
                    started_at=previous.started_at or attempt.started_at,
                )
            )
            validate_attempt_context(attempt, work, previous_attempt=prior)
            service.validator.claim(
                connection,
                transition.action_decision_ref,
                ActionType.START_ATTEMPT,
                previous,
                reservation_ref,
                needs_budget=True,
            )
            attempt_ref = service.records.stage(connection, attempt)
            service.records.publish(connection, attempt_ref)
            service.save(connection, previous, work)
            connection.execute(
                insert(models.work_attempts).values(
                    attempt_id=str(attempt.attempt_id),
                    work_id=str(attempt.work_id),
                    attempt_number=attempt.attempt_number,
                    status=attempt.status.value,
                    payload=encode(attempt),
                )
            )
            connection.execute(
                update(models.work_states)
                .where(models.work_states.c.work_id == str(work.work_id))
                .values(
                    worker_id=worker_id, lease_expires_at=lease_expires_at.isoformat()
                )
            )
            return work
