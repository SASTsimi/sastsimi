"""Work deduplication and transitions in short SQLite transactions."""

from contextlib import nullcontext

from sqlalchemy import Connection, insert, select, update

from sastsimi.contracts.actions import ActionRequest, ActionType
from sastsimi.contracts.budget import BudgetReservation
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef
from sastsimi.contracts.work import (
    StateTransition,
    WorkAttempt,
    WorkExecutionState,
    WorkStatus,
    validate_parent_work,
    validate_transition_context,
)
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.storage import models
from sastsimi.storage.codec import encode
from sastsimi.storage.repositories import SQLiteRecordStore

from .action_validator import RuntimeValidator
from .current_inputs import check_current_input
from .dynamic_state import advance_dynamic_work
from .records import next_meta
from .run_control import reject_cancelled
from .verification_state import advance_verification_work


class WorkService:
    def __init__(
        self,
        records: SQLiteRecordStore,
        validator: RuntimeValidator,
        clock: Clock,
        ids: IdGenerator,
    ) -> None:
        self.records, self.validator, self.clock, self.ids = (
            records,
            validator,
            clock,
            ids,
        )

    def get(
        self, work_id: str, connection: Connection | None = None
    ) -> WorkExecutionState:
        if connection is None:
            with self.records.database.engine.connect() as reader:
                return self.get(work_id, reader)
        payload = connection.execute(
            select(models.work_states.c.payload).where(
                models.work_states.c.work_id == work_id
            )
        ).scalar_one()
        return WorkExecutionState.model_validate_json(payload)

    def ready_work(
        self, analysis_id: str, limit: int
    ) -> tuple[WorkExecutionState, ...]:
        if not analysis_id or limit < 0:
            raise ValueError("SCHEDULER_QUERY_INVALID")
        if limit == 0:
            return ()
        with self.records.database.engine.connect() as connection:
            payloads = connection.execute(
                select(models.work_states.c.payload)
                .where(
                    models.work_states.c.analysis_id == analysis_id,
                    models.work_states.c.status == "READY",
                )
                .order_by(models.work_states.c.work_id)
                .limit(limit)
            ).scalars()
            return tuple(
                WorkExecutionState.model_validate_json(item) for item in payloads
            )

    def work_for_run(self, analysis_id: str) -> tuple[WorkExecutionState, ...]:
        if not analysis_id:
            raise ValueError("SCHEDULER_QUERY_INVALID")
        with self.records.database.engine.connect() as connection:
            payloads = connection.execute(
                select(models.work_states.c.payload)
                .where(models.work_states.c.analysis_id == analysis_id)
                .order_by(models.work_states.c.work_id)
            ).scalars()
            return tuple(
                WorkExecutionState.model_validate_json(item) for item in payloads
            )

    def attempts_for_work(self, work_id: str) -> tuple[WorkAttempt, ...]:
        if not work_id:
            raise ValueError("SCHEDULER_QUERY_INVALID")
        with self.records.database.engine.connect() as connection:
            payloads = connection.execute(
                select(models.work_attempts.c.payload)
                .where(models.work_attempts.c.work_id == work_id)
                .order_by(models.work_attempts.c.attempt_number)
            ).scalars()
            return tuple(WorkAttempt.model_validate_json(item) for item in payloads)

    def registration_scope(self, work_id: str) -> BudgetScopeRef:
        with self.records.database.engine.connect() as connection:
            work = self.get(work_id, connection)
            matches: list[BudgetScopeRef] = []
            for payload in connection.execute(
                select(models.budget_reservations.c.payload).where(
                    models.budget_reservations.c.analysis_id
                    == str(work.meta.analysis_id)
                )
            ).scalars():
                reservation = BudgetReservation.model_validate_json(payload)
                candidate = self.records.resolve(connection, reservation.work_ref)
                action = self.records.resolve(connection, reservation.action_ref)
                if (
                    isinstance(candidate, WorkExecutionState)
                    and candidate.work_id == work.work_id
                    and isinstance(action, ActionRequest)
                    and action.action_type == ActionType.REGISTER_WORK
                ):
                    matches.append(reservation.budget_binding_ref)
            if len(matches) != 1:
                raise ValueError("WORK_REGISTRATION_SCOPE_MISSING")
            return matches[0]

    def register(
        self,
        work: WorkExecutionState,
        decision_ref: RecordRef,
        reservation_ref: RecordRef | None,
        *,
        _connection: Connection | None = None,
    ) -> WorkExecutionState:
        work = WorkExecutionState.model_validate(work)
        key = content_hash(
            [
                work.meta.analysis_id,
                work.work_type,
                work.subject_id,
                work.work_generation,
                work.dedupe_key,
            ]
        )
        with (
            self.records.database.write()
            if _connection is None
            else nullcontext(_connection) as connection
        ):
            reject_cancelled(connection, str(work.meta.analysis_id))
            old = connection.execute(
                select(models.work_states.c.payload).where(
                    models.work_states.c.registration_key == key
                )
            ).scalar()
            if old is not None:
                return WorkExecutionState.model_validate_json(old)
            if work.status != WorkStatus.PENDING:
                raise ValueError("New work must be PENDING")
            if work.parent_work_ref is not None:
                parent = self.records.resolve(connection, work.parent_work_ref)
                if not isinstance(parent, WorkExecutionState):
                    raise ValueError("Invalid parent work")
                validate_parent_work(work, parent)
            # Chaining owns an immutable Primitive-index snapshot.  The snapshot
            # must be current when the work is registered, but an append after
            # registration must not invalidate an in-flight result.
            if work.work_type == "CHAINING":
                for input_ref in work.input_refs:
                    if input_ref.data_kind == "primitive_index_state":
                        check_current_input(
                            self.records,
                            connection,
                            input_ref,
                            force=True,
                        )
            self.validator.claim(
                connection,
                decision_ref,
                ActionType.REGISTER_WORK,
                work,
                reservation_ref,
                needs_budget=True,
            )
            ref = self.records.stage(connection, work)
            self.records.publish(connection, ref)
            connection.execute(
                insert(models.work_states).values(
                    work_id=str(work.work_id),
                    analysis_id=str(work.meta.analysis_id),
                    registration_key=key,
                    status=work.status.value,
                    state_version=work.state_version,
                    active_attempt_id=None,
                    payload=encode(work),
                )
            )
            self.point(connection, work)
            return work

    def point(self, connection: Connection, work: WorkExecutionState) -> None:
        table = models.current_records
        old = connection.execute(
            select(table.c.state_version).where(
                table.c.logical_record_id == str(work.meta.logical_record_id)
            )
        ).scalar()
        values = dict(
            record_id=str(work.meta.record_id), state_version=work.state_version
        )
        if old is None:
            connection.execute(
                insert(table).values(
                    logical_record_id=str(work.meta.logical_record_id), **values
                )
            )
        else:
            if old != work.state_version - 1:
                raise ValueError("STATE_VERSION_CONFLICT: current pointer")
            connection.execute(
                update(table)
                .where(
                    table.c.logical_record_id == str(work.meta.logical_record_id),
                    table.c.state_version == old,
                )
                .values(**values)
            )

    def save(
        self,
        connection: Connection,
        previous: WorkExecutionState,
        work: WorkExecutionState,
    ) -> None:
        ref = self.records.stage(connection, work)
        self.records.publish(connection, ref)
        result = connection.execute(
            update(models.work_states)
            .where(
                models.work_states.c.work_id == str(work.work_id),
                models.work_states.c.state_version == previous.state_version,
            )
            .values(
                status=work.status.value,
                state_version=work.state_version,
                active_attempt_id=str(work.active_attempt_id)
                if work.active_attempt_id
                else None,
                payload=encode(work),
            )
        )
        if result.rowcount != 1:
            raise ValueError("STATE_VERSION_CONFLICT")
        self.point(connection, work)
        advance_verification_work(
            self.records, connection, previous, work, self.clock, self.ids
        )
        advance_dynamic_work(
            self.records, connection, previous, work, self.clock, self.ids
        )

    def make_ready(self, transition: StateTransition) -> WorkExecutionState:
        with self.records.database.write() as connection:
            previous = self.get(str(transition.work_id), connection)
            reject_cancelled(connection, str(previous.meta.analysis_id))
            validate_transition_context(transition, previous)
            if transition.to_status.value != "READY" or previous.status not in {
                WorkStatus.PENDING,
                WorkStatus.BLOCKED,
            }:
                raise ValueError("STATE_TRANSITION_INVALID")
            self.validator.claim(
                connection,
                transition.action_decision_ref,
                ActionType.CHANGE_WORK_STATE,
                previous,
            )
            ref = self.records.stage(connection, transition)
            self.records.publish(connection, ref)
            work = WorkExecutionState.model_validate(
                previous.model_dump()
                | dict(
                    meta=next_meta(previous.meta, self.clock, self.ids),
                    status=WorkStatus.READY,
                    state_version=transition.new_state_version,
                    last_transition_ref=ref,
                    output_refs=(),
                    waiting_for=(),
                    stop_reason=None,
                )
            )
            self.save(connection, previous, work)
            return work
