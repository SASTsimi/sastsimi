"""Work deduplication and transitions in short SQLite transactions."""

from contextlib import nullcontext

from sqlalchemy import Connection, insert, select, update

from sastsimi.contracts.actions import ActionType
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.work import (
    StateTransition,
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
