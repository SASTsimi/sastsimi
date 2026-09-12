"""SQLite policy lifecycle with same-logical state and exact cache-head CAS."""

from sqlalchemy import Connection, insert, select, update
from sqlalchemy.exc import IntegrityError

from sastsimi.contracts.analysis import AnalysisRunState
from sastsimi.contracts.policy import PolicyCacheRecord, RunPolicyState
from sastsimi.contracts.records import validate_revision
from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.work import WorkExecutionState, WorkStatus, WorkType
from sastsimi.ports.policy_runtime import (
    PolicyCacheKey,
    PolicyPreparation,
)
from sastsimi.storage import models

from .codec import REF_ADAPTER, reference
from .records import next_meta
from .run_states import get_run, save_run
from .work_service import WorkService

_POLICY_TERMINAL = frozenset({"CURRENT", "ABSENT", "UNVERIFIED", "BLOCKED", "FAILED"})


class PolicyRuntime:
    def __init__(self, works: WorkService) -> None:
        self.works = works
        self.records = works.records

    def begin(
        self,
        work: WorkExecutionState,
        decision_ref: RecordRef,
        reservation_ref: RecordRef,
        state: RunPolicyState,
    ) -> PolicyPreparation:
        _validate_preparing(work, state)
        with self.records.database.write() as connection:
            run = get_run(connection, str(work.meta.analysis_id))
            if run.status != "RUNNING" or run.program_id != state.program_id:
                raise ValueError("POLICY_STATE_CLOSURE_MISMATCH")
            if run.run_policy_state_ref is not None:
                raise ValueError("POLICY_ALREADY_FROZEN")
            registered = self.works.register(
                work,
                decision_ref,
                reservation_ref,
                _connection=connection,
            )
            if registered != work:
                raise ValueError("POLICY_WORK_REGISTRATION_MISMATCH")
            state_ref = self.records.stage(connection, state)
            self.records.publish(connection, state_ref)
            connection.execute(
                insert(models.current_records).values(
                    logical_record_id=str(state.meta.logical_record_id),
                    record_id=str(state.meta.record_id),
                    state_version=state.meta.revision_number,
                )
            )
            updated = AnalysisRunState.model_validate(
                run.model_dump()
                | dict(
                    meta=next_meta(run.meta, self.works.clock, self.works.ids),
                    run_policy_state_ref=state_ref,
                )
            )
            save_run(self.records, connection, updated, run)
        return PolicyPreparation(registered, state)

    def current_state(self, analysis_id: str) -> RunPolicyState | None:
        with self.records.database.engine.connect() as connection:
            run = get_run(connection, analysis_id)
            if run.run_policy_state_ref is None:
                return None
            state = self.records.resolve(connection, run.run_policy_state_ref)
        if not isinstance(state, RunPolicyState):
            raise ValueError("POLICY_STATE_CLOSURE_MISMATCH")
        return state

    def current_cache(self, key: PolicyCacheKey) -> PolicyCacheRecord | None:
        with self.records.database.engine.connect() as connection:
            ref_wire = connection.execute(
                select(models.records.c.ref)
                .select_from(
                    models.current_records.join(
                        models.records,
                        models.current_records.c.record_id
                        == models.records.c.record_id,
                    )
                )
                .where(
                    models.current_records.c.logical_record_id
                    == str(key.logical_record_id)
                )
            ).scalar_one_or_none()
            if ref_wire is None:
                return None
            value = self.records.resolve(
                connection,
                REF_ADAPTER.validate_json(ref_wire),
            )
        if not isinstance(value, PolicyCacheRecord):
            raise ValueError("POLICY_CACHE_HEAD_MISMATCH")
        if PolicyCacheKey.from_record(value) != key:
            raise ValueError("POLICY_CACHE_KEY_MISMATCH")
        return value


def _validate_preparing(work: WorkExecutionState, state: RunPolicyState) -> None:
    if (
        work.work_type != WorkType.POLICY_FETCH
        or work.status != WorkStatus.PENDING
        or state.status != "PREPARING"
        or state.meta.analysis_id != work.meta.analysis_id
        or state.meta.revision_number != 1
        or state.policy_work_ref != reference(work)
    ):
        raise ValueError("POLICY_PREPARING_MISMATCH")


def validate_policy_successor(
    works: WorkService,
    connection: Connection,
    run: AnalysisRunState,
    work: WorkExecutionState,
    state: RunPolicyState,
) -> RunPolicyState:
    """Return the exact current PREPARING predecessor for one terminal state."""
    if state.status not in _POLICY_TERMINAL:
        raise ValueError("POLICY_FINAL_STATE_REQUIRED")
    if run.run_policy_state_ref is None:
        raise ValueError("POLICY_PREPARING_REQUIRED")
    previous = works.records.resolve(connection, run.run_policy_state_ref)
    if not isinstance(previous, RunPolicyState) or previous.status != "PREPARING":
        raise ValueError("POLICY_ALREADY_FROZEN")
    try:
        validate_revision(previous.meta, state.meta)
    except ValueError as error:
        raise ValueError("POLICY_STATE_REVISION_MISMATCH") from error
    if (
        previous.program_id != state.program_id
        or previous.source_config_ref != state.source_config_ref
        or previous.parser_name != state.parser_name
        or previous.parser_version != state.parser_version
        or state.policy_work_ref != reference(work)
    ):
        raise ValueError("POLICY_STATE_CLOSURE_MISMATCH")
    current_id = connection.execute(
        select(models.current_records.c.record_id).where(
            models.current_records.c.logical_record_id
            == str(previous.meta.logical_record_id)
        )
    ).scalar_one_or_none()
    if current_id != str(previous.meta.record_id):
        raise ValueError("POLICY_STATE_REVISION_MISMATCH")
    return previous


def publish_current(
    connection: Connection,
    record: RunPolicyState | PolicyCacheRecord,
    previous_record_id: str | None,
) -> None:
    table = models.current_records
    logical_id = str(record.meta.logical_record_id)
    if previous_record_id is None:
        if record.meta.revision_number != 1:
            raise ValueError(
                "RECORD_REVISION_MISMATCH: missing cache/state predecessor"
            )
        try:
            connection.execute(
                insert(table).values(
                    logical_record_id=logical_id,
                    record_id=str(record.meta.record_id),
                    state_version=1,
                )
            )
        except IntegrityError as error:
            raise ValueError("STATE_VERSION_CONFLICT: policy pointer") from error
        return
    changed = connection.execute(
        update(table)
        .where(
            table.c.logical_record_id == logical_id,
            table.c.record_id == previous_record_id,
            table.c.state_version == record.meta.revision_number - 1,
        )
        .values(
            record_id=str(record.meta.record_id),
            state_version=record.meta.revision_number,
        )
    )
    if changed.rowcount != 1:
        raise ValueError("STATE_VERSION_CONFLICT: policy pointer")


def validate_cache_head(
    connection: Connection,
    cache: PolicyCacheRecord,
    *,
    exact_key: bool,
) -> None:
    key = PolicyCacheKey.from_record(cache)
    if exact_key and cache.meta.logical_record_id != key.logical_record_id:
        raise ValueError("POLICY_CACHE_KEY_MISMATCH")
    current_id = connection.execute(
        select(models.current_records.c.record_id).where(
            models.current_records.c.logical_record_id
            == str(cache.meta.logical_record_id)
        )
    ).scalar_one_or_none()
    expected = (
        None
        if cache.meta.previous_record_id is None
        else str(cache.meta.previous_record_id)
    )
    if current_id != expected:
        raise ValueError("STATE_VERSION_CONFLICT: policy cache head")
