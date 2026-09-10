"""The Reproduction Session Manager's generation-local exact work projection."""

from sqlalchemy import Connection, select, update

from sastsimi.contracts.dynamic import DynamicReproductionState
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator

from . import models
from .codec import REF_ADAPTER, reference
from .records import next_meta
from .repositories import SQLiteRecordStore


def current_dynamic(
    records: SQLiteRecordStore, connection: Connection, work: WorkExecutionState
) -> DynamicReproductionState:
    states = []
    for wire in connection.execute(
        select(models.records.c.ref)
        .join(
            models.current_records,
            models.current_records.c.record_id == models.records.c.record_id,
        )
        .where(models.records.c.kind == "dynamic_reproduction_state")
    ).scalars():
        state = records.resolve(connection, REF_ADAPTER.validate_json(wire))
        if isinstance(state, DynamicReproductionState) and all(
            getattr(state.meta, field) == getattr(work.meta, field, None)
            for field in ("analysis_id", "workspace_id", "commit_id", "hypothesis_id")
        ):
            states.append(state)
    if len(states) != 1 or states[0].verification_generation != work.work_generation:
        raise ValueError("DYNAMIC_STATE_REQUIRED")
    return states[0]


def advance_dynamic_work(
    records: SQLiteRecordStore,
    connection: Connection,
    previous: WorkExecutionState,
    work: WorkExecutionState,
    clock: Clock,
    ids: IdGenerator,
) -> None:
    if work.work_type != "DYNAMIC_REPRO":
        return
    state = current_dynamic(records, connection, work)
    if state.dynamic_work_ref != reference(previous):
        raise ValueError("DYNAMIC_STATE_WORK_CONFLICT")
    if work.status not in {"READY", "RUNNING"}:
        # A returned result must have been projected by the owning terminal commit.
        if (
            state.status != work.status.value
            or state.dynamic_result_ref not in work.output_refs
        ):
            raise ValueError("DYNAMIC_RESULT_PROJECTION_REQUIRED")
    updated = DynamicReproductionState.model_validate(
        state.model_dump()
        | dict(meta=next_meta(state.meta, clock, ids), dynamic_work_ref=reference(work))
    )
    ref = records.stage(connection, updated)
    records.publish(connection, ref)
    changed = connection.execute(
        update(models.current_records)
        .where(
            models.current_records.c.logical_record_id
            == str(state.meta.logical_record_id),
            models.current_records.c.record_id == str(state.meta.record_id),
        )
        .values(
            record_id=str(ref.record_id), state_version=updated.meta.revision_number
        )
    )
    if changed.rowcount != 1:
        raise ValueError("DYNAMIC_STATE_WORK_CONFLICT")
