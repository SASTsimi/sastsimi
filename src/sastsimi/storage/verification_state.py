"""Current Verification work references advance only with their exact work CAS."""

from sqlalchemy import Connection, select, update

from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator

from . import models
from .codec import REF_ADAPTER, reference
from .records import next_meta
from .repositories import SQLiteRecordStore


def advance_verification_work(
    records: SQLiteRecordStore,
    connection: Connection,
    previous: WorkExecutionState,
    work: WorkExecutionState,
    clock: Clock,
    ids: IdGenerator,
) -> None:
    if work.work_type != "VERIFICATION":
        return
    candidates = []
    for wire in connection.execute(
        select(models.records.c.ref)
        .join(
            models.current_records,
            models.current_records.c.record_id == models.records.c.record_id,
        )
        .where(models.records.c.kind == "hypothesis_process_state")
    ).scalars():
        process = records.resolve(connection, REF_ADAPTER.validate_json(wire))
        if isinstance(process, HypothesisProcessState) and all(
            getattr(process.meta, name, None) == getattr(work.meta, name, None)
            for name in ("analysis_id", "workspace_id", "commit_id", "hypothesis_id")
        ):
            candidates.append(process)
    if not candidates:
        return
    if len(candidates) != 1:
        raise ValueError("VERIFICATION_PROCESS_CONFLICT")
    process = candidates[0]
    if process.status != "VERIFYING":
        return
    if (
        process.verification_work_ref != reference(previous)
        or process.verification_generation != work.work_generation
    ):
        raise ValueError("VERIFICATION_PROCESS_CONFLICT")
    if work.status == "SUCCEEDED":
        raise ValueError("VERIFICATION_FINAL_RESULT_REQUIRED")
    changes: dict[str, object] = dict(verification_work_ref=reference(work))
    if work.status in {"FAILED", "CANCELLED"}:
        changes.update(status=work.status.value, finished_at=clock.now())
    updated = HypothesisProcessState.model_validate(
        process.model_dump()
        | changes
        | dict(
            meta=next_meta(process.meta, clock, ids),
        )
    )
    ref = records.stage(connection, updated)
    records.publish(connection, ref)
    changed = connection.execute(
        update(models.current_records)
        .where(
            models.current_records.c.logical_record_id
            == str(process.meta.logical_record_id),
            models.current_records.c.record_id == str(process.meta.record_id),
        )
        .values(
            record_id=str(ref.record_id), state_version=updated.meta.revision_number
        )
    )
    if changed.rowcount != 1:
        raise ValueError("VERIFICATION_PROCESS_CONFLICT")
