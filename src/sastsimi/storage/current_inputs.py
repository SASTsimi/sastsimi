"""Recheck only runtime state inputs; historical result provenance stays exact."""

from sqlalchemy import Connection, select

from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.static import CodeWorkspace

from . import models
from .repositories import SQLiteRecordStore

CURRENT_STATE_KINDS = frozenset(
    {
        "code_workspace",
        "analysis_run_state",
        "work_execution_state",
        "hypothesis_process_state",
        "verification_assignment",
        "finding_index_state",
    }
)


def check_current_input(
    records: SQLiteRecordStore,
    connection: Connection,
    ref: RecordRef,
    *,
    force: bool = False,
) -> None:
    if not force and ref.data_kind not in CURRENT_STATE_KINDS:
        return
    record = records.resolve(connection, ref)
    pointer = connection.execute(
        select(models.current_records.c.record_id).where(
            models.current_records.c.logical_record_id
            == str(record.meta.logical_record_id)
        )
    ).scalar()
    if pointer != str(ref.record_id):
        raise ValueError("STALE_RESULT: current-sensitive input superseded")
    if isinstance(record, CodeWorkspace) and record.status != "READY":
        raise ValueError("STALE_RESULT: workspace no longer READY")
