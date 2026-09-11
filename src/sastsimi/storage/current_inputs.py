"""Recheck only runtime state inputs; historical result provenance stays exact."""

from sqlalchemy import Connection, select

from sastsimi.contracts.actions import ActionRequest, ActionType, RequesterRole
from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.static import CodeWorkspace
from sastsimi.contracts.work import WorkExecutionState, WorkType

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

READY_WORKSPACE_STATUS = frozenset({"READY"})
PREPARING_WORKSPACE_STATUS = frozenset({"PREPARING"})


def allowed_workspace_statuses(
    action: ActionRequest, work: WorkExecutionState
) -> frozenset[str]:
    """Return the sole narrow exception to the normal READY-only workspace rule."""
    if (
        action.action_type == ActionType.RUN_TOOL
        and action.requested_by == RequesterRole.REPOSITORY_LOADER
        and work.work_type == WorkType.WORKSPACE_PREP
    ):
        return PREPARING_WORKSPACE_STATUS
    return READY_WORKSPACE_STATUS


def check_current_input(
    records: SQLiteRecordStore,
    connection: Connection,
    ref: RecordRef,
    *,
    force: bool = False,
    workspace_statuses: frozenset[str] = READY_WORKSPACE_STATUS,
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
    if isinstance(record, CodeWorkspace) and record.status not in workspace_statuses:
        expected = ",".join(sorted(workspace_statuses))
        raise ValueError(f"STALE_RESULT: workspace is not {expected}")
