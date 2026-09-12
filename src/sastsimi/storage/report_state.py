"""Atomic projection of the current report-draft lifecycle state."""

from sqlalchemy import Connection

from sastsimi.contracts.reporting import ReportDraft, ReportProcessState
from sastsimi.contracts.work import (
    CommitTargetStatus,
    TransitionCommit,
    WorkExecutionState,
)

from .codec import reference
from .records import next_meta
from .verification_projection import current_scoped
from .work_service import WorkService


def report_process_projection(
    works: WorkService,
    connection: Connection,
    work: WorkExecutionState,
    outputs: tuple[object, ...],
    committed: TransitionCommit,
) -> ReportProcessState | None:
    """Derive DRAFTED/FAILED only from the exact terminal report commit."""

    if work.work_type != "REPORT_DRAFT" or work.subject_type != "HYPOTHESIS":
        return None
    if committed.target_status not in {
        CommitTargetStatus.SUCCEEDED,
        CommitTargetStatus.FAILED,
    }:
        return None
    states = current_scoped(
        works, connection, work, "report_process_state", ReportProcessState
    )
    if len(states) != 1 or states[0].status != "NOT_REQUESTED":
        raise ValueError("REPORT_PROCESS_STATE_CONFLICT")
    previous = states[0]
    finished_at = works.clock.now()
    if work.started_at is None:
        raise ValueError("REPORT_WORK_START_REQUIRED")
    elapsed_ms = max(0, int((finished_at - work.started_at).total_seconds() * 1000))
    drafts = tuple(item for item in outputs if isinstance(item, ReportDraft))
    if committed.target_status == CommitTargetStatus.SUCCEEDED:
        if len(drafts) != 1 or len(outputs) != 1:
            raise ValueError("REPORT_EXACT_OUTPUT_REQUIRED")
        draft_ref = reference(drafts[0])
        if draft_ref not in committed.output_refs:
            raise ValueError("REPORT_COMMIT_OUTPUT_MISMATCH")
        status = "DRAFTED"
    else:
        if outputs or committed.output_refs:
            raise ValueError("FAILED_REPORT_MUST_NOT_PUBLISH_DRAFT")
        draft_ref = None
        status = "FAILED"
    return ReportProcessState.model_validate(
        dict(
            meta=next_meta(previous.meta, works.clock, works.ids),
            status=status,
            report_draft_ref=draft_ref,
            started_at=work.started_at,
            finished_at=finished_at,
            elapsed_ms=elapsed_ms,
        )
    )
