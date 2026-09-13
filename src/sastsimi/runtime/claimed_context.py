"""Shared validation of a current claimed work and its exact attempt."""

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.work import AttemptStatus, WorkStatus, WorkType
from sastsimi.ports.dto import WorkContext


def require_claimed_context(context: WorkContext, expected: WorkType | str) -> None:
    """Reject stale, unclaimed, or cross-attempt handler input."""

    work, attempt = context.work, context.attempt
    if (
        work.work_type != WorkType(expected)
        or work.status != WorkStatus.RUNNING
        or attempt.status != AttemptStatus.RUNNING
        or work.active_attempt_id is None
        or work.active_attempt_id != attempt.attempt_id
        or work.work_id != attempt.work_id
        or work.input_hash != attempt.input_hash
        or work.input_hash != content_hash(work.input_refs)
        or not isinstance(work.meta, RecordMeta)
        or not isinstance(attempt.meta, RecordMeta)
        or work.meta.analysis_id != attempt.meta.analysis_id
        or work.meta.workspace_id != attempt.meta.workspace_id
        or work.meta.commit_id != attempt.meta.commit_id
    ):
        raise ValueError("WORK_CONTEXT_NOT_CURRENT")
