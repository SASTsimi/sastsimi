"""Shared pure commit/work/attempt closure for downstream domain consumers."""

from ._domain import DomainRecord, exact, exact_set, same_scope
from .canonical_json import content_hash
from .records import RecordMeta
from .refs import StoredDataRef, validate_exact_ref
from .work import (
    TransitionCommit,
    WorkAttempt,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)


def validate_committed_output(
    record: DomainRecord,
    reference: StoredDataRef,
    work: WorkExecutionState,
    attempt: WorkAttempt,
    commit: TransitionCommit,
    *,
    expected_work_type: WorkType,
    allowed_statuses: frozenset[WorkStatus] = frozenset({WorkStatus.SUCCEEDED}),
) -> None:
    exact(reference, record, work.meta)
    if (
        work.work_type != expected_work_type
        or work.status not in allowed_statuses
        or commit.state != "COMMITTED"
    ):
        raise ValueError("RESULT_NOT_COMMITTED")
    if (
        not isinstance(work.meta, RecordMeta)
        or not isinstance(attempt.meta, RecordMeta)
        or not isinstance(commit.meta, RecordMeta)
    ):
        raise ValueError("METADATA_SCOPE_MISMATCH")
    same_scope(record.meta, work.meta)
    same_scope(record.meta, attempt.meta)
    same_scope(record.meta, commit.meta)
    if record.ATTEMPT is not False and record.meta.attempt_id != attempt.attempt_id:
        raise ValueError("RESULT_ATTEMPT_MISMATCH")
    if (
        (attempt.work_id, commit.work_id) != (work.work_id, work.work_id)
        or attempt.input_hash != work.input_hash
        or commit.attempt_id != attempt.attempt_id
    ):
        raise ValueError("RESULT_WORK_ATTEMPT_MISMATCH")
    if (
        attempt.status.value != work.status.value
        or commit.target_status.value != work.status.value
        or commit.target_state_version != work.state_version
    ):
        raise ValueError("RESULT_COMMIT_STATE_MISMATCH")
    if work.last_transition_commit_ref is None:
        raise ValueError("RESULT_COMMIT_REFERENCE_REQUIRED")
    validate_exact_ref(
        work.last_transition_commit_ref,
        commit.meta,
        content_hash(commit),
        analysis_id=record.meta.analysis_id,
    )
    exact_set(work.output_refs, commit.output_refs)
    exact_set(attempt.output_refs, commit.output_refs)
    if reference not in work.output_refs:
        raise ValueError("RESULT_OUTPUT_CLOSURE_MISMATCH")
