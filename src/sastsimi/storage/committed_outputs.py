"""Resolve committed producer/work/attempt closure without current-ref substitution."""

from sqlalchemy import Connection, select

from sastsimi.contracts.closure import validate_committed_output
from sastsimi.contracts.dynamic import DynamicReproductionResult, PoCBundle
from sastsimi.contracts.gates import (
    CWELabel,
    RuleScopeImpactReview,
    TechnicalEvidenceReview,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.verification import EvidenceAgentResult, VerificationResult
from sastsimi.contracts.work import (
    TransitionCommit,
    WorkAttempt,
    WorkExecutionState,
    WorkType,
)

from . import models
from .codec import reference
from .repositories import SQLiteRecordStore

type CommittedDomainOutput = (
    EvidenceAgentResult
    | DynamicReproductionResult
    | PoCBundle
    | VerificationResult
    | CWELabel
    | RuleScopeImpactReview
    | TechnicalEvidenceReview
)


def require_committed(
    records: SQLiteRecordStore,
    connection: Connection,
    record: CommittedDomainOutput,
    work_type: WorkType,
) -> None:
    ref = reference(record)
    assert isinstance(ref, StoredDataRef)
    matches = []
    for payload in connection.execute(
        select(models.transition_commits.c.payload).where(
            models.transition_commits.c.state == "COMMITTED",
        )
    ).scalars():
        commit = TransitionCommit.model_validate_json(payload)
        if ref in commit.output_refs:
            matches.append(commit)
    if len(matches) != 1:
        raise ValueError("RESULT_NOT_COMMITTED")
    commit = matches[0]
    work_payload = connection.execute(
        select(models.work_states.c.payload).where(
            models.work_states.c.work_id == str(commit.work_id),
        )
    ).scalar_one()
    attempt_payload = connection.execute(
        select(models.work_attempts.c.payload).where(
            models.work_attempts.c.attempt_id == str(commit.attempt_id),
        )
    ).scalar_one()
    work = WorkExecutionState.model_validate_json(work_payload)
    attempt = WorkAttempt.model_validate_json(attempt_payload)
    validate_committed_output(
        record, ref, work, attempt, commit, expected_work_type=work_type
    )
