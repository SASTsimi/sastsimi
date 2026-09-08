"""Resolve current hypothesis ownership; no workflow mutation or semantic verdict."""

from sqlalchemy import Connection, select

from sastsimi.contracts.actions import ActionRequest, RequesterRole
from sastsimi.contracts.hypothesis import HypothesisProcessState, VerificationAssignment
from sastsimi.contracts.work import WorkExecutionState

from . import models
from .codec import REF_ADAPTER
from .current_inputs import check_current_input
from .repositories import SQLiteRecordStore


def current_process(
    records: SQLiteRecordStore, connection: Connection, work: WorkExecutionState
) -> HypothesisProcessState:
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
        assert isinstance(process, HypothesisProcessState)
        if all(
            getattr(process.meta, name, None) == getattr(work.meta, name, None)
            for name in ("analysis_id", "workspace_id", "commit_id", "hypothesis_id")
        ):
            candidates.append(process)
    if len(candidates) != 1:
        raise ValueError("AUTHORITY_DENIED: exact current hypothesis process required")
    return candidates[0]


def check_owner(
    records: SQLiteRecordStore,
    connection: Connection,
    action: ActionRequest,
    work: WorkExecutionState,
) -> None:
    if (
        action.requested_by != RequesterRole.VERIFICATION
        or getattr(work.meta, "hypothesis_id", None) is None
    ):
        return
    process = current_process(records, connection, work)
    if process.verification_assignment_ref is None:
        raise ValueError("AUTHORITY_DENIED: no active assignment")
    check_current_input(records, connection, process.verification_assignment_ref)
    assignment = records.resolve(connection, process.verification_assignment_ref)
    if (
        not isinstance(assignment, VerificationAssignment)
        or assignment.status != "ACTIVE"
        or assignment.owner_identity_ref != action.requester_identity_ref
        or process.verification_generation != work.work_generation
        or (
            action.expected_verification_generation is not None
            and action.expected_verification_generation
            != process.verification_generation
        )
        or any(
            getattr(assignment.meta, name, None) != getattr(work.meta, name, None)
            for name in ("analysis_id", "workspace_id", "commit_id", "hypothesis_id")
        )
    ):
        raise ValueError("AUTHORITY_DENIED: active owner/current generation mismatch")
