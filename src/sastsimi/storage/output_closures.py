"""Immutable exact output admission, derived only during trusted authorization."""

from sqlalchemy import Connection

from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.hypothesis import VerificationAssignment
from sastsimi.contracts.refs import RecordRef, StoredDataRef
from sastsimi.contracts.result_registry import validate_result_owner
from sastsimi.contracts.static import CodeContextResponse
from sastsimi.contracts.work import WorkExecutionState

from .output_receipts import read_outputs as read_outputs
from .repositories import SQLiteRecordStore


def derive_outputs(
    records: SQLiteRecordStore, connection: Connection, action: ActionRequest
) -> tuple[RecordRef, ...]:
    primary = action.candidate_result_ref
    if primary is None:
        return ()
    outputs = records.evidence.authorized_outputs(action)
    if outputs is None:
        outputs = (primary,)
    if primary not in outputs or len(outputs) != len(set(outputs)):
        raise ValueError("OUTPUT_BINDING_MISMATCH")
    for ref in outputs:
        candidate = records.resolve(connection, ref, candidate=True)
        if not isinstance(candidate, ContractModel):
            raise ValueError("OUTPUT_BINDING_MISMATCH: invalid candidate model")
        from .intermediate_policy import (
            prepublished_output,
            validate_intermediate_owner,
        )

        work = records.resolve(connection, action.work_ref) if action.work_ref else None
        if isinstance(candidate, CodeContextResponse):
            from .context_policy import check_context_response

            if not isinstance(work, WorkExecutionState):
                raise ValueError("CONTEXT_RESPONSE_SCOPE_MISMATCH")
            check_context_response(records, connection, work, candidate)
        if isinstance(work, WorkExecutionState) and prepublished_output(
            records,
            connection,
            ref,
            work,
        ):
            continue
        if ref.data_kind == "verification_initial_assessment" and isinstance(
            work, WorkExecutionState
        ):
            validate_intermediate_owner(candidate, action, work)
            continue
        if ref.data_kind == "finding" and isinstance(work, WorkExecutionState):
            from .action_context import current_process

            process = current_process(records, connection, work)
            if not isinstance(process.verification_assignment_ref, StoredDataRef):
                raise ValueError("FINDING_NORMALIZER_AUTHORITY_REQUIRED")
            assignment = records.resolve(
                connection, process.verification_assignment_ref
            )
            if not isinstance(
                action.requester_identity_ref, StoredDataRef
            ) or not isinstance(assignment, VerificationAssignment):
                raise ValueError("FINDING_NORMALIZER_AUTHORITY_REQUIRED")
            validate_result_owner(
                ref.data_kind,
                candidate,
                action.requested_by,
                requester_identity_ref=action.requester_identity_ref,
                finding_service_identity_ref=records.finding_service_identity_ref,
                active_assignment_owner_ref=assignment.owner_identity_ref,
                finding_assignment=assignment,
                expected_assignment_ref=process.verification_assignment_ref,
            )
        else:
            validate_result_owner(ref.data_kind, candidate, action.requested_by)
    return outputs
