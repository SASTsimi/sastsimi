"""Admit a semantic restart's exact closure; never perform generation mutation."""

from sqlalchemy import Connection, select

from sastsimi.contracts.actions import (
    ActionRequest,
    GenerationRestartReason,
    validate_generation_restart_context,
)
from sastsimi.contracts.dynamic import DynamicReproductionRequest, SandboxProfile
from sastsimi.contracts.refs import RecordRef, StoredDataRef
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.contracts.work import (
    WorkAttempt,
    WorkExecutionState,
    validate_attempt_context,
)

from . import models
from .action_context import current_process
from .codec import REF_ADAPTER, reference
from .current_inputs import check_current_input
from .repositories import SQLiteRecordStore


def active(
    records: SQLiteRecordStore, connection: Connection, work: WorkExecutionState
) -> None:
    check_current_input(records, connection, reference(work))
    row = (
        connection.execute(
            select(models.work_states).where(
                models.work_states.c.work_id == str(work.work_id)
            )
        )
        .mappings()
        .first()
    )
    attempt_payload = connection.execute(
        select(models.work_attempts.c.payload).where(
            models.work_attempts.c.attempt_id == str(work.active_attempt_id)
        )
    ).scalar()
    if (
        row is None
        or WorkExecutionState.model_validate_json(row["payload"]) != work
        or row["state_version"] != work.state_version
        or row["active_attempt_id"] != str(work.active_attempt_id)
        or row["status"] != "RUNNING"
        or work.status != "RUNNING"
        or attempt_payload is None
    ):
        raise ValueError("STALE_RESULT: current running work required")
    attempt = WorkAttempt.model_validate_json(attempt_payload)
    if (
        attempt.status != "RUNNING"
        or attempt.work_id != work.work_id
        or attempt.input_hash != work.input_hash
    ):
        raise ValueError("ATTEMPT_NOT_ACTIVE")
    records.resolve(connection, reference(attempt))
    validate_attempt_context(attempt, work)


def check_restart(
    records: SQLiteRecordStore,
    connection: Connection,
    action: ActionRequest,
    work: WorkExecutionState,
) -> None:
    process = current_process(records, connection, work)
    if (
        process.status != "VERIFYING"
        or process.verification_work_ref != reference(work)
        or work.work_type != "VERIFICATION"
    ):
        raise ValueError("STALE_RESULT: current VERIFYING parent required")
    active(records, connection, work)
    if getattr(action.meta, "attempt_id", None) != work.active_attempt_id:
        raise ValueError("ATTEMPT_NOT_ACTIVE")
    assert process.verification_assignment_ref is not None
    required: set[RecordRef] = {
        reference(process),
        process.verification_assignment_ref,
        reference(work),
    }
    dynamic = []
    for payload in connection.execute(
        select(models.work_states.c.payload).where(
            models.work_states.c.analysis_id == str(work.meta.analysis_id)
        )
    ).scalars():
        candidate = WorkExecutionState.model_validate_json(payload)
        if (
            candidate.work_type == "DYNAMIC_REPRO"
            and candidate.work_generation == process.verification_generation
            and getattr(candidate.meta, "hypothesis_id", None)
            == process.meta.hypothesis_id
        ):
            dynamic.append(candidate)
    if len(dynamic) != 1:
        raise ValueError("STALE_RESULT: unique current dynamic work required")
    child = dynamic[0]
    active(records, connection, child)
    if child.parent_work_ref != reference(work):
        raise ValueError("STALE_RESULT: dynamic parent mismatch")
    refs = [
        ref
        for ref in child.input_refs
        if ref.data_kind == "dynamic_reproduction_request"
    ]
    if len(refs) != 1 or not isinstance(refs[0], StoredDataRef):
        raise ValueError("STALE_RESULT: fixed dynamic request required")
    request = records.resolve(connection, refs[0])
    if (
        not isinstance(request, DynamicReproductionRequest)
        or request.verification_generation != process.verification_generation
        or request.verification_assignment_ref != process.verification_assignment_ref
    ):
        raise ValueError("STALE_RESULT: request generation/assignment mismatch")
    old_profile = records.resolve(connection, request.sandbox_profile_ref)
    if not isinstance(old_profile, SandboxProfile):
        raise ValueError("STALE_RESULT: old sandbox profile required")
    required.update((reference(child), refs[0], request.sandbox_profile_ref))
    approved = records.evidence.generation_restart_evidence(action)
    proof = set(action.generation_restart_basis_refs)
    new_profile_ref = None
    if (
        action.generation_restart_reason
        == GenerationRestartReason.SANDBOX_PROFILE_REVISION_CHANGED
    ):
        new_profile_ref = action.sandbox_profile_ref
        if new_profile_ref is None or not isinstance(
            records.resolve(connection, new_profile_ref), SandboxProfile
        ):
            raise ValueError("AUTHORITY_DENIED: approved new profile required")
        proof.add(new_profile_ref)
    if approved is None or not proof.issubset(approved):
        raise ValueError("AUTHORITY_DENIED: restart change approval unproven")
    for ref in proof:
        records.resolve(connection, ref)
    validate_generation_restart_context(
        action,
        current_request_ref=refs[0],
        current_profile_ref=request.sandbox_profile_ref,
        approved_profile_ref=new_profile_ref,
    )
    for kind, model in (
        ("playbook_policy", PlaybookPolicy),
        ("verification_playbook", VerificationPlaybook),
    ):
        selected = [ref for ref in action.input_refs if ref.data_kind == kind]
        if len(selected) != 1:
            raise ValueError("STALE_RESULT: current playbook closure required")
        value = records.resolve(connection, selected[0])
        pointer = connection.execute(
            select(models.current_records.c.record_id).where(
                models.current_records.c.logical_record_id
                == str(value.meta.logical_record_id)
            )
        ).scalar()
        if not isinstance(value, model) or pointer != str(selected[0].record_id):
            raise ValueError("STALE_RESULT: current playbook closure required")
        if isinstance(value, PlaybookPolicy) and not {
            value.common_playbook_ref,
            *(item.playbook_ref for item in value.type_playbooks),
        }.intersection(action.input_refs):
            raise ValueError("STALE_RESULT: policy/playbook pair mismatch")
    if not required.issubset(action.input_refs):
        raise ValueError("STALE_RESULT: restart inputs differ from current closure")
    for wire in connection.execute(
        select(models.records.c.ref)
        .join(models.record_revisions)
        .where(models.records.c.kind == "dynamic_reproduction_request")
    ).scalars():
        other = records.resolve(connection, REF_ADAPTER.validate_json(wire))
        assert isinstance(other, DynamicReproductionRequest)
        if (
            other.meta.analysis_id == work.meta.analysis_id
            and other.meta.hypothesis_id == process.meta.hypothesis_id
            and other.verification_generation > process.verification_generation
        ):
            raise ValueError("STALE_RESULT: premature new generation request")
