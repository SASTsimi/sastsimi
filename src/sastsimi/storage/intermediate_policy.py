"""Exact owner receipts for the finite set of same-attempt intermediate outputs."""

from sqlalchemy import Connection, select

from sastsimi.contracts.actions import ActionDecision, ActionRequest
from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.records import PolicyCacheMeta, RecordMeta, RunMeta
from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.result_registry import validate_result_owner
from sastsimi.contracts.verification import VerificationInitialAssessment
from sastsimi.contracts.work import WorkExecutionState

from . import models
from .codec import REF_ADAPTER, reference
from .repositories import SQLiteRecordStore

INTERMEDIATE_KINDS = frozenset(
    {
        ("POLICY_FETCH", "policy_parser_result", "POLICY_PARSER"),
        ("VERIFICATION", "verification_initial_assessment", "VERIFICATION"),
        ("VERIFICATION", "dynamic_reproduction_request", "VERIFICATION"),
        ("DYNAMIC_REPRO", "environment_requirements", "DYNAMIC_REPRODUCTION"),
        ("DYNAMIC_REPRO", "reproduction_plan", "DYNAMIC_REPRODUCTION"),
        ("DYNAMIC_REPRO", "environment_recipe", "REPRODUCTION_SETUP_AUTOMATION"),
        ("DYNAMIC_REPRO", "sandbox_environment", "REPRODUCTION_SETUP_AUTOMATION"),
        ("DYNAMIC_REPRO", "cleanup_result", "REPRODUCTION_SETUP_AUTOMATION"),
        ("DYNAMIC_REPRO", "sandbox_policy_decision", "SANDBOX_CONTROLLER"),
        ("DYNAMIC_REPRO", "sandbox_command_record", "REPRODUCTION_SESSION_MANAGER"),
        ("DYNAMIC_REPRO", "poc_candidate", "DYNAMIC_REPRODUCTION"),
        ("DYNAMIC_REPRO", "dynamic_reproduction_conclusion", "DYNAMIC_REPRODUCTION"),
        ("DYNAMIC_REPRO", "agent_log", "REPRODUCTION_SESSION_MANAGER"),
        ("DYNAMIC_REPRO", "poc_bundle", "REPRODUCTION_SESSION_MANAGER"),
        ("DYNAMIC_REPRO", "dynamic_reproduction_tool_request", "DYNAMIC_REPRODUCTION"),
    }
)


def validate_intermediate_owner(
    candidate: ContractModel,
    action: ActionRequest,
    work: WorkExecutionState,
) -> None:
    meta = getattr(candidate, "meta", None)
    if not isinstance(meta, (RunMeta, RecordMeta, PolicyCacheMeta)):
        raise ValueError("INTERMEDIATE_RECORD_METADATA_REQUIRED")
    kind = meta.record_type
    if (
        work.work_type.value,
        kind,
        action.requested_by.value,
    ) not in INTERMEDIATE_KINDS:
        raise ValueError("INTERMEDIATE_PUBLICATION_DENIED")
    if kind == "verification_initial_assessment":
        assessment = VerificationInitialAssessment.model_validate_json(
            candidate.model_dump_json()
        )
        if assessment.verification_work_id != work.work_id or (
            assessment.verification_generation != work.work_generation
        ):
            raise ValueError("STALE_RESULT: initial assessment work/generation")
    validate_result_owner(kind, candidate, action.requested_by)


def prepublished_output(
    records: SQLiteRecordStore,
    connection: Connection,
    ref: RecordRef,
    work: WorkExecutionState,
) -> bool:
    """Reject any published candidate without its original exact trusted receipt."""
    from .output_receipts import read_outputs

    try:
        candidate = records.resolve(connection, ref)
    except LookupError:
        return False
    if not isinstance(candidate, ContractModel):
        raise ValueError("INTERMEDIATE_RECEIPT_REQUIRED")
    if (
        work.status != "RUNNING"
        or work.active_attempt_id is None
        or getattr(candidate.meta, "attempt_id", None) != work.active_attempt_id
        or any(
            getattr(candidate.meta, name, None) != getattr(work.meta, name, None)
            for name in ("analysis_id", "workspace_id", "commit_id", "hypothesis_id")
        )
    ):
        raise ValueError("INTERMEDIATE_RECEIPT_REQUIRED: work/attempt scope")
    current = connection.execute(
        select(models.current_records.c.record_id).where(
            models.current_records.c.logical_record_id
            == str(candidate.meta.logical_record_id),
        )
    ).scalar()
    if current != str(ref.record_id):
        raise ValueError("STALE_RESULT: prepublished intermediate is not current")
    for payload in connection.execute(
        select(models.action_decisions.c.payload)
    ).scalars():
        used = ActionDecision.model_validate_json(payload)
        if (
            used.decision != "ALLOW"
            or used.use_status != "USED"
            or ref not in used.outcome_refs
        ):
            continue
        action = records.resolve(connection, used.action_ref)
        if not isinstance(action, ActionRequest) or (
            action.action_type != "SAVE_RESULT"
            or action.work_ref != reference(work)
            or getattr(action.meta, "attempt_id", None) != work.active_attempt_id
            or (work.work_type.value, ref.data_kind, action.requested_by.value)
            not in INTERMEDIATE_KINDS
        ):
            continue
        issued_wire = connection.execute(
            select(models.action_requests.c.decision_ref).where(
                models.action_requests.c.action_id == str(action.action_id),
            )
        ).scalar()
        if issued_wire is None:
            continue
        issued_ref = REF_ADAPTER.validate_json(issued_wire)
        issued = records.resolve(connection, issued_ref)
        if not isinstance(issued, ActionDecision) or (
            issued.decision != "ALLOW"
            or issued.use_status != "UNUSED"
            or issued.action_ref != used.action_ref
            or issued.decision_id != used.decision_id
            or issued.meta.logical_record_id != used.meta.logical_record_id
            or ref not in read_outputs(connection, action, issued_ref)
        ):
            continue
        validate_intermediate_owner(candidate, action, work)
        return True
    raise ValueError("INTERMEDIATE_RECEIPT_REQUIRED: exact owner decision/outcome")
