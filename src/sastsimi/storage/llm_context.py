"""Exact LLM input admission from immutable work inputs and owned stage outputs."""

from sqlalchemy import Connection, select

from sastsimi.contracts.actions import ActionDecision, ActionRequest
from sastsimi.contracts.dynamic import SandboxProfile
from sastsimi.contracts.llm import LLMCallSpec
from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.work import WorkExecutionState

from . import models
from .action_context import current_process
from .codec import reference
from .repositories import SQLiteRecordStore


def check_llm_context(
    records: SQLiteRecordStore,
    connection: Connection,
    action: ActionRequest,
    work: WorkExecutionState,
) -> None:
    if action.llm_call_spec_ref is None:
        return
    spec = records.resolve(connection, action.llm_call_spec_ref)
    if not isinstance(spec, LLMCallSpec):
        raise ValueError("LLM_CONTEXT_WORK_MISMATCH")
    if tuple(action.input_refs) != spec.context_refs:
        raise ValueError("LLM_CONTEXT_WORK_MISMATCH")
    expected_roles = {
        "CALL_TECHNICAL_GATE": "TECHNICAL_GATE",
        "CALL_RULE_SCOPE_GATE": "RULE_SCOPE_GATE",
        "CREATE_REPORT_DRAFT": "REPORTER",
    }
    expected_work = {
        "HYPOTHESIS": "HYPOTHESIS_PROPOSAL",
        "PRO": "PRO_EVIDENCE",
        "CON": "CON_EVIDENCE",
        "VERIFICATION": "VERIFICATION",
        "DYNAMIC_REPRODUCTION": "DYNAMIC_REPRO",
        "POLICY_PARSER": "POLICY_FETCH",
        "CWE_LABELING": "CWE_LABEL",
        "CHAINING": "CHAINING",
        "TECHNICAL_GATE": "TECHNICAL_GATE",
        "RULE_SCOPE_GATE": "RULE_SCOPE_GATE",
        "REPORTER": "REPORT_DRAFT",
    }
    if (
        spec.agent_role != expected_roles.get(action.action_type, action.requested_by)
        or work.work_type != expected_work[spec.agent_role]
    ):
        raise ValueError("LLM_CONTEXT_WORK_MISMATCH")
    for wire in connection.execute(select(models.action_decisions.c.payload)).scalars():
        bound = ActionDecision.model_validate_json(wire)
        producer = records.resolve(connection, bound.action_ref)
        if isinstance(producer, ActionRequest) and (
            producer.llm_call_spec_ref == action.llm_call_spec_ref
            and producer.action_id != action.action_id
        ):
            raise ValueError("LLM_CONTEXT_WORK_MISMATCH: call spec already bound")
    allowed: set[RecordRef] = set(work.input_refs)
    if work.work_type == "VERIFICATION":
        process = current_process(records, connection, work)
        if (
            process.verification_generation != work.work_generation
            or process.verification_work_ref != reference(work)
        ):
            raise ValueError("LLM_CONTEXT_GENERATION_MISMATCH")
        if process.verification_assignment_ref is not None:
            allowed.add(process.verification_assignment_ref)
    parent_ref = reference(work)
    for wire in connection.execute(
        select(models.work_states.c.payload).where(
            models.work_states.c.analysis_id == str(work.meta.analysis_id)
        )
    ).scalars():
        child = WorkExecutionState.model_validate_json(wire)
        if (
            (
                child.parent_work_ref == parent_ref
                or (
                    child.work_type == "CONTEXT_RETRIEVAL"
                    and work.work_type == "VERIFICATION"
                    and any(
                        ref.data_kind == "vulnerability_hypothesis"
                        and ref in work.input_refs
                        for ref in child.input_refs
                    )
                )
            )
            and child.work_generation == work.work_generation
            and child.status == "SUCCEEDED"
            and getattr(child.meta, "hypothesis_id", None)
            == getattr(work.meta, "hypothesis_id", None)
            and child.work_type
            in {"PRO_EVIDENCE", "CON_EVIDENCE", "CONTEXT_RETRIEVAL", "DYNAMIC_REPRO"}
        ):
            allowed.update(child.output_refs)
            if child.work_type == "CONTEXT_RETRIEVAL":
                allowed.update(child.input_refs)
    for wire in connection.execute(select(models.action_decisions.c.payload)).scalars():
        decision = ActionDecision.model_validate_json(wire)
        if decision.use_status != "USED":
            continue
        producer = records.resolve(connection, decision.action_ref)
        if not isinstance(producer, ActionRequest) or producer.work_ref != parent_ref:
            continue
        if producer.action_type == "SAVE_RESULT":
            allowed.update(decision.outcome_refs)
        elif (
            producer.action_type == "FETCH_POLICY"
            and spec.agent_role == "POLICY_PARSER"
        ):
            allowed.update(producer.input_refs)
    for ref in spec.context_refs:
        if (
            ref.data_kind == "sandbox_profile"
            and spec.task_kind == "CREATE_DYNAMIC_REQUEST"
        ):
            profile = records.resolve(connection, ref)
            if isinstance(
                profile, SandboxProfile
            ) and records.evidence.sandbox_configuration_approved(profile):
                allowed.add(ref)
        if ref not in allowed:
            raise ValueError("LLM_CONTEXT_WORK_MISMATCH: " + ref.data_kind)
        if ref.record_id is None:
            continue
        value = records.resolve(connection, ref)
        if any(
            getattr(value.meta, name, None) is not None
            and getattr(value.meta, name, None) != getattr(work.meta, name, None)
            for name in ("analysis_id", "workspace_id", "commit_id", "hypothesis_id")
        ):
            raise ValueError("LLM_CONTEXT_WORK_MISMATCH")
        if (
            getattr(value, "verification_generation", work.work_generation)
            != work.work_generation
        ):
            raise ValueError("LLM_CONTEXT_GENERATION_MISMATCH")
    if work.work_type == "VERIFICATION" and spec.agent_role == "VERIFICATION":
        required = {
            ref
            for ref in work.input_refs
            if ref.data_kind
            in {
                "vulnerability_hypothesis",
                "playbook_policy",
                "verification_playbook",
                "playbook_application",
            }
        }
        if not required.issubset(spec.context_refs):
            raise ValueError("LLM_CONTEXT_WORK_MISMATCH")
        if spec.task_kind in {"CREATE_DYNAMIC_REQUEST", "FINAL_VERDICT"} and not any(
            ref.data_kind == "verification_initial_assessment"
            for ref in spec.context_refs
        ):
            raise ValueError("LLM_CONTEXT_ASSESSMENT_REQUIRED")
