"""Action-specific current owner/generation/input admission, never semantic judging."""

from sqlalchemy import Connection, select

from sastsimi.contracts.actions import ActionRequest, ActionType, RequesterRole
from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.budget import BudgetProfileBinding
from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    DynamicReproductionResult,
    EnvironmentRecipe,
    EnvironmentRequirements,
    PoCBundle,
    ReproductionPlan,
    SandboxProfile,
)
from sastsimi.contracts.gates import (
    CWELabel,
    RuleScopeImpactReview,
    TechnicalEvidenceReview,
    validate_true_dynamic,
)
from sastsimi.contracts.policy import RunPolicyState
from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.reporting import Finding
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import TransitionCommit, WorkExecutionState

from . import models
from .action_context import current_process
from .codec import reference
from .repositories import SQLiteRecordStore
from .restart_policy import check_restart
from .run_states import get_run

R7_ROLES = frozenset(
    {
        RequesterRole.DYNAMIC_REPRODUCTION,
        RequesterRole.REPRODUCTION_SETUP_AUTOMATION,
        RequesterRole.SANDBOX_CONTROLLER,
        RequesterRole.REPRODUCTION_SESSION_MANAGER,
    }
)
STAGE_WORKS = {
    ActionType.REQUEST_DYNAMIC_REPRO: "VERIFICATION",
    ActionType.CALL_TECHNICAL_GATE: "TECHNICAL_GATE",
    ActionType.CALL_RULE_SCOPE_GATE: "RULE_SCOPE_GATE",
    ActionType.CREATE_REPORT_DRAFT: "REPORT_DRAFT",
}


def resolved[T: ContractModel](
    records: SQLiteRecordStore,
    connection: Connection,
    ref: RecordRef | None,
    model: type[T],
) -> T:
    if ref is None:
        raise ValueError("STALE_RESULT: required exact input missing")
    value = records.resolve(connection, ref)
    if not isinstance(value, model):
        raise ValueError("STALE_RESULT: exact input kind mismatch")
    return value


def current(records: SQLiteRecordStore, connection: Connection, ref: RecordRef) -> None:
    value = records.resolve(connection, ref)
    pointer = connection.execute(
        select(models.current_records.c.record_id).where(
            models.current_records.c.logical_record_id
            == str(value.meta.logical_record_id)
        )
    ).scalar()
    if pointer != str(ref.record_id):
        raise ValueError("STALE_RESULT: current stage input superseded")


def check_stage(
    records: SQLiteRecordStore,
    connection: Connection,
    action: ActionRequest,
    work: WorkExecutionState,
) -> None:
    if action.llm_call_spec_ref is not None:
        from .llm_context import check_llm_context

        check_llm_context(records, connection, action, work)
    if (
        action.requested_by == RequesterRole.CWE_LABELING
        or action.action_type
        in {
            ActionType.CALL_TECHNICAL_GATE,
            ActionType.CALL_RULE_SCOPE_GATE,
            ActionType.CREATE_REPORT_DRAFT,
        }
        or action.result_kind
        in {
            "cwe_label",
            "technical_evidence_review",
            "rule_scope_impact_review",
            "finding",
            "report_draft",
        }
    ) and current_process(records, connection, work).status != "TERMINAL":
        raise ValueError("STALE_RESULT: final admission requires TERMINAL process")
    if action.action_type == ActionType.RESTART_VERIFICATION_GENERATION:
        check_restart(records, connection, action, work)
    expected_work = STAGE_WORKS.get(action.action_type)
    if expected_work is not None and (
        work.work_type.value != expected_work
        or work.status.value != "RUNNING"
        or work.active_attempt_id is None
        or getattr(work.meta, "hypothesis_id", None) is None
    ):
        raise ValueError("AUTHORITY_DENIED: active hypothesis stage required")
    if action.requested_by in R7_ROLES:
        if (
            work.work_type.value != "DYNAMIC_REPRO"
            or getattr(work.meta, "hypothesis_id", None) is None
        ):
            raise ValueError("AUTHORITY_DENIED: exact R7 work required")
        process = current_process(records, connection, work)
        requests = [
            ref
            for ref in work.input_refs
            if ref.data_kind == "dynamic_reproduction_request"
        ]
        if len(requests) != 1:
            raise ValueError("STALE_RESULT: R7 fixed request required")
        request = resolved(records, connection, requests[0], DynamicReproductionRequest)
        if (
            request.verification_generation != process.verification_generation
            or request.verification_assignment_ref
            != process.verification_assignment_ref
            or work.work_generation != process.verification_generation
        ):
            raise ValueError("STALE_RESULT: R7 current generation/request mismatch")
        if action.action_type not in {
            ActionType.START_ATTEMPT,
            ActionType.CHANGE_WORK_STATE,
            ActionType.CANCEL_WORK,
        } and (work.status.value != "RUNNING" or work.active_attempt_id is None):
            raise ValueError("ATTEMPT_NOT_ACTIVE")
        if action.action_type == ActionType.RUN_SANDBOX:
            if action.dynamic_request_ref != requests[0]:
                raise ValueError("STALE_RESULT: sandbox request mismatch")
            plan = resolved(
                records, connection, action.reproduction_plan_ref, ReproductionPlan
            )
            requirements = resolved(
                records,
                connection,
                plan.environment_requirements_ref,
                EnvironmentRequirements,
            )
            for value in (plan, requirements):
                current(records, connection, reference(value))
                if (
                    reference(value) not in action.input_refs
                    or value.request_ref != requests[0]
                    or value.meta.attempt_id != work.active_attempt_id
                    or value.meta.hypothesis_id
                    != getattr(work.meta, "hypothesis_id", None)
                ):
                    raise ValueError(
                        "STALE_RESULT: sandbox same-attempt input mismatch"
                    )
            if (
                plan.purpose != request.purpose
                or plan.hypothesis_ref != request.hypothesis_ref
                or plan.sandbox_profile_ref != request.sandbox_profile_ref
                or action.sandbox_profile_ref != request.sandbox_profile_ref
            ):
                raise ValueError("STALE_RESULT: sandbox request/plan/profile mismatch")
            resolved(records, connection, action.sandbox_profile_ref, SandboxProfile)
            run = get_run(connection, str(work.meta.analysis_id))
            binding = resolved(
                records, connection, run.budget_binding_ref, BudgetProfileBinding
            )
            if (
                binding.status != "ACTIVE"
                or action.resource_profile_ref != binding.dynamic_lifecycle_profile_ref
            ):
                raise ValueError("STALE_RESULT: current run lifecycle required")
            records.resolve(connection, binding.dynamic_lifecycle_profile_ref)
            if action.image_digest is not None:
                recipe_refs = [
                    ref
                    for ref in action.input_refs
                    if ref.data_kind == "environment_recipe"
                ]
                recipe = resolved(
                    records,
                    connection,
                    recipe_refs[0] if len(recipe_refs) == 1 else None,
                    EnvironmentRecipe,
                )
                if (
                    recipe.request_ref != requests[0]
                    or recipe.environment_requirements_ref != reference(requirements)
                    or recipe.meta.attempt_id != work.active_attempt_id
                    or recipe.meta.hypothesis_id
                    != getattr(work.meta, "hypothesis_id", None)
                    or recipe.built_image_digest != action.image_digest
                ):
                    raise ValueError(
                        "STALE_RESULT: sandbox image/recipe binding mismatch"
                    )
            # run_policy_state_ref is deliberately audit-only for local Sandbox.
    if action.action_type == ActionType.REQUEST_DYNAMIC_REPRO:
        process = current_process(records, connection, work)
        request = resolved(
            records, connection, action.dynamic_request_ref, DynamicReproductionRequest
        )
        if (
            process.status != "VERIFYING"
            or process.verification_work_ref != reference(work)
            or request.verification_generation != process.verification_generation
            or request.verification_assignment_ref
            != process.verification_assignment_ref
            or request.meta.hypothesis_id != getattr(work.meta, "hypothesis_id", None)
        ):
            raise ValueError("STALE_RESULT: current R6 request required")
        for payload in connection.execute(
            select(models.work_states.c.payload).where(
                models.work_states.c.analysis_id == str(work.meta.analysis_id)
            )
        ).scalars():
            other = WorkExecutionState.model_validate_json(payload)
            if (
                other.work_type.value == "DYNAMIC_REPRO"
                and getattr(other.meta, "hypothesis_id", None)
                == getattr(work.meta, "hypothesis_id", None)
                and other.work_generation == process.verification_generation
                and action.dynamic_request_ref not in other.input_refs
            ):
                raise ValueError("AUTHORITY_DENIED: one dynamic request per generation")
    if (
        action.action_type
        in {
            ActionType.CALL_TECHNICAL_GATE,
            ActionType.CALL_RULE_SCOPE_GATE,
            ActionType.CREATE_REPORT_DRAFT,
        }
        or action.requested_by == RequesterRole.CWE_LABELING
    ):
        check_final_inputs(records, connection, action, work)


def check_final_inputs(
    records: SQLiteRecordStore,
    connection: Connection,
    action: ActionRequest,
    work: WorkExecutionState,
) -> None:
    process = current_process(records, connection, work)
    verification = resolved(
        records, connection, process.verification_result_ref, VerificationResult
    )
    if (
        process.verification_result_ref not in action.input_refs
        or verification.verdict != "TRUE"
    ):
        raise ValueError("STALE_RESULT: current final TRUE required")
    if action.requested_by == RequesterRole.CWE_LABELING:
        if (
            work.work_type.value != "CWE_LABEL"
            or work.status.value != "RUNNING"
            or work.active_attempt_id is None
        ):
            raise ValueError("ATTEMPT_NOT_ACTIVE")
        return

    def one[T: ContractModel](kind: str, model: type[T]) -> T:
        refs = [ref for ref in action.input_refs if ref.data_kind == kind]
        if len(refs) != 1:
            raise ValueError("STALE_RESULT: stage input closure missing")
        current(records, connection, refs[0])
        return resolved(records, connection, refs[0], model)

    dynamic = resolved(
        records, connection, verification.dynamic_result_ref, DynamicReproductionResult
    )
    poc = resolved(records, connection, verification.poc_ref, PoCBundle)
    validate_true_dynamic(verification, dynamic, poc)
    label = one("cwe_label", CWELabel)
    if (
        label.verification_result_ref != process.verification_result_ref
        or label.verification_generation != process.verification_generation
    ):
        raise ValueError("STALE_RESULT: current CWE/Verification pair required")
    required = {
        reference(verification),
        reference(dynamic),
        reference(poc),
        reference(label),
    }
    committed = {
        ref
        for payload in connection.execute(
            select(models.transition_commits.c.payload).where(
                models.transition_commits.c.state == "COMMITTED"
            )
        ).scalars()
        for ref in TransitionCommit.model_validate_json(payload).output_refs
    }
    if not required.issubset(committed):
        raise ValueError("GATE_ORDER: uncommitted evidence closure")
    if action.action_type == ActionType.CALL_TECHNICAL_GATE:
        return
    technical = one("technical_evidence_review", TechnicalEvidenceReview)
    if (
        technical.status != "ACCEPT"
        or technical.verification_result_ref != reference(verification)
        or technical.cwe_label_ref != reference(label)
        or reference(technical) not in committed
    ):
        raise ValueError("GATE_ORDER: exact Technical ACCEPT required")
    policy = one("run_policy_state", RunPolicyState)
    run = get_run(connection, str(work.meta.analysis_id))
    if (
        run.run_policy_state_ref != reference(policy)
        or policy.status not in {"CURRENT", "ABSENT", "UNVERIFIED"}
        or policy.collection_result_ref not in action.input_refs
    ):
        raise ValueError("STALE_RESULT: frozen run policy required")
    if action.action_type == ActionType.CREATE_REPORT_DRAFT:
        review = one("rule_scope_impact_review", RuleScopeImpactReview)
        finding = one("finding", Finding)
        if (
            not review.report_ready()
            or review.verification_result_ref != reference(verification)
            or review.technical_review_ref != reference(technical)
            or review.cwe_label_ref != reference(label)
            or review.run_policy_state_ref != reference(policy)
            or finding.rule_scope_impact_review_ref != reference(review)
            or finding.verification_result_ref != reference(verification)
            or finding.cwe_label_ref != reference(label)
            or reference(review) not in committed
            or reference(finding) not in committed
        ):
            raise ValueError("REPORT_NOT_READY: exact six-axis closure required")
