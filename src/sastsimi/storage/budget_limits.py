"""Trusted operation selection independent of caller supplied quantities."""

from sastsimi.contracts.actions import ActionRequest, ActionType, RequesterRole
from sastsimi.contracts.budget import (
    WORK_OPERATIONS,
    BudgetAgentRole,
    OperationKind,
    Purpose,
)
from sastsimi.contracts.work import AttemptTrigger, WorkStatus, WorkType

EXTERNAL_ACTIONS = frozenset(
    {
        ActionType.READ_CODE,
        ActionType.RUN_TOOL,
        ActionType.CALL_LLM,
        ActionType.FETCH_POLICY,
        ActionType.RUN_SANDBOX,
        ActionType.CALL_TECHNICAL_GATE,
        ActionType.CALL_RULE_SCOPE_GATE,
        ActionType.CREATE_REPORT_DRAFT,
    }
)

OPERATIONS = WORK_OPERATIONS
LOCAL_MANUAL_REPAIR_ATTEMPTS = 10
LOCAL_MANUAL_REPAIR_CALLS = 12


def allows_local_manual_repair_attempt(
    *,
    purpose: Purpose | str,
    action_type: ActionType | str,
    action_reason: str,
    work_status: WorkStatus | str,
    transition_cause: str | None,
    attempt_trigger: AttemptTrigger | str | None = None,
) -> bool:
    """Recognize only the explicit, bounded local manual-resume path."""

    if (
        purpose != Purpose.LOCAL_EVALUATION
        or action_type != ActionType.START_ATTEMPT
        or action_reason != "Claim exact READY work"
    ):
        return False
    return allows_local_manual_repair_scope(
        purpose=purpose,
        work_status=work_status,
        transition_cause=transition_cause,
        attempt_trigger=attempt_trigger,
    )


def allows_local_manual_repair_scope(
    *,
    purpose: Purpose | str,
    work_status: WorkStatus | str,
    transition_cause: str | None,
    attempt_trigger: AttemptTrigger | str | None,
) -> bool:
    """Keep the bounded allowance active inside the claimed RESUME attempt."""

    if purpose != Purpose.LOCAL_EVALUATION:
        return False
    if work_status in {WorkStatus.BLOCKED, WorkStatus.FAILED}:
        # Atomic resume admission validates the exhausted attempt before it
        # publishes the USER_RESUME transition.
        return True
    if work_status == WorkStatus.READY:
        return transition_cause == "USER_RESUME"
    return (
        work_status == WorkStatus.RUNNING
        and attempt_trigger in {AttemptTrigger.RESUME, AttemptTrigger.RETRY}
    )


def local_manual_repair_call_allowance(
    *,
    purpose: Purpose | str,
    action_type: ActionType | str,
    work_status: WorkStatus | str,
    transition_cause: str | None,
    attempt_trigger: AttemptTrigger | str | None,
) -> int:
    """Preserve one bounded end-to-end call sequence during local recovery."""

    if action_type not in EXTERNAL_ACTIONS:
        return 0
    if not allows_local_manual_repair_scope(
        purpose=purpose,
        work_status=work_status,
        transition_cause=transition_cause,
        attempt_trigger=attempt_trigger,
    ):
        return 0
    return LOCAL_MANUAL_REPAIR_CALLS


def operation(
    work_type: WorkType, action: ActionRequest
) -> tuple[OperationKind, BudgetAgentRole | None]:
    if (
        work_type == WorkType.POLICY_FETCH
        and action.requested_by == RequesterRole.POLICY_PARSER
    ):
        return OperationKind.POLICY_PARSE, BudgetAgentRole.POLICY_PARSER
    return OPERATIONS[work_type]
