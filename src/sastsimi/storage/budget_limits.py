"""Trusted operation selection independent of caller supplied quantities."""

from sastsimi.contracts.actions import ActionRequest, ActionType, RequesterRole
from sastsimi.contracts.budget import (
    WORK_OPERATIONS,
    BudgetAgentRole,
    OperationKind,
    Purpose,
)
from sastsimi.contracts.work import WorkStatus, WorkType

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
LOCAL_MANUAL_REPAIR_ATTEMPTS = 2


def allows_local_manual_repair_attempt(
    *,
    purpose: Purpose | str,
    action_type: ActionType | str,
    action_reason: str,
    work_status: WorkStatus | str,
    transition_cause: str | None,
) -> bool:
    """Recognize only the explicit, bounded local manual-resume path."""

    if (
        purpose != Purpose.LOCAL_EVALUATION
        or action_type != ActionType.START_ATTEMPT
        or action_reason != "Claim exact READY work"
    ):
        return False
    if work_status == WorkStatus.BLOCKED:
        # Atomic resume admission validates the exhausted attempt before it
        # publishes the USER_RESUME transition.
        return True
    return work_status == WorkStatus.READY and transition_cause == "USER_RESUME"


def operation(
    work_type: WorkType, action: ActionRequest
) -> tuple[OperationKind, BudgetAgentRole | None]:
    if (
        work_type == WorkType.POLICY_FETCH
        and action.requested_by == RequesterRole.POLICY_PARSER
    ):
        return OperationKind.POLICY_PARSE, BudgetAgentRole.POLICY_PARSER
    return OPERATIONS[work_type]
