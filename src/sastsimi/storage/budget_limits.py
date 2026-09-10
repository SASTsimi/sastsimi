"""Trusted operation selection independent of caller supplied quantities."""

from sastsimi.contracts.actions import ActionRequest, ActionType, RequesterRole
from sastsimi.contracts.budget import (
    WORK_OPERATIONS,
    BudgetAgentRole,
    OperationKind,
)
from sastsimi.contracts.work import WorkType

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


def operation(
    work_type: WorkType, action: ActionRequest
) -> tuple[OperationKind, BudgetAgentRole | None]:
    if (
        work_type == WorkType.POLICY_FETCH
        and action.requested_by == RequesterRole.POLICY_PARSER
    ):
        return OperationKind.POLICY_PARSE, BudgetAgentRole.POLICY_PARSER
    return OPERATIONS[work_type]
