"""Trusted operation selection independent of caller supplied quantities."""

from sastsimi.contracts.actions import ActionRequest, ActionType, RequesterRole
from sastsimi.contracts.budget import BudgetAgentRole, OperationKind
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

OPERATIONS = {
    WorkType.WORKSPACE_PREP: (
        OperationKind.WORKSPACE_PREP,
        BudgetAgentRole.REPOSITORY_LOADER,
    ),
    WorkType.STATIC_TOOL: (OperationKind.STATIC_TOOL, BudgetAgentRole.STATIC_ANALYSIS),
    WorkType.STATIC_NORMALIZE: (
        OperationKind.STATIC_NORMALIZE,
        BudgetAgentRole.STATIC_ANALYSIS,
    ),
    WorkType.HYPOTHESIS_PROPOSAL: (
        OperationKind.HYPOTHESIS_GENERATE,
        BudgetAgentRole.HYPOTHESIS,
    ),
    WorkType.CONTEXT_RETRIEVAL: (OperationKind.CONTEXT_RETRIEVAL, None),
    WorkType.PRO_EVIDENCE: (OperationKind.PRO_EVIDENCE, BudgetAgentRole.PRO),
    WorkType.CON_EVIDENCE: (OperationKind.CON_EVIDENCE, BudgetAgentRole.CON),
    WorkType.VERIFICATION: (
        OperationKind.VERIFICATION_SYNTHESIS,
        BudgetAgentRole.VERIFICATION,
    ),
    WorkType.DYNAMIC_REPRO: (
        OperationKind.DYNAMIC_REPRO,
        BudgetAgentRole.DYNAMIC_REPRODUCTION,
    ),
    WorkType.PRIMITIVE_UPDATE: (OperationKind.PRIMITIVE_UPDATE, None),
    WorkType.CHAINING: (OperationKind.CHAINING, BudgetAgentRole.CHAINING),
    WorkType.CWE_LABEL: (OperationKind.CWE_LABELING, BudgetAgentRole.CWE_LABELING),
    WorkType.POLICY_FETCH: (
        OperationKind.POLICY_COLLECT,
        BudgetAgentRole.POLICY_COLLECTOR,
    ),
    WorkType.TECHNICAL_GATE: (
        OperationKind.TECHNICAL_GATE,
        BudgetAgentRole.TECHNICAL_GATE,
    ),
    WorkType.RULE_SCOPE_GATE: (
        OperationKind.RULE_SCOPE_GATE,
        BudgetAgentRole.RULE_SCOPE_GATE,
    ),
    WorkType.FINDING_NORMALIZE: (OperationKind.FINDING_NORMALIZE, None),
    WorkType.REPORT_DRAFT: (OperationKind.REPORTER, BudgetAgentRole.REPORTER),
}


def operation(
    work_type: WorkType, action: ActionRequest
) -> tuple[OperationKind, BudgetAgentRole | None]:
    if (
        work_type == WorkType.POLICY_FETCH
        and action.requested_by == RequesterRole.POLICY_PARSER
    ):
        return OperationKind.POLICY_PARSE, BudgetAgentRole.POLICY_PARSER
    return OPERATIONS[work_type]
