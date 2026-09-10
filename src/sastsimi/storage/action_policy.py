"""Closed canonical §08 action-role policy; identity equality is not permission."""

from collections.abc import Mapping
from types import MappingProxyType

from sastsimi.contracts.actions import ActionRequest, ActionType, RequesterRole
from sastsimi.contracts.result_registry import RESULT_REGISTRY


def roles(*values: str) -> frozenset[RequesterRole]:
    return frozenset(RequesterRole(value) for value in values)


WORK_CONTROL = roles(
    "ORCHESTRATION",
    "VERIFICATION",
    "PRIMITIVE_ADMISSION_RUNTIME",
    "REPRODUCTION_SESSION_MANAGER",
    "RECOVERY",
)
ACTION_ROLES: Mapping[ActionType, frozenset[RequesterRole]] = MappingProxyType(
    {
        ActionType.REGISTER_WORK: WORK_CONTROL
        - {RequesterRole.REPRODUCTION_SESSION_MANAGER},
        ActionType.CHANGE_WORK_STATE: WORK_CONTROL,
        ActionType.START_ATTEMPT: WORK_CONTROL,
        ActionType.CANCEL_WORK: WORK_CONTROL,
        # RECOVERY replays the stored Verification action, not a new semantic request.
        ActionType.RESTART_VERIFICATION_GENERATION: roles("VERIFICATION"),
        ActionType.READ_CODE: roles(
            "HYPOTHESIS", "PRO", "CON", "VERIFICATION", "CWE_LABELING", "TECHNICAL_GATE"
        ),
        ActionType.RUN_TOOL: roles(
            "REPOSITORY_LOADER", "STATIC_ANALYSIS", "POLICY_COLLECTOR"
        ),
        ActionType.CALL_LLM: roles(
            "HYPOTHESIS",
            "PRO",
            "CON",
            "VERIFICATION",
            "CWE_LABELING",
            "CHAINING",
            "POLICY_PARSER",
            "DYNAMIC_REPRODUCTION",
        ),
        ActionType.FETCH_POLICY: roles("POLICY_COLLECTOR"),
        ActionType.REQUEST_DYNAMIC_REPRO: roles("VERIFICATION"),
        ActionType.RUN_SANDBOX: roles("REPRODUCTION_SETUP_AUTOMATION"),
        ActionType.SAVE_RESULT: frozenset(RequesterRole),
        ActionType.CALL_TECHNICAL_GATE: roles("VERIFICATION"),
        ActionType.CALL_RULE_SCOPE_GATE: roles("VERIFICATION"),
        ActionType.CREATE_REPORT_DRAFT: roles("VERIFICATION"),
    }
)


def check_role(action: ActionRequest, identity_role: RequesterRole | None) -> None:
    if (
        identity_role != action.requested_by
        or identity_role not in ACTION_ROLES[action.action_type]
    ):
        raise ValueError("AUTHORITY_DENIED")
    if action.action_type == ActionType.SAVE_RESULT:
        binding = RESULT_REGISTRY.get(action.result_kind or "")
        if binding is None or binding.owner != identity_role:
            raise ValueError("AUTHORITY_DENIED")
