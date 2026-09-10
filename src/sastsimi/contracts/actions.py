from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Self

from pydantic import AwareDatetime, field_validator, model_validator

from .base import ContractModel, NonEmptyStr, NonNegativeInt, PositiveInt
from .ids import ActionId, DecisionId, ErrorId
from .records import RecordMeta, validate_revision
from .refs import BudgetScopeRef, RecordRef, StoredDataRef, require_record_ref
from .work import ScopedRecord


class ActionType(StrEnum):
    REGISTER_WORK = "REGISTER_WORK"
    CHANGE_WORK_STATE = "CHANGE_WORK_STATE"
    START_ATTEMPT = "START_ATTEMPT"
    CANCEL_WORK = "CANCEL_WORK"
    RESTART_VERIFICATION_GENERATION = "RESTART_VERIFICATION_GENERATION"
    READ_CODE = "READ_CODE"
    RUN_TOOL = "RUN_TOOL"
    CALL_LLM = "CALL_LLM"
    FETCH_POLICY = "FETCH_POLICY"
    REQUEST_DYNAMIC_REPRO = "REQUEST_DYNAMIC_REPRO"
    RUN_SANDBOX = "RUN_SANDBOX"
    SAVE_RESULT = "SAVE_RESULT"
    CALL_TECHNICAL_GATE = "CALL_TECHNICAL_GATE"
    CALL_RULE_SCOPE_GATE = "CALL_RULE_SCOPE_GATE"
    CREATE_REPORT_DRAFT = "CREATE_REPORT_DRAFT"


class RequesterRole(StrEnum):
    ORCHESTRATION = "ORCHESTRATION"
    HYPOTHESIS = "HYPOTHESIS"
    PRO = "PRO"
    CON = "CON"
    VERIFICATION = "VERIFICATION"
    CWE_LABELING = "CWE_LABELING"
    CHAINING = "CHAINING"
    TECHNICAL_GATE = "TECHNICAL_GATE"
    RULE_SCOPE_GATE = "RULE_SCOPE_GATE"
    REPORTER = "REPORTER"
    REPOSITORY_LOADER = "REPOSITORY_LOADER"
    CONTEXT_RETRIEVAL_SERVICE = "CONTEXT_RETRIEVAL_SERVICE"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    POLICY_COLLECTOR = "POLICY_COLLECTOR"
    POLICY_PARSER = "POLICY_PARSER"
    PRIMITIVE_ADMISSION_RUNTIME = "PRIMITIVE_ADMISSION_RUNTIME"
    DYNAMIC_REPRODUCTION = "DYNAMIC_REPRODUCTION"
    REPRODUCTION_SETUP_AUTOMATION = "REPRODUCTION_SETUP_AUTOMATION"
    SANDBOX_CONTROLLER = "SANDBOX_CONTROLLER"
    REPRODUCTION_SESSION_MANAGER = "REPRODUCTION_SESSION_MANAGER"
    BUDGET_RUNTIME = "BUDGET_RUNTIME"
    R8_EVALUATION_RUNTIME = "R8_EVALUATION_RUNTIME"
    RECOVERY = "RECOVERY"


class CheckType(StrEnum):
    SCHEMA = "SCHEMA"
    AUTHORITY = "AUTHORITY"
    IDENTITY = "IDENTITY"
    REVISION = "REVISION"
    STATE = "STATE"
    BUDGET = "BUDGET"
    TOOL = "TOOL"
    FILE_PATH = "FILE_PATH"
    PROVIDER = "PROVIDER"
    SESSION = "SESSION"
    GATE_ORDER = "GATE_ORDER"
    REPORT_READY = "REPORT_READY"
    REDACTION = "REDACTION"


class CheckResult(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"


class Decision(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class UseStatus(StrEnum):
    UNUSED = "UNUSED"
    USED = "USED"
    NOT_USED = "NOT_USED"
    EXPIRED = "EXPIRED"


class SessionMode(StrEnum):
    NEW = "NEW"
    RESUME = "RESUME"
    AUTO = "AUTO"


class GenerationRestartReason(StrEnum):
    DYNAMIC_REQUEST_REPLACEMENT_REQUIRED = "DYNAMIC_REQUEST_REPLACEMENT_REQUIRED"
    SANDBOX_PROFILE_REVISION_CHANGED = "SANDBOX_PROFILE_REVISION_CHANGED"


REQUIRED_CHECKS: Mapping[ActionType, frozenset[CheckType]] = MappingProxyType(
    {
        ActionType.REGISTER_WORK: frozenset(
            {
                CheckType.SCHEMA,
                CheckType.AUTHORITY,
                CheckType.IDENTITY,
                CheckType.REVISION,
                CheckType.STATE,
                CheckType.BUDGET,
            }
        ),
        ActionType.CHANGE_WORK_STATE: frozenset(
            {CheckType.SCHEMA, CheckType.AUTHORITY, CheckType.IDENTITY, CheckType.STATE}
        ),
        ActionType.START_ATTEMPT: frozenset(
            {CheckType.SCHEMA, CheckType.AUTHORITY, CheckType.STATE, CheckType.BUDGET}
        ),
        ActionType.CANCEL_WORK: frozenset(
            {CheckType.SCHEMA, CheckType.AUTHORITY, CheckType.IDENTITY, CheckType.STATE}
        ),
        ActionType.RESTART_VERIFICATION_GENERATION: frozenset(
            {
                CheckType.SCHEMA,
                CheckType.AUTHORITY,
                CheckType.IDENTITY,
                CheckType.REVISION,
                CheckType.STATE,
                CheckType.BUDGET,
            }
        ),
        ActionType.READ_CODE: frozenset(
            {
                CheckType.SCHEMA,
                CheckType.AUTHORITY,
                CheckType.IDENTITY,
                CheckType.REVISION,
                CheckType.BUDGET,
                CheckType.FILE_PATH,
            }
        ),
        ActionType.RUN_TOOL: frozenset(
            {
                CheckType.SCHEMA,
                CheckType.AUTHORITY,
                CheckType.REVISION,
                CheckType.BUDGET,
                CheckType.TOOL,
                CheckType.FILE_PATH,
            }
        ),
        ActionType.CALL_LLM: frozenset(
            {
                CheckType.SCHEMA,
                CheckType.AUTHORITY,
                CheckType.IDENTITY,
                CheckType.REVISION,
                CheckType.STATE,
                CheckType.BUDGET,
                CheckType.PROVIDER,
                CheckType.SESSION,
                CheckType.REDACTION,
            }
        ),
        ActionType.FETCH_POLICY: frozenset(
            {
                CheckType.SCHEMA,
                CheckType.AUTHORITY,
                CheckType.REVISION,
                CheckType.STATE,
                CheckType.BUDGET,
                CheckType.TOOL,
                CheckType.REDACTION,
            }
        ),
        ActionType.REQUEST_DYNAMIC_REPRO: frozenset(
            {
                CheckType.SCHEMA,
                CheckType.AUTHORITY,
                CheckType.IDENTITY,
                CheckType.REVISION,
                CheckType.STATE,
                CheckType.BUDGET,
            }
        ),
        ActionType.RUN_SANDBOX: frozenset(
            {
                CheckType.SCHEMA,
                CheckType.AUTHORITY,
                CheckType.IDENTITY,
                CheckType.REVISION,
                CheckType.STATE,
                CheckType.BUDGET,
            }
        ),
        ActionType.SAVE_RESULT: frozenset(
            {
                CheckType.SCHEMA,
                CheckType.AUTHORITY,
                CheckType.IDENTITY,
                CheckType.REVISION,
                CheckType.STATE,
                CheckType.REDACTION,
            }
        ),
        ActionType.CALL_TECHNICAL_GATE: frozenset(
            {
                CheckType.SCHEMA,
                CheckType.AUTHORITY,
                CheckType.IDENTITY,
                CheckType.REVISION,
                CheckType.STATE,
                CheckType.BUDGET,
                CheckType.PROVIDER,
                CheckType.SESSION,
                CheckType.GATE_ORDER,
                CheckType.REDACTION,
            }
        ),
        ActionType.CALL_RULE_SCOPE_GATE: frozenset(
            {
                CheckType.SCHEMA,
                CheckType.AUTHORITY,
                CheckType.IDENTITY,
                CheckType.REVISION,
                CheckType.STATE,
                CheckType.BUDGET,
                CheckType.PROVIDER,
                CheckType.SESSION,
                CheckType.GATE_ORDER,
                CheckType.REDACTION,
            }
        ),
        ActionType.CREATE_REPORT_DRAFT: frozenset(
            {
                CheckType.SCHEMA,
                CheckType.AUTHORITY,
                CheckType.IDENTITY,
                CheckType.REVISION,
                CheckType.STATE,
                CheckType.BUDGET,
                CheckType.PROVIDER,
                CheckType.SESSION,
                CheckType.REPORT_READY,
                CheckType.REDACTION,
            }
        ),
    }
)

_LLM_ACTIONS = frozenset(
    {
        ActionType.CALL_LLM,
        ActionType.CALL_TECHNICAL_GATE,
        ActionType.CALL_RULE_SCOPE_GATE,
        ActionType.CREATE_REPORT_DRAFT,
    }
)


class ActionRequest(ScopedRecord):
    action_id: ActionId
    requested_by: RequesterRole
    requester_identity_ref: BudgetScopeRef
    action_type: ActionType
    work_ref: BudgetScopeRef | None
    expected_state_version: PositiveInt | None
    expected_verification_generation: PositiveInt | None
    generation_restart_reason: GenerationRestartReason | None
    generation_restart_basis_refs: tuple[BudgetScopeRef, ...]
    input_refs: tuple[RecordRef, ...]
    dynamic_request_ref: StoredDataRef | None
    reproduction_plan_ref: StoredDataRef | None
    result_kind: NonEmptyStr | None
    candidate_result_ref: RecordRef | None
    llm_call_spec_ref: StoredDataRef | None
    tool_name: NonEmptyStr | None
    file_paths: tuple[NonEmptyStr, ...]
    provider_profile_ref: BudgetScopeRef | None
    session_mode: SessionMode | None
    sandbox_profile_ref: BudgetScopeRef | None
    resource_profile_ref: StoredDataRef | None
    run_policy_state_ref: StoredDataRef | None
    image_digest: NonEmptyStr | None
    network_targets: tuple[NonEmptyStr, ...]
    resource_limits: Mapping[str, NonNegativeInt] | None
    reason: NonEmptyStr
    requested_at: AwareDatetime

    @field_validator("resource_limits")
    @classmethod
    def freeze_limits(cls, value: Mapping[str, int] | None) -> Mapping[str, int] | None:
        return MappingProxyType(dict(value)) if value is not None else None

    @model_validator(mode="after")
    def action_shape(self) -> Self:
        value: object
        ref: RecordRef | None
        require_record_ref(self.requester_identity_ref)
        if (self.work_ref is not None) != (self.expected_state_version is not None):
            raise ValueError("work_ref and expected_state_version must occur together")
        if self.work_ref:
            require_record_ref(self.work_ref, "work_execution_state")
        restart = self.action_type == ActionType.RESTART_VERIFICATION_GENERATION
        for value in (
            self.expected_verification_generation,
            self.generation_restart_reason,
        ):
            if restart != (value is not None):
                raise ValueError(
                    "Generation fields are required only for generation restart"
                )
        if restart != bool(self.generation_restart_basis_refs):
            raise ValueError("Generation restart requires exact basis refs")
        for ref in self.generation_restart_basis_refs:
            require_record_ref(ref)
        llm = self.action_type in _LLM_ACTIONS
        for value in (
            self.llm_call_spec_ref,
            self.provider_profile_ref,
            self.session_mode,
        ):
            if llm != (value is not None):
                raise ValueError(
                    "Provider/spec/session required only for LLM stage actions"
                )
        if llm and self.work_ref is None:
            raise ValueError("LLM action requires current work")
        if (
            self.action_type == ActionType.CALL_LLM
            and self.requested_by in {RequesterRole.PRO, RequesterRole.CON}
            and self.session_mode != SessionMode.NEW
        ):
            raise ValueError("PRO and CON CALL_LLM require session_mode=NEW")
        if self.llm_call_spec_ref:
            require_record_ref(self.llm_call_spec_ref, "llm_call_spec")
        if self.provider_profile_ref:
            require_record_ref(self.provider_profile_ref, "provider_profile")
        save = self.action_type == ActionType.SAVE_RESULT
        for value in (self.result_kind, self.candidate_result_ref):
            if save != (value is not None):
                raise ValueError(
                    "Only SAVE_RESULT requires result_kind and candidate_result_ref"
                )
        if self.candidate_result_ref:
            require_record_ref(self.candidate_result_ref, self.result_kind)
        if (self.action_type == ActionType.RUN_TOOL) != (self.tool_name is not None):
            raise ValueError("Only RUN_TOOL requires tool_name")
        path_action = self.action_type in {ActionType.READ_CODE, ActionType.RUN_TOOL}
        if path_action != bool(self.file_paths):
            raise ValueError(
                "READ_CODE/RUN_TOOL require file_paths; other actions leave them empty"
            )
        dynamic = self.action_type in {
            ActionType.REQUEST_DYNAMIC_REPRO,
            ActionType.RUN_SANDBOX,
            ActionType.RESTART_VERIFICATION_GENERATION,
        }
        if dynamic != (self.dynamic_request_ref is not None):
            raise ValueError(
                "Dynamic request required for request, sandbox and generation restart"
            )
        if self.dynamic_request_ref:
            require_record_ref(self.dynamic_request_ref, "dynamic_reproduction_request")
        sandbox = self.action_type == ActionType.RUN_SANDBOX
        for value in (
            self.reproduction_plan_ref,
            self.resource_profile_ref,
            self.run_policy_state_ref,
        ):
            if sandbox != (value is not None):
                raise ValueError("RUN_SANDBOX requires plan and profile/audit refs")
        if (sandbox or restart) != (self.sandbox_profile_ref is not None):
            raise ValueError(
                "Sandbox profile required only for sandbox or generation restart"
            )
        if self.sandbox_profile_ref is not None:
            require_record_ref(self.sandbox_profile_ref, "sandbox_profile")
        if restart:
            self._validate_restart_inputs()
        if not sandbox and (
            self.image_digest is not None
            or self.network_targets
            or self.resource_limits is not None
        ):
            raise ValueError("Sandbox execution fields cannot be used by other actions")
        if sandbox:
            for ref, kind in (
                (self.reproduction_plan_ref, "reproduction_plan"),
                (self.sandbox_profile_ref, "sandbox_profile"),
                (self.resource_profile_ref, "dynamic_reproduction_lifecycle_profile"),
                (self.run_policy_state_ref, "run_policy_state"),
            ):
                if ref is not None:
                    require_record_ref(ref, kind)
            for ref in (
                self.dynamic_request_ref,
                self.reproduction_plan_ref,
                self.sandbox_profile_ref,
                self.resource_profile_ref,
            ):
                if ref is None or self.input_refs.count(ref) != 1:
                    raise ValueError(
                        "RUN_SANDBOX must fix each execution input exactly once"
                    )
            requirements = [
                ref
                for ref in self.input_refs
                if ref.data_kind == "environment_requirements"
            ]
            if len(requirements) != 1:
                raise ValueError(
                    "RUN_SANDBOX requires one environment_requirements input"
                )
            require_record_ref(requirements[0])
            if self.run_policy_state_ref in self.input_refs:
                raise ValueError("run_policy_state_ref is audit-only, not input_refs")
        return self

    def _validate_restart_inputs(self) -> None:
        """Validate local shape; current/approved/old provenance needs resolution."""
        ref: RecordRef | None
        if (
            self.requested_by != RequesterRole.VERIFICATION
            or not isinstance(self.meta, RecordMeta)
            or self.meta.hypothesis_id is None
            or self.work_ref is None
        ):
            raise ValueError(
                "Generation restart requires hypothesis-local VERIFICATION "
                "and current work"
            )
        if len(set(self.input_refs)) != len(self.input_refs):
            raise ValueError("Generation restart input_refs must be unique")
        for ref in self.input_refs:
            require_record_ref(ref)
        for ref in (
            self.work_ref,
            self.dynamic_request_ref,
            self.sandbox_profile_ref,
            *self.generation_restart_basis_refs,
        ):
            if ref is None or self.input_refs.count(ref) != 1:
                raise ValueError(
                    "Generation restart must fix work, old request, profile "
                    "and each basis exactly once"
                )
        for kind, count in (
            ("hypothesis_process_state", 1),
            ("verification_assignment", 1),
            ("work_execution_state", 2),
            ("dynamic_reproduction_request", 1),
            ("playbook_policy", 1),
            ("verification_playbook", 1),
        ):
            if sum(ref.data_kind == kind for ref in self.input_refs) != count:
                raise ValueError(
                    f"Generation restart requires {count} exact {kind} inputs"
                )
        profiles = [
            ref for ref in self.input_refs if ref.data_kind == "sandbox_profile"
        ]
        profile_count = (
            2
            if self.generation_restart_reason
            == GenerationRestartReason.SANDBOX_PROFILE_REVISION_CHANGED
            else 1
        )
        if (
            len(profiles) != profile_count
            or len({ref.record_id for ref in profiles}) != profile_count
        ):
            raise ValueError(
                "Request replacement fixes one old profile; "
                "profile change fixes distinct old/new revisions"
            )


class ActionCheck(ContractModel):
    check_type: CheckType
    result: CheckResult
    reason_code: NonEmptyStr
    safe_message: NonEmptyStr


class ActionDecision(ScopedRecord):
    decision_id: DecisionId
    action_ref: BudgetScopeRef
    decision: Decision
    required_checks: tuple[CheckType, ...]
    check_results: tuple[ActionCheck, ...]
    checked_state_version: PositiveInt | None
    checked_config_refs: tuple[BudgetScopeRef, ...]
    valid_until: AwareDatetime | None
    error_ids: tuple[ErrorId, ...]
    use_status: UseStatus
    used_at: AwareDatetime | None
    expired_at: AwareDatetime | None
    expire_reason: NonEmptyStr | None
    outcome_refs: tuple[RecordRef, ...]
    decided_at: AwareDatetime

    @model_validator(mode="after")
    def decision_shape(self) -> Self:
        require_record_ref(self.action_ref, "action_request")
        checks = tuple(check.check_type for check in self.check_results)
        if (
            not self.required_checks
            or len(set(self.required_checks)) != len(self.required_checks)
            or len(set(checks)) != len(checks)
            or set(checks) != set(self.required_checks)
        ):
            raise ValueError(
                "Required checks and results must be nonempty, unique and set-equal"
            )
        failed = any(check.result == CheckResult.FAIL for check in self.check_results)
        if failed != (self.decision == Decision.DENY):
            raise ValueError("Any FAIL requires DENY; all PASS requires ALLOW")
        if self.decision == Decision.DENY:
            if (
                self.use_status != UseStatus.NOT_USED
                or not self.error_ids
                or self.valid_until is not None
            ):
                raise ValueError("DENY requires NOT_USED, errors and no validity")
        else:
            if (
                self.use_status == UseStatus.NOT_USED
                or self.error_ids
                or self.valid_until is None
                or self.valid_until <= self.decided_at
            ):
                raise ValueError("ALLOW requires future validity and no errors")
        if (self.use_status == UseStatus.USED) != (self.used_at is not None):
            raise ValueError("Only USED has used_at")
        expired = self.use_status == UseStatus.EXPIRED
        if expired != (self.expired_at is not None) or expired != (
            self.expire_reason is not None
        ):
            raise ValueError("Only EXPIRED has expiration time and reason")
        if self.use_status != UseStatus.USED and self.outcome_refs:
            raise ValueError("Only USED can have outcomes")
        if self.used_at is not None and (
            self.valid_until is None
            or not self.decided_at <= self.used_at <= self.valid_until
        ):
            raise ValueError("used_at must be within decision validity")
        if self.expired_at is not None and self.expired_at < self.decided_at:
            raise ValueError("expired_at precedes decided_at")
        if (
            self.meta.revision_number == 1
            and self.decision == Decision.ALLOW
            and self.use_status != UseStatus.UNUSED
        ):
            raise ValueError("Initial ALLOW revision must be UNUSED")
        for ref in self.checked_config_refs:
            require_record_ref(ref)
        return self


def validate_decision_for_action(
    decision: ActionDecision, action_type: ActionType
) -> None:
    if frozenset(decision.required_checks) != REQUIRED_CHECKS[action_type]:
        raise ValueError("Required-check set differs from action type")


def validate_generation_restart_context(
    action: ActionRequest,
    *,
    current_request_ref: StoredDataRef,
    current_profile_ref: BudgetScopeRef,
    approved_profile_ref: BudgetScopeRef | None = None,
) -> None:
    """Compare against trusted current/approved refs supplied after resolution."""
    if action.action_type != ActionType.RESTART_VERIFICATION_GENERATION:
        raise ValueError("Expected a generation restart action")
    require_record_ref(current_request_ref, "dynamic_reproduction_request")
    require_record_ref(current_profile_ref, "sandbox_profile")
    if (
        action.dynamic_request_ref != current_request_ref
        or action.input_refs.count(current_profile_ref) != 1
    ):
        raise ValueError(
            "Generation restart must retain the old current request/profile"
        )
    if (
        action.generation_restart_reason
        == GenerationRestartReason.DYNAMIC_REQUEST_REPLACEMENT_REQUIRED
    ):
        if (
            action.sandbox_profile_ref != current_profile_ref
            or approved_profile_ref is not None
        ):
            raise ValueError(
                "Request replacement must retain the current sandbox profile"
            )
    else:
        if approved_profile_ref is None:
            raise ValueError("Profile change requires the approved new exact profile")
        require_record_ref(approved_profile_ref, "sandbox_profile")
        if (
            approved_profile_ref == current_profile_ref
            or action.sandbox_profile_ref != approved_profile_ref
        ):
            raise ValueError(
                "Profile change must select the approved new sandbox profile"
            )


def validate_decision_revision(
    previous: ActionDecision, current: ActionDecision
) -> None:
    validate_revision(previous.meta, current.meta)
    immutable = (
        "decision_id",
        "action_ref",
        "decision",
        "required_checks",
        "check_results",
        "checked_state_version",
        "checked_config_refs",
        "valid_until",
        "decided_at",
        "error_ids",
    )
    if any(getattr(previous, name) != getattr(current, name) for name in immutable):
        raise ValueError("Decision revision changed immutable decision fields")
    allowed = {
        UseStatus.UNUSED: {UseStatus.USED, UseStatus.EXPIRED},
        UseStatus.USED: {UseStatus.USED},
    }
    if current.use_status not in allowed.get(previous.use_status, set()):
        raise ValueError("Decision use state cannot be reopened")
    if (
        previous.use_status == UseStatus.UNUSED
        and current.use_status == UseStatus.USED
        and current.outcome_refs
    ):
        raise ValueError("First USED claim must have empty outcome_refs")
    if current.outcome_refs[: len(previous.outcome_refs)] != previous.outcome_refs:
        raise ValueError("Decision outcomes must be append-only")
    if previous.use_status == UseStatus.USED and current.used_at != previous.used_at:
        raise ValueError("Claim timestamp is immutable")
