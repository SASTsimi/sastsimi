from enum import StrEnum
from types import MappingProxyType
from typing import Literal, Self

from pydantic import AwareDatetime, model_validator

from .base import ContractModel, NonEmptyStr, NonNegativeInt, PositiveInt
from .ids import LedgerEntryId, ReservationId
from .records import RecordMeta, RunMeta, validate_revision
from .refs import BudgetScopeRef, RunStoredDataRef, StoredDataRef, require_record_ref
from .work import ScopedRecord, WorkType


class Purpose(StrEnum):
    PRODUCTION = "PRODUCTION"
    EVALUATION = "EVALUATION"


class ProfileStatus(StrEnum):
    DRAFT = "DRAFT"
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"


class OperationKind(StrEnum):
    WORKSPACE_PREP = "WORKSPACE_PREP"
    REPOSITORY_PROFILE = "REPOSITORY_PROFILE"
    STATIC_TOOL = "STATIC_TOOL"
    STATIC_NORMALIZE = "STATIC_NORMALIZE"
    POLICY_COLLECT = "POLICY_COLLECT"
    POLICY_PARSE = "POLICY_PARSE"
    HYPOTHESIS_GENERATE = "HYPOTHESIS_GENERATE"
    CONTEXT_RETRIEVAL = "CONTEXT_RETRIEVAL"
    PRO_EVIDENCE = "PRO_EVIDENCE"
    CON_EVIDENCE = "CON_EVIDENCE"
    VERIFICATION_SYNTHESIS = "VERIFICATION_SYNTHESIS"
    PRIMITIVE_UPDATE = "PRIMITIVE_UPDATE"
    CHAINING = "CHAINING"
    DYNAMIC_REPRO = "DYNAMIC_REPRO"
    CWE_LABELING = "CWE_LABELING"
    TECHNICAL_GATE = "TECHNICAL_GATE"
    RULE_SCOPE_GATE = "RULE_SCOPE_GATE"
    FINDING_NORMALIZE = "FINDING_NORMALIZE"
    REPORTER = "REPORTER"


class BudgetAgentRole(StrEnum):
    HYPOTHESIS = "HYPOTHESIS"
    PRO = "PRO"
    CON = "CON"
    VERIFICATION = "VERIFICATION"
    CWE_LABELING = "CWE_LABELING"
    CHAINING = "CHAINING"
    TECHNICAL_GATE = "TECHNICAL_GATE"
    RULE_SCOPE_GATE = "RULE_SCOPE_GATE"
    REPORTER = "REPORTER"
    POLICY_PARSER = "POLICY_PARSER"
    DYNAMIC_REPRODUCTION = "DYNAMIC_REPRODUCTION"
    REPOSITORY_LOADER = "REPOSITORY_LOADER"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    POLICY_COLLECTOR = "POLICY_COLLECTOR"


WORK_OPERATIONS = MappingProxyType(
    {
        WorkType.WORKSPACE_PREP: (
            OperationKind.WORKSPACE_PREP,
            BudgetAgentRole.REPOSITORY_LOADER,
        ),
        WorkType.REPOSITORY_PROFILE: (
            OperationKind.REPOSITORY_PROFILE,
            BudgetAgentRole.STATIC_ANALYSIS,
        ),
        WorkType.STATIC_TOOL: (
            OperationKind.STATIC_TOOL,
            BudgetAgentRole.STATIC_ANALYSIS,
        ),
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
        WorkType.CWE_LABEL: (
            OperationKind.CWE_LABELING,
            BudgetAgentRole.CWE_LABELING,
        ),
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
)


class ReservationStatus(StrEnum):
    RESERVED = "RESERVED"
    COMMITTED = "COMMITTED"
    RELEASED = "RELEASED"


class CodeBudgetProfile(ScopedRecord):
    meta: RecordMeta

    @model_validator(mode="after")
    def analysis_profile(self) -> Self:
        if self.meta.hypothesis_id is not None or self.meta.attempt_id is not None:
            raise ValueError(
                "Budget profile is analysis-wide: hypothesis/attempt must be null"
            )
        return self


class ApprovedProfile(ScopedRecord):
    approval_ref: BudgetScopeRef | None
    approved_by: NonEmptyStr | None
    approved_at: AwareDatetime | None
    status: ProfileStatus

    @model_validator(mode="after")
    def approval_shape(self) -> Self:
        if self.status == ProfileStatus.ACTIVE and any(
            value is None
            for value in (self.approval_ref, self.approved_by, self.approved_at)
        ):
            raise ValueError(
                "ACTIVE requires exact approval reference, approver and time"
            )
        if self.status == ProfileStatus.DRAFT and (
            self.approval_ref is not None or self.approved_at is not None
        ):
            raise ValueError("DRAFT approval_ref/approved_at must be null")
        if self.approval_ref:
            require_record_ref(self.approval_ref)
        return self


class ExecutionBudgetProfile(ApprovedProfile):
    meta: RunMeta
    profile_key: NonEmptyStr
    purpose: Purpose
    max_analysis_elapsed_ms: NonNegativeInt
    max_total_cost_minor_units: NonNegativeInt
    currency: NonEmptyStr
    pricing_revision_ref: BudgetScopeRef
    max_total_work: NonNegativeInt
    max_total_llm_calls: NonNegativeInt
    max_total_retries: NonNegativeInt
    max_parallel_work: NonNegativeInt

    @model_validator(mode="after")
    def run_profile(self) -> Self:
        if isinstance(self.meta, RecordMeta):
            raise ValueError("ExecutionBudgetProfile requires RunMeta")
        require_record_ref(self.pricing_revision_ref)
        return self


class WorkBudgetLimit(ContractModel):
    limit_key: NonEmptyStr
    work_type: WorkType
    operation_kind: OperationKind
    agent_role: BudgetAgentRole | None
    timeout_ms: NonNegativeInt | None
    max_attempts: NonNegativeInt | None
    max_calls_per_work: NonNegativeInt | None
    max_items_per_work: NonNegativeInt | None


class WorkBudgetProfile(CodeBudgetProfile):
    profile_key: NonEmptyStr
    purpose: Purpose
    limits: tuple[WorkBudgetLimit, ...]
    unlisted_operation: Literal["DENY"]
    status: ProfileStatus

    @model_validator(mode="after")
    def unique_limits(self) -> Self:
        keys = [limit.limit_key for limit in self.limits]
        scopes = [
            (limit.work_type, limit.operation_kind, limit.agent_role)
            for limit in self.limits
        ]
        if len(set(keys)) != len(keys) or len(set(scopes)) != len(scopes):
            raise ValueError("Duplicate limit_key or work/operation/role")
        return self


class VerificationBudgetProfile(CodeBudgetProfile):
    profile_key: NonEmptyStr
    max_verification_elapsed_ms: NonNegativeInt
    max_work_per_verification: NonNegativeInt
    max_llm_calls_per_verification: NonNegativeInt
    max_retries_per_work: NonNegativeInt
    max_parallel_evidence_calls: NonNegativeInt
    status: ProfileStatus


class DynamicReproductionLifecycleProfile(CodeBudgetProfile):
    profile_key: NonEmptyStr
    preflight_budget_ref: StoredDataRef
    preflight_budget_source: Literal["WORK_REMAINING_TIME"]
    max_new_attempts: NonNegativeInt
    status: ProfileStatus
    created_at: AwareDatetime

    @model_validator(mode="after")
    def preflight_exact(self) -> Self:
        require_record_ref(self.preflight_budget_ref)
        return self


class BudgetProfileBinding(ApprovedProfile, CodeBudgetProfile):
    meta: RecordMeta
    binding_key: NonEmptyStr
    purpose: Purpose
    execution_budget_profile_ref: RunStoredDataRef
    work_budget_profile_ref: StoredDataRef
    verification_budget_profile_ref: StoredDataRef
    dynamic_lifecycle_profile_ref: StoredDataRef

    @model_validator(mode="after")
    def binding_shape(self) -> Self:
        for ref, kind in (
            (self.execution_budget_profile_ref, "execution_budget_profile"),
            (self.work_budget_profile_ref, "work_budget_profile"),
            (self.verification_budget_profile_ref, "verification_budget_profile"),
            (
                self.dynamic_lifecycle_profile_ref,
                "dynamic_reproduction_lifecycle_profile",
            ),
        ):
            require_record_ref(ref, kind)
        return self


class BudgetUnits(ContractModel):
    elapsed_ms: NonNegativeInt
    work_count: NonNegativeInt
    llm_call_count: NonNegativeInt
    retry_count: NonNegativeInt
    cost_minor_units: NonNegativeInt
    currency: NonEmptyStr


def validate_budget_scope(
    ref: BudgetScopeRef, meta: RunMeta | RecordMeta | None = None
) -> None:
    expected = (
        "execution_budget_profile"
        if isinstance(ref, RunStoredDataRef)
        else "budget_profile_binding"
    )
    require_record_ref(ref, expected)
    if meta is not None and isinstance(meta, RecordMeta) != isinstance(
        ref, StoredDataRef
    ):
        raise ValueError(
            "Budget scope must follow run bootstrap versus workspace binding"
        )


class BudgetReservation(ScopedRecord):
    reservation_id: ReservationId
    budget_binding_ref: BudgetScopeRef
    action_ref: BudgetScopeRef
    work_ref: BudgetScopeRef
    requested_units: BudgetUnits
    status: ReservationStatus
    ledger_entry_ref: BudgetScopeRef | None
    reserved_at: AwareDatetime
    finalized_at: AwareDatetime | None

    @model_validator(mode="after")
    def reservation_shape(self) -> Self:
        validate_budget_scope(self.budget_binding_ref, self.meta)
        require_record_ref(self.action_ref, "action_request")
        require_record_ref(self.work_ref, "work_execution_state")
        if (self.status == ReservationStatus.RESERVED) != (self.finalized_at is None):
            raise ValueError("Only RESERVED has finalized_at=null")
        if (self.status == ReservationStatus.COMMITTED) != (
            self.ledger_entry_ref is not None
        ):
            raise ValueError("Only COMMITTED requires ledger_entry_ref")
        if self.ledger_entry_ref:
            require_record_ref(self.ledger_entry_ref, "budget_ledger_entry")
        if self.finalized_at is not None and self.finalized_at < self.reserved_at:
            raise ValueError("finalized_at precedes reserved_at")
        return self


class BudgetLedgerEntry(ScopedRecord):
    ledger_entry_id: LedgerEntryId
    reservation_ref: BudgetScopeRef
    budget_binding_ref: BudgetScopeRef
    action_ref: BudgetScopeRef
    work_ref: BudgetScopeRef
    actual_units: BudgetUnits
    usage_refs: tuple[BudgetScopeRef, ...]
    sequence: PositiveInt
    committed_at: AwareDatetime

    @model_validator(mode="after")
    def ledger_shape(self) -> Self:
        validate_budget_scope(self.budget_binding_ref, self.meta)
        require_record_ref(self.reservation_ref, "budget_reservation")
        require_record_ref(self.action_ref, "action_request")
        require_record_ref(self.work_ref, "work_execution_state")
        return self


class BudgetRemaining(ContractModel):
    budget_binding_ref: BudgetScopeRef
    as_of_sequence: NonNegativeInt
    available_units: BudgetUnits
    active_reservation_count: NonNegativeInt

    @model_validator(mode="after")
    def remaining_scope(self) -> Self:
        validate_budget_scope(self.budget_binding_ref)
        return self


def select_work_limit(
    profile: WorkBudgetProfile,
    work_type: WorkType,
    operation_kind: OperationKind,
    agent_role: BudgetAgentRole | None,
) -> WorkBudgetLimit:
    if profile.status != ProfileStatus.ACTIVE:
        raise ValueError("Budget profile is not ACTIVE")
    for limit in profile.limits:
        if (limit.work_type, limit.operation_kind, limit.agent_role) == (
            work_type,
            operation_kind,
            agent_role,
        ):
            return limit
    raise ValueError("Unlisted operation: DENY")


def validate_reservation_revision(
    previous: BudgetReservation, current: BudgetReservation
) -> None:
    validate_revision(previous.meta, current.meta)
    if (
        previous.status != ReservationStatus.RESERVED
        or current.status == ReservationStatus.RESERVED
    ):
        raise ValueError("Reservation may only finalize once")
    immutable = (
        "reservation_id",
        "budget_binding_ref",
        "action_ref",
        "work_ref",
        "requested_units",
        "reserved_at",
    )
    if any(getattr(previous, name) != getattr(current, name) for name in immutable):
        raise ValueError(
            "Reservation identity, scope and requested units are immutable"
        )
