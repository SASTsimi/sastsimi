"""Evaluation provenance, safe usage and terminal run summaries (§08.9.1/11)."""

from collections.abc import Mapping
from types import MappingProxyType
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    AwareDatetime,
    JsonValue,
    PlainSerializer,
    model_validator,
)

from ._domain import DomainRecord, exact, exact_set, unique, walk
from .base import ContractModel, NonEmptyStr, NonNegativeInt
from .dynamic import DynamicReproductionResult
from .ids import CommitId, ErrorId, ProgramId, WorkspaceId
from .policy import RunPolicyState
from .records import RunMeta
from .refs import (
    BudgetScopeRef,
    PolicyCacheRef,
    RunStoredDataRef,
    StoredDataRef,
    validate_ref_scope,
)
from .reporting import FindingIndexState
from .static import AnalysisError, CodeWorkspace, DataGap


def freeze_counts(value: Mapping[str, int]) -> Mapping[str, int]:
    return MappingProxyType(dict(value))


def serialize_counts(value: Mapping[str, int]) -> dict[str, int]:
    return dict(value)


FrozenCounts = Annotated[
    Mapping[str, NonNegativeInt],
    AfterValidator(freeze_counts),
    PlainSerializer(serialize_counts),
]


class UsageMeasurement(ContractModel):
    token_source: Literal["PROVIDER_REPORTED", "ADAPTER_REPORTED", "UNAVAILABLE"]
    input_tokens: NonNegativeInt | None
    output_tokens: NonNegativeInt | None
    total_tokens: NonNegativeInt | None
    token_unavailable_reason: NonEmptyStr | None
    provider_units: dict[str, JsonValue]
    cost_source: Literal[
        "PROVIDER_REPORTED",
        "PRICING_REVISION_CALCULATED",
        "RESERVED_MAXIMUM",
        "UNAVAILABLE",
    ]
    cost_minor_units: NonNegativeInt | None
    currency: NonEmptyStr | None
    pricing_revision_ref: BudgetScopeRef | None
    cost_unavailable_reason: NonEmptyStr | None

    @model_validator(mode="after")
    def measured(self) -> Self:
        tokens = (self.input_tokens, self.output_tokens, self.total_tokens)
        if self.token_source == "UNAVAILABLE":
            if (
                any(value is not None for value in tokens)
                or self.token_unavailable_reason is None
            ):
                raise ValueError("TOKEN_USAGE_UNAVAILABLE")
        elif (
            self.input_tokens is None
            or self.output_tokens is None
            or self.total_tokens != self.input_tokens + self.output_tokens
            or self.token_unavailable_reason is not None
        ):
            raise ValueError("TOKEN_USAGE_MISMATCH")
        if self.cost_source == "UNAVAILABLE":
            if (
                any(
                    value is not None
                    for value in (
                        self.cost_minor_units,
                        self.currency,
                        self.pricing_revision_ref,
                    )
                )
                or self.cost_unavailable_reason is None
            ):
                raise ValueError("COST_USAGE_UNAVAILABLE")
        elif (
            self.cost_minor_units is None
            or self.currency is None
            or self.pricing_revision_ref is None
            or self.cost_unavailable_reason is not None
        ):
            raise ValueError("COST_PROVENANCE_REQUIRED")
        return self


class ResourceUsageSummary(ContractModel):
    elapsed_ms: NonNegativeInt
    work_count: NonNegativeInt
    attempt_count: NonNegativeInt
    retry_count: NonNegativeInt
    llm_call_count: NonNegativeInt
    dynamic_attempt_count: NonNegativeInt
    cost_minor_units: NonNegativeInt | None
    currency: NonEmptyStr | None
    pricing_revision_refs: tuple[BudgetScopeRef, ...]
    usage_measurement_refs: tuple[BudgetScopeRef, ...]
    usage_complete: bool
    unavailable_reasons: tuple[NonEmptyStr, ...]

    @model_validator(mode="after")
    def summary_shape(self) -> Self:
        if (self.cost_minor_units is None) != (self.currency is None):
            raise ValueError("COST_CURRENCY_MISMATCH")
        if self.usage_complete and self.unavailable_reasons:
            raise ValueError("USAGE_COMPLETENESS_MISMATCH")
        if not self.usage_complete and not self.unavailable_reasons:
            raise ValueError("USAGE_UNAVAILABLE_REASON_REQUIRED")
        return self


class EvaluationRunConfig(DomainRecord):
    KIND = "evaluation_run_config"
    HYPOTHESIS = False
    ATTEMPT = False
    evaluation_config_id: NonEmptyStr
    comparison_group_id: NonEmptyStr
    corpus_refs: tuple[StoredDataRef, ...]
    ground_truth_refs: tuple[StoredDataRef, ...]
    grader_refs: tuple[StoredDataRef, ...]
    provider_profile_ref: StoredDataRef
    model: NonEmptyStr
    session_policy: Literal["NEW", "RESUME", "AUTO"]
    prompt_registry_entry_ref: StoredDataRef
    execution_budget_profile_ref: RunStoredDataRef
    output_schema_ref: StoredDataRef


class EvaluationMetric(ContractModel):
    metric_key: NonEmptyStr
    value: NonEmptyStr
    unit: NonEmptyStr
    sample_count: NonNegativeInt
    evidence_refs: tuple[StoredDataRef, ...]


class EvaluationRunResult(DomainRecord):
    KIND = "evaluation_run_result"
    HYPOTHESIS = False
    ATTEMPT = False
    evaluation_run_id: NonEmptyStr
    config_ref: StoredDataRef
    analysis_result_refs: tuple[RunStoredDataRef, ...]
    grader_result_refs: tuple[StoredDataRef, ...]
    metrics: tuple[EvaluationMetric, ...]
    usage: ResourceUsageSummary
    status: Literal["SUCCEEDED", "PARTIAL", "FAILED"]
    error_ids: tuple[ErrorId, ...]
    started_at: AwareDatetime
    finished_at: AwareDatetime

    @model_validator(mode="after")
    def evaluation_shape(self) -> Self:
        unique(metric.metric_key for metric in self.metrics)
        if self.finished_at < self.started_at or (
            self.status == "FAILED" and not self.error_ids
        ):
            raise ValueError("EVALUATION_RESULT_MISMATCH")
        return self


class EvaluationRecommendation(DomainRecord):
    KIND = "evaluation_recommendation"
    HYPOTHESIS = False
    ATTEMPT = False
    recommendation_id: NonEmptyStr
    evaluation_result_ref: StoredDataRef
    target_provider_profile_ref: StoredDataRef
    target_model: NonEmptyStr
    target_session_policy: Literal["NEW", "RESUME", "AUTO"]
    target_prompt_registry_entry_ref: StoredDataRef
    decision: Literal["ACCEPT_FOR_PRODUCTION", "REJECT", "NEEDS_MORE_EVIDENCE"]
    rationale: NonEmptyStr
    decided_by: Literal["R8_EVALUATION_RUNTIME"]
    decided_at: AwareDatetime


class AnalysisRunResult(ContractModel):
    meta: RunMeta
    purpose: Literal["PRODUCTION", "EVALUATION"]
    repository_url: NonEmptyStr
    program_id: ProgramId
    workspace_id: WorkspaceId | None
    commit_id: CommitId | None
    workspace_ref: RunStoredDataRef | None
    status: Literal["COMPLETE", "PARTIAL", "FAILED", "CANCELLED"]
    hypothesis_counts: FrozenCounts
    hypothesis_duplicate_review_refs: tuple[StoredDataRef, ...]
    failed_hypothesis_count: NonNegativeInt
    verdict_counts: FrozenCounts
    gate_counts: FrozenCounts
    finding_refs: tuple[StoredDataRef, ...]
    verification_refs: tuple[StoredDataRef, ...]
    cwe_label_refs: tuple[StoredDataRef, ...]
    technical_review_refs: tuple[StoredDataRef, ...]
    rule_scope_review_refs: tuple[StoredDataRef, ...]
    run_policy_state_ref: StoredDataRef | None
    policy_cache_refs: tuple[PolicyCacheRef, ...]
    policy_collection_result_refs: tuple[StoredDataRef, ...]
    policy_parser_result_refs: tuple[StoredDataRef, ...]
    policy_record_refs: tuple[StoredDataRef, ...]
    dynamic_request_refs: tuple[StoredDataRef, ...]
    dynamic_result_refs: tuple[StoredDataRef, ...]
    environment_recipe_refs: tuple[StoredDataRef, ...]
    sandbox_environment_refs: tuple[StoredDataRef, ...]
    agent_log_refs: tuple[StoredDataRef, ...]
    dynamic_reproduction_conclusion_refs: tuple[StoredDataRef, ...]
    sandbox_policy_decision_refs: tuple[StoredDataRef, ...]
    cleanup_result_refs: tuple[StoredDataRef, ...]
    primitive_and_chaining_refs: tuple[StoredDataRef, ...]
    poc_candidate_refs: tuple[StoredDataRef, ...]
    poc_refs: tuple[StoredDataRef, ...]
    report_draft_refs: tuple[StoredDataRef, ...]
    llm_invocation_log_refs: tuple[StoredDataRef, ...]
    action_decision_refs: tuple[BudgetScopeRef, ...]
    work_state_refs: tuple[BudgetScopeRef, ...]
    work_attempt_refs: tuple[BudgetScopeRef, ...]
    transition_commit_refs: tuple[BudgetScopeRef, ...]
    eval_config_refs: tuple[BudgetScopeRef, ...]
    stop_reasons: tuple[NonEmptyStr, ...]
    errors: tuple[AnalysisError, ...]
    gaps: tuple[DataGap, ...]
    resources: ResourceUsageSummary
    started_at: AwareDatetime
    finished_at: AwareDatetime
    elapsed_ms: NonNegativeInt
    debug_trace_ref: RunStoredDataRef

    @model_validator(mode="after")
    def terminal_shape(self) -> Self:
        if (
            type(self.meta) is not RunMeta
            or self.meta.record_type != "analysis_run_result"
        ):
            raise ValueError("METADATA_SCOPE_MISMATCH")
        if self.failed_hypothesis_count and self.status != "PARTIAL":
            raise ValueError("FAILED_HYPOTHESIS_RUN_STATUS")
        if (self.purpose == "EVALUATION") != bool(self.eval_config_refs):
            raise ValueError("EVALUATION_CONFIG_REQUIRED")
        if self.finished_at < self.started_at:
            raise ValueError("INVALID_TIME_RANGE")
        for name in type(self).model_fields:
            if name.endswith("_refs"):
                unique(getattr(self, name))
        for item in walk(self):
            if isinstance(item, RunStoredDataRef):
                validate_ref_scope(item, self.meta)
            elif isinstance(item, StoredDataRef):
                if (item.workspace_id, item.commit_id) != (
                    self.workspace_id,
                    self.commit_id,
                ):
                    # Historical policy artifacts require the explicit cache path.
                    if (
                        not self.policy_cache_refs
                        or item not in self.policy_parser_result_refs
                    ):
                        raise ValueError("WORKSPACE_MISMATCH")
            elif (
                isinstance(item, PolicyCacheRef) and item.program_id != self.program_id
            ):
                raise ValueError("POLICY_PROGRAM_MISMATCH")
        if self.run_policy_state_ref is None and (
            self.policy_cache_refs
            or self.policy_record_refs
            or self.policy_collection_result_refs
            or self.policy_parser_result_refs
        ):
            raise ValueError("RUN_POLICY_STATE_REQUIRED")
        return self


def validate_evaluation_comparison(
    left: EvaluationRunConfig,
    right: EvaluationRunConfig,
    *,
    varying_axes: frozenset[str],
) -> None:
    allowed_axes = {
        "provider_profile_ref",
        "model",
        "session_policy",
        "prompt_registry_entry_ref",
    }
    if (
        not varying_axes <= allowed_axes
        or left.comparison_group_id != right.comparison_group_id
    ):
        raise ValueError("EVALUATION_CONFIG_MISMATCH")
    for name in ("corpus_refs", "ground_truth_refs", "grader_refs"):
        try:
            exact_set(getattr(left, name), getattr(right, name))
        except ValueError as error:
            raise ValueError("EVALUATION_CONFIG_MISMATCH") from error
    for name in (
        "output_schema_ref",
        "execution_budget_profile_ref",
        *sorted(allowed_axes - varying_axes),
    ):
        if getattr(left, name) != getattr(right, name):
            raise ValueError("EVALUATION_CONFIG_MISMATCH")


def validate_analysis_current(
    result: AnalysisRunResult,
    workspace: CodeWorkspace | None,
    policy: RunPolicyState | None,
    finding_indexes: tuple[FindingIndexState, ...],
    dynamics: tuple[DynamicReproductionResult, ...],
    *,
    pinned_eval_refs: tuple[BudgetScopeRef, ...],
    expected_failed_hypothesis_count: int,
) -> None:
    from .canonical_json import content_hash
    from .refs import validate_exact_ref

    if result.failed_hypothesis_count != expected_failed_hypothesis_count:
        raise ValueError("FAILED_HYPOTHESIS_COUNT_MISMATCH")
    exact_set(result.eval_config_refs, pinned_eval_refs)
    if (result.workspace_ref is None) != (workspace is None):
        raise ValueError("WORKSPACE_REFERENCE_REQUIRED")
    if workspace is not None and result.workspace_ref is not None:
        validate_exact_ref(
            result.workspace_ref,
            workspace.meta,
            content_hash(workspace),
            analysis_id=result.meta.analysis_id,
        )
        if (result.workspace_id, result.commit_id) != (
            workspace.workspace_id,
            workspace.commit_id,
        ):
            raise ValueError("WORKSPACE_MISMATCH")
    if (result.run_policy_state_ref is None) != (policy is None):
        raise ValueError("RUN_POLICY_STATE_REQUIRED")
    if policy is not None and result.run_policy_state_ref is not None:
        exact(result.run_policy_state_ref, policy, result.meta)
        if policy.program_id != result.program_id:
            raise ValueError("POLICY_PROGRAM_MISMATCH")
        exact_set(
            result.policy_cache_refs,
            () if policy.policy_cache_ref is None else (policy.policy_cache_ref,),
        )
        if (
            policy.collection_result_ref is not None
            and policy.collection_result_ref not in result.policy_collection_result_refs
        ):
            raise ValueError("POLICY_COLLECTION_CLOSURE_MISMATCH")
    exact_set(
        result.finding_refs,
        (index.finding_ref for index in finding_indexes if index.status == "CURRENT"),
    )
    if len(result.dynamic_result_refs) != len(dynamics):
        raise ValueError("DYNAMIC_RESULT_CLOSURE_MISMATCH")
    for ref, dynamic in zip(result.dynamic_result_refs, dynamics, strict=True):
        exact(ref, dynamic, result.meta)
    exact_set(
        result.dynamic_reproduction_conclusion_refs,
        (
            dynamic.agent_conclusion_ref
            for dynamic in dynamics
            if dynamic.agent_conclusion_ref is not None
        ),
    )
