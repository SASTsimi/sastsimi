"""Evaluation provenance, safe usage and terminal run summaries (§08.9.1/11)."""

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Annotated, Literal, Self, cast

from pydantic import (
    AfterValidator,
    AwareDatetime,
    JsonValue,
    PlainSerializer,
    model_validator,
)

from ._domain import DomainRecord, exact, exact_set, unique, walk
from .base import ContractModel, NonEmptyStr, NonNegativeInt
from .chaining import Primitive, PrimitiveIndexState
from .closure import validate_committed_output
from .dynamic import DynamicReproductionResult
from .gates import CWELabel
from .ids import CommitId, ErrorId, HypothesisId, ProgramId, WorkspaceId
from .policy import PolicyCacheRecord, PolicyCollectionResult, RunPolicyState
from .records import PolicyCacheMeta, RecordMeta, RunMeta
from .refs import (
    BudgetScopeRef,
    PolicyCacheRef,
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
    require_record_ref,
    validate_ref_scope,
)
from .reporting import Finding, FindingIndexState, ReportDraft
from .static import AnalysisError, CodeWorkspace, DataGap
from .verification import VerificationResult
from .work import TransitionCommit, WorkAttempt, WorkExecutionState, WorkType

RUN_INVENTORY_KINDS: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "hypothesis_duplicate_review_refs": frozenset({"hypothesis_duplicate_review"}),
        "finding_refs": frozenset({"finding"}),
        "verification_refs": frozenset({"verification_result"}),
        "cwe_label_refs": frozenset({"cwe_label"}),
        "technical_review_refs": frozenset({"technical_evidence_review"}),
        "rule_scope_review_refs": frozenset({"rule_scope_impact_review"}),
        "policy_cache_refs": frozenset({"policy_cache_record"}),
        "policy_collection_result_refs": frozenset({"policy_collection_result"}),
        "policy_parser_result_refs": frozenset({"policy_parser_result"}),
        "policy_record_refs": frozenset({"program_policy_record"}),
        "dynamic_request_refs": frozenset({"dynamic_reproduction_request"}),
        "dynamic_result_refs": frozenset({"dynamic_reproduction_result"}),
        "environment_recipe_refs": frozenset({"environment_recipe"}),
        "sandbox_environment_refs": frozenset({"sandbox_environment"}),
        "agent_log_refs": frozenset({"agent_log"}),
        "dynamic_reproduction_conclusion_refs": frozenset(
            {"dynamic_reproduction_conclusion"}
        ),
        "sandbox_policy_decision_refs": frozenset({"sandbox_policy_decision"}),
        "cleanup_result_refs": frozenset({"cleanup_result"}),
        "primitive_and_chaining_refs": frozenset(
            {
                "primitive_admission_decision",
                "primitive_index_state",
                "primitive",
                "chaining_result",
            }
        ),
        "poc_candidate_refs": frozenset({"poc_candidate"}),
        "poc_refs": frozenset({"poc_bundle"}),
        "report_draft_refs": frozenset({"report_draft"}),
        "llm_invocation_log_refs": frozenset({"llm_invocation_log"}),
        "action_decision_refs": frozenset({"action_decision"}),
        "work_state_refs": frozenset({"work_execution_state"}),
        "work_attempt_refs": frozenset({"work_attempt"}),
        "transition_commit_refs": frozenset({"transition_commit"}),
    }
)


@dataclass(frozen=True)
class ResolvedAnalysisInventory:
    """Trusted finalization snapshot; no latest-pointer lookup or inferred records."""

    records: Mapping[RecordRef, ContractModel]
    expected_refs: Mapping[str, tuple[RecordRef, ...]]
    current_verification_refs: Mapping[HypothesisId, StoredDataRef]
    verification_generations: Mapping[HypothesisId, int]

    def __post_init__(self) -> None:
        for field in (
            "records",
            "expected_refs",
            "current_verification_refs",
            "verification_generations",
        ):
            object.__setattr__(
                self, field, MappingProxyType(dict(getattr(self, field)))
            )


def freeze_counts(value: Mapping[str, int]) -> Mapping[str, int]:
    return MappingProxyType(dict(value))


def serialize_counts(value: Mapping[str, int]) -> dict[str, int]:
    return dict(value)


FrozenCounts = Annotated[
    Mapping[str, NonNegativeInt],
    AfterValidator(freeze_counts),
    PlainSerializer(serialize_counts),
]


def freeze_json(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({key: freeze_json(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(freeze_json(item) for item in value)
    return value


def freeze_provider_units(value: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
    return cast(Mapping[str, JsonValue], freeze_json(value))


def thaw_json(value: object) -> JsonValue:
    if isinstance(value, Mapping):
        return {str(key): thaw_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [thaw_json(item) for item in value]
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    raise ValueError("INVALID_PROVIDER_UNIT")


FrozenProviderUnits = Annotated[
    Mapping[str, JsonValue],
    AfterValidator(freeze_provider_units),
    PlainSerializer(thaw_json),
]


class UsageMeasurement(ContractModel):
    token_source: Literal["PROVIDER_REPORTED", "ADAPTER_REPORTED", "UNAVAILABLE"]
    input_tokens: NonNegativeInt | None
    output_tokens: NonNegativeInt | None
    total_tokens: NonNegativeInt | None
    token_unavailable_reason: NonEmptyStr | None
    provider_units: FrozenProviderUnits
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
        for field, kinds in RUN_INVENTORY_KINDS.items():
            for reference in getattr(self, field):
                if reference.data_kind not in kinds or reference.record_id is None:
                    raise ValueError("INVENTORY_KIND_MISMATCH")
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
    inventory: ResolvedAnalysisInventory,
) -> None:
    from .canonical_json import content_hash
    from .refs import validate_exact_ref

    validate_run_inventory(result, inventory)

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


def validate_run_inventory(
    result: AnalysisRunResult, inventory: ResolvedAnalysisInventory
) -> None:
    from .canonical_json import content_hash
    from .refs import validate_exact_ref

    fields = {*RUN_INVENTORY_KINDS, "eval_config_refs"}
    if set(inventory.expected_refs) != fields:
        raise ValueError("INVENTORY_FIELDS_MISMATCH")
    caches = [
        inventory.records.get(reference) for reference in result.policy_cache_refs
    ]
    cache_parser_refs = {
        ref
        for cache in caches
        if isinstance(cache, PolicyCacheRecord)
        for ref in cache.parser_result_refs
    }
    for field in fields:
        exact_set(getattr(result, field), inventory.expected_refs[field])
        for reference in getattr(result, field):
            target = inventory.records.get(reference)
            if target is None:
                raise ValueError("INVENTORY_RECORD_UNRESOLVED")
            metadata_field = "meta"
            metadata = getattr(target, metadata_field, None)
            if not isinstance(metadata, (RunMeta, RecordMeta, PolicyCacheMeta)):
                raise ValueError("INVENTORY_RECORD_METADATA_REQUIRED")
            consumer = result.meta.analysis_id
            if (
                field == "policy_parser_result_refs"
                and reference in cache_parser_refs
                and isinstance(metadata, RunMeta)
            ):
                consumer = metadata.analysis_id
            require_record_ref(reference)
            validate_exact_ref(
                reference, metadata, content_hash(target), analysis_id=consumer
            )
    current: dict[HypothesisId, VerificationResult] = {}
    for hypothesis_id, reference in inventory.current_verification_refs.items():
        target = inventory.records.get(reference)
        if (
            reference not in result.verification_refs
            or not isinstance(target, VerificationResult)
            or target.meta.hypothesis_id != hypothesis_id
        ):
            raise ValueError("CURRENT_VERIFICATION_MISMATCH")
        current[hypothesis_id] = target
    counts: Counter[str] = Counter(record.verdict for record in current.values())
    if any(
        result.verdict_counts.get(verdict, 0) != counts.get(verdict, 0)
        for verdict in ("TRUE", "FALSE", "HOLD")
    ):
        raise ValueError("CURRENT_VERDICT_COUNTS_MISMATCH")
    labels: set[HypothesisId] = set()
    works = [inventory.records[ref] for ref in result.work_state_refs]
    attempts = [inventory.records[ref] for ref in result.work_attempt_refs]
    commits = [inventory.records[ref] for ref in result.transition_commit_refs]
    for reference in result.cwe_label_refs:
        label = inventory.records[reference]
        if not isinstance(label, CWELabel) or label.meta.hypothesis_id is None:
            raise ValueError("CURRENT_CWE_VERIFICATION_MISMATCH")
        hypothesis_id = label.meta.hypothesis_id
        if (
            hypothesis_id in labels
            or hypothesis_id not in current
            or current[hypothesis_id].verdict != "TRUE"
            or label.verification_result_ref
            != inventory.current_verification_refs[hypothesis_id]
            or label.verification_generation
            != inventory.verification_generations.get(hypothesis_id)
        ):
            raise ValueError("CURRENT_CWE_VERIFICATION_MISMATCH")
        labels.add(hypothesis_id)
        producing = [
            work
            for work in works
            if isinstance(work, WorkExecutionState)
            and work.work_type == WorkType.CWE_LABEL
            and work.output_refs == (reference,)
        ]
        if len(producing) != 1:
            raise ValueError("CURRENT_CWE_WORK_MISSING")
        work = producing[0]
        if label.cwe_labeling_work_id != work.work_id:
            raise ValueError("CURRENT_CWE_WORK_MISMATCH")
        matching_attempts = [
            attempt
            for attempt in attempts
            if isinstance(attempt, WorkAttempt)
            and attempt.work_id == work.work_id
            and attempt.attempt_id == label.meta.attempt_id
        ]
        matching_commits = [
            commit
            for commit in commits
            if isinstance(commit, TransitionCommit)
            and commit.work_id == work.work_id
            and commit.attempt_id == label.meta.attempt_id
        ]
        if len(matching_attempts) != 1 or len(matching_commits) != 1:
            raise ValueError("CURRENT_CWE_WORK_MISSING")
        validate_committed_output(
            label,
            reference,
            work,
            matching_attempts[0],
            matching_commits[0],
            expected_work_type=WorkType.CWE_LABEL,
        )
    for reference in (*result.finding_refs, *result.report_draft_refs):
        target = inventory.records[reference]
        if (
            not isinstance(target, (Finding, ReportDraft))
            or target.meta.hypothesis_id is None
            or target.verification_result_ref
            != inventory.current_verification_refs.get(target.meta.hypothesis_id)
        ):
            raise ValueError("CURRENT_REPORT_VERIFICATION_MISMATCH")
    primitive_refs: list[StoredDataRef] = []
    listed_primitives: list[StoredDataRef] = []
    for reference in result.primitive_and_chaining_refs:
        target = inventory.records[reference]
        if isinstance(target, PrimitiveIndexState):
            if (
                target.meta.hypothesis_id is None
                or target.current_verification_ref
                != inventory.current_verification_refs.get(target.meta.hypothesis_id)
            ):
                raise ValueError("CURRENT_PRIMITIVE_VERIFICATION_MISMATCH")
            primitive_refs.extend(target.primitive_refs)
        elif isinstance(target, Primitive):
            listed_primitives.append(reference)
    exact_set(listed_primitives, primitive_refs)
    collections = [
        inventory.records[ref] for ref in result.policy_collection_result_refs
    ]
    if any(
        not isinstance(record, PolicyCollectionResult)
        or record.program_id != result.program_id
        for record in collections
    ):
        raise ValueError("POLICY_PROGRAM_MISMATCH")
    exact_set(
        result.policy_record_refs,
        {
            record.policy_record_ref
            for record in collections
            if isinstance(record, PolicyCollectionResult)
            and record.policy_record_ref is not None
        },
    )
    exact_set(
        result.policy_parser_result_refs,
        {
            ref
            for record in collections
            if isinstance(record, PolicyCollectionResult)
            for ref in record.parser_result_refs
        },
    )
