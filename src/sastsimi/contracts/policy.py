"""Official policy preparation, parsing and the sole cross-run cache exception."""

from datetime import datetime
from typing import Literal, Self

from pydantic import AwareDatetime, model_validator

from ._domain import DomainRecord, exact, exact_set, same_scope, unique
from .base import ContractModel, NonEmptyStr
from .canonical_json import content_hash
from .ids import ErrorId, GapId, ProgramId
from .records import PolicyCacheMeta
from .refs import BudgetScopeRef, PolicyCacheRef, StoredDataRef, validate_exact_ref

type PolicyArea = Literal[
    "RULE", "SCOPE", "IMPACT", "SOURCE", "FRESHNESS", "TESTING_RESTRICTION"
]
POLICY_ITEM_FIELDS = (
    "in_scope_assets",
    "out_of_scope_assets",
    "accepted_vulnerability_classes",
    "excluded_vulnerability_classes",
    "testing_restrictions",
    "reward_conditions",
    "impact_criteria",
    "disclosure_requirements",
)


class RunPolicyState(DomainRecord):
    KIND = "run_policy_state"
    HYPOTHESIS = False
    ATTEMPT = False
    CACHE_REFERENCE_FIELD = "policy_cache_ref"
    CACHE_PROVENANCE_FIELDS = frozenset(
        {"freshness_criterion_ref", "freshness_evidence_refs"}
    )
    program_id: ProgramId
    status: Literal["PREPARING", "CURRENT", "ABSENT", "BLOCKED", "FAILED", "UNVERIFIED"]
    preparation_source: Literal["COLLECTED", "REUSED_CACHE"] | None
    source_config_ref: BudgetScopeRef
    parser_name: NonEmptyStr
    parser_version: NonEmptyStr
    policy_work_ref: StoredDataRef
    policy_cache_ref: PolicyCacheRef | None
    collection_result_ref: StoredDataRef | None
    policy_record_ref: StoredDataRef | None
    freshness_criterion_ref: StoredDataRef | None
    freshness_checked_at: AwareDatetime | None
    freshness_evidence_refs: tuple[StoredDataRef, ...]
    freshness_valid_until: AwareDatetime | None

    @model_validator(mode="after")
    def state_shape(self) -> Self:
        ready = self.status in {"CURRENT", "ABSENT"}
        if ready and (
            self.preparation_source is None
            or self.policy_cache_ref is None
            or self.collection_result_ref is None
            or self.freshness_criterion_ref is None
            or self.freshness_checked_at is None
            or self.freshness_valid_until is None
            or not self.freshness_evidence_refs
        ):
            raise ValueError("POLICY_FRESHNESS_REQUIRED")
        if not ready and self.policy_cache_ref is not None:
            raise ValueError("UNVERIFIED_CACHE_FORBIDDEN")
        if self.status == "CURRENT" and self.policy_record_ref is None:
            raise ValueError("POLICY_RECORD_REQUIRED")
        if (
            self.status in {"ABSENT", "PREPARING", "BLOCKED", "FAILED"}
            and self.policy_record_ref is not None
        ):
            raise ValueError("POLICY_RECORD_FORBIDDEN")
        if self.status == "UNVERIFIED" and self.collection_result_ref is None:
            raise ValueError("POLICY_COLLECTION_REQUIRED")
        if self.status == "PREPARING" and (
            self.preparation_source is not None
            or self.collection_result_ref is not None
        ):
            raise ValueError("POLICY_PREPARING_MISMATCH")
        if (
            self.policy_cache_ref is not None
            and self.policy_cache_ref.program_id != self.program_id
        ):
            raise ValueError("POLICY_PROGRAM_MISMATCH")
        return self


class PolicyItem(ContractModel):
    policy_item_id: NonEmptyStr
    value: NonEmptyStr
    description: NonEmptyStr
    conditions: tuple[NonEmptyStr, ...]
    source_ref: StoredDataRef
    source_locator: NonEmptyStr


class PolicySourceCheck(ContractModel):
    source_id: NonEmptyStr
    source_ref: StoredDataRef
    source_url: NonEmptyStr
    publisher: NonEmptyStr
    status: Literal["VERIFIED", "UNVERIFIED"]
    evidence_refs: tuple[StoredDataRef, ...]
    checked_at: AwareDatetime


class PolicyParserResult(DomainRecord):
    KIND = "policy_parser_result"
    HYPOTHESIS = False
    parser_result_id: NonEmptyStr
    parser_name: NonEmptyStr
    parser_version: NonEmptyStr
    source_ref: StoredDataRef
    llm_invocation_ref: StoredDataRef
    parsed_output_ref: StoredDataRef | None
    status: Literal["SUCCEEDED", "FAILED", "INVALID_OUTPUT"]
    error_ids: tuple[ErrorId, ...]
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def parser_status(self) -> Self:
        if self.status == "SUCCEEDED":
            if self.parsed_output_ref is None or self.error_ids:
                raise ValueError("PARSER_STATUS_MISMATCH")
        elif not self.error_ids:
            raise ValueError("PARSER_ERROR_REQUIRED")
        return self


class PolicyMissingInfo(ContractModel):
    missing_info_id: NonEmptyStr
    area: PolicyArea
    blocks_allow: bool
    description: NonEmptyStr
    policy_item_ids: tuple[NonEmptyStr, ...]
    evidence_refs: tuple[StoredDataRef, ...]


class PreparedPolicyRecord(DomainRecord):
    HYPOTHESIS = False
    program_id: ProgramId
    preparation_source: Literal["COLLECTED", "REUSED_CACHE"]
    source_cache_ref: PolicyCacheRef | None

    @model_validator(mode="after")
    def preparation(self) -> Self:
        if (self.preparation_source == "REUSED_CACHE") != (
            self.source_cache_ref is not None
        ):
            raise ValueError("POLICY_CACHE_PROVENANCE_REQUIRED")
        if (
            self.source_cache_ref is not None
            and self.source_cache_ref.program_id != self.program_id
        ):
            raise ValueError("POLICY_PROGRAM_MISMATCH")
        return self


class ProgramPolicyRecord(PreparedPolicyRecord):
    KIND = "program_policy_record"
    CACHE_PROVENANCE_FIELDS = frozenset(
        (
            *POLICY_ITEM_FIELDS,
            "source_refs",
            "source_checks",
            "parser_result_refs",
            "freshness_criterion_ref",
            "freshness_evidence_refs",
            "missing_information",
        )
    )
    policy_record_id: NonEmptyStr
    program_namespace: NonEmptyStr
    external_program_id: NonEmptyStr
    policy_version: NonEmptyStr
    fetched_at: AwareDatetime
    freshness_status: Literal["CURRENT", "STALE", "UNVERIFIED"]
    freshness_checked_at: AwareDatetime | None
    in_scope_assets: tuple[PolicyItem, ...]
    out_of_scope_assets: tuple[PolicyItem, ...]
    accepted_vulnerability_classes: tuple[PolicyItem, ...]
    excluded_vulnerability_classes: tuple[PolicyItem, ...]
    testing_restrictions: tuple[PolicyItem, ...]
    reward_conditions: tuple[PolicyItem, ...]
    impact_criteria: tuple[PolicyItem, ...]
    disclosure_requirements: tuple[PolicyItem, ...]
    parser_version: NonEmptyStr
    source_refs: tuple[StoredDataRef, ...]
    source_checks: tuple[PolicySourceCheck, ...]
    parser_result_refs: tuple[StoredDataRef, ...]
    freshness_criterion_ref: StoredDataRef | None
    freshness_evidence_refs: tuple[StoredDataRef, ...]
    freshness_valid_until: AwareDatetime | None
    missing_information: tuple[PolicyMissingInfo, ...]
    freshness_warning: NonEmptyStr | None

    def items(self) -> tuple[PolicyItem, ...]:
        return tuple(
            item for name in POLICY_ITEM_FIELDS for item in getattr(self, name)
        )

    @model_validator(mode="after")
    def source_closure(self) -> Self:
        unique(item.policy_item_id for item in self.items())
        unique(check.source_id for check in self.source_checks)
        exact_set((check.source_ref for check in self.source_checks), self.source_refs)
        if any(item.source_ref not in self.source_refs for item in self.items()):
            raise ValueError("OFFICIAL_POLICY_SOURCE_REQUIRED")
        if self.freshness_status == "CURRENT":
            if (
                any(
                    check.status != "VERIFIED" or not check.evidence_refs
                    for check in self.source_checks
                )
                or not self.source_checks
            ):
                raise ValueError("OFFICIAL_POLICY_SOURCE_UNVERIFIED")
            if (
                self.freshness_criterion_ref is None
                or self.freshness_checked_at is None
                or self.freshness_valid_until is None
                or not self.freshness_evidence_refs
            ):
                raise ValueError("POLICY_FRESHNESS_REQUIRED")
        return self


class PolicyCollectionResult(PreparedPolicyRecord):
    KIND = "policy_collection_result"
    CACHE_PROVENANCE_FIELDS = frozenset({"official_source_refs", "parser_result_refs"})
    collection_result_id: NonEmptyStr
    status: Literal["FOUND", "ABSENT_CONFIRMED", "COLLECTION_FAILED"]
    official_source_refs: tuple[StoredDataRef, ...]
    parser_result_refs: tuple[StoredDataRef, ...]
    policy_record_ref: StoredDataRef | None
    gap_ids: tuple[GapId, ...]
    error_ids: tuple[ErrorId, ...]
    completed_at: AwareDatetime

    @model_validator(mode="after")
    def collection_shape(self) -> Self:
        if (self.status == "FOUND") != (self.policy_record_ref is not None):
            raise ValueError("POLICY_COLLECTION_RECORD_MISMATCH")
        if self.status == "COLLECTION_FAILED":
            if not self.error_ids or self.preparation_source != "COLLECTED":
                raise ValueError("POLICY_COLLECTION_FAILURE_REQUIRED")
        elif (
            self.error_ids
            or not self.parser_result_refs
            or not self.official_source_refs
        ):
            raise ValueError("POLICY_COLLECTION_PROVENANCE_REQUIRED")
        if self.status == "ABSENT_CONFIRMED" and not self.gap_ids:
            raise ValueError("POLICY_ABSENCE_GAP_REQUIRED")
        unique(self.official_source_refs)
        unique(self.parser_result_refs)
        return self


class PolicyCacheRecord(ContractModel):
    meta: PolicyCacheMeta
    source_config_ref: BudgetScopeRef
    parser_name: NonEmptyStr
    parser_version: NonEmptyStr
    collection_status: Literal["FOUND", "ABSENT_CONFIRMED"]
    collection_result_ref: StoredDataRef
    parser_result_refs: tuple[StoredDataRef, ...]
    policy_record_ref: StoredDataRef | None
    freshness_criterion_ref: StoredDataRef
    freshness_checked_at: AwareDatetime
    freshness_evidence_refs: tuple[StoredDataRef, ...]
    freshness_valid_until: AwareDatetime
    published_at: AwareDatetime

    @model_validator(mode="after")
    def reusable(self) -> Self:
        if (
            (self.collection_status == "FOUND") != (self.policy_record_ref is not None)
            or not self.parser_result_refs
            or not self.freshness_evidence_refs
            or self.freshness_valid_until <= self.freshness_checked_at
        ):
            raise ValueError("POLICY_CACHE_INVALID")
        return self


def validate_policy_collection(
    collection: PolicyCollectionResult,
    policy: ProgramPolicyRecord | None,
    parsers: tuple[PolicyParserResult, ...],
    *,
    source_cache: PolicyCacheRecord | None = None,
) -> None:
    if collection.preparation_source == "REUSED_CACHE":
        if source_cache is None or collection.source_cache_ref is None:
            raise ValueError("POLICY_CACHE_PROVENANCE_REQUIRED")
        validate_exact_ref(
            collection.source_cache_ref, source_cache.meta, content_hash(source_cache)
        )
        exact_set(collection.parser_result_refs, source_cache.parser_result_refs)
    elif source_cache is not None:
        raise ValueError("POLICY_CACHE_PROVENANCE_FORBIDDEN")
    if (collection.policy_record_ref is None) != (policy is None):
        raise ValueError("POLICY_COLLECTION_RECORD_MISMATCH")
    if policy is not None and collection.policy_record_ref is not None:
        exact(collection.policy_record_ref, policy, collection.meta)
        same_scope(collection.meta, policy.meta, attempt=True)
        if (policy.program_id, policy.preparation_source, policy.source_cache_ref) != (
            collection.program_id,
            collection.preparation_source,
            collection.source_cache_ref,
        ):
            raise ValueError("POLICY_PROGRAM_MISMATCH")
        exact_set(collection.official_source_refs, policy.source_refs)
        exact_set(collection.parser_result_refs, policy.parser_result_refs)
    if len(parsers) != len(collection.parser_result_refs):
        raise ValueError("PARSER_CLOSURE_MISMATCH")
    for ref, parser in zip(collection.parser_result_refs, parsers, strict=True):
        validate_exact_ref(
            ref,
            parser.meta,
            content_hash(parser),
            analysis_id=parser.meta.analysis_id
            if source_cache
            else collection.meta.analysis_id,
        )
        if source_cache is None:
            same_scope(collection.meta, parser.meta, attempt=True)
        if collection.status != "COLLECTION_FAILED" and parser.status != "SUCCEEDED":
            raise ValueError("PARSER_FAILURE_NOT_POLICY")
        if parser.source_ref not in collection.official_source_refs or (
            policy is not None and policy.parser_version != parser.parser_version
        ):
            raise ValueError("PARSER_SOURCE_MISMATCH")


def validate_run_policy(
    state: RunPolicyState,
    collection: PolicyCollectionResult | None,
    policy: ProgramPolicyRecord | None,
    *,
    started_at: datetime,
    cache: PolicyCacheRecord | None = None,
) -> None:
    if state.policy_cache_ref is not None:
        if cache is None:
            raise ValueError("POLICY_CACHE_PROVENANCE_REQUIRED")
        validate_exact_ref(state.policy_cache_ref, cache.meta, content_hash(cache))
        for field in (
            "parser_name",
            "parser_version",
            "freshness_criterion_ref",
            "freshness_checked_at",
            "freshness_valid_until",
            "freshness_evidence_refs",
        ):
            if getattr(state, field) != getattr(cache, field):
                raise ValueError("POLICY_CACHE_STATE_DRIFT")
        if state.source_config_ref.content_hash != cache.source_config_ref.content_hash:
            raise ValueError("POLICY_CACHE_STATE_DRIFT")
    if (state.collection_result_ref is None) != (collection is None):
        raise ValueError("POLICY_COLLECTION_REQUIRED")
    if collection is not None and state.collection_result_ref is not None:
        exact(state.collection_result_ref, collection, state.meta)
        if (
            state.program_id != collection.program_id
            or state.policy_record_ref != collection.policy_record_ref
            or state.preparation_source != collection.preparation_source
            or (
                collection.preparation_source == "REUSED_CACHE"
                and collection.source_cache_ref != state.policy_cache_ref
            )
        ):
            raise ValueError("POLICY_STATE_CLOSURE_MISMATCH")
        allowed = {
            "CURRENT": {"FOUND"},
            "ABSENT": {"ABSENT_CONFIRMED"},
            "UNVERIFIED": {"FOUND", "ABSENT_CONFIRMED"},
            "BLOCKED": {"COLLECTION_FAILED"},
            "FAILED": {"COLLECTION_FAILED"},
            "PREPARING": set(),
        }
        if collection.status not in allowed[state.status]:
            raise ValueError("POLICY_STATE_STATUS_MISMATCH")
    if (state.policy_record_ref is None) != (policy is None):
        raise ValueError("POLICY_RECORD_REQUIRED")
    if policy is not None and state.policy_record_ref is not None:
        exact(state.policy_record_ref, policy, state.meta)
        validate_policy_freshness(state, policy)
    if state.status in {"CURRENT", "ABSENT"} and (
        state.freshness_valid_until is None or state.freshness_valid_until <= started_at
    ):
        raise ValueError("POLICY_SOURCE_STALE")


def validate_policy_freshness(
    state: RunPolicyState, policy: ProgramPolicyRecord
) -> None:
    expected = {"CURRENT": "CURRENT", "UNVERIFIED": "UNVERIFIED"}.get(state.status)
    if expected is None or policy.freshness_status != expected:
        raise ValueError("POLICY_STATE_FRESHNESS_MISMATCH")
    if (
        state.program_id != policy.program_id
        or state.parser_version != policy.parser_version
        or state.preparation_source != policy.preparation_source
    ):
        raise ValueError("POLICY_STATE_FRESHNESS_MISMATCH")
    for field in (
        "freshness_criterion_ref",
        "freshness_checked_at",
        "freshness_valid_until",
        "freshness_evidence_refs",
    ):
        if getattr(state, field) != getattr(policy, field):
            raise ValueError("POLICY_STATE_FRESHNESS_MISMATCH")


def validate_policy_cache_reuse(
    cache: PolicyCacheRecord,
    cache_ref: PolicyCacheRef,
    original_collection: PolicyCollectionResult,
    original_policy: ProgramPolicyRecord | None,
    parsers: tuple[PolicyParserResult, ...],
    new_collection: PolicyCollectionResult,
    new_policy: ProgramPolicyRecord | None,
    *,
    started_at: datetime,
) -> None:
    validate_exact_ref(cache_ref, cache.meta, content_hash(cache))
    if cache.freshness_valid_until <= started_at:
        raise ValueError("POLICY_SOURCE_STALE")
    exact(cache.collection_result_ref, original_collection, original_collection.meta)
    if (
        original_collection.status != cache.collection_status
        or original_collection.program_id != cache.meta.program_id
    ):
        raise ValueError("POLICY_CACHE_STATUS_MISMATCH")
    exact_set(cache.parser_result_refs, original_collection.parser_result_refs)
    if original_policy is not None and cache.policy_record_ref is not None:
        exact(cache.policy_record_ref, original_policy, original_collection.meta)
        if original_policy.freshness_status != "CURRENT":
            raise ValueError("POLICY_SOURCE_STALE")
        for field in (
            "freshness_criterion_ref",
            "freshness_checked_at",
            "freshness_valid_until",
            "freshness_evidence_refs",
        ):
            if getattr(cache, field) != getattr(original_policy, field):
                raise ValueError("CACHE_POLICY_CONTENT_DRIFT")
    elif original_policy is not None or cache.policy_record_ref is not None:
        raise ValueError("POLICY_CACHE_RECORD_MISMATCH")
    validate_policy_collection(original_collection, original_policy, parsers)
    if (
        new_collection.source_cache_ref != cache_ref
        or new_collection.preparation_source != "REUSED_CACHE"
        or new_collection.status != cache.collection_status
    ):
        raise ValueError("POLICY_CACHE_PROVENANCE_REQUIRED")
    if (
        new_collection.meta.analysis_id == original_collection.meta.analysis_id
        or new_collection.meta.record_id == original_collection.meta.record_id
    ):
        raise ValueError("POLICY_CACHE_NEW_RUN_REQUIRED")
    exact_set(
        new_collection.official_source_refs, original_collection.official_source_refs
    )
    if (new_policy is None) != (original_policy is None):
        raise ValueError("POLICY_CACHE_RECORD_MISMATCH")
    if new_policy is not None and original_policy is not None:
        preserved = set(ProgramPolicyRecord.model_fields) - {
            "meta",
            "policy_record_id",
            "preparation_source",
            "source_cache_ref",
        }
        if any(
            getattr(new_policy, field) != getattr(original_policy, field)
            for field in preserved
        ):
            raise ValueError("CACHE_POLICY_CONTENT_DRIFT")
    validate_policy_collection(new_collection, new_policy, parsers, source_cache=cache)
