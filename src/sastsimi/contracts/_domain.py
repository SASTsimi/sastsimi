"""Pure common checks; no storage, producer registry, or current-pointer lookup."""

import re
from collections.abc import Iterable
from typing import Annotated, ClassVar, Self

from pydantic import AfterValidator, BaseModel, model_validator

from .base import ContractModel, NonEmptyStr
from .canonical_json import canonical_bytes, content_hash
from .records import RecordMeta, RunMeta
from .refs import (
    PolicyCacheRef,
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
    validate_exact_ref,
    validate_ref_scope,
)

REFERENCE_KINDS = {
    "action_decision_ref": "action_decision",
    "verification_result_ref": "verification_result",
    "source_verification_ref": "verification_result",
    "current_verification_ref": "verification_result",
    "hypothesis_ref": "vulnerability_hypothesis",
    "proposal_ref": "hypothesis_proposal",
    "playbook_ref": "verification_playbook",
    "playbook_application_ref": "playbook_application",
    "pro_evidence_ref": "pro_evidence_result",
    "con_evidence_ref": "con_evidence_result",
    "dynamic_request_ref": "dynamic_reproduction_request",
    "dynamic_result_ref": "dynamic_reproduction_result",
    "request_ref": "dynamic_reproduction_request",
    "reproduction_plan_ref": "reproduction_plan",
    "environment_requirements_ref": "environment_requirements",
    "requirements_ref": "environment_requirements",
    "environment_recipe_ref": "environment_recipe",
    "baseline_recipe_ref": "environment_recipe",
    "environment_ref": "sandbox_environment",
    "previous_environment_ref": "sandbox_environment",
    "agent_log_ref": "agent_log",
    "agent_conclusion_ref": "dynamic_reproduction_conclusion",
    "poc_candidate_ref": "poc_candidate",
    "candidate_ref": "poc_candidate",
    "poc_ref": "poc_bundle",
    "policy_decision_ref": "sandbox_policy_decision",
    "tool_request_ref": "dynamic_reproduction_tool_request",
    "cleanup_ref": "cleanup_result",
    "cwe_label_ref": "cwe_label",
    "technical_review_ref": "technical_evidence_review",
    "rule_scope_review_ref": "rule_scope_impact_review",
    "rule_scope_impact_review_ref": "rule_scope_impact_review",
    "admission_decision_ref": "primitive_admission_decision",
    "run_policy_state_ref": "run_policy_state",
    "policy_collection_result_ref": "policy_collection_result",
    "collection_result_ref": "policy_collection_result",
    "policy_record_ref": "program_policy_record",
    "policy_work_ref": "work_execution_state",
    "sandbox_profile_ref": "sandbox_profile",
    "resource_profile_ref": "dynamic_reproduction_lifecycle_profile",
    "finding_ref": "finding",
    "stale_finding_ref": "finding",
    "normalization_work_ref": "work_execution_state",
    "last_transition_commit_ref": "transition_commit",
    "evaluation_result_ref": "evaluation_run_result",
}


def safe_diagnostic(value: str) -> str:
    if re.search(
        r"[A-Za-z]:[\\/]|\\\\|(?<![\w/])/(?:home|Users|tmp|etc|var)/|\b(?:bearer|basic)\s+\S+|\b(?:password|token|cookie|authorization|api[_-]?key)\s*[:=]",
        value,
        re.IGNORECASE,
    ):
        raise ValueError("UNSAFE_DIAGNOSTIC")
    return value


SafeDiagnostic = Annotated[NonEmptyStr, AfterValidator(safe_diagnostic)]


def unique(values: Iterable[object], code: str = "DUPLICATE_REFERENCE") -> None:
    keys = [canonical_bytes(value) for value in values]
    if len(keys) != len(set(keys)):
        raise ValueError(code)


def exact_set(actual: Iterable[object], expected: Iterable[object]) -> None:
    left, right = tuple(actual), tuple(expected)
    unique(left)
    if {canonical_bytes(v) for v in left} != {canonical_bytes(v) for v in right}:
        raise ValueError("RECORD_REVISION_MISMATCH: exact set closure")


def walk(value: object) -> Iterable[object]:
    yield value
    if isinstance(value, BaseModel):
        for name in type(value).model_fields:
            yield from walk(getattr(value, name))
    elif isinstance(value, (tuple, list)):
        for item in value:
            yield from walk(item)


class DomainRecord(ContractModel):
    meta: RecordMeta
    KIND: ClassVar[str] = ""
    HYPOTHESIS: ClassVar[bool | None] = None
    ATTEMPT: ClassVar[bool | None] = True
    CACHE_PROVENANCE_FIELDS: ClassVar[frozenset[str]] = frozenset()
    CACHE_REFERENCE_FIELD: ClassVar[str] = "source_cache_ref"

    @model_validator(mode="after")
    def domain_scope(self) -> Self:
        if self.KIND and self.meta.record_type != self.KIND:
            raise ValueError("RECORD_KIND_MISMATCH")
        for field in ("workspace_id", "commit_id"):
            if field in type(self).model_fields and getattr(self, field) != getattr(
                self.meta, field
            ):
                raise ValueError("WORKSPACE_MISMATCH")
        for name, kind in REFERENCE_KINDS.items():
            ref = getattr(self, name, None)
            if isinstance(ref, StoredDataRef) and (
                ref.record_id is None or ref.data_kind != kind
            ):
                raise ValueError("REFERENCE_KIND_MISMATCH")
        for flag, value in (
            (self.HYPOTHESIS, self.meta.hypothesis_id),
            (self.ATTEMPT, self.meta.attempt_id),
        ):
            if flag is not None and flag != (value is not None):
                raise ValueError("METADATA_SCOPE_MISMATCH")
        values = tuple(
            getattr(self, name)
            for name in type(self).model_fields
            if not (
                getattr(self, self.CACHE_REFERENCE_FIELD, None) is not None
                and name in self.CACHE_PROVENANCE_FIELDS
            )
        )
        for item in walk(values):
            if isinstance(item, (StoredDataRef, RunStoredDataRef, PolicyCacheRef)):
                validate_ref_scope(item, self.meta)
            elif isinstance(item, RecordMeta):
                if (item.analysis_id, item.workspace_id, item.commit_id) != (
                    self.meta.analysis_id,
                    self.meta.workspace_id,
                    self.meta.commit_id,
                ):
                    raise ValueError("WORKSPACE_MISMATCH")
            elif (
                isinstance(item, BaseModel)
                and {"workspace_id", "commit_id"} <= type(item).model_fields.keys()
            ):
                workspace_field, commit_field = "workspace_id", "commit_id"
                if (getattr(item, workspace_field), getattr(item, commit_field)) != (
                    self.meta.workspace_id,
                    self.meta.commit_id,
                ):
                    raise ValueError("WORKSPACE_MISMATCH")
        return self


def same_scope(
    left: RecordMeta,
    right: RecordMeta,
    *,
    hypothesis: bool = True,
    attempt: bool = False,
) -> None:
    keys = ["analysis_id", "workspace_id", "commit_id"]
    if hypothesis:
        keys.append("hypothesis_id")
    if attempt:
        keys.append("attempt_id")
    if any(getattr(left, key) != getattr(right, key) for key in keys):
        raise ValueError("RECORD_SCOPE_MISMATCH")


def exact(ref: RecordRef, target: DomainRecord, consumer: RecordMeta | RunMeta) -> None:
    validate_exact_ref(
        ref, target.meta, content_hash(target), analysis_id=consumer.analysis_id
    )
