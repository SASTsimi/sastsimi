"""Immutable Finding normalization and the final automated ReportDraft."""

from collections.abc import Mapping
from typing import Literal, Self

from pydantic import model_validator

from ._domain import DomainRecord, exact, exact_set, unique, walk
from .base import ContractModel, NonEmptyStr, PositiveInt
from .canonical_json import canonical_bytes
from .dynamic import DynamicReproductionResult, PoCBundle
from .gates import (
    CWELabel,
    RuleScopeImpactReview,
    TechnicalEvidenceReview,
    validate_rule_scope_gate,
    validate_technical_gate,
)
from .policy import PolicyCollectionResult, ProgramPolicyRecord, RunPolicyState
from .refs import StoredDataRef, require_record_ref
from .static import CodeLocation, Restriction
from .verification import VerificationResult


class FindingConditionSource(ContractModel):
    kind: Literal["RESTRICTION", "LIMITATION", "UNRESOLVED_CONDITION"]
    source_ref: StoredDataRef
    source_path: NonEmptyStr

    @model_validator(mode="after")
    def pointer(self) -> Self:
        require_record_ref(self.source_ref)
        if not self.source_path.startswith("/"):
            raise ValueError("CONDITION_JSON_POINTER_REQUIRED")
        return self


class Finding(DomainRecord):
    KIND = "finding"
    HYPOTHESIS = True
    verification_result_ref: StoredDataRef
    dynamic_result_ref: StoredDataRef
    poc_ref: StoredDataRef
    cwe_label_ref: StoredDataRef
    technical_review_ref: StoredDataRef
    rule_scope_impact_review_ref: StoredDataRef
    policy_collection_result_ref: StoredDataRef
    policy_record_ref: StoredDataRef | None
    evidence_refs: tuple[StoredDataRef, ...]
    condition_sources: tuple[FindingConditionSource, ...]

    @model_validator(mode="after")
    def normalized_shape(self) -> Self:
        unique(self.evidence_refs)
        unique(self.condition_sources)
        return self


class FindingIndexState(DomainRecord):
    KIND = "finding_index_state"
    HYPOTHESIS = True
    ATTEMPT = False
    state_version: PositiveInt
    status: Literal["EMPTY", "CURRENT", "STALE"]
    finding_ref: StoredDataRef | None
    stale_finding_ref: StoredDataRef | None
    normalization_work_ref: StoredDataRef | None
    last_transition_commit_ref: StoredDataRef | None
    invalidated_by_refs: tuple[StoredDataRef, ...]

    @model_validator(mode="after")
    def current_shape(self) -> Self:
        if self.status == "EMPTY":
            if (
                self.state_version != 1
                or self.meta.revision_number != 1
                or any(
                    ref is not None
                    for ref in (
                        self.finding_ref,
                        self.stale_finding_ref,
                        self.normalization_work_ref,
                        self.last_transition_commit_ref,
                    )
                )
            ):
                raise ValueError("FINDING_EMPTY_INDEX_MISMATCH")
        else:
            if (
                self.normalization_work_ref is None
                or self.last_transition_commit_ref is None
            ):
                raise ValueError("FINDING_INDEX_COMMIT_REQUIRED")
            if (self.status == "CURRENT") != (self.finding_ref is not None) or (
                self.status == "STALE"
            ) != (self.stale_finding_ref is not None):
                raise ValueError("FINDING_INDEX_POINTER_MISMATCH")
        if (self.status == "STALE") != bool(self.invalidated_by_refs):
            raise ValueError("FINDING_INVALIDATION_REQUIRED")
        unique(self.invalidated_by_refs)
        return self


class ReportDraft(DomainRecord):
    KIND = "report_draft"
    HYPOTHESIS = True
    action_decision_ref: StoredDataRef
    finding_ref: StoredDataRef
    verification_result_ref: StoredDataRef
    technical_review_ref: StoredDataRef
    rule_scope_impact_review_ref: StoredDataRef
    cwe_label_ref: StoredDataRef
    run_policy_state_ref: StoredDataRef
    policy_record_ref: StoredDataRef
    dynamic_result_ref: StoredDataRef | None
    poc_ref: StoredDataRef | None
    content_ref: StoredDataRef
    restrictions: tuple[Restriction, ...]
    limitations: tuple[NonEmptyStr, ...]
    unresolved_conditions: tuple[NonEmptyStr, ...]
    redaction_status: Literal["PASSED"]
    draft_status: Literal["DRAFTED"]


def evidence_closure(
    verification: VerificationResult, resolved: Mapping[bytes, DomainRecord]
) -> tuple[StoredDataRef, ...]:
    """Traverse supplied immutable records; raw leaves need no fabricated record."""
    roots = [
        ref
        for ref in (verification.pro_evidence_ref, verification.con_evidence_ref)
        if ref is not None
    ]
    for field in (
        "supporting_evidence",
        "counter_evidence",
        "validation_results",
        "falsification_results",
        "required_primitive_candidates",
        "provided_primitive_candidates",
        "bypass_candidates",
        "impact_escalation_candidates",
    ):
        roots.extend(
            ref for item in getattr(verification, field) for ref in item.evidence_refs
        )
    visited: dict[bytes, StoredDataRef] = {}
    pending = list(roots)
    while pending:
        ref = pending.pop()
        key = canonical_bytes(ref)
        if key in visited:
            continue
        visited[key] = ref
        if ref.record_id is None:
            continue
        target = resolved.get(key)
        if target is None:
            raise ValueError("EVIDENCE_TRANSITIVE_CLOSURE_MISSING")
        exact(ref, target, verification.meta)
        # Follow actual evidence edges, not work/config/parent provenance edges.
        for item in walk(target):
            if (
                isinstance(item, ContractModel)
                and "evidence_refs" in type(item).model_fields
            ):
                evidence_field = "evidence_refs"
                pending.extend(getattr(item, evidence_field))
    return tuple(visited.values())


def condition_sources(
    records: tuple[tuple[StoredDataRef, DomainRecord], ...],
) -> tuple[FindingConditionSource, ...]:
    conditions: list[FindingConditionSource] = []
    kinds: dict[str, Literal["RESTRICTION", "LIMITATION", "UNRESOLVED_CONDITION"]] = {
        "restrictions": "RESTRICTION",
        "limitations": "LIMITATION",
        "unresolved_conditions": "UNRESOLVED_CONDITION",
    }

    def collect(value: object, path: str, ref: StoredDataRef) -> None:
        if isinstance(value, ContractModel):
            for name in type(value).model_fields:
                child = getattr(value, name)
                pointer = f"{path}/{name}"
                if name in kinds and isinstance(child, tuple):
                    for index in range(len(child)):
                        conditions.append(
                            FindingConditionSource(
                                kind=kinds[name],
                                source_ref=ref,
                                source_path=f"{pointer}/{index}",
                            )
                        )
                else:
                    collect(child, pointer, ref)
        elif isinstance(value, tuple):
            for index, child in enumerate(value):
                collect(child, f"{path}/{index}", ref)

    for ref, record in records:
        collect(record, "", ref)
    unique(conditions)
    return tuple(conditions)


def validate_finding_closure(
    finding: Finding,
    verification: VerificationResult,
    dynamic: DynamicReproductionResult,
    poc: PoCBundle,
    label: CWELabel,
    technical: TechnicalEvidenceReview,
    scope: RuleScopeImpactReview,
    state: RunPolicyState,
    collection: PolicyCollectionResult,
    policy: ProgramPolicyRecord | None,
    *,
    generation: int,
    resolved_evidence: Mapping[bytes, DomainRecord],
    upstream_conditions: tuple[tuple[StoredDataRef, DomainRecord], ...],
) -> None:
    pairs = (
        (finding.verification_result_ref, verification),
        (finding.dynamic_result_ref, dynamic),
        (finding.poc_ref, poc),
        (finding.cwe_label_ref, label),
        (finding.technical_review_ref, technical),
        (finding.rule_scope_impact_review_ref, scope),
        (finding.policy_collection_result_ref, collection),
    )
    for ref, target in pairs:
        exact(ref, target, finding.meta)
    validate_technical_gate(
        technical, verification, label, dynamic, poc, current_generation=generation
    )
    validate_rule_scope_gate(scope, technical, state, collection, policy)
    if (
        technical.status != "ACCEPT"
        or finding.policy_record_ref != scope.policy_record_ref
        or finding.verification_result_ref != scope.verification_result_ref
        or finding.dynamic_result_ref != verification.dynamic_result_ref
        or finding.poc_ref != verification.poc_ref
    ):
        raise ValueError("FINDING_UPSTREAM_CLOSURE_MISMATCH")
    exact_set(finding.evidence_refs, evidence_closure(verification, resolved_evidence))
    for condition_ref, condition_record in upstream_conditions:
        exact(condition_ref, condition_record, finding.meta)
    if any((ref, target) not in upstream_conditions for ref, target in pairs):
        raise ValueError("CONDITION_UPSTREAM_RECORD_MISSING")
    for evidence_ref in evidence_closure(verification, resolved_evidence):
        if (
            evidence_ref.record_id is not None
            and (evidence_ref, resolved_evidence[canonical_bytes(evidence_ref)])
            not in upstream_conditions
        ):
            raise ValueError("CONDITION_UPSTREAM_RECORD_MISSING")
    validate_finding_conditions(finding, upstream_conditions)


def validate_finding_conditions(
    finding: Finding, records: tuple[tuple[StoredDataRef, DomainRecord], ...]
) -> tuple[tuple[Restriction, ...], tuple[str, ...], tuple[str, ...]]:
    for ref, record in records:
        exact(ref, record, finding.meta)
    try:
        exact_set(finding.condition_sources, condition_sources(records))
    except ValueError as error:
        raise ValueError("CONDITION_CLOSURE_MISMATCH") from error
    by_ref = {canonical_bytes(ref): record for ref, record in records}
    restrictions: list[Restriction] = []
    limitations: list[str] = []
    unresolved: list[str] = []
    for source in finding.condition_sources:
        value: object = by_ref[canonical_bytes(source.source_ref)]
        for part in source.source_path.split("/")[1:]:
            decoded = part.replace("~1", "/").replace("~0", "~")
            if isinstance(value, ContractModel):
                value = getattr(value, decoded)
            elif isinstance(value, tuple):
                value = value[int(decoded)]
            else:
                raise ValueError("CONDITION_CLOSURE_MISMATCH")
        if source.kind == "RESTRICTION" and isinstance(value, Restriction):
            if value not in restrictions:
                restrictions.append(value)
        elif isinstance(value, str) and source.kind == "LIMITATION":
            if value not in limitations:
                limitations.append(value)
        elif isinstance(value, str) and source.kind == "UNRESOLVED_CONDITION":
            if value not in unresolved:
                unresolved.append(value)
        else:
            raise ValueError("CONDITION_KIND_MISMATCH")
    return tuple(restrictions), tuple(limitations), tuple(unresolved)


def validate_report_closure(
    draft: ReportDraft,
    finding: Finding,
    index: FindingIndexState,
    verification: VerificationResult,
    technical: TechnicalEvidenceReview,
    scope: RuleScopeImpactReview,
    state: RunPolicyState,
    *,
    content_locations: tuple[CodeLocation, ...],
    condition_records: tuple[tuple[StoredDataRef, DomainRecord], ...],
) -> None:
    exact(draft.finding_ref, finding, draft.meta)
    if index.status != "CURRENT" or index.finding_ref != draft.finding_ref:
        raise ValueError("STALE_RESULT")
    for name in (
        "verification_result_ref",
        "technical_review_ref",
        "rule_scope_impact_review_ref",
        "cwe_label_ref",
        "policy_record_ref",
        "dynamic_result_ref",
        "poc_ref",
    ):
        if getattr(draft, name) != getattr(finding, name):
            raise ValueError("REPORT_UPSTREAM_CLOSURE_MISMATCH")
    for ref, target in (
        (draft.verification_result_ref, verification),
        (draft.technical_review_ref, technical),
        (draft.rule_scope_impact_review_ref, scope),
        (draft.run_policy_state_ref, state),
    ):
        exact(ref, target, draft.meta)
    if (
        verification.verdict != "TRUE"
        or technical.status != "ACCEPT"
        or not scope.report_ready()
        or state.status != "CURRENT"
    ):
        raise ValueError("REPORT_NOT_READY")
    if (
        draft.run_policy_state_ref != scope.run_policy_state_ref
        or state.policy_record_ref != draft.policy_record_ref
    ):
        raise ValueError("REPORT_POLICY_CLOSURE_MISMATCH")
    if draft.restrictions != verification.restrictions:
        raise ValueError("REPORT_RESTRICTION_DRIFT")
    preserved_restrictions, expected_limitations, expected_unresolved = (
        validate_finding_conditions(finding, condition_records)
    )
    exact_set(draft.restrictions, preserved_restrictions)
    exact_set(draft.limitations, expected_limitations)
    exact_set(draft.unresolved_conditions, expected_unresolved)
    if any(
        condition not in draft.unresolved_conditions
        for condition in verification.unresolved_conditions
    ):
        raise ValueError("REPORT_CONDITION_DROPPED")
    allowed = [
        location
        for claim in (*verification.supporting_evidence, *verification.counter_evidence)
        for location in claim.code_locations
    ]
    for location in content_locations:
        if not any(
            (location.workspace_id, location.commit_id, location.file_path)
            == (source.workspace_id, source.commit_id, source.file_path)
            and source.start_line
            <= location.start_line
            <= location.end_line
            <= source.end_line
            for source in allowed
        ):
            raise ValueError("REPORT_CODE_LOCATION_UNSUPPORTED")
