"""Verification and independent Pro/Con evidence; exact joins remain pure."""

from typing import Literal, Self

from pydantic import AwareDatetime, model_validator

from ._domain import DomainRecord, exact, exact_set, same_scope, unique
from .actions import SessionMode
from .base import ContractModel, NonEmptyStr, NonNegativeInt, PositiveInt, Sha256
from .dynamic import DynamicReproductionRequest, DynamicReproductionResult, PoCBundle
from .hypothesis import HypothesisProposal, VulnerabilityHypothesis
from .ids import HypothesisId, WorkId
from .refs import StoredDataRef, require_record_ref
from .static import AnalysisError, CodeLocation, CodeSymbol, Restriction

type Verdict = Literal["TRUE", "FALSE", "HOLD"]


class PlaybookQuestionTemplate(ContractModel):
    template_key: NonEmptyStr
    question: NonEmptyStr


class VerificationPlaybook(DomainRecord):
    KIND = "verification_playbook"
    HYPOTHESIS = False
    ATTEMPT = False
    scope: Literal["COMMON", "TYPE_SPECIFIC"]
    vulnerability_type: NonEmptyStr | None
    prerequisites: tuple[NonEmptyStr, ...]
    source_checks: tuple[NonEmptyStr, ...]
    sink_checks: tuple[NonEmptyStr, ...]
    path_checks: tuple[NonEmptyStr, ...]
    defense_checks: tuple[NonEmptyStr, ...]
    falsification_question_templates: tuple[PlaybookQuestionTemplate, ...]
    static_evidence_requirements: tuple[NonEmptyStr, ...]
    dynamic_evidence_requirements: tuple[NonEmptyStr, ...]
    restriction_checks: tuple[NonEmptyStr, ...]
    hold_conditions: tuple[NonEmptyStr, ...]

    @model_validator(mode="after")
    def playbook_shape(self) -> Self:
        if (self.scope == "COMMON") != (self.vulnerability_type is None):
            raise ValueError("PLAYBOOK_SCOPE_MISMATCH")
        unique(q.template_key for q in self.falsification_question_templates)
        return self


class PlaybookPolicyItem(ContractModel):
    vulnerability_type: NonEmptyStr
    playbook_ref: StoredDataRef


class PlaybookPolicy(DomainRecord):
    KIND = "playbook_policy"
    HYPOTHESIS = False
    ATTEMPT = False
    common_playbook_ref: StoredDataRef
    type_playbooks: tuple[PlaybookPolicyItem, ...]
    approved_by: NonEmptyStr
    approved_at: AwareDatetime

    @model_validator(mode="after")
    def mapping_shape(self) -> Self:
        unique(item.vulnerability_type for item in self.type_playbooks)
        for ref in (
            self.common_playbook_ref,
            *(item.playbook_ref for item in self.type_playbooks),
        ):
            require_record_ref(ref, "verification_playbook")
        return self


class AppliedPlaybookQuestion(PlaybookQuestionTemplate):
    question_id: NonEmptyStr


class PlaybookApplication(DomainRecord):
    KIND = "playbook_application"
    HYPOTHESIS = True
    ATTEMPT = False
    verification_work_id: WorkId
    verification_generation: PositiveInt
    hypothesis_ref: StoredDataRef
    proposal_ref: StoredDataRef
    policy_ref: StoredDataRef
    playbook_ref: StoredDataRef
    selection: Literal["COMMON", "TYPE_SPECIFIC"]
    selected_type: NonEmptyStr | None
    selection_reason: Literal[
        "TYPE_MATCH", "NO_TYPE", "MULTIPLE_TYPES", "TYPE_NOT_ALLOWED"
    ]
    questions: tuple[AppliedPlaybookQuestion, ...]

    @model_validator(mode="after")
    def application_shape(self) -> Self:
        if (self.selection == "TYPE_SPECIFIC") != (self.selected_type is not None) or (
            self.selection == "TYPE_SPECIFIC"
        ) != (self.selection_reason == "TYPE_MATCH"):
            raise ValueError("PLAYBOOK_SELECTION_MISMATCH")
        unique(q.template_key for q in self.questions)
        unique(q.question_id for q in self.questions)
        return self


class VerificationInitialAssessment(DomainRecord):
    KIND = "verification_initial_assessment"
    HYPOTHESIS = True
    verification_work_id: WorkId
    verification_generation: PositiveInt
    hypothesis_ref: StoredDataRef
    policy_ref: StoredDataRef
    playbook_ref: StoredDataRef
    playbook_application_ref: StoredDataRef
    pro_evidence_ref: StoredDataRef
    con_evidence_ref: StoredDataRef
    next_step: Literal[
        "POC_CONFIRMATION", "VERDICT_EVIDENCE", "FINALIZE_WITHOUT_DYNAMIC"
    ]
    proposed_verdict: Verdict
    rationale: NonEmptyStr
    evidence_refs: tuple[StoredDataRef, ...]
    unresolved_conditions: tuple[NonEmptyStr, ...]
    llm_call_id: NonEmptyStr

    @model_validator(mode="after")
    def assessment_route(self) -> Self:
        if (
            (self.next_step == "POC_CONFIRMATION" and self.proposed_verdict != "TRUE")
            or (
                self.next_step == "VERDICT_EVIDENCE" and self.proposed_verdict != "HOLD"
            )
            or (
                self.next_step == "FINALIZE_WITHOUT_DYNAMIC"
                and self.proposed_verdict == "TRUE"
            )
        ):
            raise ValueError("INITIAL_ASSESSMENT_ROUTE_MISMATCH")
        return self


class EvidenceClaim(ContractModel):
    claim_id: NonEmptyStr
    statement: NonEmptyStr
    source_role: Literal["VERIFICATION", "PRO", "CON"]
    evidence_refs: tuple[StoredDataRef, ...]
    code_locations: tuple[CodeLocation, ...]
    limitations: tuple[NonEmptyStr, ...]

    @model_validator(mode="after")
    def actual_evidence(self) -> Self:
        if not self.evidence_refs:
            raise ValueError("EVIDENCE_REQUIRED")
        unique(self.evidence_refs)
        if any(
            ref.data_kind
            in {"analysis_error", "data_gap", "verification_initial_assessment"}
            for ref in self.evidence_refs
        ):
            raise ValueError("ERROR_IS_NOT_EVIDENCE")
        return self


class EvidenceAgentResult(DomainRecord):
    HYPOTHESIS = True
    role: Literal["PRO", "CON"]
    parent_work_id: WorkId
    evidence_work_id: WorkId
    verification_generation: PositiveInt
    llm_call_id: NonEmptyStr
    debate_input_hash: Sha256
    evidence: tuple[EvidenceClaim, ...]
    summary: NonEmptyStr
    limitations: tuple[NonEmptyStr, ...]

    @model_validator(mode="after")
    def own_role_only(self) -> Self:
        if self.meta.record_type != f"{self.role.lower()}_evidence_result":
            raise ValueError("RECORD_KIND_MISMATCH")
        if any(claim.source_role != self.role for claim in self.evidence):
            raise ValueError("CROSS_ROLE_INPUT_DENIED")
        unique(claim.claim_id for claim in self.evidence)
        return self


class ProEvidenceResult(EvidenceAgentResult):
    role: Literal["PRO"]


class ConEvidenceResult(EvidenceAgentResult):
    role: Literal["CON"]


class CandidateRef(ContractModel):
    candidate_id: NonEmptyStr
    candidate_type: Literal["BYPASS", "ALTERNATE_PATH", "IMPACT_ESCALATION"]
    statement: NonEmptyStr
    source_hypothesis_ids: tuple[HypothesisId, ...]
    target_entities: tuple[CodeSymbol, ...]
    target_locations: tuple[CodeLocation, ...]
    evidence_refs: tuple[StoredDataRef, ...]
    missing_information: tuple[NonEmptyStr, ...]
    candidate_state: Literal["UNVALIDATED"]


class PrimitiveDraft(ContractModel):
    draft_id: NonEmptyStr
    entity_refs: tuple[CodeSymbol, ...]
    privilege_level: NonEmptyStr | None
    evidence_refs: tuple[StoredDataRef, ...]
    description: NonEmptyStr

    @model_validator(mode="after")
    def supported(self) -> Self:
        if not self.evidence_refs:
            raise ValueError("EVIDENCE_REQUIRED")
        unique(self.evidence_refs)
        return self


class VerificationMetrics(ContractModel):
    pro_tokens: NonNegativeInt | None
    con_tokens: NonNegativeInt | None
    synthesis_tokens: NonNegativeInt | None
    elapsed_ms: NonNegativeInt
    verdict_changed_after_debate: bool
    hold_resolved: bool
    false_positive_reduction_candidate: bool
    new_bypass_count: NonNegativeInt
    new_restriction_count: NonNegativeInt
    new_falsification_count: NonNegativeInt


class FalsificationResult(ContractModel):
    question_id: NonEmptyStr
    outcome: Literal["DISPROVED", "NOT_DISPROVED", "INCONCLUSIVE"]
    evidence_refs: tuple[StoredDataRef, ...]
    rationale: NonEmptyStr


class ValidationCheckResult(ContractModel):
    validation_id: NonEmptyStr
    completion: Literal["COMPLETE", "INCOMPLETE"]
    evidence_refs: tuple[StoredDataRef, ...]
    summary: NonEmptyStr


class VerificationResult(DomainRecord):
    KIND = "verification_result"
    HYPOTHESIS = True
    playbook_ref: StoredDataRef
    playbook_application_ref: StoredDataRef
    verification_mode: Literal["BASIC", "CONDITIONAL_DEBATE", "ALWAYS_DEBATE"]
    debate_triggers: tuple[NonEmptyStr, ...]
    debate_skip_reason: NonEmptyStr | None
    debate_input_hash: Sha256 | None
    pro_evidence_ref: StoredDataRef | None
    con_evidence_ref: StoredDataRef | None
    supporting_evidence: tuple[EvidenceClaim, ...]
    counter_evidence: tuple[EvidenceClaim, ...]
    falsification_results: tuple[FalsificationResult, ...]
    validation_results: tuple[ValidationCheckResult, ...]
    initial_verdict: Verdict
    dynamic_request_ref: StoredDataRef | None
    dynamic_result_ref: StoredDataRef | None
    poc_ref: StoredDataRef | None
    verdict: Verdict
    verdict_rationale: NonEmptyStr
    restrictions: tuple[Restriction, ...]
    bypass_candidates: tuple[CandidateRef, ...]
    required_primitive_candidates: tuple[PrimitiveDraft, ...]
    provided_primitive_candidates: tuple[PrimitiveDraft, ...]
    impact_escalation_candidates: tuple[CandidateRef, ...]
    material_child_proposals: tuple[HypothesisProposal, ...]
    unresolved_conditions: tuple[NonEmptyStr, ...]
    metrics: VerificationMetrics
    errors: tuple[AnalysisError, ...]

    @model_validator(mode="after")
    def final_shape(self) -> Self:
        debate = self.verification_mode == "ALWAYS_DEBATE" or (
            self.verification_mode == "CONDITIONAL_DEBATE"
            and bool(self.debate_triggers)
        )
        if any(
            (value is not None) != debate
            for value in (
                self.debate_input_hash,
                self.pro_evidence_ref,
                self.con_evidence_ref,
            )
        ):
            raise ValueError("DEBATE_CLOSURE_REQUIRED")
        if (
            self.verification_mode == "CONDITIONAL_DEBATE"
            and not debate
            and not self.debate_skip_reason
        ):
            raise ValueError("DEBATE_SKIP_REASON_REQUIRED")
        if not debate and (
            self.metrics.pro_tokens is not None
            or self.metrics.con_tokens is not None
            or self.metrics.verdict_changed_after_debate
        ):
            raise ValueError("DEBATE_METRICS_MISMATCH")
        for ref, kind in (
            (self.playbook_ref, "verification_playbook"),
            (self.playbook_application_ref, "playbook_application"),
            (self.pro_evidence_ref, "pro_evidence_result"),
            (self.con_evidence_ref, "con_evidence_result"),
            (self.dynamic_request_ref, "dynamic_reproduction_request"),
            (self.dynamic_result_ref, "dynamic_reproduction_result"),
            (self.poc_ref, "poc_bundle"),
        ):
            if ref is not None:
                require_record_ref(ref, kind)
        if (self.dynamic_request_ref is None) != (self.dynamic_result_ref is None):
            raise ValueError("DYNAMIC_CLOSURE_REQUIRED")
        if self.verdict == "TRUE":
            if (
                self.poc_ref is None
                or self.dynamic_result_ref is None
                or not self.supporting_evidence
            ):
                raise ValueError("VALIDATED_POC_REQUIRED")
        elif self.poc_ref is not None:
            raise ValueError("VALIDATED_POC_FORBIDDEN")
        disproved = [q for q in self.falsification_results if q.outcome == "DISPROVED"]
        if (self.verdict == "FALSE") != bool(disproved):
            raise ValueError("FALSIFICATION_VERDICT_MISMATCH")
        if self.verdict == "HOLD" and not self.unresolved_conditions:
            raise ValueError("HOLD_CONDITIONS_REQUIRED")
        if (
            not self.falsification_results
            or not self.validation_results
            or any(
                v.completion != "COMPLETE" or not v.evidence_refs
                for v in self.validation_results
            )
        ):
            raise ValueError("VERIFICATION_INCOMPLETE")
        if any(not q.evidence_refs for q in self.falsification_results):
            raise ValueError("EVIDENCE_REQUIRED")
        unique(q.question_id for q in self.falsification_results)
        unique(v.validation_id for v in self.validation_results)
        claims = (*self.supporting_evidence, *self.counter_evidence)
        unique(c.claim_id for c in claims)
        if any(c.source_role == "CON" for c in self.supporting_evidence) or any(
            c.source_role == "PRO" for c in self.counter_evidence
        ):
            raise ValueError("CROSS_ROLE_INPUT_DENIED")
        unique(r.restriction_id for r in self.restrictions)
        drafts = (
            *self.required_primitive_candidates,
            *self.provided_primitive_candidates,
        )
        unique(d.draft_id for d in drafts)
        if self.verdict == "FALSE" and drafts:
            raise ValueError("FALSE_PRIMITIVE_FORBIDDEN")
        candidates = (*self.bypass_candidates, *self.impact_escalation_candidates)
        unique(c.candidate_id for c in candidates)
        if any(
            self.meta.hypothesis_id not in c.source_hypothesis_ids for c in candidates
        ):
            raise ValueError("CANDIDATE_HYPOTHESIS_MISMATCH")
        if any(p.origin != "VERIFICATION" for p in self.material_child_proposals):
            raise ValueError("CHILD_ORIGIN_MISMATCH")
        if self.metrics.hold_resolved and not (
            self.initial_verdict == "HOLD" and self.verdict != "HOLD"
        ):
            raise ValueError("HOLD_METRICS_MISMATCH")
        return self


def validate_evidence_pair(
    pro: EvidenceAgentResult,
    con: EvidenceAgentResult,
    *,
    parent_work_id: WorkId,
    generation: int,
    debate_input_hash: str,
) -> None:
    if pro.role != "PRO" or con.role != "CON":
        raise ValueError("CROSS_ROLE_INPUT_DENIED")
    same_scope(pro.meta, con.meta)
    for result in (pro, con):
        if (
            result.parent_work_id,
            result.verification_generation,
            result.debate_input_hash,
        ) != (parent_work_id, generation, debate_input_hash):
            raise ValueError("STALE_RESULT")
    if (
        pro.evidence_work_id == con.evidence_work_id
        or pro.meta.attempt_id == con.meta.attempt_id
        or pro.llm_call_id == con.llm_call_id
    ):
        raise ValueError("EVIDENCE_INDEPENDENCE_REQUIRED")


def validate_evidence_sessions(
    pro: EvidenceAgentResult,
    con: EvidenceAgentResult,
    *,
    pro_session_id: str,
    con_session_id: str,
    pro_mode: SessionMode,
    con_mode: SessionMode,
) -> None:
    validate_evidence_pair(
        pro,
        con,
        parent_work_id=pro.parent_work_id,
        generation=pro.verification_generation,
        debate_input_hash=pro.debate_input_hash,
    )
    if (
        pro_mode != SessionMode.NEW
        or con_mode != SessionMode.NEW
        or not pro_session_id
        or not con_session_id
        or pro_session_id == con_session_id
    ):
        raise ValueError("EVIDENCE_NEW_SESSION_REQUIRED")


def validate_dynamic_verdict(
    result: VerificationResult,
    request: DynamicReproductionRequest,
    dynamic: DynamicReproductionResult,
    poc: PoCBundle | None,
    *,
    generation: int,
) -> None:
    if result.dynamic_request_ref is None or result.dynamic_result_ref is None:
        raise ValueError("DYNAMIC_CLOSURE_REQUIRED")
    exact(result.dynamic_request_ref, request, result.meta)
    exact(result.dynamic_result_ref, dynamic, result.meta)
    same_scope(result.meta, request.meta)
    same_scope(result.meta, dynamic.meta)
    if (
        request.verification_generation != generation
        or dynamic.request_ref != result.dynamic_request_ref
        or dynamic.purpose != request.purpose
    ):
        raise ValueError("STALE_RESULT")
    if dynamic.status not in {"SUCCEEDED", "PARTIAL"}:
        raise ValueError("EXECUTION_FAILURE_IS_NOT_VERDICT")
    expected = {"SUPPORTED": "TRUE", "DISPROVED": "FALSE", "INCONCLUSIVE": "HOLD"}[
        dynamic.hypothesis_outcome
    ]
    if result.verdict != expected:
        raise ValueError("DYNAMIC_VERDICT_MISMATCH")
    if result.poc_ref != dynamic.poc_ref or (result.poc_ref is None) != (poc is None):
        raise ValueError("VALIDATED_POC_REQUIRED")
    if poc is not None and result.poc_ref is not None:
        exact(result.poc_ref, poc, result.meta)
        same_scope(poc.meta, dynamic.meta, attempt=True)
        if poc.request_ref != dynamic.request_ref:
            raise ValueError("POC_PROVENANCE_MISMATCH")


def validate_playbook_application(
    application: PlaybookApplication,
    hypothesis: VulnerabilityHypothesis,
    proposal: HypothesisProposal,
    policy: PlaybookPolicy,
    playbook: VerificationPlaybook,
) -> None:
    for ref, target in (
        (application.hypothesis_ref, hypothesis),
        (application.proposal_ref, proposal),
        (application.policy_ref, policy),
        (application.playbook_ref, playbook),
    ):
        exact(ref, target, application.meta)
    if application.proposal_ref != hypothesis.proposal_ref:
        raise ValueError("PROPOSAL_REFERENCE_MISMATCH")
    types = proposal.vulnerability_type_candidates
    mappings = {
        item.vulnerability_type: item.playbook_ref for item in policy.type_playbooks
    }
    reason = (
        "NO_TYPE"
        if not types
        else "MULTIPLE_TYPES"
        if len(types) > 1
        else "TYPE_MATCH"
        if types[0] in mappings
        else "TYPE_NOT_ALLOWED"
    )
    expected_ref = (
        mappings[types[0]] if reason == "TYPE_MATCH" else policy.common_playbook_ref
    )
    if (
        application.selection_reason != reason
        or application.playbook_ref != expected_ref
        or application.selection != playbook.scope
        or application.selected_type != playbook.vulnerability_type
    ):
        raise ValueError("PLAYBOOK_SELECTION_MISMATCH")
    if [(q.template_key, q.question) for q in application.questions] != [
        (q.template_key, q.question) for q in playbook.falsification_question_templates
    ]:
        raise ValueError("PLAYBOOK_QUESTION_DRIFT")
    unique(
        [
            *(q.question_id for q in application.questions),
            *(q.question_id for q in hypothesis.falsification_questions),
        ]
    )


def validate_verification_closure(
    result: VerificationResult,
    hypothesis: VulnerabilityHypothesis,
    proposal: HypothesisProposal,
    application: PlaybookApplication,
    pro: EvidenceAgentResult | None,
    con: EvidenceAgentResult | None,
    *,
    current_work_id: WorkId,
    current_generation: int,
    purpose: Literal["PRODUCTION", "EVALUATION"] = "PRODUCTION",
) -> None:
    same_scope(result.meta, hypothesis.meta)
    exact(result.playbook_application_ref, application, result.meta)
    exact(application.hypothesis_ref, hypothesis, result.meta)
    exact(hypothesis.proposal_ref, proposal, result.meta)
    if (
        application.verification_work_id != current_work_id
        or application.verification_generation != current_generation
        or result.playbook_ref != application.playbook_ref
    ):
        raise ValueError("STALE_RESULT")
    if purpose == "PRODUCTION" and result.verification_mode != "ALWAYS_DEBATE":
        raise ValueError("PRODUCTION_DEBATE_REQUIRED")
    exact_set(
        (q.question_id for q in result.falsification_results),
        [
            *(q.question_id for q in hypothesis.falsification_questions),
            *(q.question_id for q in application.questions),
        ],
    )
    exact_set(
        (v.validation_id for v in result.validation_results),
        (v.validation_id for v in hypothesis.validation_checks),
    )
    for restriction in proposal.restrictions:
        if restriction not in result.restrictions:
            raise ValueError("RESTRICTION_DROPPED")
    if result.debate_input_hash is not None:
        if (
            pro is None
            or con is None
            or result.pro_evidence_ref is None
            or result.con_evidence_ref is None
        ):
            raise ValueError("DEBATE_CLOSURE_REQUIRED")
        validate_evidence_pair(
            pro,
            con,
            parent_work_id=current_work_id,
            generation=current_generation,
            debate_input_hash=result.debate_input_hash,
        )
        for ref, target in (
            (result.pro_evidence_ref, pro),
            (result.con_evidence_ref, con),
        ):
            exact(ref, target, result.meta)
            same_scope(result.meta, target.meta)
        exact_set(
            (c for c in result.supporting_evidence if c.source_role == "PRO"),
            pro.evidence,
        )
        exact_set(
            (c for c in result.counter_evidence if c.source_role == "CON"), con.evidence
        )
