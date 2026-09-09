"""CWE, gates, primitives, chaining, reporting and finalization stages."""

from typing import Literal

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.chaining import (
    ChainingResult,
    Primitive,
    PrimitiveAdmissionDecision,
)
from sastsimi.contracts.dynamic import (
    DynamicReproductionResult,
    PoCBundle,
)
from sastsimi.contracts.gates import (
    CWELabel,
    RuleScopeImpactReview,
    TechnicalEvidenceReview,
)
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
)
from sastsimi.contracts.policy import (
    PolicyCollectionResult,
    ProgramPolicyRecord,
    RunPolicyState,
)
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef, reference
from sastsimi.contracts.reporting import Finding, ReportDraft, condition_sources
from sastsimi.contracts.verification import (
    VerificationResult,
)

from .fake_base import ANALYSIS_ID, COMMIT_ID, WORKSPACE_ID
from .fake_verification import FakeVerificationStages


class FakeGateStages(FakeVerificationStages):
    def _post_true(
        self,
        verification: VerificationResult,
        *,
        technical_status: Literal["ACCEPT", "REVISE"] = "ACCEPT",
    ) -> TechnicalEvidenceReview:
        assert self.runtime is not None and self.runner is not None
        state = self.runtime.budget_registry.current_state(str(ANALYSIS_ID))
        (process,) = self.runtime.queries.current_records(
            str(ANALYSIS_ID), "hypothesis_process_state"
        )
        assert isinstance(process, HypothesisProcessState)
        generation = process.verification_generation
        scope = state.budget_binding_ref
        assert scope is not None
        owner_ref = next(
            ref
            for ref in self.evidence.identities
            if isinstance(ref, StoredDataRef) and ref.data_kind == "work_budget_profile"
        )
        orchestrator_ref = next(
            ref
            for ref in self.evidence.identities
            if isinstance(ref, StoredDataRef)
            and ref.data_kind == "verification_budget_profile"
        )
        verification_ref = reference(verification)
        assert isinstance(verification_ref, StoredDataRef)
        assert verification.dynamic_result_ref is not None
        assert verification.poc_ref is not None
        dynamic = self.runtime.unit_of_work.records.get_exact(
            verification.dynamic_result_ref
        )
        poc = self.runtime.unit_of_work.records.get_exact(verification.poc_ref)
        assert isinstance(dynamic, DynamicReproductionResult)
        assert isinstance(poc, PoCBundle)
        hypothesis_id = str(verification.meta.hypothesis_id)
        observation = self._artifact("observation")
        assert isinstance(observation, StoredDataRef)

        self.evidence.identities[orchestrator_ref] = RequesterRole.ORCHESTRATION
        cwe_work = self.runner.start(
            scope,
            verification.meta,
            "CWE_LABEL",
            "HYPOTHESIS",
            hypothesis_id,
            orchestrator_ref,
            inputs=(verification_ref,),
            parent=self._verification_work_ref,
            generation=generation,
        )
        workspace_ref = self.runtime.budget_registry.current_state(
            str(ANALYSIS_ID)
        ).workspace_ref
        assert workspace_ref is not None
        cwe_identity = reference(
            self.runtime.unit_of_work.records.get_exact(workspace_ref)
        )
        assert isinstance(cwe_identity, RunStoredDataRef)
        self.evidence.identities[cwe_identity] = RequesterRole.CWE_LABELING
        prior_labels = tuple(
            item
            for item in self.runtime.queries.current_records(
                str(ANALYSIS_ID), "cwe_label"
            )
            if isinstance(item, CWELabel)
        )
        label_meta = (
            self.runner.revision_metadata(
                prior_labels[0].meta,
                attempt_id=cwe_work.active_attempt_id,
            )
            if prior_labels
            else self.runner.metadata(
                cwe_work.meta,
                "cwe_label",
                attempt_id=cwe_work.active_attempt_id,
            )
        )
        label = CWELabel.model_validate_json(
            canonical_bytes(
                dict(
                    meta=label_meta,
                    verification_result_ref=verification_ref,
                    verification_generation=cwe_work.work_generation,
                    cwe_labeling_work_id=cwe_work.work_id,
                    llm_call_id="fake-cwe-call",
                    primary="CWE-79",
                    alternatives=(),
                    taxonomy_version="4.16",
                    rationale="The executed path reaches an unsafe sink",
                    evidence_refs=(observation,),
                    uncertainty=None,
                )
            )
        )
        cwe_work = self.runner.complete(
            cwe_work, cwe_identity, "CWE_LABELING", (label,)
        )
        label_ref = cwe_work.output_refs[0]
        assert isinstance(label_ref, StoredDataRef)

        technical_work = self.runner.start(
            scope,
            verification.meta,
            "TECHNICAL_GATE",
            "HYPOTHESIS",
            hypothesis_id,
            orchestrator_ref,
            inputs=(
                verification_ref,
                verification.dynamic_result_ref,
                verification.poc_ref,
                label_ref,
            ),
            generation=generation,
        )
        binding_ref = self.runtime.budget_registry.current_state(
            str(ANALYSIS_ID)
        ).budget_binding_ref
        assert binding_ref is not None
        technical_identity = reference(
            self.runtime.unit_of_work.records.get_exact(binding_ref)
        )
        assert isinstance(technical_identity, StoredDataRef)
        technical_decision = self._gate_decision(
            technical_work,
            scope,
            owner_ref,
            RequesterRole.TECHNICAL_GATE,
            "CALL_TECHNICAL_GATE",
        )
        prior_reviews = tuple(
            item
            for item in self.runtime.queries.current_records(
                str(ANALYSIS_ID), "technical_evidence_review"
            )
            if isinstance(item, TechnicalEvidenceReview)
        )
        technical_meta = (
            self.runner.revision_metadata(
                prior_reviews[0].meta,
                attempt_id=technical_work.active_attempt_id,
            )
            if prior_reviews
            else self.runner.metadata(
                technical_work.meta,
                "technical_evidence_review",
                attempt_id=technical_work.active_attempt_id,
            )
        )
        technical = TechnicalEvidenceReview.model_validate_json(
            canonical_bytes(
                dict(
                    meta=technical_meta,
                    action_decision_ref=technical_decision,
                    verification_result_ref=verification_ref,
                    cwe_label_ref=label_ref,
                    status=technical_status,
                    evidence_verdict_alignment="The PoC supports TRUE",
                    code_flow_linkage="The reviewed path is exact",
                    dynamic_linkage="The exact PoC execution is linked",
                    cwe_assessment="CWE-79 is consistent",
                    restriction_assessment="No restrictions apply",
                    handoff_readiness="READY"
                    if technical_status == "ACCEPT"
                    else "NOT_READY",
                    revision_requests=()
                    if technical_status == "ACCEPT"
                    else ("Re-run the dynamic proof in a new generation",),
                    verification_requests=()
                    if technical_status == "ACCEPT"
                    else ("Produce a new generation PoC",),
                    rationale="All technical evidence is closed"
                    if technical_status == "ACCEPT"
                    else "Technical revision requires a fresh generation",
                )
            )
        )
        self.evidence.identities[technical_identity] = RequesterRole.TECHNICAL_GATE
        technical_work = self.runner.complete(
            technical_work,
            technical_identity,
            "TECHNICAL_GATE",
            (technical,),
        )
        technical_ref = technical_work.output_refs[0]
        assert isinstance(technical_ref, StoredDataRef)
        if technical_status == "REVISE":
            return technical

        assert state.run_policy_state_ref is not None
        policy_state = self.runtime.unit_of_work.records.get_exact(
            state.run_policy_state_ref
        )
        assert isinstance(policy_state, RunPolicyState)
        assert policy_state.collection_result_ref is not None
        assert policy_state.policy_record_ref is not None
        collection = self.runtime.unit_of_work.records.get_exact(
            policy_state.collection_result_ref
        )
        policy_record = self.runtime.unit_of_work.records.get_exact(
            policy_state.policy_record_ref
        )
        assert isinstance(collection, PolicyCollectionResult)
        assert isinstance(policy_record, ProgramPolicyRecord)
        rule_inputs = (
            verification_ref,
            verification.dynamic_result_ref,
            verification.poc_ref,
            label_ref,
            technical_ref,
            state.run_policy_state_ref,
            policy_state.collection_result_ref,
            policy_state.policy_record_ref,
        )
        rule_work = self.runner.start(
            scope,
            verification.meta,
            "RULE_SCOPE_GATE",
            "HYPOTHESIS",
            hypothesis_id,
            orchestrator_ref,
            inputs=rule_inputs,
            generation=generation,
        )
        rule_identity = reference(policy_record)
        assert isinstance(rule_identity, StoredDataRef)
        rule_decision = self._gate_decision(
            rule_work,
            scope,
            owner_ref,
            RequesterRole.RULE_SCOPE_GATE,
            "CALL_RULE_SCOPE_GATE",
        )
        links = tuple(
            dict(
                link_id=f"fake-{area.lower()}",
                area=area,
                policy_item_ids=(),
                evidence_refs=(observation,),
            )
            for area in ("RULE", "SCOPE", "IMPACT", "TESTING_RESTRICTION")
        )
        review = RuleScopeImpactReview.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(
                        rule_work.meta,
                        "rule_scope_impact_review",
                        attempt_id=rule_work.active_attempt_id,
                    ),
                    action_decision_ref=rule_decision,
                    verification_result_ref=verification_ref,
                    technical_review_ref=technical_ref,
                    cwe_label_ref=label_ref,
                    run_policy_state_ref=state.run_policy_state_ref,
                    policy_collection_result_ref=policy_state.collection_result_ref,
                    policy_record_ref=policy_state.policy_record_ref,
                    review_status="PASS",
                    rule_compliance="PASS",
                    scope_compliance="PASS",
                    testing_restriction_compliance="PASS",
                    security_impact="SUFFICIENT",
                    report_permission="ALLOW",
                    evidence_links=links,
                    reasons=(),
                    missing_information=(),
                )
            )
        )
        self.evidence.identities[rule_identity] = RequesterRole.RULE_SCOPE_GATE
        rule_work = self.runner.complete(
            rule_work, rule_identity, "RULE_SCOPE_GATE", (review,)
        )
        review_ref = rule_work.output_refs[0]
        assert isinstance(review_ref, StoredDataRef)

        primitive_work = self.runner.start(
            scope,
            verification.meta,
            "PRIMITIVE_UPDATE",
            "HYPOTHESIS",
            hypothesis_id,
            orchestrator_ref,
            inputs=(
                verification_ref,
                technical_ref,
                policy_state.collection_result_ref,
                review_ref,
            ),
            generation=generation,
        )
        primitive_identity = label_ref
        self.evidence.identities[primitive_identity] = (
            RequesterRole.PRIMITIVE_ADMISSION_RUNTIME
        )
        admission = PrimitiveAdmissionDecision.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(
                        primitive_work.meta,
                        "primitive_admission_decision",
                        attempt_id=primitive_work.active_attempt_id,
                    ),
                    verification_result_ref=verification_ref,
                    technical_review_ref=technical_ref,
                    policy_collection_result_ref=policy_state.collection_result_ref,
                    rule_scope_review_ref=review_ref,
                    testing_restriction_compliance="PASS",
                    decision="ALLOW",
                    reason_code="TESTING_RESTRICTION_PASSED",
                    decided_at=self.clock.now(),
                )
            )
        )
        admission_ref = reference(admission)
        assert isinstance(admission_ref, StoredDataRef)
        primitive = Primitive.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(
                        primitive_work.meta,
                        "primitive",
                        attempt_id=primitive_work.active_attempt_id,
                    ),
                    primitive_id="fake-primitive",
                    workspace_id=WORKSPACE_ID,
                    commit_id=COMMIT_ID,
                    inputs=verification.required_primitive_candidates,
                    result=verification.provided_primitive_candidates[0],
                    restrictions=verification.restrictions,
                    source_hypothesis_id=verification.meta.hypothesis_id,
                    source_verification_ref=verification_ref,
                    technical_review_ref=technical_ref,
                    admission_decision_ref=admission_ref,
                    evidence_refs=(observation,),
                    description="Deterministic validated primitive",
                )
            )
        )
        primitive_ref = reference(primitive)
        assert isinstance(primitive_ref, StoredDataRef)
        self.evidence.next_outputs = (admission_ref, primitive_ref)
        try:
            primitive_work = self.runner.complete(
                primitive_work,
                primitive_identity,
                "PRIMITIVE_ADMISSION_RUNTIME",
                (admission, primitive),
            )
        finally:
            self.evidence.next_outputs = None

        chaining_work = self.runner.start(
            scope,
            verification.meta,
            "CHAINING",
            "ANALYSIS",
            str(ANALYSIS_ID),
            orchestrator_ref,
            inputs=(primitive_ref,),
            trigger_primitive_ref=primitive_ref,
            generation=generation,
        )
        chaining_identity = review_ref
        self.evidence.identities[chaining_identity] = RequesterRole.CHAINING
        chaining = ChainingResult.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(
                        chaining_work.meta,
                        "chaining_result",
                        attempt_id=chaining_work.active_attempt_id,
                    ),
                    source_result_refs=(),
                    considered_primitive_refs=(primitive_ref,),
                    input_primitive_refs=(),
                    primitive_match_candidates=(),
                    chained_hypothesis_proposals=(),
                    excluded_lineage_refs=(),
                    no_match_reasons=(
                        dict(
                            upstream_result_ref=primitive_ref,
                            downstream_input_ref=primitive_ref,
                            checked_input_id="fake-input",
                            reason_code="ENTITY_UNRELATED",
                            detail="No distinct downstream primitive exists",
                        ),
                    ),
                    errors=(),
                )
            )
        )
        self.runner.complete(chaining_work, chaining_identity, "CHAINING", (chaining,))

        finding_work = self.runner.start(
            scope,
            verification.meta,
            "FINDING_NORMALIZE",
            "HYPOTHESIS",
            hypothesis_id,
            orchestrator_ref,
            inputs=(*rule_inputs, review_ref, primitive_ref),
            parent=reference(rule_work),
            generation=generation,
        )
        upstream = (
            (verification_ref, verification),
            (verification.dynamic_result_ref, dynamic),
            (verification.poc_ref, poc),
            (label_ref, label),
            (technical_ref, technical),
            (review_ref, review),
            (policy_state.collection_result_ref, collection),
        )
        assert verification.pro_evidence_ref is not None
        assert verification.con_evidence_ref is not None
        source_evidence_ref = verification.falsification_results[0].evidence_refs[0]
        finding = Finding.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(
                        finding_work.meta,
                        "finding",
                        attempt_id=finding_work.active_attempt_id,
                    ),
                    verification_result_ref=verification_ref,
                    dynamic_result_ref=verification.dynamic_result_ref,
                    poc_ref=verification.poc_ref,
                    cwe_label_ref=label_ref,
                    technical_review_ref=technical_ref,
                    rule_scope_impact_review_ref=review_ref,
                    policy_collection_result_ref=policy_state.collection_result_ref,
                    policy_record_ref=policy_state.policy_record_ref,
                    evidence_refs=(
                        verification.pro_evidence_ref,
                        verification.con_evidence_ref,
                        source_evidence_ref,
                        observation,
                    ),
                    condition_sources=condition_sources(upstream),
                )
            )
        )
        self.evidence.identities[owner_ref] = RequesterRole.VERIFICATION
        finding_work = self.runner.complete(
            finding_work, owner_ref, "VERIFICATION", (finding,)
        )
        finding_ref = finding_work.output_refs[0]
        assert isinstance(finding_ref, StoredDataRef)

        report_work = self.runner.start(
            scope,
            verification.meta,
            "REPORT_DRAFT",
            "REPORT",
            "fake-report",
            orchestrator_ref,
            inputs=(*rule_inputs, review_ref, finding_ref),
            generation=generation,
        )
        report_identity = primitive_ref
        report_decision = self._gate_decision(
            report_work,
            scope,
            owner_ref,
            RequesterRole.REPORTER,
            "CREATE_REPORT_DRAFT",
        )
        draft = ReportDraft.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(
                        report_work.meta,
                        "report_draft",
                        attempt_id=report_work.active_attempt_id,
                    ),
                    action_decision_ref=report_decision,
                    finding_ref=finding_ref,
                    verification_result_ref=verification_ref,
                    technical_review_ref=technical_ref,
                    rule_scope_impact_review_ref=review_ref,
                    cwe_label_ref=label_ref,
                    run_policy_state_ref=state.run_policy_state_ref,
                    policy_record_ref=policy_state.policy_record_ref,
                    dynamic_result_ref=verification.dynamic_result_ref,
                    poc_ref=verification.poc_ref,
                    content_ref=self._artifact("report_content", record=True),
                    restrictions=verification.restrictions,
                    limitations=(),
                    unresolved_conditions=(),
                    redaction_status="PASSED",
                    draft_status="DRAFTED",
                )
            )
        )
        self.evidence.identities[report_identity] = RequesterRole.REPORTER
        self.runner.complete(report_work, report_identity, "REPORTER", (draft,))
        return technical
