"""Evidence, dynamic reproduction and Verification generation stages."""

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    VulnerabilityHypothesis,
)
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.verification import (
    ConEvidenceResult,
    ProEvidenceResult,
    VerificationInitialAssessment,
    VerificationResult,
)

from .fake_base import ANALYSIS_ID
from .fake_dynamic import FakeDynamicStages


class FakeInitialVerificationStages(FakeDynamicStages):
    def _verification(self, verdict: str) -> VerificationResult:
        scope, owner_ref, orchestrator_ref = self._bootstrap()
        assert self.runtime is not None and self.runner is not None
        self._prepare_policy(scope, orchestrator_ref)
        proposal, bundle = self._prepare_hypothesis(scope, orchestrator_ref)
        (hypothesis,) = self.runtime.queries.current_records(
            str(ANALYSIS_ID), "vulnerability_hypothesis"
        )
        (process,) = self.runtime.queries.current_records(
            str(ANALYSIS_ID), "hypothesis_process_state"
        )
        assert isinstance(hypothesis, VulnerabilityHypothesis)
        assert isinstance(process, HypothesisProcessState)
        hypothesis_ref = reference(hypothesis)
        proposal_ref = reference(proposal)
        process_ref = reference(process)
        assert isinstance(hypothesis_ref, StoredDataRef)
        assert isinstance(proposal_ref, StoredDataRef)
        assert isinstance(process_ref, StoredDataRef)
        book_ref, policy_ref = self._playbooks()
        self.evidence.identities[orchestrator_ref] = RequesterRole.ORCHESTRATION
        self.evidence.identities[owner_ref] = RequesterRole.VERIFICATION
        registered = self.runtime.verification_registration.register(
            hypothesis_ref=hypothesis_ref,
            proposal_ref=proposal_ref,
            policy_ref=policy_ref,
            playbook_ref=book_ref,
            expected_process_ref=process_ref,
            owner_identity_ref=owner_ref,
            requester_identity_ref=orchestrator_ref,
            budget_binding_ref=scope,
        )
        verification_work = self.runner.activate(
            registered.work, scope, owner_ref, role="VERIFICATION"
        )
        evidence_ref = reference(bundle)
        assert isinstance(evidence_ref, StoredDataRef)
        evidence_results: list[ProEvidenceResult | ConEvidenceResult] = []
        identities = (orchestrator_ref, proposal_ref)
        for role, identity in zip(("PRO", "CON"), identities, strict=True):
            self.evidence.identities[identity] = RequesterRole(role)
            child = self.runner.start(
                scope,
                verification_work.meta,
                f"{role}_EVIDENCE",
                "HYPOTHESIS",
                str(hypothesis.meta.hypothesis_id),
                owner_ref,
                role="VERIFICATION",
                inputs=(evidence_ref,),
                parent=reference(verification_work),
            )
            result = self._evidence_result(
                role=role,
                work=child,
                parent_work=verification_work,
                evidence_ref=evidence_ref,
            )
            self.runner.complete(child, identity, role, (result,))
            evidence_results.append(result)
        pro, con = evidence_results
        pro_ref, con_ref = reference(pro), reference(con)
        application_ref = reference(registered.application)
        assert isinstance(pro_ref, StoredDataRef)
        assert isinstance(con_ref, StoredDataRef)
        assert isinstance(application_ref, StoredDataRef)
        dynamic_request_ref = None
        dynamic_result_ref = None
        poc_ref = None
        supporting_evidence: tuple[dict[str, object], ...] = ()
        required_primitives: tuple[dict[str, object], ...] = ()
        provided_primitives: tuple[dict[str, object], ...] = ()
        if verdict == "TRUE":
            request, dynamic, poc = self._dynamic_chain(
                scope=scope,
                owner_ref=owner_ref,
                orchestrator_ref=orchestrator_ref,
                verification_work=verification_work,
                assignment_ref=registered.assignment_ref,
                hypothesis_ref=hypothesis_ref,
                evidence_ref=evidence_ref,
                pro_ref=pro_ref,
                con_ref=con_ref,
            )
            dynamic_request_ref = reference(request)
            dynamic_result_ref = reference(dynamic)
            poc_ref = reference(poc)
            supporting_evidence = (
                dict(
                    claim_id="fake-executed-poc",
                    statement="The deterministic PoC reached the sink",
                    source_role="VERIFICATION",
                    evidence_refs=(self._artifact("observation"),),
                    code_locations=(self._location(),),
                    limitations=(),
                ),
            )
            required_primitives = (
                dict(
                    draft_id="fake-input",
                    entity_refs=(),
                    privilege_level=None,
                    evidence_refs=(self._artifact("observation"),),
                    description="Attacker-controlled input",
                ),
            )
            provided_primitives = (
                dict(
                    draft_id="fake-output",
                    entity_refs=(),
                    privilege_level="application",
                    evidence_refs=(self._artifact("observation"),),
                    description="Validated sink execution",
                ),
            )
        falsification_outcome = {
            "FALSE": "DISPROVED",
            "HOLD": "INCONCLUSIVE",
            "TRUE": "NOT_DISPROVED",
        }[verdict]
        assessment = VerificationInitialAssessment.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(
                        verification_work.meta,
                        "verification_initial_assessment",
                        attempt_id=verification_work.active_attempt_id,
                    ),
                    verification_work_id=verification_work.work_id,
                    verification_generation=verification_work.work_generation,
                    hypothesis_ref=hypothesis_ref,
                    policy_ref=policy_ref,
                    playbook_ref=book_ref,
                    playbook_application_ref=application_ref,
                    pro_evidence_ref=pro_ref,
                    con_evidence_ref=con_ref,
                    next_step="POC_CONFIRMATION"
                    if verdict == "TRUE"
                    else "FINALIZE_WITHOUT_DYNAMIC",
                    proposed_verdict=verdict,
                    rationale="The deterministic debate is complete",
                    evidence_refs=(evidence_ref,),
                    unresolved_conditions=("Reachability",)
                    if verdict == "HOLD"
                    else (),
                    llm_call_id="fake-synthesis",
                )
            )
        )
        save = self.runner.action(
            verification_work,
            owner_ref,
            "VERIFICATION",
            "SAVE_RESULT",
            result_kind="verification_initial_assessment",
            candidate_result_ref=self.runtime.unit_of_work.records.stage_record(
                assessment
            ),
        )
        self.runtime.intermediate.publish(
            str(verification_work.work_id),
            self.runner.authorize(verification_work, save),
            (assessment,),
        )
        final = VerificationResult.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(
                        verification_work.meta,
                        "verification_result",
                        attempt_id=verification_work.active_attempt_id,
                    ),
                    playbook_ref=book_ref,
                    playbook_application_ref=application_ref,
                    verification_mode="ALWAYS_DEBATE",
                    debate_triggers=(),
                    debate_skip_reason=None,
                    debate_input_hash=pro.debate_input_hash,
                    pro_evidence_ref=pro_ref,
                    con_evidence_ref=con_ref,
                    supporting_evidence=supporting_evidence,
                    counter_evidence=(),
                    falsification_results=(
                        dict(
                            question_id="reachability",
                            outcome=falsification_outcome,
                            evidence_refs=(evidence_ref,),
                            rationale="The fake evidence determines this outcome",
                        ),
                    ),
                    validation_results=(
                        dict(
                            validation_id="path",
                            completion="COMPLETE",
                            evidence_refs=(evidence_ref,),
                            summary="The exact fake path was checked",
                        ),
                    ),
                    initial_verdict=verdict,
                    dynamic_request_ref=dynamic_request_ref,
                    dynamic_result_ref=dynamic_result_ref,
                    poc_ref=poc_ref,
                    verdict=verdict,
                    verdict_rationale="Deterministic fake outcome",
                    restrictions=(),
                    bypass_candidates=(),
                    required_primitive_candidates=required_primitives,
                    provided_primitive_candidates=provided_primitives,
                    impact_escalation_candidates=(),
                    material_child_proposals=(),
                    unresolved_conditions=("Reachability",)
                    if verdict == "HOLD"
                    else (),
                    metrics=dict(
                        pro_tokens=1,
                        con_tokens=1,
                        synthesis_tokens=1,
                        elapsed_ms=1,
                        verdict_changed_after_debate=False,
                        hold_resolved=False,
                        false_positive_reduction_candidate=verdict == "FALSE",
                        new_bypass_count=0,
                        new_restriction_count=0,
                        new_falsification_count=0,
                    ),
                    errors=(),
                )
            )
        )
        self.evidence.identities[owner_ref] = RequesterRole.VERIFICATION
        verification_work = self.runner.complete(
            verification_work, owner_ref, "VERIFICATION", (final,)
        )
        self._verification_work_ref = reference(verification_work)
        return final
