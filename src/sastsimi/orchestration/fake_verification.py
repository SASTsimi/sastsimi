"""Evidence, dynamic reproduction and Verification generation stages."""

import asyncio
from typing import Any

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.gates import (
    TechnicalEvidenceReview,
)
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    HypothesisProposal,
    VulnerabilityHypothesis,
)
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import StaticFactBundle
from sastsimi.contracts.verification import (
    ConEvidenceResult,
    ProEvidenceResult,
    VerificationInitialAssessment,
    VerificationResult,
)

from .fake_base import ANALYSIS_ID
from .fake_configuration import register_fake_llm_call
from .fake_verification_initial import FakeInitialVerificationStages


class FakeVerificationStages(FakeInitialVerificationStages):
    def _revised_verification(
        self,
        prior: VerificationResult,
        review: TechnicalEvidenceReview,
    ) -> VerificationResult:
        """Run the same assignment owner through a fresh canonical generation."""
        assert self.runtime is not None and self.runner is not None
        state = self.runtime.budget_registry.current_state(str(ANALYSIS_ID))
        scope = state.budget_binding_ref
        assert scope is not None
        (hypothesis,) = self.runtime.queries.current_records(
            str(ANALYSIS_ID), "vulnerability_hypothesis"
        )
        (process,) = self.runtime.queries.current_records(
            str(ANALYSIS_ID), "hypothesis_process_state"
        )
        (bundle,) = self.runtime.queries.current_records(
            str(ANALYSIS_ID), "static_fact_bundle"
        )
        assert isinstance(hypothesis, VulnerabilityHypothesis)
        assert isinstance(process, HypothesisProcessState)
        assert isinstance(bundle, StaticFactBundle)
        application = self.runtime.unit_of_work.records.get_exact(
            prior.playbook_application_ref
        )
        from sastsimi.contracts.verification import PlaybookApplication

        assert isinstance(application, PlaybookApplication)
        hypothesis_ref = reference(hypothesis)
        process_ref = reference(process)
        review_ref = reference(review)
        assert isinstance(hypothesis_ref, StoredDataRef)
        assert isinstance(process_ref, StoredDataRef)
        assert isinstance(review_ref, StoredDataRef)
        proposal_ref = hypothesis.proposal_ref
        proposal = self.runtime.unit_of_work.records.get_exact(proposal_ref)
        assert isinstance(proposal, HypothesisProposal)
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
        self.evidence.identities[owner_ref] = RequesterRole.VERIFICATION
        self.evidence.identities[orchestrator_ref] = RequesterRole.ORCHESTRATION
        registered = self.runtime.verification_registration.revise(
            technical_review_ref=review_ref,
            hypothesis_ref=hypothesis_ref,
            proposal_ref=proposal_ref,
            policy_ref=application.policy_ref,
            playbook_ref=application.playbook_ref,
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
                generation=verification_work.work_generation,
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
        app_ref = reference(registered.application)
        assert isinstance(pro_ref, StoredDataRef)
        assert isinstance(con_ref, StoredDataRef)
        assert isinstance(app_ref, StoredDataRef)
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
        observation = self._artifact("observation")
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
                    policy_ref=application.policy_ref,
                    playbook_ref=application.playbook_ref,
                    playbook_application_ref=app_ref,
                    pro_evidence_ref=pro_ref,
                    con_evidence_ref=con_ref,
                    next_step="POC_CONFIRMATION",
                    proposed_verdict="TRUE",
                    rationale="The revised generation closed the request",
                    evidence_refs=(evidence_ref,),
                    unresolved_conditions=(),
                    llm_call_id="fake-revised-synthesis",
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
                    playbook_ref=application.playbook_ref,
                    playbook_application_ref=app_ref,
                    verification_mode="ALWAYS_DEBATE",
                    debate_triggers=(),
                    debate_skip_reason=None,
                    debate_input_hash=pro.debate_input_hash,
                    pro_evidence_ref=pro_ref,
                    con_evidence_ref=con_ref,
                    supporting_evidence=(
                        dict(
                            claim_id="fake-revised-poc",
                            statement="The revised PoC reached the sink",
                            source_role="VERIFICATION",
                            evidence_refs=(observation,),
                            code_locations=(self._location(),),
                            limitations=(),
                        ),
                    ),
                    counter_evidence=(),
                    falsification_results=(
                        dict(
                            question_id="reachability",
                            outcome="NOT_DISPROVED",
                            evidence_refs=(evidence_ref,),
                            rationale="The revised proof is supported",
                        ),
                    ),
                    validation_results=(
                        dict(
                            validation_id="path",
                            completion="COMPLETE",
                            evidence_refs=(evidence_ref,),
                            summary="The revised exact path was checked",
                        ),
                    ),
                    initial_verdict="TRUE",
                    dynamic_request_ref=reference(request),
                    dynamic_result_ref=reference(dynamic),
                    poc_ref=reference(poc),
                    verdict="TRUE",
                    verdict_rationale="Deterministic revised fake outcome",
                    restrictions=(),
                    bypass_candidates=(),
                    required_primitive_candidates=(
                        dict(
                            draft_id="fake-input",
                            entity_refs=(),
                            privilege_level=None,
                            evidence_refs=(observation,),
                            description="Attacker-controlled input",
                        ),
                    ),
                    provided_primitive_candidates=(
                        dict(
                            draft_id="fake-output",
                            entity_refs=(),
                            privilege_level="application",
                            evidence_refs=(observation,),
                            description="Validated revised sink execution",
                        ),
                    ),
                    impact_escalation_candidates=(),
                    material_child_proposals=(),
                    unresolved_conditions=(),
                    metrics=dict(
                        pro_tokens=1,
                        con_tokens=1,
                        synthesis_tokens=1,
                        elapsed_ms=1,
                        verdict_changed_after_debate=False,
                        hold_resolved=False,
                        false_positive_reduction_candidate=False,
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

    def _gate_decision(
        self,
        work: Any,
        scope: StoredDataRef,
        identity: StoredDataRef,
        config_role: RequesterRole,
        action_type: str,
    ) -> StoredDataRef:
        assert self.runtime is not None and self.runner is not None
        self.evidence.identities[identity] = RequesterRole.VERIFICATION
        result_kind = {
            "CALL_TECHNICAL_GATE": "technical_evidence_review",
            "CALL_RULE_SCOPE_GATE": "rule_scope_impact_review",
            "CREATE_REPORT_DRAFT": "report_draft",
        }[action_type]
        call_ref, provider_ref = register_fake_llm_call(
            self.runtime,
            self.evidence,
            self._record_meta,
            lambda kind: self._artifact(kind, record=True),
            self.clock.now(),
            role=config_role.value,
            result_kind=result_kind,
        )
        action = self.runner.action(
            work,
            identity,
            "VERIFICATION",
            action_type,
            llm_call_spec_ref=call_ref,
            provider_profile_ref=provider_ref,
            session_mode="NEW",
        )
        usage = self.runner.units(
            elapsed_ms=1,
            llm_call_count=1,
            cost_minor_units=1,
        )
        reservation = self.runner.reserve(work, scope, action, usage)
        decision = self.runner.authorize(work, action, reservation)

        async def accepted() -> str:
            return "fake-gate-accepted"

        asyncio.run(
            self.runtime.external.invoke(
                str(work.work_id),
                decision,
                reference(reservation),
                accepted,
                idempotency_key=str(action.action_id),
            )
        )
        self.runner.account(reservation, usage)
        assert isinstance(decision, StoredDataRef)
        return decision
