"""Evidence, dynamic reproduction and Verification generation stages."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sastsimi.contracts.actions import RequesterRole
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
    VerificationInitialAssessment,
    VerificationResult,
)
from sastsimi.ports.verification_assembly import VerificationGenerationInputs

from .fake_base import ANALYSIS_ID, FakeStageService
from .fake_configuration import register_fake_llm_call
from .fake_context import retrieve_fake_context
from .fake_debate import run_fake_debate
from .fake_provider_runtime import invoke_fake_provider, persist_fake_invocation

if TYPE_CHECKING:
    from .fake_base import FakePipelineBase
    from .fake_dynamic import FakeDynamicStages
    from .fake_setup import FakeSetupStages


class FakeVerificationStages(FakeStageService):
    def __init__(
        self,
        host: FakePipelineBase,
        setup: FakeSetupStages,
        dynamic: FakeDynamicStages,
    ) -> None:
        super().__init__(host)
        self._setup = setup
        self._dynamic = dynamic

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
        assert self.context_service_identity_ref is not None
        _context, context_ref = retrieve_fake_context(
            runtime=self.runtime,
            runner=self.runner,
            evidence=self.evidence,
            scope=scope,
            identity=owner_ref,
            service_identity=self.context_service_identity_ref,
            metadata=hypothesis.meta,
            hypothesis_id=str(hypothesis.meta.hypothesis_id),
            generation=verification_work.work_generation,
            inputs=(hypothesis_ref, evidence_ref),
            location=self._setup._location(),
            fragment_ref=self._stored_artifact("revised-code-fragment"),
        )
        debate_inputs = (hypothesis_ref, evidence_ref, context_ref)
        debate = run_fake_debate(
            runtime=self.runtime,
            runner=self.runner,
            evidence=self.evidence,
            scope=scope,
            owner_ref=owner_ref,
            orchestrator_ref=orchestrator_ref,
            proposal_ref=proposal_ref,
            verification_work=verification_work,
            debate_inputs=debate_inputs,
            record_meta=self._record_meta,
            artifact=self._artifact,
            stored_artifact=self._stored_artifact,
            now=self.clock.now,
            build_evidence=lambda role, work, parent, inputs: (
                self._dynamic._evidence_result(
                    role=role,
                    work=work,
                    parent_work=parent,
                    debate_inputs=inputs,
                )
            ),
            provider_invoke=self.provider_invoke,
            provider_probe=self.provider_probe,
        )
        pro = debate.pro
        pro_ref, con_ref = debate.pro_ref, debate.con_ref
        app_ref = reference(registered.application)
        assert isinstance(app_ref, StoredDataRef)
        observation = self._artifact("observation")
        assert isinstance(observation, StoredDataRef)
        generation_inputs = VerificationGenerationInputs(
            work_id=verification_work.work_id,
            generation=verification_work.work_generation,
            hypothesis_ref=hypothesis_ref,
            policy_ref=application.policy_ref,
            playbook_ref=application.playbook_ref,
            application_ref=app_ref,
            pro_ref=pro_ref,
            con_ref=con_ref,
            debate_input_hash=pro.debate_input_hash,
            evidence_ref=evidence_ref,
            location=self._setup._location(),
        )
        assessment_candidate = self.verification_assembly.build_initial_assessment(
            meta=self.runner.metadata(
                verification_work.meta,
                "verification_initial_assessment",
                attempt_id=verification_work.active_attempt_id,
            ),
            inputs=generation_inputs,
            verdict="TRUE",
            revised=True,
        )
        synthesis_call_ref, synthesis_provider_ref = register_fake_llm_call(
            self.runtime,
            self.evidence,
            self._record_meta,
            self._artifact,
            self.clock.now(),
            self.provider_probe,
            runner=self.runner,
            scope=scope,
            orchestration_identity=owner_ref,
            role="VERIFICATION",
            result_kind="verification_initial_assessment",
            context_refs=(*debate_inputs, pro_ref, con_ref),
        )
        self.evidence.identities[owner_ref] = RequesterRole.VERIFICATION
        assessment_record, synthesis_invocation = invoke_fake_provider(
            runtime=self.runtime,
            runner=self.runner,
            work=verification_work,
            scope=scope,
            identity=owner_ref,
            action_role=RequesterRole.VERIFICATION,
            action_type="CALL_LLM",
            call_spec_ref=synthesis_call_ref,
            provider_profile_ref=synthesis_provider_ref,
            artifact=self._stored_artifact,
            build_output=lambda _decision: assessment_candidate,
            provider_invoke=self.provider_invoke,
        )
        assert isinstance(assessment_record, VerificationInitialAssessment)
        assessment = assessment_record
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
        (assessment_ref,) = self.runtime.intermediate.publish(
            str(verification_work.work_id),
            self.runner.authorize(verification_work, save),
            (assessment,),
        )
        assert isinstance(assessment_ref, StoredDataRef)
        persist_fake_invocation(self.runtime, synthesis_invocation, assessment_ref)
        request, dynamic, poc = self._dynamic._dynamic_chain(
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
        request_ref = reference(request)
        dynamic_ref = reference(dynamic)
        poc_ref = reference(poc)
        assert isinstance(request_ref, StoredDataRef)
        assert isinstance(dynamic_ref, StoredDataRef)
        assert isinstance(poc_ref, StoredDataRef)
        final = self.verification_assembly.build_result(
            meta=self.runner.metadata(
                verification_work.meta,
                "verification_result",
                attempt_id=verification_work.active_attempt_id,
            ),
            inputs=generation_inputs,
            verdict="TRUE",
            dynamic_request_ref=request_ref,
            dynamic_result_ref=dynamic_ref,
            poc_ref=poc_ref,
            observation_ref=observation,
            revised=True,
        )
        self.evidence.identities[owner_ref] = RequesterRole.VERIFICATION
        verification_work = self.runner.complete(
            verification_work, owner_ref, "VERIFICATION", (final,)
        )
        self._verification_work_ref = reference(verification_work)
        return final
