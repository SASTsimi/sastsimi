"""Shared deterministic Verification workflow for initial and REVISE generations."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from sastsimi.agents.verification import VerificationAgent, VerificationCallRefs
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.gates import TechnicalEvidenceReview
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    HypothesisProposal,
    VulnerabilityHypothesis,
)
from sastsimi.contracts.ids import RecordId, StoredDataId
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import CodeLocation, StaticFactBundle
from sastsimi.contracts.verification import (
    VerificationInitialAssessment,
    VerificationResult,
)
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.fake_workflow import (
    DynamicReproductionWorkflow,
    InitialVerificationInputs,
    ProviderInvoker,
    ProviderProber,
    VerificationExecution,
)
from sastsimi.ports.verification_assembly import (
    VerificationAssemblyPort,
    VerificationGenerationInputs,
)
from sastsimi.ports.verification_registration import VerificationRegistration
from sastsimi.runtime.fake_llm_configuration import register_fake_llm_call
from sastsimi.runtime.fake_llm_invocation import (
    invoke_fake_provider,
    persist_fake_invocation,
)
from sastsimi.runtime.fake_support import (
    ANALYSIS_ID,
    FakeClock,
    FakeEvidence,
    FakeRecordFactory,
)
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner

from .context_service import retrieve_fake_context
from .debate_service import run_fake_debate


@dataclass(frozen=True)
class VerificationDependencies:
    runtime: RuntimeServices
    runner: WorkflowRunner
    clock: FakeClock
    evidence: FakeEvidence
    records: FakeRecordFactory
    provider_invoke: ProviderInvoker
    provider_probe: ProviderProber
    assembly: VerificationAssemblyPort
    context_service_identity_ref: StoredDataRef
    location: Callable[[], CodeLocation]
    dynamic: DynamicReproductionWorkflow


def select_revise_context(
    hypotheses: tuple[VulnerabilityHypothesis, ...],
    processes: tuple[HypothesisProcessState, ...],
    hypothesis_id: object,
) -> tuple[VulnerabilityHypothesis, HypothesisProcessState]:
    """Resolve one hypothesis's exact current state without shared-host context."""
    matching_hypotheses = tuple(
        item for item in hypotheses if item.meta.hypothesis_id == hypothesis_id
    )
    matching_processes = tuple(
        item for item in processes if item.meta.hypothesis_id == hypothesis_id
    )
    if len(matching_hypotheses) != 1 or len(matching_processes) != 1:
        raise LookupError("EXACT_REVISED_VERIFICATION_CONTEXT_NOT_FOUND")
    return matching_hypotheses[0], matching_processes[0]


class VerificationService:
    """Own context, debate, assessment, optional dynamic and final verdict."""

    def __init__(
        self, dependencies: VerificationDependencies | VerificationAgent
    ) -> None:
        self._trusted_agent: VerificationAgent | None = None
        if isinstance(dependencies, VerificationAgent):
            self._trusted_agent = dependencies
            return
        self.runtime = dependencies.runtime
        self.runner = dependencies.runner
        self.clock = dependencies.clock
        self.evidence = dependencies.evidence
        self.provider_invoke = dependencies.provider_invoke
        self.provider_probe = dependencies.provider_probe
        self.assembly = dependencies.assembly
        self.context_service_identity_ref = dependencies.context_service_identity_ref
        self.location = dependencies.location
        self.dynamic = dependencies.dynamic
        self._record_meta = dependencies.records.record_meta
        self._artifact = dependencies.records.artifact
        self._stored_artifact = dependencies.records.stored_artifact

    async def assess_initial(
        self,
        *,
        generation: VerificationGenerationInputs,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
        call: VerificationCallRefs,
    ) -> VerificationInitialAssessment:
        """Finalize one successful T09 assessment artifact using trusted scope."""
        if self._trusted_agent is None:
            raise RuntimeError("TRUSTED_VERIFICATION_AGENT_NOT_CONFIGURED")
        return await self._trusted_agent.assess_initial(
            generation=generation,
            pro_ref=pro_ref,
            con_ref=con_ref,
            call=call,
        )

    async def finalize_without_dynamic(
        self,
        *,
        generation: VerificationGenerationInputs,
        assessment_ref: StoredDataRef,
        pro_ref: StoredDataRef,
        con_ref: StoredDataRef,
        call: VerificationCallRefs,
    ) -> VerificationResult:
        """Finalize only FALSE/HOLD; T11 owns all final TRUE prerequisites."""
        if self._trusted_agent is None:
            raise RuntimeError("TRUSTED_VERIFICATION_AGENT_NOT_CONFIGURED")
        return await self._trusted_agent.finalize_without_dynamic(
            generation=generation,
            assessment_ref=assessment_ref,
            pro_ref=pro_ref,
            con_ref=con_ref,
            call=call,
        )

    def run_initial(
        self,
        inputs: InitialVerificationInputs,
        verdict: str,
        *,
        invalid_poc: bool = False,
        material_child: bool = False,
    ) -> VerificationExecution:
        hypothesis_ref = reference(inputs.hypothesis)
        proposal_ref = reference(inputs.proposal)
        process_ref = reference(inputs.process)
        assert isinstance(hypothesis_ref, StoredDataRef)
        assert isinstance(proposal_ref, StoredDataRef)
        assert isinstance(process_ref, StoredDataRef)
        registered = self.runtime.verification_registration.register(
            hypothesis_ref=hypothesis_ref,
            proposal_ref=proposal_ref,
            policy_ref=inputs.policy_ref,
            playbook_ref=inputs.playbook_ref,
            expected_process_ref=process_ref,
            owner_identity_ref=inputs.owner_ref,
            requester_identity_ref=inputs.orchestrator_ref,
            budget_binding_ref=inputs.scope,
        )
        work = self.runner.activate(
            registered.work, inputs.scope, inputs.owner_ref, role="VERIFICATION"
        )
        return self._run_generation(
            scope=inputs.scope,
            owner_ref=inputs.owner_ref,
            orchestrator_ref=inputs.orchestrator_ref,
            registered=registered,
            work=work,
            hypothesis=inputs.hypothesis,
            proposal_ref=proposal_ref,
            bundle=inputs.bundle,
            policy_ref=inputs.policy_ref,
            playbook_ref=inputs.playbook_ref,
            verdict=verdict,
            revised=False,
            invalid_poc=invalid_poc,
            material_child=material_child,
        )

    def run_revised(
        self,
        prior: VerificationResult,
        review: TechnicalEvidenceReview,
    ) -> VerificationExecution:
        """Register a fresh generation, then use the same generation workflow."""
        state = self.runtime.budget_registry.current_state(str(ANALYSIS_ID))
        scope = state.budget_binding_ref
        assert scope is not None
        hypotheses = tuple(
            item
            for item in self.runtime.queries.current_records(
                str(ANALYSIS_ID), "vulnerability_hypothesis"
            )
            if isinstance(item, VulnerabilityHypothesis)
        )
        processes = tuple(
            item
            for item in self.runtime.queries.current_records(
                str(ANALYSIS_ID), "hypothesis_process_state"
            )
            if isinstance(item, HypothesisProcessState)
        )
        hypothesis, process = select_revise_context(
            hypotheses, processes, prior.meta.hypothesis_id
        )
        (bundle,) = self.runtime.queries.current_records(
            str(ANALYSIS_ID), "static_fact_bundle"
        )
        assert isinstance(hypothesis, VulnerabilityHypothesis)
        assert isinstance(process, HypothesisProcessState)
        assert isinstance(bundle, StaticFactBundle)
        from sastsimi.contracts.verification import PlaybookApplication

        application = self.runtime.unit_of_work.records.get_exact(
            prior.playbook_application_ref
        )
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
        owner_ref = self.evidence.stored_identity(RequesterRole.VERIFICATION)
        orchestrator_ref = self.evidence.stored_identity(RequesterRole.ORCHESTRATION)
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
        work = self.runner.activate(
            registered.work, scope, owner_ref, role="VERIFICATION"
        )
        return self._run_generation(
            scope=scope,
            owner_ref=owner_ref,
            orchestrator_ref=orchestrator_ref,
            registered=registered,
            work=work,
            hypothesis=hypothesis,
            proposal_ref=proposal_ref,
            bundle=bundle,
            policy_ref=application.policy_ref,
            playbook_ref=application.playbook_ref,
            verdict="TRUE",
            revised=True,
        )

    def _run_generation(
        self,
        *,
        scope: StoredDataRef,
        owner_ref: StoredDataRef,
        orchestrator_ref: StoredDataRef,
        registered: VerificationRegistration,
        work: WorkExecutionState,
        hypothesis: VulnerabilityHypothesis,
        proposal_ref: StoredDataRef,
        bundle: StaticFactBundle,
        policy_ref: StoredDataRef,
        playbook_ref: StoredDataRef,
        verdict: str,
        revised: bool,
        invalid_poc: bool = False,
        material_child: bool = False,
    ) -> VerificationExecution:
        """Execute the semantics shared by initial and Technical REVISE."""
        hypothesis_ref = reference(hypothesis)
        evidence_ref = reference(bundle)
        application_ref = reference(registered.application)
        assert isinstance(hypothesis_ref, StoredDataRef)
        assert isinstance(evidence_ref, StoredDataRef)
        assert isinstance(application_ref, StoredDataRef)
        _, context_ref = retrieve_fake_context(
            runtime=self.runtime,
            runner=self.runner,
            evidence=self.evidence,
            scope=scope,
            identity=owner_ref,
            service_identity=self.context_service_identity_ref,
            metadata=hypothesis.meta,
            hypothesis_id=str(hypothesis.meta.hypothesis_id),
            generation=work.work_generation,
            inputs=(hypothesis_ref, evidence_ref),
            location=self.location(),
            fragment_ref=self._stored_artifact(
                "revised-code-fragment" if revised else "code-fragment"
            ),
        )
        debate_inputs = tuple(
            ref
            for ref in dict.fromkeys((*work.input_refs, evidence_ref, context_ref))
            if isinstance(ref, StoredDataRef)
        )
        debate = run_fake_debate(
            runtime=self.runtime,
            runner=self.runner,
            evidence=self.evidence,
            scope=scope,
            owner_ref=owner_ref,
            orchestrator_ref=orchestrator_ref,
            verification_work=work,
            debate_inputs=debate_inputs,
            record_meta=self._record_meta,
            artifact=self._artifact,
            stored_artifact=self._stored_artifact,
            now=self.clock.now,
            provider_invoke=self.provider_invoke,
            provider_probe=self.provider_probe,
        )
        pro_ref, con_ref = debate.pro_ref, debate.con_ref
        generation_inputs = VerificationGenerationInputs(
            work_id=work.work_id,
            generation=work.work_generation,
            hypothesis_ref=hypothesis_ref,
            policy_ref=policy_ref,
            playbook_ref=playbook_ref,
            application_ref=application_ref,
            pro_ref=pro_ref,
            con_ref=con_ref,
            debate_input_hash=debate.pro.debate_input_hash,
            evidence_ref=evidence_ref,
            location=self.location(),
            falsification_question_ids=tuple(
                str(item.question_id) for item in hypothesis.falsification_questions
            )
            + tuple(str(item.question_id) for item in registered.application.questions),
            validation_ids=tuple(
                str(item.validation_id) for item in hypothesis.validation_checks
            ),
        )
        assessment_candidate = self.assembly.build_initial_assessment(
            meta=self.runner.metadata(
                work.meta,
                "verification_initial_assessment",
                attempt_id=work.active_attempt_id,
            ),
            inputs=generation_inputs,
            verdict=verdict,
            revised=revised,
        )
        synthesis_call_ref, synthesis_provider_ref = register_fake_llm_call(
            self.runtime,
            self.evidence,
            self._record_meta,
            self._artifact,
            self.clock.now(),
            self.provider_probe,
            runner=self.runner,
            work=work,
            scope=scope,
            orchestration_identity=orchestrator_ref,
            role="VERIFICATION",
            result_kind="verification_initial_assessment",
            context_refs=tuple(
                ref
                for ref in dict.fromkeys(
                    (*work.input_refs, *debate_inputs, pro_ref, con_ref)
                )
                if isinstance(ref, StoredDataRef)
            ),
        )
        assessment_record, synthesis_invocation = invoke_fake_provider(
            runtime=self.runtime,
            runner=self.runner,
            work=work,
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
        if not isinstance(assessment_record, VerificationInitialAssessment):
            raise TypeError("FAKE_INITIAL_ASSESSMENT_OUTPUT_MISMATCH")
        persist_fake_invocation(self.runtime, synthesis_invocation)
        save = self.runner.action(
            work,
            owner_ref,
            "VERIFICATION",
            "SAVE_RESULT",
            result_kind="verification_initial_assessment",
            candidate_result_ref=self.runtime.unit_of_work.records.stage_record(
                assessment_record
            ),
        )
        (assessment_ref,) = self.runtime.intermediate.publish(
            str(work.work_id),
            self.runner.authorize(work, save),
            (assessment_record,),
        )
        assert isinstance(assessment_ref, StoredDataRef)

        dynamic_request_ref: StoredDataRef | None = None
        dynamic_result_ref: StoredDataRef | None = None
        poc_ref: StoredDataRef | None = None
        if verdict == "TRUE":
            request, dynamic, poc = self.dynamic.run(
                scope=scope,
                owner_ref=owner_ref,
                orchestrator_ref=orchestrator_ref,
                verification_work=work,
                assignment_ref=registered.assignment_ref,
                hypothesis_ref=hypothesis_ref,
                evidence_ref=evidence_ref,
                pro_ref=pro_ref,
                con_ref=con_ref,
                assessment_ref=assessment_ref,
                policy_ref=policy_ref,
                playbook_ref=playbook_ref,
                application_ref=application_ref,
            )
            request_ref = reference(request)
            result_ref = reference(dynamic)
            candidate_poc_ref = reference(poc)
            assert isinstance(request_ref, StoredDataRef)
            assert isinstance(result_ref, StoredDataRef)
            assert isinstance(candidate_poc_ref, StoredDataRef)
            dynamic_request_ref = request_ref
            dynamic_result_ref = result_ref
            poc_ref = candidate_poc_ref
            if invalid_poc:
                poc_ref = poc_ref.model_copy(
                    update={
                        "record_id": RecordId("fake-missing-poc"),
                        "stored_data_id": StoredDataId("fake-missing-poc"),
                    }
                )

        observation = self._stored_artifact("observation")
        final_candidate = self.assembly.build_result(
            meta=self.runner.metadata(
                work.meta, "verification_result", attempt_id=work.active_attempt_id
            ),
            inputs=generation_inputs,
            verdict=verdict,
            dynamic_request_ref=dynamic_request_ref,
            dynamic_result_ref=dynamic_result_ref,
            poc_ref=poc_ref,
            observation_ref=observation,
            revised=revised,
            material_child_meta=(
                self.runner.metadata(
                    work.meta,
                    "hypothesis_proposal",
                    attempt_id=work.active_attempt_id,
                )
                if material_child
                else None
            ),
            parent_hypothesis_id=hypothesis.meta.hypothesis_id,
        )
        final_context = (
            registered.assignment_ref,
            hypothesis_ref,
            proposal_ref,
            assessment_ref,
            evidence_ref,
            policy_ref,
            playbook_ref,
            application_ref,
            pro_ref,
            con_ref,
            *(() if dynamic_result_ref is None else (dynamic_result_ref,)),
            *(() if dynamic_request_ref is None else (dynamic_request_ref,)),
            *(() if poc_ref is None else (poc_ref,)),
        )
        final_call_ref, final_provider_ref = register_fake_llm_call(
            self.runtime,
            self.evidence,
            self._record_meta,
            self._artifact,
            self.clock.now(),
            self.provider_probe,
            runner=self.runner,
            work=work,
            scope=scope,
            orchestration_identity=orchestrator_ref,
            role="VERIFICATION",
            result_kind="verification_result",
            task_kind="FINAL_VERDICT",
            context_refs=final_context,
        )
        final_record, final_invocation = invoke_fake_provider(
            runtime=self.runtime,
            runner=self.runner,
            work=work,
            scope=scope,
            identity=owner_ref,
            action_role=RequesterRole.VERIFICATION,
            action_type="CALL_LLM",
            call_spec_ref=final_call_ref,
            provider_profile_ref=final_provider_ref,
            artifact=self._stored_artifact,
            build_output=lambda _decision: final_candidate,
            provider_invoke=self.provider_invoke,
        )
        if not isinstance(final_record, VerificationResult):
            raise TypeError("FAKE_FINAL_VERDICT_OUTPUT_MISMATCH")
        persist_fake_invocation(self.runtime, final_invocation)
        completed = self.runner.complete(
            work, owner_ref, "VERIFICATION", (final_record,)
        )
        current_processes = tuple(
            item
            for item in self.runtime.queries.current_records(
                str(ANALYSIS_ID), "hypothesis_process_state"
            )
            if isinstance(item, HypothesisProcessState)
            and item.meta.hypothesis_id == hypothesis.meta.hypothesis_id
            and item.verification_generation == work.work_generation
        )
        if len(current_processes) != 1:
            raise LookupError("EXACT_VERIFICATION_PROCESS_NOT_FOUND")
        current_process_ref = reference(current_processes[0])
        completed_ref = reference(completed)
        assert isinstance(current_process_ref, StoredDataRef)
        assert isinstance(completed_ref, StoredDataRef)
        return VerificationExecution(
            result=final_record,
            work_ref=completed_ref,
            hypothesis_ref=hypothesis_ref,
            process_ref=current_process_ref,
            generation=work.work_generation,
        )
