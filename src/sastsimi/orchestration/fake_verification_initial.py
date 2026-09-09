"""Evidence, dynamic reproduction and Verification generation stages."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    VulnerabilityHypothesis,
)
from sastsimi.contracts.ids import RecordId, StoredDataId
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef, reference
from sastsimi.contracts.static import CodeWorkspace
from sastsimi.contracts.verification import (
    VerificationInitialAssessment,
    VerificationResult,
)
from sastsimi.ports.verification_assembly import VerificationGenerationInputs

from .fake_base import ANALYSIS_ID, FakeStageService
from .fake_configuration import register_fake_llm_call
from .fake_context import retrieve_fake_context
from .fake_debate import run_fake_debate
from .fake_provider_runtime import (
    invoke_fake_provider,
    persist_fake_invocation,
)
from .fake_static_runtime import execute_fake_static_work, register_fake_static_works

if TYPE_CHECKING:
    from .fake_base import FakePipelineBase
    from .fake_dynamic import FakeDynamicStages
    from .fake_setup import FakeSetupStages


class FakeInitialVerificationStages(FakeStageService):
    def __init__(
        self,
        host: FakePipelineBase,
        setup: FakeSetupStages,
        dynamic: FakeDynamicStages,
    ) -> None:
        super().__init__(host)
        self._setup = setup
        self._dynamic = dynamic

    def _verification(
        self,
        verdict: str,
        *,
        invalid_poc: bool = False,
        material_child: bool = False,
    ) -> VerificationResult:
        scope, owner_ref, orchestrator_ref = self._setup._bootstrap()
        assert self.runtime is not None and self.runner is not None
        run_state = self.runtime.budget_registry.current_state(str(ANALYSIS_ID))
        assert run_state.workspace_ref is not None
        workspace = self.runtime.unit_of_work.records.get_exact(run_state.workspace_ref)
        assert isinstance(workspace, CodeWorkspace)
        workspace_ref = reference(workspace)
        assert isinstance(workspace_ref, RunStoredDataRef)
        static_works = register_fake_static_works(
            runner=self.runner,
            evidence=self.evidence,
            scope=scope,
            identity=orchestrator_ref,
            workspace=workspace,
            workspace_ref=workspace_ref,
            metadata=self._record_meta("static_tool_stage"),
        )
        policy_work = self._setup._start_policy_work(scope, orchestrator_ref)
        analysis_config_ref = self._stored_artifact("static-analysis-config")
        rule_catalog_ref = self._stored_artifact("static-rule-catalog")
        static_outputs = tuple(
            execute_fake_static_work(
                runtime=self.runtime,
                runner=self.runner,
                evidence=self.evidence,
                scope=scope,
                identity=orchestrator_ref,
                work=work,
                workspace=workspace,
                analysis_config_ref=analysis_config_ref,
                rule_catalog_ref=rule_catalog_ref,
                tool_name=tool_name,
                tool_kind=tool_kind,
                raw_result_ref=self._stored_artifact(f"raw-{tool_name}"),
                static_invoke=self.static_invoke,
            )
            for work, tool_name, tool_kind in zip(
                static_works,
                ("fake-ast", "fake-sast"),
                ("STRUCTURE", "RULE_BASED"),
                strict=True,
            )
        )
        self._setup._prepare_policy(scope, orchestrator_ref, policy_work)
        tool_runs = tuple(item[0] for item in static_outputs)
        tool_run_refs = tuple(item[1] for item in static_outputs)
        proposal, bundle = self._setup._prepare_hypothesis(
            scope, orchestrator_ref, tool_runs, tool_run_refs
        )
        (hypothesis,) = self.runtime.queries.current_records(
            str(ANALYSIS_ID), "vulnerability_hypothesis"
        )
        (process,) = self.runtime.queries.current_records(
            str(ANALYSIS_ID), "hypothesis_process_state"
        )
        assert isinstance(hypothesis, VulnerabilityHypothesis)
        assert isinstance(process, HypothesisProcessState)
        hypothesis_id = hypothesis.meta.hypothesis_id
        assert hypothesis_id is not None
        hypothesis_ref = reference(hypothesis)
        proposal_ref = reference(proposal)
        process_ref = reference(process)
        assert isinstance(hypothesis_ref, StoredDataRef)
        assert isinstance(proposal_ref, StoredDataRef)
        assert isinstance(process_ref, StoredDataRef)
        book_ref, policy_ref = self._setup._playbooks()
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
            fragment_ref=self._stored_artifact("code-fragment"),
        )
        debate_inputs = tuple(
            ref
            for ref in dict.fromkeys(
                (*verification_work.input_refs, evidence_ref, context_ref)
            )
            if isinstance(ref, StoredDataRef)
        )
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
        application_ref = reference(registered.application)
        assert isinstance(application_ref, StoredDataRef)
        generation_inputs = VerificationGenerationInputs(
            work_id=verification_work.work_id,
            generation=verification_work.work_generation,
            hypothesis_ref=hypothesis_ref,
            policy_ref=policy_ref,
            playbook_ref=book_ref,
            application_ref=application_ref,
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
            verdict=verdict,
            revised=False,
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
            context_refs=tuple(
                ref
                for ref in dict.fromkeys(
                    (*verification_work.input_refs, *debate_inputs, pro_ref, con_ref)
                )
                if isinstance(ref, StoredDataRef)
            ),
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
        persist_fake_invocation(self.runtime, synthesis_invocation)
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
        dynamic_request_ref: StoredDataRef | None = None
        dynamic_result_ref: StoredDataRef | None = None
        poc_ref: StoredDataRef | None = None
        if verdict == "TRUE":
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
                assessment_ref=assessment_ref,
                policy_ref=policy_ref,
                playbook_ref=book_ref,
                application_ref=application_ref,
            )
            request_candidate_ref = reference(request)
            result_candidate_ref = reference(dynamic)
            poc_candidate_ref = reference(poc)
            assert isinstance(request_candidate_ref, StoredDataRef)
            assert isinstance(result_candidate_ref, StoredDataRef)
            assert isinstance(poc_candidate_ref, StoredDataRef)
            dynamic_request_ref = request_candidate_ref
            dynamic_result_ref = result_candidate_ref
            poc_ref = poc_candidate_ref
            if invalid_poc:
                assert isinstance(poc_ref, StoredDataRef)
                poc_ref = poc_ref.model_copy(
                    update={
                        "record_id": RecordId("fake-missing-poc"),
                        "stored_data_id": StoredDataId("fake-missing-poc"),
                    }
                )
        final_candidate = self.verification_assembly.build_result(
            meta=self.runner.metadata(
                verification_work.meta,
                "verification_result",
                attempt_id=verification_work.active_attempt_id,
            ),
            inputs=generation_inputs,
            verdict=verdict,
            dynamic_request_ref=dynamic_request_ref,
            dynamic_result_ref=dynamic_result_ref,
            poc_ref=poc_ref,
            observation_ref=self._stored_artifact("observation"),
            revised=False,
            material_child_meta=(
                self.runner.metadata(
                    verification_work.meta,
                    "hypothesis_proposal",
                    attempt_id=verification_work.active_attempt_id,
                )
                if material_child
                else None
            ),
            parent_hypothesis_id=hypothesis_id,
        )
        final_context = (
            registered.assignment_ref,
            hypothesis_ref,
            proposal_ref,
            assessment_ref,
            evidence_ref,
            policy_ref,
            book_ref,
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
            scope=scope,
            orchestration_identity=owner_ref,
            role="VERIFICATION",
            result_kind="verification_result",
            task_kind="FINAL_VERDICT",
            context_refs=final_context,
        )
        self.evidence.identities[owner_ref] = RequesterRole.VERIFICATION
        final_record, final_invocation = invoke_fake_provider(
            runtime=self.runtime,
            runner=self.runner,
            work=verification_work,
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
        final = final_record
        self.evidence.identities[owner_ref] = RequesterRole.VERIFICATION
        verification_work = self.runner.complete(
            verification_work, owner_ref, "VERIFICATION", (final,)
        )
        self._verification_work_ref = reference(verification_work)
        return final
