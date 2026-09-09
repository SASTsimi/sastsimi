"""Evidence, dynamic reproduction and Verification generation stages."""

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
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

from .fake_base import ANALYSIS_ID, FakeStageService
from .fake_configuration import register_fake_llm_call
from .fake_context import retrieve_fake_context
from .fake_debate import run_fake_debate
from .fake_provider_runtime import (
    invoke_fake_provider,
    persist_fake_invocation,
)
from .fake_static_runtime import execute_fake_static_work, register_fake_static_works


class FakeInitialVerificationStages(FakeStageService):
    def _verification(
        self,
        verdict: str,
        *,
        invalid_poc: bool = False,
        material_child: bool = False,
    ) -> VerificationResult:
        scope, owner_ref, orchestrator_ref = self._bootstrap()
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
        policy_work = self._start_policy_work(scope, orchestrator_ref)
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
        self._prepare_policy(scope, orchestrator_ref, policy_work)
        tool_runs = tuple(item[0] for item in static_outputs)
        tool_run_refs = tuple(item[1] for item in static_outputs)
        proposal, bundle = self._prepare_hypothesis(
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
        _context, context_ref = retrieve_fake_context(
            runtime=self.runtime,
            runner=self.runner,
            evidence=self.evidence,
            scope=scope,
            identity=proposal_ref,
            service_identity=owner_ref,
            metadata=hypothesis.meta,
            hypothesis_id=str(hypothesis.meta.hypothesis_id),
            inputs=(hypothesis_ref, evidence_ref),
            location=self._location(),
            fragment_ref=self._stored_artifact("code-fragment"),
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
            build_evidence=lambda role, work, parent, inputs: self._evidence_result(
                role=role,
                work=work,
                parent_work=parent,
                debate_inputs=inputs,
            ),
            provider_invoke=self.provider_invoke,
        )
        pro = debate.pro
        pro_ref, con_ref = debate.pro_ref, debate.con_ref
        application_ref = reference(registered.application)
        assert isinstance(application_ref, StoredDataRef)
        falsification_outcome = {
            "FALSE": "DISPROVED",
            "HOLD": "INCONCLUSIVE",
            "TRUE": "NOT_DISPROVED",
        }[verdict]
        assessment_candidate = VerificationInitialAssessment.model_validate_json(
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
        synthesis_call_ref, synthesis_provider_ref = register_fake_llm_call(
            self.runtime,
            self.evidence,
            self._record_meta,
            self._artifact,
            self.clock.now(),
            runner=self.runner,
            scope=scope,
            orchestration_identity=owner_ref,
            role="VERIFICATION",
            result_kind="verification_initial_assessment",
            context_refs=debate_inputs,
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
            if invalid_poc:
                assert isinstance(poc_ref, StoredDataRef)
                poc_ref = poc_ref.model_copy(
                    update={
                        "record_id": RecordId("fake-missing-poc"),
                        "stored_data_id": StoredDataId("fake-missing-poc"),
                    }
                )
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
                    material_child_proposals=(
                        (
                            dict(
                                meta=self.runner.metadata(
                                    verification_work.meta,
                                    "hypothesis_proposal",
                                    attempt_id=verification_work.active_attempt_id,
                                ),
                                proposal_id="fake-material-child",
                                proposal_state="HYPOTHESIS_ONLY",
                                assertion_mode="NON_FINAL",
                                origin="VERIFICATION",
                                vulnerability_type_candidates=(),
                                target_entities=(),
                                target_locations=(self._location(),),
                                suspected_path=(self._location(),),
                                observed_facts=(),
                                assumptions=("A separate sink may be reachable",),
                                restrictions=(),
                                falsification_questions=(
                                    dict(
                                        question_id="child-reachability",
                                        question="Can the separate sink be reached?",
                                    ),
                                ),
                                validation_checks=(
                                    dict(
                                        validation_id="child-path",
                                        instruction="Validate the separate exact path",
                                    ),
                                ),
                                parent_hypothesis_ids=(hypothesis_id,),
                                source_primitive_match_id=None,
                            ),
                        )
                        if material_child
                        else ()
                    ),
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
