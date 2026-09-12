"""CWE, gates, primitives, chaining, reporting and finalization stages."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
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
    VulnerabilityHypothesis,
)
from sastsimi.contracts.policy import (
    PolicyCollectionResult,
    ProgramPolicyRecord,
    RunPolicyState,
)
from sastsimi.contracts.refs import (
    StoredDataRef,
    reference,
)
from sastsimi.contracts.reporting import Finding, ReportDraft, condition_sources
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.fake_workflow import (
    ChainingWorkflowPort,
    ProviderInvoker,
    ProviderProber,
    VerificationExecution,
)
from sastsimi.reporting.content_validation import ReportContent
from sastsimi.runtime.fake_llm_configuration import register_fake_llm_call
from sastsimi.runtime.fake_llm_invocation import (
    FakeInvocation,
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


@dataclass(frozen=True)
class ReportingDependencies:
    runtime: RuntimeServices
    runner: WorkflowRunner
    clock: FakeClock
    evidence: FakeEvidence
    records: FakeRecordFactory
    provider_invoke: ProviderInvoker
    provider_probe: ProviderProber
    chaining: ChainingWorkflowPort


def validate_reporting_context(
    execution: VerificationExecution,
    hypothesis: VulnerabilityHypothesis,
    process: HypothesisProcessState,
    verification_work: WorkExecutionState,
    verification_ref: StoredDataRef,
    exact_process_ref: StoredDataRef,
    current_process_ref: StoredDataRef,
) -> None:
    """Reject cross-hypothesis or stale-generation reporting inputs."""
    verification = execution.result
    if (
        hypothesis.meta.hypothesis_id != verification.meta.hypothesis_id
        or process.meta.hypothesis_id != verification.meta.hypothesis_id
        or process.status != "TERMINAL"
        or process.verification_generation != execution.generation
        or process.verification_result_ref != verification_ref
        or exact_process_ref != execution.process_ref
        or current_process_ref != execution.process_ref
        or getattr(verification_work.meta, "hypothesis_id", None)
        != verification.meta.hypothesis_id
        or verification_work.work_generation != execution.generation
        or verification_work.status != "SUCCEEDED"
        or verification_ref not in verification_work.output_refs
    ):
        raise ValueError("REPORTING_VERIFICATION_CONTEXT_MISMATCH")


class ReportingService:
    """Own CWE, gate, finding and report-draft workflows."""

    def __init__(self, dependencies: ReportingDependencies) -> None:
        self.runtime = dependencies.runtime
        self.runner = dependencies.runner
        self.clock = dependencies.clock
        self.evidence = dependencies.evidence
        self.provider_invoke = dependencies.provider_invoke
        self.provider_probe = dependencies.provider_probe
        self.chaining = dependencies.chaining
        self._record_meta = dependencies.records.record_meta
        self._artifact = dependencies.records.artifact
        self._stored_artifact = dependencies.records.stored_artifact

    def _gate_output(
        self,
        work: object,
        scope: StoredDataRef,
        identity: StoredDataRef,
        config_role: RequesterRole,
        action_type: str,
        build_output: Callable[[StoredDataRef], BaseModel],
        *,
        artifact_output: bool = False,
    ) -> tuple[BaseModel, FakeInvocation]:
        assert self.runtime is not None and self.runner is not None
        if not isinstance(work, WorkExecutionState):
            raise TypeError("Gate provider requires a running work")
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
            self.provider_probe,
            runner=self.runner,
            work=work,
            scope=scope,
            orchestration_identity=self.evidence.identity(RequesterRole.ORCHESTRATION),
            role=config_role.value,
            result_kind=result_kind,
            context_refs=tuple(
                ref for ref in work.input_refs if isinstance(ref, StoredDataRef)
            ),
        )
        return invoke_fake_provider(
            runtime=self.runtime,
            runner=self.runner,
            work=work,
            scope=scope,
            identity=identity,
            action_role=RequesterRole.VERIFICATION,
            action_type=action_type,
            call_spec_ref=call_ref,
            provider_profile_ref=provider_ref,
            artifact=self._stored_artifact,
            build_output=build_output,
            provider_invoke=self.provider_invoke,
            artifact_output=artifact_output,
        )

    def _post_true(
        self,
        execution: VerificationExecution,
        *,
        technical_status: Literal["ACCEPT", "REVISE"] = "ACCEPT",
        admission_decision: Literal["ALLOW", "DENY"] = "ALLOW",
        publish_denied_primitive: bool = False,
        stop_after_chaining: bool = False,
    ) -> TechnicalEvidenceReview:
        assert self.runtime is not None and self.runner is not None
        verification = execution.result
        state = self.runtime.budget_registry.current_state(str(ANALYSIS_ID))
        hypothesis = self.runtime.unit_of_work.records.get_exact(
            execution.hypothesis_ref
        )
        process = self.runtime.unit_of_work.records.get_exact(execution.process_ref)
        verification_work = self.runtime.unit_of_work.records.get_exact(
            execution.work_ref
        )
        verification_ref = reference(verification)
        assert isinstance(hypothesis, VulnerabilityHypothesis)
        assert isinstance(process, HypothesisProcessState)
        assert isinstance(verification_work, WorkExecutionState)
        assert isinstance(verification_ref, StoredDataRef)
        exact_process_ref = reference(process)
        current_processes = tuple(
            item
            for item in self.runtime.queries.current_records(
                str(ANALYSIS_ID), "hypothesis_process_state"
            )
            if isinstance(item, HypothesisProcessState)
            and item.meta.hypothesis_id == verification.meta.hypothesis_id
        )
        if len(current_processes) != 1:
            raise ValueError("REPORTING_VERIFICATION_CONTEXT_MISMATCH")
        current_process_ref = reference(current_processes[0])
        assert isinstance(exact_process_ref, StoredDataRef)
        assert isinstance(current_process_ref, StoredDataRef)
        validate_reporting_context(
            execution,
            hypothesis,
            process,
            verification_work,
            verification_ref,
            exact_process_ref,
            current_process_ref,
        )
        generation = execution.generation
        scope = state.budget_binding_ref
        assert scope is not None
        owner_ref = self.evidence.stored_identity(RequesterRole.VERIFICATION)
        orchestrator_ref = self.evidence.stored_identity(RequesterRole.ORCHESTRATION)
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

        cwe_work = self.runner.start(
            scope,
            verification.meta,
            "CWE_LABEL",
            "HYPOTHESIS",
            hypothesis_id,
            orchestrator_ref,
            inputs=(verification_ref,),
            parent=execution.work_ref,
            generation=generation,
        )
        cwe_identity = self.evidence.stored_identity(RequesterRole.CWE_LABELING)
        prior_labels = tuple(
            item
            for item in self.runtime.queries.current_records(
                str(ANALYSIS_ID), "cwe_label"
            )
            if isinstance(item, CWELabel)
            and item.meta.hypothesis_id == verification.meta.hypothesis_id
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
        call_ref, provider_ref = register_fake_llm_call(
            self.runtime,
            self.evidence,
            self._record_meta,
            self._artifact,
            self.clock.now(),
            self.provider_probe,
            runner=self.runner,
            work=cwe_work,
            scope=scope,
            orchestration_identity=orchestrator_ref,
            role="CWE_LABELING",
            result_kind="cwe_label",
            context_refs=(verification_ref,),
        )
        label_record, cwe_invocation = invoke_fake_provider(
            runtime=self.runtime,
            runner=self.runner,
            work=cwe_work,
            scope=scope,
            identity=cwe_identity,
            action_role=RequesterRole.CWE_LABELING,
            action_type="CALL_LLM",
            call_spec_ref=call_ref,
            provider_profile_ref=provider_ref,
            artifact=self._stored_artifact,
            build_output=lambda _decision: CWELabel.model_validate_json(
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
            ),
            provider_invoke=self.provider_invoke,
        )
        assert isinstance(label_record, CWELabel)
        label = label_record
        persist_fake_invocation(self.runtime, cwe_invocation)
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
        technical_identity = self.evidence.stored_identity(RequesterRole.TECHNICAL_GATE)
        prior_reviews = tuple(
            item
            for item in self.runtime.queries.current_records(
                str(ANALYSIS_ID), "technical_evidence_review"
            )
            if isinstance(item, TechnicalEvidenceReview)
            and item.meta.hypothesis_id == verification.meta.hypothesis_id
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
        technical_record, technical_invocation = self._gate_output(
            technical_work,
            scope,
            owner_ref,
            RequesterRole.TECHNICAL_GATE,
            "CALL_TECHNICAL_GATE",
            lambda technical_decision: TechnicalEvidenceReview.model_validate_json(
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
            ),
        )
        assert isinstance(technical_record, TechnicalEvidenceReview)
        technical = technical_record
        persist_fake_invocation(self.runtime, technical_invocation)
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
        rule_identity = self.evidence.stored_identity(RequesterRole.RULE_SCOPE_GATE)
        links = tuple(
            dict(
                link_id=f"fake-{area.lower()}",
                area=area,
                policy_item_ids=(),
                evidence_refs=(observation,),
            )
            for area in ("RULE", "SCOPE", "IMPACT", "TESTING_RESTRICTION")
        )
        rule_meta = self.runner.metadata(
            rule_work.meta,
            "rule_scope_impact_review",
            attempt_id=rule_work.active_attempt_id,
        )
        review_record, rule_invocation = self._gate_output(
            rule_work,
            scope,
            owner_ref,
            RequesterRole.RULE_SCOPE_GATE,
            "CALL_RULE_SCOPE_GATE",
            lambda rule_decision: RuleScopeImpactReview.model_validate_json(
                canonical_bytes(
                    dict(
                        meta=rule_meta,
                        action_decision_ref=rule_decision,
                        verification_result_ref=verification_ref,
                        technical_review_ref=technical_ref,
                        cwe_label_ref=label_ref,
                        run_policy_state_ref=state.run_policy_state_ref,
                        policy_collection_result_ref=policy_state.collection_result_ref,
                        policy_record_ref=policy_state.policy_record_ref,
                        review_status=(
                            "PASS" if admission_decision == "ALLOW" else "FAIL"
                        ),
                        rule_compliance="PASS",
                        scope_compliance="PASS",
                        testing_restriction_compliance=(
                            "PASS" if admission_decision == "ALLOW" else "FAIL"
                        ),
                        security_impact="SUFFICIENT",
                        report_permission=(
                            "ALLOW" if admission_decision == "ALLOW" else "DENY"
                        ),
                        evidence_links=links,
                        reasons=(),
                        missing_information=(),
                    )
                )
            ),
        )
        assert isinstance(review_record, RuleScopeImpactReview)
        review = review_record
        persist_fake_invocation(self.runtime, rule_invocation)
        rule_work = self.runner.complete(
            rule_work, rule_identity, "RULE_SCOPE_GATE", (review,)
        )
        review_ref = rule_work.output_refs[0]
        assert isinstance(review_ref, StoredDataRef)

        chaining = self.chaining.run(
            verification=verification,
            scope=scope,
            orchestrator_ref=orchestrator_ref,
            generation=generation,
            verification_ref=verification_ref,
            technical_ref=technical_ref,
            collection_ref=policy_state.collection_result_ref,
            review_ref=review_ref,
            label_ref=label_ref,
            observation=observation,
            admission_decision=admission_decision,
            publish_denied_primitive=publish_denied_primitive,
            stop_after_chaining=stop_after_chaining,
        )
        if chaining.stopped:
            return technical
        primitive_ref = chaining.primitive_ref
        assert isinstance(primitive_ref, StoredDataRef)
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
        finding_work = self.runner.complete(
            finding_work, owner_ref, "VERIFICATION", (finding,)
        )
        finding_ref = finding_work.output_refs[0]
        assert isinstance(finding_ref, StoredDataRef)

        report_work = self.runner.start(
            scope,
            verification.meta,
            "REPORT_DRAFT",
            "HYPOTHESIS",
            hypothesis_id,
            orchestrator_ref,
            inputs=(*rule_inputs, review_ref, finding_ref),
            generation=generation,
        )
        report_identity = self.evidence.stored_identity(RequesterRole.REPORTER)
        report_meta = self.runner.metadata(
            report_work.meta,
            "report_draft",
            attempt_id=report_work.active_attempt_id,
        )
        content_record, report_invocation = self._gate_output(
            report_work,
            scope,
            owner_ref,
            RequesterRole.REPORTER,
            "CREATE_REPORT_DRAFT",
            lambda _report_decision: ReportContent(
                title="Validated vulnerability finding",
                summary="The exact verified evidence supports this finding.",
                details="Static, debate, and dynamic evidence were reviewed together.",
                recommendation=(
                    "Review the affected flow and apply the documented fix."
                ),
                citations=(),
            ),
            artifact_output=True,
        )
        assert isinstance(content_record, ReportContent)
        assert report_invocation.result.parsed_output_ref is not None
        draft = ReportDraft.model_validate_json(
            canonical_bytes(
                dict(
                    meta=report_meta,
                    action_decision_ref=(report_invocation.request.action_decision_ref),
                    finding_ref=finding_ref,
                    verification_result_ref=verification_ref,
                    technical_review_ref=technical_ref,
                    rule_scope_impact_review_ref=review_ref,
                    cwe_label_ref=label_ref,
                    run_policy_state_ref=state.run_policy_state_ref,
                    policy_record_ref=policy_state.policy_record_ref,
                    dynamic_result_ref=verification.dynamic_result_ref,
                    poc_ref=verification.poc_ref,
                    content_ref=report_invocation.result.parsed_output_ref,
                    restrictions=verification.restrictions,
                    limitations=(),
                    unresolved_conditions=(),
                    redaction_status="PASSED",
                    draft_status="DRAFTED",
                )
            )
        )
        persist_fake_invocation(self.runtime, report_invocation)
        report_work = self.runner.complete(
            report_work, report_identity, "REPORTER", (draft,)
        )
        report_ref = report_work.output_refs[0]
        assert isinstance(report_ref, StoredDataRef)
        return technical
