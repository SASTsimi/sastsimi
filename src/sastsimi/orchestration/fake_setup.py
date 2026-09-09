"""Budget, workspace, static-analysis and frozen-policy setup stages."""

import asyncio
from datetime import timedelta
from typing import Any

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.analysis import AnalysisRunState
from sastsimi.contracts.budget import (
    WORK_OPERATIONS,
    BudgetProfileBinding,
    DynamicReproductionLifecycleProfile,
    ExecutionBudgetProfile,
    VerificationBudgetProfile,
    WorkBudgetProfile,
)
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.hypothesis import (
    HypothesisProposal,
)
from sastsimi.contracts.ids import (
    LogicalRecordId,
    RecordId,
)
from sastsimi.contracts.policy import (
    PolicyCacheRecord,
    PolicyCollectionResult,
    PolicyParserResult,
    ProgramPolicyRecord,
    RunPolicyState,
)
from sastsimi.contracts.records import PolicyCacheMeta
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef, reference
from sastsimi.contracts.static import (
    CodeLocation,
    CodeWorkspace,
    StaticFactBundle,
    ToolRunResult,
)
from sastsimi.contracts.verification import (
    PlaybookPolicy,
    VerificationPlaybook,
)
from sastsimi.runtime.workflow_runner import WorkflowRunner

from .fake_base import (
    ANALYSIS_ID,
    COMMIT_ID,
    PROGRAM_ID,
    WORKSPACE_ID,
    FakeStageService,
)
from .fake_configuration import register_fake_llm_call
from .fake_provider_runtime import (
    invoke_fake_provider,
    persist_fake_invocation,
)


class FakeSetupStages(FakeStageService):
    def _execution(self) -> ExecutionBudgetProfile:
        approval = self._artifact("approval", run=True, record=True)
        pricing = self._artifact("pricing", run=True, record=True)
        return ExecutionBudgetProfile.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self._run_meta("execution_budget_profile"),
                    profile_key="fake-execution",
                    purpose="PRODUCTION",
                    max_analysis_elapsed_ms=120_000,
                    max_total_cost_minor_units=100_000,
                    currency="USD",
                    pricing_revision_ref=pricing,
                    max_total_work=200,
                    max_total_llm_calls=200,
                    max_total_retries=20,
                    max_parallel_work=20,
                    approval_ref=approval,
                    approved_by="fixture-r8",
                    approved_at=self.clock.now(),
                    status="ACTIVE",
                )
            )
        )

    def _work_profile(self) -> WorkBudgetProfile:
        limits = [
            dict(
                limit_key=f"fake-{work.value.lower()}",
                work_type=work,
                operation_kind=operation,
                agent_role=role,
                timeout_ms=10_000,
                max_attempts=3,
                max_calls_per_work=40,
                max_items_per_work=100,
            )
            for work, (operation, role) in WORK_OPERATIONS.items()
        ]
        limits.append(
            dict(
                limit_key="fake-policy-parse",
                work_type="POLICY_FETCH",
                operation_kind="POLICY_PARSE",
                agent_role="POLICY_PARSER",
                timeout_ms=10_000,
                max_attempts=3,
                max_calls_per_work=40,
                max_items_per_work=100,
            )
        )
        return WorkBudgetProfile.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self._record_meta("work_budget_profile"),
                    profile_key="fake-work",
                    purpose="PRODUCTION",
                    limits=limits,
                    unlisted_operation="DENY",
                    status="ACTIVE",
                )
            )
        )

    def _bootstrap(self) -> tuple[StoredDataRef, StoredDataRef, StoredDataRef]:
        self.database_upgrader(self.data_dir)
        execution = self._execution()
        work_profile = self._work_profile()
        execution_ref = reference(execution)
        owner_ref = reference(work_profile)
        assert isinstance(execution_ref, RunStoredDataRef)
        assert isinstance(owner_ref, StoredDataRef)
        self.evidence.approvals.add(content_hash(execution))
        self.evidence.identities[execution_ref] = RequesterRole.ORCHESTRATION
        self.evidence.identities[owner_ref] = RequesterRole.VERIFICATION
        self.runtime = self.runtime_builder(
            self.data_dir,
            WORKSPACE_ID,
            COMMIT_ID,
            self.clock,
            self.ids,
            evidence=self.evidence,
            context_service_identity_ref=owner_ref,
            finding_service_identity_ref=owner_ref,
            analysis_finalization_identity_ref=owner_ref,
        )
        initial = AnalysisRunState.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self._run_meta("analysis_run_state"),
                    purpose="PRODUCTION",
                    eval_config_refs=(),
                    program_id=PROGRAM_ID,
                    execution_budget_profile_ref=execution_ref,
                    budget_binding_ref=None,
                    workspace_id=None,
                    commit_id=None,
                    workspace_ref=None,
                    run_policy_state_ref=None,
                    status="RUNNING",
                    analysis_result_ref=None,
                    started_at=self.clock.now(),
                    finished_at=None,
                    elapsed_ms=0,
                )
            )
        )
        scope = self.runtime.budget_registry.pin_execution(execution, initial)
        self.runner = WorkflowRunner(self.runtime, self.clock, self.ids)
        workspace_work = self.runner.start(
            scope,
            execution.meta,
            "WORKSPACE_PREP",
            "ANALYSIS",
            str(ANALYSIS_ID),
            execution_ref,
        )
        workspace = CodeWorkspace.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(workspace_work.meta, "code_workspace"),
                    workspace_id=WORKSPACE_ID,
                    analysis_id=ANALYSIS_ID,
                    repository_url="https://example.invalid/fake",
                    commit_id=COMMIT_ID,
                    status="READY",
                )
            )
        )
        self.evidence.identities[execution_ref] = RequesterRole.REPOSITORY_LOADER
        workspace_work = self.runner.complete(
            workspace_work, execution_ref, "REPOSITORY_LOADER", (workspace,)
        )
        workspace_ref = workspace_work.output_refs[0]
        assert isinstance(workspace_ref, RunStoredDataRef)

        verification_budget = VerificationBudgetProfile.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self._record_meta("verification_budget_profile"),
                    profile_key="fake-verification",
                    max_verification_elapsed_ms=60_000,
                    max_work_per_verification=100,
                    max_llm_calls_per_verification=100,
                    max_retries_per_work=3,
                    max_parallel_evidence_calls=4,
                    status="ACTIVE",
                )
            )
        )
        for config in (work_profile, verification_budget):
            self.evidence.budget_approvals.add(content_hash(config))
        work_ref = self.runtime.configuration.register_work_budget(work_profile)
        verification_ref = self.runtime.configuration.register_verification_budget(
            verification_budget
        )
        lifecycle = DynamicReproductionLifecycleProfile.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self._record_meta("dynamic_reproduction_lifecycle_profile"),
                    profile_key="fake-dynamic",
                    preflight_budget_ref=work_ref,
                    preflight_budget_source="WORK_REMAINING_TIME",
                    max_new_attempts=3,
                    status="ACTIVE",
                    created_at=self.clock.now(),
                )
            )
        )
        self.evidence.budget_approvals.add(content_hash(lifecycle))
        lifecycle_ref = self.runtime.configuration.register_dynamic_lifecycle(lifecycle)
        binding = BudgetProfileBinding.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self._record_meta("budget_profile_binding"),
                    binding_key="fake-binding",
                    purpose="PRODUCTION",
                    execution_budget_profile_ref=scope,
                    work_budget_profile_ref=work_ref,
                    verification_budget_profile_ref=verification_ref,
                    dynamic_lifecycle_profile_ref=lifecycle_ref,
                    approval_ref=execution_ref,
                    approved_by="fixture-r8",
                    approved_at=self.clock.now(),
                    status="ACTIVE",
                )
            )
        )
        self.evidence.approvals.add(content_hash(binding))
        state = self.runtime.budget_registry.current_state(str(ANALYSIS_ID))
        state_ref = reference(state)
        assert isinstance(state_ref, RunStoredDataRef)
        binding_ref = self.runtime.budget_registry.pin_binding(
            binding, workspace_ref, state_ref
        )
        return binding_ref, owner_ref, verification_ref

    def _location(self) -> CodeLocation:
        return CodeLocation(
            workspace_id=WORKSPACE_ID,
            commit_id=COMMIT_ID,
            file_path="src/app.py",
            start_line=1,
            end_line=2,
            start_column=None,
            end_column=None,
        )

    def _prepare_hypothesis(
        self,
        scope: StoredDataRef,
        orchestrator_ref: StoredDataRef,
        tool_runs: tuple[ToolRunResult, ...],
        tool_run_refs: tuple[StoredDataRef, ...],
    ) -> tuple[HypothesisProposal, StaticFactBundle]:
        assert self.runtime is not None and self.runner is not None
        self.evidence.identities[orchestrator_ref] = RequesterRole.ORCHESTRATION
        static_work = self.runner.start(
            scope,
            self._record_meta("fake_stage"),
            "STATIC_NORMALIZE",
            "ANALYSIS",
            str(ANALYSIS_ID),
            orchestrator_ref,
            inputs=tool_run_refs,
        )
        bundle = StaticFactBundle.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(static_work.meta, "static_fact_bundle"),
                    entities=(),
                    locations=(self._location(),),
                    source_candidates=(),
                    sink_candidates=(),
                    sanitizer_candidates=(),
                    validator_candidates=(),
                    auth_and_permission_checks=(),
                    other_facts=(),
                    call_edges=(),
                    data_flow_candidates=(),
                    route_bindings=(),
                    tool_runs=tool_runs,
                    gaps=(),
                    errors=(),
                )
            )
        )
        self.evidence.identities[orchestrator_ref] = RequesterRole.STATIC_ANALYSIS
        static_work = self.runner.complete(
            static_work, orchestrator_ref, "STATIC_ANALYSIS", (bundle,)
        )
        self.evidence.identities[orchestrator_ref] = RequesterRole.ORCHESTRATION
        proposal_work = self.runner.start(
            scope,
            static_work.meta,
            "HYPOTHESIS_PROPOSAL",
            "PROPOSAL",
            "fake-proposal",
            orchestrator_ref,
            inputs=static_work.output_refs,
        )
        proposal = HypothesisProposal.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(
                        proposal_work.meta,
                        "hypothesis_proposal",
                        attempt_id=proposal_work.active_attempt_id,
                    ),
                    proposal_id="fake-proposal",
                    proposal_state="HYPOTHESIS_ONLY",
                    assertion_mode="NON_FINAL",
                    origin="INITIAL",
                    vulnerability_type_candidates=(),
                    target_entities=(),
                    target_locations=(self._location(),),
                    suspected_path=(self._location(),),
                    observed_facts=(),
                    assumptions=("The sink is reachable",),
                    restrictions=(),
                    falsification_questions=(
                        dict(
                            question_id="reachability",
                            question="Can input reach it?",
                        ),
                    ),
                    validation_checks=(
                        dict(
                            validation_id="path",
                            instruction="Validate the exact path",
                        ),
                    ),
                    parent_hypothesis_ids=(),
                    source_primitive_match_id=None,
                )
            )
        )
        call_ref, provider_ref = register_fake_llm_call(
            self.runtime,
            self.evidence,
            self._record_meta,
            self._artifact,
            self.clock.now(),
            runner=self.runner,
            scope=scope,
            orchestration_identity=orchestrator_ref,
            role="HYPOTHESIS",
            result_kind="hypothesis_proposal",
            context_refs=tuple(
                ref for ref in static_work.output_refs if isinstance(ref, StoredDataRef)
            ),
        )
        self.evidence.identities[orchestrator_ref] = RequesterRole.HYPOTHESIS
        proposal_record, invocation = invoke_fake_provider(
            runtime=self.runtime,
            runner=self.runner,
            work=proposal_work,
            scope=scope,
            identity=orchestrator_ref,
            action_role=RequesterRole.HYPOTHESIS,
            action_type="CALL_LLM",
            call_spec_ref=call_ref,
            provider_profile_ref=provider_ref,
            artifact=self._stored_artifact,
            build_output=lambda _decision: proposal,
            provider_invoke=self.provider_invoke,
        )
        assert isinstance(proposal_record, HypothesisProposal)
        self.evidence.identities[orchestrator_ref] = RequesterRole.ORCHESTRATION
        proposal_work = self.runner.complete(
            proposal_work, orchestrator_ref, "ORCHESTRATION", (proposal,)
        )
        proposal_ref = proposal_work.output_refs[0]
        assert isinstance(proposal_ref, StoredDataRef)
        persist_fake_invocation(self.runtime, invocation, proposal_ref)
        return proposal, bundle

    def _playbooks(self) -> tuple[StoredDataRef, StoredDataRef]:
        assert self.runtime is not None
        book = VerificationPlaybook.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self._record_meta("verification_playbook"),
                    scope="COMMON",
                    vulnerability_type=None,
                    prerequisites=(),
                    source_checks=(),
                    sink_checks=(),
                    path_checks=(),
                    defense_checks=(),
                    falsification_question_templates=(),
                    static_evidence_requirements=(),
                    dynamic_evidence_requirements=(),
                    restriction_checks=(),
                    hold_conditions=(),
                )
            )
        )
        self.evidence.playbook_approvals.add(content_hash(book))
        book_ref = self.runtime.configuration.register_playbook(book)
        policy = PlaybookPolicy.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self._record_meta("playbook_policy"),
                    common_playbook_ref=book_ref,
                    type_playbooks=(),
                    approved_by="fixture-r8",
                    approved_at=self.clock.now(),
                )
            )
        )
        self.evidence.playbook_approvals.add(content_hash(policy))
        policy_ref = self.runtime.configuration.register_playbook_policy(policy)
        return book_ref, policy_ref

    def _publish_intermediate(
        self,
        work: Any,
        identity: StoredDataRef,
        role: RequesterRole,
        record: Any,
    ) -> StoredDataRef:
        assert self.runtime is not None and self.runner is not None
        self.evidence.identities[identity] = role
        candidate = self.runtime.unit_of_work.records.stage_record(record)
        action = self.runner.action(
            work,
            identity,
            role.value,
            "SAVE_RESULT",
            result_kind=candidate.data_kind,
            candidate_result_ref=candidate,
        )
        (published,) = self.runtime.intermediate.publish(
            str(work.work_id), self.runner.authorize(work, action), (record,)
        )
        assert isinstance(published, StoredDataRef)
        return published

    def _prepare_policy(
        self,
        scope: StoredDataRef,
        orchestrator_ref: StoredDataRef,
        work: Any | None = None,
    ) -> RunPolicyState:
        assert self.runtime is not None and self.runner is not None
        self.evidence.identities[orchestrator_ref] = RequesterRole.ORCHESTRATION
        if work is None:
            work = self._start_policy_work(scope, orchestrator_ref)
        official = self._artifact("official_policy")
        self.evidence.identities[orchestrator_ref] = RequesterRole.POLICY_COLLECTOR
        fetch_action = self.runner.action(
            work, orchestrator_ref, "POLICY_COLLECTOR", "FETCH_POLICY"
        )
        fetch_units = self.runner.units(elapsed_ms=1, cost_minor_units=1)
        fetch_reservation = self.runner.reserve(work, scope, fetch_action, fetch_units)
        fetch_decision = self.runner.authorize(work, fetch_action, fetch_reservation)

        if not isinstance(official, StoredDataRef):
            raise ValueError("FAKE_POLICY_ARTIFACT_SCOPE_MISMATCH")
        asyncio.run(
            self.runtime.external.invoke(
                str(work.work_id),
                fetch_decision,
                reference(fetch_reservation),
                lambda: self.policy_fetch(official),
                idempotency_key=str(fetch_action.action_id),
            )
        )
        self.runner.account(fetch_reservation, fetch_units)
        freshness = self._artifact("freshness_evidence")
        criterion = self._artifact("freshness_criterion", record=True)
        parser = PolicyParserResult.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(
                        work.meta,
                        "policy_parser_result",
                        attempt_id=work.active_attempt_id,
                    ),
                    parser_result_id="fake-parser-result",
                    parser_name="fake-policy-parser",
                    parser_version="1",
                    source_ref=official,
                    llm_invocation_ref=self._artifact(
                        "policy_llm_invocation", record=True
                    ),
                    parsed_output_ref=self._artifact("parsed_policy"),
                    status="SUCCEEDED",
                    error_ids=(),
                    completed_at=self.clock.now(),
                )
            )
        )
        parser_ref = self._publish_intermediate(
            work, orchestrator_ref, RequesterRole.POLICY_PARSER, parser
        )
        checked = self.clock.now()
        policy = ProgramPolicyRecord.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(
                        work.meta,
                        "program_policy_record",
                        attempt_id=work.active_attempt_id,
                    ),
                    policy_record_id="fake-policy",
                    program_id=PROGRAM_ID,
                    preparation_source="COLLECTED",
                    source_cache_ref=None,
                    program_namespace="fake",
                    external_program_id="fake-program",
                    policy_version="1",
                    fetched_at=checked,
                    freshness_status="CURRENT",
                    freshness_checked_at=checked,
                    in_scope_assets=(),
                    out_of_scope_assets=(),
                    accepted_vulnerability_classes=(),
                    excluded_vulnerability_classes=(),
                    testing_restrictions=(),
                    reward_conditions=(),
                    impact_criteria=(),
                    disclosure_requirements=(),
                    parser_version="1",
                    source_refs=(official,),
                    source_checks=(
                        dict(
                            source_id="fake-official",
                            source_ref=official,
                            source_url="https://example.invalid/policy",
                            publisher="fixture",
                            status="VERIFIED",
                            evidence_refs=(freshness,),
                            checked_at=checked,
                        ),
                    ),
                    parser_result_refs=(parser_ref,),
                    freshness_criterion_ref=criterion,
                    freshness_evidence_refs=(freshness,),
                    freshness_valid_until=checked + timedelta(days=1),
                    missing_information=(),
                    freshness_warning=None,
                )
            )
        )
        policy_ref = reference(policy)
        assert isinstance(policy_ref, StoredDataRef)
        collection = PolicyCollectionResult.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(
                        work.meta,
                        "policy_collection_result",
                        attempt_id=work.active_attempt_id,
                    ),
                    collection_result_id="fake-collection",
                    program_id=PROGRAM_ID,
                    preparation_source="COLLECTED",
                    source_cache_ref=None,
                    status="FOUND",
                    official_source_refs=(official,),
                    parser_result_refs=(parser_ref,),
                    policy_record_ref=policy_ref,
                    gap_ids=(),
                    error_ids=(),
                    completed_at=checked,
                )
            )
        )
        collection_ref = reference(collection)
        assert isinstance(collection_ref, StoredDataRef)
        cache_meta = PolicyCacheMeta(
            record_id=self.ids.new(RecordId),
            logical_record_id=LogicalRecordId("fake-policy-cache"),
            record_type="policy_cache_record",
            schema_version="1.0.0",
            revision_number=1,
            previous_record_id=None,
            created_at=checked,
            program_id=PROGRAM_ID,
        )
        cache = PolicyCacheRecord.model_validate_json(
            canonical_bytes(
                dict(
                    meta=cache_meta,
                    source_config_ref=scope,
                    parser_name="fake-policy-parser",
                    parser_version="1",
                    collection_status="FOUND",
                    collection_result_ref=collection_ref,
                    parser_result_refs=(parser_ref,),
                    policy_record_ref=policy_ref,
                    freshness_criterion_ref=criterion,
                    freshness_checked_at=checked,
                    freshness_evidence_refs=(freshness,),
                    freshness_valid_until=checked + timedelta(days=1),
                    published_at=checked,
                )
            )
        )
        cache_ref = reference(cache)
        state = RunPolicyState.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(work.meta, "run_policy_state"),
                    program_id=PROGRAM_ID,
                    status="CURRENT",
                    preparation_source="COLLECTED",
                    source_config_ref=scope,
                    parser_name="fake-policy-parser",
                    parser_version="1",
                    policy_work_ref=reference(work),
                    policy_cache_ref=cache_ref,
                    collection_result_ref=collection_ref,
                    policy_record_ref=policy_ref,
                    freshness_criterion_ref=criterion,
                    freshness_checked_at=checked,
                    freshness_evidence_refs=(freshness,),
                    freshness_valid_until=checked + timedelta(days=1),
                )
            )
        )
        outputs = (collection, policy, cache, state, parser)
        self.evidence.identities[orchestrator_ref] = RequesterRole.POLICY_COLLECTOR
        self.evidence.next_outputs = tuple(
            self.runtime.unit_of_work.records.stage_record(item) for item in outputs
        )
        try:
            self.runner.complete(work, orchestrator_ref, "POLICY_COLLECTOR", outputs)
        finally:
            self.evidence.next_outputs = None
        return state

    def _start_policy_work(
        self, scope: StoredDataRef, orchestrator_ref: StoredDataRef
    ) -> Any:
        assert self.runner is not None
        self.evidence.identities[orchestrator_ref] = RequesterRole.ORCHESTRATION
        return self.runner.start(
            scope,
            self._record_meta("fake_policy_stage"),
            "POLICY_FETCH",
            "ANALYSIS",
            str(ANALYSIS_ID),
            orchestrator_ref,
        )
