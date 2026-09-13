"""Budget, workspace, static-analysis and frozen-policy setup stages."""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
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
    HypothesisProcessState,
    HypothesisProposal,
    VulnerabilityHypothesis,
)
from sastsimi.contracts.policy import (
    RunPolicyState,
)
from sastsimi.contracts.records import RecordMeta, RunMeta
from sastsimi.contracts.refs import (
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.static import (
    CodeLocation,
    CodeWorkspace,
    StaticFactBundle,
    StaticToolProfile,
    ToolRunResult,
)
from sastsimi.contracts.verification import (
    PlaybookPolicy,
    VerificationPlaybook,
)
from sastsimi.ports.dto import RepositoryPreparation
from sastsimi.ports.fake_workflow import (
    InitialVerificationInputs,
    PolicyFetcher,
    PolicyPreparationPort,
    ProviderInvoker,
    ProviderProber,
    StaticInvoker,
)
from sastsimi.runtime.fake_llm_configuration import register_fake_llm_call
from sastsimi.runtime.fake_llm_invocation import (
    invoke_fake_provider,
    persist_fake_invocation,
)
from sastsimi.runtime.fake_support import (
    ANALYSIS_ID,
    COMMIT_ID,
    PROGRAM_ID,
    WORKSPACE_ID,
    FakeClock,
    FakeEvidence,
    FakeIds,
    FakeRecordFactory,
)
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner

from .fake_static_runtime import execute_fake_static_work, register_fake_static_works
from .static_publication import WorkspacePreparationPublisher


@dataclass(frozen=True)
class FakeSetupDependencies:
    data_dir: Path
    runtime_builder: Callable[..., RuntimeServices]
    database_upgrader: Callable[[Path], None]
    provider_invoke: ProviderInvoker
    provider_probe: ProviderProber
    policy_fetch: PolicyFetcher
    clock: FakeClock
    ids: FakeIds
    evidence: FakeEvidence
    records: FakeRecordFactory


class FakeSetupStages:
    """Own run bootstrap and trusted proposal registration setup."""

    def __init__(self, dependencies: FakeSetupDependencies) -> None:
        self.data_dir = dependencies.data_dir
        self.runtime_builder = dependencies.runtime_builder
        self.database_upgrader = dependencies.database_upgrader
        self.provider_invoke = dependencies.provider_invoke
        self.provider_probe = dependencies.provider_probe
        self.policy_fetch = dependencies.policy_fetch
        self.clock = dependencies.clock
        self.ids = dependencies.ids
        self.evidence = dependencies.evidence
        self.records = dependencies.records
        self.runtime: RuntimeServices | None = None
        self.runner: WorkflowRunner | None = None
        self.context_service_identity_ref: StoredDataRef | None = None
        self.policy_service: PolicyPreparationPort | None = None

    def bind_policy_service(self, service: PolicyPreparationPort) -> None:
        self.policy_service = service

    def _run_meta(self, kind: str) -> RunMeta:
        return self.records.run_meta(kind)

    def _record_meta(
        self,
        kind: str,
        *,
        hypothesis_id: str | None = None,
        attempt_id: str | None = None,
    ) -> RecordMeta:
        return self.records.record_meta(
            kind, hypothesis_id=hypothesis_id, attempt_id=attempt_id
        )

    def _artifact(self, kind: str, *, record: bool = False) -> RecordRef:
        return self.records.artifact(kind, record=record)

    def _stored_artifact(self, kind: str) -> StoredDataRef:
        return self.records.stored_artifact(kind)

    def _opaque_run_ref(self, kind: str) -> RunStoredDataRef:
        return self.records.opaque_run_ref(kind)

    def _execution(self) -> ExecutionBudgetProfile:
        approval = self._opaque_run_ref("approval")
        pricing = self._opaque_run_ref("pricing")
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

    def _work_profile(self, *, profile_key: str = "fake-work") -> WorkBudgetProfile:
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
                    profile_key=profile_key,
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
        context_profile = self._work_profile(profile_key="fake-context-identity")
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
        additional_roles = (
            RequesterRole.STATIC_ANALYSIS,
            RequesterRole.POLICY_COLLECTOR,
            RequesterRole.POLICY_PARSER,
            RequesterRole.HYPOTHESIS,
            RequesterRole.PRO,
            RequesterRole.CON,
            RequesterRole.DYNAMIC_REPRODUCTION,
            RequesterRole.REPRODUCTION_SETUP_AUTOMATION,
            RequesterRole.SANDBOX_CONTROLLER,
            RequesterRole.REPRODUCTION_SESSION_MANAGER,
            RequesterRole.CWE_LABELING,
            RequesterRole.TECHNICAL_GATE,
            RequesterRole.RULE_SCOPE_GATE,
            RequesterRole.PRIMITIVE_ADMISSION_RUNTIME,
            RequesterRole.CHAINING,
            RequesterRole.REPORTER,
            RequesterRole.R8_EVALUATION_RUNTIME,
        )
        role_profiles = {
            role: self._work_profile(profile_key=f"fake-{role.value.lower()}-identity")
            for role in additional_roles
        }
        execution_ref = reference(execution)
        owner_ref = reference(work_profile)
        context_identity_ref = reference(context_profile)
        verification_ref = reference(verification_budget)
        assert isinstance(execution_ref, RunStoredDataRef)
        assert isinstance(owner_ref, StoredDataRef)
        assert isinstance(context_identity_ref, StoredDataRef)
        assert isinstance(verification_ref, StoredDataRef)
        self.evidence.approvals.add(content_hash(execution))
        self.evidence.bind_identity(execution_ref, RequesterRole.REPOSITORY_LOADER)
        self.evidence.bind_identity(owner_ref, RequesterRole.VERIFICATION)
        self.evidence.bind_identity(
            context_identity_ref, RequesterRole.CONTEXT_RETRIEVAL_SERVICE
        )
        self.evidence.bind_identity(verification_ref, RequesterRole.ORCHESTRATION)
        self.runtime = self.runtime_builder(
            self.data_dir,
            WORKSPACE_ID,
            COMMIT_ID,
            self.clock,
            self.ids,
            evidence=self.evidence,
            context_service_identity_ref=context_identity_ref,
            finding_service_identity_ref=owner_ref,
            analysis_finalization_identity_ref=verification_ref,
        )
        self.records.attach_runtime(self.runtime)
        for config in (work_profile, context_profile, verification_budget):
            self.evidence.budget_approvals.add(content_hash(config))
        work_ref = self.runtime.configuration.register_work_budget(work_profile)
        self.runtime.configuration.register_work_budget(context_profile)
        self.runtime.configuration.register_verification_budget(verification_budget)
        for role, profile in role_profiles.items():
            self.evidence.budget_approvals.add(content_hash(profile))
            identity_ref = self.runtime.configuration.register_work_budget(profile)
            self.evidence.bind_identity(identity_ref, role)
        self.context_service_identity_ref = context_identity_ref
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
        self.runner = WorkflowRunner(
            self.runtime,
            self.clock,
            self.ids,
            output_approval=self.evidence.output_approval,
        )
        workspace_work = self.runner.start(
            scope,
            execution.meta,
            "WORKSPACE_PREP",
            "ANALYSIS",
            str(ANALYSIS_ID),
            verification_ref,
        )
        workspace_publisher = WorkspacePreparationPublisher(self.runner, execution_ref)
        preparing = workspace_publisher.begin(
            workspace_work,
            "https://example.invalid/fake",
            WORKSPACE_ID,
        )
        finished = workspace_publisher.finish(
            workspace_work,
            preparing,
            RepositoryPreparation(
                analysis_id=str(ANALYSIS_ID),
                workspace_id=str(WORKSPACE_ID),
                repository_url="https://example.invalid/fake",
                requested_ref="fake",
                status="READY",
                resolved_commit_id=str(COMMIT_ID),
                root=self.data_dir / "fake-workspace",
                tracked_files=(),
                gaps=(),
                errors=(),
                lease_id="fake-workspace",
            ),
        )
        workspace_work = finished.work
        workspace_ref = finished.workspace_ref
        assert isinstance(workspace_ref, RunStoredDataRef)
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

    def _static_tool_profile(
        self, *, adapter_key: str, tool_name: str, tool_kind: str
    ) -> StoredDataRef:
        assert self.runtime is not None
        profile = StaticToolProfile.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self._record_meta("static_tool_profile"),
                    profile_key=f"fake-{tool_name.lower()}",
                    purpose="FIXTURE",
                    status="APPROVED",
                    adapter_key=adapter_key,
                    tool_name=tool_name,
                    tool_kind=tool_kind,
                    executable_key=f"fake-{tool_name.lower()}-executable",
                    executable_sha256="a" * 64,
                    expected_version="1",
                    capability_evidence_ref=None,
                    probe_timeout_ms=1_000,
                    run_timeout_ms=30_000,
                    stdout_limit_bytes=1_024,
                    stderr_limit_bytes=1_024,
                    max_attempt_output_bytes=4_096,
                    max_output_file_bytes=2_048,
                    max_artifact_read_bytes=2_048,
                )
            )
        )
        self.evidence.static_tool_approvals.add(content_hash(profile))
        return self.runtime.configuration.register_static_tool_profile(profile)

    def prepare_initial(
        self,
        scope: StoredDataRef,
        owner_ref: StoredDataRef,
        orchestrator_ref: StoredDataRef,
        static_invoke: StaticInvoker,
    ) -> InitialVerificationInputs:
        """Sequence independent run-init branches, then trusted registration inputs."""
        assert self.runtime is not None and self.runner is not None
        run_state = self.runtime.budget_registry.current_state(str(ANALYSIS_ID))
        assert run_state.workspace_ref is not None
        workspace = self.runtime.unit_of_work.records.get_exact(run_state.workspace_ref)
        assert isinstance(workspace, CodeWorkspace)
        workspace_ref = reference(workspace)
        assert isinstance(workspace_ref, RunStoredDataRef)
        tool_profiles = (
            self._static_tool_profile(
                adapter_key="PYTHON_AST", tool_name="AST", tool_kind="STRUCTURE"
            ),
            self._static_tool_profile(
                adapter_key="OPENGREP",
                tool_name="OPENGREP",
                tool_kind="RULE_BASED",
            ),
        )
        static_works = register_fake_static_works(
            runner=self.runner,
            evidence=self.evidence,
            scope=scope,
            identity=orchestrator_ref,
            workspace=workspace,
            workspace_ref=workspace_ref,
            tool_profile_refs=tool_profiles,
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
                tool_profile_ref=tool_profile_ref,
                analysis_config_ref=analysis_config_ref,
                rule_catalog_ref=rule_catalog_ref,
                tool_name=tool_name,
                tool_kind=tool_kind,
                raw_result_ref=self._stored_artifact(f"raw-{tool_name}"),
                static_invoke=static_invoke,
            )
            for work, tool_profile_ref, tool_name, tool_kind in zip(
                static_works,
                tool_profiles,
                ("AST", "OPENGREP"),
                ("STRUCTURE", "RULE_BASED"),
                strict=True,
            )
        )
        self._prepare_policy(scope, orchestrator_ref, policy_work)
        proposal, bundle = self._prepare_hypothesis(
            scope,
            orchestrator_ref,
            tuple(item[0] for item in static_outputs),
            tuple(item[1] for item in static_outputs),
        )
        (hypothesis,) = self.runtime.queries.current_records(
            str(ANALYSIS_ID), "vulnerability_hypothesis"
        )
        (process,) = self.runtime.queries.current_records(
            str(ANALYSIS_ID), "hypothesis_process_state"
        )
        assert isinstance(hypothesis, VulnerabilityHypothesis)
        assert isinstance(process, HypothesisProcessState)
        book_ref, policy_ref = self._playbooks()
        return InitialVerificationInputs(
            scope=scope,
            owner_ref=owner_ref,
            orchestrator_ref=orchestrator_ref,
            proposal=proposal,
            hypothesis=hypothesis,
            process=process,
            bundle=bundle,
            playbook_ref=book_ref,
            policy_ref=policy_ref,
        )

    def _prepare_hypothesis(
        self,
        scope: StoredDataRef,
        orchestrator_ref: StoredDataRef,
        tool_runs: tuple[ToolRunResult, ...],
        tool_run_refs: tuple[StoredDataRef, ...],
    ) -> tuple[HypothesisProposal, StaticFactBundle]:
        assert self.runtime is not None and self.runner is not None
        self.evidence.bind_identity(orchestrator_ref, RequesterRole.ORCHESTRATION)
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
        static_identity = self.evidence.identity(RequesterRole.STATIC_ANALYSIS)
        static_work = self.runner.complete(
            static_work, static_identity, "STATIC_ANALYSIS", (bundle,)
        )
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
                    statement="Untrusted input can reach the fake command sink",
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
            self.provider_probe,
            runner=self.runner,
            work=proposal_work,
            scope=scope,
            orchestration_identity=orchestrator_ref,
            role="HYPOTHESIS",
            result_kind="hypothesis_proposal",
            context_refs=tuple(
                ref for ref in static_work.output_refs if isinstance(ref, StoredDataRef)
            ),
        )
        hypothesis_identity = self.evidence.identity(RequesterRole.HYPOTHESIS)
        proposal_record, invocation = invoke_fake_provider(
            runtime=self.runtime,
            runner=self.runner,
            work=proposal_work,
            scope=scope,
            identity=hypothesis_identity,
            action_role=RequesterRole.HYPOTHESIS,
            action_type="CALL_LLM",
            call_spec_ref=call_ref,
            provider_profile_ref=provider_ref,
            artifact=self._stored_artifact,
            build_output=lambda _decision: proposal,
            provider_invoke=self.provider_invoke,
        )
        assert isinstance(proposal_record, HypothesisProposal)
        persist_fake_invocation(self.runtime, invocation)
        proposal_work = self.runner.complete(
            proposal_work, orchestrator_ref, "ORCHESTRATION", (proposal,)
        )
        proposal_ref = proposal_work.output_refs[0]
        assert isinstance(proposal_ref, StoredDataRef)
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

    def _prepare_policy(
        self,
        scope: StoredDataRef,
        orchestrator_ref: StoredDataRef,
        work: Any | None = None,
    ) -> RunPolicyState:
        if self.policy_service is None:
            raise RuntimeError("FAKE_POLICY_SERVICE_NOT_BOUND")
        return self.policy_service.prepare(scope, orchestrator_ref, work)

    def _start_policy_work(
        self, scope: StoredDataRef, orchestrator_ref: StoredDataRef
    ) -> Any:
        if self.policy_service is None:
            raise RuntimeError("FAKE_POLICY_SERVICE_NOT_BOUND")
        return self.policy_service.start(scope, orchestrator_ref)
