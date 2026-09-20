"""Concrete T08--T13 production feature graph installation.

This module is deliberately separate from the production foundation.  A
capability resolver supplies already-approved concrete boundary components;
the installer binds them to the runtime and uses the public T10--T13 builders.
No Fake adapter, fallback handler, or guessed capability is accepted.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, cast

from sastsimi.agents.cwe_labeling import CWECallRefs
from sastsimi.agents.policy_parser import PolicyParserAgent
from sastsimi.agents.reporter import ReporterCallRefs
from sastsimi.agents.rule_scope_gate import RuleScopeCallRefs
from sastsimi.chaining.service import (
    ChainingCallRefs,
    ChainingCallResolver,
    chaining_input_hash,
    chaining_prompt_input_bytes,
)
from sastsimi.composition.production_cancellation import (
    AttemptCancellationPort,
    SandboxCancellationDockerPort,
)
from sastsimi.composition.runtime import (
    T11Services,
    build_t10_services,
    build_t11_services,
    build_t12_services,
    build_t13_services,
)
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.analysis import AnalysisRunState, AnalysisStartRequest
from sastsimi.contracts.budget import Purpose
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.dynamic import DependencyBundle, DynamicReproductionRequest
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.ids import WorkId
from sastsimi.contracts.llm import LLMRole
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    HostConfigurationRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.static import (
    CodeWorkspace,
    ContextRetrievalLimits,
    RepositoryProfile,
)
from sastsimi.contracts.work import SubjectType, WorkExecutionState, WorkType
from sastsimi.orchestration.production_context import (
    InstalledProductionServices,
    ProductionCapabilityUnavailable,
    ProductionInstallationContext,
)
from sastsimi.orchestration.production_stage_handoff import (
    ProductionStageRouter,
    RoutedWorkHandler,
)
from sastsimi.orchestration.production_verification_dispatch import (
    InitialVerificationDispatcher,
)
from sastsimi.orchestration.run_initialization import PostWorkspaceSeederPort
from sastsimi.policy.adapters.official_http import OfficialHttpPolicySource
from sastsimi.policy.cache_service import PolicyCacheService
from sastsimi.policy.collector import PolicyCollector
from sastsimi.policy.preparation_service import PolicyPreparationService
from sastsimi.policy.program_catalog import ProgramCatalog
from sastsimi.policy.work_handler import PolicyWorkHandler
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.authorized_llm_call import AuthorizedLLMCall
from sastsimi.ports.chaining import ChainingAgentInput
from sastsimi.ports.dto import WorkContext, WorkHandlerResult
from sastsimi.ports.dynamic_sandbox import TrustedDockerTargetResolverPort
from sastsimi.ports.llm_invocation import PersistedLLMInvocation
from sastsimi.ports.record_store import RecordStore
from sastsimi.ports.runtime_query import RuntimeQueryPort
from sastsimi.ports.scheduler import ExternalCancellationPort
from sastsimi.ports.work_handler import WorkHandler
from sastsimi.ports.workspace import WorkspaceLocatorPort
from sastsimi.reporting.cwe_workflow import GateCallRefs
from sastsimi.reproduction.production import DynamicSandboxAuthorizationResolver
from sastsimi.verification.completion import VerificationCompletionCoordinator
from sastsimi.verification.dynamic_verification_handoff import (
    DynamicParentResumeService,
    DynamicReproductionWorkHandler,
    ProductionDynamicVerificationHandoff,
)
from sastsimi.verification.production_llm_work_handlers import (
    DynamicVerificationPort,
    EvidenceBranchWorkHandler,
    EvidenceCommittedPort,
    HypothesisProposalWorkHandler,
    HypothesisWorkflowPort,
    NonDynamicCompletionPort,
    ProductionCallPort,
    VerificationWorkHandler,
)


class ReadinessCheck(Protocol):
    def __call__(self) -> None: ...


@dataclass(frozen=True, slots=True)
class T08ProductionFeature:
    """Already-bound real repository/static-analysis handlers."""

    workspace_prep: WorkHandler
    repository_profile: WorkHandler
    static_tool: WorkHandler
    static_normalize: WorkHandler
    context_retrieval: WorkHandler
    seeder: PostWorkspaceSeederPort
    workspace_locator: WorkspaceLocatorPort
    static_cancellation: AttemptCancellationPort


@dataclass(frozen=True, slots=True)
class PolicyProductionFeature:
    """Official HTTPS policy collection and its post-workspace seed."""

    catalog: ProgramCatalog
    source: OfficialHttpPolicySource
    handler: PolicyWorkHandler


@dataclass(frozen=True, slots=True)
class LocalPolicyFeature:
    """Run-scoped policy state for LOCAL_EVALUATION without official-policy claims."""

    handler: WorkHandler
    seeder: PostWorkspaceSeederPort


@dataclass(frozen=True, slots=True)
class OfficialPolicyPostWorkspaceSeeder:
    """Register the exact ProgramCatalog policy work after workspace commit."""

    context: ProductionInstallationContext
    catalog: ProgramCatalog

    def ensure_initial(
        self,
        request: AnalysisStartRequest,
        state: AnalysisRunState,
        binding_ref: StoredDataRef,
    ) -> tuple[WorkExecutionState, ...]:
        if state.run_policy_state_ref is not None:
            # Recovery must not create a second frozen policy lifecycle.
            return ()
        entry = self.catalog.resolve_policy_entry(request.program_id)
        prepared = self.context.runner.begin_policy(
            binding_ref,
            state.meta,
            self.context.role_identity_refs[RequesterRole.ORCHESTRATION],
            program_id=str(request.program_id),
            source_config_ref=entry.source_config_ref,
            parser_name=entry.parser_name,
            parser_version=entry.parser_version,
        )
        ready = self.context.runner.enqueue_registered(
            prepared.work,
            binding_ref,
            self.context.role_identity_refs[RequesterRole.ORCHESTRATION],
            role="ORCHESTRATION",
        )
        return (ready,)


@dataclass(frozen=True, slots=True)
class DynamicProductionFeature:
    """Exact T11 configuration; RepositoryProfile is resolved only at execution."""

    sandbox_authorization: DynamicSandboxAuthorizationResolver
    sandbox_profile: Callable[[WorkExecutionState], StoredDataRef]
    max_execute_turns: int
    resource_journal_path: Path
    docker_profile_ref: HostConfigurationRef
    docker_target_resolver: TrustedDockerTargetResolverPort
    docker: SandboxCancellationDockerPort
    dependency_bundle: DependencyBundle | None = None
    allow_repository_build_network: bool = False


@dataclass(frozen=True, slots=True)
class LocalUnavailableDynamicFeature:
    """Explicit local boundary when no approved dedicated Docker target exists."""

    sandbox_profile: Callable[[WorkExecutionState], StoredDataRef]
    reason_code: str

    def __post_init__(self) -> None:
        if re.fullmatch(r"[A-Z0-9_]{1,96}", self.reason_code) is None:
            raise ValueError("LOCAL_DYNAMIC_REASON_INVALID")


@dataclass(frozen=True, slots=True)
class _UnavailableDynamicWorkHandler:
    reason_code: str

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        del context
        raise RuntimeError(self.reason_code)


type T11Builder = Callable[[RepositoryProfile, Path], T11Services]


@dataclass(slots=True)
class CurrentRepositoryProfileT11Resolver:
    """Build T11 from the one current profile and exact checked-out workspace."""

    records: RecordStore
    queries: RuntimeQueryPort
    workspace_for: Callable[[WorkExecutionState], CodeWorkspace]
    workspace_locator: WorkspaceLocatorPort
    build: T11Builder
    _cache: dict[tuple[StoredDataRef, Path], T11Services] = field(
        default_factory=dict, init=False, repr=False
    )

    def __call__(self, work: WorkExecutionState) -> T11Services:
        if not isinstance(work.meta, RecordMeta):
            raise ValueError("DYNAMIC_REPOSITORY_PROFILE_SCOPE_REQUIRED")
        matches = tuple(
            item
            for item in self.queries.current_records(
                str(work.meta.analysis_id), RepositoryProfile.KIND
            )
            if isinstance(item, RepositoryProfile)
            and item.meta.workspace_id == work.meta.workspace_id
            and item.meta.commit_id == work.meta.commit_id
        )
        if len(matches) != 1:
            raise ValueError("CURRENT_REPOSITORY_PROFILE_REQUIRED")
        profile = matches[0]
        profile_ref = reference(profile)
        if (
            not isinstance(profile_ref, StoredDataRef)
            or self.records.get_exact(profile_ref) != profile
        ):
            raise ValueError("CURRENT_REPOSITORY_PROFILE_REQUIRED")
        workspace = self.workspace_for(work)
        if (
            workspace.status != "READY"
            or workspace.workspace_id != work.meta.workspace_id
            or workspace.commit_id != work.meta.commit_id
        ):
            raise ValueError("CURRENT_WORKSPACE_REQUIRED")
        root = self.workspace_locator.root_for(workspace).resolve(strict=True)
        key = (profile_ref, root)
        service = self._cache.get(key)
        if service is None:
            service = self.build(profile, root)
            self._cache[key] = service
        return service


@dataclass(frozen=True, slots=True)
class ProductionFeatureInputs:
    t08: T08ProductionFeature
    policy: PolicyProductionFeature | LocalPolicyFeature
    dynamic: DynamicProductionFeature | LocalUnavailableDynamicFeature
    calls: ProductionCallPort
    verification_policy_ref: StoredDataRef
    verification_playbook_ref: StoredDataRef
    taxonomy_version: str
    external_cancellation: ExternalCancellationPort
    readiness_checks: tuple[ReadinessCheck, ...] = ()


@dataclass(frozen=True, slots=True)
class ExactProductionReadiness:
    """Recheck the exact run scope and all externally supplied capabilities."""

    analysis_id: str
    workspace_id: str
    commit_id: str
    checks: tuple[ReadinessCheck, ...]

    def require_ready(
        self,
        *,
        request: object,
        scope: object,
        profile: object,
    ) -> None:
        del request, profile
        actual = (
            str(getattr(scope, "analysis_id", "")),
            str(getattr(scope, "workspace_id", "")),
            str(getattr(scope, "commit_id", "")),
        )
        if actual != (self.analysis_id, self.workspace_id, self.commit_id):
            raise ProductionCapabilityUnavailable("PRODUCTION_SCOPE_CHANGED")
        for check in self.checks:
            check()


@dataclass(frozen=True, slots=True)
class CombinedPostWorkspaceSeeder:
    """Start static profiling and policy collection from the same frozen run."""

    static: PostWorkspaceSeederPort
    policy: PostWorkspaceSeederPort
    reconcile_pending: Callable[[str], tuple[WorkExecutionState, ...]] | None = None

    def ensure_initial(
        self,
        request: AnalysisStartRequest,
        state: AnalysisRunState,
        binding_ref: StoredDataRef,
    ) -> tuple[WorkExecutionState, ...]:
        if self.reconcile_pending is not None:
            self.reconcile_pending(str(state.meta.analysis_id))
        static = self.static.ensure_initial(request, state, binding_ref)
        policy = self.policy.ensure_initial(request, state, binding_ref)
        combined = (*static, *policy)
        ids = tuple(str(item.work_id) for item in combined)
        if not combined or len(ids) != len(set(ids)):
            raise ValueError("POST_WORKSPACE_SEED_COLLISION")
        return combined


@dataclass(frozen=True, slots=True)
class SubjectDispatchWorkHandler:
    """The one WorkType has two explicit, non-overlapping subject owners."""

    analysis: WorkHandler
    proposal: WorkHandler

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        if context.work.subject_type == SubjectType.ANALYSIS:
            return await self.analysis.execute(context)
        if context.work.subject_type == SubjectType.PROPOSAL:
            return await self.proposal.execute(context)
        raise ValueError("HYPOTHESIS_PROPOSAL_SUBJECT_UNSUPPORTED")


class _CallAdapters:
    def __init__(self, calls: ProductionCallPort, artifacts: ArtifactStore) -> None:
        self.calls = calls
        self.artifacts = artifacts

    def cwe(self, context: WorkContext) -> GateCallRefs:
        call = self._resolve(context, "CWE_LABELING", "CLASSIFY_CWE")
        return CWECallRefs(call.decision_ref, call.reservation_ref, call.call_spec_ref)

    def technical(self, context: WorkContext) -> GateCallRefs:
        call = self._resolve(context, "TECHNICAL_GATE", "REVIEW_TECHNICAL")
        return CWECallRefs(call.decision_ref, call.reservation_ref, call.call_spec_ref)

    def rule_scope(self, context: WorkContext) -> RuleScopeCallRefs:
        call = self._resolve(context, "RULE_SCOPE_GATE", "REVIEW")
        return RuleScopeCallRefs(
            call.decision_ref, call.reservation_ref, call.call_spec_ref
        )

    def reporter(self, context: WorkContext) -> ReporterCallRefs:
        call = self._resolve(context, "REPORTER", "CREATE_DRAFT")
        return ReporterCallRefs(
            call.decision_ref, call.reservation_ref, call.call_spec_ref
        )

    def chaining(
        self, context: WorkContext, value: ChainingAgentInput
    ) -> tuple[ChainingCallRefs, str]:
        work = context.work
        if not isinstance(work.meta, RecordMeta) or work.active_attempt_id is None:
            raise ValueError("CHAINING_PROMPT_SCOPE_MISMATCH")
        raw = chaining_prompt_input_bytes(work, value)
        prepared_input_ref = self.artifacts.commit(
            self.artifacts.stage_bytes(raw, "application/json")
        )
        if (
            prepared_input_ref.workspace_id != work.meta.workspace_id
            or prepared_input_ref.commit_id != work.meta.commit_id
        ):
            raise ValueError("CHAINING_PROMPT_SCOPE_MISMATCH")
        refs = (*_stored_inputs(work), prepared_input_ref)
        call = self.calls.resolve(
            work=work,
            role="CHAINING",
            task_kind="MATCH_PRIMITIVES",
            source_refs=refs,
        )
        return cast(ChainingCallRefs, call), chaining_input_hash(value)

    def _resolve(
        self, context: WorkContext, role: LLMRole, task: str
    ) -> AuthorizedLLMCall:
        return self.calls.resolve(
            work=context.work,
            role=role,
            task_kind=task,
            source_refs=_stored_inputs(context.work),
        )


@dataclass(frozen=True, slots=True)
class _ProductionPolicyParserInvocation:
    calls: ProductionCallPort
    context: ProductionInstallationContext

    async def invoke(
        self, *, work: WorkExecutionState, source_ref: StoredDataRef
    ) -> PersistedLLMInvocation:
        call = self.calls.resolve(
            work=work,
            role="POLICY_PARSER",
            task_kind="PARSE_OFFICIAL_POLICY",
            source_refs=(source_ref,),
        )
        invocation = await self.context.runtime.llm_calls.invoke(
            work=work,
            decision_ref=call.decision_ref,
            reservation_ref=call.reservation_ref,
            call_spec_ref=call.call_spec_ref,
        )
        self.calls.settle(call, invocation)
        return invocation


def build_official_policy_feature(
    *,
    context: ProductionInstallationContext,
    calls: ProductionCallPort,
    catalog: ProgramCatalog,
    source: OfficialHttpPolicySource,
) -> PolicyProductionFeature:
    """Build the non-Fake policy handler around the pinned HTTPS source."""

    entry = catalog.resolve_policy_entry(context.request.program_id)
    parser = PolicyParserAgent(
        invocations=_ProductionPolicyParserInvocation(calls, context),
        artifacts=context.runtime.unit_of_work.artifacts,
        ids=context.ids,
        clock=context.clock,
        parser_name=entry.parser_name,
        parser_version=entry.parser_version,
    )
    service = PolicyPreparationService(
        runtime=context.runtime,
        runner=context.runner,
        catalog=catalog,
        source=source,
        parser=parser,
        cache=PolicyCacheService(
            runtime=context.runtime.policy,
            records=context.runtime.unit_of_work.records,
        ),
        collector=PolicyCollector(
            runner=context.runner,
            policy_runtime=context.runtime.policy,
            ids=context.ids,
            clock=context.clock,
        ),
        collector_identity_ref=context.role_identity_refs[
            RequesterRole.POLICY_COLLECTOR
        ],
        parser_identity_ref=context.role_identity_refs[RequesterRole.POLICY_PARSER],
    )
    return PolicyProductionFeature(catalog, source, PolicyWorkHandler(service))


class ProductionFeatureInstaller:
    """Bind a complete real handler matrix to one exact production run."""

    def __init__(self, inputs: ProductionFeatureInputs) -> None:
        self.inputs = inputs

    def __call__(
        self, context: ProductionInstallationContext
    ) -> InstalledProductionServices:
        self._require_inputs(context)
        runtime, runner = context.runtime, context.runner
        records = runtime.unit_of_work.records
        calls = _CallAdapters(self.inputs.calls, runtime.unit_of_work.artifacts)
        t10 = build_t10_services(
            runtime=runtime,
            runner=runner,
            clock=context.clock,
            ids=context.ids,
            role_identity_refs=context.role_identity_refs,
        )
        verification_identity = _stored_identity(context, RequesterRole.VERIFICATION)
        orchestration_identity = context.role_identity_refs[RequesterRole.ORCHESTRATION]
        dispatch = InitialVerificationDispatcher(
            records=records,
            current=runtime.queries,
            registrar=runtime.verification_registration,
            runner=runner,
            policy_ref=self.inputs.verification_policy_ref,
            verification_identity_ref=verification_identity,
            orchestration_identity_ref=orchestration_identity,
        )
        initial_hypothesis = HypothesisProposalWorkHandler(
            records=records,
            workflow=cast(HypothesisWorkflowPort, t10.hypothesis),
            calls=self.inputs.calls,
            orchestration_identity_ref=orchestration_identity,
            hypotheses_committed=dispatch,
        )

        def budget_scope(analysis_id: str) -> BudgetScopeRef:
            ref = runtime.budget_registry.current_state(analysis_id).budget_binding_ref
            if not isinstance(ref, StoredDataRef):
                raise ValueError("CURRENT_BUDGET_SCOPE_REQUIRED")
            return ref

        def resolve_work(work_id: WorkId) -> WorkExecutionState | None:
            try:
                return runtime.work.get(str(work_id))
            except LookupError:
                return None

        def workspace_for(work: WorkExecutionState) -> CodeWorkspace:
            state = runtime.budget_registry.current_state(str(work.meta.analysis_id))
            workspace_ref = state.workspace_ref
            if not isinstance(workspace_ref, RunStoredDataRef):
                raise ValueError("CURRENT_WORKSPACE_REQUIRED")
            workspace = records.get_exact(workspace_ref)
            if not isinstance(workspace, CodeWorkspace):
                raise ValueError("CURRENT_WORKSPACE_REQUIRED")
            return workspace

        def current_dynamic_process(
            request: DynamicReproductionRequest,
        ) -> HypothesisProcessState:
            candidates = tuple(
                item
                for item in runtime.queries.current_records(
                    str(request.meta.analysis_id), HypothesisProcessState.KIND
                )
                if isinstance(item, HypothesisProcessState)
                and item.meta.hypothesis_id == request.meta.hypothesis_id
            )
            if len(candidates) != 1:
                raise ValueError("DYNAMIC_REQUEST_NOT_CURRENT")
            return candidates[0]

        completion = VerificationCompletionCoordinator(
            verification=t10.verification,
            runner=runner,
            records=records,
            work_resolver=resolve_work,
            current_process=current_dynamic_process,
            verification_identity_ref=verification_identity,
        )
        parent_resume = DynamicParentResumeService(
            records=records,
            queries=runtime.queries,
            runner=runner,
            verification_identity_ref=verification_identity,
        )
        context_limits = ContextRetrievalLimits(
            max_depth=5,
            max_fragments=32,
            max_bytes=262_144,
            max_requests_per_hypothesis=24,
            timeout_ms=45_000,
        )
        context_ceiling_raw = canonical_bytes(
            {
                "kind": "context_ceiling_profile",
                "schema_version": "1.0",
                **context_limits.model_dump(),
            }
        )

        def context_ceiling() -> StoredDataRef:
            """Persist the ceiling immediately before its owning work starts."""

            return runtime.unit_of_work.artifacts.commit(
                runtime.unit_of_work.artifacts.stage_bytes(
                    context_ceiling_raw,
                    "application/json",
                )
            )

        dynamic = self.inputs.dynamic
        if isinstance(dynamic, LocalUnavailableDynamicFeature):
            dynamic_handler: WorkHandler = _UnavailableDynamicWorkHandler(
                dynamic.reason_code
            )
        else:

            def build_t11(profile: RepositoryProfile, root: Path) -> T11Services:
                return build_t11_services(
                    runtime=runtime,
                    runner=runner,
                    clock=context.clock,
                    ids=context.ids,
                    workspace_root=root,
                    workspace_id=context.scope.workspace_id,
                    commit_id=context.scope.commit_id,
                    role_identity_refs=context.role_identity_refs,
                    sandbox_authorization=dynamic.sandbox_authorization,
                    dynamic_calls=self.inputs.calls,
                    max_execute_turns=dynamic.max_execute_turns,
                    verification=t10.verification,
                    repository_profile=profile,
                    resource_journal_path=dynamic.resource_journal_path,
                    docker_profile_ref=dynamic.docker_profile_ref,
                    docker_target_resolver=dynamic.docker_target_resolver,
                    dependency_bundle=dynamic.dependency_bundle,
                    allow_repository_build_network=(
                        dynamic.allow_repository_build_network
                    ),
                )

            dynamic_services = CurrentRepositoryProfileT11Resolver(
                records=records,
                queries=runtime.queries,
                workspace_for=workspace_for,
                workspace_locator=self.inputs.t08.workspace_locator,
                build=build_t11,
            )
            dynamic_handler = DynamicReproductionWorkHandler(
                records=records,
                services_for=dynamic_services,
                parent_resume=parent_resume,
            )
        dynamic_handoff = ProductionDynamicVerificationHandoff(
            records=records,
            queries=runtime.queries,
            runner=runner,
            verification=t10.verification,
            completion=completion,
            calls=self.inputs.calls,
            dynamic_registration=runtime.dynamic_registration,
            verification_identity_ref=verification_identity,
            budget_scope=budget_scope,
            sandbox_profile=dynamic.sandbox_profile,
            context_retrieval=self.inputs.t08.context_retrieval,
            context_ceiling=context_ceiling,
        )

        verification = VerificationWorkHandler(
            records=records,
            runner=runner,
            verification=t10.verification,
            debate=t10.debate,
            non_dynamic=cast(NonDynamicCompletionPort, t10.non_dynamic_completion),
            dynamic=cast(DynamicVerificationPort, dynamic_handoff),
            calls=self.inputs.calls,
            verification_identity_ref=verification_identity,
            budget_scope=budget_scope,
        )

        def evidence_committed(
            _parent_ref: StoredDataRef, evidence_ref: StoredDataRef
        ) -> None:
            # DebateService owns the terminal commit.  This hook rejects any
            # structural adapter that returns an unstored or substituted ref.
            if records.get_exact(evidence_ref) is None:
                raise ValueError("EVIDENCE_RESULT_NOT_COMMITTED")

        pro = EvidenceBranchWorkHandler(
            role="PRO",
            records=records,
            debate=t10.debate,
            calls=self.inputs.calls,
            evidence_committed=cast(EvidenceCommittedPort, evidence_committed),
        )
        con = EvidenceBranchWorkHandler(
            role="CON",
            records=records,
            debate=t10.debate,
            calls=self.inputs.calls,
            evidence_committed=cast(EvidenceCommittedPort, evidence_committed),
        )
        t12 = build_t12_services(
            runtime=runtime,
            runner=runner,
            clock=context.clock,
            ids=context.ids,
            t10_services=t10,
            taxonomy_version=self.inputs.taxonomy_version,
            role_identity_refs=context.role_identity_refs,
            cwe_call_resolver=calls.cwe,
            technical_call_resolver=calls.technical,
            rule_scope_call_resolver=calls.rule_scope,
            reporter_call_resolver=calls.reporter,
        )
        lineage = runtime.chaining_lineage
        if lineage is None:
            raise ProductionCapabilityUnavailable("CHAINING_LINEAGE_REQUIRED")
        t13 = build_t13_services(
            runtime=runtime,
            runner=runner,
            clock=context.clock,
            ids=context.ids,
            budget_scope_ref=context.budget_binding_ref,
            role_identity_refs=context.role_identity_refs,
            chaining_call_resolver=cast(ChainingCallResolver, calls.chaining),
            chaining_lineage=lineage,
            verification_policy_ref=self.inputs.verification_policy_ref,
            verification_playbook_ref=self.inputs.verification_playbook_ref,
        )
        router = ProductionStageRouter(context, t12)
        handlers: dict[WorkType, WorkHandler] = {
            WorkType.WORKSPACE_PREP: self.inputs.t08.workspace_prep,
            WorkType.REPOSITORY_PROFILE: self.inputs.t08.repository_profile,
            WorkType.STATIC_TOOL: self.inputs.t08.static_tool,
            WorkType.STATIC_NORMALIZE: self.inputs.t08.static_normalize,
            WorkType.HYPOTHESIS_PROPOSAL: SubjectDispatchWorkHandler(
                initial_hypothesis, t13.hypothesis_proposal
            ),
            WorkType.CONTEXT_RETRIEVAL: self.inputs.t08.context_retrieval,
            WorkType.PRO_EVIDENCE: pro,
            WorkType.CON_EVIDENCE: con,
            WorkType.VERIFICATION: RoutedWorkHandler(verification, router),
            WorkType.DYNAMIC_REPRO: RoutedWorkHandler(dynamic_handler, router),
            WorkType.PRIMITIVE_UPDATE: t13.primitive_update,
            WorkType.CHAINING: t13.chaining,
            WorkType.CWE_LABEL: RoutedWorkHandler(t12.cwe, router),
            WorkType.POLICY_FETCH: RoutedWorkHandler(
                self.inputs.policy.handler, router
            ),
            WorkType.TECHNICAL_GATE: RoutedWorkHandler(t12.technical, router),
            WorkType.RULE_SCOPE_GATE: RoutedWorkHandler(t12.rule_scope, router),
            WorkType.FINDING_NORMALIZE: RoutedWorkHandler(t12.finding, router),
            WorkType.REPORT_DRAFT: t12.reporter,
        }
        if set(handlers) != set(WorkType):
            raise ProductionCapabilityUnavailable(
                "PRODUCTION_HANDLER_INSTALLATION_INCOMPLETE"
            )
        return InstalledProductionServices(
            handlers=tuple(handlers.items()),
            seeder=CombinedPostWorkspaceSeeder(
                self.inputs.t08.seeder,
                self._policy_seeder(context),
                parent_resume.reconcile_pending,
            ),
            readiness=ExactProductionReadiness(
                str(context.scope.analysis_id),
                str(context.scope.workspace_id),
                str(context.scope.commit_id),
                self.inputs.readiness_checks,
            ),
            external_cancellation=self.inputs.external_cancellation,
        )

    def _require_inputs(self, context: ProductionInstallationContext) -> None:
        refs = (
            self.inputs.verification_policy_ref,
            self.inputs.verification_playbook_ref,
        )
        if not self.inputs.taxonomy_version.strip() or any(
            (ref.workspace_id, ref.commit_id)
            != (context.scope.workspace_id, context.scope.commit_id)
            for ref in refs
        ):
            raise ProductionCapabilityUnavailable("PRODUCTION_FEATURE_INPUT_NOT_EXACT")
        _require_policy_feature(context, self.inputs.policy)
        components: tuple[object, ...] = (
            self.inputs.t08.workspace_prep,
            self.inputs.t08.repository_profile,
            self.inputs.t08.static_tool,
            self.inputs.t08.static_normalize,
            self.inputs.t08.context_retrieval,
            self.inputs.t08.seeder,
            self.inputs.t08.workspace_locator,
            self.inputs.calls,
            self.inputs.external_cancellation,
        )
        if isinstance(self.inputs.dynamic, DynamicProductionFeature):
            components = (
                *components,
                self.inputs.dynamic.sandbox_authorization,
                self.inputs.dynamic.sandbox_profile,
                self.inputs.dynamic.docker_target_resolver,
                self.inputs.dynamic.docker,
            )
        elif context.request.purpose != Purpose.LOCAL_EVALUATION:
            raise ProductionCapabilityUnavailable("LOCAL_DYNAMIC_FEATURE_INVALID")
        for component in components:
            if "fake" in type(component).__module__.casefold():
                raise ProductionCapabilityUnavailable("FAKE_PRODUCTION_COMPONENT")
        if isinstance(self.inputs.dynamic, DynamicProductionFeature) and not (
            self.inputs.dynamic.resource_journal_path.is_absolute()
        ):
            raise ProductionCapabilityUnavailable("PRODUCTION_DYNAMIC_CONFIG_INVALID")

    def _policy_seeder(
        self, context: ProductionInstallationContext
    ) -> PostWorkspaceSeederPort:
        policy = self.inputs.policy
        if isinstance(policy, LocalPolicyFeature):
            return policy.seeder
        return OfficialPolicyPostWorkspaceSeeder(context, policy.catalog)


def _stored_identity(
    context: ProductionInstallationContext, role: RequesterRole
) -> StoredDataRef:
    value = context.role_identity_refs[role]
    if not isinstance(value, StoredDataRef):
        raise ProductionCapabilityUnavailable(f"{role.value}_IDENTITY_REQUIRED")
    return value


def _require_policy_feature(
    context: ProductionInstallationContext,
    policy: PolicyProductionFeature | LocalPolicyFeature,
) -> None:
    if isinstance(policy, PolicyProductionFeature):
        if (
            context.request.purpose != Purpose.PRODUCTION
            or not isinstance(policy.source, OfficialHttpPolicySource)
            or not isinstance(policy.handler, PolicyWorkHandler)
            or getattr(getattr(policy.handler, "_service", None), "_source", None)
            is not policy.source
            or getattr(getattr(policy.handler, "_service", None), "_catalog", None)
            is not policy.catalog
        ):
            raise ProductionCapabilityUnavailable("PRODUCTION_FEATURE_INPUT_NOT_EXACT")
        return
    if (
        context.request.purpose != Purpose.LOCAL_EVALUATION
        or not callable(getattr(policy.handler, "execute", None))
        or not callable(getattr(policy.seeder, "ensure_initial", None))
        or "fake" in type(policy.handler).__module__.casefold()
        or "fake" in type(policy.seeder).__module__.casefold()
    ):
        raise ProductionCapabilityUnavailable("LOCAL_POLICY_FEATURE_INVALID")


def _stored_inputs(work: WorkExecutionState) -> tuple[StoredDataRef, ...]:
    refs = tuple(ref for ref in work.input_refs if isinstance(ref, StoredDataRef))
    if len(refs) != len(work.input_refs):
        raise ValueError("PRODUCTION_PROMPT_INPUT_NOT_STORED")
    return refs


__all__ = [
    "CombinedPostWorkspaceSeeder",
    "CurrentRepositoryProfileT11Resolver",
    "DynamicProductionFeature",
    "ExactProductionReadiness",
    "LocalPolicyFeature",
    "LocalUnavailableDynamicFeature",
    "OfficialPolicyPostWorkspaceSeeder",
    "PolicyProductionFeature",
    "ProductionFeatureInputs",
    "ProductionFeatureInstaller",
    "SubjectDispatchWorkHandler",
    "T08ProductionFeature",
    "build_official_policy_feature",
]
