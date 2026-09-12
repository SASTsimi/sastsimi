"""Concrete T08--T13 production feature graph installation.

This module is deliberately separate from the production foundation.  A
capability resolver supplies already-approved concrete boundary components;
the installer binds them to the runtime and uses the public T10--T13 builders.
No Fake adapter, fallback handler, or guessed capability is accepted.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from sastsimi.agents.cwe_labeling import CWECallRefs
from sastsimi.agents.policy_parser import PolicyParserAgent
from sastsimi.agents.reporter import ReporterCallRefs
from sastsimi.agents.rule_scope_gate import RuleScopeCallRefs
from sastsimi.bootstrap import (
    build_t10_services,
    build_t12_services,
    build_t13_services,
)
from sastsimi.chaining.service import ChainingCallRefs, ChainingCallResolver
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.analysis import AnalysisRunState, AnalysisStartRequest
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.llm import LLMRole
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef
from sastsimi.contracts.work import SubjectType, WorkExecutionState, WorkType
from sastsimi.orchestration.production_composition import (
    InstalledProductionServices,
    ProductionCapabilityUnavailable,
    ProductionInstallationContext,
)
from sastsimi.orchestration.production_llm_work_handlers import (
    DynamicVerificationPort,
    EvidenceBranchWorkHandler,
    EvidenceCommittedPort,
    HypothesisProposalWorkHandler,
    HypothesisWorkflowPort,
    NonDynamicCompletionPort,
    ProductionCallPort,
    VerificationWorkHandler,
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
from sastsimi.ports.chaining import ChainingAgentInput
from sastsimi.ports.dto import WorkContext, WorkHandlerResult
from sastsimi.ports.llm_invocation import PersistedLLMInvocation
from sastsimi.ports.scheduler import ExternalCancellationPort
from sastsimi.ports.work_handler import WorkHandler
from sastsimi.reporting.cwe_workflow import GateCallRefs
from sastsimi.verification.debate_service import AuthorizedLLMCall


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


@dataclass(frozen=True, slots=True)
class PolicyProductionFeature:
    """Official HTTPS policy collection and its post-workspace seed."""

    catalog: ProgramCatalog
    source: OfficialHttpPolicySource
    handler: PolicyWorkHandler


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
    """T10 handoff plus the independently scheduled real T11 handler."""

    handoff: DynamicVerificationPort
    handler: WorkHandler


@dataclass(frozen=True, slots=True)
class ProductionFeatureInputs:
    t08: T08ProductionFeature
    policy: PolicyProductionFeature
    dynamic: DynamicProductionFeature
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

    def ensure_initial(
        self,
        request: AnalysisStartRequest,
        state: AnalysisRunState,
        binding_ref: StoredDataRef,
    ) -> tuple[WorkExecutionState, ...]:
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
    def __init__(self, calls: ProductionCallPort) -> None:
        self.calls = calls

    def cwe(self, context: WorkContext) -> GateCallRefs:
        call = self._resolve(context, "CWE_LABELING", "CLASSIFY_CWE")
        return CWECallRefs(call.decision_ref, call.reservation_ref, call.call_spec_ref)

    def technical(self, context: WorkContext) -> GateCallRefs:
        call = self._resolve(context, "TECHNICAL_GATE", "REVIEW_TECHNICAL")
        return CWECallRefs(
            call.decision_ref, call.reservation_ref, call.call_spec_ref
        )

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
        refs = _stored_inputs(context.work)
        call = self.calls.resolve(
            work=context.work,
            role="CHAINING",
            task_kind="MATCH_PRIMITIVES",
            source_refs=refs,
        )
        return cast(ChainingCallRefs, call), content_hash(value)

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
        calls = _CallAdapters(self.inputs.calls)
        t10 = build_t10_services(
            runtime=runtime,
            runner=runner,
            clock=context.clock,
            ids=context.ids,
            role_identity_refs=context.role_identity_refs,
        )
        verification_identity = _stored_identity(
            context, RequesterRole.VERIFICATION
        )
        orchestration_identity = context.role_identity_refs[
            RequesterRole.ORCHESTRATION
        ]
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

        verification = VerificationWorkHandler(
            records=records,
            runner=runner,
            verification=t10.verification,
            debate=t10.debate,
            non_dynamic=cast(NonDynamicCompletionPort, t10.non_dynamic_completion),
            dynamic=self.inputs.dynamic.handoff,
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
            WorkType.DYNAMIC_REPRO: RoutedWorkHandler(
                self.inputs.dynamic.handler, router
            ),
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
                OfficialPolicyPostWorkspaceSeeder(context, self.inputs.policy.catalog),
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
        if (
            not self.inputs.taxonomy_version.strip()
            or any(
                (ref.workspace_id, ref.commit_id)
                != (context.scope.workspace_id, context.scope.commit_id)
                for ref in refs
            )
            or not isinstance(self.inputs.policy.source, OfficialHttpPolicySource)
            or not isinstance(self.inputs.policy.handler, PolicyWorkHandler)
            or getattr(
                getattr(self.inputs.policy.handler, "_service", None),
                "_source",
                None,
            )
            is not self.inputs.policy.source
            or getattr(
                getattr(self.inputs.policy.handler, "_service", None),
                "_catalog",
                None,
            )
            is not self.inputs.policy.catalog
        ):
            raise ProductionCapabilityUnavailable(
                "PRODUCTION_FEATURE_INPUT_NOT_EXACT"
            )
        for component in (
            self.inputs.t08.workspace_prep,
            self.inputs.t08.repository_profile,
            self.inputs.t08.static_tool,
            self.inputs.t08.static_normalize,
            self.inputs.t08.context_retrieval,
            self.inputs.t08.seeder,
            self.inputs.dynamic.handoff,
            self.inputs.dynamic.handler,
            self.inputs.calls,
            self.inputs.external_cancellation,
        ):
            if "fake" in type(component).__module__.casefold():
                raise ProductionCapabilityUnavailable("FAKE_PRODUCTION_COMPONENT")


def _stored_identity(
    context: ProductionInstallationContext, role: RequesterRole
) -> StoredDataRef:
    value = context.role_identity_refs[role]
    if not isinstance(value, StoredDataRef):
        raise ProductionCapabilityUnavailable(f"{role.value}_IDENTITY_REQUIRED")
    return value


def _stored_inputs(work: WorkExecutionState) -> tuple[StoredDataRef, ...]:
    refs = tuple(ref for ref in work.input_refs if isinstance(ref, StoredDataRef))
    if len(refs) != len(work.input_refs):
        raise ValueError("PRODUCTION_PROMPT_INPUT_NOT_STORED")
    return refs


__all__ = [
    "CombinedPostWorkspaceSeeder",
    "DynamicProductionFeature",
    "ExactProductionReadiness",
    "OfficialPolicyPostWorkspaceSeeder",
    "PolicyProductionFeature",
    "ProductionFeatureInputs",
    "ProductionFeatureInstaller",
    "SubjectDispatchWorkHandler",
    "T08ProductionFeature",
    "build_official_policy_feature",
]
