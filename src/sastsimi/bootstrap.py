"""The composition root for configuration, logging and injected local runtime."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal, Protocol, TextIO, cast

from sastsimi.config.loader import ConfigError as ConfigError
from sastsimi.config.loader import load_config
from sastsimi.config.models import AppConfig
from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.ids import (
    AttemptId,
    CommitId,
    LogicalRecordId,
    RecordId,
    WorkspaceId,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef, reference
from sastsimi.logging import SafeJsonHandler, safe_event
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.ports.llm_provider import LLMProviderAdapter
from sastsimi.ports.trusted_evidence import TrustedEvidencePort
from sastsimi.runtime.services import RuntimeServices
from sastsimi.storage.action_validator import (
    RuntimeValidator as SQLiteRuntimeValidator,
)
from sastsimi.storage.schema_version import MigrationRequired as MigrationRequired

if TYPE_CHECKING:
    from sastsimi.chaining.service import ChainingCallResolver
    from sastsimi.chaining.work_handlers import (
        ChainingWorkHandler,
        HypothesisProposalHandler,
        PrimitiveUpdateHandler,
    )
    from sastsimi.contracts.dynamic import DynamicReproductionRequest
    from sastsimi.contracts.evaluation import AnalysisRunResult
    from sastsimi.contracts.hypothesis import HypothesisProcessState
    from sastsimi.contracts.reporting import ReportDraft
    from sastsimi.contracts.static import StaticToolProfile
    from sastsimi.contracts.work import WorkExecutionState, WorkType
    from sastsimi.orchestration.fake_pipeline import FakePipeline
    from sastsimi.orchestration.fake_scenario_runtime import WorkflowBundle
    from sastsimi.orchestration.hypothesis_workflow import HypothesisWorkflow
    from sastsimi.orchestration.primitive_handoff import PrimitiveUpdateHandoff
    from sastsimi.orchestration.static_external_runner import (
        RepositoryRecoveryValidatorPort,
        RepositorySourceCanonicalizer,
        StaticCancellationObservationReader,
        StaticDispatchStateReader,
        StaticExternalRunner,
        StaticProcessReceiptReader,
        WorkspacePolicyDecoder,
    )
    from sastsimi.orchestration.static_publication import (
        StaticNormalizationPublisher,
    )
    from sastsimi.ports.chaining import (
        ChainingLineagePort,
    )
    from sastsimi.ports.context import ContextLineageReaderPort
    from sastsimi.ports.dto import StaticRuleMapping, WorkHandlerResult
    from sastsimi.ports.static_tool import StaticProcessAdapter
    from sastsimi.ports.work_handler import WorkHandler
    from sastsimi.ports.workspace import WorkspaceLocatorPort
    from sastsimi.reporting.cwe_work_handler import (
        CWELabelingHandler,
        GateCallResolver,
    )
    from sastsimi.reporting.rule_scope_gate_handler import (
        RuleScopeCallResolver,
        RuleScopeGateHandler,
    )
    from sastsimi.reporting.technical_gate_handler import TechnicalGateHandler
    from sastsimi.reporting.technical_gate_workflow import TechnicalRevisionReconciler
    from sastsimi.reporting.work_handlers import (
        FindingNormalizeHandler,
        ReporterCallResolver,
        ReporterWorkHandler,
    )
    from sastsimi.reproduction.production import DynamicSandboxAuthorizationResolver
    from sastsimi.reproduction.service import DynamicStageAuthorizations
    from sastsimi.runtime.chaining_reconciliation import (
        ChainingReconciliationService,
        ChainingStartupReconciler,
    )
    from sastsimi.runtime.workflow_runner import WorkflowRunner
    from sastsimi.static_analysis.coordinator import StaticToolCoordinator
    from sastsimi.static_analysis.normalizer import DecoderKey, RawDecoder
    from sastsimi.verification.completion import (
        NonDynamicVerificationCompletionCoordinator,
        VerificationCompletionCoordinator,
    )
    from sastsimi.verification.context_service import (
        ContextRetrievalService,
        TrackedFilesResolver,
    )
    from sastsimi.verification.debate_service import DebateService
    from sastsimi.verification.revision_workflow import RevisionWorkflow
    from sastsimi.verification.service import VerificationService
    from sastsimi.verification.verdict_router import VerdictRouter


class DynamicExecutor(Protocol):
    async def __call__(
        self,
        *,
        work: WorkExecutionState,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
        authorizations: DynamicStageAuthorizations,
    ) -> WorkHandlerResult: ...


type CurrentProcessResolver = Callable[
    [DynamicReproductionRequest], HypothesisProcessState
]


@dataclass(frozen=True)
class T11Services:
    """Production T11 slice assembled only at the application composition root."""

    execute_dynamic: DynamicExecutor
    current_process: CurrentProcessResolver
    completion: VerificationCompletionCoordinator

    async def execute(
        self,
        *,
        work: WorkExecutionState,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
        authorizations: DynamicStageAuthorizations,
    ) -> WorkHandlerResult:
        process = self.current_process(request)
        _require_current_dynamic_request(work, request, request_ref, process)
        result = await self.execute_dynamic(
            work=work,
            request=request,
            request_ref=request_ref,
            authorizations=authorizations,
        )
        if len(result.output_refs) != 1 or any(
            output.data_kind != "dynamic_reproduction_result"
            for output in result.output_refs
        ):
            raise ValueError("R7_OUTPUT_AUTHORITY_DENIED")
        return result


@dataclass(frozen=True)
class T12Services:
    """CWE, Gate, Finding, and Reporter services owned by root composition."""

    cwe: CWELabelingHandler
    technical: TechnicalGateHandler
    rule_scope: RuleScopeGateHandler
    finding: FindingNormalizeHandler
    reporter: ReporterWorkHandler
    primitive_handoff: PrimitiveUpdateHandoff
    technical_revisions: TechnicalRevisionReconciler


@dataclass(frozen=True)
class T13Services:
    """Primitive admission and Chaining handlers owned by root composition."""

    primitive_update: PrimitiveUpdateHandler
    chaining: ChainingWorkHandler
    hypothesis_proposal: HypothesisProposalHandler
    reconciliation: ChainingReconciliationService
    reconcile_startup: ChainingStartupReconciler

    @property
    def work_handlers(self) -> Mapping[WorkType, WorkHandler]:
        """Typed T13 registry seam consumed by the T14 production worker."""

        from sastsimi.contracts.work import WorkType

        return MappingProxyType(
            {
                WorkType.PRIMITIVE_UPDATE: self.primitive_update,
                WorkType.CHAINING: self.chaining,
                WorkType.HYPOTHESIS_PROPOSAL: self.hypothesis_proposal,
            }
        )


def _require_current_dynamic_request(
    work: WorkExecutionState,
    request: DynamicReproductionRequest,
    request_ref: StoredDataRef,
    process: HypothesisProcessState,
) -> None:
    if not isinstance(work.meta, RecordMeta) or not isinstance(
        process.meta, RecordMeta
    ):
        raise ValueError("DYNAMIC_REQUEST_NOT_CURRENT")
    if (
        reference(request) != request_ref
        or work.work_type != "DYNAMIC_REPRO"
        or work.status != "RUNNING"
        or work.active_attempt_id is None
        or work.input_refs != (request_ref,)
        or request.verification_generation != work.work_generation
        or process.status != "VERIFYING"
        or process.verification_generation != request.verification_generation
        or process.verification_assignment_ref != request.verification_assignment_ref
        or request.meta.analysis_id != work.meta.analysis_id
        or request.meta.workspace_id != work.meta.workspace_id
        or request.meta.commit_id != work.meta.commit_id
        or request.meta.hypothesis_id != work.meta.hypothesis_id
        or process.meta.analysis_id != work.meta.analysis_id
        or process.meta.workspace_id != work.meta.workspace_id
        or process.meta.commit_id != work.meta.commit_id
        or process.meta.hypothesis_id != work.meta.hypothesis_id
    ):
        raise ValueError("DYNAMIC_REQUEST_NOT_CURRENT")


def _current_process_from(
    records: Callable[[str, str], tuple[object, ...]],
) -> CurrentProcessResolver:
    """Build an exact current-process resolver over the runtime query port."""

    from sastsimi.contracts.hypothesis import HypothesisProcessState

    def resolve(request: DynamicReproductionRequest) -> HypothesisProcessState:
        candidates = tuple(
            item
            for item in records(
                str(request.meta.analysis_id), "hypothesis_process_state"
            )
            if isinstance(item, HypothesisProcessState)
            and item.meta.hypothesis_id == request.meta.hypothesis_id
        )
        if len(candidates) != 1:
            raise ValueError("DYNAMIC_REQUEST_NOT_CURRENT")
        return candidates[0]

    return resolve


def _dynamic_executor(
    execute: Callable[..., Awaitable[WorkHandlerResult]],
) -> DynamicExecutor:
    """Narrow an injected workflow method to the T11 executor seam."""

    async def invoke(
        *,
        work: WorkExecutionState,
        request: DynamicReproductionRequest,
        request_ref: StoredDataRef,
        authorizations: DynamicStageAuthorizations,
    ) -> WorkHandlerResult:
        return await execute(
            work=work,
            request=request,
            request_ref=request_ref,
            authorizations=authorizations,
        )

    return invoke


@dataclass(frozen=True)
class T10Services:
    """Production T10 slice assembled only at the application composition root."""

    hypothesis: HypothesisWorkflow
    debate: DebateService
    verification: VerificationService
    non_dynamic_completion: NonDynamicVerificationCompletionCoordinator
    verdict_router: VerdictRouter
    primitive_handoff: PrimitiveUpdateHandoff
    revision: RevisionWorkflow


@dataclass(frozen=True, slots=True)
class _RealStaticSlice:
    """Explicit, private composition of T08 services; never selected implicitly."""

    external: StaticExternalRunner
    tools: StaticToolCoordinator
    normalization: StaticNormalizationPublisher
    context: ContextRetrievalService


@dataclass(frozen=True, slots=True)
class _RuntimeStaticToolProfileResolver:
    runtime: RuntimeServices

    def resolve(self, profile_ref: StoredDataRef) -> StaticToolProfile:
        return self.runtime.configuration.resolve_static_tool_profile(profile_ref)


def _build_real_static_slice(
    *,
    runner: WorkflowRunner,
    workspace_locator: WorkspaceLocatorPort,
    adapters: Mapping[str, StaticProcessAdapter],
    executables: Mapping[str, Path],
    receipt_root: Path,
    context_receipt_root: Path,
    canonicalize_source: RepositorySourceCanonicalizer,
    decode_policy: WorkspacePolicyDecoder,
    static_process_receipts: StaticProcessReceiptReader,
    static_cancellation_observation: StaticCancellationObservationReader,
    static_dispatch_state: StaticDispatchStateReader,
    lease_root_resolver: Callable[[str], Path],
    recovery_validator: RepositoryRecoveryValidatorPort,
    decoders: Mapping[DecoderKey, RawDecoder],
    rule_catalogs: Mapping[StoredDataRef, tuple[str, ...]],
    rule_selections: Mapping[StoredDataRef, tuple[str, ...]],
    rule_mappings: Mapping[StoredDataRef, tuple[StaticRuleMapping, ...]],
    tracked_files_for: TrackedFilesResolver,
    prohibited_workspace_roots: tuple[Path, ...],
    lineage_reader: ContextLineageReaderPort | None = None,
) -> _RealStaticSlice:
    """Wire exact injected dependencies without profiles, I/O, or CLI activation."""
    from sastsimi.orchestration.static_external_runner import StaticExternalRunner
    from sastsimi.orchestration.static_publication import (
        StaticAttemptPublisher,
        StaticNormalizationPublisher,
    )
    from sastsimi.static_analysis.coordinator import StaticToolCoordinator
    from sastsimi.static_analysis.normalizer import StaticNormalizer
    from sastsimi.verification.context_service import ContextRetrievalService

    attempt_publisher = StaticAttemptPublisher(
        runner,
        rule_catalogs=rule_catalogs,
        rule_selections=rule_selections,
    )
    external = StaticExternalRunner(
        runner,
        receipt_root,
        canonicalize_source,
        decode_policy,
        lease_root_resolver=lease_root_resolver,
        recovery_validator=recovery_validator,
        static_publisher=attempt_publisher,
        static_process_receipts=static_process_receipts,
        static_cancellation_observation=static_cancellation_observation,
        static_dispatch_state=static_dispatch_state,
    )
    tools = StaticToolCoordinator(
        _RuntimeStaticToolProfileResolver(runner.runtime),
        adapters,
        external,
        workspace_locator,
        executables,
        prohibited_workspace_roots=prohibited_workspace_roots,
    )
    normalization = StaticNormalizationPublisher(
        runner,
        StaticNormalizer(decoders),
        rule_mappings=rule_mappings,
    )
    context = ContextRetrievalService(
        runtime=runner.runtime,
        runner=runner,
        workspace_locator=workspace_locator,
        tracked_files_for=tracked_files_for,
        receipt_root=context_receipt_root,
        lineage_reader=lineage_reader,
    )
    return _RealStaticSlice(external, tools, normalization, context)


def build_config(
    config_path: Path | None, overrides: Mapping[str, object]
) -> AppConfig:
    return load_config(config_path=config_path, cli=overrides)


def build_diagnostic_logger(stream: TextIO, level: str) -> logging.Logger:
    logger = logging.Logger("sastsimi", level=level)
    handler = SafeJsonHandler(stream)
    logger.addHandler(handler)
    return logger


# Public safe event factory for interface diagnostics.
diagnostic_event = safe_event


def upgrade_database(data_dir: Path, revision: str = "head") -> None:
    from sastsimi.storage.database import Database
    from sastsimi.storage.migrations import upgrade

    upgrade(Database(RuntimePaths(data_dir).database), revision)


def database_command(data_dir: Path, command: str, revision: str | None) -> str:
    from sastsimi.storage.database import Database
    from sastsimi.storage.migrations import current, downgrade, upgrade

    database = Database(RuntimePaths(data_dir).database)
    if command == "current":
        return current(database)
    if command == "upgrade":
        upgrade(database, revision or "head")
    else:
        downgrade(database, revision or "base")
    return revision or "head"


def build_fake_pipeline(data_dir: Path) -> FakePipeline:
    """Compose the deterministic local fake vertical slice."""
    from sastsimi.chaining import no_match_result
    from sastsimi.chaining.service import ChainingDependencies, ChainingService
    from sastsimi.contracts.dynamic import (
        CleanupResult,
        SandboxCommandRecord,
        SandboxEnvironment,
    )
    from sastsimi.contracts.llm import (
        LLMInvocationRequest,
        LLMInvocationResult,
        ProviderValidationEvidence,
    )
    from sastsimi.contracts.refs import reference
    from sastsimi.contracts.static import CodeLocation, ToolRunResult
    from sastsimi.evaluation.service import EvaluationDependencies, EvaluationService
    from sastsimi.orchestration.fake_pipeline import FakePipeline
    from sastsimi.policy import FakePolicySource
    from sastsimi.policy.service import PolicyDependencies, PolicyPreparationService
    from sastsimi.ports.dto import (
        ApprovedSandboxCommand,
        CapabilityProbeResult,
        OfficialPolicyFetchRequest,
        OfficialPolicySource,
        SandboxCleanupRequest,
        SandboxPrepareRequest,
        StaticToolRequest,
    )
    from sastsimi.ports.fake_workflow import (
        NoMatchBuilder,
        PolicyFetcher,
        ProviderInvoker,
        ProviderProber,
        SandboxCleaner,
        SandboxExecutor,
        SandboxPreparer,
    )
    from sastsimi.ports.verification_assembly import VerificationAssemblyPort
    from sastsimi.providers.fake import FakeProviderAdapter
    from sastsimi.reporting.service import ReportingDependencies, ReportingService
    from sastsimi.reproduction import (
        require_cleanup_result,
        require_executed_command,
        require_prepared_environment,
    )
    from sastsimi.reproduction.service import (
        DynamicReproductionService,
        ReproductionDependencies,
    )
    from sastsimi.runtime.fake_support import (
        FakeClock,
        FakeEvidence,
        FakeIds,
        FakeRecordFactory,
    )
    from sastsimi.sandbox.fake import FakeSandboxAdapter
    from sastsimi.static_analysis.fake import FakeStaticToolAdapter
    from sastsimi.storage.fake_action_validator import FakeRecordOutputRuntimeValidator
    from sastsimi.verification import FakeVerificationAssembly
    from sastsimi.verification.service import (
        VerificationDependencies,
        VerificationService,
    )

    @dataclass(frozen=True)
    class Services:
        policy: PolicyPreparationService
        verification: VerificationService
        reporting: ReportingService
        evaluation: EvaluationService

    async def provider_invoke(
        request: LLMInvocationRequest, result: LLMInvocationResult
    ) -> LLMInvocationResult:
        return await FakeProviderAdapter({reference(request): result}).invoke(request)

    async def provider_probe(
        candidate: ProviderValidationEvidence,
    ) -> CapabilityProbeResult:
        return await FakeProviderAdapter({}).probe(candidate)

    async def static_invoke(
        request: StaticToolRequest, result: ToolRunResult
    ) -> ToolRunResult:
        return await FakeStaticToolAdapter({reference(request.action): result}).run(
            request
        )

    async def sandbox_prepare(
        request: SandboxPrepareRequest, environment: SandboxEnvironment
    ) -> SandboxEnvironment:
        adapter = FakeSandboxAdapter(
            environments={reference(request.request): environment},
            commands={},
            cleanups={},
        )
        returned = await adapter.prepare(request)
        return require_prepared_environment(request, environment, returned)

    async def sandbox_execute(
        request: ApprovedSandboxCommand, command: SandboxCommandRecord
    ) -> SandboxCommandRecord:
        adapter = FakeSandboxAdapter(
            environments={},
            commands={reference(request.tool_request): command},
            cleanups={},
        )
        return require_executed_command(
            request, command, await adapter.execute(request)
        )

    async def sandbox_cleanup(
        request: SandboxCleanupRequest, cleanup: CleanupResult
    ) -> CleanupResult:
        adapter = FakeSandboxAdapter(
            environments={},
            commands={},
            cleanups={reference(request.request): cleanup},
        )
        return require_cleanup_result(request, cleanup, await adapter.cleanup(request))

    async def policy_fetch(
        request: OfficialPolicyFetchRequest, expected: OfficialPolicySource
    ) -> OfficialPolicySource:
        return await FakePolicySource(expected).fetch_official(request)

    def workflow_factory(
        *,
        runtime: RuntimeServices,
        runner: WorkflowRunner,
        clock: FakeClock,
        ids: FakeIds,
        evidence: FakeEvidence,
        records: FakeRecordFactory,
        provider_invoke: ProviderInvoker,
        provider_probe: ProviderProber,
        sandbox_prepare: SandboxPreparer,
        sandbox_execute: SandboxExecutor,
        sandbox_cleanup: SandboxCleaner,
        policy_fetch: PolicyFetcher,
        no_match_builder: NoMatchBuilder,
        verification_assembly: VerificationAssemblyPort,
        context_service_identity_ref: StoredDataRef,
        location: Callable[[], CodeLocation],
    ) -> WorkflowBundle:
        policy = PolicyPreparationService(
            PolicyDependencies(
                runtime=runtime,
                runner=runner,
                clock=clock,
                ids=ids,
                evidence=evidence,
                records=records,
                provider_invoke=provider_invoke,
                provider_probe=provider_probe,
                policy_fetch=policy_fetch,
            )
        )
        reproduction = DynamicReproductionService(
            ReproductionDependencies(
                runtime=runtime,
                runner=runner,
                clock=clock,
                evidence=evidence,
                records=records,
                provider_invoke=provider_invoke,
                provider_probe=provider_probe,
                sandbox_prepare=sandbox_prepare,
                sandbox_execute=sandbox_execute,
                sandbox_cleanup=sandbox_cleanup,
            )
        )
        verification = VerificationService(
            VerificationDependencies(
                runtime=runtime,
                runner=runner,
                clock=clock,
                evidence=evidence,
                records=records,
                provider_invoke=provider_invoke,
                provider_probe=provider_probe,
                assembly=verification_assembly,
                context_service_identity_ref=context_service_identity_ref,
                location=location,
                dynamic=reproduction,
            )
        )
        chaining = ChainingService(
            ChainingDependencies(
                runtime=runtime,
                runner=runner,
                clock=clock,
                evidence=evidence,
                records=records,
                provider_invoke=provider_invoke,
                provider_probe=provider_probe,
                no_match_builder=no_match_builder,
            )
        )
        reporting = ReportingService(
            ReportingDependencies(
                runtime=runtime,
                runner=runner,
                clock=clock,
                evidence=evidence,
                records=records,
                provider_invoke=provider_invoke,
                provider_probe=provider_probe,
                chaining=chaining,
            )
        )
        evaluation = EvaluationService(
            EvaluationDependencies(
                runtime=runtime,
                clock=clock,
                evidence=evidence,
                run_meta=records.run_meta,
            )
        )
        return Services(policy, verification, reporting, evaluation)

    result, reports = _load_fake_outputs(data_dir)
    return FakePipeline(
        data_dir,
        partial(
            _build_runtime,
            validator_factory=FakeRecordOutputRuntimeValidator,
        ),
        upgrade_database,
        provider_invoke,
        provider_probe,
        static_invoke,
        sandbox_prepare,
        sandbox_execute,
        sandbox_cleanup,
        policy_fetch,
        no_match_result,
        FakeVerificationAssembly(),
        workflow_factory,
        persisted_result=result,
        persisted_reports=reports,
    )


def _load_fake_outputs(
    data_dir: Path,
) -> tuple[AnalysisRunResult | None, tuple[ReportDraft, ...]]:
    from sastsimi.evaluation import persisted_analysis_result
    from sastsimi.reporting import persisted_report_drafts
    from sastsimi.storage.database import Database
    from sastsimi.storage.queries import RuntimeQueries
    from sastsimi.storage.repositories import SQLiteRecordStore

    path = RuntimePaths(data_dir).database
    if not path.exists():
        return None, ()
    database = Database(path)
    database.check_ready()
    records = SQLiteRecordStore(database)
    queries = RuntimeQueries(records)
    reports = persisted_report_drafts(queries, "fake-analysis")
    return persisted_analysis_result(queries, "fake-analysis"), reports


def load_fake_progress(data_dir: Path) -> dict[str, object]:
    """Read only durable fake-run progress; never synthesize a terminal result."""
    import json
    from collections import Counter

    from sastsimi.contracts.analysis import AnalysisRunState
    from sastsimi.contracts.canonical_json import canonical_bytes
    from sastsimi.contracts.evaluation import AnalysisRunResult
    from sastsimi.contracts.work import WorkExecutionState
    from sastsimi.storage.database import Database
    from sastsimi.storage.queries import RuntimeQueries
    from sastsimi.storage.repositories import SQLiteRecordStore

    path = RuntimePaths(data_dir).database
    not_found: dict[str, object] = {
        "analysis_id": "fake-analysis",
        "status": "NOT_FOUND",
        "work_counts": {},
    }
    if not path.exists():
        return not_found
    database = Database(path)
    database.check_ready()
    records = SQLiteRecordStore(database)
    queries = RuntimeQueries(records)
    runs = tuple(
        item
        for item in queries.current_records("fake-analysis", "analysis_run_state")
        if isinstance(item, AnalysisRunState)
    )
    if not runs:
        return not_found
    state = runs[-1]
    if state.analysis_result_ref is not None:
        result = records.get_exact(state.analysis_result_ref)
        if not isinstance(result, AnalysisRunResult):
            raise ValueError("ANALYSIS_RESULT_KIND_MISMATCH")
        payload = json.loads(canonical_bytes(result))
        if not isinstance(payload, dict):
            raise TypeError("ANALYSIS_RESULT_OBJECT_REQUIRED")
        return cast(dict[str, object], payload)
    works = tuple(
        item
        for item in queries.current_records("fake-analysis", "work_execution_state")
        if isinstance(item, WorkExecutionState)
    )
    counts = Counter(str(work.status) for work in works)
    status = "BLOCKED" if counts.get("BLOCKED", 0) else "RUNNING"
    return {
        "analysis_id": str(state.meta.analysis_id),
        "status": status,
        "work_counts": dict(sorted(counts.items())),
    }


def _build_runtime(
    data_dir: Path,
    workspace_id: WorkspaceId | None,
    commit_id: CommitId | None,
    clock: Clock,
    ids: IdGenerator,
    recovery_identity_ref: BudgetScopeRef | None = None,
    evidence: TrustedEvidencePort | None = None,
    context_service_identity_ref: BudgetScopeRef | None = None,
    finding_service_identity_ref: StoredDataRef | None = None,
    analysis_finalization_identity_ref: BudgetScopeRef | None = None,
    llm_adapters: Mapping[tuple[StoredDataRef, str], LLMProviderAdapter] | None = None,
    chaining_lineage: ChainingLineagePort | None = None,
    *,
    validator_factory: Callable[..., SQLiteRuntimeValidator],
) -> RuntimeServices:
    from sastsimi.runtime.action_validator import RuntimeValidator
    from sastsimi.runtime.analysis_finalization import AnalysisFinalizationService
    from sastsimi.runtime.attempt_service import AttemptService
    from sastsimi.runtime.budget_registry import BudgetProfileRegistry
    from sastsimi.runtime.budget_service import BudgetService
    from sastsimi.runtime.configuration_registry import ConfigurationRegistry
    from sastsimi.runtime.context_binding import ContextBindingService
    from sastsimi.runtime.dynamic_registration import DynamicRegistrationService
    from sastsimi.runtime.external_call_service import ExternalCallService
    from sastsimi.runtime.intermediate_publication import IntermediatePublicationService
    from sastsimi.runtime.llm_call_service import ExactAdapterResolver, LLMCallService
    from sastsimi.runtime.policy_runtime import PolicyRuntimeService
    from sastsimi.runtime.queries import RuntimeQueries
    from sastsimi.runtime.recovery_service import RecoveryService
    from sastsimi.runtime.transition_service import TransitionService
    from sastsimi.runtime.verification_registration import (
        VerificationRegistrationService,
    )
    from sastsimi.runtime.work_service import WorkService
    from sastsimi.storage.analysis_finalization import (
        AnalysisFinalizationService as SQLiteAnalysisFinalization,
    )
    from sastsimi.storage.artifact_store import LocalArtifactStore
    from sastsimi.storage.attempt_service import AttemptService as SQLiteAttempts
    from sastsimi.storage.budget_registry import BudgetProfileRegistry as SQLiteRegistry
    from sastsimi.storage.budget_service import BudgetService as SQLiteBudget
    from sastsimi.storage.configuration_registry import (
        ConfigurationRegistry as SQLiteConfigurationRegistry,
    )
    from sastsimi.storage.context_binding import ContextBindingService as SQLiteContext
    from sastsimi.storage.database import Database
    from sastsimi.storage.dynamic_registration import (
        DynamicRegistrationService as SQLiteDynamicRegistration,
    )
    from sastsimi.storage.intermediate_publication import (
        IntermediatePublicationService as SQLiteIntermediates,
    )
    from sastsimi.storage.llm_session_guard import LLMParentSessionGuard
    from sastsimi.storage.policy_runtime import PolicyRuntime as SQLitePolicyRuntime
    from sastsimi.storage.queries import RuntimeQueries as SQLiteQueries
    from sastsimi.storage.recovery_service import RecoveryService as SQLiteRecovery
    from sastsimi.storage.repositories import SQLiteRecordStore
    from sastsimi.storage.transition_service import (
        TransitionService as SQLiteTransitions,
    )
    from sastsimi.storage.unit_of_work import SQLiteUnitOfWork
    from sastsimi.storage.verification_registration import (
        VerificationRegistrationService as SQLiteVerificationRegistration,
    )
    from sastsimi.storage.work_service import WorkService as SQLiteWorks

    paths = RuntimePaths(data_dir)
    database = Database(paths.database)
    database.check_ready()
    records = SQLiteRecordStore(database, evidence, finding_service_identity_ref)
    artifacts = LocalArtifactStore(paths.artifacts, workspace_id, commit_id)
    registry = SQLiteRegistry(records, clock, ids)
    budget = SQLiteBudget(records, registry, clock, ids)
    authorization = validator_factory(
        records,
        budget,
        clock,
        ids,
        artifacts,
    )
    works = SQLiteWorks(records, authorization, clock, ids)
    transitions = SQLiteTransitions(
        works,
        artifacts,
        chaining_lineage=chaining_lineage,
    )
    unit = SQLiteUnitOfWork(records, artifacts, transitions)
    recovery = RecoveryService(SQLiteRecovery(transitions, recovery_identity_ref))
    recovery.recover()
    validator = RuntimeValidator(authorization)
    external = ExternalCallService(validator)
    configuration_store = SQLiteConfigurationRegistry(records, artifacts)

    def llm_metadata(
        source: RecordMeta,
        record_type: str,
        attempt_id: AttemptId | None,
    ) -> RecordMeta:
        return RecordMeta(
            record_id=ids.new(RecordId),
            logical_record_id=ids.new(LogicalRecordId),
            record_type=record_type,
            schema_version=source.schema_version,
            revision_number=1,
            previous_record_id=None,
            created_at=clock.now(),
            analysis_id=source.analysis_id,
            workspace_id=source.workspace_id,
            commit_id=source.commit_id,
            hypothesis_id=source.hypothesis_id,
            attempt_id=attempt_id,
        )

    llm_calls = LLMCallService(
        records=records,
        artifacts=artifacts,
        external=external,
        validator=validator,
        adapters=ExactAdapterResolver(llm_adapters or {}),
        metadata_factory=llm_metadata,
        run_states=registry,
        current_selection=configuration_store,
        parent_sessions=LLMParentSessionGuard(records),
        clock=clock,
    )
    return RuntimeServices(
        WorkService(works),
        AttemptService(SQLiteAttempts(works)),
        validator,
        BudgetProfileRegistry(registry),
        BudgetService(budget),
        TransitionService(records),
        external,
        recovery,
        unit,
        IntermediatePublicationService(SQLiteIntermediates(transitions)),
        ContextBindingService(SQLiteContext(transitions, context_service_identity_ref)),
        VerificationRegistrationService(SQLiteVerificationRegistration(transitions)),
        RuntimeQueries(SQLiteQueries(records)),
        DynamicRegistrationService(SQLiteDynamicRegistration(transitions)),
        ConfigurationRegistry(configuration_store),
        AnalysisFinalizationService(
            SQLiteAnalysisFinalization(
                records,
                clock,
                ids,
                analysis_finalization_identity_ref,
                authorization,
                artifacts,
            )
        ),
        llm_calls,
        PolicyRuntimeService(SQLitePolicyRuntime(works), clock, ids),
        chaining_lineage,
    )


def build_runtime(
    data_dir: Path,
    workspace_id: WorkspaceId | None,
    commit_id: CommitId | None,
    clock: Clock,
    ids: IdGenerator,
    recovery_identity_ref: BudgetScopeRef | None = None,
    evidence: TrustedEvidencePort | None = None,
    context_service_identity_ref: BudgetScopeRef | None = None,
    finding_service_identity_ref: StoredDataRef | None = None,
    analysis_finalization_identity_ref: BudgetScopeRef | None = None,
    llm_adapters: Mapping[tuple[StoredDataRef, str], LLMProviderAdapter] | None = None,
    chaining_lineage: ChainingLineagePort | None = None,
) -> RuntimeServices:
    """Compose the production runtime without fake output capabilities."""
    return _build_runtime(
        data_dir,
        workspace_id,
        commit_id,
        clock,
        ids,
        recovery_identity_ref,
        evidence,
        context_service_identity_ref,
        finding_service_identity_ref,
        analysis_finalization_identity_ref,
        llm_adapters,
        chaining_lineage,
        validator_factory=SQLiteRuntimeValidator,
    )


def build_t10_services(
    *,
    runtime: RuntimeServices,
    runner: WorkflowRunner,
    clock: Clock,
    ids: IdGenerator,
    role_identity_refs: Mapping[RequesterRole, BudgetScopeRef],
) -> T10Services:
    """Build the real T10 role slice after runtime identities are registered."""
    from sastsimi.agents.hypothesis import HypothesisAgent
    from sastsimi.agents.verification import VerificationAgent
    from sastsimi.contracts.ids import WorkId
    from sastsimi.contracts.llm import LLMInvocationLog
    from sastsimi.contracts.refs import reference
    from sastsimi.contracts.verification import ConEvidenceResult, ProEvidenceResult
    from sastsimi.orchestration.hypothesis_workflow import HypothesisWorkflow
    from sastsimi.orchestration.primitive_handoff import PrimitiveUpdateHandoff
    from sastsimi.ports.llm_invocation import PersistedLLMInvocation
    from sastsimi.prompts.builder import PromptBuilder
    from sastsimi.verification.completion import (
        NonDynamicVerificationCompletionCoordinator,
    )
    from sastsimi.verification.debate_service import (
        CurrentEvidenceParallelLimit,
        DebateService,
    )
    from sastsimi.verification.revision_workflow import RevisionWorkflow
    from sastsimi.verification.service import VerificationService
    from sastsimi.verification.verdict_router import VerdictRouter, current_process_from

    records = runtime.unit_of_work.records
    artifacts = runtime.unit_of_work.artifacts

    verification_identity = role_identity_refs.get(RequesterRole.VERIFICATION)
    if verification_identity is None:
        raise ValueError("VERIFICATION_IDENTITY_REQUIRED")
    orchestration_identity = role_identity_refs.get(RequesterRole.ORCHESTRATION)
    if orchestration_identity is None:
        raise ValueError("ORCHESTRATION_IDENTITY_REQUIRED")

    def budget_scope(analysis_id: str) -> BudgetScopeRef:
        state = runtime.budget_registry.current_state(analysis_id)
        if state.status != "RUNNING" or state.budget_binding_ref is None:
            raise ValueError("CURRENT_BUDGET_SCOPE_REQUIRED")
        return state.budget_binding_ref

    def metadata(
        source: RecordMeta, record_type: str, attempt_id: AttemptId | None
    ) -> RecordMeta:
        return RecordMeta(
            record_id=ids.new(RecordId),
            logical_record_id=ids.new(LogicalRecordId),
            record_type=record_type,
            schema_version=source.schema_version,
            revision_number=1,
            previous_record_id=None,
            created_at=clock.now(),
            analysis_id=source.analysis_id,
            workspace_id=source.workspace_id,
            commit_id=source.commit_id,
            hypothesis_id=source.hypothesis_id,
            attempt_id=attempt_id,
        )

    def resolve_work(work_id: WorkId) -> WorkExecutionState | None:
        try:
            return runtime.work.get(str(work_id))
        except LookupError:
            return None

    def evidence_session(
        llm_call_id: str, analysis_id: str
    ) -> tuple[str, Literal["NEW", "RESUME"]]:
        logs = tuple(
            item
            for item in runtime.queries.published_records(analysis_id)
            if isinstance(item, LLMInvocationLog)
            and item.llm_call_id == llm_call_id
            and item.agent_role in {"PRO", "CON"}
        )
        if len(logs) != 1 or logs[0].session_ref is None:
            raise ValueError("EVIDENCE_INVOCATION_LOG_REQUIRED")
        return logs[0].session_ref, "NEW"

    def publish_evidence(
        work: WorkExecutionState,
        output: ProEvidenceResult | ConEvidenceResult,
        invocation: PersistedLLMInvocation,
    ) -> StoredDataRef:
        role = RequesterRole(output.role)
        identity = role_identity_refs.get(role)
        if identity is None:
            raise ValueError(f"{role.value}_IDENTITY_REQUIRED")
        request_ref = reference(invocation.request)
        result_ref = reference(invocation.result)
        if not isinstance(request_ref, StoredDataRef) or not isinstance(
            result_ref, StoredDataRef
        ):
            raise ValueError("EVIDENCE_INVOCATION_PROVENANCE_MISMATCH")
        persisted_request = records.get_exact(request_ref)
        persisted_result = records.get_exact(result_ref)
        persisted_log = records.get_exact(invocation.log_ref)
        if (
            persisted_request != invocation.request
            or persisted_result != invocation.result
            or not isinstance(persisted_log, LLMInvocationLog)
            or reference(persisted_log) != invocation.log_ref
            or invocation.result.parsed_output_ref is None
            or output.llm_call_id != invocation.request.llm_call_id
        ):
            raise ValueError("EVIDENCE_INVOCATION_PROVENANCE_MISMATCH")
        completed = runner.complete(
            work,
            identity,
            role.value,
            (output,),
            action_input_refs=(
                *work.input_refs,
                request_ref,
                result_ref,
                invocation.log_ref,
                invocation.result.parsed_output_ref,
            ),
        )
        output_ref = completed.output_refs[0]
        if not isinstance(output_ref, StoredDataRef):
            raise TypeError("EVIDENCE_OUTPUT_SCOPE_MISMATCH")
        return output_ref

    hypothesis_agent = HypothesisAgent(
        prompt_builder=PromptBuilder(artifacts),
        llm_calls=runtime.llm_calls,
        artifacts=artifacts,
        ids=ids,
        clock=clock,
    )
    hypothesis = HypothesisWorkflow(
        agent=hypothesis_agent,
        runner=runner,
        records=records,
    )
    debate = DebateService(
        records=records,
        artifacts=artifacts,
        llm_calls=runtime.llm_calls,
        metadata_factory=metadata,
        claim_id_factory=lambda role: str(ids.new(RecordId)),
        publish_result=publish_evidence,
        parallel_limit=CurrentEvidenceParallelLimit(
            records=records,
            run_states=runtime.budget_registry,
        ),
    )
    verification_agent = VerificationAgent(
        llm_calls=runtime.llm_calls,
        records=records,
        artifacts=artifacts,
        metadata_factory=metadata,
        draft_id_factory=lambda: str(ids.new(RecordId)),
        work_resolver=resolve_work,
        evidence_session_resolver=evidence_session,
    )
    verification = VerificationService(verification_agent)
    primitive_handoff = PrimitiveUpdateHandoff(
        records=records, current=runtime.queries, ready_work=runner
    )
    return T10Services(
        hypothesis=hypothesis,
        debate=debate,
        verification=verification,
        non_dynamic_completion=NonDynamicVerificationCompletionCoordinator(
            verification=verification,
            runner=runner,
            records=records,
            work_resolver=resolve_work,
            current=runtime.queries,
            budget_scope=budget_scope,
            hold_handoff=primitive_handoff,
            verification_identity_ref=verification_identity,
            orchestration_identity_ref=orchestration_identity,
        ),
        verdict_router=VerdictRouter(
            records,
            current_process=current_process_from(runtime.queries.current_records),
        ),
        primitive_handoff=primitive_handoff,
        revision=RevisionWorkflow(
            registrar=runtime.verification_registration,
            records=records,
        ),
    )


def build_t11_services(
    *,
    runtime: RuntimeServices,
    runner: WorkflowRunner,
    clock: Clock,
    ids: IdGenerator,
    workspace_root: Path,
    workspace_id: WorkspaceId,
    commit_id: CommitId,
    role_identity_refs: Mapping[RequesterRole, BudgetScopeRef],
    sandbox_authorization: DynamicSandboxAuthorizationResolver,
    verification: VerificationService,
    docker_executable: str = "docker",
) -> T11Services:
    """Build the real local-Docker T11 slice after trusted config resolution."""

    from sastsimi.agents.dynamic_reproduction import DynamicReproductionAgent
    from sastsimi.contracts.ids import WorkId
    from sastsimi.ports.dynamic_sandbox import (
        DynamicDockerExecutionPort,
        ReproductionSetupPort,
        SandboxControllerPort,
    )
    from sastsimi.ports.reproduction_session import ReproductionSessionPort
    from sastsimi.reproduction.production import (
        ProductionDynamicExecutor,
        ProductionDynamicWorkflow,
        RuntimeDynamicRecordSink,
    )
    from sastsimi.reproduction.service import DynamicAgentPort
    from sastsimi.sandbox.cleanup import OwnedResourceRegistry
    from sastsimi.sandbox.controller import SandboxController
    from sastsimi.sandbox.docker_adapter import DockerAdapter
    from sastsimi.sandbox.health_check import SandboxHealthChecker
    from sastsimi.sandbox.recipe_store import EnvironmentRecipeStore
    from sastsimi.sandbox.session_manager import ReproductionSessionManager
    from sastsimi.sandbox.setup_automation import ReproductionSetupAutomation
    from sastsimi.verification.completion import VerificationCompletionCoordinator

    artifacts = runtime.unit_of_work.artifacts
    docker = DockerAdapter(docker_executable)
    setup = ReproductionSetupAutomation(
        docker=docker,
        recipes=EnvironmentRecipeStore(),
        health=SandboxHealthChecker(),
        resources=OwnedResourceRegistry(),
    )
    controller = SandboxController(
        workspace_root=workspace_root,
        workspace_id=str(workspace_id),
        commit_id=str(commit_id),
        record_resolver=runtime.unit_of_work.records.get_exact,
    )
    agent = DynamicReproductionAgent(
        llm_calls=runtime.llm_calls,
        artifacts=artifacts,
        ids=ids,
        clock=clock,
    )
    sessions = ReproductionSessionManager(clock=clock, ids=ids)
    sink = RuntimeDynamicRecordSink(runner, role_identity_refs)
    process_resolver = _current_process_from(runtime.queries.current_records)

    def resolve_work(work_id: WorkId) -> WorkExecutionState | None:
        try:
            return runtime.work.get(str(work_id))
        except LookupError:
            return None

    verification_identity = role_identity_refs.get(RequesterRole.VERIFICATION)
    if verification_identity is None:
        raise ValueError("VERIFICATION_IDENTITY_REQUIRED")

    def workflow_factory(work: WorkExecutionState) -> ProductionDynamicWorkflow:
        return ProductionDynamicWorkflow(
            work=work,
            controller=cast(SandboxControllerPort, controller),
            setup=cast(ReproductionSetupPort, setup),
            docker=cast(DynamicDockerExecutionPort, docker),
            sessions=cast(ReproductionSessionPort, sessions),
            artifacts=artifacts,
            clock=clock,
            ids=ids,
            sink=sink,
            authorization=sandbox_authorization,
        )

    production = ProductionDynamicExecutor(
        cast(DynamicAgentPort, agent), workflow_factory
    )
    return T11Services(
        execute_dynamic=_dynamic_executor(production),
        current_process=process_resolver,
        completion=VerificationCompletionCoordinator(
            verification=verification,
            runner=runner,
            records=runtime.unit_of_work.records,
            work_resolver=resolve_work,
            current_process=process_resolver,
            verification_identity_ref=verification_identity,
        ),
    )


def build_t12_services(
    *,
    runtime: RuntimeServices,
    runner: WorkflowRunner,
    clock: Clock,
    ids: IdGenerator,
    t10_services: T10Services,
    taxonomy_version: str,
    role_identity_refs: Mapping[RequesterRole, BudgetScopeRef],
    cwe_call_resolver: GateCallResolver,
    technical_call_resolver: GateCallResolver,
    rule_scope_call_resolver: RuleScopeCallResolver,
    reporter_call_resolver: ReporterCallResolver,
) -> T12Services:
    """Build T12 from trusted call resolvers without choosing Provider/model."""

    from sastsimi.agents.cwe_labeling import CWELabelingAgent
    from sastsimi.agents.reporter import ReporterAgent
    from sastsimi.agents.rule_scope_gate import RuleScopeGateAgent
    from sastsimi.agents.technical_gate import TechnicalGateAgent
    from sastsimi.contracts.hypothesis import (
        HypothesisProcessState,
        VerificationAssignment,
    )
    from sastsimi.contracts.verification import VerificationResult
    from sastsimi.reporting.cwe_work_handler import CWELabelingHandler
    from sastsimi.reporting.cwe_workflow import CWELabelingService
    from sastsimi.reporting.finding_normalization import FindingNormalizationService
    from sastsimi.reporting.rule_scope_gate_handler import (
        RuleScopeGateHandler,
        StoredRuleScopeInputResolver,
        WorkflowRuleScopePublisher,
    )
    from sastsimi.reporting.rule_scope_gate_workflow import (
        ExactRuleScopePromptGuard,
        RuleScopeGateService,
    )
    from sastsimi.reporting.technical_gate_handler import TechnicalGateHandler
    from sastsimi.reporting.technical_gate_workflow import (
        TechnicalGateService,
        TechnicalRevisionReconciler,
    )
    from sastsimi.reporting.work_handlers import (
        FindingNormalizeHandler,
        ReporterDraftWorkflow,
        ReporterWorkHandler,
        StoredReporterInputResolver,
    )
    from sastsimi.runtime.llm_invocation_provenance import (
        validate_llm_invocation_provenance,
    )

    records = runtime.unit_of_work.records
    artifacts = runtime.unit_of_work.artifacts

    def metadata(
        source: RecordMeta, record_type: str, attempt_id: AttemptId | None
    ) -> RecordMeta:
        record_id = ids.new(RecordId)
        return RecordMeta(
            record_id=record_id,
            logical_record_id=LogicalRecordId(str(record_id)),
            record_type=record_type,
            schema_version=source.schema_version,
            revision_number=1,
            previous_record_id=None,
            created_at=clock.now(),
            analysis_id=source.analysis_id,
            workspace_id=source.workspace_id,
            commit_id=source.commit_id,
            hypothesis_id=source.hypothesis_id,
            attempt_id=attempt_id,
        )

    def identity(role: RequesterRole) -> BudgetScopeRef:
        value = role_identity_refs.get(role)
        if value is None:
            raise ValueError(f"{role.value}_IDENTITY_REQUIRED")
        return value

    def stored_identity(role: RequesterRole) -> StoredDataRef:
        value = identity(role)
        if not isinstance(value, StoredDataRef):
            raise ValueError(f"{role.value}_CODE_SCOPE_IDENTITY_REQUIRED")
        return value

    def current_owner(verification: VerificationResult) -> StoredDataRef:
        candidates = tuple(
            item
            for item in runtime.queries.current_records(
                str(verification.meta.analysis_id), "hypothesis_process_state"
            )
            if isinstance(item, HypothesisProcessState)
            and item.meta.hypothesis_id == verification.meta.hypothesis_id
        )
        if (
            len(candidates) != 1
            or candidates[0].status != "TERMINAL"
            or candidates[0].verification_result_ref != reference(verification)
            or candidates[0].verification_assignment_ref is None
        ):
            raise ValueError("STALE_VERIFICATION_OWNER")
        assignment_ref = candidates[0].verification_assignment_ref
        assignment = records.get_exact(assignment_ref)
        if (
            not isinstance(assignment, VerificationAssignment)
            or reference(assignment) != assignment_ref
            or assignment.status != "ACTIVE"
        ):
            raise ValueError("STALE_VERIFICATION_OWNER")
        return assignment.owner_identity_ref

    def reporter_owner(work: WorkExecutionState) -> StoredDataRef:
        refs = tuple(
            ref
            for ref in work.input_refs
            if isinstance(ref, StoredDataRef) and ref.data_kind == "verification_result"
        )
        if len(refs) != 1:
            raise ValueError("STALE_VERIFICATION_OWNER")
        verification = records.get_exact(refs[0])
        if not isinstance(verification, VerificationResult):
            raise ValueError("STALE_VERIFICATION_OWNER")
        return current_owner(verification)

    def current_policy_state(analysis_id: str) -> StoredDataRef:
        state_ref = runtime.budget_registry.current_state(
            analysis_id
        ).run_policy_state_ref
        if not isinstance(state_ref, StoredDataRef):
            raise ValueError("CURRENT_RUN_POLICY_STATE_REQUIRED")
        return state_ref

    cwe_agent = CWELabelingAgent(
        llm_calls=runtime.llm_calls,
        records=records,
        artifacts=artifacts,
        metadata_factory=metadata,
        provenance_validator=validate_llm_invocation_provenance,
    )
    cwe_service = CWELabelingService(
        agent=cwe_agent,
        publisher=runner,
        records=records,
        identity_ref=identity(RequesterRole.CWE_LABELING),
        taxonomy_version=taxonomy_version,
    )
    technical_agent = TechnicalGateAgent(
        llm_calls=runtime.llm_calls,
        records=records,
        artifacts=artifacts,
        metadata_factory=metadata,
        provenance_validator=validate_llm_invocation_provenance,
    )
    technical_service = TechnicalGateService(
        agent=technical_agent,
        publisher=runner,
        records=records,
        identity_ref=identity(RequesterRole.TECHNICAL_GATE),
        orchestration_identity_ref=identity(RequesterRole.ORCHESTRATION),
        t10_services=t10_services,
        ready_work=runner,
    )
    rule_scope_agent = RuleScopeGateAgent(
        llm_calls=runtime.llm_calls,
        records=records,
        artifacts=artifacts,
        provenance_validator=validate_llm_invocation_provenance,
    )
    rule_scope_service = RuleScopeGateService(
        agent=rule_scope_agent,
        execution_factory=None,
        publisher=WorkflowRuleScopePublisher(runner),
        metadata_factory=metadata,
        id_factory=lambda _prefix: str(ids.new(RecordId)),
        current_owner=current_owner,
        current_policy_state=current_policy_state,
        prompt_guard=ExactRuleScopePromptGuard(records=records, artifacts=artifacts),
    )
    rule_scope_inputs = StoredRuleScopeInputResolver(
        records=records,
        artifacts=artifacts,
        resolve_call=rule_scope_call_resolver,
        current_owner=current_owner,
        gate_identity_ref=stored_identity(RequesterRole.RULE_SCOPE_GATE),
    )
    finding_service = FindingNormalizationService(
        records=records,
        current_records=runtime.queries.current_records,
        published_records=runtime.queries.published_records,
        ids=ids,
        clock=clock,
    )
    reporter_agent = ReporterAgent(
        llm_calls=runtime.llm_calls,
        records=records,
        artifacts=artifacts,
        provenance_validator=validate_llm_invocation_provenance,
        owner_resolver=reporter_owner,
    )
    reporter_workflow = ReporterDraftWorkflow(
        agent=reporter_agent,
        records=records,
        artifacts=artifacts,
        metadata_factory=metadata,
    )
    reporter_inputs = StoredReporterInputResolver(
        records=records, resolve_call=reporter_call_resolver
    )
    return T12Services(
        cwe=CWELabelingHandler(cwe_service, cwe_call_resolver),
        technical=TechnicalGateHandler(technical_service, technical_call_resolver),
        rule_scope=RuleScopeGateHandler(
            rule_scope_service, resolve_inputs=rule_scope_inputs
        ),
        finding=FindingNormalizeHandler(service=finding_service, records=records),
        reporter=ReporterWorkHandler(
            workflow=reporter_workflow, resolve_inputs=reporter_inputs
        ),
        primitive_handoff=t10_services.primitive_handoff,
        technical_revisions=TechnicalRevisionReconciler(
            service=technical_service,
            current=runtime.queries,
        ),
    )


def build_t13_services(
    *,
    runtime: RuntimeServices,
    runner: WorkflowRunner,
    clock: Clock,
    ids: IdGenerator,
    budget_scope_ref: BudgetScopeRef,
    role_identity_refs: Mapping[RequesterRole, BudgetScopeRef],
    chaining_call_resolver: ChainingCallResolver,
    chaining_lineage: ChainingLineagePort,
    verification_policy_ref: StoredDataRef | None,
    verification_playbook_ref: StoredDataRef | None,
) -> T13Services:
    """Build T13 from injected T09 calls and the runtime's concrete lineage.

    The caller must provide the exact-call resolver selected by T09 and the same
    concrete lineage adapter already bound to ``runtime``.  There is no fake or
    empty production fallback, and this builder never selects a Provider/model.
    """

    from sastsimi.agents.chaining import ChainingAgent
    from sastsimi.chaining.publication import RuntimeChainingResultPublisher
    from sastsimi.chaining.service import ChainingWorkflowService
    from sastsimi.chaining.work_handlers import (
        ChainingWorkHandler,
        HypothesisProposalHandler,
        PrimitiveUpdateHandler,
    )
    from sastsimi.reporting.primitive_admission import PrimitiveAdmissionRuntime
    from sastsimi.runtime.chaining_reconciliation import (
        ChainingReconciliationService,
        ChainingStartupReconciler,
    )
    from sastsimi.runtime.llm_invocation_provenance import (
        validate_llm_invocation_provenance,
    )
    from sastsimi.storage.chaining_child_registration import (
        ChainingChildRegistrationConfig,
        SQLiteChainingChildRegistration,
    )
    from sastsimi.storage.chaining_registration import (
        ChainingCohortStore,
        ChainingCommittedSourceStore,
    )
    from sastsimi.storage.repositories import SQLiteRecordStore
    from sastsimi.storage.verification_registration import (
        VerificationRegistrationService as SQLiteVerificationRegistration,
    )
    from sastsimi.storage.work_service import WorkService as SQLiteWorkService

    def identity(role: RequesterRole) -> BudgetScopeRef:
        value = role_identity_refs.get(role)
        if value is None:
            raise ValueError(f"{role.value}_IDENTITY_REQUIRED")
        return value

    orchestration_identity = identity(RequesterRole.ORCHESTRATION)
    chaining_identity = identity(RequesterRole.CHAINING)
    primitive_identity = identity(RequesterRole.PRIMITIVE_ADMISSION_RUNTIME)
    recovery_identity = identity(RequesterRole.RECOVERY)
    verification_identity = identity(RequesterRole.VERIFICATION)

    records = runtime.unit_of_work.records
    works = runtime.work.store
    verification = runtime.verification_registration.store
    if runner.runtime is not runtime:
        raise ValueError("T13_RUNTIME_MISMATCH")
    if (
        not isinstance(records, SQLiteRecordStore)
        or not isinstance(works, SQLiteWorkService)
        or works.records is not records
        or not isinstance(verification, SQLiteVerificationRegistration)
        or verification.transitions.works is not works
    ):
        raise ValueError("T13_STORAGE_RUNTIME_MISMATCH")
    if runtime.chaining_lineage is not chaining_lineage:
        raise ValueError("CHAINING_LINEAGE_RUNTIME_MISMATCH")
    if (
        not isinstance(budget_scope_ref, StoredDataRef)
        or not isinstance(verification_identity, StoredDataRef)
        or verification_policy_ref is None
        or verification_playbook_ref is None
    ):
        raise ValueError("T13_CHILD_CONFIG_REQUIRED")
    child_config = ChainingChildRegistrationConfig(
        budget_binding_ref=budget_scope_ref,
        verification_owner_identity_ref=verification_identity,
        verification_policy_ref=verification_policy_ref,
        verification_playbook_ref=verification_playbook_ref,
    )
    if len(
        {
            (ref.workspace_id, ref.commit_id)
            for ref in (
                child_config.budget_binding_ref,
                child_config.verification_owner_identity_ref,
                child_config.verification_policy_ref,
                child_config.verification_playbook_ref,
            )
        }
    ) != 1:
        raise ValueError("T13_CHILD_CONFIG_SCOPE_MISMATCH")
    child_registration = SQLiteChainingChildRegistration(
        works=works,
        transitions=verification.transitions,
        verification=verification,
        lineage=chaining_lineage,
        config=child_config,
    )

    def metadata(
        source: RecordMeta,
        record_type: str,
        attempt_id: AttemptId | None,
    ) -> RecordMeta:
        record_id = ids.new(RecordId)
        return RecordMeta(
            record_id=record_id,
            logical_record_id=LogicalRecordId(str(record_id)),
            record_type=record_type,
            schema_version=source.schema_version,
            revision_number=1,
            previous_record_id=None,
            created_at=clock.now(),
            analysis_id=source.analysis_id,
            workspace_id=source.workspace_id,
            commit_id=source.commit_id,
            hypothesis_id=source.hypothesis_id,
            attempt_id=attempt_id,
        )

    sources = ChainingCommittedSourceStore(records)
    cohorts = ChainingCohortStore(works)
    admission = PrimitiveAdmissionRuntime(
        records=records,
        current=runtime.queries,
        publisher=runner,
        identity_ref=primitive_identity,
        clock=clock,
        ids=ids,
    )
    agent = ChainingAgent(
        llm_calls=runtime.llm_calls,
        records=records,
        artifacts=runtime.unit_of_work.artifacts,
        provenance_validator=validate_llm_invocation_provenance,
    )
    publisher = RuntimeChainingResultPublisher(runner, chaining_identity)
    workflow = ChainingWorkflowService(
        agent=agent,
        records=records,
        artifacts=runtime.unit_of_work.artifacts,
        pools=cohorts.pools,
        lineage=chaining_lineage,
        publisher=publisher,
        children=child_registration,
        ids=ids,
        metadata_factory=metadata,
        requester_identity_ref=orchestration_identity,
    )
    reconciliation = ChainingReconciliationService(
        sources=sources,
        cohorts=cohorts,
        children=child_registration,
        records=records,
        budget_scope_ref=budget_scope_ref,
        requester_identity_ref=recovery_identity,
    )
    return T13Services(
        primitive_update=PrimitiveUpdateHandler(
            admission=admission,
            sources=sources,
            cohorts=cohorts,
            budget_scope_ref=budget_scope_ref,
            requester_identity_ref=primitive_identity,
        ),
        chaining=ChainingWorkHandler(
            service=workflow,
            resolve_call=chaining_call_resolver,
        ),
        hypothesis_proposal=HypothesisProposalHandler(
            registration=child_registration,
            requester_identity_ref=orchestration_identity,
        ),
        reconciliation=reconciliation,
        reconcile_startup=ChainingStartupReconciler(
            reconciliation=reconciliation,
            published_records=runtime.queries.published_records,
        ),
    )
