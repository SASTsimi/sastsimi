"""The composition root for configuration, logging and injected local runtime."""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, TextIO, cast

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
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef
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
    from sastsimi.contracts.evaluation import AnalysisRunResult
    from sastsimi.contracts.reporting import ReportDraft
    from sastsimi.contracts.static import StaticToolProfile
    from sastsimi.gates.composition import T12Services
    from sastsimi.gates.cwe_handler import GateCallResolver
    from sastsimi.gates.rule_scope_handler import RuleScopeCallResolver
    from sastsimi.orchestration.fake_pipeline import FakePipeline
    from sastsimi.orchestration.fake_scenario_runtime import WorkflowBundle
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
    from sastsimi.ports.context import ContextLineageReaderPort
    from sastsimi.ports.dto import StaticRuleMapping
    from sastsimi.ports.static_tool import StaticProcessAdapter
    from sastsimi.ports.workspace import WorkspaceLocatorPort
    from sastsimi.reporting.work_handlers import ReporterCallResolver
    from sastsimi.reproduction.composition import T11Services
    from sastsimi.reproduction.production import DynamicSandboxAuthorizationResolver
    from sastsimi.runtime.workflow_runner import WorkflowRunner
    from sastsimi.static_analysis.coordinator import StaticToolCoordinator
    from sastsimi.static_analysis.normalizer import DecoderKey, RawDecoder
    from sastsimi.verification.composition import T10Services
    from sastsimi.verification.context_service import (
        ContextRetrievalService,
        TrackedFilesResolver,
    )
    from sastsimi.verification.service import VerificationService


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
    transitions = SQLiteTransitions(works, artifacts)
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
    from sastsimi.verification.composition import compose_t10_services

    return compose_t10_services(
        runtime=runtime,
        runner=runner,
        clock=clock,
        ids=ids,
        role_identity_refs=role_identity_refs,
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
    from sastsimi.reproduction.composition import compose_t11_services
    from sastsimi.sandbox.cleanup import OwnedResourceRegistry
    from sastsimi.sandbox.controller import SandboxController
    from sastsimi.sandbox.docker_adapter import DockerAdapter
    from sastsimi.sandbox.health_check import SandboxHealthChecker
    from sastsimi.sandbox.recipe_store import EnvironmentRecipeStore
    from sastsimi.sandbox.session_manager import ReproductionSessionManager
    from sastsimi.sandbox.setup_automation import ReproductionSetupAutomation

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
    return compose_t11_services(
        runtime=runtime,
        runner=runner,
        agent=agent,
        controller=controller,
        setup=setup,
        docker=docker,
        sessions=ReproductionSessionManager(clock=clock, ids=ids),
        artifacts=artifacts,
        clock=clock,
        ids=ids,
        role_identity_refs=role_identity_refs,
        sandbox_authorization=sandbox_authorization,
        verification=verification,
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

    from sastsimi.gates.composition import compose_t12_services

    return compose_t12_services(
        runtime=runtime,
        runner=runner,
        clock=clock,
        ids=ids,
        t10_services=t10_services,
        taxonomy_version=taxonomy_version,
        role_identity_refs=role_identity_refs,
        cwe_call_resolver=cwe_call_resolver,
        technical_call_resolver=technical_call_resolver,
        rule_scope_call_resolver=rule_scope_call_resolver,
        reporter_call_resolver=reporter_call_resolver,
    )
