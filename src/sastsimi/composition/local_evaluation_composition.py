"""Scope-locked application foundation for honest local evaluation runs.

This composition reuses the normal runtime, scheduler, handlers, persistence,
and report exporter.  It deliberately does not create Production descriptors
or infer approvals.  Exact tool, prompt, Provider, and Sandbox capabilities
must arrive through the injected capability resolver.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, cast

from sastsimi.config.local_evaluation_profile import LocalEvaluationProfile
from sastsimi.config.production_profile import ProductionBudgetSettings
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.analysis import AnalysisRunState, AnalysisStartRequest
from sastsimi.contracts.budget import Purpose
from sastsimi.contracts.ids import LogicalRecordId, RecordId
from sastsimi.contracts.records import RunMeta
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    HostConfigurationRef,
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.work import WorkType
from sastsimi.orchestration.analysis_application import (
    AnalysisReadinessPort,
    build_analysis_application,
)
from sastsimi.orchestration.local_evaluation_entrypoint import (
    ScopeOwnedLocalEvaluationApplication,
)
from sastsimi.orchestration.production_operator_profiles import (
    LocalEvaluationOperatorProfiles,
    ProductionTrustedEvidence,
)
from sastsimi.orchestration.run_initialization import PostWorkspaceSeederPort
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.ports.llm_provider import LLMProviderAdapter
from sastsimi.ports.scheduler import ExternalCancellationPort, SchedulerStorePort
from sastsimi.ports.trusted_evidence import TrustedEvidencePort
from sastsimi.ports.work_handler import WorkHandler
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.work_service import HandlerFailureRecorder
from sastsimi.runtime.workflow_runner import WorkflowRunner

_SAFE_REASON = re.compile(r"[A-Z0-9_]{1,96}\Z")


class LocalEvaluationCompositionUnavailable(RuntimeError):
    """Safe reason why the explicit local capability closure cannot run."""

    def __init__(self, reason_code: str) -> None:
        if _SAFE_REASON.fullmatch(reason_code) is None:
            raise ValueError("LOCAL_EVALUATION_REASON_INVALID")
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class LocalEvaluationInstallationContext:
    """Exact runtime-owned services exposed to an injected local installer."""

    data_dir: Path
    request: AnalysisStartRequest
    profile: LocalEvaluationProfile
    scope: PlannedRunScope
    clock: Clock
    ids: IdGenerator
    profiles: LocalEvaluationOperatorProfiles
    role_identity_refs: Mapping[RequesterRole, BudgetScopeRef]
    budget_binding_ref: StoredDataRef
    runtime: RuntimeServices
    scheduler_store: SchedulerStorePort
    runner: WorkflowRunner


@dataclass(frozen=True, slots=True)
class InstalledLocalEvaluationServices:
    """Complete handler graph and readiness checks supplied by local wiring."""

    handlers: tuple[tuple[WorkType, WorkHandler], ...]
    seeder: PostWorkspaceSeederPort
    readiness: AnalysisReadinessPort
    external_cancellation: ExternalCancellationPort


type LocalEvaluationFeatureInstaller = Callable[
    [LocalEvaluationInstallationContext], InstalledLocalEvaluationServices
]


@dataclass(frozen=True, slots=True)
class ResolvedLocalEvaluationCapabilities:
    """Exact non-secret local capabilities selected before runtime creation."""

    llm_adapters: Mapping[tuple[StoredDataRef, str], LLMProviderAdapter]
    workspace_dependency_refs: tuple[RecordRef, ...]
    handler_failure_recorder: HandlerFailureRecorder
    install: LocalEvaluationFeatureInstaller
    configuration_evidence: TrustedEvidencePort


class LocalEvaluationCapabilityResolver(Protocol):
    def resolve(
        self,
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: LocalEvaluationProfile,
        scope: PlannedRunScope,
    ) -> ResolvedLocalEvaluationCapabilities: ...


@dataclass(frozen=True, slots=True)
class _ResultMetadata:
    clock: Clock
    ids: IdGenerator

    def create(self, state: AnalysisRunState) -> RunMeta:
        record_id = self.ids.new(RecordId)
        return RunMeta(
            record_id=record_id,
            logical_record_id=LogicalRecordId(str(record_id)),
            record_type="analysis_run_result",
            schema_version="1.0.0",
            revision_number=1,
            previous_record_id=None,
            created_at=self.clock.now(),
            analysis_id=state.meta.analysis_id,
        )


class ConcreteLocalEvaluationApplicationFactory:
    """Build one local-only application from an explicit capability closure."""

    def __init__(
        self,
        capabilities: LocalEvaluationCapabilityResolver | None = None,
        *,
        clock: Clock | None = None,
        ids: IdGenerator | None = None,
    ) -> None:
        self._capabilities = capabilities
        self._clock = clock
        self._ids = ids

    def build(
        self,
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: LocalEvaluationProfile,
        scope: PlannedRunScope,
    ) -> ScopeOwnedLocalEvaluationApplication:
        _require_local_scope(request, profile, scope)
        if self._capabilities is None:
            raise LocalEvaluationCompositionUnavailable(
                "LOCAL_EVALUATION_CAPABILITY_RESOLVER_REQUIRED"
            )

        from sastsimi.runtime.system_support import SystemClock, UUIDIds

        resolved = self._capabilities.resolve(
            data_dir=data_dir,
            request=request,
            profile=profile,
            scope=scope,
        )
        _require_resolved_capabilities(resolved, profile, scope)
        return self._build_foundation(
            data_dir=data_dir,
            request=request,
            profile=profile,
            scope=scope,
            resolved=resolved,
            clock=self._clock or SystemClock(),
            ids=self._ids or UUIDIds(),
        )

    @staticmethod
    def _build_foundation(
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: LocalEvaluationProfile,
        scope: PlannedRunScope,
        resolved: ResolvedLocalEvaluationCapabilities,
        clock: Clock,
        ids: IdGenerator,
    ) -> ScopeOwnedLocalEvaluationApplication:
        from sastsimi.composition.runtime import build_runtime
        from sastsimi.config.runtime_paths import RuntimePaths
        from sastsimi.orchestration.analysis_state_factory import AnalysisStateFactory
        from sastsimi.orchestration.production_capabilities import (
            CompositeProductionTrustedEvidence,
        )
        from sastsimi.orchestration.reporting_application import (
            ReportingAnalysisApplication,
        )
        from sastsimi.orchestration.result_aggregation import ResultAggregationService
        from sastsimi.orchestration.run_initialization import RunInitializationService
        from sastsimi.reporting.markdown_export import ReportMarkdownService
        from sastsimi.runtime.cancellation_service import CancellationService
        from sastsimi.runtime.work_service import WorkService
        from sastsimi.storage.database import Database
        from sastsimi.storage.report_export import SQLiteCurrentReportSource
        from sastsimi.storage.run_control import (
            CancellationTransitionPort,
            RunControlStore,
        )
        from sastsimi.storage.work_dispatch import WorkDispatchStore
        from sastsimi.storage.work_service import WorkService as SQLiteWorkService

        profiles = LocalEvaluationOperatorProfiles(
            scope=scope,
            program_id=profile.program_id,
            settings=cast(ProductionBudgetSettings, profile.budget),
            clock=clock,
            ids=ids,
        )
        evidence = CompositeProductionTrustedEvidence(
            ProductionTrustedEvidence(profiles), resolved.configuration_evidence
        )
        identities = MappingProxyType(
            {role: profiles.identity_ref(role) for role in RequesterRole}
        )
        runtime = build_runtime(
            data_dir,
            scope.workspace_id,
            scope.commit_id,
            clock,
            ids,
            recovery_identity_ref=identities[RequesterRole.RECOVERY],
            evidence=evidence,
            context_service_identity_ref=_stored_identity(
                identities, RequesterRole.CONTEXT_RETRIEVAL_SERVICE
            ),
            finding_service_identity_ref=_stored_identity(
                identities, RequesterRole.VERIFICATION
            ),
            analysis_finalization_identity_ref=identities[RequesterRole.ORCHESTRATION],
            llm_adapters=resolved.llm_adapters,
            capability_host_id=profile.host_id,
        )
        runtime = replace(
            runtime,
            work=WorkService(runtime.work.store, resolved.handler_failure_recorder),
        )
        profiles.publish_code_profiles(runtime.configuration)

        scheduler_store = WorkDispatchStore(cast(SQLiteWorkService, runtime.work.store))
        runner = WorkflowRunner(
            runtime,
            clock,
            ids,
            output_approval=evidence.output_approval,
            scheduler_store=scheduler_store,
        )
        binding_ref = reference(profiles.binding)
        if not isinstance(binding_ref, StoredDataRef):
            raise LocalEvaluationCompositionUnavailable(
                "LOCAL_EVALUATION_BUDGET_BINDING_SCOPE_INVALID"
            )
        installation = resolved.install(
            LocalEvaluationInstallationContext(
                data_dir=data_dir,
                request=request,
                profile=profile,
                scope=scope,
                clock=clock,
                ids=ids,
                profiles=profiles,
                role_identity_refs=identities,
                budget_binding_ref=binding_ref,
                runtime=runtime,
                scheduler_store=scheduler_store,
                runner=runner,
            )
        )
        _require_installed_services(installation)

        storage_works = cast(SQLiteWorkService, runtime.work.store)
        controls = RunControlStore(
            Database(RuntimePaths(data_dir).database),
            clock,
            works=storage_works,
            ids=ids,
            transitions=cast(CancellationTransitionPort, runtime.transitions),
            cancellation_identity_ref=identities[RequesterRole.ORCHESTRATION],
        )
        cancellation = CancellationService(
            controls,
            scheduler_store,
            installation.external_cancellation,
        )
        initializer = RunInitializationService(
            profiles=profiles,
            state_factory=AnalysisStateFactory(clock, ids, scope=scope),
            budgets=runtime.budget_registry,
            ready_work=runner,
            work_query=scheduler_store,
            workspace_identity_ref=identities[RequesterRole.REPOSITORY_LOADER],
            workspace_dependency_refs=resolved.workspace_dependency_refs,
            seeder=installation.seeder,
        )
        aggregator = ResultAggregationService(
            states=runtime.budget_registry,
            queries=runtime.queries,
            records=runtime.unit_of_work.records,
            artifacts=runtime.unit_of_work.artifacts,
            clock=clock,
            metadata=_ResultMetadata(clock, ids),
        )
        application = build_analysis_application(
            expected_purpose=Purpose.LOCAL_EVALUATION,
            request=request,
            scope=scope,
            profile=profile,
            runtime=runtime,
            handlers=installation.handlers,
            initializer=initializer,
            aggregator=aggregator,
            scheduler_store=scheduler_store,
            controls=controls,
            cancellation=cancellation,
            resumer=scheduler_store,
            clock=clock,
            readiness=installation.readiness,
            error_namespace="LOCAL_EVALUATION",
        )
        return ReportingAnalysisApplication(
            application,
            ReportMarkdownService(data_dir, SQLiteCurrentReportSource(data_dir)),
        )


def _stored_identity(
    identities: Mapping[RequesterRole, BudgetScopeRef], role: RequesterRole
) -> StoredDataRef:
    value = identities[role]
    if not isinstance(value, StoredDataRef):
        raise LocalEvaluationCompositionUnavailable(
            f"LOCAL_EVALUATION_{role.value}_IDENTITY_REQUIRED"
        )
    return value


def _require_local_scope(
    request: AnalysisStartRequest,
    profile: LocalEvaluationProfile,
    scope: PlannedRunScope,
) -> None:
    if (
        request.purpose != Purpose.LOCAL_EVALUATION
        or profile.purpose != "LOCAL_EVALUATION"
        or profile.production_ready is not False
        or request.repository_ref != scope.repository_ref
        or request.requested_git_ref.lower() != str(scope.commit_id)
        or str(request.program_id) != profile.program_id
    ):
        raise LocalEvaluationCompositionUnavailable(
            "LOCAL_EVALUATION_REQUEST_SCOPE_MISMATCH"
        )


def _require_resolved_capabilities(
    resolved: ResolvedLocalEvaluationCapabilities,
    profile: LocalEvaluationProfile,
    scope: PlannedRunScope,
) -> None:
    if not resolved.llm_adapters:
        raise LocalEvaluationCompositionUnavailable(
            "LOCAL_EVALUATION_LLM_ADAPTER_REQUIRED"
        )
    if not callable(
        getattr(resolved.handler_failure_recorder, "record_handler_failure", None)
    ):
        raise LocalEvaluationCompositionUnavailable(
            "LOCAL_EVALUATION_HANDLER_FAILURE_RECORDER_REQUIRED"
        )
    if not callable(resolved.install):
        raise LocalEvaluationCompositionUnavailable(
            "LOCAL_EVALUATION_FEATURE_INSTALLER_REQUIRED"
        )
    evidence_methods = (
        "capability_approval_authorized",
        "static_tool_configuration_approved",
        "playbook_configuration_approved",
        "llm_configuration_approved",
        "sandbox_configuration_approved",
    )
    if any(
        not callable(getattr(resolved.configuration_evidence, method, None))
        for method in evidence_methods
    ):
        raise LocalEvaluationCompositionUnavailable(
            "LOCAL_EVALUATION_CONFIGURATION_EVIDENCE_REQUIRED"
        )
    for (provider_ref, model), adapter in resolved.llm_adapters.items():
        if (
            provider_ref.data_kind != "provider_profile"
            or (provider_ref.workspace_id, provider_ref.commit_id)
            != (scope.workspace_id, scope.commit_id)
            or not model.strip()
            or not isinstance(adapter, LLMProviderAdapter)
        ):
            raise LocalEvaluationCompositionUnavailable(
                "LOCAL_EVALUATION_LLM_ADAPTER_INVALID"
            )

    dependencies = resolved.workspace_dependency_refs
    policies = tuple(
        ref
        for ref in dependencies
        if isinstance(ref, RunStoredDataRef)
        and ref.data_kind == "artifact"
        and ref.record_id is None
    )
    git_refs = tuple(
        ref for ref in dependencies if isinstance(ref, HostConfigurationRef)
    )
    if (
        len(dependencies) != len(set(dependencies))
        or len(policies) != 1
        or policies[0].analysis_id != scope.analysis_id
        or len(git_refs) not in {1, 2}
        # Host capability profiles are deliberately reusable across analysis
        # runs.  The resolver owns the approved-current check; this boundary
        # only rejects capabilities published for another host.
        or any(ref.host_id != profile.host_id for ref in git_refs)
        or len(policies) + len(git_refs) != len(dependencies)
    ):
        raise LocalEvaluationCompositionUnavailable(
            "LOCAL_EVALUATION_WORKSPACE_CAPABILITY_INVALID"
        )


def _require_installed_services(
    installation: InstalledLocalEvaluationServices,
) -> None:
    kinds = tuple(kind for kind, _handler in installation.handlers)
    if (
        len(kinds) != len(set(kinds))
        or set(kinds) != set(WorkType)
        or any(
            not callable(getattr(handler, "execute", None))
            for _kind, handler in installation.handlers
        )
        or not callable(getattr(installation.seeder, "ensure_initial", None))
        or not callable(getattr(installation.readiness, "require_ready", None))
        or not callable(getattr(installation.external_cancellation, "prepare", None))
        or not callable(
            getattr(installation.external_cancellation, "validate_inventory", None)
        )
        or not callable(getattr(installation.external_cancellation, "cancel", None))
    ):
        raise LocalEvaluationCompositionUnavailable(
            "LOCAL_EVALUATION_HANDLER_INSTALLATION_INCOMPLETE"
        )


__all__ = [
    "ConcreteLocalEvaluationApplicationFactory",
    "InstalledLocalEvaluationServices",
    "LocalEvaluationCapabilityResolver",
    "LocalEvaluationCompositionUnavailable",
    "LocalEvaluationFeatureInstaller",
    "LocalEvaluationInstallationContext",
    "ResolvedLocalEvaluationCapabilities",
]
