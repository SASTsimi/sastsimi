"""Fail-closed production composition over exact approved capabilities.

The command profile intentionally contains no approval records. A capability
resolver must therefore supply the already-validated Provider/Prompt, Git,
static-analysis, policy, playbook, and Sandbox closure. This module owns the
generic production foundation and never invents a missing configuration.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, cast

from sastsimi.config.production_profile import ProductionProfile
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.analysis import AnalysisRunState, AnalysisStartRequest
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
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.ports.llm_provider import LLMProviderAdapter
from sastsimi.ports.scheduler import ExternalCancellationPort, SchedulerStorePort
from sastsimi.ports.work_handler import WorkHandler
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.work_service import HandlerFailureRecorder, WorkService
from sastsimi.runtime.workflow_runner import WorkflowRunner

from .production_application import (
    ProductionReadinessPort,
    build_production_application,
)
from .production_call_authority import AnalysisApprovedRoute
from .production_entrypoint import ScopeOwnedProductionApplication
from .production_operator_profiles import (
    ProductionOperatorProfiles,
    ProductionTrustedEvidence,
)
from .run_initialization import PostWorkspaceSeederPort
from .run_scope_plan import PlannedRunScope

_SAFE_REASON = re.compile(r"[A-Z0-9_]{1,96}\Z")


class ProductionCapabilityUnavailable(RuntimeError):
    """A safe, operator-actionable reason why exact production input is absent."""

    def __init__(self, reason_code: str) -> None:
        if _SAFE_REASON.fullmatch(reason_code) is None:
            raise ValueError("PRODUCTION_CAPABILITY_REASON_INVALID")
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class ProductionInstallationContext:
    """Scope-bound services exposed to the T08-T13 capability installer.

    The installer uses existing public builders for the workspace/static graph,
    T10 LLM verification, lazy T11 dynamic reproduction, T12 reporting, and T13
    chaining. It may not replace the runtime, scheduler, identities, or budget
    binding created here.
    """

    data_dir: Path
    request: AnalysisStartRequest
    profile: ProductionProfile
    scope: PlannedRunScope
    clock: Clock
    ids: IdGenerator
    profiles: ProductionOperatorProfiles
    role_identity_refs: Mapping[RequesterRole, BudgetScopeRef]
    approved_llm_routes: tuple[AnalysisApprovedRoute, ...]
    budget_binding_ref: StoredDataRef
    runtime: RuntimeServices
    scheduler_store: SchedulerStorePort
    runner: WorkflowRunner


@dataclass(frozen=True, slots=True)
class InstalledProductionServices:
    """Complete domain handler graph installed from exact capability records."""

    handlers: tuple[tuple[WorkType, WorkHandler], ...]
    seeder: PostWorkspaceSeederPort
    readiness: ProductionReadinessPort
    external_cancellation: ExternalCancellationPort


type ProductionFeatureInstaller = Callable[
    [ProductionInstallationContext], InstalledProductionServices
]


@dataclass(frozen=True, slots=True)
class ResolvedProductionCapabilities:
    """Pre-runtime capability closure with no credential values."""

    llm_adapters: Mapping[tuple[StoredDataRef, str], LLMProviderAdapter]
    approved_llm_routes: tuple[AnalysisApprovedRoute, ...]
    workspace_dependency_refs: tuple[RecordRef, ...]
    handler_failure_recorder: HandlerFailureRecorder
    install: ProductionFeatureInstaller


class ProductionCapabilityResolver(Protocol):
    """Resolve only explicit, currently ACTIVE capability and approval records."""

    def resolve(
        self,
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: ProductionProfile,
        scope: PlannedRunScope,
    ) -> ResolvedProductionCapabilities: ...


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


class ConcreteProductionApplicationFactory:
    """Build one production-only SQLite application from exact capabilities."""

    def __init__(
        self,
        capabilities: ProductionCapabilityResolver | None = None,
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
        profile: ProductionProfile,
        scope: PlannedRunScope,
    ) -> ScopeOwnedProductionApplication:
        if self._capabilities is None:
            raise _unavailable("PRODUCTION_CAPABILITY_RESOLVER_REQUIRED")

        from sastsimi.prompts.production import ProductionLLMConfigurationService
        from sastsimi.runtime.system_support import SystemClock, UUIDIds

        try:
            ProductionLLMConfigurationService.require_complete_profile(
                profile.llm_routes
            )
        except ValueError:
            raise _unavailable("PRODUCTION_PROMPT_ROUTE_SET_INCOMPLETE") from None

        try:
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
        except ProductionCapabilityUnavailable as error:
            raise _unavailable(error.reason_code) from None

    @staticmethod
    def _build_foundation(
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: ProductionProfile,
        scope: PlannedRunScope,
        resolved: ResolvedProductionCapabilities,
        clock: Clock,
        ids: IdGenerator,
    ) -> ScopeOwnedProductionApplication:
        from sastsimi.bootstrap import build_runtime
        from sastsimi.config.runtime_paths import RuntimePaths
        from sastsimi.orchestration.analysis_state_factory import AnalysisStateFactory
        from sastsimi.orchestration.result_aggregation import ResultAggregationService
        from sastsimi.orchestration.run_initialization import RunInitializationService
        from sastsimi.runtime.cancellation_service import CancellationService
        from sastsimi.storage.database import Database
        from sastsimi.storage.run_control import RunControlStore
        from sastsimi.storage.work_dispatch import WorkDispatchStore
        from sastsimi.storage.work_service import WorkService as SQLiteWorkService

        profiles = ProductionOperatorProfiles(
            scope=scope,
            program_id=profile.program_id,
            settings=profile.budget,
            clock=clock,
            ids=ids,
        )
        evidence = ProductionTrustedEvidence(profiles)
        identities = MappingProxyType(
            {role: profiles.identity_ref(role) for role in RequesterRole}
        )

        context_identity = _stored_identity(
            identities, RequesterRole.CONTEXT_RETRIEVAL_SERVICE
        )
        finding_identity = _stored_identity(identities, RequesterRole.VERIFICATION)
        runtime = build_runtime(
            data_dir,
            scope.workspace_id,
            scope.commit_id,
            clock,
            ids,
            recovery_identity_ref=identities[RequesterRole.RECOVERY],
            evidence=evidence,
            context_service_identity_ref=context_identity,
            finding_service_identity_ref=finding_identity,
            analysis_finalization_identity_ref=identities[
                RequesterRole.ORCHESTRATION
            ],
            llm_adapters=resolved.llm_adapters,
            capability_host_id=profile.host_id,
        )
        # ``build_runtime`` is intentionally transport-agnostic. Production
        # workers must never start unless an exact durable failure recorder was
        # supplied by the capability closure.
        runtime = replace(
            runtime,
            work=WorkService(runtime.work.store, resolved.handler_failure_recorder),
        )
        profiles.publish_code_profiles(runtime.configuration)

        scheduler_store = WorkDispatchStore(
            cast(SQLiteWorkService, runtime.work.store)
        )
        runner = WorkflowRunner(
            runtime,
            clock,
            ids,
            output_approval=evidence.output_approval,
            scheduler_store=scheduler_store,
        )
        binding_ref = reference(profiles.binding)
        if not isinstance(binding_ref, StoredDataRef):
            raise ValueError("PRODUCTION_BUDGET_BINDING_SCOPE_INVALID")
        installation = resolved.install(
            ProductionInstallationContext(
                data_dir=data_dir,
                request=request,
                profile=profile,
                scope=scope,
                clock=clock,
                ids=ids,
                profiles=profiles,
                role_identity_refs=identities,
                approved_llm_routes=resolved.approved_llm_routes,
                budget_binding_ref=binding_ref,
                runtime=runtime,
                scheduler_store=scheduler_store,
                runner=runner,
            )
        )
        _require_installed_services(installation)

        controls = RunControlStore(Database(RuntimePaths(data_dir).database), clock)
        cancellation = CancellationService(
            controls,
            scheduler_store,
            installation.external_cancellation,
        )
        initializer = RunInitializationService(
            profiles=profiles,
            state_factory=AnalysisStateFactory(clock, ids),
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
        return build_production_application(
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
        )


def _stored_identity(
    identities: Mapping[RequesterRole, BudgetScopeRef], role: RequesterRole
) -> StoredDataRef:
    value = identities[role]
    if not isinstance(value, StoredDataRef):
        raise ValueError(f"{role.value}_CODE_SCOPE_IDENTITY_REQUIRED")
    return value


def _require_resolved_capabilities(
    resolved: ResolvedProductionCapabilities,
    profile: ProductionProfile,
    scope: PlannedRunScope,
) -> None:
    if not resolved.llm_adapters:
        raise ProductionCapabilityUnavailable("PRODUCTION_LLM_ADAPTER_REQUIRED")
    if not callable(
        getattr(resolved.handler_failure_recorder, "record_handler_failure", None)
    ):
        raise ProductionCapabilityUnavailable(
            "PRODUCTION_HANDLER_FAILURE_RECORDER_REQUIRED"
        )
    if not callable(resolved.install):
        raise ProductionCapabilityUnavailable("PRODUCTION_FEATURE_INSTALLER_REQUIRED")
    for (provider_ref, model), adapter in resolved.llm_adapters.items():
        if (
            not isinstance(provider_ref, StoredDataRef)
            or provider_ref.data_kind != "provider_profile"
            or (provider_ref.workspace_id, provider_ref.commit_id)
            != (scope.workspace_id, scope.commit_id)
            or not model.strip()
            or not isinstance(adapter, LLMProviderAdapter)
        ):
            raise ProductionCapabilityUnavailable("PRODUCTION_LLM_ADAPTER_INVALID")

    profile_routes = {
        (route.role, route.task_kind): route for route in profile.llm_routes
    }
    approved_routes = {
        (item.route.role, item.route.task_kind): item
        for item in resolved.approved_llm_routes
    }
    if (
        len(approved_routes) != len(resolved.approved_llm_routes)
        or set(approved_routes) != set(profile_routes)
    ):
        raise ProductionCapabilityUnavailable(
            "PRODUCTION_LLM_ROUTE_APPROVAL_INCOMPLETE"
        )
    approved_provider_keys: set[tuple[StoredDataRef, str]] = set()
    for key, item in approved_routes.items():
        configured = profile_routes[key]
        approval = item.approval
        scoped_refs = (
            approval.active_prompt_ref,
            approval.evaluation_prompt_ref,
            approval.quality_evaluation_ref,
            approval.provider_profile_ref,
        )
        if (
            item.analysis_id != str(scope.analysis_id)
            or item.route.provider_profile_key != configured.provider_profile_key
            or item.route.model != configured.model
            or item.route.prompt_key != configured.prompt_key
            or tuple(ref.data_kind for ref in scoped_refs)
            != (
                "prompt_registry_entry",
                "prompt_registry_entry",
                "evaluation_recommendation",
                "provider_profile",
            )
            or any(
                (ref.workspace_id, ref.commit_id)
                != (scope.workspace_id, scope.commit_id)
                for ref in scoped_refs
            )
        ):
            raise ProductionCapabilityUnavailable(
                "PRODUCTION_LLM_ROUTE_APPROVAL_INVALID"
            )
        approved_provider_keys.add((approval.provider_profile_ref, configured.model))
    if approved_provider_keys != set(resolved.llm_adapters):
        raise ProductionCapabilityUnavailable(
            "PRODUCTION_LLM_ROUTE_ADAPTER_MISMATCH"
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
        or any(ref.host_id != profile.host_id for ref in git_refs)
        or len(policies) + len(git_refs) != len(dependencies)
    ):
        raise ProductionCapabilityUnavailable(
            "PRODUCTION_WORKSPACE_CAPABILITY_INVALID"
        )


def _require_installed_services(installation: InstalledProductionServices) -> None:
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
        or not callable(
            getattr(installation.external_cancellation, "cancel", None)
        )
    ):
        raise ProductionCapabilityUnavailable(
            "PRODUCTION_HANDLER_INSTALLATION_INCOMPLETE"
        )


def _unavailable(reason_code: str) -> RuntimeError:
    from sastsimi.interfaces.cli.analyze import ProductionAnalyzeUnavailable

    return ProductionAnalyzeUnavailable(reason_code)


__all__ = [
    "ConcreteProductionApplicationFactory",
    "InstalledProductionServices",
    "ProductionCapabilityResolver",
    "ProductionCapabilityUnavailable",
    "ProductionInstallationContext",
    "ResolvedProductionCapabilities",
]
