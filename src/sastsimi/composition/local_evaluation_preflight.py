"""Concrete async preparation for the explicit LOCAL_EVALUATION command."""

from __future__ import annotations

import os
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Any, Protocol, cast

from sastsimi.capabilities.composition import (
    build_production_capability_probe_service,
)
from sastsimi.composition.local_evaluation_capabilities import (
    LocalCapabilityServiceFactory,
    LocalEvaluationApprovedCapabilities,
    resolve_local_approved_capabilities,
)
from sastsimi.composition.local_evaluation_composition import (
    ConcreteLocalEvaluationApplicationFactory,
    InstalledLocalEvaluationServices,
    LocalEvaluationCapabilityResolver,
    LocalEvaluationCompositionUnavailable,
    LocalEvaluationInstallationContext,
    ResolvedLocalEvaluationCapabilities,
)
from sastsimi.config.local_evaluation_profile import LocalEvaluationProfile
from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.ports.scheduler import CancellationObservation, CancellationTarget
from sastsimi.runtime.work_service import HandlerFailureRecorder
from sastsimi.verification.production_llm_work_handlers import ProductionCallPort


def _required_executable(name: str) -> Path:
    found = shutil.which(name)
    if found is None:
        raise LocalEvaluationCompositionUnavailable(
            f"LOCAL_EVALUATION_{name.upper()}_UNAVAILABLE"
        )
    try:
        executable = Path(found).resolve(strict=True)
    except OSError:
        raise LocalEvaluationCompositionUnavailable(
            f"LOCAL_EVALUATION_{name.upper()}_UNAVAILABLE"
        ) from None
    if not executable.is_file():
        raise LocalEvaluationCompositionUnavailable(
            f"LOCAL_EVALUATION_{name.upper()}_UNAVAILABLE"
        )
    return executable


def _default_capability_service_factory(
    data_dir: Path, profile: LocalEvaluationProfile
) -> LocalCapabilityServiceFactory:
    service = build_production_capability_probe_service(
        data_dir,
        host_id=profile.host_id,
        executable_paths={
            "git": _required_executable("git"),
            "opengrep": _required_executable("opengrep"),
            "docker": _required_executable("docker"),
        },
        docker_host=(
            "npipe:////./pipe/docker_engine"
            if os.name == "nt"
            else "unix:///var/run/docker.sock"
        ),
        codeql_container_config=profile.codeql_container,
    )
    return cast(LocalCapabilityServiceFactory, lambda _kind: service)


class ConcreteLocalEvaluationPreflight:
    """Resolve exact local host capabilities before synchronous composition."""

    def __init__(
        self,
        *,
        service_factory: Callable[
            [Path, LocalEvaluationProfile], LocalCapabilityServiceFactory
        ] = _default_capability_service_factory,
    ) -> None:
        self._service_factory = service_factory

    async def prepare(
        self,
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: LocalEvaluationProfile,
        scope: PlannedRunScope,
    ) -> ConcreteLocalEvaluationApplicationFactory:
        from sastsimi.composition.local_codex_binding import (
            build_local_codex_binding,
        )
        from sastsimi.composition.local_evaluation_evidence import (
            ExactLocalEvaluationTrustedEvidence,
        )
        from sastsimi.composition.local_evaluation_run_configuration import (
            build_local_evaluation_run_configuration,
        )
        from sastsimi.composition.local_prompt_configuration import (
            build_local_prompt_configuration_plan,
        )
        from sastsimi.config.package_resources import builtin_package_root
        from sastsimi.config.runtime_paths import RuntimePaths
        from sastsimi.providers.local_codex_validation import (
            validate_local_codex_binding,
        )
        from sastsimi.providers.local_evaluation_codex import (
            DeferredLLMProviderAdapter,
        )
        from sastsimi.runtime.system_support import SystemClock, UUIDIds
        from sastsimi.storage.artifact_store import LocalArtifactStore

        clock = SystemClock()
        ids = UUIDIds()
        approved = resolve_local_approved_capabilities(
            cast(Any, profile), self._service_factory(data_dir, profile)
        )
        docker_executable = _required_executable("docker")
        artifacts = LocalArtifactStore(
            RuntimePaths(data_dir).artifacts,
            scope.workspace_id,
            scope.commit_id,
        )
        binding_records = build_local_codex_binding(
            settings=profile.codex,
            scope=scope,
            artifacts=artifacts,
            ids=ids,
            clock=clock,
        )
        validation = await validate_local_codex_binding(
            records=binding_records,
            artifacts=artifacts,
            ids=ids,
            clock=clock,
            probe_timeout_ms=min(profile.timeouts.llm_ms, 120_000),
        )
        prompt_plan = build_local_prompt_configuration_plan(
            repository_root=builtin_package_root(),
            binding_records=binding_records,
            validation=validation,
            artifacts=artifacts,
            ids=ids,
            clock=clock,
            timeout_ms=profile.timeouts.llm_ms,
            max_parallel_calls=profile.budget.max_parallel_evidence_calls,
            max_calls_per_work=profile.budget.max_calls_per_work,
            max_retries=profile.budget.max_retries_per_work,
        )
        run_configuration = build_local_evaluation_run_configuration(
            profile=profile,
            scope=scope,
            artifacts=artifacts,
            ids=ids,
            clock=clock,
        )
        provider_ref = reference(validation.provider)
        if not isinstance(provider_ref, StoredDataRef):
            raise LocalEvaluationCompositionUnavailable(
                "LOCAL_EVALUATION_PROVIDER_SCOPE_INVALID"
            )
        deferred_adapter = DeferredLLMProviderAdapter(
            provider_profile_ref=provider_ref,
            model=validation.provider.model,
        )
        deferred_calls = DeferredLocalEvaluationCalls()
        deferred_failures = _DeferredLocalFailureRecorder()
        evidence = ExactLocalEvaluationTrustedEvidence(
            capability_evidence=approved.trusted_evidence,
            llm_records=cast(Any, prompt_plan.approval_records),
            playbook_records=(
                run_configuration.playbook,
                run_configuration.playbook_policy,
            ),
            sandbox_profiles=(run_configuration.sandbox_profile,),
        )

        def install(
            context: LocalEvaluationInstallationContext,
        ) -> InstalledLocalEvaluationServices:
            _require_install_scope(
                context=context,
                data_dir=data_dir,
                request=request,
                profile=profile,
                scope=scope,
            )
            return _install_local_features(
                context=context,
                approved=approved,
                prompt_plan=prompt_plan,
                run_configuration=run_configuration,
                validation=validation,
                deferred_adapter=deferred_adapter,
                deferred_calls=deferred_calls,
                deferred_failures=deferred_failures,
                repository_root=builtin_package_root(),
                docker_executable=docker_executable,
            )

        resolved = ResolvedLocalEvaluationCapabilities(
            llm_adapters={
                (provider_ref, validation.provider.model): deferred_adapter,
            },
            workspace_dependency_refs=(
                *approved.workspace_dependency_refs,
                run_configuration.workspace_policy_ref,
            ),
            handler_failure_recorder=deferred_failures,
            install=install,
            configuration_evidence=evidence,
        )
        resolver = _PreparedLocalCapabilityResolver(
            data_dir=data_dir.resolve(),
            request=request,
            profile=profile,
            scope=scope,
            resolved=resolved,
        )
        return ConcreteLocalEvaluationApplicationFactory(
            cast(LocalEvaluationCapabilityResolver, resolver),
            clock=clock,
            ids=ids,
        )


@dataclass(frozen=True, slots=True)
class _PreparedLocalCapabilityResolver:
    data_dir: Path
    request: AnalysisStartRequest
    profile: LocalEvaluationProfile
    scope: PlannedRunScope
    resolved: ResolvedLocalEvaluationCapabilities

    def resolve(
        self,
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: LocalEvaluationProfile,
        scope: PlannedRunScope,
    ) -> ResolvedLocalEvaluationCapabilities:
        if (
            data_dir.resolve() != self.data_dir
            or request != self.request
            or profile != self.profile
            or scope != self.scope
        ):
            raise LocalEvaluationCompositionUnavailable(
                "LOCAL_EVALUATION_PREFLIGHT_SCOPE_MISMATCH"
            )
        return self.resolved


class _DeferredLocalFailureRecorder(HandlerFailureRecorder):
    def __init__(self) -> None:
        self._delegate: HandlerFailureRecorder | None = None
        self._lock = Lock()

    def bind(self, delegate: HandlerFailureRecorder) -> None:
        with self._lock:
            if self._delegate is not None:
                raise ValueError("LOCAL_FAILURE_RECORDER_ALREADY_BOUND")
            self._delegate = delegate

    def record_handler_failure(self, context: Any, reason_code: str) -> Any:
        with self._lock:
            delegate = self._delegate
        if delegate is None:
            raise ValueError("LOCAL_FAILURE_RECORDER_NOT_BOUND")
        return delegate.record_handler_failure(context, reason_code)


def _require_install_scope(
    *,
    context: LocalEvaluationInstallationContext,
    data_dir: Path,
    request: AnalysisStartRequest,
    profile: LocalEvaluationProfile,
    scope: PlannedRunScope,
) -> None:
    if (
        context.data_dir.resolve() != data_dir.resolve()
        or context.request != request
        or context.profile != profile
        or context.scope != scope
    ):
        raise LocalEvaluationCompositionUnavailable(
            "LOCAL_EVALUATION_INSTALL_SCOPE_MISMATCH"
        )


def _install_local_features(
    *,
    context: LocalEvaluationInstallationContext,
    approved: LocalEvaluationApprovedCapabilities,
    prompt_plan: Any,
    run_configuration: Any,
    validation: Any,
    deferred_adapter: Any,
    deferred_calls: DeferredLocalEvaluationCalls,
    deferred_failures: _DeferredLocalFailureRecorder,
    repository_root: Path,
    docker_executable: Path,
) -> InstalledLocalEvaluationServices:
    from sastsimi.composition.local_dynamic_composition import (
        build_local_shared_dynamic_feature,
    )
    from sastsimi.composition.local_evaluation_policy import (
        build_local_evaluation_policy_feature,
    )
    from sastsimi.composition.local_prompt_configuration import (
        publish_local_prompt_configuration,
    )
    from sastsimi.composition.local_t08_factory import (
        LocalEvaluationT08Capabilities,
        build_local_evaluation_t08,
    )
    from sastsimi.composition.production_cancellation import (
        build_production_cancellation_router,
    )
    from sastsimi.composition.production_feature_installer import (
        ProductionFeatureInputs,
        ProductionFeatureInstaller,
    )
    from sastsimi.contracts.actions import RequesterRole
    from sastsimi.contracts.ids import AttemptId, LogicalRecordId, RecordId
    from sastsimi.contracts.records import RecordMeta
    from sastsimi.contracts.refs import RunStoredDataRef
    from sastsimi.contracts.static import CodeWorkspace
    from sastsimi.contracts.work import WorkExecutionState
    from sastsimi.orchestration.production_call_authority import (
        ProductionPreparedCallAuthorizer,
    )
    from sastsimi.orchestration.production_capabilities import (
        DurableHandlerFailureRecorder,
    )
    from sastsimi.orchestration.production_context import (
        ProductionInstallationContext,
    )
    from sastsimi.prompts.local_calls import (
        ConfiguredLocalEvaluationCallResolver,
        ExactAnalysisLocalEvaluationRouteLookup,
    )
    from sastsimi.prompts.local_evaluation import (
        LocalEvaluationLLMConfigurationService,
    )
    from sastsimi.prompts.validation import validate_output
    from sastsimi.providers.local_evaluation_codex import (
        build_local_evaluation_codex_call_service,
    )
    from sastsimi.providers.openai_composition import StoredProviderSessionStore
    from sastsimi.providers.storage_io import (
        StoredInvocationResultBuilder,
        StoredOutputValidator,
        StoredPromptInputResolver,
    )
    from sastsimi.reporting.content_validation import (
        ReporterOutputSemanticValidator,
    )
    from sastsimi.runtime.prompt_registry import PromptRegistry
    from sastsimi.sandbox.cleanup import OwnedResourceRegistry

    configuration = context.runtime.configuration
    if configuration.register_playbook(run_configuration.playbook) != (
        run_configuration.playbook_ref
    ):
        raise ValueError("LOCAL_PLAYBOOK_PUBLICATION_MISMATCH")
    if configuration.register_playbook_policy(run_configuration.playbook_policy) != (
        run_configuration.playbook_policy_ref
    ):
        raise ValueError("LOCAL_PLAYBOOK_PUBLICATION_MISMATCH")
    if configuration.register_sandbox_profile(run_configuration.sandbox_profile) != (
        run_configuration.sandbox_profile_ref
    ):
        raise ValueError("LOCAL_SANDBOX_PUBLICATION_MISMATCH")

    published = publish_local_prompt_configuration(
        plan=prompt_plan,
        configuration=configuration,
    )
    records = context.runtime.unit_of_work.records
    artifacts = context.runtime.unit_of_work.artifacts
    prompt_service = LocalEvaluationLLMConfigurationService(
        repository_root=repository_root,
        records=records,
        configuration=configuration,
        prompt_registry=PromptRegistry(configuration, records, context.runtime.queries),
        artifacts=artifacts,
        ids=context.ids,
        clock=context.clock,
    )
    lookup = ExactAnalysisLocalEvaluationRouteLookup(
        records=records,
        queries=context.runtime.queries,
        bindings=published.bindings,
    )
    requester_identities = {
        (str(context.scope.analysis_id), role.value): identity
        for role, identity in context.role_identity_refs.items()
    }
    authorizer = ProductionPreparedCallAuthorizer(
        runner=context.runner,
        records=records,
        requester_identities=requester_identities,
        reserved_cost_minor_units=max(
            1,
            context.profile.budget.max_total_cost_minor_units
            // context.profile.budget.max_total_llm_calls,
        ),
    )
    calls = ConfiguredLocalEvaluationCallResolver(
        configuration=prompt_service,
        records=records,
        route_lookup=lookup,
        authorizer=cast(Any, authorizer),
    )
    deferred_calls.bind(cast(ProductionCallPort, calls))

    def metadata(
        source: RecordMeta,
        record_type: str,
        attempt_id: AttemptId | None,
    ) -> RecordMeta:
        record_id = context.ids.new(RecordId)
        return RecordMeta(
            record_id=record_id,
            logical_record_id=LogicalRecordId(str(record_id)),
            record_type=record_type,
            schema_version="1.0.0",
            revision_number=1,
            previous_record_id=None,
            created_at=context.clock.now(),
            analysis_id=source.analysis_id,
            workspace_id=source.workspace_id,
            commit_id=source.commit_id,
            hypothesis_id=source.hypothesis_id,
            attempt_id=attempt_id,
        )

    codex = build_local_evaluation_codex_call_service(
        binding=validation.binding,
        prompt_resolver=StoredPromptInputResolver(records, artifacts),
        session_store=StoredProviderSessionStore(artifacts),
        output_schema_validator=StoredOutputValidator(
            records,
            published.semantic_validators,
            validate_output,
            request_semantic_validators={
                ("REPORTER", "CREATE_DRAFT"): ReporterOutputSemanticValidator(
                    records
                )
            },
        ),
        result_builder=StoredInvocationResultBuilder(records, artifacts, metadata),
        clock=context.clock,
    )
    deferred_adapter.bind(codex)
    recovery_identity = context.role_identity_refs[RequesterRole.RECOVERY]
    if not isinstance(recovery_identity, StoredDataRef):
        raise ValueError("LOCAL_RECOVERY_IDENTITY_REQUIRED")
    deferred_failures.bind(
        DurableHandlerFailureRecorder(context.runner, recovery_identity)
    )

    t08 = build_local_evaluation_t08(
        context,
        LocalEvaluationT08Capabilities(
            git_profile_ref=approved.git_profile_ref,
            python_ast_profile_ref=approved.static_profile_refs["AST"],
            opengrep_profile_ref=approved.static_profile_refs["OPENGREP"],
            codeql_profile_ref=approved.static_profile_refs["CODEQL"],
            git_executable=approved.executables["GIT"],
            python_ast_executable=approved.executables["PYTHON_RUNTIME"],
            opengrep_executable=approved.executables["OPENGREP"],
            codeql_executable=approved.executables["CODEQL"],
            python_ast_worker=repository_root
            / "static_analysis"
            / "python_ast_worker.py",
            candidate_material_root=repository_root.parent.parent
            / "config"
            / "static-analysis"
            / "candidate-v1",
        ),
    )
    policy = build_local_evaluation_policy_feature(
        context=cast(Any, context),
        calls=cast(ProductionCallPort, calls),
    )

    def workspace_root_for(work: WorkExecutionState) -> Path:
        meta = work.meta
        if (
            not isinstance(meta, RecordMeta)
            or meta.analysis_id != context.scope.analysis_id
            or meta.workspace_id != context.scope.workspace_id
            or meta.commit_id != context.scope.commit_id
        ):
            raise ValueError("CURRENT_WORKSPACE_REQUIRED")
        state = context.runtime.budget_registry.current_state(str(meta.analysis_id))
        workspace_ref = state.workspace_ref
        if not isinstance(workspace_ref, RunStoredDataRef):
            raise ValueError("CURRENT_WORKSPACE_REQUIRED")
        workspace = records.get_exact(workspace_ref)
        if (
            not isinstance(workspace, CodeWorkspace)
            or reference(workspace) != workspace_ref
            or workspace.status != "READY"
            or workspace.workspace_id != meta.workspace_id
            or workspace.commit_id != meta.commit_id
        ):
            raise ValueError("CURRENT_WORKSPACE_REQUIRED")
        return t08.workspace_locator.root_for(workspace)

    dynamic = build_local_shared_dynamic_feature(
        context=context,
        sandbox_profile=run_configuration.sandbox_profile,
        docker_executable=docker_executable,
        workspace_root_for=workspace_root_for,
    )
    cancellation = build_production_cancellation_router(
        records=records,
        static=t08.static_cancellation,
        provider_calls=context.runtime.llm_calls,
        docker=dynamic.docker,
        resources=OwnedResourceRegistry(journal_path=dynamic.resource_journal_path),
    )
    installed = ProductionFeatureInstaller(
        ProductionFeatureInputs(
            t08=t08,
            policy=policy,
            dynamic=dynamic,
            calls=cast(ProductionCallPort, calls),
            verification_policy_ref=run_configuration.playbook_policy_ref,
            verification_playbook_ref=run_configuration.playbook_ref,
            taxonomy_version=context.profile.taxonomy_version,
            external_cancellation=cancellation,
        )
    )(cast(ProductionInstallationContext, context))
    return InstalledLocalEvaluationServices(
        handlers=installed.handlers,
        seeder=installed.seeder,
        readiness=installed.readiness,
        external_cancellation=installed.external_cancellation,
    )


class DeferredLocalEvaluationCalls:
    """Break the runtime/call-authority cycle without permitting early calls."""

    def __init__(self) -> None:
        self._delegate: ProductionCallPort | None = None
        self._lock = Lock()

    def bind(self, delegate: ProductionCallPort) -> None:
        if not callable(getattr(delegate, "resolve", None)) or not callable(
            getattr(delegate, "settle", None)
        ):
            raise ValueError("LOCAL_EVALUATION_CALLS_INVALID")
        with self._lock:
            if self._delegate is not None:
                raise ValueError("LOCAL_EVALUATION_CALLS_ALREADY_BOUND")
            self._delegate = delegate

    def _bound(self) -> ProductionCallPort:
        with self._lock:
            value = self._delegate
        if value is None:
            raise ValueError("LOCAL_EVALUATION_CALLS_NOT_BOUND")
        return value

    def resolve(self, **kwargs: Any) -> Any:
        return self._bound().resolve(**kwargs)

    def settle(self, call: object, invocation: object) -> None:
        self._bound().settle(
            cast(Any, call),
            cast(Any, invocation),
        )


class _CancellationTargetLike(Protocol):
    target_kind: str


class LocalUnavailableSandboxCancellation:
    """Report absence when the local run has no approved Docker capability."""

    async def prepare(self, target: CancellationTarget) -> CancellationTarget:
        if cast(_CancellationTargetLike, target).target_kind != "SANDBOX":
            raise ValueError("CANCELLATION_TARGET_KIND_MISMATCH")
        return target

    def validate_inventory(
        self, analysis_id: str, targets: tuple[CancellationTarget, ...]
    ) -> None:
        if not analysis_id.strip() or any(
            cast(_CancellationTargetLike, target).target_kind != "SANDBOX"
            for target in targets
        ):
            raise ValueError("LOCAL_SANDBOX_CANCELLATION_SCOPE_MISMATCH")

    async def cancel(self, target: CancellationTarget) -> CancellationObservation:
        if cast(_CancellationTargetLike, target).target_kind != "SANDBOX":
            raise ValueError("CANCELLATION_TARGET_KIND_MISMATCH")
        return CancellationObservation(
            target=target,
            status="ABSENT",
            reason_code="LOCAL_SANDBOX_NOT_STARTED",
        )


__all__ = [
    "ConcreteLocalEvaluationPreflight",
    "DeferredLocalEvaluationCalls",
    "LocalUnavailableSandboxCancellation",
]
