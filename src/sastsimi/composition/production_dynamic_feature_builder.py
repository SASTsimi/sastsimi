"""Fail-closed production assembly for the R7 dynamic-reproduction feature."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Literal

from sastsimi.composition.production_feature_installer import (
    CurrentRepositoryProfileT11Resolver,
    DynamicProductionFeature,
    ReadinessCheck,
)
from sastsimi.composition.runtime import T11Services, build_t11_services
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
    DynamicReproductionLifecycleProfile,
)
from sastsimi.contracts.capabilities import RuntimeCapabilityProfile
from sastsimi.contracts.dynamic import (
    DependencyBundle,
    DynamicReproductionRequest,
    EnvironmentRequirements,
    ReproductionPlan,
    SandboxProfile,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    HostConfigurationRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.static import CodeWorkspace, RepositoryProfile
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.orchestration.production_context import ProductionInstallationContext
from sastsimi.orchestration.production_provisioning import (
    MaterializedProvisioningArtifacts,
    ResolvedProductionProvisioning,
    SandboxProfileProvisioning,
)
from sastsimi.ports.dto import Record
from sastsimi.ports.dynamic_sandbox import (
    SandboxRunSpec,
    TrustedDockerTargetResolverPort,
)
from sastsimi.ports.record_store import RecordStore
from sastsimi.ports.runtime_query import RuntimeQueryPort
from sastsimi.ports.runtime_store import ActionAuthorizationPort
from sastsimi.ports.workspace import WorkspaceLocatorPort
from sastsimi.reproduction.production import DynamicSandboxAuthorization
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.sandbox.docker_adapter import DockerAdapter
from sastsimi.verification.production_llm_work_handlers import ProductionCallPort
from sastsimi.verification.service import VerificationService

_DOCKER_OPERATIONS = frozenset(
    {"IMAGE_BUILD", "CONTAINER_RUN", "HEALTH_CHECK", "CLEANUP"}
)
_NUMERIC_USER = re.compile(r"^[1-9][0-9]*(?::[1-9][0-9]*)?$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class DockerCapabilityReadiness:
    """Recheck the exact approved Docker target before each run."""

    profile_ref: HostConfigurationRef
    resolver: TrustedDockerTargetResolverPort

    def __call__(self) -> None:
        target = self.resolver.resolve_current(self.profile_ref)
        self.resolver.require_current(target)


@dataclass(frozen=True, slots=True)
class ProductionDynamicAuthorizationResolver:
    """Create one runtime-authorized, exact BUILD or RUN Sandbox binding."""

    runner: WorkflowRunner
    records: RecordStore
    queries: RuntimeQueryPort
    current_run: Callable[[str], object]
    setup_identity: BudgetScopeRef
    sandbox_profile: SandboxProfile
    container_user: str
    workspace_root_for: Callable[[WorkExecutionState], Path]
    docker_readiness: ReadinessCheck
    authorization: ActionAuthorizationPort

    def __call__(
        self,
        work: WorkExecutionState,
        request: DynamicReproductionRequest,
        requirements: EnvironmentRequirements,
        plan: ReproductionPlan,
        phase: Literal["BUILD", "RUN"],
        phase_ref: StoredDataRef,
        image_digest: str | None,
        context_refs: tuple[StoredDataRef, ...],
    ) -> DynamicSandboxAuthorization:
        self.docker_readiness()
        if phase not in {"BUILD", "RUN"}:
            raise ValueError("PRODUCTION_SANDBOX_PHASE_INVALID")
        if not isinstance(work.meta, RecordMeta):
            raise ValueError("PRODUCTION_SANDBOX_WORK_SCOPE_REQUIRED")
        sandbox_ref = _stored_ref(self.sandbox_profile)
        _require_current_sandbox(
            records=self.records,
            queries=self.queries,
            profile=self.sandbox_profile,
            expected_ref=sandbox_ref,
            analysis_id=str(work.meta.analysis_id),
        )
        request_ref = _stored_ref(request)
        requirements_ref = _stored_ref(requirements)
        plan_ref = _stored_ref(plan)
        if (
            work.active_attempt_id is None
            or work.meta.hypothesis_id is None
            or request.meta.analysis_id != work.meta.analysis_id
            or request.meta.workspace_id != work.meta.workspace_id
            or request.meta.commit_id != work.meta.commit_id
            or request.meta.hypothesis_id != work.meta.hypothesis_id
            or requirements.meta.attempt_id != work.active_attempt_id
            or plan.meta.attempt_id != work.active_attempt_id
            or requirements.request_ref != request_ref
            or plan.request_ref != request_ref
            or plan.environment_requirements_ref != requirements_ref
            or request.sandbox_profile_ref != sandbox_ref
            or plan.sandbox_profile_ref != sandbox_ref
        ):
            raise ValueError("PRODUCTION_SANDBOX_ATTEMPT_SCOPE_MISMATCH")
        if any(item.secret_ref is not None for item in requirements.items):
            raise ValueError("PRODUCTION_SANDBOX_SECRET_DENIED")

        run = self.current_run(str(work.meta.analysis_id))
        binding_ref = getattr(run, "budget_binding_ref", None)
        run_policy_ref = getattr(run, "run_policy_state_ref", None)
        if not isinstance(binding_ref, StoredDataRef) or not isinstance(
            run_policy_ref, StoredDataRef
        ):
            raise ValueError("PRODUCTION_SANDBOX_RUN_SCOPE_REQUIRED")
        binding = self.records.get_exact(binding_ref)
        if not isinstance(binding, BudgetProfileBinding):
            raise ValueError("PRODUCTION_SANDBOX_BUDGET_BINDING_REQUIRED")
        lifecycle_ref = binding.dynamic_lifecycle_profile_ref
        if not isinstance(lifecycle_ref, StoredDataRef):
            raise ValueError("PRODUCTION_SANDBOX_LIFECYCLE_REQUIRED")
        lifecycle = self.records.get_exact(lifecycle_ref)
        if (
            not isinstance(lifecycle, DynamicReproductionLifecycleProfile)
            or lifecycle.status != "ACTIVE"
            or _stored_ref(lifecycle) != lifecycle_ref
        ):
            raise ValueError("PRODUCTION_SANDBOX_LIFECYCLE_REQUIRED")

        if phase == "BUILD" and (
            image_digest is not None or phase_ref.data_kind != "recipe_source"
        ):
            raise ValueError("PRODUCTION_SANDBOX_BUILD_IMAGE_FORBIDDEN")
        if phase == "RUN" and (
            image_digest is None
            or _IMAGE_DIGEST.fullmatch(image_digest) is None
            or phase_ref.data_kind != "environment_recipe"
        ):
            raise ValueError("PRODUCTION_SANDBOX_RUN_IMAGE_REQUIRED")
        fixed_inputs = (
            request_ref,
            requirements_ref,
            plan_ref,
            sandbox_ref,
            lifecycle_ref,
            phase_ref,
            *context_refs,
        )
        if len(fixed_inputs) != len(set(fixed_inputs)):
            raise ValueError("PRODUCTION_SANDBOX_INPUT_DUPLICATED")

        profile = self.sandbox_profile
        workspace_root = self.workspace_root_for(work).resolve(strict=True)
        if not workspace_root.is_dir():
            raise ValueError("PRODUCTION_SANDBOX_WORKSPACE_REQUIRED")
        spec = SandboxRunSpec(
            workspace_root=workspace_root,
            image_digest=image_digest,
            user=self.container_user,
            mounts=(),
            network_mode="DEFAULT_DENY",
            network_targets=(),
            secret_refs=(),
            privileged=False,
            pid_mode=None,
            ipc_mode=None,
            capabilities=(),
            cpu_limit_millicores=profile.cpu_limit_millicores,
            memory_limit_bytes=profile.memory_limit_bytes,
            disk_limit_bytes=profile.disk_limit_bytes,
            pid_limit=profile.pid_limit,
            requested_execution_ms=profile.max_requested_execution_ms,
            source_baked=True,
        )
        action = self.runner.action(
            work,
            self.setup_identity,
            RequesterRole.REPRODUCTION_SETUP_AUTOMATION.value,
            "RUN_SANDBOX",
            input_refs=fixed_inputs,
            dynamic_request_ref=request_ref,
            reproduction_plan_ref=plan_ref,
            sandbox_profile_ref=sandbox_ref,
            resource_profile_ref=lifecycle_ref,
            run_policy_state_ref=run_policy_ref,
            image_digest=image_digest,
            network_targets=(),
            resource_limits={
                "cpu_limit_millicores": profile.cpu_limit_millicores,
                "memory_limit_bytes": profile.memory_limit_bytes,
                "disk_limit_bytes": profile.disk_limit_bytes,
                "pid_limit": profile.pid_limit,
                "requested_execution_ms": profile.max_requested_execution_ms,
            },
            reason=f"Authorize exact dynamic reproduction {phase.lower()} phase",
        )
        # Authorization needs positive estimated time and cost.  The execution
        # path owns observed accounting; this resolver must not invent it.
        units = self.runner.units(elapsed_ms=1, cost_minor_units=1)
        reservation = self.runner.reserve(work, binding_ref, action, units)
        decision_ref = self.runner.authorize(work, action, reservation)
        if not isinstance(decision_ref, StoredDataRef):
            raise ValueError("PRODUCTION_SANDBOX_DECISION_NOT_STORED")
        reservation_ref = reference(reservation)
        if not isinstance(reservation_ref, StoredDataRef):
            raise ValueError("PRODUCTION_SANDBOX_RESERVATION_NOT_STORED")
        claimed_ref = self.authorization.claim_external(
            str(work.work_id), decision_ref, reservation_ref
        )
        if not isinstance(claimed_ref, StoredDataRef):
            raise ValueError("PRODUCTION_SANDBOX_DECISION_NOT_STORED")
        return DynamicSandboxAuthorization(
            action=action,
            action_decision_ref=claimed_ref,
            sandbox_profile=profile,
            lifecycle_profile=lifecycle,
            run_policy_state_ref=run_policy_ref,
            run_spec=spec,
        )


@dataclass(frozen=True, slots=True)
class BuiltDynamicProductionFeature:
    """R7 feature plus the mandatory live-Docker readiness check."""

    feature: DynamicProductionFeature
    docker_readiness: DockerCapabilityReadiness

    @property
    def readiness_checks(self) -> tuple[ReadinessCheck, ...]:
        return (self.docker_readiness,)


def build_production_dynamic_feature(
    *,
    context: ProductionInstallationContext,
    resolved: ResolvedProductionProvisioning,
    materialized: MaterializedProvisioningArtifacts,
    workspace_root_for: Callable[[WorkExecutionState], Path],
    docker_target_resolver: TrustedDockerTargetResolverPort,
    dependency_bundle: DependencyBundle | None = None,
) -> BuiltDynamicProductionFeature:
    """Build R7 only from one exact run's materialized approved inputs."""

    document = materialized.documents.get("SANDBOX_PROFILE")
    if not isinstance(document, SandboxProfileProvisioning):
        raise ValueError("PRODUCTION_SANDBOX_PROVISIONING_REQUIRED")
    if (
        document.analysis_id,
        document.workspace_id,
        document.commit_id,
    ) != (
        str(context.scope.analysis_id),
        str(context.scope.workspace_id),
        str(context.scope.commit_id),
    ):
        raise ValueError("PRODUCTION_SANDBOX_PROVISIONING_SCOPE_MISMATCH")
    profile_ref = document.record_refs[0] if len(document.record_refs) == 1 else None
    profile = materialized.records.get(profile_ref) if profile_ref is not None else None
    if not isinstance(profile, SandboxProfile) or reference(profile) != profile_ref:
        raise ValueError("PRODUCTION_SANDBOX_PROFILE_REQUIRED")
    policy = materialized.evidence.get(document.authorization_policy_sha256)
    if (
        policy is None
        or not policy
        or hashlib.sha256(policy).hexdigest() != document.authorization_policy_sha256
    ):
        raise ValueError("PRODUCTION_SANDBOX_POLICY_STALE")
    if profile.allowed_egress_refs:
        raise ValueError("PRODUCTION_SANDBOX_EGRESS_UNRESOLVED")
    if profile.network_mode != "DEFAULT_DENY" or not _NUMERIC_USER.fullmatch(
        document.container_user
    ):
        raise ValueError("PRODUCTION_SANDBOX_PROFILE_UNSAFE")

    docker = resolved.capabilities.get("DOCKER")
    if not isinstance(docker, RuntimeCapabilityProfile):
        raise ValueError("PRODUCTION_DOCKER_CAPABILITY_REQUIRED")
    docker_profile_ref = reference(docker)
    if not isinstance(docker_profile_ref, HostConfigurationRef):
        raise ValueError("PRODUCTION_DOCKER_CAPABILITY_REQUIRED")
    readiness = DockerCapabilityReadiness(docker_profile_ref, docker_target_resolver)
    readiness()
    journal_relative = PurePath(document.resource_journal_relative)
    journal = _inside(
        context.data_dir,
        str(
            journal_relative.parent
            / str(context.scope.analysis_id)
            / journal_relative.name
        ),
    )
    resolver = ProductionDynamicAuthorizationResolver(
        runner=context.runner,
        records=context.runtime.unit_of_work.records,
        queries=context.runtime.queries,
        current_run=context.runtime.budget_registry.current_state,
        setup_identity=context.role_identity_refs[
            RequesterRole.REPRODUCTION_SETUP_AUTOMATION
        ],
        sandbox_profile=profile,
        container_user=document.container_user,
        workspace_root_for=workspace_root_for,
        docker_readiness=readiness,
        authorization=context.runtime.validator,
    )
    docker_adapter = DockerAdapter.from_profile(
        docker_profile_ref, docker_target_resolver
    )
    feature = DynamicProductionFeature(
        sandbox_authorization=resolver,
        sandbox_profile=lambda work: _profile_ref_for_work(
            work,
            profile=profile,
            records=context.runtime.unit_of_work.records,
            queries=context.runtime.queries,
        ),
        max_execute_turns=document.max_execute_turns,
        resource_journal_path=journal,
        docker_profile_ref=docker_profile_ref,
        docker_target_resolver=docker_target_resolver,
        docker=docker_adapter,
        dependency_bundle=dependency_bundle,
    )
    return BuiltDynamicProductionFeature(feature, readiness)


def build_current_repository_t11_resolver(
    *,
    context: ProductionInstallationContext,
    feature: DynamicProductionFeature,
    workspace_for: Callable[[WorkExecutionState], CodeWorkspace],
    workspace_locator: WorkspaceLocatorPort,
    verification: VerificationService,
    calls: ProductionCallPort,
) -> CurrentRepositoryProfileT11Resolver:
    """Join the exact current RepositoryProfile to the real T11 service builder."""

    def build(profile: RepositoryProfile, root: Path) -> T11Services:
        return build_t11_services(
            runtime=context.runtime,
            runner=context.runner,
            clock=context.clock,
            ids=context.ids,
            workspace_root=root,
            workspace_id=context.scope.workspace_id,
            commit_id=context.scope.commit_id,
            role_identity_refs=context.role_identity_refs,
            sandbox_authorization=feature.sandbox_authorization,
            dynamic_calls=calls,
            max_execute_turns=feature.max_execute_turns,
            verification=verification,
            repository_profile=profile,
            resource_journal_path=feature.resource_journal_path,
            docker_profile_ref=feature.docker_profile_ref,
            docker_target_resolver=feature.docker_target_resolver,
            dependency_bundle=feature.dependency_bundle,
        )

    return CurrentRepositoryProfileT11Resolver(
        records=context.runtime.unit_of_work.records,
        queries=context.runtime.queries,
        workspace_for=workspace_for,
        workspace_locator=workspace_locator,
        build=build,
    )


def _profile_ref_for_work(
    work: WorkExecutionState,
    *,
    profile: SandboxProfile,
    records: RecordStore,
    queries: RuntimeQueryPort,
) -> StoredDataRef:
    profile_ref = _stored_ref(profile)
    _require_current_sandbox(
        records=records,
        queries=queries,
        profile=profile,
        expected_ref=profile_ref,
        analysis_id=str(work.meta.analysis_id),
    )
    return profile_ref


def _require_current_sandbox(
    *,
    records: RecordStore,
    queries: RuntimeQueryPort,
    profile: SandboxProfile,
    expected_ref: StoredDataRef,
    analysis_id: str,
) -> None:
    if records.get_exact(expected_ref) != profile:
        raise ValueError("PRODUCTION_SANDBOX_PROFILE_STALE")
    current = tuple(
        item
        for item in queries.current_records(analysis_id, SandboxProfile.KIND)
        if isinstance(item, SandboxProfile)
        and item.meta.logical_record_id == profile.meta.logical_record_id
    )
    if len(current) != 1 or reference(current[0]) != expected_ref:
        raise ValueError("PRODUCTION_SANDBOX_PROFILE_STALE")


def _inside(root: Path, relative: str) -> Path:
    if PurePath(relative).is_absolute():
        raise ValueError("PRODUCTION_SANDBOX_JOURNAL_INVALID")
    base = root.resolve()
    target = (base / Path(relative)).resolve(strict=False)
    try:
        target.relative_to(base)
    except ValueError:
        raise ValueError("PRODUCTION_SANDBOX_JOURNAL_INVALID") from None
    return target


def _stored_ref(record: Record) -> StoredDataRef:
    value = reference(record)
    if not isinstance(value, StoredDataRef):
        raise ValueError("PRODUCTION_SANDBOX_RECORD_NOT_STORED")
    return value


__all__ = [
    "BuiltDynamicProductionFeature",
    "DockerCapabilityReadiness",
    "ProductionDynamicAuthorizationResolver",
    "build_current_repository_t11_resolver",
    "build_production_dynamic_feature",
]
