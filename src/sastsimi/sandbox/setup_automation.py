"""Prepare, conditionally reuse, recreate, and clean local Docker Sandboxes."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol
from uuid import uuid4

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.dynamic import (
    CleanupResult,
    DynamicReproductionRequest,
    EnvironmentCheck,
    EnvironmentRecipe,
    EnvironmentRequirements,
    ReproductionPlan,
    SandboxEnvironment,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import RepositoryProfile
from sastsimi.ports.dynamic_sandbox import (
    PreparedRecipeSourceView,
    RecreateReason,
    SandboxBoundaryOutcome,
    SandboxBuildBoundaryOutcome,
    SandboxRunSpec,
)
from sastsimi.ports.dynamic_sandbox import (
    PreparedSandbox as PreparedSandbox,
)
from sastsimi.ports.dynamic_sandbox import (
    SandboxSetupCleanupError as SandboxSetupCleanupError,
)

from .cleanup import OwnedResourceRegistry
from .docker_adapter import DockerAdapter, DockerCommandOutcome, DockerContainerState
from .health_check import SandboxHealthChecker
from .recipe_store import (
    EnvironmentRecipeStore,
    PreparedRecipeSource,
    fresh_record_meta,
)


class DockerLifecyclePort(Protocol):
    async def build(
        self,
        dockerfile: bytes,
        labels: Mapping[str, str],
        *,
        timeout_ms: int,
    ) -> str: ...
    async def inspect_image(self, image: str, *, timeout_ms: int) -> str: ...
    async def build_context(
        self,
        context_archive: bytes,
        dockerfile_path: str,
        labels: Mapping[str, str],
        *,
        timeout_ms: int,
    ) -> str: ...
    async def create(self, spec: SandboxRunSpec, labels: Mapping[str, str]) -> str: ...
    async def verify_created_mounts(
        self, container_id: str, spec: SandboxRunSpec
    ) -> None: ...
    async def start(self, container_id: str) -> None: ...
    async def materialize_poc(
        self, container_id: str, content: bytes, content_digest: str
    ) -> str: ...
    async def execute(
        self,
        container_id: str,
        argv: tuple[str, ...],
        timeout_ms: int,
        *,
        working_directory: str,
    ) -> DockerCommandOutcome: ...
    async def inspect(self, container_id: str) -> DockerContainerState: ...
    async def remove(self, resource_ids: tuple[str, ...]) -> None: ...


@dataclass(frozen=True, slots=True)
class _PreparationContext:
    approval: SandboxBoundaryOutcome
    request: DynamicReproductionRequest
    requirements: EnvironmentRequirements
    plan: ReproductionPlan
    labels: Mapping[str, str]


class ReproductionSetupAutomation:
    """Own Docker setup actions, not vulnerability decisions or Docker policy."""

    def __init__(
        self,
        *,
        docker: DockerLifecyclePort,
        recipes: EnvironmentRecipeStore,
        health: SandboxHealthChecker,
        resources: OwnedResourceRegistry,
    ) -> None:
        self._docker = docker
        self._recipes = recipes
        self._health = health
        self._resources = resources
        self._contexts: dict[bytes, _PreparationContext] = {}

    async def preflight(
        self,
        *,
        workspace_root: Path,
        request: DynamicReproductionRequest,
        requirements: EnvironmentRequirements,
        meta: RecordMeta,
        repository_profile: RepositoryProfile | None = None,
    ) -> PreparedRecipeSource:
        """Read and validate recipe files without touching Docker."""

        return self._recipes.preflight(
            context=workspace_root,
            request_ref=self._exact_ref(request),
            requirements=requirements,
            meta=meta,
            repository_profile=repository_profile,
        )

    async def build(
        self,
        *,
        approval: SandboxBuildBoundaryOutcome,
        source: PreparedRecipeSourceView,
        request: DynamicReproductionRequest,
        requirements: EnvironmentRequirements,
        meta: RecordMeta,
    ) -> EnvironmentRecipe:
        """Inspect and build only after the exact source boundary is approved."""

        spec = self._validate_build(approval, source, request, requirements, meta)
        labels = self._labels(meta)
        return await self._recipes.build(
            docker=self._docker,
            source=source,
            labels=labels,
            build_timeout_ms=spec.requested_execution_ms,
        )

    async def create(
        self,
        *,
        approval: SandboxBoundaryOutcome,
        recipe: EnvironmentRecipe,
        request: DynamicReproductionRequest,
        requirements: EnvironmentRequirements,
        plan: ReproductionPlan,
        meta: RecordMeta,
    ) -> PreparedSandbox:
        """Create only with a second approval bound to the built image digest."""

        spec = self._validate_create(
            approval, recipe, request, requirements, plan, meta
        )
        labels = self._labels(meta)
        prepared = await self._create_environment(
            spec=spec,
            recipe=recipe,
            request=request,
            requirements=requirements,
            plan=plan,
            labels=self._container_labels(meta),
            reason="INITIAL_CLEAN",
            previous_environment_ref=None,
            meta=meta,
        )
        self._remember(
            prepared,
            _PreparationContext(approval, request, requirements, plan, labels),
        )
        return prepared

    async def reuse(
        self,
        *,
        previous: PreparedSandbox,
        meta: RecordMeta,
    ) -> PreparedSandbox:
        context = self._context(previous)
        self._validate_reuse_scope(previous, context, meta)
        state = await self._health.inspect_ready(
            self._docker.inspect,
            previous.environment.container_instance_id,
        )
        recipe = previous.recipe
        evidence_ref = previous.resource_refs[0]
        checks = self._health.requirement_checks(
            requirements=context.requirements,
            state=state,
            evidence_ref=evidence_ref,
        )
        environment = self._environment(
            request=context.request,
            requirements=context.requirements,
            plan=context.plan,
            recipe=recipe,
            container_id=previous.environment.container_instance_id,
            action="REUSED",
            reason="NO_RELEVANT_CHANGE",
            previous_environment_ref=self._exact_ref(previous.environment),
            checks=checks,
            meta=meta,
        )
        prepared = PreparedSandbox(recipe, environment, previous.resource_refs)
        self._remember(prepared, context)
        return prepared

    async def recreate(
        self,
        *,
        approval: SandboxBoundaryOutcome,
        previous: PreparedSandbox,
        reason: RecreateReason,
        meta: RecordMeta,
    ) -> PreparedSandbox:
        context = self._context(previous)
        self._validate_reuse_scope(previous, context, meta)
        if reason not in {"STATE_CHANGED", "CONFIG_CHANGED", "STATE_UNCERTAIN"}:
            raise ValueError("SANDBOX_RECREATE_REASON_INVALID")
        recipe = previous.recipe
        spec = self._validate_create(
            approval,
            recipe,
            context.request,
            context.requirements,
            context.plan,
            meta,
        )
        labels = self._container_labels(meta)
        prepared = await self._create_environment(
            spec=spec,
            recipe=recipe,
            request=context.request,
            requirements=context.requirements,
            plan=context.plan,
            labels=labels,
            reason=reason,
            previous_environment_ref=self._exact_ref(previous.environment),
            meta=meta,
        )
        self._remember(
            prepared,
            _PreparationContext(
                approval,
                context.request,
                context.requirements,
                context.plan,
                labels,
            ),
        )
        return prepared

    async def cleanup(
        self,
        *,
        request: DynamicReproductionRequest,
        environments: tuple[SandboxEnvironment, ...],
        resource_refs: tuple[StoredDataRef, ...],
        meta: RecordMeta,
    ) -> CleanupResult:
        return await self._resources.cleanup(
            docker=self._docker,
            request=request,
            environments=environments,
            resource_refs=resource_refs,
            meta=meta,
        )

    async def _create_environment(
        self,
        *,
        spec: SandboxRunSpec | None,
        recipe: EnvironmentRecipe,
        request: DynamicReproductionRequest,
        requirements: EnvironmentRequirements,
        plan: ReproductionPlan,
        labels: Mapping[str, str],
        reason: Literal[
            "INITIAL_CLEAN", "STATE_CHANGED", "CONFIG_CHANGED", "STATE_UNCERTAIN"
        ],
        previous_environment_ref: StoredDataRef | None,
        meta: RecordMeta,
    ) -> PreparedSandbox:
        if spec is None:
            raise ValueError("SANDBOX_APPROVAL_REQUIRED")
        container_name = DockerAdapter.runtime_container_name(labels)
        self._resources.reserve_container(
            container_name=container_name,
            labels=labels,
        )
        try:
            container_id = await self._docker.create(spec, labels)
        except BaseException:
            try:
                await self._resources.reconcile_intent(
                    docker=self._docker,
                    container_name=container_name,
                )
            except BaseException as cleanup_error:
                resource_ref = self._resources.register_reserved_container(
                    container_name=container_name,
                    container_id=container_name,
                    meta=meta,
                    reconcile_required=True,
                )
                failed = PreparedSandbox(
                    recipe,
                    self._failed_environment(
                        request=request,
                        requirements=requirements,
                        plan=plan,
                        recipe=recipe,
                        container_id=container_name,
                        reason=reason,
                        previous_environment_ref=previous_environment_ref,
                        resource_ref=resource_ref,
                        meta=meta,
                    ),
                    (resource_ref,),
                )
                raise SandboxSetupCleanupError(failed) from cleanup_error
            raise
        resource_ref = self._resources.register_reserved_container(
            container_name=container_name,
            container_id=container_id,
            meta=meta,
        )
        try:
            await self._docker.verify_created_mounts(container_id, spec)
            await self._docker.start(container_id)
            state = await self._health.inspect_ready(self._docker.inspect, container_id)
        except BaseException:
            try:
                await self._docker.remove((container_id,))
            except BaseException as cleanup_error:
                failed = PreparedSandbox(
                    recipe,
                    self._failed_environment(
                        request=request,
                        requirements=requirements,
                        plan=plan,
                        recipe=recipe,
                        container_id=container_id,
                        reason=reason,
                        previous_environment_ref=previous_environment_ref,
                        resource_ref=resource_ref,
                        meta=meta,
                    ),
                    (resource_ref,),
                )
                raise SandboxSetupCleanupError(failed) from cleanup_error
            self._resources.forget(resource_ref)
            raise
        checks = self._health.requirement_checks(
            requirements=requirements,
            state=state,
            evidence_ref=resource_ref,
        )
        environment = self._environment(
            request=request,
            requirements=requirements,
            plan=plan,
            recipe=recipe,
            container_id=container_id,
            action="CREATED",
            reason=reason,
            previous_environment_ref=previous_environment_ref,
            checks=checks,
            meta=meta,
        )
        return PreparedSandbox(recipe, environment, (resource_ref,))

    @staticmethod
    def _failed_environment(
        *,
        request: DynamicReproductionRequest,
        requirements: EnvironmentRequirements,
        plan: ReproductionPlan,
        recipe: EnvironmentRecipe,
        container_id: str,
        reason: Literal[
            "INITIAL_CLEAN", "STATE_CHANGED", "CONFIG_CHANGED", "STATE_UNCERTAIN"
        ],
        previous_environment_ref: StoredDataRef | None,
        resource_ref: StoredDataRef,
        meta: RecordMeta,
    ) -> SandboxEnvironment:
        checks = tuple(
            EnvironmentCheck(
                requirement_id=item.requirement_id,
                status="ERROR",
                actual=None,
                actual_ref=None,
                difference="Sandbox setup failed before environment checks completed",
                evidence_refs=(resource_ref,),
                check_result_ref=None,
            )
            for item in requirements.items
        )
        status: Literal["READY", "ERROR"] = (
            "ERROR" if any(item.required for item in requirements.items) else "READY"
        )
        return SandboxEnvironment(
            meta=fresh_record_meta(meta, "sandbox_environment"),
            request_ref=ReproductionSetupAutomation._exact_ref(request),
            reproduction_plan_ref=ReproductionSetupAutomation._exact_ref(plan),
            environment_recipe_ref=ReproductionSetupAutomation._exact_ref(recipe),
            requirements_ref=ReproductionSetupAutomation._exact_ref(requirements),
            container_instance_id=container_id,
            container_action="CREATED",
            container_reason=reason,
            previous_environment_ref=previous_environment_ref,
            status=status,
            checks=checks,
            limitations=("Sandbox setup did not complete",),
            created_at=meta.created_at,
        )

    @staticmethod
    def _validate_build(
        approval: SandboxBuildBoundaryOutcome,
        source: PreparedRecipeSourceView,
        request: DynamicReproductionRequest,
        requirements: EnvironmentRequirements,
        meta: RecordMeta,
    ) -> SandboxRunSpec:
        if (
            approval.decision.decision != "ALLOW"
            or approval.approved_spec is None
            or approval.approved_source != source
            or approval.approved_spec.image_digest is not None
        ):
            raise ValueError("SANDBOX_BUILD_APPROVAL_REQUIRED")
        request_ref = ReproductionSetupAutomation._exact_ref(request)
        requirements_ref = ReproductionSetupAutomation._exact_ref(requirements)
        if (
            approval.decision.request_ref != request_ref
            or requirements.request_ref != request_ref
            or source.request_ref != request_ref
            or source.requirements_ref != requirements_ref
            or source.workspace_root.resolve(strict=False)
            != approval.approved_spec.workspace_root.resolve(strict=False)
        ):
            raise ValueError("DYNAMIC_SETUP_CLOSURE_MISMATCH")
        ReproductionSetupAutomation._validate_scope(
            (requirements,), meta, request=request, source=source
        )
        if source.repository_profile_ref is not None and (
            not approval.approved_spec.source_baked or approval.approved_spec.mounts
        ):
            raise ValueError("SANDBOX_HOST_MOUNT_DENIED")
        return approval.approved_spec

    @staticmethod
    def _validate_create(
        approval: SandboxBoundaryOutcome,
        recipe: EnvironmentRecipe,
        request: DynamicReproductionRequest,
        requirements: EnvironmentRequirements,
        plan: ReproductionPlan,
        meta: RecordMeta,
    ) -> SandboxRunSpec:
        if approval.decision.decision != "ALLOW" or approval.approved_spec is None:
            raise ValueError("SANDBOX_APPROVAL_REQUIRED")
        request_ref = ReproductionSetupAutomation._exact_ref(request)
        requirements_ref = ReproductionSetupAutomation._exact_ref(requirements)
        recipe_ref = ReproductionSetupAutomation._exact_ref(recipe)
        if (
            approval.decision.request_ref != request_ref
            or approval.approved_recipe_ref != recipe_ref
            or requirements.request_ref != request_ref
            or plan.request_ref != request_ref
            or plan.environment_requirements_ref != requirements_ref
            or plan.purpose != request.purpose
            or plan.hypothesis_ref != request.hypothesis_ref
            or plan.sandbox_profile_ref != request.sandbox_profile_ref
            or recipe.request_ref != request_ref
            or recipe.environment_requirements_ref != requirements_ref
            or recipe.built_image_digest != approval.approved_spec.image_digest
        ):
            raise ValueError("APPROVED_IMAGE_DIGEST_MISMATCH")
        ReproductionSetupAutomation._validate_scope(
            (requirements, plan, recipe), meta, request=request
        )
        has_repository_profile = any(
            ref.data_kind == "repository_profile" for ref in recipe.source_refs
        )
        if has_repository_profile and (
            not approval.approved_spec.source_baked or approval.approved_spec.mounts
        ):
            raise ValueError("SANDBOX_HOST_MOUNT_DENIED")
        return approval.approved_spec

    @staticmethod
    def _validate_scope(
        records: tuple[
            EnvironmentRequirements | ReproductionPlan | EnvironmentRecipe, ...
        ],
        meta: RecordMeta,
        *,
        request: DynamicReproductionRequest,
        source: PreparedRecipeSourceView | None = None,
    ) -> None:
        for record in records:
            record_meta = record.meta
            if (
                record_meta.analysis_id != meta.analysis_id
                or record_meta.workspace_id != meta.workspace_id
                or record_meta.commit_id != meta.commit_id
                or record_meta.hypothesis_id != meta.hypothesis_id
                or record_meta.attempt_id != meta.attempt_id
            ):
                raise ValueError("DYNAMIC_SETUP_SCOPE_MISMATCH")
        if request.meta.hypothesis_id != meta.hypothesis_id or (
            source is not None
            and (
                source.meta.analysis_id != meta.analysis_id
                or source.meta.workspace_id != meta.workspace_id
                or source.meta.commit_id != meta.commit_id
                or source.meta.hypothesis_id != meta.hypothesis_id
                or source.meta.attempt_id != meta.attempt_id
            )
        ):
            raise ValueError("DYNAMIC_SETUP_SCOPE_MISMATCH")

    @staticmethod
    def _validate_reuse_scope(
        previous: PreparedSandbox,
        context: _PreparationContext,
        meta: RecordMeta,
    ) -> None:
        old = previous.environment.meta
        if (
            old.analysis_id != meta.analysis_id
            or old.workspace_id != meta.workspace_id
            or old.commit_id != meta.commit_id
            or old.hypothesis_id != meta.hypothesis_id
            or context.request.meta.hypothesis_id != meta.hypothesis_id
        ):
            raise ValueError("SANDBOX_REUSE_SCOPE_MISMATCH")
        if previous.environment.status != "READY":
            raise ValueError("SANDBOX_REUSE_NOT_READY")

    def _context(self, previous: PreparedSandbox) -> _PreparationContext:
        context = self._contexts.get(
            canonical_bytes(self._exact_ref(previous.environment))
        )
        if context is None:
            raise ValueError("SANDBOX_PREDECESSOR_UNRESOLVED")
        return context

    def _remember(
        self, prepared: PreparedSandbox, context: _PreparationContext
    ) -> None:
        self._contexts[canonical_bytes(self._exact_ref(prepared.environment))] = context

    @staticmethod
    def _environment(
        *,
        request: DynamicReproductionRequest,
        requirements: EnvironmentRequirements,
        plan: ReproductionPlan,
        recipe: EnvironmentRecipe,
        container_id: str,
        action: Literal["CREATED", "REUSED"],
        reason: Literal[
            "INITIAL_CLEAN",
            "NO_RELEVANT_CHANGE",
            "STATE_CHANGED",
            "CONFIG_CHANGED",
            "STATE_UNCERTAIN",
        ],
        previous_environment_ref: StoredDataRef | None,
        checks: tuple[EnvironmentCheck, ...],
        meta: RecordMeta,
    ) -> SandboxEnvironment:
        required = {item.requirement_id for item in requirements.items if item.required}
        status_by_id = {check.requirement_id: check.status for check in checks}
        status: Literal["READY", "MISMATCH", "ERROR"] = (
            "ERROR"
            if any(status_by_id[item] == "ERROR" for item in required)
            else "MISMATCH"
            if any(status_by_id[item] != "MATCH" for item in required)
            else "READY"
        )
        return SandboxEnvironment(
            meta=fresh_record_meta(meta, "sandbox_environment"),
            request_ref=ReproductionSetupAutomation._exact_ref(request),
            reproduction_plan_ref=ReproductionSetupAutomation._exact_ref(plan),
            environment_recipe_ref=ReproductionSetupAutomation._exact_ref(recipe),
            requirements_ref=ReproductionSetupAutomation._exact_ref(requirements),
            container_instance_id=container_id,
            container_action=action,
            container_reason=reason,
            previous_environment_ref=previous_environment_ref,
            status=status,
            checks=checks,
            limitations=(),
            created_at=meta.created_at,
        )

    @staticmethod
    def _exact_ref(record: object) -> StoredDataRef:
        result = reference(record)  # type: ignore[arg-type]
        if not isinstance(result, StoredDataRef):
            raise ValueError("CODE_SCOPED_REFERENCE_REQUIRED")
        return result

    @staticmethod
    def _labels(meta: RecordMeta) -> Mapping[str, str]:
        if meta.hypothesis_id is None or meta.attempt_id is None:
            raise ValueError("DYNAMIC_SETUP_SCOPE_REQUIRED")
        return {
            "sastsimi.owner": "reproduction-setup-automation",
            "sastsimi.analysis-id": str(meta.analysis_id),
            "sastsimi.workspace-id": str(meta.workspace_id),
            "sastsimi.commit-id": str(meta.commit_id),
            "sastsimi.hypothesis-id": str(meta.hypothesis_id),
            "sastsimi.attempt-id": str(meta.attempt_id),
        }

    @staticmethod
    def _container_labels(meta: RecordMeta) -> Mapping[str, str]:
        labels = dict(ReproductionSetupAutomation._labels(meta))
        labels.update(
            {
                "sastsimi.resource-kind": "container",
                "sastsimi.resource-id": uuid4().hex,
            }
        )
        return labels
