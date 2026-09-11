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

from .cleanup import OwnedResourceRegistry
from .controller import SandboxBoundaryOutcome, SandboxRunSpec
from .docker_adapter import DockerCommandOutcome, DockerContainerState
from .health_check import SandboxHealthChecker
from .recipe_store import EnvironmentRecipeStore, fresh_record_meta

RecreateReason = Literal["STATE_CHANGED", "CONFIG_CHANGED", "STATE_UNCERTAIN"]


class DockerLifecyclePort(Protocol):
    async def build(self, recipe_source: Path, labels: Mapping[str, str]) -> str: ...
    async def inspect_image(self, image: str) -> str: ...
    async def create(self, spec: SandboxRunSpec, labels: Mapping[str, str]) -> str: ...
    async def start(self, container_id: str) -> None: ...
    async def exec(
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
class PreparedSandbox:
    recipe: EnvironmentRecipe
    environment: SandboxEnvironment
    resource_refs: tuple[StoredDataRef, ...]


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

    async def prepare(
        self,
        *,
        approval: SandboxBoundaryOutcome,
        request: DynamicReproductionRequest,
        requirements: EnvironmentRequirements,
        plan: ReproductionPlan,
        meta: RecordMeta,
    ) -> PreparedSandbox:
        spec = self._validate_prepare(approval, request, requirements, plan, meta)
        labels = self._labels(meta)
        recipe = await self._recipes.prepare(
            docker=self._docker,
            context=spec.workspace_root,
            labels=labels,
            request_ref=self._exact_ref(request),
            requirements=requirements,
            meta=meta,
        )
        if recipe.built_image_digest != spec.image_digest:
            raise ValueError("APPROVED_IMAGE_DIGEST_MISMATCH")
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
        try:
            state = await self._health.inspect_ready(
                self._docker.inspect,
                previous.environment.container_instance_id,
            )
        except ValueError as error:
            if str(error) != "SANDBOX_STATE_UNCERTAIN":
                raise
            return await self.recreate(
                previous=previous,
                reason="STATE_UNCERTAIN",
                meta=meta,
            )
        recipe = self._recipes.bind_existing(
            baseline=previous.recipe,
            requirements=context.requirements,
            meta=meta,
        )
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
        previous: PreparedSandbox,
        reason: RecreateReason,
        meta: RecordMeta,
    ) -> PreparedSandbox:
        context = self._context(previous)
        self._validate_reuse_scope(previous, context, meta)
        if reason not in {"STATE_CHANGED", "CONFIG_CHANGED", "STATE_UNCERTAIN"}:
            raise ValueError("SANDBOX_RECREATE_REASON_INVALID")
        recipe = self._recipes.bind_existing(
            baseline=previous.recipe,
            requirements=context.requirements,
            meta=meta,
        )
        labels = self._container_labels(meta)
        prepared = await self._create_environment(
            spec=context.approval.approved_spec,
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
                context.approval,
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
        container_id = await self._docker.create(spec, labels)
        resource_ref = self._resources.register_container(
            container_id=container_id,
            labels=labels,
            meta=meta,
        )
        try:
            await self._docker.start(container_id)
            state = await self._health.inspect_ready(self._docker.inspect, container_id)
        except BaseException:
            try:
                await self._docker.remove((container_id,))
            except BaseException:
                pass
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
    def _validate_prepare(
        approval: SandboxBoundaryOutcome,
        request: DynamicReproductionRequest,
        requirements: EnvironmentRequirements,
        plan: ReproductionPlan,
        meta: RecordMeta,
    ) -> SandboxRunSpec:
        if approval.decision.decision != "ALLOW" or approval.approved_spec is None:
            raise ValueError("SANDBOX_APPROVAL_REQUIRED")
        request_ref = ReproductionSetupAutomation._exact_ref(request)
        requirements_ref = ReproductionSetupAutomation._exact_ref(requirements)
        if (
            approval.decision.request_ref != request_ref
            or requirements.request_ref != request_ref
            or plan.request_ref != request_ref
            or plan.environment_requirements_ref != requirements_ref
            or plan.purpose != request.purpose
            or plan.hypothesis_ref != request.hypothesis_ref
            or plan.sandbox_profile_ref != request.sandbox_profile_ref
        ):
            raise ValueError("DYNAMIC_SETUP_CLOSURE_MISMATCH")
        for record in (requirements, plan):
            if (
                record.meta.analysis_id != meta.analysis_id
                or record.meta.workspace_id != meta.workspace_id
                or record.meta.commit_id != meta.commit_id
                or record.meta.hypothesis_id != meta.hypothesis_id
                or record.meta.attempt_id != meta.attempt_id
            ):
                raise ValueError("DYNAMIC_SETUP_SCOPE_MISMATCH")
        if request.meta.hypothesis_id != meta.hypothesis_id:
            raise ValueError("DYNAMIC_SETUP_SCOPE_MISMATCH")
        return approval.approved_spec

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
