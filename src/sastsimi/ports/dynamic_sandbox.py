"""Narrow ports used by the dynamic-reproduction application service."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.budget import DynamicReproductionLifecycleProfile
from sastsimi.contracts.dynamic import (
    CleanupResult,
    DynamicReproductionRequest,
    EnvironmentRecipe,
    EnvironmentRequirements,
    ReproductionPlan,
    SandboxEnvironment,
    SandboxPolicyDecision,
    SandboxProfile,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef


class SandboxRunSpecView(Protocol):
    """Opaque, already-normalized Sandbox run specification."""

    @property
    def requested_execution_ms(self) -> int: ...


class PreparedRecipeSourceView(Protocol):
    @property
    def recipe_source_ref(self) -> StoredDataRef: ...


class SandboxBuildBoundaryOutcomeView(Protocol):
    @property
    def decision(self) -> SandboxPolicyDecision: ...


class SandboxBoundaryOutcomeView(Protocol):
    @property
    def decision(self) -> SandboxPolicyDecision: ...


class PreparedSandboxView(Protocol):
    @property
    def recipe(self) -> EnvironmentRecipe: ...

    @property
    def environment(self) -> SandboxEnvironment: ...

    @property
    def resource_refs(self) -> tuple[StoredDataRef, ...]: ...


class DockerCommandOutcomeView(Protocol):
    @property
    def exit_code(self) -> int: ...

    @property
    def stdout(self) -> bytes: ...

    @property
    def stderr(self) -> bytes: ...

    @property
    def timed_out(self) -> bool: ...


class SandboxSetupCleanupError(RuntimeError):
    """Setup failed and its exact owned container still requires cleanup."""

    def __init__(self, prepared: PreparedSandboxView) -> None:
        super().__init__("OWNED_RESOURCE_CLEANUP_FAILED")
        self.prepared = prepared


class SandboxControllerPort(Protocol):
    @property
    def workspace_root(self) -> Path: ...

    def evaluate_build(
        self,
        *,
        spec: SandboxRunSpecView,
        source: PreparedRecipeSourceView,
        action: ActionRequest,
        action_decision_ref: StoredDataRef,
        request: DynamicReproductionRequest,
        plan: ReproductionPlan,
        sandbox_profile: SandboxProfile,
        lifecycle_profile: DynamicReproductionLifecycleProfile,
        run_policy_state_ref: StoredDataRef,
        required_context_refs: tuple[StoredDataRef, ...],
        meta: RecordMeta,
    ) -> SandboxBuildBoundaryOutcomeView: ...

    def evaluate(
        self,
        *,
        spec: SandboxRunSpecView,
        recipe: EnvironmentRecipe,
        action: ActionRequest,
        action_decision_ref: StoredDataRef,
        request: DynamicReproductionRequest,
        plan: ReproductionPlan,
        sandbox_profile: SandboxProfile,
        lifecycle_profile: DynamicReproductionLifecycleProfile,
        run_policy_state_ref: StoredDataRef,
        required_context_refs: tuple[StoredDataRef, ...],
        meta: RecordMeta,
    ) -> SandboxBoundaryOutcomeView: ...


class ReproductionSetupPort(Protocol):
    async def preflight(
        self,
        *,
        workspace_root: Path,
        request: DynamicReproductionRequest,
        requirements: EnvironmentRequirements,
        meta: RecordMeta,
    ) -> PreparedRecipeSourceView: ...

    async def build(
        self,
        *,
        approval: SandboxBuildBoundaryOutcomeView,
        source: PreparedRecipeSourceView,
        request: DynamicReproductionRequest,
        requirements: EnvironmentRequirements,
        meta: RecordMeta,
    ) -> EnvironmentRecipe: ...

    async def create(
        self,
        *,
        approval: SandboxBoundaryOutcomeView,
        recipe: EnvironmentRecipe,
        request: DynamicReproductionRequest,
        requirements: EnvironmentRequirements,
        plan: ReproductionPlan,
        meta: RecordMeta,
    ) -> PreparedSandboxView: ...

    async def reuse(
        self, *, previous: PreparedSandboxView, meta: RecordMeta
    ) -> PreparedSandboxView: ...

    async def recreate(
        self,
        *,
        approval: SandboxBoundaryOutcomeView,
        previous: PreparedSandboxView,
        reason: str,
        meta: RecordMeta,
    ) -> PreparedSandboxView: ...

    async def cleanup(
        self,
        *,
        request: DynamicReproductionRequest,
        environments: tuple[SandboxEnvironment, ...],
        resource_refs: tuple[StoredDataRef, ...],
        meta: RecordMeta,
    ) -> CleanupResult: ...


class DynamicDockerExecutionPort(Protocol):
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
    ) -> DockerCommandOutcomeView: ...


__all__ = [
    "DockerCommandOutcomeView",
    "DynamicDockerExecutionPort",
    "PreparedRecipeSourceView",
    "PreparedSandboxView",
    "ReproductionSetupPort",
    "SandboxBoundaryOutcomeView",
    "SandboxBuildBoundaryOutcomeView",
    "SandboxControllerPort",
    "SandboxRunSpecView",
    "SandboxSetupCleanupError",
]
