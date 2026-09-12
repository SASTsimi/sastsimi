"""Narrow ports used by the dynamic-reproduction application service."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal, Protocol

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

type RecreateReason = Literal["STATE_CHANGED", "CONFIG_CHANGED", "STATE_UNCERTAIN"]


@dataclass(frozen=True)
class SandboxMount:
    """One normalized mount admitted at the Sandbox boundary."""

    source: Path | None
    target: PurePosixPath
    read_only: bool


@dataclass(frozen=True)
class SandboxRunSpec:
    """Exact, already-normalized Sandbox run specification."""

    workspace_root: Path
    image_digest: str | None
    user: str
    mounts: tuple[SandboxMount, ...]
    network_mode: str
    network_targets: tuple[str, ...]
    secret_refs: tuple[StoredDataRef, ...]
    privileged: bool
    pid_mode: str | None
    ipc_mode: str | None
    capabilities: tuple[str, ...]
    cpu_limit_millicores: int
    memory_limit_bytes: int
    disk_limit_bytes: int
    pid_limit: int
    requested_execution_ms: int


class PreparedRecipeSourceView(Protocol):
    @property
    def workspace_root(self) -> Path: ...

    @property
    def request_ref(self) -> StoredDataRef: ...

    @property
    def requirements_ref(self) -> StoredDataRef: ...

    @property
    def meta(self) -> RecordMeta: ...

    @property
    def recipe_source_ref(self) -> StoredDataRef: ...

    @property
    def source_refs(self) -> tuple[StoredDataRef, ...]: ...

    @property
    def source_digest(self) -> str: ...

    @property
    def dockerfile(self) -> bytes: ...

    @property
    def dockerfile_digest(self) -> str: ...

    @property
    def base_image(self) -> str: ...


@dataclass(frozen=True)
class SandboxBuildBoundaryOutcome:
    decision: SandboxPolicyDecision
    approved_spec: SandboxRunSpec | None
    approved_source: PreparedRecipeSourceView | None


@dataclass(frozen=True)
class SandboxBoundaryOutcome:
    decision: SandboxPolicyDecision
    approved_spec: SandboxRunSpec | None
    approved_recipe_ref: StoredDataRef | None = None


@dataclass(frozen=True, slots=True)
class PreparedSandbox:
    recipe: EnvironmentRecipe
    environment: SandboxEnvironment
    resource_refs: tuple[StoredDataRef, ...]


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

    def __init__(self, prepared: PreparedSandbox) -> None:
        super().__init__("OWNED_RESOURCE_CLEANUP_FAILED")
        self.prepared = prepared


class SandboxControllerPort(Protocol):
    @property
    def workspace_root(self) -> Path: ...

    def evaluate_build(
        self,
        *,
        spec: SandboxRunSpec,
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
    ) -> SandboxBuildBoundaryOutcome: ...

    def evaluate(
        self,
        *,
        spec: SandboxRunSpec,
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
    ) -> SandboxBoundaryOutcome: ...


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
        approval: SandboxBuildBoundaryOutcome,
        source: PreparedRecipeSourceView,
        request: DynamicReproductionRequest,
        requirements: EnvironmentRequirements,
        meta: RecordMeta,
    ) -> EnvironmentRecipe: ...

    async def create(
        self,
        *,
        approval: SandboxBoundaryOutcome,
        recipe: EnvironmentRecipe,
        request: DynamicReproductionRequest,
        requirements: EnvironmentRequirements,
        plan: ReproductionPlan,
        meta: RecordMeta,
    ) -> PreparedSandbox: ...

    async def reuse(
        self, *, previous: PreparedSandbox, meta: RecordMeta
    ) -> PreparedSandbox: ...

    async def recreate(
        self,
        *,
        approval: SandboxBoundaryOutcome,
        previous: PreparedSandbox,
        reason: RecreateReason,
        meta: RecordMeta,
    ) -> PreparedSandbox: ...

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
    "PreparedSandbox",
    "RecreateReason",
    "ReproductionSetupPort",
    "SandboxBoundaryOutcome",
    "SandboxBuildBoundaryOutcome",
    "SandboxControllerPort",
    "SandboxMount",
    "SandboxRunSpec",
    "SandboxSetupCleanupError",
]
