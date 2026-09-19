"""Real repository and static-tool wiring for ``LOCAL_EVALUATION`` runs.

This module reuses the hardened repository loader and static adapters.  It
does not mint production approval, infer a replacement tool, or translate a
tool failure into a vulnerability verdict.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, cast

from sastsimi.contracts.capabilities import RuntimeCapabilityProfile
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import (
    HostConfigurationRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.static import (
    CodeWorkspace,
    RepositoryProfile,
    StaticToolProfile,
    ToolRunResult,
)
from sastsimi.orchestration.static_adapter_context import (
    ApprovedStaticRuleClosure,
    StaticAdapterBuildContext,
    StaticAdapterFactory,
)
from sastsimi.orchestration.static_work_handlers import StaticToolRoute
from sastsimi.ports.capability_registry import ProductionCapabilityResolverPort
from sastsimi.ports.dto import (
    MonotonicActionDeadline,
    RepositoryPreparation,
    StaticToolRequest,
    TrackedFile,
    WorkspaceStoragePolicy,
)
from sastsimi.ports.static_tool import (
    StaticExternalExecutionPort,
    StaticProcessAdapter,
    StaticToolAdapter,
)
from sastsimi.ports.workspace import WorkspaceLocatorPort, WorkspaceStoragePort
from sastsimi.static_analysis.coordinator import StaticToolCoordinator
from sastsimi.static_analysis.repository_loader import (
    RepositoryLoader,
    RepositoryProcessRunnerFactory,
)
from sastsimi.static_analysis.repository_profile import RepositoryProfiler


class LocalEvaluationStaticBlocked(RuntimeError):
    """Fail-closed local evaluation state; deliberately has no verdict field."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class LocalStaticCapabilityKeys(Protocol):
    @property
    def git_profile_key(self) -> str: ...

    @property
    def python_ast_profile_key(self) -> str: ...

    @property
    def opengrep_profile_key(self) -> str: ...

    @property
    def codeql_profile_key(self) -> str: ...


class RegisteringWorkspaceLocator(WorkspaceLocatorPort, Protocol):
    def register(self, outcome: RepositoryPreparation) -> None: ...

    def tracked_files_for(
        self, workspace: CodeWorkspace
    ) -> tuple[TrackedFile, ...]: ...


class LocalRepositoryLoaderPort(Protocol):
    async def prepare(
        self,
        *,
        submitted_source: str,
        requested_ref: str,
        analysis_id: str,
        workspace_id: str,
        attempt_id: str,
        policy_ref: RunStoredDataRef,
        policy: WorkspaceStoragePolicy,
        deadline: MonotonicActionDeadline,
    ) -> RepositoryPreparation: ...


@dataclass(frozen=True, slots=True)
class LocalEvaluationStaticInputs:
    """Exact, credential-free dependencies selected for one local run."""

    data_dir: Path
    host_id: str
    capability_keys: LocalStaticCapabilityKeys
    capability_resolver: ProductionCapabilityResolverPort
    storage: WorkspaceStoragePort
    workspace_locator: RegisteringWorkspaceLocator
    repository_process_runner_factory: RepositoryProcessRunnerFactory
    external_execution: StaticExternalExecutionPort
    git_executable: Path
    git_profile_ref: HostConfigurationRef
    static_profile_refs: Mapping[str, HostConfigurationRef]
    routes: Mapping[str, StaticToolRoute]
    evidence: Mapping[str, bytes]
    rule_closures: Mapping[str, ApprovedStaticRuleClosure]
    build_static_adapters: StaticAdapterFactory
    allow_local_repository: bool = False


class _PinnedStaticProfileResolver:
    def __init__(
        self,
        resolver: ProductionCapabilityResolverPort,
        allowed: Mapping[HostConfigurationRef, StaticToolProfile],
    ) -> None:
        self._resolver = resolver
        self._allowed = dict(allowed)

    def resolve(
        self, profile_ref: StoredDataRef | HostConfigurationRef
    ) -> StaticToolProfile:
        if not isinstance(profile_ref, HostConfigurationRef):
            raise LookupError("LOCAL_EVALUATION_STATIC_PROFILE_NOT_PINNED")
        try:
            expected = self._allowed[profile_ref]
        except KeyError:
            raise LookupError("LOCAL_EVALUATION_STATIC_PROFILE_NOT_PINNED") from None
        current = self._resolver.resolve_pinned_active_profile(profile_ref)
        if current != expected or reference(current) != profile_ref:
            raise LookupError("LOCAL_EVALUATION_STATIC_PROFILE_STALE")
        return expected


@dataclass(frozen=True, slots=True)
class LocalEvaluationStaticServices:
    """Reusable local-evaluation repository and static execution slice."""

    loader: LocalRepositoryLoaderPort
    profiler: RepositoryProfiler
    tools: StaticToolAdapter
    profile_refs: Mapping[str, HostConfigurationRef]
    workspace_locator: RegisteringWorkspaceLocator

    async def prepare_repository(
        self,
        *,
        submitted_source: str,
        requested_ref: str,
        analysis_id: str,
        workspace_id: str,
        attempt_id: str,
        policy_ref: RunStoredDataRef,
        policy: WorkspaceStoragePolicy,
        deadline: MonotonicActionDeadline,
    ) -> RepositoryPreparation:
        try:
            outcome = await self.loader.prepare(
                submitted_source=submitted_source,
                requested_ref=requested_ref,
                analysis_id=analysis_id,
                workspace_id=workspace_id,
                attempt_id=attempt_id,
                policy_ref=policy_ref,
                policy=policy,
                deadline=deadline,
            )
        except Exception as error:
            raise LocalEvaluationStaticBlocked(
                "LOCAL_EVALUATION_REPOSITORY_PREPARATION_BLOCKED"
            ) from error
        if not isinstance(outcome, RepositoryPreparation) or outcome.status != "READY":
            raise LocalEvaluationStaticBlocked(
                "LOCAL_EVALUATION_REPOSITORY_PREPARATION_BLOCKED"
            )
        try:
            self.workspace_locator.register(outcome)
        except Exception as error:
            raise LocalEvaluationStaticBlocked(
                "LOCAL_EVALUATION_WORKSPACE_REGISTRATION_BLOCKED"
            ) from error
        return outcome

    def build_repository_profile(
        self,
        preparation: RepositoryPreparation,
        *,
        meta: RecordMeta,
        workspace_ref: RunStoredDataRef,
        action_decision_ref: StoredDataRef,
    ) -> RepositoryProfile:
        try:
            return self.profiler.build(
                preparation,
                meta=meta,
                workspace_ref=workspace_ref,
                action_decision_ref=action_decision_ref,
            )
        except Exception as error:
            raise LocalEvaluationStaticBlocked(
                "LOCAL_EVALUATION_REPOSITORY_PROFILE_BLOCKED"
            ) from error

    async def run_tools(
        self, requests: tuple[StaticToolRequest, ...]
    ) -> tuple[ToolRunResult, ...]:
        if not requests:
            raise LocalEvaluationStaticBlocked(
                "LOCAL_EVALUATION_STATIC_REQUESTS_EMPTY"
            )
        configured = frozenset(self.profile_refs.values())
        requested = tuple(item.tool_profile_ref for item in requests)
        if (
            len(requested) != len(set(requested))
            or any(ref not in configured for ref in requested)
        ):
            raise LocalEvaluationStaticBlocked(
                "LOCAL_EVALUATION_STATIC_PROFILE_BINDING_BLOCKED"
            )
        try:
            capabilities = await asyncio.gather(
                *(self.tools.probe(ref) for ref in requested)
            )
            if any(not item.available for item in capabilities):
                raise LocalEvaluationStaticBlocked(
                    "LOCAL_EVALUATION_STATIC_CAPABILITY_BLOCKED"
                )
            raw_results = await asyncio.gather(
                *(self.tools.run(request) for request in requests),
                return_exceptions=True,
            )
        except LocalEvaluationStaticBlocked:
            raise
        except Exception as error:
            raise LocalEvaluationStaticBlocked(
                "LOCAL_EVALUATION_STATIC_EXECUTION_BLOCKED"
            ) from error
        cancellation = next(
            (
                item
                for item in raw_results
                if isinstance(item, asyncio.CancelledError)
            ),
            None,
        )
        if cancellation is not None:
            raise cancellation
        if any(isinstance(item, BaseException) for item in raw_results):
            raise LocalEvaluationStaticBlocked(
                "LOCAL_EVALUATION_STATIC_EXECUTION_BLOCKED"
            )
        results = cast(tuple[ToolRunResult, ...], tuple(raw_results))
        if any(item.status in {"FAILED", "SKIPPED"} for item in results):
            raise LocalEvaluationStaticBlocked(
                "LOCAL_EVALUATION_STATIC_EXECUTION_BLOCKED"
            )
        return results


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_directory(root: Path, relative: str) -> Path:
    base = root.resolve(strict=True)
    target = base.joinpath(*relative.split("/"))
    try:
        target.relative_to(base)
        target.mkdir(parents=True, exist_ok=True)
        resolved = target.resolve(strict=True)
    except (OSError, ValueError) as error:
        raise ValueError("LOCAL_EVALUATION_STATIC_PATH_INVALID") from error
    if target.is_symlink() or not resolved.is_dir():
        raise ValueError("LOCAL_EVALUATION_STATIC_PATH_INVALID")
    return resolved


def _expected_static_key(keys: LocalStaticCapabilityKeys, tool: str) -> str:
    try:
        return {
            "AST": keys.python_ast_profile_key,
            "OPENGREP": keys.opengrep_profile_key,
            "CODEQL": keys.codeql_profile_key,
        }[tool]
    except KeyError:
        raise ValueError("LOCAL_EVALUATION_STATIC_ROUTE_INVALID") from None


def _resolve_capabilities(
    inputs: LocalEvaluationStaticInputs,
) -> tuple[RuntimeCapabilityProfile, Mapping[str, StaticToolProfile]]:
    git = inputs.capability_resolver.resolve_pinned_active_profile(
        inputs.git_profile_ref
    )
    if (
        not isinstance(git, RuntimeCapabilityProfile)
        or reference(git) != inputs.git_profile_ref
        or git.host_id != inputs.host_id
        or git.profile_key != inputs.capability_keys.git_profile_key
        or git.status != "ACTIVE"
        or git.purpose != "PRODUCTION"
        or git.capability_kind != "GIT"
        or not {"CLONE", "CHECKOUT"} <= set(git.operations)
    ):
        raise ValueError("LOCAL_EVALUATION_GIT_CAPABILITY_INVALID")

    if set(inputs.static_profile_refs) != set(inputs.routes):
        raise ValueError("LOCAL_EVALUATION_STATIC_PROFILE_SET_INVALID")
    profiles: dict[str, StaticToolProfile] = {}
    for tool, profile_ref in inputs.static_profile_refs.items():
        current = inputs.capability_resolver.resolve_pinned_active_profile(profile_ref)
        route = inputs.routes[tool]
        if (
            not isinstance(current, StaticToolProfile)
            or reference(current) != profile_ref
            or current.host_id != inputs.host_id
            or current.status != "ACTIVE"
            or current.purpose != "PRODUCTION"
            or current.tool_name != tool
            or current.profile_key != _expected_static_key(inputs.capability_keys, tool)
            or route.tool_profile_ref != profile_ref
        ):
            raise ValueError("LOCAL_EVALUATION_STATIC_CAPABILITY_INVALID")
        profiles[tool] = current
    return git, MappingProxyType(profiles)


def _require_evidence(inputs: LocalEvaluationStaticInputs) -> None:
    direct_digests = {
        route.analysis_config_ref.content_hash for route in inputs.routes.values()
    } | {
        route.rule_catalog_ref.content_hash
        for route in inputs.routes.values()
        if route.rule_catalog_ref is not None
    }
    for closure in inputs.rule_closures.values():
        direct_digests.update(
            (
                closure.catalog_sha256,
                closure.selection_sha256,
                closure.mapping_sha256,
            )
        )
    for digest in direct_digests:
        payload = inputs.evidence.get(digest)
        if payload is None or hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError("LOCAL_EVALUATION_STATIC_EVIDENCE_INVALID")


def build_local_evaluation_static(
    inputs: LocalEvaluationStaticInputs,
) -> LocalEvaluationStaticServices:
    """Compose exact real repository/static components for one local run."""

    git_profile, profiles = _resolve_capabilities(inputs)
    _require_evidence(inputs)
    try:
        git = inputs.git_executable.resolve(strict=True)
    except OSError as error:
        raise ValueError("LOCAL_EVALUATION_GIT_EXECUTABLE_INVALID") from error
    if (
        not git.is_file()
        or git.stem.lower() != str(git_profile.subject_key).lower()
        or _sha256(git) != git_profile.subject_sha256
    ):
        raise ValueError("LOCAL_EVALUATION_GIT_EXECUTABLE_INVALID")

    output_root = _safe_directory(inputs.data_dir, "process-output/local-static")
    loader = RepositoryLoader(
        storage=inputs.storage,
        process_runner_factory=inputs.repository_process_runner_factory,
        git_executable=git,
        output_dir=output_root,
        allow_local_file=inputs.allow_local_repository,
    )
    adapter_context = StaticAdapterBuildContext(
        data_dir=inputs.data_dir,
        workspace_locator=inputs.workspace_locator,
        tracked_files_for=inputs.workspace_locator.tracked_files_for,
        routes=MappingProxyType(dict(inputs.routes)),
        profiles=profiles,
        evidence=MappingProxyType(dict(inputs.evidence)),
        rule_closures=MappingProxyType(dict(inputs.rule_closures)),
    )
    adapters = dict(inputs.build_static_adapters(adapter_context))
    expected_adapters = {profile.adapter_key for profile in profiles.values()}
    if set(adapters) != expected_adapters:
        raise ValueError("LOCAL_EVALUATION_STATIC_ADAPTER_SET_INVALID")

    executables: dict[str, Path] = {}
    for profile in profiles.values():
        adapter = adapters[profile.adapter_key]
        adapter_type = type(adapter)
        if (
            "fake" in adapter_type.__module__.lower()
            or "fake" in adapter_type.__name__.lower()
            or not callable(getattr(adapter, "probe", None))
            or not callable(getattr(adapter, "execute", None))
            or not callable(getattr(adapter, "cancel", None))
            or not isinstance(getattr(adapter, "executable", None), Path)
        ):
            raise ValueError("LOCAL_EVALUATION_STATIC_ADAPTER_INVALID")
        executable = adapter.executable.resolve(strict=True)
        if not executable.is_file() or _sha256(executable) != profile.executable_sha256:
            raise ValueError("LOCAL_EVALUATION_STATIC_EXECUTABLE_INVALID")
        existing = executables.get(str(profile.executable_key))
        if existing is not None and existing != executable:
            raise ValueError("LOCAL_EVALUATION_STATIC_EXECUTABLE_KEY_COLLISION")
        executables[str(profile.executable_key)] = executable

    by_ref = {
        inputs.static_profile_refs[tool]: profile
        for tool, profile in profiles.items()
    }
    tools = StaticToolCoordinator(
        _PinnedStaticProfileResolver(inputs.capability_resolver, by_ref),
        cast(Mapping[str, StaticProcessAdapter], adapters),
        inputs.external_execution,
        inputs.workspace_locator,
        executables,
        prohibited_workspace_roots=(inputs.data_dir,),
    )
    return LocalEvaluationStaticServices(
        loader=loader,
        profiler=RepositoryProfiler(),
        tools=cast(StaticToolAdapter, tools),
        profile_refs=MappingProxyType(dict(sorted(inputs.static_profile_refs.items()))),
        workspace_locator=inputs.workspace_locator,
    )


__all__ = [
    "LocalEvaluationStaticBlocked",
    "LocalEvaluationStaticInputs",
    "LocalEvaluationStaticServices",
    "build_local_evaluation_static",
]
