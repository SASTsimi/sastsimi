"""LOCAL_EVALUATION dynamic reproduction on the current shared Docker daemon.

This composition intentionally does not publish or require a Production Docker
capability.  It pins the selected local Docker CLI for the lifetime of the run
and reuses the existing T11 outer-boundary implementation, which owns every
Docker argument and every SASTSIMI ownership label.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from sastsimi.composition.local_evaluation_composition import (
    LocalEvaluationInstallationContext,
)
from sastsimi.composition.production_dynamic_feature_builder import (
    ProductionDynamicAuthorizationResolver,
)
from sastsimi.composition.production_feature_installer import (
    DynamicProductionFeature,
)
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.budget import Purpose
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.dynamic import DependencyBundle, SandboxProfile
from sastsimi.contracts.ids import RecordId, StoredDataId
from sastsimi.contracts.refs import HostConfigurationRef, StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dynamic_sandbox import TrustedDockerTarget
from sastsimi.sandbox.docker_adapter import DockerAdapter


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class LocalSharedDockerTargetResolver:
    """Pin one current local CLI/daemon pair without a Production approval."""

    target: TrustedDockerTarget

    def resolve_current(self, profile_ref: HostConfigurationRef) -> TrustedDockerTarget:
        if profile_ref != self.target.profile_ref:
            raise ValueError("LOCAL_DOCKER_TARGET_MISMATCH")
        return self.target

    def require_current(self, target: TrustedDockerTarget) -> None:
        if target != self.target:
            raise ValueError("LOCAL_DOCKER_TARGET_CHANGED")
        executable = target.executable
        try:
            if executable.is_symlink():
                raise ValueError
            current = executable.resolve(strict=True)
            if current != executable or not current.is_file():
                raise ValueError
            digest = _sha256(current)
        except (OSError, ValueError):
            raise ValueError("LOCAL_DOCKER_TARGET_CHANGED") from None
        if digest != target.subject_sha256:
            raise ValueError("LOCAL_DOCKER_TARGET_CHANGED")


def _local_target(
    context: LocalEvaluationInstallationContext,
    *,
    docker_executable: Path,
    docker_host: str,
    build_disk_limit_bytes: int,
) -> tuple[HostConfigurationRef, LocalSharedDockerTargetResolver]:
    try:
        if docker_executable.is_symlink():
            raise ValueError
        executable = docker_executable.resolve(strict=True)
        if (
            executable != docker_executable.absolute()
            or not executable.is_file()
            or executable.name.lower() not in {"docker", "docker.exe"}
        ):
            raise ValueError
        executable_sha256 = _sha256(executable)
    except (OSError, ValueError):
        raise ValueError("LOCAL_DOCKER_EXECUTABLE_INVALID") from None

    target_hash = content_hash(
        {
            "kind": "local_shared_docker_target",
            "host_id": context.profile.host_id,
            "executable_sha256": executable_sha256,
            "daemon_target": docker_host,
        }
    )
    record_id = RecordId(f"local-shared-docker-{target_hash[:32]}")
    profile_ref = HostConfigurationRef(
        stored_data_id=StoredDataId(str(record_id)),
        data_kind="local_shared_docker_target",
        content_hash=target_hash,
        host_id=context.profile.host_id,
        publication_analysis_id=context.scope.analysis_id,
        publication_workspace_id=context.scope.workspace_id,
        publication_commit_id=context.scope.commit_id,
        record_id=record_id,
    )
    target = TrustedDockerTarget(
        profile_ref=profile_ref,
        executable=executable,
        subject_key="docker",
        subject_sha256=executable_sha256,
        daemon_target=docker_host,
        # The shared T11 adapter has one shell-free build implementation.  In
        # local evaluation these fixed flags are requested directly; they are
        # not represented as Production boundary evidence.
        build_backend="LEGACY_LIMITED",
        enforced_build_limits=frozenset({"CPU", "MEMORY", "PID", "DISK"}),
        external_build_disk_limit_bytes=build_disk_limit_bytes,
    )
    resolver = LocalSharedDockerTargetResolver(target)
    # Validate the fixed local host syntax and target shape at composition time.
    DockerAdapter.from_profile(profile_ref, resolver)
    return profile_ref, resolver


def _default_docker_host() -> str:
    if os.name == "nt":
        return "npipe:////./pipe/docker_engine"
    return "unix:///var/run/docker.sock"


def build_local_shared_dynamic_feature(
    *,
    context: LocalEvaluationInstallationContext,
    sandbox_profile: SandboxProfile,
    docker_executable: Path,
    workspace_root_for: Callable[[WorkExecutionState], Path],
    docker_host: str | None = None,
    max_execute_turns: int = 8,
    dependency_bundle: DependencyBundle | None = None,
) -> DynamicProductionFeature:
    """Connect the existing T11 graph to this run's current shared Docker."""

    if (
        context.request.purpose != Purpose.LOCAL_EVALUATION
        or context.profile.purpose != "LOCAL_EVALUATION"
        or context.profile.production_ready is not False
    ):
        raise ValueError("LOCAL_DYNAMIC_PURPOSE_REQUIRED")
    if max_execute_turns <= 0:
        raise ValueError("LOCAL_DYNAMIC_EXECUTE_TURNS_INVALID")

    profile_ref, target_resolver = _local_target(
        context,
        docker_executable=docker_executable,
        docker_host=docker_host or _default_docker_host(),
        build_disk_limit_bytes=sandbox_profile.disk_limit_bytes,
    )
    authorization = ProductionDynamicAuthorizationResolver(
        runner=context.runner,
        records=context.runtime.unit_of_work.records,
        queries=context.runtime.queries,
        current_run=context.runtime.budget_registry.current_state,
        setup_identity=context.role_identity_refs[
            RequesterRole.REPRODUCTION_SETUP_AUTOMATION
        ],
        sandbox_profile=sandbox_profile,
        container_user=context.profile.codeql_container.container_user,
        workspace_root_for=workspace_root_for,
        docker_readiness=lambda: target_resolver.require_current(
            target_resolver.target
        ),
        authorization=context.runtime.validator,
    )
    journal = (
        context.data_dir
        / "local-dynamic"
        / str(context.scope.analysis_id)
        / "resources.json"
    ).resolve(strict=False)
    docker = DockerAdapter.from_profile(
        profile_ref,
        target_resolver,
        build_network="default",
    )
    return DynamicProductionFeature(
        sandbox_authorization=authorization,
        sandbox_profile=lambda _work: _sandbox_ref(sandbox_profile),
        max_execute_turns=max_execute_turns,
        resource_journal_path=journal,
        docker_profile_ref=profile_ref,
        docker_target_resolver=target_resolver,
        docker=docker,
        dependency_bundle=dependency_bundle,
        allow_repository_build_network=True,
    )


def _sandbox_ref(profile: SandboxProfile) -> StoredDataRef:
    value = reference(profile)
    if not isinstance(value, StoredDataRef):
        raise ValueError("LOCAL_SANDBOX_PROFILE_SCOPE_INVALID")
    return value


__all__ = [
    "LocalSharedDockerTargetResolver",
    "build_local_shared_dynamic_feature",
]
