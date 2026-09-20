from __future__ import annotations

import hashlib
import shutil
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from sastsimi.config.local_evaluation_profile import LocalEvaluationProfile
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.ids import (
    AnalysisId,
    CommitId,
    RecordId,
    StoredDataId,
    WorkspaceId,
)
from sastsimi.contracts.refs import HostConfigurationRef
from sastsimi.ports.dynamic_sandbox import SandboxRunSpec, TrustedDockerTarget
from sastsimi.sandbox.docker_adapter import DockerAdapter

from .models import CheckpointIdentity, StageCheckpoint


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class _PinnedDockerResolver:
    target: TrustedDockerTarget

    def resolve_current(self, profile_ref: HostConfigurationRef) -> TrustedDockerTarget:
        if profile_ref != self.target.profile_ref:
            raise ValueError("SIMPLE_DOCKER_TARGET_MISMATCH")
        return self.target

    def require_current(self, target: TrustedDockerTarget) -> None:
        if target != self.target:
            raise ValueError("SIMPLE_DOCKER_TARGET_CHANGED")
        executable = target.executable.resolve(strict=True)
        if executable != target.executable or executable.is_symlink():
            raise ValueError("SIMPLE_DOCKER_TARGET_CHANGED")
        if _file_sha256(executable) != target.subject_sha256:
            raise ValueError("SIMPLE_DOCKER_TARGET_CHANGED")


def build_simple_docker_adapter(
    profile: LocalEvaluationProfile,
    identity: CheckpointIdentity,
) -> DockerAdapter:
    located = shutil.which("docker")
    if located is None:
        raise ValueError("DOCKER_NOT_FOUND")
    executable = Path(located).resolve(strict=True)
    target_hash = content_hash(
        {
            "kind": "simple_local_docker_target",
            "host_id": profile.host_id,
            "executable_sha256": _file_sha256(executable),
            "daemon_target": "unix:///var/run/docker.sock",
        }
    )
    record_id = RecordId(f"simple-docker-{target_hash[:32]}")
    profile_ref = HostConfigurationRef(
        stored_data_id=StoredDataId(str(record_id)),
        data_kind="simple_local_docker_target",
        content_hash=target_hash,
        host_id=profile.host_id,
        publication_analysis_id=AnalysisId(identity.analysis_id),
        publication_workspace_id=WorkspaceId(identity.workspace_id),
        publication_commit_id=CommitId(identity.commit_id),
        record_id=record_id,
    )
    target = TrustedDockerTarget(
        profile_ref=profile_ref,
        executable=executable,
        subject_key="docker",
        subject_sha256=_file_sha256(executable),
        daemon_target="unix:///var/run/docker.sock",
        build_backend="LEGACY_LIMITED",
        enforced_build_limits=frozenset({"CPU", "MEMORY", "PID", "DISK"}),
        external_build_disk_limit_bytes=profile.codeql_container.database_limit_bytes,
    )
    resolver = _PinnedDockerResolver(target)
    return DockerAdapter.from_profile(profile_ref, resolver)


class SimpleLocalContainerFactory:
    def __init__(
        self,
        *,
        docker: DockerAdapter,
        profile: LocalEvaluationProfile,
    ) -> None:
        self._docker = docker
        self._profile = profile

    async def acquire(self, checkpoint: StageCheckpoint) -> str:
        if checkpoint.image_digest is None or checkpoint.attempt_id is None:
            raise ValueError("SIMPLE_DOCKER_CHECKPOINT_INCOMPLETE")
        identity = checkpoint.identity
        labels = {
            "sastsimi.owner": "reproduction-setup-automation",
            "sastsimi.analysis-id": identity.analysis_id,
            "sastsimi.workspace-id": identity.workspace_id,
            "sastsimi.commit-id": identity.commit_id,
            "sastsimi.hypothesis-id": identity.hypothesis_id or "analysis",
            "sastsimi.attempt-id": checkpoint.attempt_id,
            "sastsimi.resource-kind": "container",
            "sastsimi.resource-id": uuid4().hex,
        }
        config = self._profile.codeql_container
        spec = SandboxRunSpec(
            workspace_root=self._profile.workspace_root,
            image_digest=checkpoint.image_digest,
            user=config.container_user,
            mounts=(),
            network_mode="DEFAULT_DENY",
            network_targets=(),
            secret_refs=(),
            privileged=False,
            pid_mode=None,
            ipc_mode=None,
            capabilities=(),
            cpu_limit_millicores=max(1, config.nano_cpus // 1_000_000),
            memory_limit_bytes=config.memory_limit_bytes,
            disk_limit_bytes=config.database_limit_bytes,
            pid_limit=config.pids_limit,
            requested_execution_ms=self._profile.timeouts.sandbox_ms,
            source_baked=True,
        )
        container_id = await self._docker.create(spec, labels)
        await self._docker.verify_created_mounts(container_id, spec)
        await self._docker.start(container_id)
        return container_id


__all__ = ["SimpleLocalContainerFactory", "build_simple_docker_adapter"]
