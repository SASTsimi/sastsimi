"""Shell-free Docker CLI boundary for the local reproduction Sandbox."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import re
import tarfile
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Literal

from sastsimi.contracts.dynamic import POC_RUNTIME_PATH
from sastsimi.contracts.prompt_redaction import redact_untrusted_text
from sastsimi.contracts.refs import HostConfigurationRef
from sastsimi.ports.dynamic_sandbox import (
    SandboxRunSpec,
    TrustedDockerTarget,
    TrustedDockerTargetResolverPort,
)

_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_OWNED_IMAGE_TAG = re.compile(r"^sastsimi-attempt:[0-9a-f]{32}$")
_RESOURCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_LABEL_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_REQUIRED_LABELS = frozenset(
    {
        "sastsimi.owner",
        "sastsimi.analysis-id",
        "sastsimi.workspace-id",
        "sastsimi.commit-id",
        "sastsimi.hypothesis-id",
        "sastsimi.attempt-id",
    }
)
_CONTAINER_LABELS = _REQUIRED_LABELS | {
    "sastsimi.resource-kind",
    "sastsimi.resource-id",
}
_OUTPUT_LIMIT_BYTES = 1024 * 1024
_OUTPUT_READ_BYTES = 64 * 1024
_POC_STAGING_PATH = f"{POC_RUNTIME_PATH}.next"
_MAX_BUILD_CONTEXT_BYTES = 64 * 1024 * 1024
_REQUIRED_BUILD_LIMITS = frozenset({"CPU", "MEMORY", "PID", "DISK"})
_SAFE_DOCKER_ENV = ("SYSTEMROOT", "WINDIR", "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL")
_CLEANUP_TIMEOUT_MS = 10_000


class _DockerOutputLimitExceeded(Exception):
    pass


@dataclass(frozen=True, slots=True)
class DockerCommandOutcome:
    exit_code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool


@dataclass(frozen=True, slots=True)
class DockerContainerState:
    container_id: str
    image_digest: str
    user: str
    network_mode: str
    privileged: bool
    read_only_rootfs: bool
    running: bool
    exit_code: int
    health_status: str | None
    labels: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class DockerImageState:
    image_digest: str
    labels: Mapping[str, str]


@dataclass(frozen=True, slots=True)
class DockerContainerPresence:
    status: Literal["PRESENT", "ABSENT", "UNKNOWN"]
    state: DockerContainerState | None = None


@dataclass(frozen=True, slots=True)
class DockerImageTagPresence:
    status: Literal["PRESENT", "ABSENT", "UNKNOWN"]
    state: DockerImageState | None = None


class DockerOperationError(RuntimeError):
    """Safe Docker failure; raw process output is available only after redaction."""

    def __init__(self, code: str, outcome: DockerCommandOutcome | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.outcome = outcome


class DockerAdapter:
    """Invoke a fixed Docker executable using argv, never a command shell."""

    def __init__(
        self,
        target: TrustedDockerTarget | None = None,
        resolver: TrustedDockerTargetResolverPort | None = None,
    ) -> None:
        if (target is None) != (resolver is None):
            raise ValueError("DOCKER_TRUSTED_TARGET_INCOMPLETE")
        self._target = target
        self._resolver = resolver
        if target is not None:
            self._validate_target(target)

    @classmethod
    def from_profile(
        cls,
        profile_ref: HostConfigurationRef,
        resolver: TrustedDockerTargetResolverPort,
    ) -> DockerAdapter:
        target = resolver.resolve_current(profile_ref)
        if target.profile_ref != profile_ref:
            raise ValueError("DOCKER_CAPABILITY_PROFILE_MISMATCH")
        return cls(target, resolver)

    async def build(
        self,
        dockerfile: bytes,
        labels: Mapping[str, str],
        *,
        spec: SandboxRunSpec,
        timeout_ms: int,
    ) -> str:
        if not dockerfile or timeout_ms <= 0:
            raise ValueError("DOCKER_BUILD_INPUT_INVALID")
        label_args = self._label_args(labels)
        image_tag = self.runtime_image_tag(labels)
        command = (
            *self._build_command_prefix(),
            "--quiet",
            *self._build_output_args(),
            "--pull=false",
            "--network",
            "none",
            *self._build_limit_args(spec),
            *label_args,
            "--tag",
            image_tag,
            "-",
        )
        try:
            outcome = await self._run(
                command,
                timeout_ms=timeout_ms,
                input_bytes=dockerfile,
            )
            self._require_success("DOCKER_BUILD_FAILED", outcome)
            digest = (
                outcome.stdout.decode("ascii", errors="strict").strip().splitlines()[-1]
            )
            if not _IMAGE_DIGEST.fullmatch(digest):
                raise DockerOperationError("DOCKER_IMAGE_DIGEST_INVALID", outcome)
            return digest
        except BaseException as failure:
            await self._compensate_failed_build(image_tag, labels, failure)
            raise

    async def build_context(
        self,
        context_archive: bytes,
        dockerfile_path: str,
        labels: Mapping[str, str],
        *,
        spec: SandboxRunSpec,
        timeout_ms: int,
    ) -> str:
        """Build a deterministic, prevalidated tar context without host paths."""

        if (
            not context_archive
            or timeout_ms <= 0
            or not dockerfile_path
            or dockerfile_path.startswith(("/", "\\"))
            or ".." in dockerfile_path.replace("\\", "/").split("/")
            or any(character in dockerfile_path for character in "\r\n\0")
        ):
            raise ValueError("DOCKER_BUILD_CONTEXT_INVALID")
        self._validate_build_context(context_archive, dockerfile_path)
        image_tag = self.runtime_image_tag(labels)
        command = (
            *self._build_command_prefix(),
            "--quiet",
            *self._build_output_args(),
            "--pull=false",
            "--network",
            "none",
            *self._build_limit_args(spec),
            *self._label_args(labels),
            "--tag",
            image_tag,
            "--file",
            dockerfile_path,
            "-",
        )
        try:
            outcome = await self._run(
                command,
                timeout_ms=timeout_ms,
                input_bytes=context_archive,
            )
            self._require_success("DOCKER_BUILD_FAILED", outcome)
            digest = (
                outcome.stdout.decode("ascii", errors="strict").strip().splitlines()[-1]
            )
            if not _IMAGE_DIGEST.fullmatch(digest):
                raise DockerOperationError("DOCKER_IMAGE_DIGEST_INVALID", outcome)
            return digest
        except BaseException as failure:
            await self._compensate_failed_build(image_tag, labels, failure)
            raise

    def _build_limit_args(self, spec: SandboxRunSpec) -> tuple[str, ...]:
        limits = (
            spec.cpu_limit_millicores,
            spec.memory_limit_bytes,
            spec.pid_limit,
            spec.disk_limit_bytes,
        )
        if any(value <= 0 for value in limits):
            raise ValueError("DOCKER_BUILD_RESOURCE_LIMIT_INVALID")
        if self._target is None or not _REQUIRED_BUILD_LIMITS <= set(
            self._target.enforced_build_limits
        ):
            raise DockerOperationError("DOCKER_BUILD_LIMITS_UNVERIFIED")
        if (
            self._target.external_build_disk_limit_bytes <= 0
            or self._target.external_build_disk_limit_bytes > spec.disk_limit_bytes
        ):
            raise DockerOperationError("DOCKER_BUILD_DISK_LIMIT_UNVERIFIED")
        if self._target.build_backend == "BUILDX_RESOURCE":
            return (
                "--resource",
                "cpu-period=100000",
                "--resource",
                f"cpu-quota={spec.cpu_limit_millicores * 100}",
                "--resource",
                f"memory={spec.memory_limit_bytes}",
                "--ulimit",
                f"nproc={spec.pid_limit}:{spec.pid_limit}",
            )
        if self._target.build_backend == "LEGACY_LIMITED":
            return (
                "--cpu-period",
                "100000",
                "--cpu-quota",
                str(spec.cpu_limit_millicores * 100),
                "--memory",
                str(spec.memory_limit_bytes),
                "--ulimit",
                f"nproc={spec.pid_limit}:{spec.pid_limit}",
            )
        raise DockerOperationError("DOCKER_BUILD_BACKEND_UNSUPPORTED")

    def _build_command_prefix(self) -> tuple[str, ...]:
        if self._target is None:
            raise DockerOperationError("DOCKER_BUILD_LIMITS_UNVERIFIED")
        if self._target.build_backend == "BUILDX_RESOURCE":
            return ("buildx", "build")
        if self._target.build_backend == "LEGACY_LIMITED":
            return ("image", "build")
        raise DockerOperationError("DOCKER_BUILD_BACKEND_UNSUPPORTED")

    def _build_output_args(self) -> tuple[str, ...]:
        if self._target is None:
            raise DockerOperationError("DOCKER_BUILD_LIMITS_UNVERIFIED")
        if self._target.build_backend == "BUILDX_RESOURCE":
            return ("--load",)
        if self._target.build_backend == "LEGACY_LIMITED":
            return ()
        raise DockerOperationError("DOCKER_BUILD_BACKEND_UNSUPPORTED")

    @staticmethod
    def _validate_build_context(context_archive: bytes, dockerfile_path: str) -> None:
        if len(context_archive) > _MAX_BUILD_CONTEXT_BYTES + 1024 * 1024:
            raise ValueError("DOCKER_BUILD_CONTEXT_INVALID")
        try:
            with tarfile.open(
                fileobj=io.BytesIO(context_archive), mode="r:"
            ) as archive:
                members = archive.getmembers()
                names = [item.name for item in members]
                if (
                    len(members) > 100_000
                    or len(names) != len(set(names))
                    or dockerfile_path not in names
                    or sum(item.size for item in members) > _MAX_BUILD_CONTEXT_BYTES
                ):
                    raise ValueError
                for item in members:
                    normalized = item.name.replace("\\", "/")
                    parts = normalized.split("/")
                    if (
                        not item.isfile()
                        or normalized.startswith("/")
                        or re.match(r"^[A-Za-z]:", normalized)
                        or any(part in {"", ".", ".."} for part in parts)
                    ):
                        raise ValueError
        except (tarfile.TarError, ValueError) as error:
            raise ValueError("DOCKER_BUILD_CONTEXT_INVALID") from error

    async def inspect_image(self, image: str, *, timeout_ms: int) -> str:
        if (
            not image
            or timeout_ms <= 0
            or any(character in image for character in "\r\n\0")
        ):
            raise ValueError("DOCKER_IMAGE_REFERENCE_INVALID")
        outcome = await self._run(
            ("image", "inspect", "--format", "{{json .RepoDigests}}", image),
            timeout_ms=timeout_ms,
        )
        self._require_success("DOCKER_IMAGE_INSPECT_FAILED", outcome)
        try:
            repo_digests = json.loads(outcome.stdout.decode("ascii", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise DockerOperationError(
                "DOCKER_IMAGE_DIGEST_INVALID", outcome
            ) from error
        repository = self._image_repository(image)
        matching_digests = (
            {
                digest
                for item in repo_digests
                if isinstance(item, str)
                for candidate, separator, digest in (item.rpartition("@"),)
                if separator
                and self._same_repository(repository, candidate)
                and _IMAGE_DIGEST.fullmatch(digest)
            }
            if isinstance(repo_digests, list)
            else set()
        )
        if len(matching_digests) != 1:
            raise DockerOperationError("DOCKER_IMAGE_DIGEST_INVALID", outcome)
        return matching_digests.pop()

    async def create(self, spec: SandboxRunSpec, labels: Mapping[str, str]) -> str:
        image_digest = spec.image_digest
        if not isinstance(image_digest, str) or not _IMAGE_DIGEST.fullmatch(
            image_digest
        ):
            raise ValueError("IMAGE_DIGEST_REQUIRED")
        if spec.network_mode != "DEFAULT_DENY" or spec.network_targets:
            raise ValueError("DOCKER_NETWORK_BOUNDARY_INVALID")
        if spec.privileged or spec.pid_mode is not None or spec.ipc_mode is not None:
            raise ValueError("DOCKER_NAMESPACE_BOUNDARY_INVALID")
        if spec.capabilities or spec.secret_refs:
            raise ValueError("DOCKER_CAPABILITY_BOUNDARY_INVALID")
        if spec.user in {"0", "root"} or not spec.user:
            raise ValueError("NON_ROOT_USER_REQUIRED")
        if (spec.source_baked and spec.mounts) or (
            not spec.source_baked and not spec.mounts
        ):
            raise ValueError("DOCKER_MOUNT_BOUNDARY_INVALID")

        mount_args: list[str] = []
        for mount in spec.mounts:
            if mount.source is None or not mount.read_only:
                raise ValueError("READ_ONLY_MOUNT_REQUIRED")
            source = mount.source.resolve(strict=True)
            values = (str(source), str(mount.target))
            if any(any(char in value for char in ",\r\n\0") for value in values):
                raise ValueError("DOCKER_MOUNT_VALUE_INVALID")
            mount_args.extend(
                (
                    "--mount",
                    f"type=bind,src={source},dst={mount.target},readonly",
                )
            )

        name = self.runtime_container_name(labels)
        cpu = str(Decimal(spec.cpu_limit_millicores) / Decimal(1000))
        outcome = await self._run(
            (
                "create",
                "--name",
                name,
                "--network",
                "none",
                "--read-only",
                "--user",
                spec.user,
                "--security-opt",
                "no-new-privileges",
                "--cap-drop",
                "ALL",
                "--pids-limit",
                str(spec.pid_limit),
                "--cpus",
                cpu,
                "--memory",
                str(spec.memory_limit_bytes),
                "--tmpfs",
                (f"/tmp:rw,noexec,nosuid,nodev,size={spec.disk_limit_bytes},mode=1777"),
                *self._label_args(labels),
                *mount_args,
                image_digest,
                "sleep",
                "infinity",
            )
        )
        self._require_success("DOCKER_CREATE_FAILED", outcome)
        container_id = outcome.stdout.decode("ascii", errors="strict").strip()
        if not _RESOURCE_ID.fullmatch(container_id):
            raise DockerOperationError("DOCKER_CONTAINER_ID_INVALID", outcome)
        return container_id

    @staticmethod
    def _image_repository(image: str) -> str:
        repository = image.split("@", maxsplit=1)[0]
        last_slash = repository.rfind("/")
        last_colon = repository.rfind(":")
        return repository[:last_colon] if last_colon > last_slash else repository

    @staticmethod
    def _same_repository(left: str, right: str) -> bool:
        def normalized(value: str) -> str:
            if value.startswith("index.docker.io/"):
                value = value.removeprefix("index.docker.io/")
            elif value.startswith("docker.io/"):
                value = value.removeprefix("docker.io/")
            return value if "/" in value else f"library/{value}"

        return normalized(left) == normalized(right)

    async def start(self, container_id: str) -> None:
        self._require_resource_id(container_id)
        outcome = await self._run(("start", container_id))
        self._require_success("DOCKER_START_FAILED", outcome)

    async def verify_created_mounts(
        self, container_id: str, spec: SandboxRunSpec
    ) -> None:
        """Reject image-declared or otherwise unapproved mounts before start."""

        self._require_resource_id(container_id)
        outcome = await self._run(
            ("inspect", "--format", "{{json .Mounts}}", container_id)
        )
        self._require_success("DOCKER_MOUNT_INSPECT_FAILED", outcome)
        try:
            mounts = json.loads(outcome.stdout)
            if not isinstance(mounts, list):
                raise TypeError
            actual = []
            for item in mounts:
                if not isinstance(item, dict):
                    raise TypeError
                mount_type = item["Type"]
                destination = item["Destination"]
                writable = item["RW"]
                if (
                    not isinstance(mount_type, str)
                    or not isinstance(destination, str)
                    or not isinstance(writable, bool)
                ):
                    raise TypeError
                actual.append((mount_type, destination, writable))
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise DockerOperationError(
                "DOCKER_MOUNT_INSPECT_INVALID", outcome
            ) from error
        expected = [
            ("bind", str(mount.target), not mount.read_only) for mount in spec.mounts
        ]
        if sorted(actual) != sorted(expected):
            raise ValueError("DOCKER_MOUNT_BOUNDARY_INVALID")

    async def materialize_poc(
        self, container_id: str, content: bytes, content_digest: str
    ) -> str:
        """Stream verified candidate bytes into the container, never a host file."""
        self._require_resource_id(container_id)
        if hashlib.sha256(content).hexdigest() != content_digest:
            raise ValueError("POC_CONTENT_DIGEST_MISMATCH")
        cleared = await self._run(("exec", container_id, "rm", "-f", _POC_STAGING_PATH))
        self._require_success("DOCKER_POC_STAGING_CLEANUP_FAILED", cleared)
        written = await self._run(
            (
                "exec",
                "-i",
                container_id,
                "dd",
                f"of={_POC_STAGING_PATH}",
                "status=none",
            ),
            input_bytes=content,
        )
        self._require_success("DOCKER_POC_MATERIALIZATION_FAILED", written)
        verified = await self._run(
            ("exec", container_id, "sha256sum", _POC_STAGING_PATH)
        )
        self._require_success("DOCKER_POC_DIGEST_VERIFICATION_FAILED", verified)
        try:
            digest_output = verified.stdout.decode("ascii", errors="strict").split()
        except UnicodeDecodeError as error:
            raise DockerOperationError(
                "DOCKER_POC_DIGEST_MISMATCH", verified
            ) from error
        if digest_output not in (
            [content_digest, _POC_STAGING_PATH],
            [content_digest, "[REDACTED:HOST_ABSOLUTE_PATH]"],
        ):
            raise DockerOperationError("DOCKER_POC_DIGEST_MISMATCH", verified)
        protected = await self._run(
            ("exec", container_id, "chmod", "0444", _POC_STAGING_PATH)
        )
        self._require_success("DOCKER_POC_PERMISSION_FAILED", protected)
        replaced = await self._run(
            (
                "exec",
                container_id,
                "mv",
                "-f",
                _POC_STAGING_PATH,
                POC_RUNTIME_PATH,
            )
        )
        self._require_success("DOCKER_POC_REPLACE_FAILED", replaced)
        return POC_RUNTIME_PATH

    async def execute(
        self,
        container_id: str,
        argv: tuple[str, ...],
        timeout_ms: int,
        *,
        working_directory: str,
    ) -> DockerCommandOutcome:
        self._require_resource_id(container_id)
        if not argv or timeout_ms <= 0 or working_directory != "/workspace":
            raise ValueError("DOCKER_EXEC_INPUT_INVALID")
        if any(not item or any(char in item for char in "\r\n\0") for item in argv):
            raise ValueError("DOCKER_EXEC_ARGV_INVALID")
        return await self._run(
            ("exec", "--workdir", working_directory, container_id, *argv),
            timeout_ms=timeout_ms,
        )

    async def inspect(self, container_id: str) -> DockerContainerState:
        self._require_resource_id(container_id)
        outcome = await self._run(("inspect", container_id))
        self._require_success("DOCKER_INSPECT_FAILED", outcome)
        try:
            decoded = json.loads(outcome.stdout)
            item = decoded[0]
            if not isinstance(item, dict):
                raise TypeError
            config = item["Config"]
            host = item["HostConfig"]
            state = item["State"]
            if not all(isinstance(value, dict) for value in (config, host, state)):
                raise TypeError
            health = state.get("Health")
            labels = config.get("Labels") or {}
            if not isinstance(labels, dict) or not all(
                isinstance(key, str) and isinstance(value, str)
                for key, value in labels.items()
            ):
                raise TypeError
            health_status = health.get("Status") if isinstance(health, dict) else None
            return DockerContainerState(
                container_id=str(item["Id"]),
                image_digest=str(item["Image"]),
                user=str(config["User"]),
                network_mode=str(host["NetworkMode"]),
                privileged=bool(host["Privileged"]),
                read_only_rootfs=bool(host["ReadonlyRootfs"]),
                running=bool(state["Running"]),
                exit_code=int(state["ExitCode"]),
                health_status=(
                    str(health_status) if health_status is not None else None
                ),
                labels=dict(labels),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise DockerOperationError(
                "DOCKER_INSPECT_OUTPUT_INVALID", outcome
            ) from error

    async def remove(self, resource_ids: tuple[str, ...]) -> None:
        if not resource_ids:
            return
        if len(set(resource_ids)) != len(resource_ids):
            raise ValueError("DUPLICATE_DOCKER_RESOURCE")
        for resource_id in resource_ids:
            self._require_resource_id(resource_id)
        outcome = await self._run(
            ("rm", "--force", "--volumes", *resource_ids),
            timeout_ms=_CLEANUP_TIMEOUT_MS,
        )
        self._require_success("DOCKER_REMOVE_FAILED", outcome)

    async def inspect_owned_image(self, image_digest: str) -> DockerImageState:
        if not _IMAGE_DIGEST.fullmatch(image_digest):
            raise ValueError("DOCKER_IMAGE_DIGEST_INVALID")
        outcome = await self._run(("image", "inspect", image_digest))
        self._require_success("DOCKER_IMAGE_INSPECT_FAILED", outcome)
        try:
            values = json.loads(outcome.stdout)
            if not isinstance(values, list) or len(values) != 1:
                raise TypeError
            value = values[0]
            if not isinstance(value, dict) or value.get("Id") != image_digest:
                raise TypeError
            config = value["Config"]
            if not isinstance(config, dict):
                raise TypeError
            labels = config["Labels"]
            if not isinstance(labels, dict) or any(
                not isinstance(key, str) or not isinstance(label, str)
                for key, label in labels.items()
            ):
                raise TypeError
            owned_labels = {
                key: labels[key] for key in _CONTAINER_LABELS if key in labels
            }
            normalized = self._validated_labels(owned_labels)
            if normalized.get("sastsimi.resource-kind") != "image":
                raise TypeError
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise DockerOperationError(
                "DOCKER_IMAGE_INSPECT_OUTPUT_INVALID", outcome
            ) from error
        return DockerImageState(image_digest=image_digest, labels=normalized)

    async def remove_images(self, image_digests: tuple[str, ...]) -> None:
        if not image_digests:
            return
        if len(set(image_digests)) != len(image_digests) or any(
            not _IMAGE_DIGEST.fullmatch(digest) for digest in image_digests
        ):
            raise ValueError("DOCKER_IMAGE_DIGEST_INVALID")
        outcome = await self._run(
            ("image", "rm", *image_digests), timeout_ms=_CLEANUP_TIMEOUT_MS
        )
        self._require_success("DOCKER_IMAGE_REMOVE_FAILED", outcome)

    async def remove_image_tags(self, image_tags: tuple[str, ...]) -> None:
        if not image_tags:
            return
        if len(set(image_tags)) != len(image_tags) or any(
            not _OWNED_IMAGE_TAG.fullmatch(image_tag) for image_tag in image_tags
        ):
            raise ValueError("DOCKER_IMAGE_TAG_INVALID")
        outcome = await self._run(
            ("image", "rm", *image_tags), timeout_ms=_CLEANUP_TIMEOUT_MS
        )
        self._require_success("DOCKER_IMAGE_REMOVE_FAILED", outcome)

    async def inspect_image_tag(self, image_tag: str) -> DockerImageTagPresence:
        if not _OWNED_IMAGE_TAG.fullmatch(image_tag):
            raise ValueError("DOCKER_IMAGE_TAG_INVALID")
        listed = await self._run(
            ("image", "ls", "--quiet", "--no-trunc", image_tag),
            timeout_ms=_CLEANUP_TIMEOUT_MS,
        )
        if listed.timed_out or listed.exit_code != 0:
            return DockerImageTagPresence("UNKNOWN")
        try:
            identifiers = tuple(
                line
                for line in listed.stdout.decode("ascii", errors="strict").splitlines()
                if line
            )
        except UnicodeDecodeError:
            return DockerImageTagPresence("UNKNOWN")
        if not identifiers:
            return DockerImageTagPresence("ABSENT")
        if len(identifiers) != 1 or not _IMAGE_DIGEST.fullmatch(identifiers[0]):
            return DockerImageTagPresence("UNKNOWN")
        inspected = await self._run(
            ("image", "inspect", image_tag), timeout_ms=_CLEANUP_TIMEOUT_MS
        )
        if inspected.timed_out or inspected.exit_code != 0:
            return DockerImageTagPresence("UNKNOWN")
        try:
            state = self._parse_image_state(inspected, identifiers[0])
        except DockerOperationError:
            return DockerImageTagPresence("UNKNOWN")
        return DockerImageTagPresence("PRESENT", state)

    async def inspect_container_presence(
        self,
        container_id: str,
        *,
        by_name: bool = False,
    ) -> DockerContainerPresence:
        self._require_resource_id(container_id)
        filter_value = f"name=^/{container_id}$" if by_name else f"id={container_id}"
        listed = await self._run(
            (
                "container",
                "ls",
                "--all",
                "--quiet",
                "--no-trunc",
                "--filter",
                filter_value,
            ),
            timeout_ms=_CLEANUP_TIMEOUT_MS,
        )
        if listed.timed_out or listed.exit_code != 0:
            return DockerContainerPresence("UNKNOWN")
        try:
            identifiers = tuple(
                line
                for line in listed.stdout.decode("ascii", errors="strict").splitlines()
                if line
            )
        except UnicodeDecodeError:
            return DockerContainerPresence("UNKNOWN")
        if not identifiers:
            return DockerContainerPresence("ABSENT")
        if len(identifiers) != 1 or not _RESOURCE_ID.fullmatch(identifiers[0]):
            return DockerContainerPresence("UNKNOWN")
        try:
            state = await asyncio.wait_for(
                self.inspect(identifiers[0]), _CLEANUP_TIMEOUT_MS / 1000
            )
        except (TimeoutError, OSError, RuntimeError, ValueError):
            return DockerContainerPresence("UNKNOWN")
        return DockerContainerPresence("PRESENT", state)

    @staticmethod
    def runtime_image_tag(labels: Mapping[str, str]) -> str:
        normalized = DockerAdapter._validated_labels(labels)
        if (
            set(normalized) != _CONTAINER_LABELS
            or normalized.get("sastsimi.resource-kind") != "image"
        ):
            raise ValueError("DOCKER_IMAGE_OWNERSHIP_LABELS_REQUIRED")
        identity = "\0".join(f"{key}={normalized[key]}" for key in sorted(normalized))
        suffix = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]
        return f"sastsimi-attempt:{suffix}"

    @staticmethod
    def runtime_container_name(labels: Mapping[str, str]) -> str:
        normalized = DockerAdapter._validated_labels(labels)
        if (
            set(normalized) != _CONTAINER_LABELS
            or normalized.get("sastsimi.resource-kind") != "container"
        ):
            raise ValueError("DOCKER_CONTAINER_OWNERSHIP_LABELS_REQUIRED")
        identity = "\0".join(f"{key}={normalized[key]}" for key in sorted(normalized))
        return "sastsimi-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]

    @staticmethod
    def _validated_labels(labels: Mapping[str, str]) -> dict[str, str]:
        if frozenset(labels) not in {_REQUIRED_LABELS, _CONTAINER_LABELS}:
            raise ValueError("DOCKER_OWNERSHIP_LABELS_INVALID")
        normalized = dict(labels)
        if normalized.get("sastsimi.owner") != "reproduction-setup-automation":
            raise ValueError("DOCKER_OWNERSHIP_LABELS_INVALID")
        if any(not _LABEL_VALUE.fullmatch(value) for value in normalized.values()):
            raise ValueError("DOCKER_OWNERSHIP_LABELS_INVALID")
        if "sastsimi.resource-kind" in normalized and normalized[
            "sastsimi.resource-kind"
        ] not in {"container", "image"}:
            raise ValueError("DOCKER_RESOURCE_KIND_INVALID")
        return normalized

    @classmethod
    def _label_args(cls, labels: Mapping[str, str]) -> tuple[str, ...]:
        normalized = cls._validated_labels(labels)
        values: list[str] = []
        for key in sorted(normalized):
            values.extend(("--label", f"{key}={normalized[key]}"))
        return tuple(values)

    @staticmethod
    def _require_resource_id(resource_id: str) -> None:
        if not _RESOURCE_ID.fullmatch(resource_id):
            raise ValueError("DOCKER_RESOURCE_ID_INVALID")

    @staticmethod
    def _parse_image_state(
        outcome: DockerCommandOutcome,
        expected_digest: str,
    ) -> DockerImageState:
        try:
            values = json.loads(outcome.stdout)
            if not isinstance(values, list) or len(values) != 1:
                raise TypeError
            value = values[0]
            if not isinstance(value, dict) or value.get("Id") != expected_digest:
                raise TypeError
            config = value["Config"]
            if not isinstance(config, dict):
                raise TypeError
            labels = config["Labels"]
            if not isinstance(labels, dict) or any(
                not isinstance(key, str) or not isinstance(label, str)
                for key, label in labels.items()
            ):
                raise TypeError
            owned_labels = {
                key: labels[key] for key in _CONTAINER_LABELS if key in labels
            }
            normalized = DockerAdapter._validated_labels(owned_labels)
            if normalized.get("sastsimi.resource-kind") != "image":
                raise TypeError
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise DockerOperationError(
                "DOCKER_IMAGE_INSPECT_OUTPUT_INVALID", outcome
            ) from error
        return DockerImageState(image_digest=expected_digest, labels=normalized)

    async def _reconcile_image_tag(
        self,
        image_tag: str,
        labels: Mapping[str, str],
    ) -> Literal["ABSENT", "REMOVED", "UNKNOWN"]:
        presence = await self.inspect_image_tag(image_tag)
        if presence.status == "ABSENT":
            return "ABSENT"
        if presence.status != "PRESENT" or presence.state is None:
            return "UNKNOWN"
        if dict(presence.state.labels) != self._validated_labels(labels):
            return "UNKNOWN"
        await self.remove_image_tags((image_tag,))
        return "REMOVED"

    async def _compensate_failed_build(
        self,
        image_tag: str,
        labels: Mapping[str, str],
        failure: BaseException,
    ) -> None:
        cleanup = asyncio.create_task(
            asyncio.wait_for(
                self._reconcile_image_tag(image_tag, labels),
                _CLEANUP_TIMEOUT_MS / 1000,
            )
        )
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                continue
        try:
            if cleanup.result() == "UNKNOWN":
                raise DockerOperationError("DOCKER_CANCELLATION_CLEANUP_FAILED")
        except BaseException:
            failure.add_note("DOCKER_CANCELLATION_CLEANUP_FAILED")

    async def _run(
        self,
        argv: tuple[str, ...],
        *,
        timeout_ms: int | None = None,
        input_bytes: bytes | None = None,
    ) -> DockerCommandOutcome:
        executable, daemon_target = self._verified_target()
        environment = {
            name: os.environ[name] for name in _SAFE_DOCKER_ENV if name in os.environ
        }
        is_build = argv[:2] in {("image", "build"), ("buildx", "build")}
        if is_build and self._target is not None:
            if self._target.build_backend == "LEGACY_LIMITED":
                environment["DOCKER_BUILDKIT"] = "0"
            elif self._target.build_backend != "BUILDX_RESOURCE":
                raise DockerOperationError("DOCKER_BUILD_BACKEND_UNSUPPORTED")
        process = await asyncio.create_subprocess_exec(
            str(executable),
            "--host",
            daemon_target,
            *argv,
            stdin=(
                asyncio.subprocess.PIPE
                if input_bytes is not None
                else asyncio.subprocess.DEVNULL
            ),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=environment,
        )
        if process.stdout is None or process.stderr is None:
            await self._stop_process(process)
            raise DockerOperationError("DOCKER_OUTPUT_PIPE_MISSING")
        stdout_buffer = bytearray()
        stderr_buffer = bytearray()
        timed_out = False
        try:
            try:
                collection = self._collect_output(
                    process,
                    stdout_buffer,
                    stderr_buffer,
                    input_bytes=input_bytes,
                )
                if timeout_ms is None:
                    await collection
                else:
                    await asyncio.wait_for(collection, timeout_ms / 1000)
            except TimeoutError:
                timed_out = True
                await self._stop_process(process)
                await self._collect_output(
                    process,
                    stdout_buffer,
                    stderr_buffer,
                )
        except asyncio.CancelledError:
            await self._stop_process(process)
            raise
        except _DockerOutputLimitExceeded:
            await self._stop_process(process)
            raise DockerOperationError("DOCKER_OUTPUT_LIMIT_EXCEEDED") from None
        stdout = self._safe_output(bytes(stdout_buffer))
        stderr = self._safe_output(bytes(stderr_buffer))
        return DockerCommandOutcome(
            exit_code=process.returncode if process.returncode is not None else -1,
            stdout=stdout,
            stderr=stderr,
            timed_out=timed_out,
        )

    @staticmethod
    def _validate_target(target: TrustedDockerTarget) -> None:
        if (
            not target.executable.is_absolute()
            or target.executable.name.lower() not in {"docker", "docker.exe"}
            or target.executable.stem.lower() != target.subject_key.lower()
            or not re.fullmatch(r"[0-9a-f]{64}", target.subject_sha256)
            or not DockerAdapter._local_daemon_target(target.daemon_target)
            or target.build_backend not in {"BUILDX_RESOURCE", "LEGACY_LIMITED"}
            or target.external_build_disk_limit_bytes <= 0
            or not re.fullmatch(
                r"[0-9a-f]{64}", target.external_build_storage_identity_hash
            )
        ):
            raise ValueError("DOCKER_TRUSTED_TARGET_INVALID")

    @staticmethod
    def _local_daemon_target(target: str) -> bool:
        if target in {
            "unix:///var/run/docker.sock",
            "unix:///run/docker.sock",
            "npipe:////./pipe/docker_engine",
        }:
            return True
        return bool(re.fullmatch(r"unix:///run/user/[1-9][0-9]*/docker\.sock", target))

    def _verified_target(self) -> tuple[Path, str]:
        target = self._target
        resolver = self._resolver
        if target is None or resolver is None:
            raise ValueError("DOCKER_TRUSTED_TARGET_REQUIRED")
        resolver.require_current(target)
        self._validate_target(target)
        try:
            if target.executable.is_symlink():
                raise ValueError
            executable = target.executable.resolve(strict=True)
            if executable != target.executable or not executable.is_file():
                raise ValueError
            digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        except (OSError, ValueError) as error:
            raise ValueError("DOCKER_EXECUTABLE_CHANGED") from error
        if digest != target.subject_sha256:
            raise ValueError("DOCKER_EXECUTABLE_CHANGED")
        return executable, target.daemon_target

    @staticmethod
    async def _read_output(
        stream: asyncio.StreamReader,
        destination: bytearray,
    ) -> None:
        while True:
            remaining = _OUTPUT_LIMIT_BYTES + 1 - len(destination)
            if remaining <= 0:
                raise _DockerOutputLimitExceeded
            chunk = await stream.read(min(_OUTPUT_READ_BYTES, remaining))
            if not chunk:
                return
            destination.extend(chunk)
            if len(destination) > _OUTPUT_LIMIT_BYTES:
                raise _DockerOutputLimitExceeded

    @classmethod
    async def _collect_output(
        cls,
        process: asyncio.subprocess.Process,
        stdout: bytearray,
        stderr: bytearray,
        *,
        input_bytes: bytes | None = None,
    ) -> None:
        if process.stdout is None or process.stderr is None:
            raise DockerOperationError("DOCKER_OUTPUT_PIPE_MISSING")
        tasks = (
            asyncio.create_task(cls._read_output(process.stdout, stdout)),
            asyncio.create_task(cls._read_output(process.stderr, stderr)),
            *(
                (asyncio.create_task(cls._write_input(process, input_bytes)),)
                if input_bytes is not None
                else ()
            ),
            asyncio.create_task(process.wait()),
        )
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    @staticmethod
    async def _write_input(
        process: asyncio.subprocess.Process, input_bytes: bytes
    ) -> None:
        if process.stdin is None:
            raise DockerOperationError("DOCKER_INPUT_PIPE_MISSING")
        process.stdin.write(input_bytes)
        await process.stdin.drain()
        process.stdin.close()
        await process.stdin.wait_closed()

    @staticmethod
    async def _stop_process(process: asyncio.subprocess.Process) -> None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.wait()

    @staticmethod
    def _safe_output(value: bytes) -> bytes:
        return redact_untrusted_text(value).data

    @staticmethod
    def _require_success(code: str, outcome: DockerCommandOutcome) -> None:
        if outcome.timed_out or outcome.exit_code != 0:
            raise DockerOperationError(code, outcome)
