"""Shell-free Docker CLI boundary for the local reproduction Sandbox."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path

from sastsimi.contracts.dynamic import POC_RUNTIME_PATH

from .controller import SandboxRunSpec

_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
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


class DockerOperationError(RuntimeError):
    """Safe Docker failure; raw process output is available only after redaction."""

    def __init__(self, code: str, outcome: DockerCommandOutcome | None = None) -> None:
        super().__init__(code)
        self.code = code
        self.outcome = outcome


class DockerAdapter:
    """Invoke a fixed Docker executable using argv, never a command shell."""

    def __init__(self, executable: str = "docker") -> None:
        executable_name = Path(executable).name.lower()
        if executable_name not in {"docker", "docker.exe"} or (
            executable != executable_name and not Path(executable).is_absolute()
        ):
            raise ValueError("DOCKER_EXECUTABLE_NOT_FIXED")
        self._executable = executable

    async def build(
        self,
        dockerfile: bytes,
        labels: Mapping[str, str],
        *,
        timeout_ms: int,
    ) -> str:
        if not dockerfile or timeout_ms <= 0:
            raise ValueError("DOCKER_BUILD_INPUT_INVALID")
        label_args = self._label_args(labels)
        outcome = await self._run(
            (
                "build",
                "--quiet",
                "--pull=false",
                "--network",
                "none",
                *label_args,
                "-",
            ),
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

    async def materialize_poc(
        self, container_id: str, content: bytes, content_digest: str
    ) -> str:
        """Stream verified candidate bytes into the container, never a host file."""
        self._require_resource_id(container_id)
        if hashlib.sha256(content).hexdigest() != content_digest:
            raise ValueError("POC_CONTENT_DIGEST_MISMATCH")
        written = await self._run(
            (
                "exec",
                "-i",
                container_id,
                "dd",
                f"of={POC_RUNTIME_PATH}",
                "status=none",
            ),
            input_bytes=content,
        )
        self._require_success("DOCKER_POC_MATERIALIZATION_FAILED", written)
        verified = await self._run(
            ("exec", container_id, "sha256sum", POC_RUNTIME_PATH)
        )
        self._require_success("DOCKER_POC_DIGEST_VERIFICATION_FAILED", verified)
        try:
            digest_output = verified.stdout.decode("ascii", errors="strict").split()
        except UnicodeDecodeError as error:
            raise DockerOperationError(
                "DOCKER_POC_DIGEST_MISMATCH", verified
            ) from error
        if digest_output != [content_digest, POC_RUNTIME_PATH]:
            raise DockerOperationError("DOCKER_POC_DIGEST_MISMATCH", verified)
        protected = await self._run(
            ("exec", container_id, "chmod", "0444", POC_RUNTIME_PATH)
        )
        self._require_success("DOCKER_POC_PERMISSION_FAILED", protected)
        return POC_RUNTIME_PATH

    async def exec(
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
        outcome = await self._run(("rm", "--force", *resource_ids))
        self._require_success("DOCKER_REMOVE_FAILED", outcome)

    @staticmethod
    def runtime_container_name(labels: Mapping[str, str]) -> str:
        normalized = DockerAdapter._validated_labels(labels)
        if set(normalized) != _CONTAINER_LABELS:
            raise ValueError("DOCKER_CONTAINER_OWNERSHIP_LABELS_REQUIRED")
        identity = "\0".join(f"{key}={normalized[key]}" for key in sorted(normalized))
        return "sastsimi-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:32]

    @staticmethod
    def _validated_labels(labels: Mapping[str, str]) -> dict[str, str]:
        if set(labels) != _REQUIRED_LABELS and set(labels) != _CONTAINER_LABELS:
            raise ValueError("DOCKER_OWNERSHIP_LABELS_INVALID")
        normalized = dict(labels)
        if normalized.get("sastsimi.owner") != "reproduction-setup-automation":
            raise ValueError("DOCKER_OWNERSHIP_LABELS_INVALID")
        if any(not _LABEL_VALUE.fullmatch(value) for value in normalized.values()):
            raise ValueError("DOCKER_OWNERSHIP_LABELS_INVALID")
        if (
            "sastsimi.resource-kind" in normalized
            and normalized["sastsimi.resource-kind"] != "container"
        ):
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

    async def _run(
        self,
        argv: tuple[str, ...],
        *,
        timeout_ms: int | None = None,
        input_bytes: bytes | None = None,
    ) -> DockerCommandOutcome:
        process = await asyncio.create_subprocess_exec(
            self._executable,
            *argv,
            stdin=(
                asyncio.subprocess.PIPE
                if input_bytes is not None
                else asyncio.subprocess.DEVNULL
            ),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
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
        text = value.decode("utf-8", errors="replace")
        text = re.sub(
            r"(?i)\b(bearer|basic)\s+\S+",
            r"\1 [REDACTED]",
            text,
        )
        text = re.sub(
            r"(?i)\b(password|token|cookie|authorization|api[_-]?key)\s*[:=]\s*\S+",
            r"\1=[REDACTED]",
            text,
        )
        return text.encode("utf-8")

    @staticmethod
    def _require_success(code: str, outcome: DockerCommandOutcome) -> None:
        if outcome.timed_out or outcome.exit_code != 0:
            raise DockerOperationError(code, outcome)
