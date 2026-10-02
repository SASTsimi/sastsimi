"""Small cross-platform Docker CLI path for the local SimpleRuntime."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import re
import shlex
import socket
import stat
import subprocess
import tarfile
import tomllib
from collections.abc import Mapping, Sequence
from fnmatch import fnmatchcase
from pathlib import Path, PurePosixPath

from sastsimi.config.user_config import SimpleExecutionProfile
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.ports.docker_state import DockerContainerState
from sastsimi.sandbox.docker_adapter import (
    DockerCommandOutcome,
    DockerOperationError,
)

from .artifacts import SimpleArtifactRepository
from .models import CheckpointIdentity, SimpleStage, StageCheckpoint
from .recovery import (
    RecoveryAction,
    RecoveryDecision,
    validate_environment_patch,
)
from .stages import ReproductionEnvironment

_RESOURCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMMIT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_MAX_OUTPUT = 1024 * 1024
_MAX_PINNED_CONTEXT_BYTES = 64 * 1024 * 1024
_MAX_PINNED_FILES = 20_000
_DEPENDENCY_INSTALL = re.compile(
    rb"(?:pip3? install|python -m pip install|npm (?:ci|install)|"
    rb"apt-get install|yarn install|poetry install)",
    re.IGNORECASE,
)


class DockerBuildAttemptsError(DockerOperationError):
    def __init__(
        self,
        error: DockerOperationError,
        attempt_refs: tuple[StoredDataRef, ...],
        recipe_ref: StoredDataRef,
    ) -> None:
        super().__init__(error.code, error.outcome)
        self.attempt_refs = attempt_refs
        self.recipe_ref = recipe_ref


def build_pinned_context(
    workspace: Path,
    commit_id: str,
    dockerfile: bytes,
    wheels: Mapping[str, bytes],
    *,
    git_executable: str = "git",
) -> bytes:
    """Build a bounded Docker context from the exact, unchanged Git checkout."""

    if _COMMIT_ID.fullmatch(commit_id) is None:
        raise ValueError("PINNED_CONTEXT_UNAVAILABLE")
    root = workspace.resolve(strict=True)

    def git(*args: str) -> subprocess.CompletedProcess[bytes]:
        try:
            return subprocess.run(
                (git_executable, "-C", str(root), *args),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("PINNED_CONTEXT_UNAVAILABLE") from error

    def require_unchanged() -> None:
        diff = git("diff", "--quiet", "--no-ext-diff", "--no-textconv", commit_id, "--")
        if diff.returncode == 1:
            raise ValueError("PINNED_CONTEXT_CHANGED")
        if diff.returncode != 0:
            raise ValueError("PINNED_CONTEXT_UNAVAILABLE")

    listed = git("ls-tree", "-r", "-z", commit_id)
    if listed.returncode != 0 or len(listed.stdout) > 16 * 1024 * 1024:
        raise ValueError("PINNED_CONTEXT_UNAVAILABLE")
    entries = listed.stdout.split(b"\0")
    if len(entries) > _MAX_PINNED_FILES + 1:
        raise ValueError("PINNED_CONTEXT_TOO_LARGE")
    stream = io.BytesIO()
    names = {"dockerfile", ".dockerignore"}
    total_bytes = len(dockerfile)

    def add_member(archive: tarfile.TarFile, name: str, raw: bytes) -> None:
        nonlocal total_bytes
        total_bytes += len(raw)
        if total_bytes > _MAX_PINNED_CONTEXT_BYTES:
            raise ValueError("PINNED_CONTEXT_TOO_LARGE")
        info = tarfile.TarInfo(name)
        info.size = len(raw)
        info.mode = 0o644
        info.mtime = 0
        archive.addfile(info, io.BytesIO(raw))

    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as archive:
        add_member(archive, "Dockerfile", dockerfile)
        for entry in entries:
            if not entry:
                continue
            try:
                header, path_bytes = entry.split(b"\t", 1)
                mode, kind, object_id = header.split()
                name = path_bytes.decode("utf-8", errors="strict")
                parts = PurePosixPath(name).parts
            except (ValueError, UnicodeError) as error:
                raise ValueError("PINNED_CONTEXT_UNSAFE") from error
            if (
                not parts
                or name.startswith("/")
                or "\\" in name
                or ":" in name
                or any(part in {"", ".", ".."} for part in parts)
                or (
                    name.casefold() in names
                    and name not in {"Dockerfile", ".dockerignore"}
                )
                or name == "wheels"
                or name.startswith("wheels/")
            ):
                raise ValueError("PINNED_CONTEXT_UNSAFE")
            if mode not in {b"100644", b"100755"} or kind != b"blob":
                raise ValueError("PINNED_CONTEXT_UNSAFE")
            if name in {"Dockerfile", ".dockerignore"}:
                continue
            target = root.joinpath(*parts)
            try:
                target.resolve(strict=True).relative_to(root)
                if any(
                    parent.is_symlink()
                    for parent in target.parents
                    if parent != root and parent.is_relative_to(root)
                ):
                    raise ValueError("PINNED_CONTEXT_UNSAFE")
                before = target.lstat()
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_nlink != 1
                    or getattr(before, "st_file_attributes", 0) & 0x400
                ):
                    raise ValueError("PINNED_CONTEXT_UNSAFE")
            except OSError as error:
                raise ValueError("PINNED_CONTEXT_UNSAFE") from error
            object_name = object_id.decode("ascii", errors="strict")
            size = git("cat-file", "-s", object_name)
            if size.returncode != 0:
                raise ValueError("PINNED_CONTEXT_UNAVAILABLE")
            try:
                blob_size = int(size.stdout.strip())
            except ValueError as error:
                raise ValueError("PINNED_CONTEXT_UNAVAILABLE") from error
            if blob_size + total_bytes > _MAX_PINNED_CONTEXT_BYTES:
                raise ValueError("PINNED_CONTEXT_TOO_LARGE")
            content = git("cat-file", "blob", object_name)
            if content.returncode != 0 or len(content.stdout) != blob_size:
                raise ValueError("PINNED_CONTEXT_UNAVAILABLE")
            raw = content.stdout
            add_member(archive, name, raw)
            names.add(name.casefold())
        for name, raw in sorted(wheels.items()):
            if (
                not name
                or name != Path(name).name
                or "/" in name
                or "\\" in name
                or not name.endswith(".whl")
            ):
                raise ValueError("WHEEL_ARCHIVE_INVALID")
            add_member(archive, f"wheels/{name}", raw)
    require_unchanged()
    result = stream.getvalue()
    if len(result) > _MAX_PINNED_CONTEXT_BYTES:
        raise ValueError("PINNED_CONTEXT_TOO_LARGE")
    return result


class PortableDockerRuntime:
    """Use Docker Desktop or Engine defaults without WSL-specific paths."""

    def __init__(self, profile: SimpleExecutionProfile) -> None:
        try:
            self._executable = profile.tools["docker"].executable_path
        except KeyError:
            raise ValueError("DOCKER_NOT_CONFIGURED") from None
        self._network = "default" if profile.docker_network == "BRIDGE" else "none"
        configured_timeout = profile.max_elapsed_seconds
        self._timeout = max(
            30, 3600 if configured_timeout == "unlimited" else configured_timeout
        )
        self._build_slots = asyncio.Semaphore(profile.max_parallel_builds)
        self._container_slots = asyncio.Semaphore(profile.max_parallel_containers)
        self._container_limit = profile.max_parallel_containers

    async def build_or_reuse(
        self,
        *,
        workspace: Path,
        dockerfile: bytes,
        cache_key: str,
        labels: Mapping[str, str],
        context_archive: bytes | None = None,
    ) -> str:
        gate = getattr(self, "_build_slots", None)
        if gate is None:
            return await self._build_or_reuse(
                workspace=workspace,
                dockerfile=dockerfile,
                cache_key=cache_key,
                labels=labels,
                context_archive=context_archive,
            )
        async with gate:
            return await self._build_or_reuse(
                workspace=workspace,
                dockerfile=dockerfile,
                cache_key=cache_key,
                labels=labels,
                context_archive=context_archive,
            )

    async def _build_or_reuse(
        self,
        *,
        workspace: Path,
        dockerfile: bytes,
        cache_key: str,
        labels: Mapping[str, str],
        context_archive: bytes | None = None,
    ) -> str:
        if context_archive is not None:
            if self._network != "none":
                raise ValueError("POC_OFFLINE_NETWORK_REQUIRED")
            if len(context_archive) > _MAX_PINNED_CONTEXT_BYTES:
                raise ValueError("PINNED_CONTEXT_TOO_LARGE")
            cache_key += ":" + hashlib.sha256(context_archive).hexdigest()
        tag = f"sastsimi-simple:{hashlib.sha256(cache_key.encode()).hexdigest()[:24]}"
        inspected = await self._run(
            ("image", "inspect", "--format", "{{.Id}}", tag),
            timeout_seconds=30,
        )
        if inspected.exit_code == 0:
            return self._image_digest(inspected.stdout)
        args: list[str] = [
            "build",
            "--pull=false",
            "--network",
            self._network,
        ]
        for key, value in sorted(labels.items()):
            args.extend(("--label", f"{key}={value}"))
        args.extend(
            ("--tag", tag, "--file", "Dockerfile", "-")
            if context_archive is not None
            else ("--tag", tag, "--file", "-", str(workspace))
        )
        built = await self._run(
            tuple(args),
            input_bytes=context_archive if context_archive is not None else dockerfile,
            timeout_seconds=self._timeout,
        )
        self._require_success("DOCKER_BUILD_FAILED", built)
        inspected = await self._run(
            ("image", "inspect", "--format", "{{.Id}}", tag),
            timeout_seconds=30,
        )
        self._require_success("DOCKER_IMAGE_INSPECT_FAILED", inspected)
        return self._image_digest(inspected.stdout)

    async def target_wheel_tags(self, base_image: str) -> frozenset[str] | None:
        """Probe only an already-local Linux image, without network or mounts."""

        inspected = await self._run(
            (
                "image",
                "inspect",
                "--format",
                "{{.Os}}|{{.Architecture}}|{{.Id}}",
                base_image,
            ),
            timeout_seconds=30,
        )
        if inspected.exit_code != 0 or inspected.timed_out:
            return None
        try:
            os_name, _arch, image_id = (
                inspected.stdout.decode("ascii").strip().split("|")
            )
        except (UnicodeError, ValueError):
            return None
        if os_name != "linux" or _IMAGE_DIGEST.fullmatch(image_id) is None:
            return None
        probed = await self._run(
            (
                "run",
                "--pull",
                "never",
                "--rm",
                "--network",
                "none",
                "--read-only",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,size=16m",
                image_id,
                "python",
                "-c",
                "import json; from pip._vendor.packaging import tags; "
                "print(json.dumps([str(tag) for tag in tags.sys_tags()]))",
            ),
            timeout_seconds=60,
        )
        if probed.exit_code != 0 or probed.timed_out:
            return None
        try:
            parsed = json.loads(probed.stdout)
        except (UnicodeError, ValueError):
            return None
        if (
            not isinstance(parsed, list)
            or not parsed
            or len(parsed) > 20_000
            or any(not isinstance(tag, str) or len(tag) > 128 for tag in parsed)
        ):
            return None
        return frozenset(parsed)

    async def create_container(
        self,
        image_digest: str,
        labels: Mapping[str, str],
    ) -> str:
        gate = getattr(self, "_container_slots", None)
        if gate is None:
            return await self._create_container(image_digest, labels)
        async with gate:
            return await self._create_container(image_digest, labels)

    async def _create_container(
        self, image_digest: str, labels: Mapping[str, str]
    ) -> str:
        if _IMAGE_DIGEST.fullmatch(image_digest) is None:
            raise ValueError("IMAGE_DIGEST_REQUIRED")
        if labels.get("sastsimi.owner") == "simple-runtime":
            analysis_id = labels.get("sastsimi.analysis-id")
            if not analysis_id:
                raise ValueError("DOCKER_OWNER_LABELS_INCOMPLETE")
            active = await self._run(
                (
                    "ps",
                    "--quiet",
                    "--filter",
                    "label=sastsimi.owner=simple-runtime",
                    "--filter",
                    f"label=sastsimi.analysis-id={analysis_id}",
                    "--filter",
                    "status=running",
                ),
                timeout_seconds=30,
            )
            self._require_success("DOCKER_CONTAINER_COUNT_FAILED", active)
            if len(active.stdout) >= _MAX_OUTPUT:
                raise DockerOperationError("DOCKER_CONTAINER_COUNT_TRUNCATED")
            if len(active.stdout.splitlines()) >= getattr(self, "_container_limit", 1):
                raise DockerOperationError("DOCKER_CONTAINER_LIMIT_REACHED")
        args: list[str] = [
            "create",
            "--network",
            "none",
            "--user",
            "10001:10001",
            "--security-opt",
            "no-new-privileges",
            "--cap-drop",
            "ALL",
            "--pids-limit",
            "256",
            "--cpus",
            "2",
            "--memory",
            "2g",
            "--tmpfs",
            "/tmp:rw,nosuid,nodev,size=256m,mode=1777",
        ]
        for key, value in sorted(labels.items()):
            args.extend(("--label", f"{key}={value}"))
        args.extend((image_digest, "sleep", "infinity"))
        created = await self._run(tuple(args), timeout_seconds=60)
        self._require_success("DOCKER_CREATE_FAILED", created)
        container_id = created.stdout.decode("ascii", errors="strict").strip()
        self._require_resource_id(container_id)
        try:
            await self._require_success_call(
                "DOCKER_START_FAILED", ("start", container_id)
            )
        except (DockerOperationError, asyncio.CancelledError):
            if labels.get("sastsimi.owner") == "simple-runtime":
                try:
                    await self._remove_with_expected_labels(container_id, labels)
                except (DockerOperationError, OSError, ValueError):
                    pass
            raise
        return container_id

    async def materialize_poc(
        self,
        container_id: str,
        content: bytes,
        content_digest: str,
    ) -> str:
        self._require_resource_id(container_id)
        if hashlib.sha256(content).hexdigest() != content_digest:
            raise ValueError("POC_CONTENT_DIGEST_MISMATCH")
        path = "/tmp/sastsimi-poc-candidate"
        written = await self._run(
            (
                "exec",
                "-i",
                container_id,
                "sh",
                "-c",
                f"rm -f {path} && cat > {path}",
            ),
            input_bytes=content,
            timeout_seconds=30,
        )
        self._require_success("DOCKER_POC_MATERIALIZATION_FAILED", written)
        await self._require_success_call(
            "DOCKER_POC_PERMISSION_FAILED",
            ("exec", container_id, "chmod", "0500", path),
        )
        return path

    async def execute(
        self,
        container_id: str,
        argv: tuple[str, ...],
        timeout_ms: int,
        *,
        working_directory: str,
    ) -> DockerCommandOutcome:
        self._require_resource_id(container_id)
        if not argv or not working_directory.startswith("/"):
            raise ValueError("DOCKER_EXEC_INPUT_INVALID")
        return await self._run(
            ("exec", "--workdir", working_directory, container_id, *argv),
            timeout_seconds=max(1, timeout_ms // 1000),
        )

    async def inspect(self, container_id: str) -> DockerContainerState:
        self._require_resource_id(container_id)
        outcome = await self._run(("inspect", container_id), timeout_seconds=30)
        self._require_success("DOCKER_INSPECT_FAILED", outcome)
        try:
            item = json.loads(outcome.stdout)[0]
            config = item["Config"]
            host = item["HostConfig"]
            state = item["State"]
            labels = config.get("Labels") or {}
            return DockerContainerState(
                container_id=str(item["Id"]),
                image_digest=str(item["Image"]),
                user=str(config["User"]),
                network_mode=str(host["NetworkMode"]),
                privileged=bool(host["Privileged"]),
                read_only_rootfs=bool(host["ReadonlyRootfs"]),
                running=bool(state["Running"]),
                exit_code=int(state["ExitCode"]),
                health_status=None,
                labels={str(key): str(value) for key, value in labels.items()},
            )
        except (
            IndexError,
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as error:
            raise DockerOperationError(
                "DOCKER_INSPECT_OUTPUT_INVALID",
                outcome,
            ) from error

    @staticmethod
    def _owner_labels(identity: CheckpointIdentity, attempt_id: str) -> dict[str, str]:
        return {
            "sastsimi.owner": "simple-runtime",
            "sastsimi.analysis-id": identity.analysis_id,
            "sastsimi.workspace-id": identity.workspace_id,
            "sastsimi.commit-id": identity.commit_id,
            "sastsimi.hypothesis-id": identity.hypothesis_id or "analysis",
            "sastsimi.attempt-id": attempt_id,
        }

    async def remove_owned(
        self, container_id: str, identity: CheckpointIdentity, attempt_id: str
    ) -> bool:
        return await self._remove_with_expected_labels(
            container_id, self._owner_labels(identity, attempt_id)
        )

    async def _remove_with_expected_labels(
        self, container_id: str, expected: Mapping[str, str]
    ) -> bool:
        state = await self.inspect(container_id)
        if state.container_id != container_id or any(
            state.labels.get(key) != value for key, value in expected.items()
        ):
            return False
        removed = await self._run(("rm", "--force", container_id), timeout_seconds=30)
        self._require_success("DOCKER_OWNED_REMOVE_FAILED", removed)
        return True

    async def sweep_orphans(self) -> tuple[str, ...]:
        listed = await self._run(
            (
                "ps",
                "--all",
                "--quiet",
                "--filter",
                "label=sastsimi.owner=simple-runtime",
            ),
            timeout_seconds=30,
        )
        self._require_success("DOCKER_OWNED_LIST_FAILED", listed)
        if len(listed.stdout) >= _MAX_OUTPUT:
            raise DockerOperationError("DOCKER_OWNED_LIST_TRUNCATED")
        removed: list[str] = []
        for raw in listed.stdout.splitlines():
            container_id = raw.decode("ascii", errors="strict").strip()
            if _RESOURCE_ID.fullmatch(container_id) is None:
                continue
            try:
                state = await self.inspect(container_id)
            except DockerOperationError:
                continue
            labels = state.labels
            if (
                state.container_id != container_id
                or labels.get("sastsimi.owner") != "simple-runtime"
                or labels.get("sastsimi.host") != socket.gethostname()
            ):
                continue
            try:
                pid = int(labels["sastsimi.pid"])
                identity = CheckpointIdentity(
                    analysis_id=labels["sastsimi.analysis-id"],
                    workspace_id=labels["sastsimi.workspace-id"],
                    commit_id=labels["sastsimi.commit-id"],
                    hypothesis_id=(
                        None
                        if labels["sastsimi.hypothesis-id"] == "analysis"
                        else labels["sastsimi.hypothesis-id"]
                    ),
                )
                attempt_id = labels["sastsimi.attempt-id"]
            except (KeyError, TypeError, ValueError):
                continue
            if pid > 0 and self._pid_known_dead(pid):
                if await self.remove_owned(container_id, identity, attempt_id):
                    removed.append(container_id)
        return tuple(removed)

    @staticmethod
    def _pid_known_dead(pid: int, *, platform_name: str | None = None) -> bool:
        if (platform_name or os.name) != "posix" or pid <= 0:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return False
        return False

    async def _require_success_call(
        self,
        code: str,
        argv: Sequence[str],
    ) -> None:
        outcome = await self._run(tuple(argv), timeout_seconds=60)
        self._require_success(code, outcome)

    async def _run(
        self,
        args: Sequence[str],
        *,
        timeout_seconds: int,
        input_bytes: bytes | None = None,
    ) -> DockerCommandOutcome:
        process = await asyncio.create_subprocess_exec(
            str(self._executable),
            *args,
            stdin=(
                asyncio.subprocess.PIPE
                if input_bytes is not None
                else asyncio.subprocess.DEVNULL
            ),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=self._environment(),
        )
        assert process.stdout is not None
        assert process.stderr is not None
        stdout_tail = bytearray()
        stderr_tail = bytearray()
        tasks = [
            asyncio.create_task(self._read_output_tail(process.stdout, stdout_tail)),
            asyncio.create_task(self._read_output_tail(process.stderr, stderr_tail)),
            asyncio.create_task(process.wait()),
        ]
        if process.stdin is not None:
            assert input_bytes is not None
            tasks.append(
                asyncio.create_task(self._write_input(process.stdin, input_bytes))
            )
        try:
            _, pending = await asyncio.wait(tasks, timeout=timeout_seconds)
            if pending:
                if process.returncode is None:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                await asyncio.gather(*tasks, return_exceptions=True)
                return DockerCommandOutcome(
                    exit_code=-1,
                    stdout=bytes(stdout_tail),
                    stderr=bytes(stderr_tail),
                    timed_out=True,
                )
            await asyncio.gather(*tasks)
            return DockerCommandOutcome(
                exit_code=process.returncode or 0,
                stdout=bytes(stdout_tail),
                stderr=bytes(stderr_tail),
                timed_out=False,
            )
        except asyncio.CancelledError:
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            await asyncio.gather(*tasks, return_exceptions=True)
            raise

    @staticmethod
    async def _read_output_tail(stream: asyncio.StreamReader, tail: bytearray) -> None:
        while chunk := await stream.read(64 * 1024):
            if len(chunk) >= _MAX_OUTPUT:
                tail[:] = chunk[-_MAX_OUTPUT:]
            else:
                overflow = len(tail) + len(chunk) - _MAX_OUTPUT
                if overflow > 0:
                    del tail[:overflow]
                tail.extend(chunk)

    @staticmethod
    async def _write_input(stream: asyncio.StreamWriter, payload: bytes) -> None:
        try:
            for offset in range(0, len(payload), 64 * 1024):
                stream.write(payload[offset : offset + 64 * 1024])
                await stream.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            stream.close()
            try:
                await stream.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                pass

    @staticmethod
    def _environment() -> dict[str, str]:
        allowed = {
            "PATH",
            "PATHEXT",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "TMPDIR",
            "HOME",
            "USERPROFILE",
            "PROGRAMFILES",
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
        }
        return {key: value for key, value in os.environ.items() if key in allowed}

    @staticmethod
    def _require_success(code: str, outcome: DockerCommandOutcome) -> None:
        if outcome.timed_out or outcome.exit_code != 0:
            raise DockerOperationError(code, outcome)

    @staticmethod
    def _require_resource_id(value: str) -> None:
        if _RESOURCE_ID.fullmatch(value) is None:
            raise ValueError("DOCKER_RESOURCE_ID_INVALID")

    @staticmethod
    def _image_digest(raw: bytes) -> str:
        value = raw.decode("ascii", errors="strict").strip()
        if _IMAGE_DIGEST.fullmatch(value) is None:
            raise DockerOperationError("DOCKER_IMAGE_DIGEST_INVALID")
        return value


class PortableContainerFactory:
    def __init__(self, docker: PortableDockerRuntime) -> None:
        self._docker = docker
        self._swept = False

    async def acquire(self, checkpoint: StageCheckpoint) -> str:
        if checkpoint.image_digest is None or checkpoint.attempt_id is None:
            raise ValueError("SIMPLE_DOCKER_CHECKPOINT_INCOMPLETE")
        if not self._swept:
            await self._docker.sweep_orphans()
            self._swept = True
        identity = checkpoint.identity
        return await self._docker.create_container(
            checkpoint.image_digest,
            {
                **self._docker._owner_labels(identity, checkpoint.attempt_id),
                "sastsimi.host": socket.gethostname(),
                "sastsimi.pid": str(os.getpid()),
            },
        )

    async def release(self, checkpoint: StageCheckpoint, container_id: str) -> bool:
        if checkpoint.attempt_id is None:
            return False
        return await self._docker.remove_owned(
            container_id, checkpoint.identity, checkpoint.attempt_id
        )


class DirectEnvironmentPreparer:
    def __init__(
        self,
        *,
        docker: PortableDockerRuntime,
        artifacts: SimpleArtifactRepository,
        workspace: Path,
    ) -> None:
        self._docker = docker
        self._artifacts = artifacts
        self._workspace = workspace

    async def prepare(
        self,
        checkpoint: StageCheckpoint,
        prior: Mapping[SimpleStage, StageCheckpoint],
        requirements: tuple[str, ...],
    ) -> ReproductionEnvironment:
        target_manifest = self._target_manifest_path(prior)
        if (
            target_manifest is None
            and (self._workspace / "pyproject.toml").is_file()
            and self._target_install_layer("pyproject.toml")
        ):
            target_manifest = "pyproject.toml"
        target_install = self._target_install_layer(target_manifest)
        dockerfile_path = self._workspace / "Dockerfile"
        if dockerfile_path.is_file():
            git_install = (
                self._repository_git_install_layer()
                if target_install.startswith(
                    b"RUN python -m pip install --no-cache-dir uv\n"
                )
                else b""
            )
            dockerfile = self._portable_repository_dockerfile(
                dockerfile_path.read_bytes()
            ) + (
                b"\nUSER root\nWORKDIR /workspace\nCOPY . /workspace\n"
                + git_install
                + target_install
                + b"RUN chmod -R a+rX /workspace && mkdir -p /tmp "
                b"&& chmod 1777 /tmp\n"
            )
            source = "REPOSITORY_DOCKERFILE"
        else:
            dockerfile = self._generated_dockerfile(target_manifest)
            source = "GENERATED"
        dockerfile += self._recovery_patch(checkpoint)
        dockerfile_ref = self._artifacts.put_bytes(dockerfile, "text/x-dockerfile")
        labels = PortableDockerRuntime._owner_labels(
            checkpoint.identity, checkpoint.attempt_id or "initial"
        )
        attempt_refs: list[StoredDataRef] = []
        degraded = False
        while True:
            try:
                image_digest = await self._docker.build_or_reuse(
                    workspace=self._workspace,
                    dockerfile=dockerfile,
                    cache_key=(
                        f"{checkpoint.identity.commit_id}:{dockerfile_ref.content_hash}"
                    ),
                    labels=labels,
                )
            except DockerOperationError as error:
                attempt_refs.append(
                    self._build_attempt_ref(
                        checkpoint, source, dockerfile_ref, "FAILED", error
                    )
                )
                if (
                    not degraded
                    and not target_install
                    and target_manifest in {None, "requirements.txt", "pyproject.toml"}
                    and self._dependency_install_failed(error, dockerfile)
                ):
                    dockerfile = self._generated_dockerfile(include_dependencies=False)
                    dockerfile_ref = self._artifacts.put_bytes(
                        dockerfile, "text/x-dockerfile"
                    )
                    source = "GENERATED_NO_INSTALL"
                    degraded = True
                    continue
                recipe_ref = self._artifacts.put_json(
                    self._recipe(
                        checkpoint,
                        source,
                        dockerfile_ref,
                        target_manifest,
                        requirements,
                        attempt_refs,
                        degraded,
                        status="BLOCKED",
                    )
                )
                raise DockerBuildAttemptsError(
                    error, tuple(attempt_refs), recipe_ref
                ) from error
            attempt_refs.append(
                self._build_attempt_ref(
                    checkpoint, source, dockerfile_ref, "BUILT", None
                )
            )
            recipe_ref = self._artifacts.put_json(
                self._recipe(
                    checkpoint,
                    source,
                    dockerfile_ref,
                    target_manifest,
                    requirements,
                    attempt_refs,
                    degraded,
                    status="BUILT",
                    image_digest=image_digest,
                )
            )
            return ReproductionEnvironment(recipe_ref, image_digest)

    def _build_attempt_ref(
        self,
        checkpoint: StageCheckpoint,
        source: str,
        dockerfile_ref: StoredDataRef,
        status: str,
        error: DockerOperationError | None,
    ) -> StoredDataRef:
        stderr_ref = (
            self._artifacts.put_bytes(error.outcome.stderr, "text/plain")
            if error is not None and error.outcome is not None
            else None
        )
        stdout_ref = (
            self._artifacts.put_bytes(error.outcome.stdout, "text/plain")
            if error is not None and error.outcome is not None
            else None
        )
        return self._artifacts.put_json(
            {
                "kind": "simple_docker_build_attempt",
                "identity": checkpoint.identity.model_dump(mode="json"),
                "attempt_id": checkpoint.attempt_id,
                "dockerfile_source": source,
                "dockerfile_ref": dockerfile_ref.model_dump(mode="json"),
                "status": status,
                "error_code": error.code if error is not None else None,
                "stderr_ref": (
                    stderr_ref.model_dump(mode="json")
                    if stderr_ref is not None
                    else None
                ),
                "stdout_ref": (
                    stdout_ref.model_dump(mode="json")
                    if stdout_ref is not None
                    else None
                ),
                "timed_out": (
                    error.outcome.timed_out
                    if error is not None and error.outcome is not None
                    else False
                ),
            }
        )

    @staticmethod
    def _dependency_install_failed(
        error: DockerOperationError, dockerfile: bytes
    ) -> bool:
        return bool(
            error.code == "DOCKER_BUILD_FAILED"
            and error.outcome is not None
            and not error.outcome.timed_out
            and _DEPENDENCY_INSTALL.search(dockerfile)
            and _DEPENDENCY_INSTALL.search(
                error.outcome.stderr + b"\n" + error.outcome.stdout
            )
        )

    @staticmethod
    def _recipe(
        checkpoint: StageCheckpoint,
        source: str,
        dockerfile_ref: StoredDataRef,
        target_manifest: str | None,
        requirements: tuple[str, ...],
        attempt_refs: list[StoredDataRef],
        degraded: bool,
        *,
        status: str,
        image_digest: str | None = None,
    ) -> dict[str, object]:
        return {
            "kind": "simple_environment_recipe",
            "analysis_id": checkpoint.identity.analysis_id,
            "workspace_id": checkpoint.identity.workspace_id,
            "commit_id": checkpoint.identity.commit_id,
            "hypothesis_id": checkpoint.identity.hypothesis_id,
            "attempt_id": checkpoint.attempt_id,
            "dockerfile_source": source,
            "dockerfile_ref": dockerfile_ref.model_dump(mode="json"),
            "target_requirements_path": (
                target_manifest
                if target_manifest is not None
                and PurePosixPath(target_manifest).name == "requirements.txt"
                else None
            ),
            "target_manifest_path": target_manifest,
            "requirements": requirements,
            "build_attempt_refs": [ref.model_dump(mode="json") for ref in attempt_refs],
            "degraded": degraded,
            "status": status,
            **({"image_digest": image_digest} if image_digest is not None else {}),
        }

    def _recovery_patch(self, checkpoint: StageCheckpoint) -> bytes:
        for ref in reversed(checkpoint.input_refs):
            try:
                value = json.loads(self._artifacts.read(ref))
            except (OSError, UnicodeError, json.JSONDecodeError):
                continue
            if not isinstance(value, dict) or value.get("kind") != (
                "simple_recovery_decision"
            ):
                continue
            decision_identity = CheckpointIdentity.model_validate(value.get("identity"))
            if decision_identity != checkpoint.identity:
                raise ValueError("RECOVERY_DECISION_IDENTITY_MISMATCH")
            decision_value = value.get("decision")
            if not isinstance(decision_value, dict):
                raise ValueError("RECOVERY_DECISION_ARTIFACT_INVALID")
            decision = RecoveryDecision.model_validate_json(
                canonical_bytes(decision_value)
            )
            if decision.action is not RecoveryAction.REBUILD_ENVIRONMENT:
                continue
            patch = validate_environment_patch(decision.environment_patch)
            return (
                b"\n# SASTSIMI validated recovery patch\n"
                + patch.encode("utf-8")
                + b"\n"
            )
        return b""

    @staticmethod
    def _portable_repository_dockerfile(dockerfile: bytes) -> bytes:
        """Keep repository Dockerfiles usable after Debian Buster EOL.

        Some real repositories still pin a Buster-based image and exact
        package versions. Debian moved those package indexes to its archive,
        so an otherwise reproducible repository Dockerfile now fails before
        the target application is built. Insert the archive configuration in
        each affected stage while preserving the repository's own build.
        """

        if b"archive.debian.org/debian" in dockerfile:
            return dockerfile
        archive_setup = (
            b"RUN sed -i "
            b"-e 's|deb.debian.org/debian|archive.debian.org/debian|g' "
            b"-e 's|security.debian.org/debian-security|"
            b"archive.debian.org/debian-security|g' "
            b"-e '/buster-updates/d' /etc/apt/sources.list "
            b"&& printf 'Acquire::Check-Valid-Until \"false\";\\n' "
            b"> /etc/apt/apt.conf.d/99archive\n"
        )
        prepared: list[bytes] = []
        for line in dockerfile.splitlines(keepends=True):
            prepared.append(line)
            normalized = line.lstrip().lower()
            if normalized.startswith(b"from ") and b"buster" in normalized:
                prepared.append(archive_setup)
        return b"".join(prepared)

    @staticmethod
    def _repository_git_install_layer() -> bytes:
        """Install Git for uv on supported Linux bases, or fail the build."""

        return (
            b"RUN if ! command -v git >/dev/null 2>&1; then "
            b"if command -v apt-get >/dev/null 2>&1; then "
            b"apt-get update && apt-get install -y --no-install-recommends "
            b"git ca-certificates && rm -rf /var/lib/apt/lists/*; "
            b"elif command -v apk >/dev/null 2>&1; then "
            b"apk add --no-cache git ca-certificates; "
            b"elif command -v dnf >/dev/null 2>&1; then "
            b"dnf install -y git ca-certificates && dnf clean all; "
            b"elif command -v microdnf >/dev/null 2>&1; then "
            b"microdnf install -y git ca-certificates && microdnf clean all; "
            b"elif command -v yum >/dev/null 2>&1; then "
            b"yum install -y git ca-certificates && yum clean all; "
            b"else echo SASTSIMI_GIT_UNAVAILABLE: "
            b"no supported package manager >&2; exit 1; fi; fi\n"
        )

    def _target_manifest_path(
        self,
        prior: Mapping[SimpleStage, StageCheckpoint],
    ) -> str | None:
        pro_con = prior.get(SimpleStage.PRO_CON_DONE)
        if pro_con is None:
            return None
        root = self._workspace.resolve()
        for ref in pro_con.input_refs:
            try:
                value = json.loads(self._artifacts.read(ref))
            except (OSError, UnicodeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(value, dict) or value.get("kind") != (
                "simple_hypothesis_proposal"
            ):
                continue
            proposal = value.get("proposal")
            locations = (
                proposal.get("code_locations") if isinstance(proposal, dict) else None
            )
            if not isinstance(locations, list):
                continue
            for location in locations:
                if not isinstance(location, str):
                    continue
                relative_text, separator, line = location.rpartition(":")
                relative = PurePosixPath(relative_text)
                if (
                    separator != ":"
                    or not line.isdigit()
                    or relative.is_absolute()
                    or ".." in relative.parts
                    or "\\" in relative_text
                ):
                    continue
                candidate_source = root / Path(*relative.parts)
                if candidate_source.is_symlink() or any(
                    parent.is_symlink()
                    for parent in candidate_source.parents
                    if parent.is_relative_to(root)
                ):
                    continue
                try:
                    source = candidate_source.resolve(strict=True)
                except OSError:
                    continue
                if not source.is_relative_to(root):
                    continue
                if not source.is_file() or source.is_symlink():
                    continue
                current = source.parent
                while current.is_relative_to(root):
                    pyproject = current / "pyproject.toml"
                    prefer_uv = False
                    if (
                        (current / "requirements.txt").is_file()
                        and pyproject.is_file()
                        and not pyproject.is_symlink()
                    ):
                        try:
                            prefer_uv = (
                                self._uv_sync_target(
                                    current, self._read_project(pyproject)
                                )
                                is not None
                            )
                        except ValueError as error:
                            if str(error) != "TARGET_MANIFEST_INVALID":
                                raise
                    names = (
                        ("pyproject.toml", "requirements.txt")
                        if prefer_uv
                        else ("requirements.txt", "pyproject.toml")
                    )
                    for name in names:
                        candidate = current / name
                        if (
                            candidate.is_file()
                            and not candidate.is_symlink()
                            and candidate.resolve().is_relative_to(root)
                        ):
                            return candidate.relative_to(root).as_posix()
                    if current == root:
                        break
                    current = current.parent
        return None

    @staticmethod
    def _read_project(path: Path) -> dict[str, object]:
        try:
            return tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError):
            raise ValueError("TARGET_MANIFEST_INVALID") from None

    @staticmethod
    def _uv_config(project: Mapping[str, object]) -> Mapping[str, object]:
        tool = project.get("tool")
        uv = tool.get("uv") if isinstance(tool, dict) else None
        return uv if isinstance(uv, dict) else {}

    @staticmethod
    def _workspace_pattern_matches(relative: PurePosixPath, patterns: object) -> bool:
        if not isinstance(patterns, list):
            return False

        def matches(
            path_parts: tuple[str, ...], pattern_parts: tuple[str, ...]
        ) -> bool:
            if not pattern_parts:
                return not path_parts
            if pattern_parts[0] == "**":
                return (
                    matches(path_parts, pattern_parts[1:])
                    or bool(path_parts)
                    and matches(path_parts[1:], pattern_parts)
                )
            return (
                bool(path_parts)
                and fnmatchcase(path_parts[0], pattern_parts[0])
                and matches(path_parts[1:], pattern_parts[1:])
            )

        for pattern in patterns:
            if not isinstance(pattern, str) or any(
                char in pattern for char in "\r\n\x00\\:"
            ):
                continue
            parsed = PurePosixPath(pattern)
            if parsed.is_absolute() or ".." in parsed.parts:
                continue
            if matches(relative.parts, parsed.parts):
                return True
        return False

    def _uv_sync_target(
        self, project_dir: Path, project: Mapping[str, object]
    ) -> tuple[Path, str | None] | None:
        uv_config = self._uv_config(project)
        if isinstance(uv_config.get("workspace"), dict):
            return project_dir, None

        workspace = self._workspace.resolve()
        for parent in project_dir.parents:
            if not parent.is_relative_to(workspace):
                break
            manifest = parent / "pyproject.toml"
            if not manifest.is_file():
                continue
            if manifest.is_symlink() or not manifest.resolve().is_relative_to(
                workspace
            ):
                raise ValueError("TARGET_MANIFEST_PATH_UNSAFE")
            parent_uv = self._uv_config(self._read_project(manifest))
            workspace_config = parent_uv.get("workspace")
            if not isinstance(workspace_config, dict):
                continue
            relative = PurePosixPath(project_dir.relative_to(parent).as_posix())
            if self._workspace_pattern_matches(
                relative, workspace_config.get("members")
            ) and not self._workspace_pattern_matches(
                relative, workspace_config.get("exclude")
            ):
                metadata = project.get("project")
                name = metadata.get("name") if isinstance(metadata, dict) else None
                if not isinstance(name, str) or not name.strip():
                    raise ValueError("TARGET_MANIFEST_INVALID")
                return parent, name

        sources = uv_config.get("sources")
        if isinstance(sources, dict) and sources:
            return project_dir, None
        lock = project_dir / "uv.lock"
        if lock.is_symlink():
            raise ValueError("TARGET_LOCK_PATH_UNSAFE")
        if lock.is_file():
            return project_dir, None
        return None

    def _target_install_layer(self, manifest_path: str | None) -> bytes:
        if manifest_path is None or manifest_path == "requirements.txt":
            return b""
        if any(char in manifest_path for char in "\r\n\x00\\"):
            raise ValueError("TARGET_MANIFEST_PATH_UNSAFE")
        relative = PurePosixPath(manifest_path)
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("TARGET_MANIFEST_PATH_UNSAFE")
        host_path = self._workspace.joinpath(*relative.parts)
        root = self._workspace.resolve()
        if (
            not host_path.is_file()
            or host_path.is_symlink()
            or not host_path.resolve().is_relative_to(root)
            or any(
                parent.is_symlink()
                for parent in host_path.parents
                if parent.is_relative_to(root)
            )
        ):
            raise ValueError("TARGET_MANIFEST_PATH_UNSAFE")
        absolute = f"/workspace/{manifest_path}"
        if relative.name == "requirements.txt":
            return (
                f"RUN python -m pip install --no-cache-dir -r {shlex.quote(absolute)}\n"
            ).encode()
        if relative.name != "pyproject.toml":
            raise ValueError("TARGET_MANIFEST_UNSUPPORTED")
        project_dir = (
            "/workspace"
            if relative.parent == PurePosixPath(".")
            else f"/workspace/{relative.parent.as_posix()}"
        )
        source_path = (
            f"RUN ln -s {shlex.quote(project_dir)} /opt/sastsimi-target-source\n"
            'ENV PYTHONPATH="/opt/sastsimi-target-source:'
            '/opt/sastsimi-target-source/src:${PYTHONPATH}"\n'
        )
        uv_target = self._uv_sync_target(
            host_path.parent, self._read_project(host_path)
        )
        if uv_target is None:
            if manifest_path == "pyproject.toml":
                return b""
            return (
                "RUN python -m pip install --no-cache-dir "
                f"{shlex.quote(project_dir)}\n"
                f"{source_path}"
            ).encode()
        uv_root, member_name = uv_target
        lock = uv_root / "uv.lock"
        if lock.is_symlink():
            raise ValueError("TARGET_LOCK_PATH_UNSAFE")
        frozen = " --frozen" if lock.is_file() else ""
        uv_root_path = (
            "/workspace"
            if uv_root == root
            else f"/workspace/{uv_root.relative_to(root).as_posix()}"
        )
        member = f" --package {shlex.quote(member_name)}" if member_name else ""
        return (
            "RUN python -m pip install --no-cache-dir uv\n"
            f"RUN cd {shlex.quote(uv_root_path)} && uv sync{member}{frozen} "
            "--no-dev && "
            f"test -x {shlex.quote(uv_root_path + '/.venv/bin/python')} && "
            f"ln -s {shlex.quote(uv_root_path + '/.venv')} "
            "/opt/sastsimi-target-venv\n"
            "ENV VIRTUAL_ENV=/opt/sastsimi-target-venv\n"
            'ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"\n'
            f"{source_path}"
        ).encode()

    def _generated_dockerfile(
        self,
        target_manifest: str | None = None,
        *,
        include_dependencies: bool = True,
    ) -> bytes:
        if not include_dependencies:
            install = ""
            target_manifest = None
        target_install = self._target_install_layer(target_manifest)
        uses_uv = target_install.startswith(
            b"RUN python -m pip install --no-cache-dir uv\n"
        )
        if include_dependencies and uses_uv:
            install = ""
        elif include_dependencies and (self._workspace / "requirements.txt").is_file():
            install = "RUN pip install --no-cache-dir -r requirements.txt"
        elif include_dependencies and (self._workspace / "pyproject.toml").is_file():
            install = (
                ""
                if self._target_install_layer("pyproject.toml")
                else "RUN pip install --no-cache-dir ."
            )
        else:
            install = ""
        git_install = (
            "RUN apt-get update && apt-get install -y --no-install-recommends "
            "git ca-certificates && rm -rf /var/lib/apt/lists/*\n"
            if uses_uv
            else ""
        )
        return (
            "FROM python:3.12-slim\n"
            "WORKDIR /workspace\n"
            "COPY . /workspace\n"
            f"{install}\n"
            f"{git_install}"
            f"{target_install.decode('utf-8')}"
            "RUN chmod -R a+rX /workspace && mkdir -p /tmp && chmod 1777 /tmp\n"
            'CMD ["sleep", "infinity"]\n'
        ).encode()


__all__ = [
    "build_pinned_context",
    "DirectEnvironmentPreparer",
    "PortableContainerFactory",
    "PortableDockerRuntime",
]
