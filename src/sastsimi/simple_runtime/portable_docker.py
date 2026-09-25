"""Small cross-platform Docker CLI path for the local SimpleRuntime."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shlex
import socket
from collections.abc import Mapping, Sequence
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
_MAX_OUTPUT = 1024 * 1024
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


class PortableDockerRuntime:
    """Use Docker Desktop or Engine defaults without WSL-specific paths."""

    def __init__(self, profile: SimpleExecutionProfile) -> None:
        try:
            self._executable = profile.tools["docker"].executable_path
        except KeyError:
            raise ValueError("DOCKER_NOT_CONFIGURED") from None
        self._network = "default" if profile.docker_network == "BRIDGE" else "none"
        self._timeout = max(30, profile.max_elapsed_seconds)
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
    ) -> str:
        gate = getattr(self, "_build_slots", None)
        if gate is None:
            return await self._build_or_reuse(
                workspace=workspace,
                dockerfile=dockerfile,
                cache_key=cache_key,
                labels=labels,
            )
        async with gate:
            return await self._build_or_reuse(
                workspace=workspace,
                dockerfile=dockerfile,
                cache_key=cache_key,
                labels=labels,
            )

    async def _build_or_reuse(
        self,
        *,
        workspace: Path,
        dockerfile: bytes,
        cache_key: str,
        labels: Mapping[str, str],
    ) -> str:
        tag = f"sastsimi-simple:{hashlib.sha256(cache_key.encode()).hexdigest()[:24]}"
        inspected = await self._run(
            ("image", "inspect", "--format", "{{.Id}}", tag),
            timeout_seconds=30,
        )
        if inspected.exit_code == 0:
            return self._image_digest(inspected.stdout)
        args: list[str] = [
            "build",
            "--quiet",
            "--pull=false",
            "--network",
            self._network,
        ]
        for key, value in sorted(labels.items()):
            args.extend(("--label", f"{key}={value}"))
        args.extend(("--tag", tag, "--file", "-", str(workspace)))
        built = await self._run(
            tuple(args),
            input_bytes=dockerfile,
            timeout_seconds=self._timeout,
        )
        self._require_success("DOCKER_BUILD_FAILED", built)
        inspected = await self._run(
            ("image", "inspect", "--format", "{{.Id}}", tag),
            timeout_seconds=30,
        )
        self._require_success("DOCKER_IMAGE_INSPECT_FAILED", inspected)
        return self._image_digest(inspected.stdout)

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
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(input_bytes),
                timeout=timeout_seconds,
            )
            return DockerCommandOutcome(
                exit_code=process.returncode or 0,
                stdout=stdout[:_MAX_OUTPUT],
                stderr=stderr[:_MAX_OUTPUT],
                timed_out=False,
            )
        except TimeoutError:
            process.kill()
            stdout, stderr = await process.communicate()
            return DockerCommandOutcome(
                exit_code=-1,
                stdout=stdout[:_MAX_OUTPUT],
                stderr=stderr[:_MAX_OUTPUT],
                timed_out=True,
            )
        except asyncio.CancelledError:
            process.kill()
            await process.communicate()
            raise

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
        target_requirements = self._target_requirements_path(prior)
        target_install = self._target_install_layer(target_requirements)
        dockerfile_path = self._workspace / "Dockerfile"
        if dockerfile_path.is_file():
            dockerfile = self._portable_repository_dockerfile(
                dockerfile_path.read_bytes()
            ) + (
                b"\nUSER root\nWORKDIR /workspace\nCOPY . /workspace\n"
                + target_install
                + b"RUN chmod -R a+rX /workspace && mkdir -p /tmp "
                b"&& chmod 1777 /tmp\n"
            )
            source = "REPOSITORY_DOCKERFILE"
        else:
            dockerfile = self._generated_dockerfile(target_requirements)
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
                if not degraded and self._dependency_install_failed(error, dockerfile):
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
                        target_requirements,
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
                    target_requirements,
                    requirements,
                    attempt_refs,
                    degraded,
                    status="BUILT",
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
        target_requirements: str | None,
        requirements: tuple[str, ...],
        attempt_refs: list[StoredDataRef],
        degraded: bool,
        *,
        status: str,
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
            "target_requirements_path": target_requirements,
            "requirements": requirements,
            "build_attempt_refs": [ref.model_dump(mode="json") for ref in attempt_refs],
            "degraded": degraded,
            "status": status,
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

    def _target_requirements_path(
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
                ):
                    continue
                try:
                    source = (root / Path(*relative.parts)).resolve(strict=True)
                except OSError:
                    continue
                if not source.is_relative_to(root):
                    continue
                current = source.parent
                while current.is_relative_to(root):
                    candidate = current / "requirements.txt"
                    if candidate.is_file() and not candidate.is_symlink():
                        return candidate.relative_to(root).as_posix()
                    if current == root:
                        break
                    current = current.parent
        return None

    @staticmethod
    def _target_install_layer(requirements_path: str | None) -> bytes:
        if requirements_path in {None, "requirements.txt"}:
            return b""
        absolute = f"/workspace/{requirements_path}"
        return (
            f"RUN python -m pip install --no-cache-dir -r {shlex.quote(absolute)}\n"
        ).encode()

    def _generated_dockerfile(
        self,
        target_requirements: str | None = None,
        *,
        include_dependencies: bool = True,
    ) -> bytes:
        if not include_dependencies:
            install = ""
            target_requirements = None
        elif (self._workspace / "requirements.txt").is_file():
            install = "RUN pip install --no-cache-dir -r requirements.txt"
        elif (self._workspace / "pyproject.toml").is_file():
            install = "RUN pip install --no-cache-dir ."
        else:
            install = ""
        return (
            "FROM python:3.12-slim\n"
            "WORKDIR /workspace\n"
            "COPY . /workspace\n"
            f"{install}\n"
            f"{self._target_install_layer(target_requirements).decode('utf-8')}"
            "RUN chmod -R a+rX /workspace && mkdir -p /tmp && chmod 1777 /tmp\n"
            'CMD ["sleep", "infinity"]\n'
        ).encode()


__all__ = [
    "DirectEnvironmentPreparer",
    "PortableContainerFactory",
    "PortableDockerRuntime",
]
