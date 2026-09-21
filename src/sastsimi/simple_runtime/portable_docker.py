"""Small cross-platform Docker CLI path for the local SimpleRuntime."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shlex
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath

from sastsimi.config.user_config import SimpleExecutionProfile
from sastsimi.ports.docker_state import DockerContainerState
from sastsimi.sandbox.docker_adapter import (
    DockerCommandOutcome,
    DockerOperationError,
)

from .artifacts import SimpleArtifactRepository
from .models import SimpleStage, StageCheckpoint
from .stages import ReproductionEnvironment

_RESOURCE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_OUTPUT = 1024 * 1024


class PortableDockerRuntime:
    """Use Docker Desktop or Engine defaults without WSL-specific paths."""

    def __init__(self, profile: SimpleExecutionProfile) -> None:
        try:
            self._executable = profile.tools["docker"].executable_path
        except KeyError:
            raise ValueError("DOCKER_NOT_CONFIGURED") from None
        self._network = "default" if profile.docker_network == "BRIDGE" else "none"
        self._timeout = max(30, profile.max_elapsed_seconds)

    async def build_or_reuse(
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
        if _IMAGE_DIGEST.fullmatch(image_digest) is None:
            raise ValueError("IMAGE_DIGEST_REQUIRED")
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
        # An image that declares its own ENTRYPOINT would receive "sleep
        # infinity" as arguments instead of running it, so the container exits
        # at once and every later exec fails.  Replace the entrypoint outright.
        args.extend(("--entrypoint", "sleep", image_digest, "infinity"))
        created = await self._run(tuple(args), timeout_seconds=60)
        self._require_success("DOCKER_CREATE_FAILED", created)
        container_id = created.stdout.decode("ascii", errors="strict").strip()
        self._require_resource_id(container_id)
        await self._require_success_call("DOCKER_START_FAILED", ("start", container_id))
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
            ("exec", "-i", container_id, "sh", "-c", f"cat > {path}"),
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

    async def acquire(self, checkpoint: StageCheckpoint) -> str:
        if checkpoint.image_digest is None or checkpoint.attempt_id is None:
            raise ValueError("SIMPLE_DOCKER_CHECKPOINT_INCOMPLETE")
        identity = checkpoint.identity
        return await self._docker.create_container(
            checkpoint.image_digest,
            {
                "sastsimi.owner": "simple-runtime",
                "sastsimi.analysis-id": identity.analysis_id,
                "sastsimi.workspace-id": identity.workspace_id,
                "sastsimi.commit-id": identity.commit_id,
                "sastsimi.hypothesis-id": identity.hypothesis_id or "analysis",
                "sastsimi.attempt-id": checkpoint.attempt_id,
            },
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
        dockerfile_ref = self._artifacts.put_bytes(dockerfile, "text/x-dockerfile")
        recipe = {
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
        }
        recipe_ref = self._artifacts.put_json(recipe)
        image_digest = await self._docker.build_or_reuse(
            workspace=self._workspace,
            dockerfile=dockerfile,
            cache_key=(
                f"{checkpoint.identity.commit_id}:{dockerfile_ref.content_hash}"
            ),
            labels={
                "sastsimi.owner": "simple-runtime",
                "sastsimi.analysis-id": checkpoint.identity.analysis_id,
                "sastsimi.workspace-id": checkpoint.identity.workspace_id,
                "sastsimi.commit-id": checkpoint.identity.commit_id,
                "sastsimi.hypothesis-id": checkpoint.identity.hypothesis_id
                or "analysis",
                "sastsimi.attempt-id": checkpoint.attempt_id or "initial",
            },
        )
        return ReproductionEnvironment(recipe_ref, image_digest)

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
    ) -> bytes:
        if (self._workspace / "requirements.txt").is_file():
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
