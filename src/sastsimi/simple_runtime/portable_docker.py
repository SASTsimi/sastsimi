"""Small cross-platform Docker CLI path for the local SimpleRuntime."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import shlex
import socket
import tomllib
from collections.abc import Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import ClassVar

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
_OWNER = "sastsimi.owner=simple-runtime"
# Which process on which machine owns a container, so a later run can tell a
# container left by a dead run from one a live run is still using.
_HOST = socket.gethostname()


def _alive(pid: int) -> bool:
    if os.name == "nt":
        # Signal 0 terminates the process on Windows rather than probing it, so
        # there a container is kept rather than risk a live run's.
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


class PortableDockerRuntime:
    """Use Docker Desktop or Engine defaults without WSL-specific paths."""

    def __init__(self, profile: SimpleExecutionProfile) -> None:
        try:
            self._executable = profile.tools["docker"].executable_path
        except KeyError:
            raise ValueError("DOCKER_NOT_CONFIGURED") from None
        self._network = "default" if profile.docker_network == "BRIDGE" else "none"
        self._timeout = max(30, profile.max_elapsed_seconds)
        # A build was measured above two gigabytes, so it waits on its own gate;
        # a running container costs a few megabytes and is gated where it runs.
        self._builds = asyncio.Semaphore(profile.max_parallel_builds)

    async def build_or_reuse(
        self,
        *,
        workspace: Path,
        dockerfile: bytes,
        cache_key: str,
        labels: Mapping[str, str],
    ) -> str:
        tag = f"sastsimi-simple:{hashlib.sha256(cache_key.encode()).hexdigest()[:24]}"
        async with self._builds:
            return await self._build_or_reuse(tag, workspace, dockerfile, labels)

    async def _build_or_reuse(
        self,
        tag: str,
        workspace: Path,
        dockerfile: bytes,
        labels: Mapping[str, str],
    ) -> str:
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

    async def changes(self, container_id: str) -> tuple[str, ...] | None:
        """What the container changed in its file system, or None if unknown.

        Recorded before the container is removed, to learn whether returning
        to a failed reproduction ever needs more than its image and PoC.
        """

        self._require_resource_id(container_id)
        outcome = await self._run(("diff", container_id), timeout_seconds=60)
        if outcome.exit_code != 0:
            return None
        return tuple(outcome.stdout.decode("utf-8", errors="replace").splitlines())

    async def remove(self, container_ids: Sequence[str]) -> None:
        """Remove containers; a failure is left to the next run's sweep."""

        for container_id in container_ids:
            self._require_resource_id(container_id)
        if container_ids:
            await self._run(
                ("rm", "--force", "--volumes", *container_ids), timeout_seconds=60
            )

    async def sweep_orphans(self) -> tuple[str, ...]:
        """Remove this runtime's containers whose run is no longer alive.

        A run removes each container after its reproduction, but a killed
        process or a stopped machine skips that.
        """

        try:
            listed = await self._run(
                (
                    "ps",
                    "--all",
                    "--filter",
                    f"label={_OWNER}",
                    "--format",
                    '{{.ID}}\t{{.Label "sastsimi.host"}}'
                    '\t{{.Label "sastsimi.host-pid"}}',
                ),
                timeout_seconds=60,
            )
            if listed.exit_code != 0:
                return ()
            orphans: list[str] = []
            for line in listed.stdout.decode("utf-8", errors="replace").splitlines():
                container_id, host, pid = (line.split("\t") + ["", ""])[:3]
                if host and host != _HOST:
                    continue
                if pid.isdigit() and _alive(int(pid)):
                    continue
                orphans.append(container_id)
            await self.remove(orphans)
        except (DockerOperationError, OSError, ValueError):
            return ()
        return tuple(orphans)

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
                "sastsimi.host": _HOST,
                "sastsimi.host-pid": str(os.getpid()),
            },
        )

    async def changes(self, container_id: str) -> tuple[str, ...] | None:
        try:
            return await self._docker.changes(container_id)
        except (DockerOperationError, OSError, ValueError):
            return None

    async def release(self, container_id: str) -> None:
        try:
            await self._docker.remove((container_id,))
        except (DockerOperationError, OSError, ValueError):
            pass


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
        # Installing the repository is a convenience, not a requirement: the PoC
        # reads the checkout that is copied in either way.  A build backend can
        # need tooling a plain Python image does not carry - one repository here
        # needs npm to generate its own metadata - and a failure there would
        # otherwise block every hypothesis in the run.
        #
        # A repository's own Dockerfile can fail for a reason that has nothing
        # to do with its Python dependencies - one pins Node 18 against a base
        # image too old for its glibc - while a plain Python image with those
        # dependencies installed would work fine.  Before giving up on
        # installing anything, a small ladder of Python versions is tried: the
        # version the repository states for itself first (its own Dockerfile,
        # pyproject.toml, or .python-version), then a fixed descending list.
        # Old pinned dependencies are frequently built against one exact range
        # - one target's urllib3 breaks on 3.10, its Pillow on 3.12 - and a
        # requirements file does not say which; installing is what finds out.
        installs = [
            self._generated_dockerfile(
                target_requirements, python_version=version, install=True
            )
            for version in self._install_attempt_versions()
        ]
        fallback = self._generated_dockerfile(target_requirements, install=False)
        image_digest, dockerfile, source = await self._built_image(
            checkpoint, dockerfile, source, installs, fallback
        )
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
        return ReproductionEnvironment(recipe_ref, image_digest)

    # A repository Dockerfile that cannot build here will not build for the next
    # hypothesis either, and some of them are very expensive to fail: one target
    # compiles a frontend and downloads gigabytes of model weights before giving
    # up.  Remember the exact file that failed so the run pays for it once.
    _unbuildable: ClassVar[set[str]] = set()

    async def _built_image(
        self,
        checkpoint: StageCheckpoint,
        dockerfile: bytes,
        source: str,
        installs: Sequence[bytes],
        fallback: bytes,
    ) -> tuple[str, bytes, str]:
        """Build the full environment, an installed fallback, or a bare one."""

        bare = "GENERATED_NO_INSTALL"
        candidates = [(dockerfile, source)]
        candidates.extend(
            (candidate, f"GENERATED_INSTALL_{index}")
            for index, candidate in enumerate(installs)
        )
        # The bare fallback never fails a build, so it is never cached as
        # unbuildable and always stays as the last resort.
        attempts = [
            (candidate, label)
            for candidate, label in candidates
            if hashlib.sha256(candidate).hexdigest() not in self._unbuildable
        ]
        attempts.append((fallback, bare))
        for candidate, label in attempts:
            try:
                digest = await self._build(checkpoint, candidate)
            except DockerOperationError as error:
                if error.code != "DOCKER_BUILD_FAILED" or label == bare:
                    raise
                self._unbuildable.add(hashlib.sha256(candidate).hexdigest())
                continue
            return digest, candidate, label
        raise DockerOperationError("DOCKER_BUILD_FAILED")

    async def _build(self, checkpoint: StageCheckpoint, dockerfile: bytes) -> str:
        reference = self._artifacts.put_bytes(dockerfile, "text/x-dockerfile")
        return await self._docker.build_or_reuse(
            workspace=self._workspace,
            dockerfile=dockerfile,
            cache_key=f"{checkpoint.identity.commit_id}:{reference.content_hash}",
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

    @staticmethod
    def _declares_a_package(pyproject: Path) -> bool:
        """Say whether this file configures a build, not just a workspace.

        A repository root may carry a ``pyproject.toml`` that only holds tool
        settings for a monorepo.  Installing that root makes setuptools guess
        at a flat layout and fail, so only a file declaring ``[project]`` or
        ``[build-system]`` counts as installable.
        """

        try:
            document = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError):
            return False
        return "project" in document or "build-system" in document

    def _installable_directory(self) -> str | None:
        """Return the one directory to install, or ``None`` when unclear.

        A build failure blocks every hypothesis in the run, so an ambiguous
        layout skips the install layer instead of guessing: the repository
        source is copied into the image either way.
        """

        if self._declares_a_package(self._workspace / "pyproject.toml"):
            return "."
        try:
            children = sorted(self._workspace.iterdir())
        except OSError:
            return None
        candidates = [
            child.name
            for child in children
            if child.is_dir()
            and not child.name.startswith(".")
            and self._declares_a_package(child / "pyproject.toml")
        ]
        return candidates[0] if len(candidates) == 1 else None

    def _generated_dockerfile(
        self,
        target_requirements: str | None = None,
        *,
        install: bool = True,
        python_version: str = "3.12",
    ) -> bytes:
        directory = self._installable_directory() if install else None
        if install and (self._workspace / "requirements.txt").is_file():
            install_layer = "RUN pip install --no-cache-dir -r requirements.txt"
        elif directory is not None:
            install_layer = f"RUN pip install --no-cache-dir {shlex.quote(directory)}"
        else:
            install_layer = ""
        # Old pinned dependencies frequently need a native build - a C
        # extension, a database driver - that a bare Python image has no
        # toolchain for.  Installed once, cheap when nothing needs it.
        build_tools = (
            "RUN apt-get update && apt-get install -y --no-install-recommends "
            "build-essential libpq-dev libjpeg-dev zlib1g-dev "
            "&& rm -rf /var/lib/apt/lists/*\n"
            if install_layer
            else ""
        )
        return (
            f"FROM python:{python_version}-slim\n"
            f"{build_tools}"
            "WORKDIR /workspace\n"
            "COPY . /workspace\n"
            f"{install_layer}\n"
            f"{self._target_install_layer(target_requirements).decode('utf-8')}"
            "RUN chmod -R a+rX /workspace && mkdir -p /tmp && chmod 1777 /tmp\n"
            'CMD ["sleep", "infinity"]\n'
        ).encode()

    # A repository rarely states an exact upper bound, and old pinned
    # dependencies often have one anyway - one target's urllib3 breaks on
    # 3.10, its Pillow on 3.12.  Building is what finds out; this only bounds
    # how many times it is tried before falling back to installing nothing.
    _PYTHON_VERSION_LADDER: ClassVar[tuple[str, ...]] = (
        "3.12",
        "3.11",
        "3.10",
        "3.9",
    )

    def _declared_python_version(self) -> str | None:
        """Return the Python version the repository states for itself, if any.

        Checked even when the file that states it could not be built here -
        a Dockerfile that fails on an unrelated step, such as a Node install
        against a base image too old for it, still names the right Python.
        """

        dockerfile_path = self._workspace / "Dockerfile"
        if dockerfile_path.is_file():
            try:
                text = dockerfile_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                text = ""
            match = re.search(r"(?im)^\s*FROM\s+python:(\d+\.\d+)", text)
            if match:
                return match.group(1)
        pyproject_path = self._workspace / "pyproject.toml"
        if pyproject_path.is_file():
            try:
                document = tomllib.loads(
                    pyproject_path.read_text(encoding="utf-8", errors="ignore")
                )
            except (OSError, tomllib.TOMLDecodeError):
                document = {}
            requires = document.get("project", {}).get("requires-python")
            if isinstance(requires, str):
                match = re.search(r"(\d+\.\d+)", requires)
                if match:
                    return match.group(1)
        version_file = self._workspace / ".python-version"
        if version_file.is_file():
            try:
                text = version_file.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                text = ""
            match = re.search(r"(\d+\.\d+)", text)
            if match:
                return match.group(1)
        return None

    def _install_attempt_versions(self) -> tuple[str, ...]:
        """Versions to try installing under, the repository's own stated one first."""

        declared = self._declared_python_version()
        ladder = self._PYTHON_VERSION_LADDER
        if declared is None or declared in ladder:
            return ladder
        return (declared, *ladder)


__all__ = [
    "DirectEnvironmentPreparer",
    "PortableContainerFactory",
    "PortableDockerRuntime",
]
