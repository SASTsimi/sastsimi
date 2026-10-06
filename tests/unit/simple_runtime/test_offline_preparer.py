"""Opt-in, networkless PoC dependency environment tests."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
import subprocess
import tarfile
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest
from pydantic import JsonValue

import sastsimi.simple_runtime.portable_docker as portable_docker
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.observability.agent_activity import ActivityKind
from sastsimi.sandbox.docker_adapter import DockerCommandOutcome, DockerOperationError
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.portable_docker import (
    DependencyBundleResolutionError,
    DirectEnvironmentPreparer,
    DockerBuildAttemptsError,
    PortableDockerRuntime,
    offline_recipe_cache_key,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.runner import StageBlocked, StageFailed
from sastsimi.simple_runtime.stages import (
    InitialVerificationStage,
    ReproductionEnvironment,
)


def _fixture(
    tmp_path: Path, manifest: str = "sample-pkg==1.0\n"
) -> tuple[Path, str, Path, str]:
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text("print('test')\n", encoding="utf-8")
    (workspace / "requirements.txt").write_text(manifest, encoding="utf-8")
    (workspace / "Dockerfile").write_text("FROM alpine\nRUN apt-get update\n")
    subprocess.run(("git", "init", "-q", str(workspace)), check=True)
    subprocess.run(("git", "-C", str(workspace), "add", "."), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ),
        check=True,
    )
    commit = (
        subprocess.check_output(("git", "-C", str(workspace), "rev-parse", "HEAD"))
        .decode("ascii")
        .strip()
    )
    wheel_stream = io.BytesIO()
    with zipfile.ZipFile(wheel_stream, "w") as wheel:
        wheel.writestr("sample_pkg/__init__.py", "")
        wheel.writestr(
            "sample_pkg-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\nTag: py3-none-any\n"
        )
        wheel.writestr(
            "sample_pkg-1.0.dist-info/METADATA",
            "Metadata-Version: 2.1\nName: sample-pkg\nVersion: 1.0\n",
        )
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as bundle:
        raw = wheel_stream.getvalue()
        info = tarfile.TarInfo("sample_pkg-1.0-py3-none-any.whl")
        info.size = len(raw)
        bundle.addfile(info, io.BytesIO(raw))
    path = tmp_path / "wheels.tar"
    path.write_bytes(stream.getvalue())
    return workspace, commit, path, hashlib.sha256(stream.getvalue()).hexdigest()


def _checkpoint(
    tmp_path: Path, commit: str
) -> tuple[SimpleArtifactRepository, StageCheckpoint]:
    identity = CheckpointIdentity(
        analysis_id="offline-test",
        workspace_id="offline-workspace",
        commit_id=commit,
        hypothesis_id="offline-hypothesis",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    inputs = ()
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        status=StageStatus.RUNNING,
        input_refs=inputs,
        input_hash=input_reference_hash(inputs),
        attempt_id="offline-attempt",
        attempt_number=1,
    )
    return artifacts, checkpoint


class _Docker:
    def __init__(self, failure: bytes | None = None) -> None:
        self._network = "none"
        self.failure = failure
        self.calls: list[tuple[bytes, str, bytes | None]] = []

    async def local_base_image_digest(self, base_image: str) -> str:
        assert base_image in {
            "python:3.12-slim",
            "sastsimi-offline-base:" + "b" * 64,
        }
        return "sha256:" + "b" * 64

    async def target_wheel_tags(self, base_image: str) -> frozenset[str]:
        assert base_image == "sha256:" + "b" * 64
        return frozenset({"py3-none-any"})

    async def pin_local_base(self, image_digest: str) -> str:
        assert image_digest == "sha256:" + "b" * 64
        return "sastsimi-offline-base:" + "b" * 64

    async def build_or_reuse(
        self,
        *,
        workspace: Path,
        dockerfile: bytes,
        cache_key: str,
        labels: Mapping[str, str],
        context_archive: bytes | None = None,
    ) -> str:
        del workspace, labels
        self.calls.append((dockerfile, cache_key, context_archive))
        if self.failure is not None:
            raise DockerOperationError(
                "DOCKER_BUILD_FAILED",
                DockerCommandOutcome(1, b"", self.failure, False),
            )
        return "sha256:" + "c" * 64


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "requirement",
    (
        "python:3.11-alpine",
        "python:alpine3.8",
        "python 3.11",
        "python\t3.11",
        "python3.11",
    ),
)
async def test_direct_preparer_rejects_unparsed_python_runtime(
    tmp_path: Path, requirement: str
) -> None:
    workspace, commit, _path, _digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    docker = _Docker()
    preparer = DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    )

    with pytest.raises(ValueError, match="POC_OFFLINE_PYTHON_RUNTIME_INVALID"):
        await preparer.prepare(checkpoint, {}, (requirement,))

    assert docker.calls == []


def test_python_runtime_parser_does_not_reject_package_names() -> None:
    assert (
        DirectEnvironmentPreparer._requested_python_runtime(
            ("python-dateutil==2.9.0", "pip:python-dotenv==1.0.0")
        )
        is None
    )


@pytest.mark.asyncio
async def test_offline_base_preflight_checks_and_pins_local_image(
    tmp_path: Path,
) -> None:
    workspace, commit, path, digest = _fixture(tmp_path)
    artifacts, _ = _checkpoint(tmp_path, commit)

    class _ObservedDocker(_Docker):
        def __init__(self) -> None:
            super().__init__()
            self.probes: list[tuple[str, str]] = []

        async def local_base_image_digest(self, base_image: str) -> str:
            self.probes.append(("inspect", base_image))
            return await super().local_base_image_digest(base_image)

        async def pin_local_base(self, image_digest: str) -> str:
            self.probes.append(("tag", image_digest))
            return await super().pin_local_base(image_digest)

    docker = _ObservedDocker()
    preparer = DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        wheel_bundle_path=path,
        wheel_bundle_sha256=digest,
    )

    assert await preparer.offline_base_ready() is True
    assert docker.probes == [
        ("inspect", "python:3.12-slim"),
        ("tag", "sha256:" + "b" * 64),
    ]


@pytest.mark.asyncio
async def test_configured_offline_base_is_pinned_and_changes_recipe_cache(
    tmp_path: Path,
) -> None:
    workspace, commit, path, wheel_digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    default_docker = _Docker()
    default_result = await DirectEnvironmentPreparer(
        docker=default_docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        wheel_bundle_path=path,
        wheel_bundle_sha256=wheel_digest,
    ).prepare(checkpoint, {}, ())

    selected_digest = "sha256:" + "d" * 64
    selected_reference = "sastsimi-offline-base:" + "d" * 64

    class _SelectedDocker(_Docker):
        def __init__(self) -> None:
            super().__init__()
            self.probes: list[str] = []

        async def local_base_image_digest(self, base_image: str) -> str:
            self.probes.append(base_image)
            assert base_image in {selected_digest, selected_reference}
            return selected_digest

        async def target_wheel_tags(self, base_image: str) -> frozenset[str]:
            assert base_image == selected_digest
            return frozenset({"py3-none-any"})

        async def pin_local_base(self, image_digest: str) -> str:
            assert image_digest == selected_digest
            return selected_reference

    docker = _SelectedDocker()
    preparer = DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        wheel_bundle_path=path,
        wheel_bundle_sha256=wheel_digest,
        offline_base_image_digest=selected_digest,
    )

    assert await preparer.offline_base_ready() is True
    result = await preparer.prepare(checkpoint, {}, ())

    assert docker.probes == [
        selected_digest,
        selected_digest,
        selected_reference,
        selected_digest,
        selected_reference,
    ]
    assert docker.calls[0][0].startswith(f"FROM {selected_reference}\n".encode("ascii"))
    assert docker.calls[0][1] != default_docker.calls[0][1]
    assert json.loads(artifacts.read(result.recipe_ref))["base_image_digest"] == (
        selected_digest
    )
    assert (
        json.loads(artifacts.read(default_result.recipe_ref))["base_image_digest"]
        == "sha256:" + "b" * 64
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("requested", ["3.6", "3.6.2"])
async def test_explicit_python_runtime_matches_only_a_probed_configured_digest(
    tmp_path: Path, requested: str
) -> None:
    workspace, commit, bundle_path, bundle_sha256 = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    selected_digest = "sha256:" + "d" * 64

    class _VersionedDocker(_Docker):
        def __init__(self) -> None:
            super().__init__()
            self.events: list[tuple[str, str]] = []

        async def local_base_image_digest(self, base_image: str) -> str:
            self.events.append(("inspect", base_image))
            assert base_image in {
                selected_digest,
                "sastsimi-offline-base:" + "d" * 64,
            }
            return selected_digest

        async def _probe_python_version(self, image_digest: str) -> str:
            self.events.append(("version", image_digest))
            assert image_digest == selected_digest
            return "3.6.2"

        async def target_wheel_tags(self, base_image: str) -> frozenset[str]:
            assert base_image == selected_digest
            return frozenset({"py3-none-any"})

        async def pin_local_base(self, image_digest: str) -> str:
            assert image_digest == selected_digest
            return "sastsimi-offline-base:" + "d" * 64

    docker = _VersionedDocker()
    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        wheel_bundle_path=bundle_path,
        wheel_bundle_sha256=bundle_sha256,
        offline_base_image_digest=selected_digest,
    ).prepare(checkpoint, {}, (f"python:{requested}",))

    assert docker.events[:2] == [
        ("inspect", selected_digest),
        ("version", selected_digest),
    ]
    assert docker.calls[0][0].startswith(b"FROM sastsimi-offline-base:" + b"d" * 64)
    recipe = json.loads(artifacts.read(result.recipe_ref))
    assert recipe["python_runtime_requirement"] == requested
    assert recipe["python_runtime_observed_version"] == "3.6.2"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("requirements", "expected_code"),
    [
        (("python:3.6",), "POC_OFFLINE_PYTHON_RUNTIME_DIGEST_REQUIRED"),
        (
            ("python:3.6", "python:3.7"),
            "POC_OFFLINE_PYTHON_RUNTIME_CONFLICT",
        ),
    ],
)
async def test_explicit_python_runtime_blocks_before_unconfigured_base_is_used(
    tmp_path: Path, requirements: tuple[str, ...], expected_code: str
) -> None:
    workspace, commit, bundle_path, bundle_sha256 = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    docker = _Docker()

    with pytest.raises(ValueError, match=expected_code):
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            wheel_bundle_path=bundle_path,
            wheel_bundle_sha256=bundle_sha256,
        ).prepare(checkpoint, {}, requirements)

    assert docker.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("requested", "observed"),
    [("3.6.2", "3.6.3"), ("3.6.2", "3.8.20"), ("3.12", "3.11.9")],
)
async def test_explicit_python_runtime_mismatch_blocks_before_offline_build(
    tmp_path: Path, requested: str, observed: str
) -> None:
    workspace, commit, bundle_path, bundle_sha256 = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    selected_digest = "sha256:" + "d" * 64

    class _MismatchedDocker(_Docker):
        async def local_base_image_digest(self, base_image: str) -> str:
            assert base_image in {
                selected_digest,
                "sastsimi-offline-base:" + "d" * 64,
            }
            return selected_digest

        async def _probe_python_version(self, image_digest: str) -> str:
            assert image_digest == selected_digest
            return observed

        async def target_wheel_tags(self, base_image: str) -> frozenset[str]:
            assert base_image == selected_digest
            return frozenset({"py3-none-any"})

        async def pin_local_base(self, image_digest: str) -> str:
            assert image_digest == selected_digest
            return "sastsimi-offline-base:" + "d" * 64

    docker = _MismatchedDocker()
    with pytest.raises(ValueError, match="POC_OFFLINE_PYTHON_RUNTIME_MISMATCH"):
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            wheel_bundle_path=bundle_path,
            wheel_bundle_sha256=bundle_sha256,
            offline_base_image_digest=selected_digest,
        ).prepare(checkpoint, {}, (f"python:{requested}",))

    assert docker.calls == []


@pytest.mark.asyncio
async def test_python_version_probe_is_networkless_and_uses_only_the_digest() -> None:
    selected_digest = "sha256:" + "d" * 64

    class _Runtime(PortableDockerRuntime):
        async def _run(
            self,
            args: Sequence[str],
            *,
            timeout_seconds: int,
            input_bytes: bytes | None = None,
        ) -> DockerCommandOutcome:
            assert input_bytes is None
            assert timeout_seconds <= 60
            self.command = tuple(args)
            return DockerCommandOutcome(0, b"3.6.2\n", b"", False)

    runtime = object.__new__(_Runtime)
    assert await runtime._probe_python_version(selected_digest) == "3.6.2"
    command = runtime.command
    assert command[:5] == ("run", "--pull", "never", "--rm", "--network")
    assert command[5] == "none"
    assert "--read-only" in command
    assert ("--cap-drop", "ALL") == command[
        command.index("--cap-drop") : command.index("--cap-drop") + 2
    ]
    assert ("--security-opt", "no-new-privileges") == command[
        command.index("--security-opt") : command.index("--security-opt") + 2
    ]
    assert ("--entrypoint", "python") == command[
        command.index("--entrypoint") : command.index("--entrypoint") + 2
    ]
    assert selected_digest in command
    assert "-c" == command[command.index(selected_digest) + 1]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "outcome",
    [
        DockerCommandOutcome(1, b"", b"python unavailable", False),
        DockerCommandOutcome(0, b"3.6.2\nunexpected\n", b"", False),
        DockerCommandOutcome(0, b"3.6.2\n", b"", True),
    ],
)
async def test_python_version_probe_rejects_unavailable_or_ambiguous_output(
    outcome: DockerCommandOutcome,
) -> None:
    class _Runtime(PortableDockerRuntime):
        async def _run(
            self,
            args: Sequence[str],
            *,
            timeout_seconds: int,
            input_bytes: bytes | None = None,
        ) -> DockerCommandOutcome:
            del args, timeout_seconds, input_bytes
            return outcome

    with pytest.raises(ValueError, match="POC_OFFLINE_PYTHON_RUNTIME_UNAVAILABLE"):
        await object.__new__(_Runtime)._probe_python_version("sha256:" + "d" * 64)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("requested", "observed"),
    [("3.6.2", "3.6.2"), ("3.12", "3.12.9")],
)
async def test_auto_bundle_verifies_explicit_python_before_networked_resolution(
    tmp_path: Path, requested: str, observed: str
) -> None:
    workspace, commit, bundle_path, _ = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    selected_digest = "sha256:" + "d" * 64

    class _AutoDocker(_Docker):
        def __init__(self) -> None:
            super().__init__()
            self.events: list[str] = []

        async def local_base_image_digest(self, base_image: str) -> str:
            self.events.append("inspect")
            assert base_image in {
                selected_digest,
                "sastsimi-offline-base:" + "d" * 64,
            }
            return selected_digest

        async def _probe_python_version(self, image_digest: str) -> str:
            self.events.append("version")
            assert image_digest == selected_digest
            return observed

        async def pin_local_base(self, image_digest: str) -> str:
            self.events.append("pin")
            assert image_digest == selected_digest
            return "sastsimi-offline-base:" + "d" * 64

        async def target_wheel_tags(self, base_image: str) -> frozenset[str]:
            assert base_image == selected_digest
            return frozenset({"py3-none-any"})

        async def download_python_wheels(
            self,
            *,
            base_image: str,
            requirements: tuple[str, ...],
            timeout_seconds: int,
        ) -> bytes:
            del timeout_seconds
            self.events.append("download")
            assert base_image == "sastsimi-offline-base:" + "d" * 64
            assert requirements == ("sample-pkg==1.0",)
            return bundle_path.read_bytes()

    docker = _AutoDocker()
    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        offline_base_image_digest=selected_digest,
        auto_dependency_bundle=True,
    ).prepare(checkpoint, {}, (f"python:{requested}",))

    assert docker.events[:4] == ["inspect", "version", "pin", "download"]
    assert docker.events.count("version") == 1
    recipe = json.loads(artifacts.read(result.recipe_ref))
    assert recipe["python_runtime_requirement"] == requested
    assert recipe["python_runtime_observed_version"] == observed


@pytest.mark.asyncio
async def test_auto_bundle_blocks_mismatched_configured_default_before_resolution(
    tmp_path: Path,
) -> None:
    workspace, commit, _bundle_path, _ = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    selected_digest = "sha256:" + "d" * 64

    class _WrongDefaultDocker(_Docker):
        async def local_base_image_digest(self, base_image: str) -> str:
            assert base_image == selected_digest
            return selected_digest

        async def _probe_python_version(self, image_digest: str) -> str:
            assert image_digest == selected_digest
            return "3.11.9"

        async def pin_local_base(self, image_digest: str) -> str:
            assert image_digest == selected_digest
            return "sastsimi-offline-base:" + "d" * 64

        async def download_python_wheels(self, **_kwargs: object) -> bytes:
            raise AssertionError("mismatched runtime must block before resolution")

    docker = _WrongDefaultDocker()
    with pytest.raises(ValueError, match="POC_OFFLINE_PYTHON_RUNTIME_MISMATCH"):
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            offline_base_image_digest=selected_digest,
            auto_dependency_bundle=True,
        ).prepare(checkpoint, {}, ("python:3.12",))

    assert docker.calls == []


@pytest.mark.asyncio
async def test_auto_bundle_nondefault_python_without_digest_never_resolves_base(
    tmp_path: Path,
) -> None:
    workspace, commit, _bundle_path, _ = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)

    class _NoBaseAccess(_Docker):
        async def local_base_image_digest(self, base_image: str) -> str:
            raise AssertionError(f"base access was not permitted: {base_image}")

    with pytest.raises(ValueError, match="POC_OFFLINE_PYTHON_RUNTIME_DIGEST_REQUIRED"):
        await DirectEnvironmentPreparer(
            docker=_NoBaseAccess(),  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            auto_dependency_bundle=True,
        ).prepare(checkpoint, {}, ("python:3.6",))


def test_alpine_image_tag_is_not_accepted_as_a_python_version() -> None:
    with pytest.raises(ValueError, match="POC_OFFLINE_REQUIREMENT_UNSUPPORTED"):
        DirectEnvironmentPreparer._offline_agent_requirements(
            ("python:alpine3.8",), commit_id="a" * 40
        )


@pytest.mark.asyncio
async def test_auto_bundle_resolves_safe_python_requirements_before_offline_build(
    tmp_path: Path,
) -> None:
    """A normal requirements.txt must not fall back to a source-only image."""

    workspace, commit, bundle_path, _ = _fixture(tmp_path)
    (workspace / "pyproject.toml").write_text(
        "[project]\nname = 'untracked-package'\nversion = '1.0'\n",
        encoding="utf-8",
    )
    artifacts, checkpoint = _checkpoint(tmp_path, commit)

    class _AutoBundleDocker(_Docker):
        def __init__(self) -> None:
            super().__init__()
            self.resolution_requests: list[tuple[str, tuple[str, ...], int]] = []

        async def download_python_wheels(
            self,
            *,
            base_image: str,
            requirements: tuple[str, ...],
            timeout_seconds: int,
        ) -> bytes:
            self.resolution_requests.append((base_image, requirements, timeout_seconds))
            return bundle_path.read_bytes()

        async def local_base_image_digest(self, base_image: str) -> str:
            if base_image == "sha256:" + "b" * 64:
                return base_image
            return await super().local_base_image_digest(base_image)

    docker = _AutoBundleDocker()
    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        auto_dependency_bundle=True,
    ).prepare(checkpoint, {}, ())

    assert docker.resolution_requests == [
        ("sastsimi-offline-base:" + "b" * 64, ("sample-pkg==1.0",), 300)
    ]
    dockerfile, _cache_key, context = docker.calls[0]
    assert dockerfile.startswith(
        ("FROM sastsimi-offline-base:" + "b" * 64 + "\n").encode("ascii")
    )
    assert b"--no-index --find-links=/opt/sastsimi-wheels" in dockerfile
    assert b"apt-get" not in dockerfile
    assert context is not None
    recipe = json.loads(artifacts.read(result.recipe_ref))
    assert recipe["dependency_bundle_source"] == "AUTO_RESOLVED"
    assert recipe["build_network"] == "none"


@pytest.mark.asyncio
async def test_auto_resolver_has_network_only_without_repository_mount(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _workspace, _commit, bundle_path, _digest = _fixture(tmp_path)
    with tarfile.open(bundle_path, "r:") as archive:
        member = archive.getmember("sample_pkg-1.0-py3-none-any.whl")
        stream = archive.extractfile(member)
        assert stream is not None
        wheel = stream.read()

    if os.name == "nt":

        def reject_restrictive_tempdir(**_kwargs: object) -> None:
            raise AssertionError("Windows wheel workspace must inherit Temp ACL")

        monkeypatch.setattr(
            "sastsimi.simple_runtime.portable_docker.tempfile.TemporaryDirectory",
            reject_restrictive_tempdir,
        )

    class _RecordedRuntime(PortableDockerRuntime):
        def __init__(self) -> None:
            self._network = "none"
            self.commands: list[tuple[str, ...]] = []

        async def _run(
            self,
            args: Sequence[str],
            *,
            timeout_seconds: int,
            input_bytes: bytes | None = None,
        ) -> DockerCommandOutcome:
            del timeout_seconds, input_bytes
            self.commands.append(tuple(args))
            if args[0] == "run":
                mount = args[args.index("--mount") + 1]
                source = mount.split("source=", 1)[1].split(",target=", 1)[0]
                wheel_path = Path(source) / "wheels" / "sample_pkg-1.0-py3-none-any.whl"
                wheel_path.write_bytes(wheel)
                return DockerCommandOutcome(0, b"downloaded", b"", False)
            if args[:2] == ("container", "inspect"):
                return DockerCommandOutcome(
                    1,
                    b"[]\n",
                    (
                        f"Error response from daemon: No such container: {args[-1]}\n"
                    ).encode(),
                    False,
                )
            return DockerCommandOutcome(1, b"", b"already removed", False)

    runtime = _RecordedRuntime()
    bundle = await runtime.download_python_wheels(
        base_image="sastsimi-offline-base:" + "b" * 64,
        requirements=("sample-pkg==1.0",),
        timeout_seconds=30,
    )

    command = runtime.commands[0]
    assert ("--network", "bridge") == command[
        command.index("--network") : command.index("--network") + 2
    ]
    assert "--read-only" in command
    assert ("--cap-drop", "ALL") == command[
        command.index("--cap-drop") : command.index("--cap-drop") + 2
    ]
    assert ("--only-binary=:all:") in command
    assert ("--retries", "3") == command[
        command.index("--retries") : command.index("--retries") + 2
    ]
    assert ("--timeout", "45") == command[
        command.index("--timeout") : command.index("--timeout") + 2
    ]
    assert ("--entrypoint", "python") == command[
        command.index("--entrypoint") : command.index("--entrypoint") + 2
    ]
    assert str(_workspace) not in "\n".join(command)
    assert runtime.commands[1][:2] == ("rm", "--force")
    assert runtime.commands[2][:2] == ("container", "inspect")
    assert bundle
    mount = command[command.index("--mount") + 1]
    workspace_root = Path(mount.split("source=", 1)[1].split(",target=", 1)[0])
    assert not workspace_root.exists()


@pytest.mark.asyncio
async def test_auto_resolver_fails_closed_when_timed_out_helper_may_remain() -> None:
    class _UnremovedRuntime(PortableDockerRuntime):
        def __init__(self) -> None:
            self._network = "none"
            self.commands: list[tuple[str, ...]] = []

        async def _run(
            self,
            args: Sequence[str],
            *,
            timeout_seconds: int,
            input_bytes: bytes | None = None,
        ) -> DockerCommandOutcome:
            del timeout_seconds, input_bytes
            self.commands.append(tuple(args))
            if args[0] == "run":
                return DockerCommandOutcome(-1, b"", b"download timed out", True)
            if args[0] == "rm":
                return DockerCommandOutcome(1, b"", b"daemon busy", False)
            if args[:2] == ("container", "inspect"):
                return DockerCommandOutcome(0, b"still-running-id", b"", False)
            raise AssertionError(args)

    runtime = _UnremovedRuntime()
    with pytest.raises(ValueError, match="POC_AUTO_BUNDLE_CLEANUP_FAILED"):
        await runtime.download_python_wheels(
            base_image="sastsimi-offline-base:" + "b" * 64,
            requirements=("sample-pkg==1.0",),
            timeout_seconds=30,
        )

    assert runtime.commands[1][:2] == ("rm", "--force")


@pytest.mark.asyncio
async def test_auto_base_resolver_pulls_missing_default_image_once() -> None:
    """AUTO mode must recover a missing, fixed default base image."""

    class _PullingRuntime(PortableDockerRuntime):
        def __init__(self) -> None:
            self._network = "none"
            self.pulled = False
            self.commands: list[tuple[str, ...]] = []

        async def _run(
            self,
            args: Sequence[str],
            *,
            timeout_seconds: int,
            input_bytes: bytes | None = None,
        ) -> DockerCommandOutcome:
            del timeout_seconds, input_bytes
            self.commands.append(tuple(args))
            if args[:2] == ("image", "inspect"):
                if not self.pulled:
                    return DockerCommandOutcome(1, b"", b"missing", False)
                return DockerCommandOutcome(0, b"linux|sha256:" + b"a" * 64, b"", False)
            if tuple(args) == ("image", "pull", "python:3.12-slim"):
                self.pulled = True
                return DockerCommandOutcome(0, b"pulled", b"", False)
            raise AssertionError(args)

    runtime = _PullingRuntime()

    digest, source = await runtime.resolve_offline_base(
        "python:3.12-slim", allow_pull=True
    )

    assert digest == "sha256:" + "a" * 64
    assert source == "AUTO_PULLED"
    assert runtime.commands == [
        ("image", "inspect", "--format", "{{.Os}}|{{.Id}}", "python:3.12-slim"),
        ("image", "pull", "python:3.12-slim"),
        ("image", "inspect", "--format", "{{.Os}}|{{.Id}}", "python:3.12-slim"),
    ]


@pytest.mark.asyncio
async def test_auto_base_resolver_reports_unavailable_when_pull_fails() -> None:
    """A registry failure must remain a safe availability error."""

    class _UnavailableRuntime(PortableDockerRuntime):
        def __init__(self) -> None:
            self._network = "none"

        async def _run(
            self,
            args: Sequence[str],
            *,
            timeout_seconds: int,
            input_bytes: bytes | None = None,
        ) -> DockerCommandOutcome:
            del timeout_seconds, input_bytes
            if args[:2] == ("image", "inspect"):
                return DockerCommandOutcome(1, b"", b"missing", False)
            if tuple(args) == ("image", "pull", "python:3.12-slim"):
                return DockerCommandOutcome(1, b"", b"registry unavailable", False)
            raise AssertionError(args)

    with pytest.raises(ValueError, match="POC_OFFLINE_BASE_IMAGE_UNAVAILABLE"):
        await _UnavailableRuntime().resolve_offline_base(
            "python:3.12-slim", allow_pull=True
        )


@pytest.mark.asyncio
async def test_auto_base_resolver_deduplicates_concurrent_default_pull() -> None:
    """Concurrent AUTO checks must share one pull of the fixed base image."""

    class _ConcurrentRuntime(PortableDockerRuntime):
        def __init__(self) -> None:
            self._network = "none"
            self.pulled = False
            self.pull_count = 0

        async def _run(
            self,
            args: Sequence[str],
            *,
            timeout_seconds: int,
            input_bytes: bytes | None = None,
        ) -> DockerCommandOutcome:
            del timeout_seconds, input_bytes
            if args[:2] == ("image", "inspect"):
                if not self.pulled:
                    return DockerCommandOutcome(1, b"", b"missing", False)
                return DockerCommandOutcome(0, b"linux|sha256:" + b"a" * 64, b"", False)
            if tuple(args) == ("image", "pull", "python:3.12-slim"):
                self.pull_count += 1
                await asyncio.sleep(0)
                self.pulled = True
                return DockerCommandOutcome(0, b"pulled", b"", False)
            raise AssertionError(args)

    runtime = _ConcurrentRuntime()
    results = await asyncio.gather(
        runtime.resolve_offline_base("python:3.12-slim", allow_pull=True),
        runtime.resolve_offline_base("python:3.12-slim", allow_pull=True),
    )

    assert results[0] == ("sha256:" + "a" * 64, "AUTO_PULLED")
    assert results[1] == ("sha256:" + "a" * 64, "LOCAL")
    assert runtime.pull_count == 1


@pytest.mark.asyncio
async def test_auto_bundle_deduplicates_concurrent_matching_resolution(
    tmp_path: Path,
) -> None:
    workspace, commit, bundle_path, _digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)

    class _SlowResolverDocker(_Docker):
        def __init__(self) -> None:
            super().__init__()
            self.resolver_calls = 0

        async def download_python_wheels(
            self,
            **_kwargs: object,
        ) -> bytes:
            self.resolver_calls += 1
            await asyncio.sleep(0)
            return bundle_path.read_bytes()

        async def local_base_image_digest(self, base_image: str) -> str:
            if base_image == "sha256:" + "b" * 64:
                return base_image
            return await super().local_base_image_digest(base_image)

    docker = _SlowResolverDocker()
    preparer = DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        auto_dependency_bundle=True,
    )
    await asyncio.gather(
        preparer.prepare(checkpoint, {}, ()),
        preparer.prepare(checkpoint, {}, ()),
    )

    assert docker.resolver_calls == 1


@pytest.mark.parametrize("concurrent", [False, True])
@pytest.mark.asyncio
async def test_auto_bundle_reuses_resolution_across_distinct_hypothesis_preparers(
    tmp_path: Path,
    concurrent: bool,
) -> None:
    """A new runner for the next hypothesis must not redownload identical wheels."""

    workspace, commit, bundle_path, _digest = _fixture(tmp_path)
    artifacts, first = _checkpoint(tmp_path, commit)
    second_identity = first.identity.model_copy(update={"hypothesis_id": "second"})
    second = first.model_copy(update={"identity": second_identity})

    class _CountingDocker(_Docker):
        def __init__(self) -> None:
            super().__init__()
            self.resolver_calls = 0

        async def download_python_wheels(self, **_kwargs: object) -> bytes:
            self.resolver_calls += 1
            await asyncio.sleep(0)
            return bundle_path.read_bytes()

        async def local_base_image_digest(self, base_image: str) -> str:
            if base_image == "sha256:" + "b" * 64:
                return base_image
            return await super().local_base_image_digest(base_image)

    docker = _CountingDocker()
    shared_cache = portable_docker.AutoWheelBundleCache()
    first_preparer = DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        auto_dependency_bundle=True,
        auto_bundle_cache=shared_cache,
    )
    second_preparer = DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=SimpleArtifactRepository(tmp_path / "data", second_identity),
        workspace=workspace,
        auto_dependency_bundle=True,
        auto_bundle_cache=shared_cache,
    )

    if concurrent:
        await asyncio.gather(
            first_preparer.prepare(first, {}, ()),
            second_preparer.prepare(second, {}, ()),
        )
    else:
        await first_preparer.prepare(first, {}, ())
        await second_preparer.prepare(second, {}, ())

    assert docker.resolver_calls == 1


def test_auto_bundle_cache_is_analysis_scoped_and_memory_bounded() -> None:
    cache = portable_docker.AutoWheelBundleCache(max_bytes=4, max_entries=2)
    cache.put("analysis-a", "same-content-key", b"one")

    assert cache.get("analysis-b", "same-content-key") is None
    assert cache.get("analysis-a", "same-content-key") == b"one"

    cache.put("analysis-a", "next-content-key", b"two")
    assert cache.get("analysis-a", "same-content-key") is None
    assert cache.get("analysis-a", "next-content-key") == b"two"

    cache.put("analysis-a", "oversize-key", b"larger")
    assert cache.get("analysis-a", "oversize-key") is None


def test_auto_bundle_cache_rejects_archive_with_mismatched_hash() -> None:
    cache = portable_docker.AutoWheelBundleCache()
    cache.put("analysis-a", "content-key", b"valid archive")
    cache._entries[("analysis-a", "content-key")] = ("0" * 64, b"valid archive")

    assert cache.get("analysis-a", "content-key") is None


@pytest.mark.asyncio
async def test_auto_bundle_keeps_stdlib_only_project_offline_without_resolver(
    tmp_path: Path,
) -> None:
    """A project with no dependency manifest must not be blocked by AUTO mode."""

    workspace = tmp_path / "stdlib-checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text("print('stdlib only')\n", encoding="utf-8")
    subprocess.run(("git", "init", "-q", str(workspace)), check=True)
    subprocess.run(("git", "-C", str(workspace), "add", "app.py"), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "stdlib fixture",
        ),
        check=True,
    )
    commit = (
        subprocess.check_output(("git", "-C", str(workspace), "rev-parse", "HEAD"))
        .decode("ascii")
        .strip()
    )
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    docker = _Docker()

    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        auto_dependency_bundle=True,
    ).prepare(checkpoint, {}, ())

    assert len(docker.calls) == 1
    dockerfile, _cache_key, context = docker.calls[0]
    assert b"FROM python:3.12-slim" in dockerfile
    assert b"pip install" not in dockerfile
    assert context is None
    recipe = json.loads(artifacts.read(result.recipe_ref))
    assert recipe["dockerfile_source"] == "GENERATED"
    assert "dependency_bundle_source" not in recipe


@pytest.mark.asyncio
@pytest.mark.parametrize("has_empty_manifest", [False, True])
@pytest.mark.parametrize(
    ("requested", "observed"), [("3.6.2", "3.6.2"), ("3.12", "3.12.9")]
)
async def test_auto_dependency_free_python_uses_pinned_local_image(
    tmp_path: Path, has_empty_manifest: bool, requested: str, observed: str
) -> None:
    workspace, commit, _bundle_path, _bundle_sha256 = _fixture(tmp_path, manifest="")
    if not has_empty_manifest:
        (workspace / "requirements.txt").unlink()
        subprocess.run(("git", "-C", str(workspace), "add", "-A"), check=True)
        subprocess.run(
            (
                "git",
                "-C",
                str(workspace),
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-qm",
                "stdlib target",
            ),
            check=True,
        )
        commit = (
            subprocess.check_output(("git", "-C", str(workspace), "rev-parse", "HEAD"))
            .decode("ascii")
            .strip()
        )
    (workspace / "untracked.py").write_text(
        "raise RuntimeError('untrusted')\n", encoding="utf-8"
    )
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    selected_digest = "sha256:" + "d" * 64
    selected_reference = "sastsimi-offline-base:" + "d" * 64

    class _VersionedDocker(_Docker):
        def __init__(self) -> None:
            super().__init__()
            self.probes: list[tuple[str, str]] = []

        async def local_base_image_digest(self, base_image: str) -> str:
            self.probes.append(("inspect", base_image))
            assert base_image in {selected_digest, selected_reference}
            return selected_digest

        async def _probe_python_version(self, image_digest: str) -> str:
            self.probes.append(("python", image_digest))
            assert image_digest == selected_digest
            return observed

        async def pin_local_base(self, image_digest: str) -> str:
            self.probes.append(("pin", image_digest))
            assert image_digest == selected_digest
            return selected_reference

        async def download_python_wheels(self, **_kwargs: object) -> bytes:
            raise AssertionError("dependency-free target must not resolve wheels")

    docker = _VersionedDocker()
    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        offline_base_image_digest=selected_digest,
        auto_dependency_bundle=True,
    ).prepare(checkpoint, {}, (f"python:{requested}",))

    assert docker.probes[:3] == [
        ("inspect", selected_digest),
        ("python", selected_digest),
        ("pin", selected_digest),
    ]
    assert len(docker.calls) == 1
    dockerfile, _cache_key, context = docker.calls[0]
    assert dockerfile.startswith(f"FROM {selected_reference}\n".encode("ascii"))
    assert b"pip install" not in dockerfile
    assert b"apt-get" not in dockerfile
    assert context is not None
    with tarfile.open(fileobj=io.BytesIO(context), mode="r:") as archive:
        names = {member.name for member in archive}
        assert archive.extractfile("app.py").read() == b"print('test')\n"  # type: ignore[union-attr]
    assert "untracked.py" not in names
    assert ("requirements.txt" in names) is has_empty_manifest
    assert not any(name.startswith("wheels/") for name in names)
    recipe = json.loads(artifacts.read(result.recipe_ref))
    assert recipe["status"] == "BUILT"
    assert recipe["dockerfile_source"] == "GENERATED"
    assert recipe["base_image_digest"] == selected_digest
    assert recipe["python_runtime_requirement"] == requested
    assert recipe["python_runtime_observed_version"] == observed
    assert recipe["build_network"] == "none"
    assert recipe["context_sha256"] == hashlib.sha256(context).hexdigest()
    assert recipe["commit_id"] == commit
    assert recipe["image_digest"] == result.image_digest


@pytest.mark.asyncio
async def test_auto_dependency_free_python_rejects_excluded_manifest(
    tmp_path: Path,
) -> None:
    workspace, _commit, _bundle_path, _bundle_sha256 = _fixture(tmp_path, manifest="")
    (workspace / ".dockerignore").write_text("requirements.txt\n", encoding="utf-8")
    subprocess.run(("git", "-C", str(workspace), "add", ".dockerignore"), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "exclude manifest",
        ),
        check=True,
    )
    commit = (
        subprocess.check_output(("git", "-C", str(workspace), "rev-parse", "HEAD"))
        .decode("ascii")
        .strip()
    )
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    selected_digest = "sha256:" + "b" * 64

    class _VersionedDocker(_Docker):
        async def local_base_image_digest(self, base_image: str) -> str:
            if base_image == selected_digest:
                return selected_digest
            return await super().local_base_image_digest(base_image)

        async def _probe_python_version(self, image_digest: str) -> str:
            assert image_digest == selected_digest
            return "3.6.15"

    docker = _VersionedDocker()
    with pytest.raises(ValueError, match="POC_OFFLINE_MANIFEST_EXCLUDED"):
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            offline_base_image_digest=selected_digest,
            auto_dependency_bundle=True,
        ).prepare(checkpoint, {}, ("python:3.6",))

    assert docker.calls == []


@pytest.mark.asyncio
async def test_auto_dependency_free_python_blocks_mismatched_local_digest_before_build(
    tmp_path: Path,
) -> None:
    workspace, commit, _bundle_path, _bundle_sha256 = _fixture(tmp_path, manifest="")
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    selected_digest = "sha256:" + "d" * 64

    class _WrongVersionDocker(_Docker):
        async def local_base_image_digest(self, base_image: str) -> str:
            assert base_image == selected_digest
            return selected_digest

        async def _probe_python_version(self, image_digest: str) -> str:
            assert image_digest == selected_digest
            return "3.7.1"

        async def download_python_wheels(self, **_kwargs: object) -> bytes:
            raise AssertionError("mismatched runtime must not resolve wheels")

    docker = _WrongVersionDocker()
    with pytest.raises(ValueError, match="POC_OFFLINE_PYTHON_RUNTIME_MISMATCH"):
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            offline_base_image_digest=selected_digest,
            auto_dependency_bundle=True,
        ).prepare(checkpoint, {}, ("python:3.6",))

    assert docker.calls == []


@pytest.mark.asyncio
async def test_auto_dependency_free_python_requires_declared_source_in_pinned_context(
    tmp_path: Path,
) -> None:
    workspace, commit, _bundle_path, _bundle_sha256 = _fixture(tmp_path, manifest="")
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    selected_digest = "sha256:" + "d" * 64

    class _VersionedDocker(_Docker):
        async def local_base_image_digest(self, base_image: str) -> str:
            assert base_image in {
                selected_digest,
                "sastsimi-offline-base:" + "d" * 64,
            }
            return selected_digest

        async def _probe_python_version(self, image_digest: str) -> str:
            assert image_digest == selected_digest
            return "3.6.2"

        async def pin_local_base(self, image_digest: str) -> str:
            assert image_digest == selected_digest
            return "sastsimi-offline-base:" + "d" * 64

    docker = _VersionedDocker()
    with pytest.raises(ValueError, match="POC_OFFLINE_REQUIREMENT_UNSUPPORTED"):
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            offline_base_image_digest=selected_digest,
            auto_dependency_bundle=True,
        ).prepare(
            checkpoint,
            {},
            ("python:3.6", f"Source checkout at commit {commit} containing missing.py"),
        )

    assert docker.calls == []


@pytest.mark.asyncio
async def test_auto_nondefault_python_without_dependencies_rejects_pyproject_install(
    tmp_path: Path,
) -> None:
    workspace, _commit, _bundle_path, _bundle_sha256 = _fixture(tmp_path, manifest="")
    (workspace / "requirements.txt").unlink()
    (workspace / "pyproject.toml").write_text(
        "[project]\nname = 'local-package'\nversion = '1.0'\ndependencies = []\n",
        encoding="utf-8",
    )
    subprocess.run(("git", "-C", str(workspace), "add", "-A"), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "local package",
        ),
        check=True,
    )
    commit = (
        subprocess.check_output(("git", "-C", str(workspace), "rev-parse", "HEAD"))
        .decode("ascii")
        .strip()
    )
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    selected_digest = "sha256:" + "d" * 64

    class _VersionedDocker(_Docker):
        async def local_base_image_digest(self, base_image: str) -> str:
            assert base_image in {
                selected_digest,
                "sastsimi-offline-base:" + "d" * 64,
            }
            return selected_digest

        async def _probe_python_version(self, image_digest: str) -> str:
            assert image_digest == selected_digest
            return "3.6.2"

        async def pin_local_base(self, image_digest: str) -> str:
            assert image_digest == selected_digest
            return "sastsimi-offline-base:" + "d" * 64

    docker = _VersionedDocker()
    with pytest.raises(ValueError, match="POC_OFFLINE_PYTHON_RUNTIME_BUNDLE_REQUIRED"):
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            offline_base_image_digest=selected_digest,
            auto_dependency_bundle=True,
        ).prepare(checkpoint, {}, ("python:3.6",))

    assert docker.calls == []


@pytest.mark.asyncio
async def test_auto_dependency_free_without_explicit_python_keeps_default_build(
    tmp_path: Path,
) -> None:
    workspace, _commit, _bundle_path, _bundle_sha256 = _fixture(tmp_path, manifest="")
    (workspace / "Dockerfile").unlink()
    subprocess.run(("git", "-C", str(workspace), "add", "-A"), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "no Dockerfile",
        ),
        check=True,
    )
    commit = (
        subprocess.check_output(("git", "-C", str(workspace), "rev-parse", "HEAD"))
        .decode("ascii")
        .strip()
    )
    artifacts, checkpoint = _checkpoint(tmp_path, commit)

    class _ConfiguredDocker(_Docker):
        async def local_base_image_digest(self, base_image: str) -> str:
            if base_image == "sha256:" + "b" * 64:
                return base_image
            return await super().local_base_image_digest(base_image)

    docker = _ConfiguredDocker()

    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        offline_base_image_digest="sha256:" + "b" * 64,
        auto_dependency_bundle=True,
    ).prepare(checkpoint, {}, ())

    assert len(docker.calls) == 1
    dockerfile, _cache_key, context = docker.calls[0]
    assert dockerfile.startswith(b"FROM python:3.12-slim\n")
    assert context is None
    assert "base_image_digest" not in json.loads(artifacts.read(result.recipe_ref))


@pytest.mark.asyncio
@pytest.mark.parametrize("requested_runtime", [None, "3.6"])
async def test_auto_bundle_resolves_literal_dockerfile_pip_requirements(
    tmp_path: Path,
    requested_runtime: str | None,
) -> None:
    """A safe Dockerfile declaration can seed an offline Python runtime."""

    workspace, _commit, bundle_path, _digest = _fixture(tmp_path)
    (workspace / "requirements.txt").unlink()
    (workspace / "Dockerfile").write_text(
        "FROM python:3.6-slim\n"
        "RUN apt-get update && apt-get install -y sqlite3\n"
        "RUN pip install Flask==2.3.0\n",
        encoding="utf-8",
    )
    subprocess.run(("git", "-C", str(workspace), "add", "-A"), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "dockerfile python dependencies",
        ),
        check=True,
    )
    commit = (
        subprocess.check_output(("git", "-C", str(workspace), "rev-parse", "HEAD"))
        .decode("ascii")
        .strip()
    )
    (workspace / "pyproject.toml").write_text(
        "[project]\nname = 'untracked-package'\nversion = '1.0'\n",
        encoding="utf-8",
    )
    artifacts, checkpoint = _checkpoint(tmp_path, commit)

    class _AutoBundleDocker(_Docker):
        def __init__(self) -> None:
            super().__init__()
            self.resolution_requests: list[tuple[str, tuple[str, ...], int]] = []
            self.version_probes: list[str] = []

        async def _probe_python_version(self, image_digest: str) -> str:
            self.version_probes.append(image_digest)
            assert image_digest == "sha256:" + "b" * 64
            return "3.6.15"

        async def download_python_wheels(
            self,
            *,
            base_image: str,
            requirements: tuple[str, ...],
            timeout_seconds: int,
        ) -> bytes:
            self.resolution_requests.append((base_image, requirements, timeout_seconds))
            return bundle_path.read_bytes()

        async def local_base_image_digest(self, base_image: str) -> str:
            if base_image == "sha256:" + "b" * 64:
                return base_image
            return await super().local_base_image_digest(base_image)

    docker = _AutoBundleDocker()
    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        offline_base_image_digest=(
            "sha256:" + "b" * 64 if requested_runtime is not None else None
        ),
        auto_dependency_bundle=True,
    ).prepare(
        checkpoint,
        {},
        (f"python:{requested_runtime}",) if requested_runtime is not None else (),
    )

    assert docker.resolution_requests == [
        ("sastsimi-offline-base:" + "b" * 64, ("Flask==2.3.0",), 300)
    ]
    dockerfile, _cache_key, context = docker.calls[0]
    assert context is not None
    assert b"Flask==2.3.0" in dockerfile
    assert b"apt-get" not in dockerfile
    recipe = json.loads(artifacts.read(result.recipe_ref))
    assert recipe["dependency_resolution_input_kind"] == (
        "DOCKERFILE_LITERAL_PIP_REQUIREMENTS"
    )
    assert recipe["dependency_provisioning_input_kind"] == (
        "DOCKERFILE_LITERAL_PIP_REQUIREMENTS"
    )
    assert recipe["environment_fidelity"] == "DERIVED_PYTHON_RUNTIME"
    assert recipe["target_manifest_path"] is None
    assert docker.version_probes == (
        ["sha256:" + "b" * 64] if requested_runtime is not None else []
    )
    if requested_runtime is not None:
        assert recipe["python_runtime_requirement"] == "3.6"
        assert recipe["python_runtime_observed_version"] == "3.6.15"


@pytest.mark.asyncio
async def test_auto_bundle_rejects_dirty_checkout_before_resolving_wheels(
    tmp_path: Path,
) -> None:
    """A mutable checkout must not cause an external dependency download."""

    workspace, commit, bundle_path, _digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    (workspace / "requirements.txt").write_text("other-package==9\n", encoding="utf-8")

    class _ObservedDocker(_Docker):
        def __init__(self) -> None:
            super().__init__()
            self.resolution_requests = 0

        async def download_python_wheels(self, **_kwargs: object) -> bytes:
            self.resolution_requests += 1
            return bundle_path.read_bytes()

    docker = _ObservedDocker()
    with pytest.raises(ValueError, match="PINNED_CONTEXT_CHANGED"):
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            auto_dependency_bundle=True,
        ).prepare(checkpoint, {}, ())

    assert docker.resolution_requests == 0


@pytest.mark.asyncio
async def test_python_runtime_omits_nested_node_project_from_python_context(
    tmp_path: Path,
) -> None:
    """An unrelated Node subtree must not enter a derived Python PoC image."""

    workspace, _commit, bundle_path, digest = _fixture(tmp_path)
    node_project = workspace / "ui"
    node_project.mkdir()
    (node_project / "package.json").write_text(
        '{"name":"unrelated-ui","private":true}\n', encoding="utf-8"
    )
    (node_project / ".npmrc").write_text(
        "//registry.example.invalid/:_authToken=not-for-container\n",
        encoding="utf-8",
    )
    subprocess.run(("git", "-C", str(workspace), "add", "ui"), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "nested node credentials",
        ),
        check=True,
    )
    commit = (
        subprocess.check_output(("git", "-C", str(workspace), "rev-parse", "HEAD"))
        .decode("ascii")
        .strip()
    )
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    docker = _Docker()

    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        wheel_bundle_path=bundle_path,
        wheel_bundle_sha256=digest,
    ).prepare(checkpoint, {}, ())

    _dockerfile, _cache_key, context = docker.calls[0]
    assert context is not None
    assert b"not-for-container" not in context
    with tarfile.open(fileobj=io.BytesIO(context), mode="r:") as archive:
        assert "ui/.npmrc" not in archive.getnames()
        assert "ui/package.json" not in archive.getnames()
    recipe = json.loads(artifacts.read(result.recipe_ref))
    assert recipe["omitted_foreign_runtime_path_count"] == 2
    assert recipe["omitted_foreign_runtime_secret_path_count"] == 1
    assert isinstance(recipe["omitted_foreign_runtime_secret_paths_sha256"], str)


@pytest.mark.asyncio
async def test_python_runtime_keeps_secret_in_hybrid_nested_project_blocked(
    tmp_path: Path,
) -> None:
    """A nested project with Python metadata is not safe to omit as Node-only."""

    workspace, _commit, bundle_path, digest = _fixture(tmp_path)
    hybrid_project = workspace / "ui"
    hybrid_project.mkdir()
    (hybrid_project / "package.json").write_text(
        '{"name":"hybrid-ui"}\n', encoding="utf-8"
    )
    (hybrid_project / "requirements.txt").write_text(
        "sample-pkg==1.0\n", encoding="utf-8"
    )
    (hybrid_project / ".npmrc").write_text(
        "//registry.example.invalid/:_authToken=do-not-copy\n",
        encoding="utf-8",
    )
    subprocess.run(("git", "-C", str(workspace), "add", "ui"), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "hybrid credentials",
        ),
        check=True,
    )
    commit = (
        subprocess.check_output(("git", "-C", str(workspace), "rev-parse", "HEAD"))
        .decode("ascii")
        .strip()
    )
    artifacts, checkpoint = _checkpoint(tmp_path, commit)

    with pytest.raises(ValueError, match="PINNED_CONTEXT_SECRET_FILE_DENIED"):
        await DirectEnvironmentPreparer(
            docker=_Docker(),  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            wheel_bundle_path=bundle_path,
            wheel_bundle_sha256=digest,
        ).prepare(checkpoint, {}, ())


@pytest.mark.asyncio
async def test_python_runtime_keeps_setup_py_hybrid_project_blocked(
    tmp_path: Path,
) -> None:
    """A nested setup.py project is Python-capable, not Node-only."""

    workspace, _commit, bundle_path, digest = _fixture(tmp_path)
    hybrid_project = workspace / "ui"
    hybrid_project.mkdir()
    (hybrid_project / "package.json").write_text(
        '{"name":"hybrid-ui"}\n', encoding="utf-8"
    )
    (hybrid_project / "setup.py").write_text(
        "from setuptools import setup\nsetup(name='hybrid-ui')\n",
        encoding="utf-8",
    )
    (hybrid_project / ".npmrc").write_text(
        "//registry.example.invalid/:_authToken=do-not-copy\n",
        encoding="utf-8",
    )
    subprocess.run(("git", "-C", str(workspace), "add", "ui"), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "setup hybrid credentials",
        ),
        check=True,
    )
    commit = (
        subprocess.check_output(("git", "-C", str(workspace), "rev-parse", "HEAD"))
        .decode("ascii")
        .strip()
    )
    artifacts, checkpoint = _checkpoint(tmp_path, commit)

    with pytest.raises(ValueError, match="PINNED_CONTEXT_SECRET_FILE_DENIED"):
        await DirectEnvironmentPreparer(
            docker=_Docker(),  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            wheel_bundle_path=bundle_path,
            wheel_bundle_sha256=digest,
        ).prepare(checkpoint, {}, ())


@pytest.mark.asyncio
async def test_auto_bundle_ignores_untracked_dependency_files(
    tmp_path: Path,
) -> None:
    """AUTO mode discovers manifests and Dockerfiles from the pinned tree only."""

    workspace = tmp_path / "manifestless-checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text("print('stdlib only')\n", encoding="utf-8")
    subprocess.run(("git", "init", "-q", str(workspace)), check=True)
    subprocess.run(("git", "-C", str(workspace), "add", "app.py"), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "manifestless fixture",
        ),
        check=True,
    )
    commit = (
        subprocess.check_output(("git", "-C", str(workspace), "rev-parse", "HEAD"))
        .decode("ascii")
        .strip()
    )
    (workspace / "requirements.txt").write_text(
        "untracked-package==1\n", encoding="utf-8"
    )
    artifacts, checkpoint = _checkpoint(tmp_path, commit)

    class _ObservedDocker(_Docker):
        def __init__(self) -> None:
            super().__init__()
            self.resolution_requests = 0

        async def download_python_wheels(self, **_kwargs: object) -> bytes:
            self.resolution_requests += 1
            raise AssertionError("untracked dependency input must not resolve")

    docker = _ObservedDocker()
    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        auto_dependency_bundle=True,
    ).prepare(checkpoint, {}, ())

    assert docker.resolution_requests == 0
    assert (
        json.loads(artifacts.read(result.recipe_ref))["dockerfile_source"]
        == "GENERATED"
    )


def test_literal_dockerfile_parser_ignores_shell_and_custom_index_commands() -> None:
    requirements = DirectEnvironmentPreparer._literal_dockerfile_pip_requirements(
        b"FROM python:3.12-slim\n"
        b"RUN pip install Flask==2.3.0 && echo unsafe\n"
        b"RUN pip install --index-url https://example.invalid private-package\n"
        b"RUN python -m pip install --no-cache-dir safe-package==1.0\n"
    )

    assert requirements == ("safe-package==1.0",)


@pytest.mark.asyncio
async def test_auto_bundle_installs_explicit_python_requirement_without_manifest(
    tmp_path: Path,
) -> None:
    """A declared PoC runtime library must not require packaging metadata."""

    workspace = tmp_path / "manifestless-checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text("print('uses a library')\n", encoding="utf-8")
    subprocess.run(("git", "init", "-q", str(workspace)), check=True)
    subprocess.run(("git", "-C", str(workspace), "add", "app.py"), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "manifestless fixture",
        ),
        check=True,
    )
    commit = (
        subprocess.check_output(("git", "-C", str(workspace), "rev-parse", "HEAD"))
        .decode("ascii")
        .strip()
    )
    # This local file is outside the pinned commit and cannot become the
    # selected install target after AUTO has already resolved the dependency.
    (workspace / "requirements.txt").write_text(
        "untracked-package==1\n", encoding="utf-8"
    )
    bundle_root = tmp_path / "bundle-source"
    bundle_root.mkdir()
    _unused_workspace, _unused_commit, bundle_path, _unused_digest = _fixture(
        bundle_root
    )
    artifacts, checkpoint = _checkpoint(tmp_path, commit)

    class _AutoBundleDocker(_Docker):
        def __init__(self) -> None:
            super().__init__()
            self.resolution_requests: list[tuple[str, tuple[str, ...], int]] = []

        async def download_python_wheels(
            self,
            *,
            base_image: str,
            requirements: tuple[str, ...],
            timeout_seconds: int,
        ) -> bytes:
            self.resolution_requests.append((base_image, requirements, timeout_seconds))
            return bundle_path.read_bytes()

        async def local_base_image_digest(self, base_image: str) -> str:
            if base_image == "sha256:" + "b" * 64:
                return base_image
            return await super().local_base_image_digest(base_image)

    docker = _AutoBundleDocker()
    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        auto_dependency_bundle=True,
    ).prepare(checkpoint, {}, ("pip:sample-pkg==1.0",))

    assert docker.resolution_requests == [
        ("sastsimi-offline-base:" + "b" * 64, ("sample-pkg==1.0",), 300)
    ]
    dockerfile, _cache_key, context = docker.calls[0]
    assert context is not None
    assert b"pip install --no-cache-dir --no-index" in dockerfile
    assert b"sample-pkg==1.0" in dockerfile
    recipe = json.loads(artifacts.read(result.recipe_ref))
    assert recipe["target_manifest_path"] is None
    assert recipe["dependency_bundle_source"] == "AUTO_RESOLVED"


@pytest.mark.asyncio
async def test_auto_bundle_keeps_empty_requirements_project_offline_without_resolver(
    tmp_path: Path,
) -> None:
    workspace, _commit, _bundle_path, _digest = _fixture(tmp_path, manifest="")
    (workspace / "Dockerfile").unlink()
    subprocess.run(("git", "-C", str(workspace), "rm", "-q", "Dockerfile"), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "remove dockerfile",
        ),
        check=True,
    )
    commit = (
        subprocess.check_output(("git", "-C", str(workspace), "rev-parse", "HEAD"))
        .decode("ascii")
        .strip()
    )
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    docker = _Docker()

    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        auto_dependency_bundle=True,
    ).prepare(checkpoint, {}, ())

    assert len(docker.calls) == 1
    dockerfile, _cache_key, context = docker.calls[0]
    assert b"FROM python:3.12-slim" in dockerfile
    assert b"--network" not in dockerfile
    assert context is None
    recipe = json.loads(artifacts.read(result.recipe_ref))
    assert recipe["dockerfile_source"] == "GENERATED"
    assert "dependency_bundle_source" not in recipe


@pytest.mark.asyncio
async def test_auto_bundle_records_download_failure_without_source_only_fallback(
    tmp_path: Path,
) -> None:
    workspace, commit, _bundle_path, _digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)

    class _UnavailableIndexDocker(_Docker):
        async def download_python_wheels(
            self,
            **_kwargs: object,
        ) -> bytes:
            raise DockerOperationError(
                "POC_AUTO_BUNDLE_DOWNLOAD_FAILED",
                DockerCommandOutcome(1, b"", b"index unavailable", False),
            )

    with pytest.raises(DependencyBundleResolutionError) as caught:
        await DirectEnvironmentPreparer(
            docker=_UnavailableIndexDocker(),  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            auto_dependency_bundle=True,
        ).prepare(checkpoint, {}, ())

    assert caught.value.code == "POC_AUTO_BUNDLE_DOWNLOAD_FAILED"
    assert len(caught.value.attempt_refs) == 1
    receipt = json.loads(artifacts.read(caught.value.attempt_refs[0]))
    assert receipt["kind"] == "simple_dependency_bundle_attempt"
    assert receipt["status"] == "FAILED"
    assert receipt["error_code"] == "POC_AUTO_BUNDLE_DOWNLOAD_FAILED"
    assert receipt["requirement_count"] == 1
    assert receipt["pinned_requirement_provenance"] == {
        "kind": "simple_pinned_requirement_provenance_v1",
        "source_kind": "TARGET_MANIFEST",
        "source_path": "requirements.txt",
        "source_sha256": receipt["manifest_sha256"],
        "requirements": ["sample-pkg==1.0"],
    }


@pytest.mark.asyncio
async def test_auto_bundle_does_not_certify_marker_pin_without_resolver_environment(
    tmp_path: Path,
) -> None:
    workspace, commit, _bundle_path, _digest = _fixture(
        tmp_path, manifest='ghost-extra==1.0; sys_platform == "win32"\n'
    )
    artifacts, checkpoint = _checkpoint(tmp_path, commit)

    class _UnavailableDocker(_Docker):
        def __init__(self) -> None:
            super().__init__()
            self.requests: list[tuple[str, ...]] = []

        async def download_python_wheels(
            self,
            *,
            base_image: str,
            requirements: tuple[str, ...],
            timeout_seconds: int,
        ) -> bytes:
            del base_image, timeout_seconds
            self.requests.append(requirements)
            raise DockerOperationError(
                "POC_AUTO_BUNDLE_DOWNLOAD_FAILED",
                DockerCommandOutcome(
                    1,
                    b"",
                    b"ERROR: No matching distribution found for ghost-extra==1.0",
                    False,
                ),
            )

    docker = _UnavailableDocker()
    with pytest.raises(DependencyBundleResolutionError) as caught:
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            auto_dependency_bundle=True,
        ).prepare(checkpoint, {}, ("pip:ghost-extra==1.0",))

    assert len(docker.requests) == 1
    receipt = json.loads(artifacts.read(caught.value.attempt_refs[0]))
    assert "pinned_requirement_provenance" not in receipt


@pytest.mark.asyncio
async def test_auto_bundle_omits_only_unavailable_agent_extra_with_receipt(
    tmp_path: Path,
) -> None:
    """A hallucinated PoC extra must not block the pinned manifest's packages."""

    workspace, commit, bundle_path, _digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)

    class _ExtraUnavailableDocker(_Docker):
        def __init__(self) -> None:
            super().__init__()
            self.requests: list[tuple[str, ...]] = []

        async def local_base_image_digest(self, base_image: str) -> str:
            if base_image == "sha256:" + "b" * 64:
                return base_image
            return await super().local_base_image_digest(base_image)

        async def download_python_wheels(
            self,
            *,
            base_image: str,
            requirements: tuple[str, ...],
            timeout_seconds: int,
        ) -> bytes:
            del base_image, timeout_seconds
            self.requests.append(requirements)
            if "ghost-extra==1.0" in requirements:
                raise DockerOperationError(
                    "POC_AUTO_BUNDLE_DOWNLOAD_FAILED",
                    DockerCommandOutcome(
                        1,
                        b"",
                        b"ERROR: No matching distribution found for ghost-extra==1.0",
                        False,
                    ),
                )
            return bundle_path.read_bytes()

    docker = _ExtraUnavailableDocker()
    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        auto_dependency_bundle=True,
    ).prepare(checkpoint, {}, ("python:3.12", "pip:ghost-extra==1.0"))

    assert docker.requests == [
        ("sample-pkg==1.0", "ghost-extra==1.0"),
        ("sample-pkg==1.0",),
    ]
    recipe = json.loads(artifacts.read(result.recipe_ref))
    assert recipe["dependency_resolution_omitted_agent_requirements"] == [
        "ghost-extra==1.0"
    ]
    attempt_refs = recipe["dependency_resolution_omission_attempt_refs"]
    assert len(attempt_refs) == 1
    receipt = json.loads(artifacts.read(StoredDataRef.model_validate(attempt_refs[0])))
    assert receipt["error_code"] == "POC_AUTO_BUNDLE_DOWNLOAD_FAILED"


@pytest.mark.asyncio
async def test_auto_bundle_receipt_lists_every_removed_agent_constraint(
    tmp_path: Path,
) -> None:
    workspace, commit, bundle_path, _digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)

    class _UnavailableExtraDocker(_Docker):
        async def local_base_image_digest(self, base_image: str) -> str:
            if base_image == "sha256:" + "b" * 64:
                return base_image
            return await super().local_base_image_digest(base_image)

        async def download_python_wheels(
            self,
            *,
            base_image: str,
            requirements: tuple[str, ...],
            timeout_seconds: int,
        ) -> bytes:
            del base_image, timeout_seconds
            if any(value.startswith("ghost-extra") for value in requirements):
                raise DockerOperationError(
                    "POC_AUTO_BUNDLE_DOWNLOAD_FAILED",
                    DockerCommandOutcome(
                        1,
                        b"",
                        b"ERROR: No matching distribution found for ghost-extra>=1",
                        False,
                    ),
                )
            return bundle_path.read_bytes()

    result = await DirectEnvironmentPreparer(
        docker=_UnavailableExtraDocker(),  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        auto_dependency_bundle=True,
    ).prepare(
        checkpoint,
        {},
        ("python:3.12", "pip:ghost-extra>=1", "pip:ghost-extra!=2"),
    )
    recipe = json.loads(artifacts.read(result.recipe_ref))
    assert recipe["dependency_resolution_omitted_agent_requirements"] == [
        "ghost-extra>=1",
        "ghost-extra!=2",
    ]


@pytest.mark.asyncio
async def test_offline_repair_preflight_smokes_configured_local_image_without_mounts(
    tmp_path: Path,
) -> None:
    workspace, commit, path, wheel_digest = _fixture(tmp_path)
    artifacts, _ = _checkpoint(tmp_path, commit)
    selected_digest = "sha256:" + "d" * 64
    smoke_stdout = json.dumps(
        {
            "marker": "SASTSIMI_BROWSER_SMOKE_OK",
            "browser_command": "/usr/bin/chromium",
            "python_version": "3.12.15",
        }
    ).encode("utf-8")

    class _SmokeDocker(_Docker):
        def __init__(self) -> None:
            super().__init__()
            self.probes: list[str] = []
            self.run_args: tuple[str, ...] = ()

        async def local_base_image_digest(self, base_image: str) -> str:
            self.probes.append(base_image)
            return selected_digest

        async def _run(
            self,
            args: tuple[str, ...],
            *,
            timeout_seconds: int,
        ) -> DockerCommandOutcome:
            assert timeout_seconds <= 90
            self.run_args = args
            return DockerCommandOutcome(0, smoke_stdout, b"DBus warning", False)

    docker = _SmokeDocker()
    preparer = DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        wheel_bundle_path=path,
        wheel_bundle_sha256=wheel_digest,
        offline_base_image_digest=selected_digest,
    )

    smoke = await preparer.preflight_offline_repair()

    assert docker.probes == [selected_digest]
    assert docker.run_args[:4] == ("run", "--pull", "never", "--rm")
    assert ("--network", "none") == docker.run_args[4:6]
    assert "--read-only" in docker.run_args
    assert ("--user", "10001:10001") == docker.run_args[
        docker.run_args.index("--user") : docker.run_args.index("--user") + 2
    ]
    assert ("--cap-drop", "ALL") == docker.run_args[
        docker.run_args.index("--cap-drop") : docker.run_args.index("--cap-drop") + 2
    ]
    assert "--tmpfs" in docker.run_args
    assert ("--env", "HOME=/tmp") == docker.run_args[
        docker.run_args.index("HOME=/tmp") - 1 : docker.run_args.index("HOME=/tmp") + 1
    ]
    assert ("--env", "XDG_CACHE_HOME=/tmp/cache") == docker.run_args[
        docker.run_args.index("XDG_CACHE_HOME=/tmp/cache") - 1 : docker.run_args.index(
            "XDG_CACHE_HOME=/tmp/cache"
        )
        + 1
    ]
    assert "--mount" not in docker.run_args
    assert "--volume" not in docker.run_args
    assert selected_digest in docker.run_args
    assert smoke.base_image_digest == selected_digest
    assert smoke.browser_command == "/usr/bin/chromium"
    assert smoke.python_version == "3.12.15"
    assert (
        smoke.smoke_output_digest
        == "sha256:" + hashlib.sha256(smoke_stdout).hexdigest()
    )


@pytest.mark.asyncio
async def test_offline_repair_preflight_rejects_different_local_image_id(
    tmp_path: Path,
) -> None:
    workspace, commit, path, wheel_digest = _fixture(tmp_path)
    artifacts, _ = _checkpoint(tmp_path, commit)

    class _WrongDocker(_Docker):
        async def local_base_image_digest(self, base_image: str) -> str:
            assert base_image == "sha256:" + "d" * 64
            return "sha256:" + "b" * 64

        async def _run(self, *args: object, **kwargs: object) -> DockerCommandOutcome:
            raise AssertionError("must not run a different image")

    with pytest.raises(ValueError, match="POC_OFFLINE_BASE_IMAGE_CHANGED"):
        await DirectEnvironmentPreparer(
            docker=_WrongDocker(),  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            wheel_bundle_path=path,
            wheel_bundle_sha256=wheel_digest,
            offline_base_image_digest="sha256:" + "d" * 64,
        ).preflight_offline_repair()


@pytest.mark.asyncio
async def test_offline_repair_proof_rejects_profile_digest_change(
    tmp_path: Path,
) -> None:
    workspace, commit, path, wheel_digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    proof = artifacts.put_json(
        {
            "kind": "simple_offline_environment_repair",
            "identity": checkpoint.identity.model_dump(mode="json"),
            "new_base_image_digest": "sha256:" + "d" * 64,
        }
    )
    checkpoint = checkpoint.model_copy(
        update={
            "input_refs": (proof,),
            "input_hash": input_reference_hash((proof,)),
            "recovery_decision_refs": (proof,),
        }
    )
    docker = _Docker()

    with pytest.raises(ValueError, match="POC_OFFLINE_REPAIR_BASE_MISMATCH"):
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            wheel_bundle_path=path,
            wheel_bundle_sha256=wheel_digest,
            offline_base_image_digest="sha256:" + "e" * 64,
        ).prepare(checkpoint, {}, ())
    assert docker.calls == []


@pytest.mark.asyncio
async def test_offline_repair_rejects_unreadable_recovery_evidence(
    tmp_path: Path,
) -> None:
    workspace, commit, path, wheel_digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    damaged = artifacts.put_bytes(b"not-json", "application/json")
    checkpoint = checkpoint.model_copy(
        update={
            "input_refs": (damaged,),
            "input_hash": input_reference_hash((damaged,)),
            "recovery_decision_refs": (damaged,),
        }
    )

    with pytest.raises(ValueError, match="POC_OFFLINE_REPAIR_EVIDENCE_INVALID"):
        await DirectEnvironmentPreparer(
            docker=_Docker(),  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            wheel_bundle_path=path,
            wheel_bundle_sha256=wheel_digest,
            offline_base_image_digest="sha256:" + "d" * 64,
        ).prepare(checkpoint, {}, ())


def test_offline_repair_proof_stops_historical_rebuild_patch(
    tmp_path: Path,
) -> None:
    workspace, commit, path, wheel_digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    old_decision = artifacts.put_json(
        {
            "kind": "simple_recovery_decision",
            "identity": checkpoint.identity.model_dump(mode="json"),
            "decision": {
                "category": "ENVIRONMENT",
                "action": "REBUILD_ENVIRONMENT",
                "diagnosis": "old environment",
                "guidance": "historical patch",
                "environment_patch": "RUN python -m pip install pytest",
            },
        }
    )
    proof = artifacts.put_json(
        {
            "kind": "simple_offline_environment_repair",
            "identity": checkpoint.identity.model_dump(mode="json"),
            "new_base_image_digest": "sha256:" + "d" * 64,
        }
    )
    refs = (old_decision, proof)
    checkpoint = checkpoint.model_copy(
        update={
            "input_refs": refs,
            "input_hash": input_reference_hash(refs),
            "recovery_decision_refs": refs,
        }
    )
    preparer = DirectEnvironmentPreparer(
        docker=_Docker(),  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        wheel_bundle_path=path,
        wheel_bundle_sha256=wheel_digest,
        offline_base_image_digest="sha256:" + "d" * 64,
    )

    preparer._require_repair_base_digest(checkpoint)
    assert preparer._recovery_patch(checkpoint) == b""


@pytest.mark.asyncio
async def test_offline_base_preflight_rejects_missing_local_image(
    tmp_path: Path,
) -> None:
    workspace, commit, path, digest = _fixture(tmp_path)
    artifacts, _ = _checkpoint(tmp_path, commit)

    class _MissingBase(_Docker):
        async def local_base_image_digest(self, base_image: str) -> str:
            assert base_image == "python:3.12-slim"
            raise ValueError("POC_OFFLINE_BASE_IMAGE_UNAVAILABLE")

        async def pin_local_base(self, image_digest: str) -> str:
            raise AssertionError("must not tag a missing image")

    preparer = DirectEnvironmentPreparer(
        docker=_MissingBase(),  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        wheel_bundle_path=path,
        wheel_bundle_sha256=digest,
    )

    assert await preparer.offline_base_ready() is False


@pytest.mark.asyncio
async def test_bundle_mode_installs_without_index_or_build_network(
    tmp_path: Path,
) -> None:
    workspace, commit, path, digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    docker = _Docker()

    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        wheel_bundle_path=path,
        wheel_bundle_sha256=digest,
    ).prepare(checkpoint, {}, ())

    dockerfile, cache_key, context = docker.calls[0]
    assert b"--no-index" in dockerfile
    assert b"--find-links=/opt/sastsimi-wheels" in dockerfile
    assert b"apt-get" not in dockerfile
    assert b"FROM sastsimi-offline-base:" in dockerfile
    assert digest in cache_key
    assert context is not None
    recipe = json.loads(artifacts.read(result.recipe_ref))
    assert recipe["dockerfile_source"] == "GENERATED_OFFLINE_WHEELS"
    assert recipe["degraded"] is False
    assert recipe["base_image_digest"] == "sha256:" + "b" * 64
    assert recipe["wheel_archive_sha256"] == digest


@pytest.mark.asyncio
async def test_bundle_mode_rejects_bridge_setting(tmp_path: Path) -> None:
    workspace, commit, path, digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    docker = _Docker()
    docker._network = "default"
    with pytest.raises(ValueError, match="POC_OFFLINE_NETWORK_REQUIRED"):
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            wheel_bundle_path=path,
            wheel_bundle_sha256=digest,
        ).prepare(checkpoint, {}, ())
    assert docker.calls == []


@pytest.mark.asyncio
async def test_bundle_mode_blocks_without_local_linux_base(tmp_path: Path) -> None:
    workspace, commit, path, digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)

    class _MissingBase(_Docker):
        async def local_base_image_digest(self, base_image: str) -> str:
            del base_image
            raise ValueError("POC_OFFLINE_BASE_IMAGE_UNAVAILABLE")

    docker = _MissingBase()
    with pytest.raises(ValueError, match="POC_OFFLINE_BASE_IMAGE_UNAVAILABLE"):
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            wheel_bundle_path=path,
            wheel_bundle_sha256=digest,
        ).prepare(checkpoint, {}, ())
    assert docker.calls == []


def test_cache_separates_all_offline_recipe_inputs() -> None:
    baseline = dict(
        archive_sha256="a" * 64,
        manifest_sha256="b" * 64,
        commit_id="c" * 40,
        dockerfile_sha256="d" * 64,
        base_image_digest="sha256:" + "e" * 64,
        network="none",
    )
    initial = offline_recipe_cache_key(**baseline)
    for key in baseline:
        changed = dict(baseline)
        changed[key] = "different"
        assert offline_recipe_cache_key(**changed) != initial


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "diagnostic",
    [
        b"No matching distribution found for missing-transitive",
        b"ModuleNotFoundError: No module named 'setuptools_scm'",
    ],
)
async def test_missing_transitive_dependency_is_blocked_not_disproved(
    tmp_path: Path,
    diagnostic: bytes,
) -> None:
    workspace, commit, path, digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    docker = _Docker(diagnostic)
    with pytest.raises(
        DockerBuildAttemptsError, match="POC_OFFLINE_DEPENDENCY_MISSING"
    ) as blocked:
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            wheel_bundle_path=path,
            wheel_bundle_sha256=digest,
        ).prepare(checkpoint, {}, ())
    recipe = json.loads(artifacts.read(blocked.value.recipe_ref))
    assert recipe["status"] == "BLOCKED"
    assert recipe["degraded"] is False
    assert len(docker.calls) == 1


def test_offline_dockerfile_rejects_control_character_path() -> None:
    with pytest.raises(ValueError, match="POC_OFFLINE_MANIFEST_UNSUPPORTED"):
        DirectEnvironmentPreparer._offline_dockerfile(
            "module\nRUN echo unsafe/requirements.txt",
            "sastsimi-offline-base:" + "b" * 64,
        )


def test_offline_dockerfile_normalizes_zip_compatible_source_mtime() -> None:
    dockerfile = DirectEnvironmentPreparer._offline_dockerfile(
        "pyproject.toml", "sastsimi-offline-base:" + "b" * 64
    )
    normalize = b"RUN find /workspace -type f -exec touch -t 198001020000.00 {} +"
    install = b"RUN python -m pip install"
    assert normalize in dockerfile
    assert dockerfile.index(b"COPY . /workspace") < dockerfile.index(normalize)
    assert dockerfile.index(normalize) < dockerfile.index(install)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("manifest", "requirements"),
    [
        ("git+https://example.invalid/project.git\n", ()),
        ("sample-pkg @ https://example.invalid/pkg.tar.gz\n", ()),
        ("-r extra-requirements.txt\n", ()),
        ("sample-pkg==1.0\n", ("apt-get install libpq",)),
    ],
)
async def test_unsupported_uv_apt_vcs_and_sdist_are_blocked(
    tmp_path: Path, manifest: str, requirements: tuple[str, ...]
) -> None:
    workspace, commit, path, digest = _fixture(tmp_path, manifest)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    docker = _Docker()
    with pytest.raises(ValueError, match="POC_OFFLINE_REQUIREMENT_UNSUPPORTED"):
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            wheel_bundle_path=path,
            wheel_bundle_sha256=digest,
        ).prepare(checkpoint, {}, requirements)
    assert docker.calls == []


@pytest.mark.asyncio
async def test_uv_lock_install_route_is_explicitly_blocked(tmp_path: Path) -> None:
    workspace, _commit, path, digest = _fixture(tmp_path)
    (workspace / "requirements.txt").unlink()
    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "sample-pkg"\nversion = "1.0"\n[tool.uv]\nmanaged = true\n',
        encoding="utf-8",
    )
    (workspace / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    subprocess.run(("git", "-C", str(workspace), "add", "-A"), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "uv",
        ),
        check=True,
    )
    commit = (
        subprocess.check_output(("git", "-C", str(workspace), "rev-parse", "HEAD"))
        .decode("ascii")
        .strip()
    )
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    docker = _Docker()
    with pytest.raises(ValueError, match="POC_OFFLINE_REQUIREMENT_UNSUPPORTED"):
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            wheel_bundle_path=path,
            wheel_bundle_sha256=digest,
        ).prepare(checkpoint, {}, ())
    assert docker.calls == []


@pytest.mark.asyncio
async def test_unproven_agent_requirement_is_blocked(tmp_path: Path) -> None:
    workspace, commit, path, digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    docker = _Docker()
    with pytest.raises(ValueError, match="POC_OFFLINE_REQUIREMENT_UNSUPPORTED"):
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            wheel_bundle_path=path,
            wheel_bundle_sha256=digest,
        ).prepare(checkpoint, {}, ("ffmpeg",))
    assert docker.calls == []


@pytest.mark.asyncio
async def test_pinned_source_checkout_requirement_uses_tracked_python_file(
    tmp_path: Path,
) -> None:
    workspace, commit, path, digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    docker = _Docker()

    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        wheel_bundle_path=path,
        wheel_bundle_sha256=digest,
    ).prepare(
        checkpoint,
        {},
        ("python:3.12", f"Source checkout at commit {commit} containing app.py"),
    )

    assert json.loads(artifacts.read(result.recipe_ref))["status"] == "BUILT"
    assert len(docker.calls) == 1
    context_archive = docker.calls[0][2]
    assert context_archive is not None
    with tarfile.open(fileobj=io.BytesIO(context_archive), mode="r:") as context:
        assert "app.py" in context.getnames()


def test_pinned_source_checkout_requirement_accepts_sha256_commit() -> None:
    commit = "a" * 64
    assert DirectEnvironmentPreparer._offline_agent_requirements(
        (f"Source checkout at commit {commit} containing src/app.py",),
        commit_id=commit,
    ) == ((), ("src/app.py",))


def test_pinned_source_checkout_requirement_accepts_unicode_spaced_path() -> None:
    commit = "a" * 40
    assert DirectEnvironmentPreparer._offline_agent_requirements(
        (f"Source checkout at commit {commit} containing src/설정 파일.py",),
        commit_id=commit,
    ) == ((), ("src/설정 파일.py",))


def test_pinned_source_checkout_requirement_accepts_file_first_wording() -> None:
    commit = "a" * 40
    assert DirectEnvironmentPreparer._offline_agent_requirements(
        (f"Source checkout of src/app.py at commit {commit}",),
        commit_id=commit,
    ) == ((), ("src/app.py",))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "requirement_template",
    [
        "Source checkout at commit "
        "0000000000000000000000000000000000000000 containing app.py",
        "Source checkout at commit {commit} containing missing.py",
        "Source checkout at commit {commit} containing ../app.py",
        "Source checkout at commit {commit}, with its declared runtime "
        "dependencies installed",
        "A readable test file outside the app's root_path",
    ],
)
async def test_unproven_source_checkout_requirement_is_blocked(
    tmp_path: Path, requirement_template: str
) -> None:
    workspace, commit, path, digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    docker = _Docker()

    with pytest.raises(ValueError, match="POC_OFFLINE_REQUIREMENT_UNSUPPORTED"):
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            wheel_bundle_path=path,
            wheel_bundle_sha256=digest,
        ).prepare(checkpoint, {}, (requirement_template.format(commit=commit),))

    assert docker.calls == []


@pytest.mark.asyncio
async def test_untracked_python_file_does_not_satisfy_source_checkout(
    tmp_path: Path,
) -> None:
    workspace, commit, path, digest = _fixture(tmp_path)
    (workspace / "untracked.py").write_text("pass\n", encoding="utf-8")
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    docker = _Docker()

    with pytest.raises(ValueError, match="POC_OFFLINE_REQUIREMENT_UNSUPPORTED"):
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            wheel_bundle_path=path,
            wheel_bundle_sha256=digest,
        ).prepare(
            checkpoint,
            {},
            (f"Source checkout at commit {commit} containing untracked.py",),
        )

    assert docker.calls == []


@pytest.mark.asyncio
async def test_pip_inline_comment_is_accepted(tmp_path: Path) -> None:
    workspace, commit, path, digest = _fixture(tmp_path, "sample-pkg==1.0  # pinned\n")
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    docker = _Docker()
    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        wheel_bundle_path=path,
        wheel_bundle_sha256=digest,
    ).prepare(checkpoint, {}, ())
    assert json.loads(artifacts.read(result.recipe_ref))["status"] == "BUILT"


@pytest.mark.asyncio
async def test_unrelated_nested_uv_lock_does_not_block_project(tmp_path: Path) -> None:
    workspace, _commit, path, digest = _fixture(tmp_path)
    (workspace / "requirements.txt").unlink()
    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "sample-pkg"\nversion = "1.0"\n',
        encoding="utf-8",
    )
    (workspace / "other" / "uv.lock").parent.mkdir()
    (workspace / "other" / "uv.lock").write_text("version = 1\n")
    subprocess.run(("git", "-C", str(workspace), "add", "-A"), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "nested-uv",
        ),
        check=True,
    )
    commit = (
        subprocess.check_output(("git", "-C", str(workspace), "rev-parse", "HEAD"))
        .decode("ascii")
        .strip()
    )
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    docker = _Docker()
    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        wheel_bundle_path=path,
        wheel_bundle_sha256=digest,
    ).prepare(checkpoint, {}, ())
    assert json.loads(artifacts.read(result.recipe_ref))["status"] == "BUILT"


@pytest.mark.asyncio
async def test_explicit_python_requirement_is_installed_offline(tmp_path: Path) -> None:
    workspace, commit, path, digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    docker = _Docker()
    await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        wheel_bundle_path=path,
        wheel_bundle_sha256=digest,
    ).prepare(checkpoint, {}, ("pip: sample-pkg==1.0", "python:3.12"))
    dockerfile = docker.calls[0][0]
    assert b"--no-index --find-links=/opt/sastsimi-wheels" in dockerfile
    assert b"sample-pkg==1.0" in dockerfile


@pytest.mark.asyncio
async def test_ambiguous_dual_manifest_is_blocked(tmp_path: Path) -> None:
    workspace, _commit, path, digest = _fixture(tmp_path)
    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "sample-pkg"\nversion = "1.0"\n',
        encoding="utf-8",
    )
    subprocess.run(("git", "-C", str(workspace), "add", "pyproject.toml"), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "dual",
        ),
        check=True,
    )
    commit = (
        subprocess.check_output(("git", "-C", str(workspace), "rev-parse", "HEAD"))
        .decode("ascii")
        .strip()
    )
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    docker = _Docker()
    with pytest.raises(ValueError, match="POC_OFFLINE_MANIFEST_AMBIGUOUS"):
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
            wheel_bundle_path=path,
            wheel_bundle_sha256=digest,
        ).prepare(checkpoint, {}, ())
    assert docker.calls == []


@pytest.mark.asyncio
async def test_offline_dependency_failure_is_nonretryable_stage_block(
    tmp_path: Path,
) -> None:
    _workspace, commit, _path, _digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    prompts: list[bytes] = []

    class _Client:
        async def call(self, **kwargs: object) -> SimpleLLMCallResult:
            prompt = kwargs["prompt"]
            assert isinstance(prompt, bytes)
            prompts.append(prompt)
            return SimpleLLMCallResult(
                value={
                    "initial_assessment": "HOLD",
                    "rationale": "Needs a runtime check.",
                    "reproduction_goal": "Run a local test.",
                    "environment_requirements": [],
                    "unmet_external_prerequisites": [],
                    "supporting_refs": [],
                    "limitations": [],
                },
                prompt_digest="a" * 64,
                output_digest="b" * 64,
            )

    class _MissingDependency:
        offline_mode = True

        def validate_requirements(
            self, _requirements: tuple[str, ...], *, commit_id: str
        ) -> None:
            del commit_id

        async def prepare(self, *_args: object) -> None:
            raise ValueError("POC_OFFLINE_DEPENDENCY_MISSING")

    stage = InitialVerificationStage(
        _Client(),
        artifacts,
        _MissingDependency(),  # type: ignore[arg-type]
    )
    with pytest.raises(StageBlocked) as blocked:
        await stage(checkpoint, {})
    assert blocked.value.failure.code == "POC_OFFLINE_DEPENDENCY_MISSING"
    assert blocked.value.failure.retryable is False
    assert b"in-process PoC fixtures" in prompts[0]
    assert b"already provided by the pinned checkout" in prompts[0]
    assert b"pinned HTTP handler is not an external prerequisite" in prompts[0]


@pytest.mark.asyncio
async def test_initial_verification_retry_explains_offline_requirement_contract(
    tmp_path: Path,
) -> None:
    _workspace, commit, _path, _digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    prompts: list[bytes] = []

    class _Client:
        async def call(self, **kwargs: object) -> SimpleLLMCallResult:
            prompt = kwargs["prompt"]
            assert isinstance(prompt, bytes)
            prompts.append(prompt)
            return SimpleLLMCallResult(
                value={
                    "initial_assessment": "HOLD",
                    "rationale": "Needs a runtime check.",
                    "reproduction_goal": "Run a local command-injection test.",
                    "environment_requirements": [
                        "python:3.12",
                        "pip:Flask",
                        "GNU coreutils (provides ls with -R support)",
                    ],
                    "unmet_external_prerequisites": [],
                    "supporting_refs": [],
                    "limitations": [],
                },
                prompt_digest="a" * 64,
                output_digest="b" * 64,
            )

    class _OfflineValidator:
        offline_mode = True

        def validate_requirements(
            self, requirements: tuple[str, ...], *, commit_id: str
        ) -> None:
            DirectEnvironmentPreparer._offline_agent_requirements(
                requirements, commit_id=commit_id
            )

        async def prepare(
            self,
            current: StageCheckpoint,
            _prior: object,
            requirements: tuple[str, ...],
        ) -> None:
            DirectEnvironmentPreparer._offline_agent_requirements(
                requirements, commit_id=current.identity.commit_id
            )
            raise AssertionError("the invalid requirement must not be accepted")

    stage = InitialVerificationStage(
        _Client(),
        artifacts,
        _OfflineValidator(),  # type: ignore[arg-type]
    )
    for attempt_number in (1, 2):
        with pytest.raises(StageBlocked) as blocked:
            await stage(
                checkpoint.model_copy(update={"attempt_number": attempt_number}), {}
            )
        assert blocked.value.failure.code == "POC_OFFLINE_REQUIREMENT_UNSUPPORTED"
        assert len(blocked.value.failure.evidence_refs) == 2

    assert len(prompts) == 4
    assert b"On this retry" not in prompts[0]
    assert b"On this retry" not in prompts[1]
    assert b"On this retry" in prompts[2]
    assert b"pip:<PEP 508 requirement>" in prompts[2]
    assert b"Source checkout at commit" in prompts[2]
    assert commit.encode("ascii") in prompts[2]
    assert b"shell utilities already present in the base image" in prompts[2]
    assert b"unmet_external_prerequisites" in prompts[2]
    assert len(prompts[2]) - len(prompts[0]) < 1200


@pytest.mark.asyncio
async def test_initial_verification_reasks_once_for_invalid_offline_requirement(
    tmp_path: Path,
) -> None:
    workspace, commit, path, digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    prompts: list[bytes] = []
    schemas: list[object] = []
    responses: list[JsonValue] = [
        ["python:3.12", "pip:Flask", "GNU coreutils (provides ls with -R support)"],
        ["python:3.12", "pip:Flask"],
    ]

    class _Client:
        async def call(self, **kwargs: object) -> SimpleLLMCallResult:
            prompt = kwargs["prompt"]
            assert isinstance(prompt, bytes)
            prompts.append(prompt)
            schemas.append(kwargs["output_schema"])
            return SimpleLLMCallResult(
                value={
                    "initial_assessment": "TRUE",
                    "rationale": "Can run locally.",
                    "reproduction_goal": "Run a local test.",
                    "environment_requirements": responses.pop(0),
                    "unmet_external_prerequisites": [],
                    "supporting_refs": [],
                    "limitations": [],
                },
                prompt_digest="a" * 64,
                output_digest="b" * 64,
            )

    class _Environment(DirectEnvironmentPreparer):
        async def prepare(
            self,
            _checkpoint: StageCheckpoint,
            _prior: object,
            requirements: tuple[str, ...],
        ) -> ReproductionEnvironment:
            assert requirements == ("python:3.12", "pip:Flask")
            return ReproductionEnvironment(
                recipe_ref=artifacts.put_json({"kind": "test_offline_recipe"}),
                image_digest="sha256:" + "c" * 64,
            )

    environment = _Environment(
        docker=_Docker(),  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        wheel_bundle_path=path,
        wheel_bundle_sha256=digest,
    )
    result = await InitialVerificationStage(_Client(), artifacts, environment)(
        checkpoint, {}
    )

    assert result.recipe_ref is not None
    assert len(prompts) == 2
    assert schemas[0] == schemas[1]
    assert b"POC_OFFLINE_REQUIREMENT_UNSUPPORTED" in prompts[1]
    assert b"pip:<PEP 508 requirement>" in prompts[1]
    assert responses == []
    assert len(result.activity_events) == 2
    rejected_event, accepted_event = result.activity_events
    assert rejected_event.kind is ActivityKind.EVIDENCE_RECORDED
    assert rejected_event.sequence % 100 == 9
    assert accepted_event.kind is ActivityKind.DECISION_RECORDED
    assert accepted_event.sequence % 100 == 10
    assert accepted_event.output_refs == result.output_refs
    assert len(rejected_event.output_refs) == 1
    assert rejected_event.output_refs[0] not in result.output_refs
    rejected = json.loads(artifacts.read(rejected_event.output_refs[0]))
    assert rejected["result"]["environment_requirements"] == [
        "python:3.12",
        "pip:Flask",
        "GNU coreutils (provides ls with -R support)",
    ]
    assert "GNU coreutils" not in rejected_event.summary_ko


@pytest.mark.asyncio
@pytest.mark.parametrize("failure_mode", ("prepare", "provider"))
async def test_rejected_offline_requirement_remains_failure_evidence(
    tmp_path: Path, failure_mode: str
) -> None:
    workspace, commit, path, digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    raw_failure_ref = artifacts.put_bytes(b"provider response", "text/plain")
    calls = 0

    class _Client:
        async def call(self, **_kwargs: object) -> SimpleLLMCallResult | StageFailure:
            nonlocal calls
            calls += 1
            if calls == 2 and failure_mode == "provider":
                return StageFailure(
                    code="INVALID_OUTPUT",
                    retryable=False,
                    safe_message="Second response was invalid",
                    evidence_refs=(raw_failure_ref,),
                )
            requirements: JsonValue = (
                ["python:3.12", "pip:Flask", "GNU coreutils"]
                if calls == 1
                else ["python:3.12", "pip:Flask"]
            )
            return SimpleLLMCallResult(
                value={
                    "initial_assessment": "TRUE",
                    "rationale": "Can run locally.",
                    "reproduction_goal": "Run a local test.",
                    "environment_requirements": requirements,
                    "unmet_external_prerequisites": [],
                    "supporting_refs": [],
                    "limitations": [],
                },
                prompt_digest="a" * 64,
                output_digest="b" * 64,
            )

    class _Environment(DirectEnvironmentPreparer):
        async def prepare(
            self,
            _checkpoint: StageCheckpoint,
            _prior: object,
            requirements: tuple[str, ...],
        ) -> ReproductionEnvironment:
            assert failure_mode == "prepare"
            assert requirements == ("python:3.12", "pip:Flask")
            raise ValueError("POC_OFFLINE_MANIFEST_UNSUPPORTED")

    environment = _Environment(
        docker=_Docker(),  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        wheel_bundle_path=path,
        wheel_bundle_sha256=digest,
    )
    failure_type = StageBlocked if failure_mode == "prepare" else StageFailed
    with pytest.raises(failure_type) as caught:
        await InitialVerificationStage(_Client(), artifacts, environment)(
            checkpoint, {}
        )

    assert calls == 2
    assert isinstance(caught.value, (StageBlocked, StageFailed))
    evidence_refs = caught.value.failure.evidence_refs
    assert len(evidence_refs) == 2
    rejected = json.loads(artifacts.read(evidence_refs[0]))
    assert rejected["result"]["environment_requirements"] == [
        "python:3.12",
        "pip:Flask",
        "GNU coreutils",
    ]
    if failure_mode == "provider":
        assert evidence_refs[1] == raw_failure_ref


@pytest.mark.asyncio
async def test_offline_preparer_without_requirement_validator_fails_closed(
    tmp_path: Path,
) -> None:
    _workspace, commit, _path, _digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)

    class _Client:
        async def call(self, **_kwargs: object) -> SimpleLLMCallResult:
            raise AssertionError("offline preflight must fail before an LLM call")

    class _BrokenOffline:
        offline_mode = True

        async def prepare(
            self,
            _checkpoint: StageCheckpoint,
            _prior: Mapping[SimpleStage, StageCheckpoint],
            _requirements: tuple[str, ...],
        ) -> ReproductionEnvironment:
            raise AssertionError("offline requirements must be validated first")

    stage = InitialVerificationStage(_Client(), artifacts, _BrokenOffline())
    with pytest.raises(StageBlocked) as blocked:
        await stage(checkpoint, {})
    code = blocked.value.failure.code
    assert code == "POC_OFFLINE_REQUIREMENT_VALIDATION_UNAVAILABLE"
    assert blocked.value.failure.retryable is False


@pytest.mark.asyncio
async def test_non_offline_retry_does_not_impose_offline_requirement_contract(
    tmp_path: Path,
) -> None:
    _workspace, commit, _path, _digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    prompts: list[bytes] = []

    class _Client:
        async def call(self, **kwargs: object) -> SimpleLLMCallResult:
            prompt = kwargs["prompt"]
            assert isinstance(prompt, bytes)
            prompts.append(prompt)
            return SimpleLLMCallResult(
                value={
                    "initial_assessment": "HOLD",
                    "rationale": "An external service is needed.",
                    "reproduction_goal": "Check the service integration.",
                    "environment_requirements": [],
                    "unmet_external_prerequisites": ["external service unavailable"],
                    "supporting_refs": [],
                    "limitations": [],
                },
                prompt_digest="a" * 64,
                output_digest="b" * 64,
            )

    class _OnlineEnvironment:
        offline_mode = False

        async def prepare(self, *_args: object) -> None:
            raise AssertionError("external prerequisite must remain a HOLD")

    result = await InitialVerificationStage(
        _Client(),
        artifacts,
        _OnlineEnvironment(),  # type: ignore[arg-type]
    )(checkpoint.model_copy(update={"attempt_number": 2}), {})

    assert result.verdict == "HOLD"
    assert len(prompts) == 1
    assert b"On this retry" not in prompts[0]


@pytest.mark.asyncio
async def test_unmet_attack_prerequisite_is_inconclusive_without_preparing(
    tmp_path: Path,
) -> None:
    _workspace, commit, _path, _digest = _fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)

    class _Client:
        async def call(self, **_kwargs: object) -> SimpleLLMCallResult:
            return SimpleLLMCallResult(
                value={
                    "initial_assessment": "HOLD",
                    "rationale": "The attacker-controlled setting is not established.",
                    "reproduction_goal": "Verify process startup control.",
                    "environment_requirements": ["python:3.12"],
                    "unmet_external_prerequisites": [
                        "attacker can set the target process PYTHONSTARTUP"
                    ],
                    "supporting_refs": [],
                    "limitations": ["No proof of attacker control"],
                },
                prompt_digest="a" * 64,
                output_digest="b" * 64,
            )

    class _NeverPrepare:
        async def prepare(self, *_args: object) -> None:
            raise AssertionError("unmet attack precondition cannot be built away")

    result = await InitialVerificationStage(
        _Client(),
        artifacts,
        _NeverPrepare(),  # type: ignore[arg-type]
    )(checkpoint, {})

    assert result.verdict == "HOLD"
    assert result.external_prerequisites_ref == result.output_refs[0]
    assert result.recipe_ref is None
    assert len(result.output_refs) == 1
