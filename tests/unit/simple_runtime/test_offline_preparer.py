"""Opt-in, networkless PoC dependency environment tests."""

from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tarfile
import zipfile
from collections.abc import Mapping
from pathlib import Path

import pytest

from sastsimi.sandbox.docker_adapter import DockerCommandOutcome, DockerOperationError
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.portable_docker import (
    DirectEnvironmentPreparer,
    DockerBuildAttemptsError,
    offline_recipe_cache_key,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.runner import StageBlocked
from sastsimi.simple_runtime.stages import InitialVerificationStage


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

    class _Client:
        async def call(self, **_kwargs: object) -> SimpleLLMCallResult:
            return SimpleLLMCallResult(
                value={
                    "initial_assessment": "HOLD",
                    "rationale": "Needs a runtime check.",
                    "reproduction_goal": "Run a local test.",
                    "environment_requirements": [],
                    "supporting_refs": [],
                    "limitations": [],
                },
                prompt_digest="a" * 64,
                output_digest="b" * 64,
            )

    class _MissingDependency:
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
