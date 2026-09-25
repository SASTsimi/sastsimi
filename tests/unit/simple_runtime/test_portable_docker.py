import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.sandbox.docker_adapter import (
    DockerCommandOutcome,
    DockerOperationError,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.portable_docker import (
    DirectEnvironmentPreparer,
    PortableDockerRuntime,
)


class _RecordingPortableDockerRuntime(PortableDockerRuntime):
    calls: list[tuple[str, ...]]

    async def _run(
        self,
        args: Sequence[str],
        *,
        timeout_seconds: int,
        input_bytes: bytes | None = None,
    ) -> DockerCommandOutcome:
        del timeout_seconds, input_bytes
        call = tuple(args)
        self.calls.append(call)
        return DockerCommandOutcome(
            exit_code=0,
            stdout=(b"container-1\n" if call[0] == "create" else b""),
            stderr=b"",
            timed_out=False,
        )


def test_target_environment_change_invalidates_initial_verification() -> None:
    assert STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE] == "2"


@pytest.mark.asyncio
async def test_reproduction_container_keeps_baked_workspace_writable() -> None:
    runtime = _RecordingPortableDockerRuntime.__new__(_RecordingPortableDockerRuntime)
    runtime._executable = Path("docker")
    runtime._network = "none"
    runtime._timeout = 60
    runtime.calls = []
    await runtime.create_container("sha256:" + "a" * 64, {})

    create = runtime.calls[0]
    assert create[0] == "create"
    assert "--read-only" not in create
    assert "--network" in create
    assert "no-new-privileges" in create


def test_repository_buster_dockerfile_uses_archive_mirrors_before_apt() -> None:
    original = (
        b"FROM python:3.11.0b1-buster\n"
        b"RUN apt-get update && apt-get install -y dnsutils\n"
    )

    prepared = DirectEnvironmentPreparer._portable_repository_dockerfile(original)

    assert b"archive.debian.org/debian" in prepared
    assert b"Acquire::Check-Valid-Until" in prepared
    assert prepared.index(b"archive.debian.org") < prepared.index(b"apt-get update")


def test_target_requirements_are_resolved_from_exact_hypothesis(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    target = workspace / "nested" / "lab"
    target.mkdir(parents=True)
    (target / "main.py").write_text("print('target')\n", encoding="utf-8")
    (target / "requirements.txt").write_text("Flask==3.0.0\n", encoding="utf-8")
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    hypothesis_ref = artifacts.put_json(
        {
            "kind": "simple_hypothesis_proposal",
            "proposal": {"code_locations": ["nested/lab/main.py:1"]},
        }
    )
    input_refs = (hypothesis_ref,)
    pro_con = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=input_refs,
        input_hash=input_reference_hash(input_refs),
    )
    preparer = DirectEnvironmentPreparer(
        docker=object(),  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    )

    resolved = preparer._target_requirements_path({SimpleStage.PRO_CON_DONE: pro_con})

    assert resolved == "nested/lab/requirements.txt"


def _preparer_for(workspace: Path) -> DirectEnvironmentPreparer:
    preparer = DirectEnvironmentPreparer.__new__(DirectEnvironmentPreparer)
    preparer._workspace = workspace
    return preparer


_PACKAGE = '[project]\nname = "thing"\nversion = "1"\n'
_WORKSPACE_ONLY = '[tool.mypy]\npython_version = "3.12"\n'


def test_a_repository_root_that_is_a_package_is_installed(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(_PACKAGE, encoding="utf-8")

    assert _preparer_for(tmp_path)._installable_directory() == "."
    assert (
        b"pip install --no-cache-dir ."
        in _preparer_for(tmp_path)._generated_dockerfile()
    )


def test_a_monorepo_root_installs_its_one_package_instead(tmp_path: Path) -> None:
    # The root only configures tools, so installing it makes setuptools guess a
    # flat layout across every sibling directory and fail the whole build.
    (tmp_path / "pyproject.toml").write_text(_WORKSPACE_ONLY, encoding="utf-8")
    (tmp_path / "backend").mkdir()
    (tmp_path / "backend" / "pyproject.toml").write_text(_PACKAGE, encoding="utf-8")
    (tmp_path / "frontend").mkdir()
    (tmp_path / "cypress").mkdir()

    assert _preparer_for(tmp_path)._installable_directory() == "backend"
    assert (
        b"pip install --no-cache-dir backend"
        in _preparer_for(tmp_path)._generated_dockerfile()
    )


def test_an_ambiguous_layout_skips_the_install_layer(tmp_path: Path) -> None:
    # A failed build blocks every hypothesis, so an unclear layout installs
    # nothing rather than guessing which package the run needs.
    (tmp_path / "pyproject.toml").write_text(_WORKSPACE_ONLY, encoding="utf-8")
    for name in ("one", "two"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "pyproject.toml").write_text(_PACKAGE, encoding="utf-8")

    assert _preparer_for(tmp_path)._installable_directory() is None
    assert b"pip install" not in _preparer_for(tmp_path)._generated_dockerfile()


def test_requirements_still_win_over_a_package_directory(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(_PACKAGE, encoding="utf-8")

    dockerfile = _preparer_for(tmp_path)._generated_dockerfile()

    assert b"pip install --no-cache-dir -r requirements.txt" in dockerfile


def test_an_unreadable_pyproject_is_not_treated_as_a_package(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[project\nbroken", encoding="utf-8")

    assert _preparer_for(tmp_path)._installable_directory() is None


class _FailingInstallDocker:
    """Fails any build carrying an install layer, the way a missing toolchain does."""

    def __init__(self) -> None:
        self.attempts: list[bytes] = []

    async def build_or_reuse(
        self,
        *,
        workspace: Path,
        dockerfile: bytes,
        cache_key: str,
        labels: dict[str, str],
    ) -> str:
        self.attempts.append(dockerfile)
        if b"pip install" in dockerfile:
            raise DockerOperationError("DOCKER_BUILD_FAILED")
        return "sha256:" + "a" * 64


@pytest.mark.asyncio
async def test_a_failed_install_falls_back_to_the_source_only_image(
    tmp_path: Path,
) -> None:
    # open-webui's own build backend needs npm, which a plain Python image has
    # not got.  The checkout is copied in either way, so the run must continue
    # on a source-only image instead of blocking every hypothesis.
    workspace = tmp_path / "repo"
    workspace.mkdir()
    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "thing"\nversion = "1"\n', encoding="utf-8"
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    docker = _FailingInstallDocker()
    preparer = DirectEnvironmentPreparer(
        docker=cast(Any, docker), artifacts=artifacts, workspace=workspace
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-1",
    )

    environment = await preparer.prepare(checkpoint, {}, ())

    assert len(docker.attempts) == 2
    assert b"pip install" in docker.attempts[0]
    assert b"pip install" not in docker.attempts[1]
    recipe = json.loads(artifacts.read(environment.recipe_ref))
    # The recipe says the environment is bare, so the agent is not left to
    # assume dependencies it does not have.
    assert recipe["dockerfile_source"] == "GENERATED_NO_INSTALL"
    assert environment.image_digest == "sha256:" + "a" * 64


@pytest.mark.asyncio
async def test_a_build_that_fails_without_an_install_still_raises(
    tmp_path: Path,
) -> None:
    class _AlwaysFails(_FailingInstallDocker):
        async def build_or_reuse(self, **kwargs: Any) -> str:
            self.attempts.append(kwargs["dockerfile"])
            raise DockerOperationError("DOCKER_BUILD_FAILED")

    workspace = tmp_path / "repo"
    workspace.mkdir()
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    preparer = DirectEnvironmentPreparer(
        docker=cast(Any, _AlwaysFails()),
        artifacts=SimpleArtifactRepository(tmp_path / "data", identity),
        workspace=workspace,
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-1",
    )

    with pytest.raises(DockerOperationError):
        await preparer.prepare(checkpoint, {}, ())


@pytest.mark.asyncio
async def test_a_dockerfile_that_failed_once_is_not_built_again(
    tmp_path: Path,
) -> None:
    # One target compiles a frontend and downloads model weights before failing,
    # so retrying it per hypothesis costs the run hours for a known outcome.
    DirectEnvironmentPreparer._unbuildable.clear()
    workspace = tmp_path / "repo"
    workspace.mkdir()
    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "thing"\nversion = "1"\n', encoding="utf-8"
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    docker = _FailingInstallDocker()
    preparer = DirectEnvironmentPreparer(
        docker=cast(Any, docker),
        artifacts=SimpleArtifactRepository(tmp_path / "data", identity),
        workspace=workspace,
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-1",
    )

    await preparer.prepare(checkpoint, {}, ())
    assert len(docker.attempts) == 2

    await preparer.prepare(checkpoint, {}, ())

    # The second hypothesis goes straight to the image that works.
    assert len(docker.attempts) == 3
    assert b"pip install" not in docker.attempts[2]
    DirectEnvironmentPreparer._unbuildable.clear()
