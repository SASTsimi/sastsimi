import asyncio
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from sastsimi.config.user_config import (
    ElapsedLimit,
    SimpleExecutionProfile,
    SimpleToolBinding,
)
from sastsimi.ports.docker_state import DockerContainerState
from sastsimi.sandbox.docker_adapter import DockerCommandOutcome, DockerOperationError
from sastsimi.sandbox.recipe_store import EnvironmentRecipeStore
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.portable_docker import (
    DirectEnvironmentPreparer,
    PortableDockerRuntime,
    build_pinned_context,
)
from sastsimi.simple_runtime.recovery import (
    RecoveryAction,
    RecoveryCategory,
    RecoveryDecision,
    RecoveryResolution,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore


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


class _BuildFailurePortableDockerRuntime(PortableDockerRuntime):
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []
        self._network = "none"
        self._timeout = 60

    async def _run(
        self,
        args: Sequence[str],
        *,
        timeout_seconds: int,
        input_bytes: bytes | None = None,
    ) -> DockerCommandOutcome:
        del timeout_seconds, input_bytes
        self.calls.append(tuple(args))
        return DockerCommandOutcome(
            exit_code=1,
            stdout=b"",
            stderr=b"uv sync: Git executable not found\n",
            timed_out=False,
        )


class _OwnedListDocker(PortableDockerRuntime):
    def __init__(self, outcomes: list[DockerCommandOutcome]) -> None:
        self.outcomes = iter(outcomes)
        self.calls: list[tuple[str, ...]] = []

    async def _run(
        self,
        args: Sequence[str],
        *,
        timeout_seconds: int,
        input_bytes: bytes | None = None,
    ) -> DockerCommandOutcome:
        assert timeout_seconds == 30
        assert input_bytes is None
        self.calls.append(tuple(args))
        return next(self.outcomes)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    [
        DockerCommandOutcome(1, b"", b"daemon unavailable", False),
        DockerCommandOutcome(-1, b"", b"", True),
    ],
)
async def test_owned_container_list_retries_one_failed_read_only_call(
    failure: DockerCommandOutcome,
) -> None:
    docker = _OwnedListDocker([failure, DockerCommandOutcome(0, b"", b"", False)])

    assert await docker.sweep_orphans() == ()
    assert docker.calls == [
        ("ps", "--all", "--quiet", "--filter", "label=sastsimi.owner=simple-runtime"),
        ("ps", "--all", "--quiet", "--filter", "label=sastsimi.owner=simple-runtime"),
    ]


@pytest.mark.asyncio
async def test_owned_container_list_stops_after_three_failures() -> None:
    failures = [
        DockerCommandOutcome(1, b"", b"daemon unavailable", False),
        DockerCommandOutcome(-1, b"", b"timeout", True),
        DockerCommandOutcome(2, b"", b"still unavailable", False),
    ]
    docker = _OwnedListDocker(failures)

    with pytest.raises(DockerOperationError) as caught:
        await docker.sweep_orphans()

    assert caught.value.code == "DOCKER_OWNED_LIST_FAILED"
    assert caught.value.outcome == failures[-1]
    assert len(docker.calls) == 3
    assert set(docker.calls) == {
        ("ps", "--all", "--quiet", "--filter", "label=sastsimi.owner=simple-runtime")
    }


@pytest.mark.asyncio
async def test_owned_container_list_success_does_not_retry() -> None:
    docker = _OwnedListDocker([DockerCommandOutcome(0, b"", b"", False)])

    assert await docker.sweep_orphans() == ()
    assert len(docker.calls) == 1


@pytest.mark.asyncio
async def test_timed_out_docker_command_waits_for_direct_process_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = PortableDockerRuntime.__new__(PortableDockerRuntime)
    runtime._executable = Path(sys.executable)
    spawn = asyncio.create_subprocess_exec
    processes: list[asyncio.subprocess.Process] = []

    async def capture_spawn(
        executable: str,
        *args: str,
        stdin: int,
        stdout: int,
        stderr: int,
        env: Mapping[str, str],
    ) -> asyncio.subprocess.Process:
        process = await spawn(
            executable,
            *args,
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
            env=env,
        )
        processes.append(process)
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", capture_spawn)

    outcome = await runtime._run(
        ("-c", "import time; time.sleep(60)"), timeout_seconds=0
    )

    assert outcome.timed_out is True
    assert processes[0].returncode is not None


_FULL_CONTAINER_ID = "a" * 64


def _owned_attempt_identity() -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="analysis-owned-attempt",
        workspace_id="workspace-owned-attempt",
        commit_id="b" * 40,
        hypothesis_id="hypothesis-owned-attempt",
    )


def _owned_attempt_state(
    container_id: str, labels: Mapping[str, str]
) -> DockerContainerState:
    return DockerContainerState(
        container_id=container_id,
        image_digest="sha256:" + "c" * 64,
        user="10001:10001",
        network_mode="none",
        privileged=False,
        read_only_rootfs=False,
        running=False,
        exit_code=0,
        health_status=None,
        labels=labels,
    )


class _OwnedAttemptDocker(PortableDockerRuntime):
    def __init__(
        self,
        outcome: DockerCommandOutcome,
        states: Mapping[str, DockerContainerState],
    ) -> None:
        self.outcome = outcome
        self.states = states
        self.calls: list[tuple[str, ...]] = []
        self.inspected: list[str] = []

    async def _run(
        self,
        args: Sequence[str],
        *,
        timeout_seconds: int,
        input_bytes: bytes | None = None,
    ) -> DockerCommandOutcome:
        assert timeout_seconds == 30
        assert input_bytes is None
        self.calls.append(tuple(args))
        return self.outcome

    async def inspect(self, container_id: str) -> DockerContainerState:
        self.inspected.append(container_id)
        return self.states[container_id]


@pytest.mark.asyncio
async def test_owned_attempt_absence_requires_exact_successful_list() -> None:
    identity = _owned_attempt_identity()
    docker = _OwnedAttemptDocker(DockerCommandOutcome(0, b"", b"", False), {})

    assert await docker.has_owned_attempt_container(identity, "attempt-owned") is False
    assert docker.calls == [
        (
            "ps",
            "--all",
            "--quiet",
            "--no-trunc",
            "--filter",
            "label=sastsimi.owner=simple-runtime",
            "--filter",
            "label=sastsimi.analysis-id=analysis-owned-attempt",
            "--filter",
            "label=sastsimi.workspace-id=workspace-owned-attempt",
            "--filter",
            "label=sastsimi.commit-id=" + "b" * 40,
            "--filter",
            "label=sastsimi.hypothesis-id=hypothesis-owned-attempt",
            "--filter",
            "label=sastsimi.attempt-id=attempt-owned",
        )
    ]
    assert docker.inspected == []


@pytest.mark.asyncio
async def test_owned_attempt_presence_requires_inspected_matching_labels() -> None:
    identity = _owned_attempt_identity()
    expected = PortableDockerRuntime._owner_labels(identity, "attempt-owned")
    docker = _OwnedAttemptDocker(
        DockerCommandOutcome(0, (_FULL_CONTAINER_ID + "\n").encode(), b"", False),
        {_FULL_CONTAINER_ID: _owned_attempt_state(_FULL_CONTAINER_ID, expected)},
    )

    assert await docker.has_owned_attempt_container(identity, "attempt-owned") is True
    assert docker.inspected == [_FULL_CONTAINER_ID]
    assert len(docker.calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("outcome", "expected_calls"),
    [
        (DockerCommandOutcome(1, b"", b"daemon unavailable", False), 3),
        (DockerCommandOutcome(-1, b"", b"", True), 3),
        (DockerCommandOutcome(0, b"z" * (1024 * 1024), b"", False), 1),
        (DockerCommandOutcome(0, b"not-a-docker-id\n", b"", False), 1),
    ],
)
async def test_owned_attempt_query_failures_never_prove_absence(
    outcome: DockerCommandOutcome,
    expected_calls: int,
) -> None:
    docker = _OwnedAttemptDocker(outcome, {})

    with pytest.raises(DockerOperationError):
        await docker.has_owned_attempt_container(
            _owned_attempt_identity(), "attempt-owned"
        )
    assert len(docker.calls) == expected_calls


@pytest.mark.asyncio
async def test_owned_attempt_mismatched_inspect_fails_closed() -> None:
    identity = _owned_attempt_identity()
    labels = {
        **PortableDockerRuntime._owner_labels(identity, "attempt-owned"),
        "sastsimi.attempt-id": "other-attempt",
    }
    docker = _OwnedAttemptDocker(
        DockerCommandOutcome(0, (_FULL_CONTAINER_ID + "\n").encode(), b"", False),
        {_FULL_CONTAINER_ID: _owned_attempt_state(_FULL_CONTAINER_ID, labels)},
    )

    with pytest.raises(DockerOperationError, match="DOCKER_OWNED_ATTEMPT_MISMATCH"):
        await docker.has_owned_attempt_container(identity, "attempt-owned")


@pytest.mark.asyncio
async def test_owned_attempt_rejects_filter_delimiters() -> None:
    identity = _owned_attempt_identity().model_copy(
        update={"analysis_id": "analysis-owned-attempt,other"}
    )
    docker = _OwnedAttemptDocker(DockerCommandOutcome(0, b"", b"", False), {})

    with pytest.raises(ValueError, match="DOCKER_OWNER_LABELS_INVALID"):
        await docker.has_owned_attempt_container(identity, "attempt-owned")

    assert docker.calls == []


@pytest.mark.asyncio
async def test_failed_docker_build_keeps_diagnostic_output() -> None:
    docker = _BuildFailurePortableDockerRuntime()

    with pytest.raises(DockerOperationError) as failure:
        await docker.build_or_reuse(
            workspace=Path.cwd(),
            dockerfile=b"FROM python:3.12-slim\n",
            cache_key="diagnostic-build",
            labels={},
        )

    assert "--quiet" not in docker.calls[1]
    assert failure.value.outcome is not None
    assert b"Git executable not found" in failure.value.outcome.stderr


class _ArchiveDocker(PortableDockerRuntime):
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], bytes | None]] = []
        self._network = "none"
        self._timeout = 60

    async def _run(
        self,
        args: Sequence[str],
        *,
        timeout_seconds: int,
        input_bytes: bytes | None = None,
    ) -> DockerCommandOutcome:
        del timeout_seconds
        call = tuple(args)
        self.calls.append((call, input_bytes))
        if call[:2] == ("buildx", "inspect"):
            return DockerCommandOutcome(
                0, b"Name: desktop-linux\nDriver: docker\n", b"", False
            )
        if call[:2] == ("image", "inspect"):
            return DockerCommandOutcome(1, b"", b"not found", False)
        return DockerCommandOutcome(0, b"", b"", False)


class _TargetProbeDocker(_ArchiveDocker):
    async def _run(
        self,
        args: Sequence[str],
        *,
        timeout_seconds: int,
        input_bytes: bytes | None = None,
    ) -> DockerCommandOutcome:
        del timeout_seconds
        call = tuple(args)
        self.calls.append((call, input_bytes))
        if call[:2] == ("image", "inspect"):
            return DockerCommandOutcome(
                0, b"linux|amd64|sha256:" + b"a" * 64 + b"\n", b"", False
            )
        if call[0] == "run":
            return DockerCommandOutcome(
                0,
                b'["cp312-cp312-manylinux_2_17_x86_64", "py3-none-any"]\n',
                b"",
                False,
            )
        raise AssertionError(call)


@pytest.mark.asyncio
async def test_target_tags_are_probed_inside_local_networkless_linux_image() -> None:
    docker = _TargetProbeDocker()

    tags = await docker.target_wheel_tags("python:3.12-slim")

    assert tags is not None
    assert "cp312-cp312-manylinux_2_17_x86_64" in tags
    run = docker.calls[1][0]
    assert run[:3] == ("run", "--pull", "never")
    assert ("--network", "none") == run[
        run.index("--network") : run.index("--network") + 2
    ]
    assert "--mount" not in run
    assert run[run.index("--entrypoint") : run.index("--entrypoint") + 2] == (
        "--entrypoint",
        "python",
    )


@pytest.mark.asyncio
async def test_python_version_probe_overrides_image_entrypoint() -> None:
    class _VersionProbeDocker(PortableDockerRuntime):
        def __init__(self) -> None:
            self.command: tuple[str, ...] = ()

        async def _run(
            self,
            args: Sequence[str],
            *,
            timeout_seconds: int,
            input_bytes: bytes | None = None,
        ) -> DockerCommandOutcome:
            del timeout_seconds, input_bytes
            self.command = tuple(args)
            return DockerCommandOutcome(0, b"3.6.15\n", b"", False)

    docker = _VersionProbeDocker()
    assert await docker._probe_python_version("sha256:" + "a" * 64) == "3.6.15"
    assert docker.command[
        docker.command.index("--entrypoint") : docker.command.index("--entrypoint") + 2
    ] == ("--entrypoint", "python")


def _committed_workspace(tmp_path: Path) -> tuple[Path, str]:
    workspace = tmp_path / "checkout"
    workspace.mkdir()
    (workspace / "app.py").write_text("print('pinned')\n", encoding="utf-8")
    (workspace / "requirements.txt").write_text("sample-pkg==1.0\n", encoding="utf-8")
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
    commit = subprocess.check_output(("git", "-C", str(workspace), "rev-parse", "HEAD"))
    return workspace, commit.decode("ascii").strip()


def test_archive_context_has_only_pinned_checkout_and_wheels(tmp_path: Path) -> None:
    workspace, commit = _committed_workspace(tmp_path)
    (workspace / "untracked-secret.txt").write_text("do not include", encoding="utf-8")
    wheel = b"wheel-bytes"

    raw = build_pinned_context(
        workspace,
        commit,
        b"FROM python:3.12-slim\n",
        {"sample_pkg-1.0-py3-none-any.whl": wheel},
    )

    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        names = {member.name for member in archive}
        assert names == {
            "Dockerfile",
            "app.py",
            "requirements.txt",
            "wheels/sample_pkg-1.0-py3-none-any.whl",
        }
        app_file = archive.extractfile("app.py")
        wheel_file = archive.extractfile("wheels/sample_pkg-1.0-py3-none-any.whl")
        assert app_file is not None
        assert wheel_file is not None
        assert app_file.read() == b"print('pinned')\n"
        assert wheel_file.read() == wheel


def test_root_node_manifest_does_not_hide_python_subproject(
    tmp_path: Path,
) -> None:
    workspace, _commit = _committed_workspace(tmp_path)
    backend = workspace / "backend"
    backend.mkdir()
    (workspace / "requirements.txt").replace(backend / "requirements.txt")
    (backend / "service.py").write_text("print('backend')\n", encoding="utf-8")
    (workspace / "package.json").write_text('{"name":"monorepo"}\n', encoding="utf-8")
    ui = workspace / "ui"
    ui.mkdir()
    (ui / "package.json").write_text('{"name":"ui"}\n', encoding="utf-8")
    (ui / ".npmrc").write_text("token=not-for-python\n", encoding="utf-8")
    subprocess.run(
        ("git", "-C", str(workspace), "rm", "-q", "requirements.txt"),
        check=True,
    )
    commit = _commit_fixture(workspace, "node root with python backend")

    raw = build_pinned_context(
        workspace,
        commit,
        b"FROM python:3.12-slim\n",
        {},
        target_python_manifest="backend/requirements.txt",
    )

    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        names = set(archive.getnames())
    assert {"backend/requirements.txt", "backend/service.py", "package.json"} <= names
    assert {"ui/package.json", "ui/.npmrc"}.isdisjoint(names)


def test_node_subtree_with_python_source_stays_in_python_context(
    tmp_path: Path,
) -> None:
    workspace, _commit = _committed_workspace(tmp_path)
    frontend = workspace / "frontend"
    frontend.mkdir()
    (frontend / "package.json").write_text('{"name":"frontend"}\n', encoding="utf-8")
    (frontend / "shared_auth.py").write_text(
        "def check(): return True\n", encoding="utf-8"
    )
    (workspace / "app.py").write_text(
        "from frontend.shared_auth import check\nprint(check())\n", encoding="utf-8"
    )
    commit = _commit_fixture(workspace, "shared Python code in Node subtree")

    raw = build_pinned_context(
        workspace,
        commit,
        b"FROM python:3.12-slim\n",
        {},
        target_python_manifest="requirements.txt",
    )

    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        names = set(archive.getnames())
    assert {"app.py", "frontend/package.json", "frontend/shared_auth.py"} <= names


def test_node_subtree_with_python_source_keeps_secret_denial(
    tmp_path: Path,
) -> None:
    workspace, _commit = _committed_workspace(tmp_path)
    frontend = workspace / "frontend"
    frontend.mkdir()
    (frontend / "package.json").write_text('{"name":"frontend"}\n', encoding="utf-8")
    (frontend / "shared_auth.py").write_text(
        "def check(): return True\n", encoding="utf-8"
    )
    (frontend / ".npmrc").write_text("token=product-secret\n", encoding="utf-8")
    commit = _commit_fixture(workspace, "shared Python code and registry secret")

    with pytest.raises(ValueError, match="PINNED_CONTEXT_SECRET_FILE_DENIED"):
        build_pinned_context(
            workspace,
            commit,
            b"FROM python:3.12-slim\n",
            {},
            target_python_manifest="requirements.txt",
        )


def test_archive_context_rejects_source_symlink_or_changed_content(
    tmp_path: Path,
) -> None:
    workspace, commit = _committed_workspace(tmp_path)
    (workspace / "app.py").write_text("print('modified')\n", encoding="utf-8")
    with pytest.raises(ValueError, match="PINNED_CONTEXT_CHANGED"):
        build_pinned_context(workspace, commit, b"FROM python:3.12-slim\n", {})
    (workspace / "app.py").unlink()
    try:
        (workspace / "app.py").symlink_to(workspace / "requirements.txt")
    except OSError:
        pytest.skip("Windows symlink creation is unavailable")
    with pytest.raises(ValueError, match="PINNED_CONTEXT_UNSAFE"):
        build_pinned_context(workspace, commit, b"FROM python:3.12-slim\n", {})


def _commit_fixture(workspace: Path, message: str) -> str:
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
            message,
        ),
        check=True,
    )
    return (
        subprocess.check_output(("git", "-C", str(workspace), "rev-parse", "HEAD"))
        .decode("ascii")
        .strip()
    )


def test_archive_context_honors_dockerignore_and_blocks_tracked_secret(
    tmp_path: Path,
) -> None:
    workspace, _commit = _committed_workspace(tmp_path)
    (workspace / ".env").write_text("SECRET=private\n", encoding="utf-8")
    (workspace / ".dockerignore").write_text(".env\n*.py[cod]\n", encoding="utf-8")
    commit = _commit_fixture(workspace, "ignore")

    raw = build_pinned_context(workspace, commit, b"FROM python:3.12-slim\n", {})
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        assert ".env" not in archive.getnames()
        assert ".dockerignore" not in archive.getnames()

    (workspace / ".dockerignore").write_text("*.py[cod]\n", encoding="utf-8")
    commit = _commit_fixture(workspace, "unignore")
    with pytest.raises(ValueError, match="PINNED_CONTEXT_SECRET_FILE_DENIED"):
        build_pinned_context(workspace, commit, b"FROM python:3.12-slim\n", {})


def test_archive_context_honors_dockerignore_character_class(tmp_path: Path) -> None:
    workspace, _commit = _committed_workspace(tmp_path)
    (workspace / ".dockerignore").write_text(
        "*.py[cod]\ncache[12]/\n", encoding="utf-8"
    )
    for suffix in ("pyc", "pyo", "pyd", "pyx"):
        (workspace / f"module.{suffix}").write_bytes(b"module")
    for directory in ("cache1", "cache2", "cache3"):
        target = workspace / directory
        target.mkdir()
        (target / "data.txt").write_bytes(b"data")
    commit = _commit_fixture(workspace, "class ignore")

    raw = build_pinned_context(workspace, commit, b"FROM python:3.12-slim\n", {})

    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        names = set(archive.getnames())
    assert {"app.py", "module.pyx", "requirements.txt", "cache3/data.txt"} <= names
    assert {
        "module.pyc",
        "module.pyo",
        "module.pyd",
        "cache1/data.txt",
        "cache2/data.txt",
    }.isdisjoint(names)


@pytest.mark.parametrize(
    "pattern",
    (
        "*.py[",
        "*.py[]",
        "*.py[!c]",
        "*.py[a-z]",
        "*.py[c/d]",
        "*.py?",
        "**/*.py[cod]",
        "../*.py[cod]",
        "!*.py[cod]",
        "*.py\\[cod]",
    ),
)
def test_dockerignore_rejects_unsupported_wildcard_patterns(pattern: str) -> None:
    with pytest.raises(ValueError, match="DOCKERIGNORE_UNSUPPORTED"):
        EnvironmentRecipeStore._dockerignore_patterns(
            {".dockerignore": (f"{pattern}\n".encode(), 0o644)}
        )


def test_archive_context_omits_test_only_secret_fixture(tmp_path: Path) -> None:
    workspace, _commit = _committed_workspace(tmp_path)
    package = workspace / "src" / "sample"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "sample"\nversion = "1.0.0"\n'
        '[build-system]\nbuild-backend = "flit_core.buildapi"\n'
        '[tool.flit.module]\nname = "sample"\n',
        encoding="utf-8",
    )
    fixture = workspace / "tests" / "test_apps" / ".env"
    fixture.parent.mkdir(parents=True)
    fixture.write_text("SECRET=fixture-only\n", encoding="utf-8")
    commit = _commit_fixture(workspace, "test fixture")

    raw = build_pinned_context(workspace, commit, b"FROM python:3.12-slim\n", {})
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        assert "app.py" in archive.getnames()
        assert "tests/test_apps/.env" not in archive.getnames()
        assert b"fixture-only" not in raw


def test_archive_context_blocks_test_secret_inside_package(tmp_path: Path) -> None:
    workspace, _commit = _committed_workspace(tmp_path)
    package = workspace / "src" / "sample"
    (package / "tests").mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "tests" / ".env").write_text("SECRET=packaged\n", encoding="utf-8")
    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "sample"\nversion = "1.0.0"\n'
        '[build-system]\nbuild-backend = "flit_core.buildapi"\n'
        '[tool.flit.module]\nname = "sample"\n',
        encoding="utf-8",
    )
    commit = _commit_fixture(workspace, "packaged test data")

    with pytest.raises(ValueError, match="PINNED_CONTEXT_SECRET_FILE_DENIED"):
        build_pinned_context(workspace, commit, b"FROM python:3.12-slim\n", {})


def test_archive_context_blocks_ambiguous_test_secret_package_data(
    tmp_path: Path,
) -> None:
    workspace, _commit = _committed_workspace(tmp_path)
    fixture = workspace / "tests" / ".env"
    fixture.parent.mkdir()
    fixture.write_text("SECRET=maybe-packaged\n", encoding="utf-8")
    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "sample"\nversion = "1.0.0"\n'
        '[build-system]\nbuild-backend = "flit_core.buildapi"\n'
        '[tool.flit.module]\nname = "sample"\n'
        '[tool.flit.external-data]\ndirectory = "tests"\n',
        encoding="utf-8",
    )
    package = workspace / "src" / "sample"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    commit = _commit_fixture(workspace, "ambiguous data")

    with pytest.raises(ValueError, match="PINNED_CONTEXT_SECRET_FILE_DENIED"):
        build_pinned_context(workspace, commit, b"FROM python:3.12-slim\n", {})


def test_archive_context_blocks_secret_in_nested_project(tmp_path: Path) -> None:
    workspace, _commit = _committed_workspace(tmp_path)
    package = workspace / "src" / "sample"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "sample"\nversion = "1.0.0"\n'
        '[build-system]\nbuild-backend = "flit_core.buildapi"\n'
        '[tool.flit.module]\nname = "sample"\n',
        encoding="utf-8",
    )
    nested = workspace / "examples" / "tool"
    nested.mkdir(parents=True)
    (nested / "pyproject.toml").write_text(
        '[build-system]\nbuild-backend = "setuptools.build_meta"\n',
        encoding="utf-8",
    )
    secret = nested / "tests" / ".env"
    secret.parent.mkdir()
    secret.write_text("SECRET=nested-product-data\n", encoding="utf-8")
    commit = _commit_fixture(workspace, "nested project")

    with pytest.raises(ValueError, match="PINNED_CONTEXT_SECRET_FILE_DENIED"):
        build_pinned_context(workspace, commit, b"FROM python:3.12-slim\n", {})


@pytest.mark.parametrize(
    "metadata",
    (
        'readme = "tests/.env"',
        'license = {file = "tests/.env"}',
        'license-files = ["tests/*.env"]',
        'license-files = ["./tests/*.env"]',
    ),
)
def test_archive_context_blocks_test_secret_referenced_by_project_metadata(
    tmp_path: Path, metadata: str
) -> None:
    workspace, _commit = _committed_workspace(tmp_path)
    package = workspace / "src" / "sample"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (workspace / "pyproject.toml").write_text(
        f'[project]\nname = "sample"\nversion = "1.0.0"\n{metadata}\n'
        '[build-system]\nbuild-backend = "flit_core.buildapi"\n'
        '[tool.flit.module]\nname = "sample"\n',
        encoding="utf-8",
    )
    secret = workspace / "tests" / ".env"
    secret.parent.mkdir()
    secret.write_text("SECRET=metadata-input\n", encoding="utf-8")
    commit = _commit_fixture(workspace, "metadata input")

    with pytest.raises(ValueError, match="PINNED_CONTEXT_SECRET_FILE_DENIED"):
        build_pinned_context(workspace, commit, b"FROM python:3.12-slim\n", {})


def test_archive_context_uses_reproducible_zip_compatible_mtime(
    tmp_path: Path,
) -> None:
    workspace, commit = _committed_workspace(tmp_path)
    raw = build_pinned_context(workspace, commit, b"FROM python:3.12-slim\n", {})

    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        assert {member.mtime for member in archive} == {315532800}


def test_archive_context_blocks_declared_product_secret_under_tests(
    tmp_path: Path,
) -> None:
    workspace, _commit = _committed_workspace(tmp_path)
    product = workspace / "tests" / ".env.prod.js"
    product.parent.mkdir(parents=True)
    product.write_text("export const value = 'dummy';\n", encoding="utf-8")
    (workspace / "package.json").write_text(
        '{"main":"./tests/.env.prod.js"}\n', encoding="utf-8"
    )
    commit = _commit_fixture(workspace, "declared product")

    with pytest.raises(ValueError, match="PINNED_CONTEXT_SECRET_FILE_DENIED"):
        build_pinned_context(workspace, commit, b"FROM python:3.12-slim\n", {})


def test_archive_context_preserves_executable_bit_and_rejects_filter(
    tmp_path: Path,
) -> None:
    workspace, _commit = _committed_workspace(tmp_path)
    (workspace / "app.py").chmod(0o755)
    subprocess.run(
        ("git", "-C", str(workspace), "update-index", "--chmod=+x", "app.py"),
        check=True,
    )
    commit = _commit_fixture(workspace, "executable")
    raw = build_pinned_context(workspace, commit, b"FROM python:3.12-slim\n", {})
    with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
        assert archive.getmember("app.py").mode == 0o755

    (workspace / ".gitattributes").write_text("app.py filter=lfs\n", encoding="utf-8")
    commit = _commit_fixture(workspace, "filter")
    with pytest.raises(ValueError, match="PINNED_CONTEXT_FILTER_UNSUPPORTED"):
        build_pinned_context(workspace, commit, b"FROM python:3.12-slim\n", {})


@pytest.mark.asyncio
async def test_tar_build_uses_network_none(tmp_path: Path) -> None:
    docker = _ArchiveDocker()
    workspace, commit = _committed_workspace(tmp_path)
    dockerfile = b"FROM python:3.12-slim\n"
    raw = build_pinned_context(workspace, commit, dockerfile, {})

    with pytest.raises(DockerOperationError, match="DOCKER_IMAGE_INSPECT_FAILED"):
        await docker.build_or_reuse(
            workspace=tmp_path,
            dockerfile=dockerfile,
            cache_key="archive-build",
            labels={},
            context_archive=raw,
        )

    args, input_bytes = next(
        (args, payload) for args, payload in docker.calls if args[0] == "build"
    )
    assert docker.calls[0][0] == ("buildx", "inspect")
    assert args[:3] == ("build", "--builder", "desktop-linux")
    assert ("--network", "none") == args[
        args.index("--network") : args.index("--network") + 2
    ]
    assert args[-3:] == ("--file", "Dockerfile", "-")
    assert input_bytes == raw


@pytest.mark.asyncio
async def test_tar_build_rejects_unverified_archive(tmp_path: Path) -> None:
    docker = _ArchiveDocker()
    with pytest.raises(ValueError, match="PINNED_CONTEXT_UNSAFE"):
        await docker.build_or_reuse(
            workspace=tmp_path,
            dockerfile=b"FROM python:3.12-slim\n",
            cache_key="invalid",
            labels={},
            context_archive=b"not a tar",
        )
    assert docker.calls == []


@pytest.mark.asyncio
async def test_archive_cache_hit_requires_matching_recipe_label(tmp_path: Path) -> None:
    workspace, commit = _committed_workspace(tmp_path)
    dockerfile = b"FROM python:3.12-slim\n"
    raw = build_pinned_context(workspace, commit, dockerfile, {})

    class _WrongCache(_ArchiveDocker):
        async def _run(
            self,
            args: Sequence[str],
            *,
            timeout_seconds: int,
            input_bytes: bytes | None = None,
        ) -> DockerCommandOutcome:
            del timeout_seconds
            self.calls.append((tuple(args), input_bytes))
            if tuple(args)[:2] == ("buildx", "inspect"):
                return DockerCommandOutcome(
                    0, b"Name: default\nDriver: docker\n", b"", False
                )
            return DockerCommandOutcome(
                0, b"0" * 64 + b"|sha256:" + b"a" * 64 + b"\n", b"", False
            )

    docker = _WrongCache()
    with pytest.raises(ValueError, match="POC_OFFLINE_CACHE_MISMATCH"):
        await docker.build_or_reuse(
            workspace=workspace,
            dockerfile=dockerfile,
            cache_key="offline",
            labels={},
            context_archive=raw,
        )
    assert len(docker.calls) == 2


@pytest.mark.asyncio
async def test_archive_build_rejects_non_engine_builder(tmp_path: Path) -> None:
    workspace, commit = _committed_workspace(tmp_path)
    dockerfile = b"FROM python:3.12-slim\n"
    raw = build_pinned_context(workspace, commit, dockerfile, {})

    class _ContainerBuilder(_ArchiveDocker):
        async def _run(
            self,
            args: Sequence[str],
            *,
            timeout_seconds: int,
            input_bytes: bytes | None = None,
        ) -> DockerCommandOutcome:
            del timeout_seconds
            self.calls.append((tuple(args), input_bytes))
            return DockerCommandOutcome(
                0, b"Name: default\nDriver: docker-container\n", b"", False
            )

    docker = _ContainerBuilder()
    with pytest.raises(ValueError, match="POC_OFFLINE_BUILDER_UNSUPPORTED"):
        await docker.build_or_reuse(
            workspace=workspace,
            dockerfile=dockerfile,
            cache_key="offline",
            labels={},
            context_archive=raw,
        )
    assert len(docker.calls) == 1


@pytest.mark.parametrize(
    ("elapsed_limit", "expected_timeout"),
    [(7200, 7200), ("unlimited", 3600)],
)
def test_docker_call_timeout_preserves_finite_configuration(
    elapsed_limit: ElapsedLimit, expected_timeout: int
) -> None:
    profile = SimpleExecutionProfile(
        provider_profile_ref="test",
        provider="test",
        model="test",
        auth_mode="API_KEY",
        credential_ref="env:TEST_API_KEY",
        data_dir=Path.cwd(),
        workspace_root=Path.cwd(),
        max_cost_minor_units=1,
        max_tokens=1,
        docker_network="NONE",
        max_elapsed_seconds=elapsed_limit,
        tools={
            "docker": SimpleToolBinding(
                executable_path=Path("docker"),
                version="test",
                executable_sha256="a" * 64,
            )
        },
        max_parallel_builds=1,
        max_parallel_containers=1,
    )

    runtime = PortableDockerRuntime(profile)

    assert runtime._timeout == expected_timeout


class _BuildDocker:
    def __init__(self) -> None:
        self.dockerfiles: list[bytes] = []

    async def build_or_reuse(
        self,
        *,
        workspace: Path,
        dockerfile: bytes,
        cache_key: str,
        labels: Mapping[str, str],
    ) -> str:
        del workspace, cache_key, labels
        self.dockerfiles.append(dockerfile)
        return "sha256:" + "a" * 64


class _FailingBuildDocker(_BuildDocker):
    def __init__(self, failures: list[bytes]) -> None:
        super().__init__()
        self.failures = failures

    async def build_or_reuse(
        self,
        *,
        workspace: Path,
        dockerfile: bytes,
        cache_key: str,
        labels: Mapping[str, str],
    ) -> str:
        result = await super().build_or_reuse(
            workspace=workspace,
            dockerfile=dockerfile,
            cache_key=cache_key,
            labels=labels,
        )
        if self.failures:
            raise DockerOperationError(
                "DOCKER_BUILD_FAILED",
                DockerCommandOutcome(1, b"", self.failures.pop(0), False),
            )
        return result


@pytest.mark.asyncio
async def test_dependency_failure_uses_recorded_source_only_fallback(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "Dockerfile").write_bytes(
        b"FROM python:3.12-slim\nRUN pip install -r requirements.txt\n"
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-fallback",
        workspace_id="workspace-fallback",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-fallback",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    checkpoint = _environment_checkpoint(artifacts, action="RETRY_STAGE", patch="")
    docker = _FailingBuildDocker([b"RUN pip install -r requirements.txt: exit code 1"])

    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    ).prepare(checkpoint, {}, ())

    recipe = json.loads(artifacts.read(result.recipe_ref))
    assert recipe["dockerfile_source"] == "GENERATED_NO_INSTALL"
    assert recipe["degraded"] is True
    assert len(recipe["build_attempt_refs"]) == 2
    assert b"pip install" not in docker.dockerfiles[1]
    assert json.loads(artifacts.read(result.recipe_ref))["status"] == "BUILT"
    assert recipe["image_digest"] == result.image_digest


@pytest.mark.asyncio
async def test_failed_recovery_install_keeps_build_failure_for_recovery(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "Dockerfile").write_bytes(b"FROM python:3.12-slim\n")
    identity = CheckpointIdentity(
        analysis_id="analysis-recovery-install-failure",
        workspace_id="workspace-recovery-install-failure",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-recovery-install-failure",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    checkpoint = _environment_checkpoint(
        artifacts,
        action="REBUILD_ENVIRONMENT",
        patch="RUN apt-get install -y libxml2-dev",
    )
    docker = _FailingBuildDocker([b"RUN apt-get install -y libxml2-dev: exit code 100"])

    with pytest.raises(DockerOperationError, match="DOCKER_BUILD_FAILED") as failure:
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
        ).prepare(checkpoint, {}, ())

    assert len(docker.dockerfiles) == 1
    assert b"RUN apt-get install -y libxml2-dev" in docker.dockerfiles[0]
    recipe = json.loads(artifacts.read(failure.value.recipe_ref))  # type: ignore[attr-defined]
    assert recipe["status"] == "BLOCKED"
    assert recipe["degraded"] is False
    assert recipe["dockerfile_source"] == "REPOSITORY_DOCKERFILE"
    assert len(recipe["build_attempt_refs"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "diagnostics", [b"syntax error near FROM", b"pull access denied"]
)
async def test_unrelated_build_failure_does_not_fallback(
    tmp_path: Path, diagnostics: bytes
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "Dockerfile").write_bytes(b"FROM invalid\n")
    identity = CheckpointIdentity(
        analysis_id="analysis-no-fallback",
        workspace_id="workspace-no-fallback",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-no-fallback",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    checkpoint = _environment_checkpoint(artifacts, action="RETRY_STAGE", patch="")
    docker = _FailingBuildDocker([diagnostics])

    with pytest.raises(DockerOperationError, match="DOCKER_BUILD_FAILED") as failure:
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
        ).prepare(checkpoint, {}, ())

    assert len(docker.dockerfiles) == 1
    assert len(failure.value.attempt_refs) == 1  # type: ignore[attr-defined]
    attempt = json.loads(artifacts.read(failure.value.attempt_refs[0]))  # type: ignore[attr-defined]
    assert attempt["status"] == "FAILED"


@pytest.mark.asyncio
async def test_both_build_failures_recorded_without_success(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "requirements.txt").write_text("broken==1\n", encoding="utf-8")
    identity = CheckpointIdentity(
        analysis_id="analysis-both-fail",
        workspace_id="workspace-both-fail",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-both-fail",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    checkpoint = _environment_checkpoint(artifacts, action="RETRY_STAGE", patch="")
    docker = _FailingBuildDocker(
        [b"RUN pip install -r requirements.txt: exit code 1", b"network timeout"]
    )

    with pytest.raises(DockerOperationError) as failure:
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
        ).prepare(checkpoint, {}, ())

    assert len(docker.dockerfiles) == 2
    assert len(failure.value.attempt_refs) == 2  # type: ignore[attr-defined]


def _environment_checkpoint(
    artifacts: SimpleArtifactRepository,
    *,
    action: str,
    patch: str,
) -> StageCheckpoint:
    decision_ref = artifacts.put_json(
        {
            "kind": "simple_recovery_decision",
            "identity": artifacts.identity.model_dump(mode="json"),
            "decision": {
                "category": (
                    "ENVIRONMENT"
                    if action == "REBUILD_ENVIRONMENT"
                    else "TRANSIENT_TOOL"
                ),
                "action": action,
                "diagnosis": "test diagnosis",
                "guidance": "test guidance",
                "environment_patch": patch,
            },
        }
    )
    inputs = (decision_ref,)
    return StageCheckpoint(
        identity=artifacts.identity,
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        status=StageStatus.RUNNING,
        input_refs=inputs,
        input_hash=input_reference_hash(inputs),
        recovery_decision_refs=inputs,
        attempt_id="environment-attempt-2",
        attempt_number=2,
    )


@pytest.mark.asyncio
async def test_runtime_process_preserves_programfiles_for_windows_docker_plugins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = PortableDockerRuntime.__new__(PortableDockerRuntime)
    runtime._executable = Path(sys.executable)
    monkeypatch.setenv("PROGRAMFILES", r"C:\Program Files")
    monkeypatch.setenv("SASTSIMI_TEST_SECRET", "must-not-leak")

    outcome = await runtime._run(
        (
            "-c",
            "import json, os; print(json.dumps(dict(os.environ)))",
        ),
        timeout_seconds=30,
    )

    child_environment = json.loads(outcome.stdout)
    assert child_environment["PROGRAMFILES"] == r"C:\Program Files"
    assert "SASTSIMI_TEST_SECRET" not in child_environment


@pytest.mark.asyncio
async def test_runtime_process_keeps_end_of_large_docker_diagnostics() -> None:
    runtime = PortableDockerRuntime.__new__(PortableDockerRuntime)
    runtime._executable = Path(sys.executable)

    outcome = await runtime._run(
        (
            "-c",
            "import sys; "
            "sys.stdout.buffer.write(b'o' * (1024 * 1024 + 64) + b'OUT-END'); "
            "sys.stderr.buffer.write(b'e' * (1024 * 1024 + 64) + b'GIT-ERROR')",
        ),
        timeout_seconds=30,
    )

    assert outcome.exit_code == 0
    assert outcome.stdout.endswith(b"OUT-END")
    assert outcome.stderr.endswith(b"GIT-ERROR")
    assert len(outcome.stdout) <= 1024 * 1024
    assert len(outcome.stderr) <= 1024 * 1024


@pytest.mark.asyncio
async def test_runtime_process_sends_input_while_draining_output() -> None:
    runtime = PortableDockerRuntime.__new__(PortableDockerRuntime)
    runtime._executable = Path(sys.executable)
    payload = b"Dockerfile" * 100_000

    outcome = await runtime._run(
        (
            "-c",
            "import sys; data = sys.stdin.buffer.read(); "
            "sys.stdout.write(str(len(data)))",
        ),
        timeout_seconds=30,
        input_bytes=payload,
    )

    assert outcome.exit_code == 0
    assert outcome.stdout == b"1000000"


def test_target_environment_change_invalidates_only_initial_verification_and_later(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-old-environment",
        workspace_id="workspace-old-environment",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-old-environment",
    )
    for stage, version in (
        (SimpleStage.PRO_CON_DONE, STAGE_VERSION[SimpleStage.PRO_CON_DONE]),
        (SimpleStage.VERIFICATION_INITIAL_DONE, "3"),
        (SimpleStage.POC_CANDIDATE_DONE, STAGE_VERSION[SimpleStage.POC_CANDIDATE_DONE]),
    ):
        store.save_checkpoint(
            StageCheckpoint(
                identity=identity,
                stage=stage,
                stage_version=version,
                status=StageStatus.SUCCEEDED,
                input_refs=(),
                input_hash=input_reference_hash(()),
            )
        )

    assert store.reusable(identity, SimpleStage.PRO_CON_DONE, ())
    assert not store.reusable(identity, SimpleStage.VERIFICATION_INITIAL_DONE, ())
    store.invalidate_from(
        identity, SimpleStage.VERIFICATION_INITIAL_DONE, new_inputs=()
    )
    assert store.get(identity, SimpleStage.PRO_CON_DONE) is not None
    assert store.get(identity, SimpleStage.VERIFICATION_INITIAL_DONE) is None
    assert store.get(identity, SimpleStage.POC_CANDIDATE_DONE) is None


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
    assert create[create.index("--network") + 1] == "none"
    assert "no-new-privileges" in create
    assert create[create.index("--env") + 1] == "HOME=/tmp"


@pytest.mark.asyncio
async def test_reproduction_container_overrides_inherited_entrypoint() -> None:
    runtime = _RecordingPortableDockerRuntime.__new__(_RecordingPortableDockerRuntime)
    runtime._executable = Path("docker")
    runtime._network = "none"
    runtime._timeout = 60
    runtime.calls = []

    await runtime.create_container("sha256:" + "a" * 64, {})

    create = runtime.calls[0]
    assert create[create.index("--entrypoint") : create.index("--entrypoint") + 2] == (
        "--entrypoint",
        "sleep",
    )
    assert create[-2:] == ("sha256:" + "a" * 64, "infinity")


@pytest.mark.asyncio
async def test_materialize_poc_replaces_read_only_candidate_from_prior_run() -> None:
    runtime = _RecordingPortableDockerRuntime.__new__(_RecordingPortableDockerRuntime)
    runtime._executable = Path("docker")
    runtime._network = "none"
    runtime._timeout = 60
    runtime.calls = []
    content = b"#!/bin/sh\necho ok\n"

    await runtime.materialize_poc(
        "container-1",
        content,
        hashlib.sha256(content).hexdigest(),
    )

    assert runtime.calls[0] == (
        "exec",
        "-i",
        "container-1",
        "sh",
        "-c",
        "rm -f /tmp/sastsimi-poc-candidate && cat > /tmp/sastsimi-poc-candidate",
    )


def test_repository_buster_dockerfile_uses_archive_mirrors_before_apt() -> None:
    original = (
        b"FROM python:3.11.0b1-buster\n"
        b"RUN apt-get update && apt-get install -y dnsutils\n"
    )

    prepared = DirectEnvironmentPreparer._portable_repository_dockerfile(original)

    assert b"archive.debian.org/debian" in prepared
    assert b"Acquire::Check-Valid-Until" in prepared
    assert prepared.index(b"archive.debian.org") < prepared.index(b"apt-get update")


def test_target_manifest_is_resolved_from_exact_hypothesis(
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

    resolved = preparer._target_manifest_path({SimpleStage.PRO_CON_DONE: pro_con})

    assert resolved == "nested/lab/requirements.txt"

    backslash_ref = artifacts.put_json(
        {
            "kind": "simple_hypothesis_proposal",
            "proposal": {"code_locations": [r"nested\lab\main.py:1"]},
        }
    )
    backslash_inputs = (backslash_ref,)
    backslash_pro_con = pro_con.model_copy(
        update={
            "input_refs": backslash_inputs,
            "input_hash": input_reference_hash(backslash_inputs),
        }
    )
    assert (
        preparer._target_manifest_path({SimpleStage.PRO_CON_DONE: backslash_pro_con})
        is None
    )


@pytest.mark.parametrize(
    "pyproject_body",
    [
        '[project]\nname = "plain-root"\nversion = "0.1.0"\n',
        "[project\n",
    ],
)
def test_root_requirements_remain_selected_without_uv_sources(
    tmp_path: Path, pyproject_body: str
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.py").write_text("pass\n", encoding="utf-8")
    (workspace / "requirements.txt").write_text("flask\n", encoding="utf-8")
    (workspace / "pyproject.toml").write_text(pyproject_body, encoding="utf-8")
    identity = CheckpointIdentity(
        analysis_id="analysis-root-pip",
        workspace_id="workspace-root-pip",
        commit_id="c" * 40,
        hypothesis_id="hypothesis-root-pip",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    proposal_ref = artifacts.put_json(
        {
            "kind": "simple_hypothesis_proposal",
            "proposal": {"code_locations": ["app.py:1"]},
        }
    )
    pro_con = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(proposal_ref,),
        input_hash=input_reference_hash((proposal_ref,)),
    )
    preparer = DirectEnvironmentPreparer(
        docker=object(),  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    )

    assert preparer._target_manifest_path({SimpleStage.PRO_CON_DONE: pro_con}) == (
        "requirements.txt"
    )


def test_target_manifest_rejects_symlinked_source(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "real.py").write_text("pass\n", encoding="utf-8")
    (workspace / "requirements.txt").write_text("Flask\n", encoding="utf-8")
    try:
        (workspace / "link.py").symlink_to(workspace / "real.py")
    except (OSError, NotImplementedError):
        pytest.skip("This Windows account cannot create symbolic links")
    identity = CheckpointIdentity(
        analysis_id="analysis-symlink",
        workspace_id="workspace-symlink",
        commit_id="d" * 40,
        hypothesis_id="hypothesis-symlink",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    proposal_ref = artifacts.put_json(
        {
            "kind": "simple_hypothesis_proposal",
            "proposal": {"code_locations": ["link.py:1"]},
        }
    )
    pro_con = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(proposal_ref,),
        input_hash=input_reference_hash((proposal_ref,)),
    )
    preparer = DirectEnvironmentPreparer(
        docker=object(),  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    )

    assert preparer._target_manifest_path({SimpleStage.PRO_CON_DONE: pro_con}) is None


@pytest.mark.asyncio
async def test_generated_image_installs_nearest_nested_pyproject(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    target = workspace / "service"
    target.mkdir(parents=True)
    (target / "app.py").write_text("import socketio\n", encoding="utf-8")
    (target / "pyproject.toml").write_text(
        '[project]\nname = "example-service"\nversion = "0.1.0"\n'
        'dependencies = ["python-socketio"]\n',
        encoding="utf-8",
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-nested-project",
        workspace_id="workspace-nested-project",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-nested-project",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    proposal_ref = artifacts.put_json(
        {
            "kind": "simple_hypothesis_proposal",
            "proposal": {"code_locations": ["service/app.py:1"]},
        }
    )
    pro_con = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(proposal_ref,),
        input_hash=input_reference_hash((proposal_ref,)),
    )
    docker = _BuildDocker()

    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    ).prepare(
        _environment_checkpoint(artifacts, action="RETRY_STAGE", patch=""),
        {SimpleStage.PRO_CON_DONE: pro_con},
        (),
    )

    assert (
        b"python -m pip install --no-cache-dir /workspace/service"
        in docker.dockerfiles[0]
    )
    assert (
        b"ln -s /workspace/service /opt/sastsimi-target-source" in docker.dockerfiles[0]
    )
    recipe = json.loads(artifacts.read(result.recipe_ref))
    assert recipe["target_manifest_path"] == "service/pyproject.toml"


@pytest.mark.asyncio
async def test_generated_image_uses_uv_for_nested_workspace_sources(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    project = workspace / "backend"
    project.mkdir(parents=True)
    (project / "app.py").write_text("import socketio\n", encoding="utf-8")
    (project / "pyproject.toml").write_text(
        '[project]\nname = "example-service"\nversion = "0.1.0"\n'
        'dependencies = ["local-agent"]\n'
        '[tool.uv.sources]\nlocal-agent = { path = "../local-agent" }\n',
        encoding="utf-8",
    )
    (project / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    identity = CheckpointIdentity(
        analysis_id="analysis-uv-project",
        workspace_id="workspace-uv-project",
        commit_id="b" * 40,
        hypothesis_id="hypothesis-uv-project",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    proposal_ref = artifacts.put_json(
        {
            "kind": "simple_hypothesis_proposal",
            "proposal": {"code_locations": ["backend/app.py:1"]},
        }
    )
    pro_con = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(proposal_ref,),
        input_hash=input_reference_hash((proposal_ref,)),
    )
    docker = _BuildDocker()

    await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    ).prepare(
        _environment_checkpoint(artifacts, action="RETRY_STAGE", patch=""),
        {SimpleStage.PRO_CON_DONE: pro_con},
        (),
    )

    built = docker.dockerfiles[0]
    assert b"python -m pip install --no-cache-dir uv" in built
    assert b"uv sync --frozen --no-dev" in built
    assert b"--no-default-groups" not in built
    assert b"ln -s /workspace/backend/.venv /opt/sastsimi-target-venv" in built
    assert b"ENV VIRTUAL_ENV=/opt/sastsimi-target-venv" in built
    assert b'ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"' in built
    assert b"ln -s /workspace/backend /opt/sastsimi-target-source" in built
    assert (
        b'ENV PYTHONPATH="/opt/sastsimi-target-source:'
        b'/opt/sastsimi-target-source/src:${PYTHONPATH}"' in built
    )
    assert b"pip install --no-cache-dir /workspace/backend" not in built


@pytest.mark.asyncio
async def test_nested_workspace_member_uses_root_uv_environment(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    project = workspace / "apps" / "worker"
    project.mkdir(parents=True)
    (project / "app.py").write_text("import local_lib\n", encoding="utf-8")
    (project / "pyproject.toml").write_text(
        '[project]\nname = "example-worker"\nversion = "0.1.0"\n'
        'dependencies = ["local-lib"]\n',
        encoding="utf-8",
    )
    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "example-root"\nversion = "0.1.0"\n'
        'requires-python = ">=3.12,<3.13"\n'
        '[tool.uv.workspace]\nmembers = ["apps/*"]\n'
        '[tool.uv.sources]\nlocal-lib = { path = "libs/local-lib" }\n',
        encoding="utf-8",
    )
    (workspace / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    identity = CheckpointIdentity(
        analysis_id="analysis-member-uv",
        workspace_id="workspace-member-uv",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-member-uv",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    proposal_ref = artifacts.put_json(
        {
            "kind": "simple_hypothesis_proposal",
            "proposal": {"code_locations": ["apps/worker/app.py:1"]},
        }
    )
    pro_con = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(proposal_ref,),
        input_hash=input_reference_hash((proposal_ref,)),
    )
    docker = _BuildDocker()

    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    ).prepare(
        _environment_checkpoint(artifacts, action="RETRY_STAGE", patch=""),
        {SimpleStage.PRO_CON_DONE: pro_con},
        (),
    )

    built = docker.dockerfiles[0]
    assert b"cd /workspace && uv sync --package example-worker --frozen" in built
    assert b"test -x /workspace/.venv/bin/python" in built
    assert b"ln -s /workspace/.venv /opt/sastsimi-target-venv" in built
    assert b"/workspace/apps/worker/.venv" not in built
    assert b"pip install --no-cache-dir /workspace/apps/worker" not in built
    assert json.loads(artifacts.read(result.recipe_ref))["target_manifest_path"] == (
        "apps/worker/pyproject.toml"
    )


def test_uv_workspace_member_sync_creates_root_environment(tmp_path: Path) -> None:
    executable = shutil.which("uv")
    if executable is None:
        sibling = Path(sys.executable).with_name(
            "uv.exe" if sys.platform == "win32" else "uv"
        )
        if sibling.is_file():
            executable = str(sibling)
    if executable is None:
        pytest.skip("uv is not installed for the offline workspace smoke test")

    workspace = tmp_path / "workspace"
    member = workspace / "apps" / "worker"
    local_lib = workspace / "libs" / "local-lib"
    member.mkdir(parents=True)
    local_lib.mkdir(parents=True)
    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "example-root"\nversion = "0.1.0"\n'
        'requires-python = ">=3.12,<3.13"\n'
        '[tool.uv.workspace]\nmembers = ["apps/*"]\n'
        '[tool.uv.sources]\nlocal-lib = { path = "libs/local-lib" }\n',
        encoding="utf-8",
    )
    (member / "pyproject.toml").write_text(
        '[project]\nname = "example-worker"\nversion = "0.1.0"\n'
        'requires-python = ">=3.12,<3.13"\n'
        'dependencies = ["local-lib"]\n',
        encoding="utf-8",
    )
    (local_lib / "pyproject.toml").write_text(
        '[project]\nname = "local-lib"\nversion = "0.1.0"\n'
        'requires-python = ">=3.12,<3.13"\n'
        "[tool.uv]\npackage = false\n",
        encoding="utf-8",
    )
    env = {**os.environ, "UV_CACHE_DIR": str(tmp_path / "uv-cache")}
    locked = subprocess.run(
        [executable, "lock", "--offline"],
        cwd=workspace,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert locked.returncode == 0, locked.stderr

    synced = subprocess.run(
        [
            executable,
            "sync",
            "--offline",
            "--frozen",
            "--package",
            "example-worker",
            "--no-dev",
            "--python",
            sys.executable,
        ],
        cwd=workspace,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert synced.returncode == 0, synced.stderr
    interpreter = "python.exe" if sys.platform == "win32" else "python"
    scripts = "Scripts" if sys.platform == "win32" else "bin"
    assert (workspace / ".venv" / scripts / interpreter).is_file()
    assert not (member / ".venv").exists()


@pytest.mark.asyncio
async def test_generated_image_uses_uv_for_root_workspace_sources(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.py").write_text("import local_agent\n", encoding="utf-8")
    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "example-root"\nversion = "0.1.0"\n'
        'dependencies = ["local-agent"]\n'
        '[tool.uv.sources]\nlocal-agent = { path = "local-agent" }\n',
        encoding="utf-8",
    )
    (workspace / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    identity = CheckpointIdentity(
        analysis_id="analysis-root-uv",
        workspace_id="workspace-root-uv",
        commit_id="d" * 40,
        hypothesis_id="hypothesis-root-uv",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    proposal_ref = artifacts.put_json(
        {
            "kind": "simple_hypothesis_proposal",
            "proposal": {"code_locations": ["app.py:1"]},
        }
    )
    pro_con = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(proposal_ref,),
        input_hash=input_reference_hash((proposal_ref,)),
    )
    docker = _BuildDocker()

    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    ).prepare(
        _environment_checkpoint(artifacts, action="RETRY_STAGE", patch=""),
        {SimpleStage.PRO_CON_DONE: pro_con},
        (),
    )

    built = docker.dockerfiles[0]
    assert b"cd /workspace && uv sync --frozen --no-dev" in built
    assert b"--no-default-groups" not in built
    assert b"apt-get install -y --no-install-recommends git" in built
    assert built.index(b"apt-get install -y --no-install-recommends git") < built.index(
        b"uv sync"
    )
    assert b"ln -s /workspace/.venv /opt/sastsimi-target-venv" in built
    assert b"pip install --no-cache-dir ." not in built
    assert json.loads(artifacts.read(result.recipe_ref))["target_manifest_path"] == (
        "pyproject.toml"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("base_image", ["python:3.12-slim", "python:3.12-alpine"])
async def test_repository_uv_image_can_install_git_before_sync(
    tmp_path: Path, base_image: str
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    original = f"FROM {base_image}\nUSER nobody\nWORKDIR /service\n".encode()
    (workspace / "Dockerfile").write_bytes(original)
    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "example-root"\nversion = "0.1.0"\n'
        'dependencies = ["remote-lib"]\n'
        '[tool.uv.sources]\nremote-lib = { git = "https://example.org/lib.git" }\n',
        encoding="utf-8",
    )
    (workspace / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    identity = CheckpointIdentity(
        analysis_id="analysis-repository-uv-git",
        workspace_id="workspace-repository-uv-git",
        commit_id="d" * 40,
        hypothesis_id="hypothesis-repository-uv-git",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    docker = _BuildDocker()

    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    ).prepare(
        _environment_checkpoint(artifacts, action="RETRY_STAGE", patch=""),
        {},
        (),
    )

    built = docker.dockerfiles[0]
    assert built.startswith(original)
    assert built.index(b"USER root") < built.index(b"command -v git")
    assert built.index(b"command -v git") < built.index(b"uv sync --frozen")
    assert b"apt-get install -y --no-install-recommends git" in built
    assert b"apk add --no-cache git" in built
    assert b"SASTSIMI_GIT_UNAVAILABLE" in built
    assert (workspace / "Dockerfile").read_bytes() == original
    assert json.loads(artifacts.read(result.recipe_ref))["dockerfile_source"] == (
        "REPOSITORY_DOCKERFILE"
    )


@pytest.mark.asyncio
async def test_uv_sync_includes_project_default_runtime_groups(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "example-root"\nversion = "0.1.0"\n'
        '[dependency-groups]\nruntime = ["pydantic-settings"]\n'
        'dev = ["pytest"]\n'
        '[tool.uv]\ndefault-groups = ["runtime", "dev"]\n',
        encoding="utf-8",
    )
    (workspace / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    identity = CheckpointIdentity(
        analysis_id="analysis-default-runtime-groups",
        workspace_id="workspace-default-runtime-groups",
        commit_id="e" * 40,
        hypothesis_id="hypothesis-default-runtime-groups",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    docker = _BuildDocker()

    await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    ).prepare(
        _environment_checkpoint(artifacts, action="RETRY_STAGE", patch=""),
        {},
        (),
    )

    built = docker.dockerfiles[0]
    assert b"uv sync --frozen --no-dev" in built
    assert b"--no-default-groups" not in built


@pytest.mark.parametrize(
    "uv_sources",
    ["", '[tool.uv.sources]\nlocal-lib = { path = "libs/local-lib" }\n'],
)
@pytest.mark.asyncio
async def test_root_uv_lock_takes_precedence_over_requirements(
    tmp_path: Path, uv_sources: str
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.py").write_text("import local_lib\n", encoding="utf-8")
    (workspace / "requirements.txt").write_text("other-package\n", encoding="utf-8")
    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "example-root"\nversion = "0.1.0"\n'
        'dependencies = ["local-lib"]\n'
        f"{uv_sources}",
        encoding="utf-8",
    )
    (workspace / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    identity = CheckpointIdentity(
        analysis_id="analysis-root-mixed",
        workspace_id="workspace-root-mixed",
        commit_id="b" * 40,
        hypothesis_id="hypothesis-root-mixed",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    proposal_ref = artifacts.put_json(
        {
            "kind": "simple_hypothesis_proposal",
            "proposal": {"code_locations": ["app.py:1"]},
        }
    )
    pro_con = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(proposal_ref,),
        input_hash=input_reference_hash((proposal_ref,)),
    )
    docker = _BuildDocker()

    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    ).prepare(
        _environment_checkpoint(artifacts, action="RETRY_STAGE", patch=""),
        {SimpleStage.PRO_CON_DONE: pro_con},
        (),
    )

    built = docker.dockerfiles[0]
    assert b"cd /workspace && uv sync --frozen" in built
    assert b"pip install --no-cache-dir -r requirements.txt" not in built
    assert json.loads(artifacts.read(result.recipe_ref))["target_manifest_path"] == (
        "pyproject.toml"
    )


@pytest.mark.asyncio
async def test_root_uv_install_failure_does_not_fall_back_to_no_install(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "example-root"\nversion = "0.1.0"\n'
        'dependencies = ["local-agent"]\n'
        '[tool.uv.sources]\nlocal-agent = { path = "local-agent" }\n',
        encoding="utf-8",
    )
    (workspace / "uv.lock").write_text("version = 1\n", encoding="utf-8")
    identity = CheckpointIdentity(
        analysis_id="analysis-root-uv-failure",
        workspace_id="workspace-root-uv-failure",
        commit_id="e" * 40,
        hypothesis_id="hypothesis-root-uv-failure",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    docker = _FailingBuildDocker(
        [b"RUN cd /workspace && uv sync --frozen: exit code 1"]
    )

    with pytest.raises(DockerOperationError, match="DOCKER_BUILD_FAILED") as failure:
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
        ).prepare(
            _environment_checkpoint(artifacts, action="RETRY_STAGE", patch=""),
            {},
            (),
        )

    assert b"uv sync --frozen" in docker.dockerfiles[0]
    assert len(docker.dockerfiles) == 1
    recipe = json.loads(artifacts.read(failure.value.recipe_ref))  # type: ignore[attr-defined]
    assert recipe["degraded"] is False
    assert recipe["status"] == "BLOCKED"


@pytest.mark.asyncio
async def test_plain_root_pyproject_keeps_existing_pip_and_fallback(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "pyproject.toml").write_text(
        '[project]\nname = "example-root"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-plain-root",
        workspace_id="workspace-plain-root",
        commit_id="f" * 40,
        hypothesis_id="hypothesis-plain-root",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    docker = _FailingBuildDocker([b"RUN pip install --no-cache-dir .: exit code 1"])

    result = await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    ).prepare(
        _environment_checkpoint(artifacts, action="RETRY_STAGE", patch=""),
        {},
        (),
    )

    assert b"RUN pip install --no-cache-dir ." in docker.dockerfiles[0]
    assert b"uv sync" not in docker.dockerfiles[0]
    assert len(docker.dockerfiles) == 2
    assert json.loads(artifacts.read(result.recipe_ref))["degraded"] is True


@pytest.mark.asyncio
async def test_nested_manifest_install_failure_stays_blocked(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    project = workspace / "service"
    project.mkdir(parents=True)
    (project / "app.py").write_text("pass\n", encoding="utf-8")
    (project / "pyproject.toml").write_text(
        '[project]\nname = "example"\nversion = "0.1.0"\n', encoding="utf-8"
    )
    identity = CheckpointIdentity(
        analysis_id="analysis-install-failure",
        workspace_id="workspace-install-failure",
        commit_id="c" * 40,
        hypothesis_id="hypothesis-install-failure",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    proposal_ref = artifacts.put_json(
        {
            "kind": "simple_hypothesis_proposal",
            "proposal": {"code_locations": ["service/app.py:1"]},
        }
    )
    pro_con = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(proposal_ref,),
        input_hash=input_reference_hash((proposal_ref,)),
    )
    docker = _FailingBuildDocker(
        [b"RUN python -m pip install --no-cache-dir /workspace/service: exit code 1"]
    )

    with pytest.raises(DockerOperationError) as failure:
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
        ).prepare(
            _environment_checkpoint(artifacts, action="RETRY_STAGE", patch=""),
            {SimpleStage.PRO_CON_DONE: pro_con},
            (),
        )

    assert len(docker.dockerfiles) == 1
    assert (
        b"python -m pip install --no-cache-dir /workspace/service"
        in docker.dockerfiles[0]
    )
    recipe = json.loads(artifacts.read(failure.value.recipe_ref))  # type: ignore[attr-defined]
    assert recipe["status"] == "BLOCKED"
    assert recipe["degraded"] is False
    assert len(recipe["build_attempt_refs"]) == 1


@pytest.mark.parametrize(
    "patch",
    [
        "RUN python -m pip install 'pytest==8.3.0'",
        "ENV PLAYWRIGHT_BROWSERS_PATH=/opt/sastsimi-playwright-browsers\n"
        "RUN python -m playwright install --with-deps chromium",
    ],
)
@pytest.mark.asyncio
async def test_rebuild_decision_patches_only_in_memory_dockerfile(
    tmp_path: Path,
    patch: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    original = b"FROM python:3.12-slim\n"
    dockerfile_path = workspace / "Dockerfile"
    dockerfile_path.write_bytes(original)
    identity = CheckpointIdentity(
        analysis_id="analysis-rebuild",
        workspace_id="workspace-rebuild",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-rebuild",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    checkpoint = _environment_checkpoint(
        artifacts,
        action="REBUILD_ENVIRONMENT",
        patch=patch,
    )
    docker = _BuildDocker()
    before = hashlib.sha256(dockerfile_path.read_bytes()).hexdigest()

    await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    ).prepare(checkpoint, {}, ())

    assert len(docker.dockerfiles) == 1
    built = docker.dockerfiles[0]
    assert built.count(b"# SASTSIMI validated recovery patch") == 1
    assert built.count(patch.encode("utf-8")) == 1
    assert hashlib.sha256(dockerfile_path.read_bytes()).hexdigest() == before
    assert dockerfile_path.read_bytes() == original


@pytest.mark.asyncio
async def test_non_rebuild_decision_does_not_patch_environment(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "Dockerfile").write_bytes(b"FROM python:3.12-slim\n")
    identity = CheckpointIdentity(
        analysis_id="analysis-retry",
        workspace_id="workspace-retry",
        commit_id="b" * 40,
        hypothesis_id="hypothesis-retry",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    checkpoint = _environment_checkpoint(
        artifacts,
        action="RETRY_STAGE",
        patch="",
    )
    docker = _BuildDocker()

    await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    ).prepare(checkpoint, {}, ())

    assert b"SASTSIMI validated recovery patch" not in docker.dockerfiles[0]


@pytest.mark.asyncio
async def test_retry_after_rebuild_keeps_the_latest_rebuild_patch(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "Dockerfile").write_bytes(b"FROM python:3.12-slim\n")
    identity = CheckpointIdentity(
        analysis_id="analysis-rebuild-retry",
        workspace_id="workspace-rebuild-retry",
        commit_id="e" * 40,
        hypothesis_id="hypothesis-rebuild-retry",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    rebuild = _environment_checkpoint(
        artifacts,
        action="REBUILD_ENVIRONMENT",
        patch="RUN python -m pip install 'pytest==8.3.0'",
    )
    retry = _environment_checkpoint(
        artifacts,
        action="RETRY_STAGE",
        patch="",
    )
    inputs = rebuild.input_refs + retry.input_refs
    checkpoint = retry.model_copy(
        update={
            "input_refs": inputs,
            "input_hash": input_reference_hash(inputs),
            "recovery_decision_refs": (
                *rebuild.recovery_decision_refs,
                *retry.recovery_decision_refs,
            ),
        }
    )
    docker = _BuildDocker()

    await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    ).prepare(checkpoint, {}, ())

    assert b"RUN python -m pip install 'pytest==8.3.0'" in docker.dockerfiles[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("prior_built", [False, True])
async def test_rebuild_only_carries_prior_patch_with_built_recipe(
    tmp_path: Path,
    prior_built: bool,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "Dockerfile").write_bytes(b"FROM python:3.12-slim\n")
    identity = CheckpointIdentity(
        analysis_id="analysis-rebuild-correction",
        workspace_id="workspace-rebuild-correction",
        commit_id="d" * 40,
        hypothesis_id="hypothesis-rebuild-correction",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    first = _environment_checkpoint(
        artifacts,
        action="REBUILD_ENVIRONMENT",
        patch="RUN python -m pip install pytest",
    )
    first_docker = (
        _BuildDocker() if prior_built else _FailingBuildDocker([b"pull access denied"])
    )
    first_preparer = DirectEnvironmentPreparer(
        docker=first_docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    )
    if prior_built:
        recipe_ref = (await first_preparer.prepare(first, {}, ())).recipe_ref
    else:
        with pytest.raises(DockerOperationError) as failure:
            await first_preparer.prepare(first, {}, ())
        recipe_ref = failure.value.recipe_ref  # type: ignore[attr-defined]

    second = _environment_checkpoint(
        artifacts,
        action="REBUILD_ENVIRONMENT",
        patch="RUN python -m pip install PyJWT",
    )
    inputs = (*first.input_refs, recipe_ref, *second.input_refs)
    checkpoint = second.model_copy(
        update={
            "input_refs": inputs,
            "input_hash": input_reference_hash(inputs),
            "recovery_decision_refs": (
                *first.recovery_decision_refs,
                *second.recovery_decision_refs,
            ),
        }
    )
    second_docker = _BuildDocker()
    await DirectEnvironmentPreparer(
        docker=second_docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    ).prepare(checkpoint, {}, ())

    assert len(second_docker.dockerfiles) == 1
    assert (b"RUN python -m pip install pytest" in second_docker.dockerfiles[0]) is (
        prior_built
    )
    assert b"RUN python -m pip install PyJWT" in second_docker.dockerfiles[0]


def test_unbound_rebuild_decision_ref_fails_closed(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    artifacts = SimpleArtifactRepository(
        tmp_path / "data",
        CheckpointIdentity(
            analysis_id="analysis-unbound-rebuild",
            workspace_id="workspace-unbound-rebuild",
            commit_id="d" * 40,
            hypothesis_id="hypothesis-unbound-rebuild",
        ),
    )
    checkpoint = _environment_checkpoint(
        artifacts,
        action="REBUILD_ENVIRONMENT",
        patch="RUN python -m pip install pytest",
    ).model_copy(update={"recovery_decision_refs": ()})

    with pytest.raises(ValueError, match="RECOVERY_DECISION_REF_UNBOUND"):
        DirectEnvironmentPreparer(
            docker=_BuildDocker(),  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
        )._recovery_patch(checkpoint)


@pytest.mark.asyncio
async def test_built_recipe_alone_does_not_authorize_unbound_rebuild_ref(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "Dockerfile").write_bytes(b"FROM python:3.12-slim\n")
    artifacts = SimpleArtifactRepository(
        tmp_path / "data",
        CheckpointIdentity(
            analysis_id="analysis-replayed-rebuild",
            workspace_id="workspace-replayed-rebuild",
            commit_id="d" * 40,
            hypothesis_id="hypothesis-replayed-rebuild",
        ),
    )
    first = _environment_checkpoint(
        artifacts,
        action="REBUILD_ENVIRONMENT",
        patch="RUN python -m pip install pytest",
    )
    preparer = DirectEnvironmentPreparer(
        docker=_BuildDocker(),  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    )
    built = await preparer.prepare(first, {}, ())
    inputs = (*first.input_refs, built.recipe_ref)
    replay = first.model_copy(
        update={
            "input_refs": inputs,
            "input_hash": input_reference_hash(inputs),
            "recovery_decision_refs": (),
        }
    )

    with pytest.raises(ValueError, match="RECOVERY_DECISION_REF_UNBOUND"):
        preparer._recovery_patch(replay)


@pytest.mark.asyncio
async def test_completed_rebuild_survives_later_import_replan_without_unbinding(
    tmp_path: Path,
) -> None:
    """The store clears recovery refs on success but retains their input lineage."""

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "Dockerfile").write_bytes(b"FROM python:3.12-slim\n")
    identity = CheckpointIdentity(
        analysis_id="analysis-built-then-replan",
        workspace_id="workspace-built-then-replan",
        commit_id="e" * 40,
        hypothesis_id="hypothesis-built-then-replan",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    store = SimpleCheckpointStore(tmp_path / "data" / "checkpoints.sqlite3")
    first = _environment_checkpoint(
        artifacts,
        action="REBUILD_ENVIRONMENT",
        patch="RUN python -m pip install PyJWT",
    ).model_copy(
        update={"recovery_origin_stage": SimpleStage.VERIFICATION_INITIAL_DONE}
    )
    store.save_checkpoint(first)
    docker = _BuildDocker()
    preparer = DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    )
    environment = await preparer.prepare(first, {}, ())
    completed = store.complete(
        first,
        StageResult(
            output_refs=(environment.recipe_ref,),
            recipe_ref=environment.recipe_ref,
            image_digest=environment.image_digest,
        ),
    )
    assert completed.recovery_decision_refs == ()

    error_ref = artifacts.put_bytes(b"ModuleNotFoundError: jwt", "text/plain")
    failed = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_EXECUTION_DONE,
        status=StageStatus.BLOCKED,
        input_refs=(environment.recipe_ref,),
        input_hash=input_reference_hash((environment.recipe_ref,)),
        output_refs=(error_ref,),
        recipe_ref=environment.recipe_ref,
        image_digest=environment.image_digest,
        error_code="POC_RUNTIME_IMPORT_FAILED",
        retryable=True,
        attempt_number=2,
    )
    store.save_checkpoint(failed)
    replan_ref = artifacts.put_json(
        {
            "kind": "simple_recovery_decision",
            "identity": identity.model_dump(mode="json"),
            "stage": SimpleStage.POC_EXECUTION_DONE.value,
            "decision_origin": "RULE",
            "original_error": {"code": "POC_RUNTIME_IMPORT_FAILED"},
            "decision": {
                "category": "ENVIRONMENT",
                "action": "REPLAN_ENVIRONMENT",
                "diagnosis": "missing runtime dependency",
                "guidance": "replan pinned requirements",
                "environment_patch": "",
            },
        }
    )
    pending = store.prepare_recovery(
        failed,
        RecoveryResolution(
            decision=RecoveryDecision(
                category=RecoveryCategory.ENVIRONMENT,
                action=RecoveryAction.REPLAN_ENVIRONMENT,
                diagnosis="missing runtime dependency",
                guidance="replan pinned requirements",
            ),
            decision_ref=replan_ref,
        ),
        SimpleStage.VERIFICATION_INITIAL_DONE,
    )
    assert first.input_refs[0] in pending.input_refs
    assert first.input_refs[0] not in pending.recovery_decision_refs
    assert environment.recipe_ref in pending.input_refs
    assert replan_ref in pending.recovery_decision_refs
    running = store.mark_running(
        identity,
        SimpleStage.VERIFICATION_INITIAL_DONE,
        pending.input_refs,
        attempt_id="replan-attempt",
        inherit_from=pending,
    )

    rebuilt = await preparer.prepare(running, {}, ())

    assert rebuilt.recipe_ref is not None
    assert len(docker.dockerfiles) == 2
    assert b"RUN python -m pip install PyJWT" in docker.dockerfiles[-1]


def test_import_replan_preserves_a_prior_validated_dockerfile_patch(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    identity = CheckpointIdentity(
        analysis_id="analysis-import-replan",
        workspace_id="workspace-import-replan",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-import-replan",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    old = _environment_checkpoint(
        artifacts,
        action="REBUILD_ENVIRONMENT",
        patch="RUN python -m pip install pytest",
    )
    replan_ref = artifacts.put_json(
        {
            "kind": "simple_recovery_decision",
            "identity": identity.model_dump(mode="json"),
            "stage": SimpleStage.POC_EXECUTION_DONE.value,
            "decision_origin": "RULE",
            "original_error": {
                "code": "POC_RUNTIME_IMPORT_FAILED",
                "retryable": True,
                "safe_message": "isolated import failed",
                "evidence_refs": [],
            },
            "decision": {
                "category": "ENVIRONMENT",
                "action": "REPLAN_ENVIRONMENT",
                "diagnosis": "isolated import failed",
                "guidance": "replan pinned package requirements",
                "environment_patch": "",
            },
        }
    )
    inputs = (*old.input_refs, replan_ref)
    checkpoint = old.model_copy(
        update={
            "input_refs": inputs,
            "input_hash": input_reference_hash(inputs),
            "recovery_decision_refs": inputs,
        }
    )

    preparer = DirectEnvironmentPreparer(
        docker=_BuildDocker(),  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    )
    assert b"RUN python -m pip install pytest" in preparer._recovery_patch(checkpoint)


@pytest.mark.asyncio
async def test_multiple_rebuilds_keep_distinct_patches_once_in_order(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "Dockerfile").write_bytes(b"FROM python:3.12-slim\n")
    identity = CheckpointIdentity(
        analysis_id="analysis-patch-sequence",
        workspace_id="workspace-patch-sequence",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-patch-sequence",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    first = _environment_checkpoint(
        artifacts,
        action="REBUILD_ENVIRONMENT",
        patch="RUN python -m pip install pytest",
    )
    preparer = DirectEnvironmentPreparer(
        docker=_BuildDocker(),  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    )
    first_recipe = (await preparer.prepare(first, {}, ())).recipe_ref
    second = _environment_checkpoint(
        artifacts,
        action="REBUILD_ENVIRONMENT",
        patch="RUN python -m pip install PyJWT",
    )
    inputs = (*first.input_refs, first_recipe, *second.input_refs, *first.input_refs)
    checkpoint = second.model_copy(
        update={
            "input_refs": inputs,
            "input_hash": input_reference_hash(inputs),
            "recovery_decision_refs": (
                *first.recovery_decision_refs,
                *second.recovery_decision_refs,
            ),
        }
    )

    patch = preparer._recovery_patch(checkpoint)

    assert patch.count(b"RUN python -m pip install pytest") == 1
    assert patch.count(b"RUN python -m pip install PyJWT") == 1
    assert patch.index(b"RUN python -m pip install pytest") < patch.index(
        b"RUN python -m pip install PyJWT"
    )


def test_import_replan_from_unbound_agent_decision_fails_closed(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    identity = CheckpointIdentity(
        analysis_id="analysis-import-replan-unbound",
        workspace_id="workspace-import-replan-unbound",
        commit_id="b" * 40,
        hypothesis_id="hypothesis-import-replan-unbound",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    replan_ref = artifacts.put_json(
        {
            "kind": "simple_recovery_decision",
            "identity": identity.model_dump(mode="json"),
            "stage": SimpleStage.POC_EXECUTION_DONE.value,
            "decision_origin": "AGENT",
            "original_error": {"code": "POC_RUNTIME_IMPORT_FAILED"},
            "decision": {
                "category": "ENVIRONMENT",
                "action": "REPLAN_ENVIRONMENT",
                "diagnosis": "unbound",
                "guidance": "replan",
                "environment_patch": "",
            },
        }
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        status=StageStatus.RUNNING,
        input_refs=(replan_ref,),
        input_hash=input_reference_hash((replan_ref,)),
        recovery_decision_refs=(replan_ref,),
    )

    with pytest.raises(ValueError, match="RECOVERY_REPLAN_EVIDENCE_INVALID"):
        DirectEnvironmentPreparer(
            docker=_BuildDocker(),  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
        )._recovery_patch(checkpoint)


@pytest.mark.asyncio
async def test_rebuild_rejects_a_different_hypothesis_decision(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "Dockerfile").write_bytes(b"FROM python:3.12-slim\n")
    target_identity = CheckpointIdentity(
        analysis_id="analysis-scope",
        workspace_id="workspace-scope",
        commit_id="f" * 40,
        hypothesis_id="hypothesis-target",
    )
    foreign_identity = target_identity.model_copy(
        update={"hypothesis_id": "hypothesis-foreign"}
    )
    foreign_artifacts = SimpleArtifactRepository(tmp_path / "data", foreign_identity)
    foreign = _environment_checkpoint(
        foreign_artifacts,
        action="REBUILD_ENVIRONMENT",
        patch="RUN python -m pip install pytest",
    )
    checkpoint = foreign.model_copy(update={"identity": target_identity})
    docker = _BuildDocker()

    with pytest.raises(ValueError, match="RECOVERY_DECISION_IDENTITY_MISMATCH"):
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=SimpleArtifactRepository(tmp_path / "data", target_identity),
            workspace=workspace,
        ).prepare(checkpoint, {}, ())

    assert docker.dockerfiles == []


@pytest.mark.asyncio
async def test_invalid_recovery_decision_artifact_fails_before_docker_build(
    tmp_path: Path,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    identity = CheckpointIdentity(
        analysis_id="analysis-invalid",
        workspace_id="workspace-invalid",
        commit_id="c" * 40,
        hypothesis_id="hypothesis-invalid",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    invalid_ref = artifacts.put_json(
        {
            "kind": "simple_recovery_decision",
            "identity": identity.model_dump(mode="json"),
            "decision": {"action": "STOP"},
        }
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        status=StageStatus.RUNNING,
        input_refs=(invalid_ref,),
        input_hash=input_reference_hash((invalid_ref,)),
    )
    docker = _BuildDocker()

    with pytest.raises(ValueError):
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
        ).prepare(checkpoint, {}, ())

    assert docker.dockerfiles == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "patch",
    [
        "RUN python -m pip install pytest && powershell.exe",
        "RUN python -m pip install pytest > /tmp/output",
        "RUN echo unbounded-command",
    ],
)
async def test_unsafe_recovery_patch_fails_before_docker_build(
    tmp_path: Path,
    patch: str,
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    identity = CheckpointIdentity(
        analysis_id="analysis-unsafe",
        workspace_id="workspace-unsafe",
        commit_id="d" * 40,
        hypothesis_id="hypothesis-unsafe",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    checkpoint = _environment_checkpoint(
        artifacts,
        action="REBUILD_ENVIRONMENT",
        patch=patch,
    )
    docker = _BuildDocker()

    with pytest.raises(
        ValueError,
        match="RECOVERY_ENVIRONMENT_PATCH_FORBIDDEN",
    ):
        await DirectEnvironmentPreparer(
            docker=docker,  # type: ignore[arg-type]
            artifacts=artifacts,
            workspace=workspace,
        ).prepare(checkpoint, {}, ())

    assert docker.dockerfiles == []
