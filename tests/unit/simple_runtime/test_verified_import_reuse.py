"""A verified missing product import can be reused by sibling PoCs."""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import subprocess
import tarfile
import zipfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from sastsimi.sandbox.docker_adapter import (
    DockerCommandOutcome,
    DockerOperationError,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.offline_wheels import import_wheel_bundle
from sastsimi.simple_runtime.portable_docker import (
    AutoWheelBundleCache,
    DirectEnvironmentPreparer,
    ImportSmokeCleanupUnconfirmed,
    PortableDockerRuntime,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.runner import SimpleRuntimeRunner
from sastsimi.simple_runtime.stages import InitialVerificationStage
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from tests.unit.simple_runtime.test_offline_preparer import (
    _checkpoint,
    _Docker,
    _fixture,
)


def _wheel(name: str, package: str) -> bytes:
    stream = io.BytesIO()
    normalized = name.replace("-", "_")
    with zipfile.ZipFile(stream, "w") as wheel:
        wheel.writestr(f"{package}/__init__.py", "")
        wheel.writestr(
            f"{normalized}-1.0.dist-info/WHEEL",
            "Wheel-Version: 1.0\nTag: py3-none-any\n",
        )
        wheel.writestr(
            f"{normalized}-1.0.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n",
        )
    return stream.getvalue()


def _bundle(*wheels: tuple[str, str]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, package in wheels:
            raw = _wheel(name, package)
            info = tarfile.TarInfo(
                f"{name.replace('-', '_')}-1.0-py3-none-any.whl"
            )
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return stream.getvalue()


def _purelib_wheel(name: str, member: str) -> bytes:
    stream = io.BytesIO()
    normalized = name.replace("-", "_")
    with zipfile.ZipFile(stream, "w") as wheel:
        wheel.writestr(
            f"{normalized}-1.0.data/purelib/{member}", "",
        )
        wheel.writestr(
            f"{normalized}-1.0.dist-info/WHEEL",
            "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        )
        wheel.writestr(
            f"{normalized}-1.0.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n",
        )
    return stream.getvalue()


def _native_wheel(name: str, member: str, tag: str) -> bytes:
    stream = io.BytesIO()
    normalized = name.replace("-", "_")
    with zipfile.ZipFile(stream, "w") as wheel:
        wheel.writestr(member, b"native-extension-fixture")
        wheel.writestr(
            f"{normalized}-1.0.dist-info/WHEEL",
            f"Wheel-Version: 1.0\nRoot-Is-Purelib: false\nTag: {tag}\n",
        )
        wheel.writestr(
            f"{normalized}-1.0.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: {name}\nVersion: 1.0\n",
        )
    return stream.getvalue()


def _raw_wheel_bundle(*wheels: tuple[str, bytes]) -> bytes:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        for name, raw in wheels:
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return stream.getvalue()


def _source_fixture(
    tmp_path: Path, *, with_manifest: bool = True
) -> tuple[Path, str]:
    workspace, _commit, _path, _digest = _fixture(
        tmp_path, manifest="sample-pkg==1.0\n"
    )
    (workspace / "app.py").write_text("import widget_api\n", encoding="utf-8")
    if not with_manifest:
        (workspace / "requirements.txt").unlink()
    subprocess.run(("git", "-C", str(workspace), "add", "-A"), check=True)
    subprocess.run(
        (
            "git", "-C", str(workspace), "-c", "user.name=Test",
            "-c", "user.email=test@example.invalid", "commit", "-qm", "import",
        ),
        check=True,
    )
    commit = subprocess.check_output(
        ("git", "-C", str(workspace), "rev-parse", "HEAD")
    ).decode("ascii").strip()
    return workspace, commit


def _import_replan(
    artifacts: SimpleArtifactRepository,
    checkpoint: StageCheckpoint,
    *,
    failed_attempt: int = 1,
    evidence_attempt_id: str = "failed-attempt",
) -> StageCheckpoint:
    evidence = artifacts.put_json(
        {
            "kind": "simple_poc_execution",
            "attempt_id": evidence_attempt_id,
            "timed_out": False,
            "exit_code": 1,
        }
    )
    decision = artifacts.put_json(
        {
            "kind": "simple_recovery_decision",
            "identity": checkpoint.identity.model_dump(mode="json"),
            "stage": "POC_EXECUTION_DONE",
            "attempt": failed_attempt,
            "attempt_id": "failed-attempt",
            "decision_origin": "RULE",
            "original_error": {
                "code": "POC_RUNTIME_IMPORT_FAILED",
                "retryable": True,
                "evidence_refs": [evidence.model_dump(mode="json")],
            },
            "diagnostic_excerpt": (
                "ModuleNotFoundError: widget_api\nTraceback: frame -> exec_module"
            ),
            "decision": {
                "category": "ENVIRONMENT",
                "action": "REPLAN_ENVIRONMENT",
                "diagnosis": "verified import failure",
                "guidance": "Use an explicit verified distribution",
                "environment_patch": "",
            },
        }
    )
    refs = (evidence, decision)
    return checkpoint.model_copy(
        update={
            "attempt_number": 2,
            "recovery_lineage_id": "synthetic-lineage",
            "input_refs": refs,
            "input_hash": input_reference_hash(refs),
            "recovery_decision_refs": (decision,),
        }
    )


class _Resolver(_Docker):
    def __init__(self, *, smoke_passes: bool = True, ambiguous: bool = False) -> None:
        super().__init__()
        self.smoke_passes = smoke_passes
        self.ambiguous = ambiguous
        self.base_digest = "sha256:" + "b" * 64
        self.downloads: list[tuple[str, ...]] = []
        self.smokes: list[tuple[str, str]] = []

    async def download_python_wheels(self, **kwargs: object) -> bytes:
        requirements = kwargs["requirements"]
        assert isinstance(requirements, tuple)
        self.downloads.append(requirements)
        wheels = [("sample-pkg", "sample_pkg")]
        if "widget-dist" in requirements:
            wheels.append(("widget-dist", "widget_api"))
            if self.ambiguous:
                wheels.append(("other-dist", "widget_api"))
        return _bundle(*wheels)

    async def local_base_image_digest(self, base_image: str) -> str:
        if base_image == "python:3.12-slim":
            return self.base_digest
        if base_image.startswith("sastsimi-offline-base:"):
            return "sha256:" + base_image.partition(":")[2]
        if base_image.startswith("sha256:"):
            return base_image
        raise AssertionError(base_image)

    async def target_wheel_tags(self, base_image: str) -> frozenset[str]:
        assert base_image == self.base_digest
        return frozenset({"py3-none-any"})

    async def pin_local_base(self, image_digest: str) -> str:
        assert image_digest == self.base_digest
        return "sastsimi-offline-base:" + image_digest.partition(":")[2]

    async def probe_python_import(
        self,
        image_digest: str,
        module: str,
        identity: CheckpointIdentity,
        attempt_id: str,
    ) -> bool:
        del identity, attempt_id
        self.smokes.append((image_digest, module))
        return self.smoke_passes and module == "widget_api"


@pytest.mark.asyncio
@pytest.mark.parametrize("with_manifest", (True, False))
async def test_verified_import_requirement_reused_by_sibling(
    tmp_path: Path, with_manifest: bool,
) -> None:
    """Without reuse, a sibling keeps the same missing product import."""

    workspace, commit = _source_fixture(tmp_path, with_manifest=with_manifest)
    artifacts, first = _checkpoint(tmp_path, commit)
    first = _import_replan(artifacts, first)
    second_identity = first.identity.model_copy(update={"hypothesis_id": "sibling"})
    second = first.model_copy(
        update={
            "identity": second_identity,
            "attempt_number": 1,
            "input_refs": (),
            "input_hash": input_reference_hash(()),
            "recovery_decision_refs": (),
        }
    )

    docker = _Resolver()
    cache = AutoWheelBundleCache()
    first_preparer = DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        auto_dependency_bundle=True,
        auto_bundle_cache=cache,
    )
    second_artifacts = SimpleArtifactRepository(tmp_path / "data", second_identity)
    second_preparer = DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=second_artifacts,
        workspace=workspace,
        auto_dependency_bundle=True,
        auto_bundle_cache=cache,
    )

    await first_preparer.prepare(first, {}, ("pip:widget-dist",))
    sibling_environment = await second_preparer.prepare(second, {}, ())
    sibling_recipe = json.loads(
        second_artifacts.read(sibling_environment.recipe_ref)
    )

    assert "pip:widget-dist" in sibling_recipe["requirements"]
    assert sibling_recipe["dependency_resolution_verified_import_reuse"] == [
        {
            "module": "widget_api",
            "requirement": "widget-dist",
            "decision_sha256": first.recovery_decision_refs[-1].content_hash,
        }
    ]
    expected_download = (
        (("sample-pkg==1.0",) if with_manifest else ()) + ("widget-dist",)
    )
    assert docker.downloads == [expected_download]
    assert docker.smokes == [("sha256:" + "c" * 64, "widget_api")]
    assert docker.calls[0][1] == docker.calls[1][1]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure", ("smoke", "ambiguous", "unbound", "stale", "wrong_attempt_id")
)
async def test_unverified_import_is_not_reused(
    tmp_path: Path, failure: str
) -> None:
    workspace, commit = _source_fixture(tmp_path)
    artifacts, first = _checkpoint(tmp_path, commit)
    if failure != "unbound":
        first = _import_replan(
            artifacts,
            first,
            failed_attempt=0 if failure == "stale" else 1,
            evidence_attempt_id=(
                "older-attempt" if failure == "wrong_attempt_id" else "failed-attempt"
            ),
        )
    second_identity = first.identity.model_copy(update={"hypothesis_id": "sibling"})
    second = first.model_copy(
        update={
            "identity": second_identity,
            "attempt_number": 1,
            "input_refs": (),
            "input_hash": input_reference_hash(()),
            "recovery_decision_refs": (),
        }
    )
    docker = _Resolver(
        smoke_passes=failure != "smoke", ambiguous=failure == "ambiguous"
    )
    cache = AutoWheelBundleCache()
    first_preparer = DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        auto_dependency_bundle=True,
        auto_bundle_cache=cache,
    )
    sibling_artifacts = SimpleArtifactRepository(tmp_path / "data", second_identity)
    sibling_preparer = DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=sibling_artifacts,
        workspace=workspace,
        auto_dependency_bundle=True,
        auto_bundle_cache=cache,
    )

    await first_preparer.prepare(first, {}, ("pip:widget-dist",))
    sibling_environment = await sibling_preparer.prepare(second, {}, ())
    sibling_recipe = json.loads(
        sibling_artifacts.read(sibling_environment.recipe_ref)
    )

    assert sibling_recipe["requirements"] == []
    assert docker.downloads[-1] == ("sample-pkg==1.0",)
    expected_smokes = (
        [("sha256:" + "c" * 64, "widget_api")]
        if failure == "smoke"
        else []
    )
    assert docker.smokes == expected_smokes
    assert docker.calls[0][1] != docker.calls[1][1]


@pytest.mark.asyncio
async def test_invalid_wheel_archive_cannot_seed_verified_import(
    tmp_path: Path,
) -> None:
    workspace, commit = _source_fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    checkpoint = _import_replan(artifacts, checkpoint)

    class _BadResolver(_Resolver):
        async def download_python_wheels(self, **kwargs: object) -> bytes:
            del kwargs
            return b"not a wheel archive"

    docker = _BadResolver()
    cache = AutoWheelBundleCache()
    preparer = DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        auto_dependency_bundle=True,
        auto_bundle_cache=cache,
    )
    with pytest.raises(ValueError, match="WHEEL_ARCHIVE_INVALID"):
        await preparer.prepare(checkpoint, {}, ("pip:widget-dist",))
    assert docker.calls == []
    assert docker.smokes == []
    assert not cache.has_verified_import_scope(
        ("offline-test", "offline-workspace", commit)
    )


@pytest.mark.asyncio
async def test_verified_import_is_scoped_to_base_digest(tmp_path: Path) -> None:
    workspace, commit = _source_fixture(tmp_path)
    artifacts, first = _checkpoint(tmp_path, commit)
    first = _import_replan(artifacts, first)
    second_identity = first.identity.model_copy(update={"hypothesis_id": "sibling"})
    second = first.model_copy(
        update={
            "identity": second_identity,
            "attempt_number": 1,
            "input_refs": (),
            "input_hash": input_reference_hash(()),
            "recovery_decision_refs": (),
        }
    )
    docker = _Resolver()
    cache = AutoWheelBundleCache()
    first_preparer = DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        auto_dependency_bundle=True,
        auto_bundle_cache=cache,
    )
    sibling_artifacts = SimpleArtifactRepository(tmp_path / "data", second_identity)
    sibling_preparer = DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=sibling_artifacts,
        workspace=workspace,
        auto_dependency_bundle=True,
        auto_bundle_cache=cache,
    )
    await first_preparer.prepare(first, {}, ("pip:widget-dist",))
    docker.base_digest = "sha256:" + "d" * 64

    sibling_environment = await sibling_preparer.prepare(second, {}, ())
    sibling_recipe = json.loads(
        sibling_artifacts.read(sibling_environment.recipe_ref)
    )
    assert sibling_recipe["requirements"] == []
    assert docker.downloads[-1] == ("sample-pkg==1.0",)
    assert docker.calls[0][1] != docker.calls[1][1]


@pytest.mark.asyncio
async def test_verified_import_is_scoped_to_pinned_commit(tmp_path: Path) -> None:
    workspace, commit = _source_fixture(tmp_path)
    artifacts, first = _checkpoint(tmp_path, commit)
    first = _import_replan(artifacts, first)
    docker = _Resolver()
    cache = AutoWheelBundleCache()
    first_preparer = DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        auto_dependency_bundle=True,
        auto_bundle_cache=cache,
    )
    await first_preparer.prepare(first, {}, ("pip:widget-dist",))

    (workspace / "README.md").write_text("second commit\n", encoding="utf-8")
    subprocess.run(("git", "-C", str(workspace), "add", "README.md"), check=True)
    subprocess.run(
        (
            "git", "-C", str(workspace), "-c", "user.name=Test",
            "-c", "user.email=test@example.invalid", "commit", "-qm", "next",
        ),
        check=True,
    )
    next_commit = subprocess.check_output(
        ("git", "-C", str(workspace), "rev-parse", "HEAD")
    ).decode("ascii").strip()
    sibling_identity = first.identity.model_copy(
        update={"commit_id": next_commit, "hypothesis_id": "sibling"}
    )
    sibling = first.model_copy(
        update={
            "identity": sibling_identity,
            "attempt_number": 1,
            "input_refs": (),
            "input_hash": input_reference_hash(()),
            "recovery_decision_refs": (),
        }
    )
    sibling_artifacts = SimpleArtifactRepository(tmp_path / "data", sibling_identity)
    sibling_preparer = DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=sibling_artifacts,
        workspace=workspace,
        auto_dependency_bundle=True,
        auto_bundle_cache=cache,
    )
    sibling_environment = await sibling_preparer.prepare(sibling, {}, ())
    sibling_recipe = json.loads(
        sibling_artifacts.read(sibling_environment.recipe_ref)
    )
    assert sibling_recipe["requirements"] == []
    assert docker.downloads[-1] == ("sample-pkg==1.0",)
    assert docker.calls[0][1] != docker.calls[1][1]


def test_verified_import_cache_requires_exact_runtime_scope() -> None:
    cache = AutoWheelBundleCache()
    scope = ("analysis", "workspace", "commit", "manifest", "base", "3.12")
    cache.put_verified_import(scope, "widget_api", "widget-dist", "a" * 64)
    assert cache.verified_imports(scope) == ("widget-dist",)
    assert cache.verified_imports((*scope[:-1], "3.11")) == ()


def test_conflicting_verified_provider_is_not_reused() -> None:
    cache = AutoWheelBundleCache()
    scope = ("analysis", "workspace", "commit", "manifest", "base", "3.12")
    cache.put_verified_import(scope, "widget_api", "widget-dist", "a" * 64)
    cache.put_verified_import(scope, "widget_api", "other-dist", "b" * 64)
    cache.put_verified_import(scope, "widget_api", "widget-dist", "c" * 64)
    assert cache.verified_imports(scope) == ()


@pytest.mark.parametrize(
    "provided_path", ("widget_api.py", "widget_api/__init__.py")
)
def test_purelib_wheel_provider_blocks_ambiguous_reuse(
    tmp_path: Path, provided_path: str
) -> None:
    root_wheel = _wheel("widget-dist", "widget_api")
    purelib_wheel = _purelib_wheel("other-dist", provided_path)
    archive = _raw_wheel_bundle(
        ("widget_dist-1.0-py3-none-any.whl", root_wheel),
        ("other_dist-1.0-py3-none-any.whl", purelib_wheel),
    )
    path = tmp_path / "valid-purelib-wheels.tar"
    path.write_bytes(archive)
    artifacts, _checkpoint_value = _checkpoint(tmp_path, "a" * 40)
    import_wheel_bundle(
        path,
        hashlib.sha256(archive).hexdigest(),
        artifacts,
        target_tags=frozenset({"py3-none-any"}),
    )
    assert DirectEnvironmentPreparer._unique_wheel_provider(
        archive, "widget_api", ("widget-dist",)
    ) is None


@pytest.mark.parametrize(
    ("member", "tag"),
    (
        ("widget_api.so", "cp312-cp312-manylinux_2_17_x86_64"),
        (
            "widget_api.cpython-312-x86_64-linux-gnu.so",
            "cp312-cp312-manylinux_2_17_x86_64",
        ),
        ("widget_api.pyd", "cp312-cp312-win_amd64"),
        (
            "other_dist-1.0.data/purelib/widget_api.so",
            "cp312-cp312-manylinux_2_17_x86_64",
        ),
    ),
)
def test_native_extension_wheel_blocks_ambiguous_import_binding(
    tmp_path: Path, member: str, tag: str
) -> None:
    root_wheel = _wheel("widget-dist", "widget_api")
    native_wheel = _native_wheel("other-dist", member, tag)
    archive = _raw_wheel_bundle(
        ("widget_dist-1.0-py3-none-any.whl", root_wheel),
        (f"other_dist-1.0-{tag}.whl", native_wheel),
    )
    path = tmp_path / "valid-native-wheels.tar"
    path.write_bytes(archive)
    artifacts, _checkpoint_value = _checkpoint(tmp_path, "a" * 40)
    import_wheel_bundle(
        path,
        hashlib.sha256(archive).hexdigest(),
        artifacts,
        target_tags=frozenset({"py3-none-any", tag}),
    )
    assert DirectEnvironmentPreparer._unique_wheel_provider(
        archive, "widget_api", ("widget-dist",)
    ) is None


def test_import_proof_ignores_dirty_checkout_bytes(tmp_path: Path) -> None:
    workspace, commit, _path, _digest = _fixture(tmp_path)
    (workspace / "app.py").write_text("import widget_api\n", encoding="utf-8")
    artifacts, _checkpoint_value = _checkpoint(tmp_path, commit)
    preparer = DirectEnvironmentPreparer(
        docker=_Resolver(),  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        auto_dependency_bundle=True,
    )
    assert not preparer._pinned_source_imports(
        "widget_api", frozenset({"app.py"}), commit_id=commit
    )


def test_import_proof_rejects_large_git_blob_before_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace, _commit, _path, _digest = _fixture(tmp_path)
    (workspace / "app.py").write_text(
        "import widget_api\n" + "# padding\n" * 30_000,
        encoding="utf-8",
    )
    subprocess.run(("git", "-C", str(workspace), "add", "app.py"), check=True)
    subprocess.run(
        (
            "git", "-C", str(workspace), "-c", "user.name=Test",
            "-c", "user.email=test@example.invalid", "commit", "-qm", "large",
        ),
        check=True,
    )
    commit = subprocess.check_output(
        ("git", "-C", str(workspace), "rev-parse", "HEAD")
    ).decode("ascii").strip()
    artifacts, _checkpoint_value = _checkpoint(tmp_path, commit)
    preparer = DirectEnvironmentPreparer(
        docker=_Resolver(),  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        auto_dependency_bundle=True,
    )
    real_run = subprocess.run
    git_actions: list[str] = []

    def record_run(
        *args: Any, **kwargs: Any
    ) -> subprocess.CompletedProcess[Any]:
        command = args[0]
        assert isinstance(command, tuple)
        git_actions.append(command[3])
        return real_run(*args, **kwargs)

    monkeypatch.setattr(subprocess, "run", record_run)
    assert not preparer._pinned_source_imports(
        "widget_api", frozenset({"app.py"}), commit_id=commit
    )
    assert "cat-file" in git_actions
    assert "show" not in git_actions


class _ProbeDocker(PortableDockerRuntime):
    def __init__(self, *, run_mode: str = "success") -> None:
        self.run_mode = run_mode
        self.commands: list[tuple[str, ...]] = []
        self.container_name: str | None = None

    async def _run(
        self,
        args: Sequence[str],
        *,
        timeout_seconds: int,
        input_bytes: bytes | None = None,
    ) -> DockerCommandOutcome:
        assert timeout_seconds == 30
        assert input_bytes is None
        self.commands.append(tuple(args))
        if args[0] == "run":
            self.container_name = args[args.index("--name") + 1]
            if self.run_mode in {
                "cancel", "cancel_cleanup_timeout", "cancel_cleanup_error"
            }:
                raise asyncio.CancelledError()
            if self.run_mode == "timeout":
                return DockerCommandOutcome(-1, b"", b"", True)
            if self.run_mode == "import_failure":
                return DockerCommandOutcome(1, b"", b"", False)
            return DockerCommandOutcome(0, b"", b"", False)
        if args[:2] == ("rm", "--force"):
            if self.run_mode in {"cleanup_timeout", "cancel_cleanup_timeout"}:
                return DockerCommandOutcome(-1, b"", b"", True)
            if self.run_mode == "cancel_cleanup_error":
                raise DockerOperationError("SYNTHETIC_DOCKER_ERROR")
            return DockerCommandOutcome(0, b"", b"", False)
        assert args[:2] == ("container", "inspect")
        assert self.container_name is not None
        return DockerCommandOutcome(
            1,
            b"[]",
            f"Error: No such container: {self.container_name}".encode(),
            False,
        )


def _probe_identity() -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="probe-analysis",
        workspace_id="probe-workspace",
        commit_id="a" * 40,
        hypothesis_id="probe-hypothesis",
    )


@pytest.mark.asyncio
async def test_import_smoke_keeps_built_image_isolated_and_owned() -> None:
    docker = _ProbeDocker()
    digest = "sha256:" + "c" * 64
    assert await docker.probe_python_import(
        digest, "widget_api", _probe_identity(), "probe-attempt"
    )
    assert len(docker.commands) == 3
    command = docker.commands[0]
    assert command[0] == "run"
    name = command[command.index("--name") + 1]
    assert name.startswith("sastsimi-import-smoke-")
    labels = {
        command[index + 1]
        for index, part in enumerate(command[:-1])
        if part == "--label"
    }
    assert "sastsimi.owner=simple-runtime" in labels
    assert "sastsimi.analysis-id=probe-analysis" in labels
    assert "sastsimi.attempt-id=probe-attempt" in labels
    assert command[command.index("--pull") + 1] == "never"
    assert command[command.index("--network") + 1] == "none"
    assert "--read-only" in command
    assert command[command.index("--user") + 1] == "10001:10001"
    assert "--cap-drop" in command
    assert "--security-opt" in command
    assert command[command.index("--entrypoint") + 1] == "python"
    assert command[command.index("--entrypoint") + 2] == digest
    assert command[-3:-1] == ("-I", "-c")
    assert docker.commands[1] == ("rm", "--force", name)
    assert docker.commands[2] == ("container", "inspect", name)
    assert not await docker.probe_python_import(
        "python:3.12-slim", "widget_api", _probe_identity(), "probe-attempt"
    )
    assert len(docker.commands) == 3


@pytest.mark.asyncio
async def test_import_smoke_timeout_forces_removal_and_returns_false() -> None:
    docker = _ProbeDocker(run_mode="timeout")
    assert not await docker.probe_python_import(
        "sha256:" + "c" * 64, "widget_api", _probe_identity(), "probe-attempt"
    )
    assert [command[0] for command in docker.commands] == [
        "run", "rm", "container"
    ]


@pytest.mark.asyncio
async def test_import_smoke_import_failure_returns_false_after_cleanup() -> None:
    docker = _ProbeDocker(run_mode="import_failure")
    assert not await docker.probe_python_import(
        "sha256:" + "c" * 64, "widget_api", _probe_identity(), "probe-attempt"
    )
    assert [command[0] for command in docker.commands] == [
        "run", "rm", "container"
    ]


@pytest.mark.asyncio
async def test_import_smoke_cancellation_forces_removal() -> None:
    docker = _ProbeDocker(run_mode="cancel")
    with pytest.raises(asyncio.CancelledError):
        await docker.probe_python_import(
            "sha256:" + "c" * 64, "widget_api", _probe_identity(), "probe-attempt"
        )
    assert [command[0] for command in docker.commands] == [
        "run", "rm", "container"
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "run_mode", ("cancel_cleanup_timeout", "cancel_cleanup_error")
)
async def test_import_smoke_uncertain_cleanup_overrides_cancellation(
    run_mode: str,
) -> None:
    docker = _ProbeDocker(run_mode=run_mode)
    with pytest.raises(ImportSmokeCleanupUnconfirmed) as unconfirmed:
        await docker.probe_python_import(
            "sha256:" + "c" * 64, "widget_api", _probe_identity(), "probe-attempt"
        )
    assert str(unconfirmed.value) == "POC_IMPORT_SMOKE_CLEANUP_FAILED"
    assert [command[0] for command in docker.commands] == ["run", "rm"]


@pytest.mark.asyncio
@pytest.mark.parametrize("cleanup_fails", (False, True))
async def test_import_smoke_repeated_cancellation_finishes_cleanup(
    cleanup_fails: bool,
) -> None:
    class _RepeatedCancelDocker(_ProbeDocker):
        def __init__(self) -> None:
            super().__init__()
            self.run_started = asyncio.Event()
            self.remove_started = asyncio.Event()
            self.allow_remove = asyncio.Event()

        async def _run(
            self,
            args: Sequence[str],
            *,
            timeout_seconds: int,
            input_bytes: bytes | None = None,
        ) -> DockerCommandOutcome:
            assert input_bytes is None
            if args[0] == "run":
                self.commands.append(tuple(args))
                self.container_name = args[args.index("--name") + 1]
                self.run_started.set()
                await asyncio.Event().wait()
                raise AssertionError("run must be cancelled")
            if args[:2] == ("rm", "--force"):
                self.commands.append(tuple(args))
                self.remove_started.set()
                await self.allow_remove.wait()
                if cleanup_fails:
                    return DockerCommandOutcome(-1, b"", b"", True)
                return DockerCommandOutcome(0, b"", b"", False)
            return await super()._run(args, timeout_seconds=timeout_seconds)

    docker = _RepeatedCancelDocker()
    task = asyncio.create_task(
        docker.probe_python_import(
            "sha256:" + "c" * 64,
            "widget_api",
            _probe_identity(),
            "probe-attempt",
        )
    )
    try:
        await asyncio.wait_for(docker.run_started.wait(), timeout=10)
        task.cancel()
        await asyncio.wait_for(docker.remove_started.wait(), timeout=10)
        task.cancel()
        await asyncio.sleep(0)
        docker.allow_remove.set()
        expected_error = (
            ImportSmokeCleanupUnconfirmed if cleanup_fails else asyncio.CancelledError
        )
        with pytest.raises(expected_error) as raised:
            await task
        if cleanup_fails:
            assert str(raised.value) == "POC_IMPORT_SMOKE_CLEANUP_FAILED"
    finally:
        docker.allow_remove.set()
        if not task.done():
            task.cancel()
    assert [command[0] for command in docker.commands] == (
        ["run", "rm"] if cleanup_fails else ["run", "rm", "container"]
    )


@pytest.mark.asyncio
async def test_import_smoke_uncertain_cleanup_rejects_binding() -> None:
    docker = _ProbeDocker(run_mode="cleanup_timeout")
    with pytest.raises(ValueError, match="POC_IMPORT_SMOKE_CLEANUP_FAILED"):
        await docker.probe_python_import(
            "sha256:" + "c" * 64, "widget_api", _probe_identity(), "probe-attempt"
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("failed_command", "failure"),
    (
        ("rm", "oserror"),
        ("rm", "docker_error"),
        ("container", "oserror"),
        ("container", "docker_error"),
    ),
)
async def test_import_smoke_cleanup_command_errors_are_unconfirmed(
    failed_command: str, failure: str,
) -> None:
    class _CleanupErrorDocker(_ProbeDocker):
        async def _run(
            self,
            args: Sequence[str],
            *,
            timeout_seconds: int,
            input_bytes: bytes | None = None,
        ) -> DockerCommandOutcome:
            assert input_bytes is None
            if args[0] == failed_command:
                if failure == "oserror":
                    raise OSError("synthetic docker unavailable")
                raise DockerOperationError("SYNTHETIC_DOCKER_ERROR")
            return await super()._run(args, timeout_seconds=timeout_seconds)

    docker = _CleanupErrorDocker()
    with pytest.raises(
        ImportSmokeCleanupUnconfirmed, match="POC_IMPORT_SMOKE_CLEANUP_FAILED"
    ):
        await docker.probe_python_import(
            "sha256:" + "c" * 64, "widget_api", _probe_identity(), "probe-attempt"
        )


@pytest.mark.asyncio
async def test_uncertain_import_smoke_cleanup_blocks_preparation(
    tmp_path: Path,
) -> None:
    workspace, commit = _source_fixture(tmp_path)
    artifacts, checkpoint = _checkpoint(tmp_path, commit)
    checkpoint = _import_replan(artifacts, checkpoint)

    class _UncertainCleanupResolver(_Resolver):
        async def probe_python_import(
            self,
            image_digest: str,
            module: str,
            identity: CheckpointIdentity,
            attempt_id: str,
        ) -> bool:
            del image_digest, module, identity, attempt_id
            raise ImportSmokeCleanupUnconfirmed(
                "POC_IMPORT_SMOKE_CLEANUP_FAILED"
            )

    cache = AutoWheelBundleCache()
    preparer = DirectEnvironmentPreparer(
        docker=_UncertainCleanupResolver(),  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
        auto_dependency_bundle=True,
        auto_bundle_cache=cache,
    )
    with pytest.raises(
        ImportSmokeCleanupUnconfirmed, match="POC_IMPORT_SMOKE_CLEANUP_FAILED"
    ):
        await preparer.prepare(checkpoint, {}, ("pip:widget-dist",))
    assert not cache.has_verified_import_scope(
        ("offline-test", "offline-workspace", commit)
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "run_mode", ("cancel_cleanup_timeout", "cancel_cleanup_error")
)
async def test_uncertain_import_smoke_cleanup_blocks_stage_without_retry_or_poc(
    tmp_path: Path, run_mode: str,
) -> None:
    identity = _probe_identity()
    docker = _ProbeDocker(run_mode=run_mode)
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    store = SimpleCheckpointStore(
        tmp_path / "state" / "sastsimi.sqlite3",
        artifact_data_dir=tmp_path / "data",
    )

    class _Client:
        async def call(self, **_kwargs: object) -> SimpleLLMCallResult:
            return SimpleLLMCallResult(
                value={
                    "initial_assessment": "TRUE",
                    "rationale": "Run the local reproduction.",
                    "reproduction_goal": "Exercise the pinned route.",
                    "environment_requirements": [],
                    "unmet_external_prerequisites": [],
                    "supporting_refs": [],
                    "limitations": [],
                },
                prompt_digest="a" * 64,
                output_digest="b" * 64,
            )

    class _Environment:
        async def prepare(
            self,
            checkpoint: StageCheckpoint,
            prior: Mapping[SimpleStage, StageCheckpoint],
            requirements: tuple[str, ...],
        ) -> None:
            del prior, requirements
            await docker.probe_python_import(
                "sha256:" + "c" * 64,
                "widget_api",
                checkpoint.identity,
                checkpoint.attempt_id or "initial",
            )
            raise AssertionError("uncertain cleanup must block preparation")

    async def pro_con(
        checkpoint: StageCheckpoint,
        prior: Mapping[SimpleStage, StageCheckpoint],
    ) -> StageResult:
        del checkpoint, prior
        return StageResult(output_refs=())

    initial_stage = InitialVerificationStage(
        _Client(), artifacts, _Environment()  # type: ignore[arg-type]
    )

    async def isolated_initial(
        checkpoint: StageCheckpoint,
        prior: Mapping[SimpleStage, StageCheckpoint],
    ) -> StageResult:
        del prior
        return await initial_stage(checkpoint, {})

    poc_called = False

    async def poc_candidate(
        checkpoint: StageCheckpoint,
        prior: Mapping[SimpleStage, StageCheckpoint],
    ) -> StageResult:
        nonlocal poc_called
        del checkpoint, prior
        poc_called = True
        return StageResult(output_refs=())

    runner = SimpleRuntimeRunner(
        store,
        {
            SimpleStage.PRO_CON_DONE: pro_con,
            SimpleStage.VERIFICATION_INITIAL_DONE: isolated_initial,
            SimpleStage.POC_CANDIDATE_DONE: poc_candidate,
        },
    )
    try:
        outcome = await runner.resume_hypothesis(identity)
    except asyncio.CancelledError:
        outcome = None

    blocked = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
    assert blocked.error_code == "POC_IMPORT_SMOKE_CLEANUP_FAILED"
    assert blocked.retryable is False
    assert not poc_called
    assert outcome is not None
    assert outcome.current_stage is SimpleStage.VERIFICATION_INITIAL_DONE
    assert outcome.status is StageStatus.BLOCKED
    assert outcome.error_code == "POC_IMPORT_SMOKE_CLEANUP_FAILED"
    assert await runner.resume_hypothesis(identity) == outcome
    assert store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE) == blocked
    assert not poc_called
