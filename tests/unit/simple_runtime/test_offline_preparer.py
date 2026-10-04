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
from pydantic import JsonValue

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
    DirectEnvironmentPreparer,
    DockerBuildAttemptsError,
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
