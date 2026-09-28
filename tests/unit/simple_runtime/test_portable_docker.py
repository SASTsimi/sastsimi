import hashlib
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from sastsimi.sandbox.docker_adapter import DockerCommandOutcome, DockerOperationError
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


@pytest.mark.parametrize(
    "patch",
    [
        "RUN python -m pip install -e '.[test]'",
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
        patch="RUN python -m pip install -e '.[test]'",
    )
    retry = _environment_checkpoint(
        artifacts,
        action="RETRY_STAGE",
        patch="",
    )
    inputs = rebuild.input_refs + retry.input_refs
    checkpoint = retry.model_copy(
        update={"input_refs": inputs, "input_hash": input_reference_hash(inputs)}
    )
    docker = _BuildDocker()

    await DirectEnvironmentPreparer(
        docker=docker,  # type: ignore[arg-type]
        artifacts=artifacts,
        workspace=workspace,
    ).prepare(checkpoint, {}, ())

    assert b"RUN python -m pip install -e '.[test]'" in docker.dockerfiles[0]


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
