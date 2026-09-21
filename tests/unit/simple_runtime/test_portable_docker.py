from collections.abc import Sequence
from pathlib import Path

import pytest

from sastsimi.sandbox.docker_adapter import DockerCommandOutcome
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
