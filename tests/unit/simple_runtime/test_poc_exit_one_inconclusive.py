"""A PoC's disproof claim is not the interpretation Agent's counterevidence."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

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
from sastsimi.simple_runtime.poc_observation import (
    exit_one_claim_interpreted_inconclusive,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.runner import StageBlocked
from sastsimi.simple_runtime.stages import PoCExecutionStage

MARKED_STDOUT = (
    b"pinned_source=verified\n"
    b"project_settings_source=verified\n"
    b"project_urlconf_source=verified\n"
    b"project_routes=190\n"
    b"reversible_superuser_routes=2\n"
    b"normal_login=succeeded\n"
    b"active_route_http=200\n"
    b"inactive_request_authenticated=False\n"
    b"inactive_route_http=302\n"
    b"SASTSIMI_POC_DISPROVED: normal session rejects inactive account\n"
)


@pytest.mark.parametrize(
    ("stdout", "stderr", "expected"),
    [
        (MARKED_STDOUT, b"", True),
        (b"SASTSIMI_POC_DISPROVED: condition failed\n", b"", True),
        (b"SASTSIMI_POC_DISPROVED: condition failed\nother output\n", b"", False),
        (b"prefix SASTSIMI_POC_DISPROVED: condition failed\n", b"", False),
        (b"SASTSIMI_POC_DISPROVED: condition failed\n", b"warning", False),
        (b"SASTSIMI_POC_DISPROVED: \n", b"", False),
        (b"x" * 4096 + b"\nSASTSIMI_POC_DISPROVED: failed\n", b"", False),
        (b"\x1b[31merror\nSASTSIMI_POC_DISPROVED: failed\n", b"", False),
        (b"ordinary output\n", b"", False),
    ],
)
def test_exit_one_claim_requires_bounded_clean_terminal_marker(
    stdout: bytes, stderr: bytes, expected: bool
) -> None:
    assert exit_one_claim_interpreted_inconclusive(stdout, stderr) is expected


class _InconclusiveInterpretation:
    async def call(self, **_kwargs: Any) -> SimpleLLMCallResult:
        return SimpleLLMCallResult(
            value={
                "outcome": "INCONCLUSIVE",
                "rationale": "The inactive-authentication precondition was not met.",
                "limitations": ["An inactive authenticated session was not observed."],
            },
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


class _ExitOneDocker:
    def __init__(self, stdout: bytes, stderr: bytes) -> None:
        self.stdout = stdout
        self.stderr = stderr

    async def materialize_poc(self, *_args: Any) -> str:
        return "/tmp/sastsimi-poc-candidate"

    async def execute(self, *_args: Any, **_kwargs: Any) -> DockerCommandOutcome:
        return DockerCommandOutcome(1, self.stdout, self.stderr, False)


class _Containers:
    async def acquire(self, _checkpoint: StageCheckpoint) -> str:
        return "a" * 64

    async def release(self, _checkpoint: StageCheckpoint, _container_id: str) -> bool:
        return True


def _case(
    tmp_path: Path,
    *,
    stdout: bytes = MARKED_STDOUT,
    stderr: bytes = b"",
    attempt_number: int = 3,
) -> tuple[
    SimpleArtifactRepository,
    StageCheckpoint,
    StageCheckpoint,
    PoCExecutionStage,
]:
    identity = CheckpointIdentity(
        analysis_id="analysis-exit-one",
        workspace_id="workspace-exit-one",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-exit-one",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    content_ref = artifacts.put_bytes(
        b"#!/bin/sh\nprintf 'probe\n'\n", "text/x-shellscript"
    )
    candidate_ref = artifacts.put_json({"kind": "simple_poc_candidate"})
    refs = (candidate_ref, content_ref)
    recipe_ref = artifacts.put_json(
        {
            "kind": "simple_environment_recipe",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "hypothesis_id": identity.hypothesis_id,
            "attempt_id": "attempt-exit-one",
            "dockerfile_source": "GENERATED",
            "degraded": False,
            "status": "BUILT",
            "image_digest": f"sha256:{'1' * 64}",
        }
    )
    candidate = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=refs,
        attempt_id="attempt-exit-one",
        recipe_ref=recipe_ref,
        image_digest=f"sha256:{'1' * 64}",
    )
    current = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_EXECUTION_DONE,
        status=StageStatus.PENDING,
        input_refs=refs,
        input_hash=input_reference_hash(refs),
        attempt_id="attempt-exit-one",
        attempt_number=attempt_number,
    )
    stage = PoCExecutionStage(
        client=_InconclusiveInterpretation(),
        artifacts=artifacts,
        docker=_ExitOneDocker(stdout, stderr),  # type: ignore[arg-type]
        containers=_Containers(),
    )
    return artifacts, candidate, current, stage


@pytest.mark.asyncio
async def test_exit_one_disproof_claim_and_inconclusive_interpretation_end_in_hold(
    tmp_path: Path,
) -> None:
    artifacts, candidate, current, stage = _case(tmp_path)

    result = await stage(current, {SimpleStage.POC_CANDIDATE_DONE: candidate})

    assert result.verdict == "HOLD"
    assert result.validated_poc_ref is None
    assert len(result.output_refs) == 3
    assert json.loads(artifacts.read(result.output_refs[1]))["result"]["outcome"] == (
        "INCONCLUSIVE"
    )
    saved = current.model_copy(
        update={
            "stage_version": STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE],
            "status": StageStatus.SUCCEEDED,
            "output_refs": result.output_refs,
            "verdict": result.verdict,
            "container_id": result.container_id,
        }
    )
    assert artifacts.verified_terminal_poc_outcome(saved) == "INCONCLUSIVE"


@pytest.mark.asyncio
async def test_exit_one_disproof_claim_still_retries_below_ceiling(
    tmp_path: Path,
) -> None:
    _artifacts, candidate, current, stage = _case(tmp_path, attempt_number=1)

    with pytest.raises(StageBlocked) as blocked:
        await stage(current, {SimpleStage.POC_CANDIDATE_DONE: candidate})

    assert blocked.value.failure.code == "POC_INCONCLUSIVE"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "corruption",
    [
        "missing_stdout_ref",
        "changed_stdout",
        "changed_stderr",
        "tampered_stdout_digest",
        "wrong_cleanup",
    ],
)
async def test_terminal_exit_one_hold_rejects_unbound_observation(
    tmp_path: Path, corruption: str
) -> None:
    artifacts, candidate, current, stage = _case(tmp_path)
    result = await stage(current, {SimpleStage.POC_CANDIDATE_DONE: candidate})
    execution_ref, interpretation_ref, cleanup_ref = result.output_refs
    execution = json.loads(artifacts.read(execution_ref))
    interpretation = json.loads(artifacts.read(interpretation_ref))
    if corruption == "missing_stdout_ref":
        del execution["stdout_ref"]
    elif corruption == "changed_stdout":
        execution["stdout_ref"] = artifacts.put_bytes(
            b"ordinary output\n", "text/plain"
        ).model_dump(mode="json")
    elif corruption == "changed_stderr":
        execution["stderr_ref"] = artifacts.put_bytes(
            b"warning", "text/plain"
        ).model_dump(mode="json")
    elif corruption == "tampered_stdout_digest":
        execution["stdout_ref"]["content_hash"] = "0" * 64
    else:
        cleanup = json.loads(artifacts.read(cleanup_ref))
        cleanup["container_id"] = "b" * 64
        cleanup_ref = artifacts.put_json(cleanup)
    execution_ref = artifacts.put_json(execution)
    interpretation["execution_ref"] = execution_ref.model_dump(mode="json")
    interpretation_ref = artifacts.put_json(interpretation)
    saved = current.model_copy(
        update={
            "stage_version": STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE],
            "status": StageStatus.SUCCEEDED,
            "output_refs": (execution_ref, interpretation_ref, cleanup_ref),
            "verdict": "HOLD",
            "container_id": result.container_id,
        }
    )

    with pytest.raises(ValueError, match="POC_TERMINAL_EVIDENCE_INVALID"):
        artifacts.verified_terminal_poc_outcome(saved)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("stdout", "stderr"),
    [
        (b"SASTSIMI_POC_DISPROVED: condition failed\nother output\n", b""),
        (b"prefix SASTSIMI_POC_DISPROVED: condition failed\n", b""),
        (b"SASTSIMI_POC_DISPROVED: condition failed\n", b"warning"),
        (b"SASTSIMI_POC_DISPROVED: \n", b""),
        (b"ordinary output\n", b""),
    ],
)
async def test_exit_one_without_clean_terminal_marker_is_not_terminal_hold(
    tmp_path: Path, stdout: bytes, stderr: bytes
) -> None:
    _artifacts, candidate, current, stage = _case(
        tmp_path, stdout=stdout, stderr=stderr
    )

    with pytest.raises(StageBlocked) as blocked:
        await stage(current, {SimpleStage.POC_CANDIDATE_DONE: candidate})

    assert blocked.value.failure.code == "POC_EXECUTION_FAILED"
