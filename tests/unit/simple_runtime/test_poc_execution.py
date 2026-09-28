from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sastsimi.sandbox.docker_adapter import DockerCommandOutcome
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.runner import StageBlocked
from sastsimi.simple_runtime.stages import PoCExecutionStage


class _InterpretationClient:
    async def call(self, **_kwargs: Any) -> SimpleLLMCallResult:
        return SimpleLLMCallResult(
            value={
                "outcome": "SUPPORTED",
                "rationale": "The observed exit and marker support the hypothesis.",
                "limitations": [],
            },
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


class _InconclusiveClient(_InterpretationClient):
    async def call(self, **_kwargs: Any) -> SimpleLLMCallResult:
        return SimpleLLMCallResult(
            value={
                "outcome": "INCONCLUSIVE",
                "rationale": "The completed run has insufficient evidence.",
                "limitations": ["No observable exploit effect"],
            },
            prompt_digest="c" * 64,
            output_digest="d" * 64,
        )


class _Docker:
    async def materialize_poc(self, *_args: Any) -> str:
        return "/tmp/sastsimi-poc-candidate"

    async def execute(self, *_args: Any, **_kwargs: Any) -> DockerCommandOutcome:
        return DockerCommandOutcome(
            exit_code=0,
            stdout=b"REPRODUCED\n",
            stderr=b"",
            timed_out=False,
        )


class _Containers:
    def __init__(self) -> None:
        self.released: list[str] = []

    async def acquire(self, _checkpoint: StageCheckpoint) -> str:
        return "a" * 64

    async def release(self, _checkpoint: StageCheckpoint, container_id: str) -> bool:
        self.released.append(container_id)
        return True


@pytest.mark.asyncio
async def test_runtime_pins_interpretation_to_exact_execution_ref(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    content_ref = artifacts.put_bytes(
        b"#!/bin/sh\nset -eu\nprintf REPRODUCED\n",
        "text/x-shellscript",
    )
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "content_ref": content_ref.model_dump(mode="json"),
            "attempt_id": "attempt-1",
        }
    )
    input_refs = (candidate_ref, content_ref)
    candidate = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=input_refs,
        attempt_id="attempt-1",
        image_digest=f"sha256:{'1' * 64}",
    )
    current = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_EXECUTION_DONE,
        status=StageStatus.PENDING,
        input_refs=input_refs,
        input_hash=input_reference_hash(input_refs),
        attempt_id="attempt-1",
    )
    containers = _Containers()
    stage = PoCExecutionStage(
        client=_InterpretationClient(),
        artifacts=artifacts,
        docker=_Docker(),  # type: ignore[arg-type]
        containers=containers,
    )

    result = await stage(
        current,
        {SimpleStage.POC_CANDIDATE_DONE: candidate},
    )

    assert result.validated_poc_ref is not None
    execution_ref, interpretation_ref, _validated_ref, cleanup_ref = result.output_refs
    interpretation = json.loads(artifacts.read(interpretation_ref))
    assert interpretation["execution_ref"] == execution_ref.model_dump(mode="json")
    assert "execution_ref" not in interpretation["result"]
    assert json.loads(artifacts.read(cleanup_ref))["status"] == "REMOVED"
    assert containers.released == ["a" * 64]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("attempt_number", "exit_code", "expected_error"),
    [
        (1, 0, "POC_INCONCLUSIVE"),
        (3, 0, None),
        (3, 1, "POC_EXECUTION_FAILED"),
        (3, -1, "POC_EXECUTION_FAILED"),
    ],
)
async def test_executed_inconclusive_poc_is_terminal_only_at_attempt_limit(
    tmp_path: Path,
    attempt_number: int,
    exit_code: int,
    expected_error: str | None,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-inconclusive",
        workspace_id="workspace-inconclusive",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-inconclusive",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    content_ref = artifacts.put_bytes(
        b"#!/bin/sh\nprintf observed\n", "text/x-shellscript"
    )
    candidate_ref = artifacts.put_json({"kind": "simple_poc_candidate"})
    refs = (candidate_ref, content_ref)
    candidate = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=refs,
        attempt_id="attempt-inconclusive",
        image_digest=f"sha256:{'1' * 64}",
    )
    current = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_EXECUTION_DONE,
        status=StageStatus.PENDING,
        input_refs=refs,
        input_hash=input_reference_hash(refs),
        attempt_id="attempt-inconclusive",
        attempt_number=attempt_number,
    )

    class _ExitDocker(_Docker):
        async def execute(self, *_args: Any, **_kwargs: Any) -> DockerCommandOutcome:
            return DockerCommandOutcome(
                exit_code, b"", b"execution inconclusive", False
            )

    stage = PoCExecutionStage(
        client=_InconclusiveClient(),
        artifacts=artifacts,
        docker=_ExitDocker(),  # type: ignore[arg-type]
        containers=_Containers(),
    )

    if expected_error is not None:
        with pytest.raises(StageBlocked) as blocked:
            await stage(current, {SimpleStage.POC_CANDIDATE_DONE: candidate})
        assert blocked.value.failure.code == expected_error
    else:
        result = await stage(current, {SimpleStage.POC_CANDIDATE_DONE: candidate})
        assert result.verdict == "HOLD"
        assert result.validated_poc_ref is None
        assert len(result.output_refs) >= 2
        interpretation = json.loads(artifacts.read(result.output_refs[1]))
        assert interpretation["result"]["outcome"] == "INCONCLUSIVE"


@pytest.mark.asyncio
async def test_poc_execution_error_is_blocked_and_releases_container(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-error",
        workspace_id="workspace-error",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-error",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    content_ref = artifacts.put_bytes(b"#!/bin/sh\nexit 2\n", "text/x-shellscript")
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "content_ref": content_ref.model_dump(mode="json"),
            "attempt_id": "attempt-error",
        }
    )
    refs = (candidate_ref, content_ref)
    candidate = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=refs,
        attempt_id="attempt-error",
        image_digest=f"sha256:{'1' * 64}",
    )
    current = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_EXECUTION_DONE,
        status=StageStatus.PENDING,
        input_refs=refs,
        input_hash=input_reference_hash(refs),
        attempt_id="attempt-error",
    )

    class _FailingDocker(_Docker):
        async def execute(self, *_args: Any, **_kwargs: Any) -> DockerCommandOutcome:
            return DockerCommandOutcome(2, b"", b"script failed", False)

    containers = _Containers()
    stage = PoCExecutionStage(
        client=_InterpretationClient(),
        artifacts=artifacts,
        docker=_FailingDocker(),  # type: ignore[arg-type]
        containers=containers,
    )

    with pytest.raises(StageBlocked) as blocked:
        await stage(current, {SimpleStage.POC_CANDIDATE_DONE: candidate})

    assert blocked.value.failure.code == "POC_EXECUTION_FAILED"
    assert containers.released == ["a" * 64]
