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
    async def acquire(self, _checkpoint: StageCheckpoint) -> str:
        return "a" * 64


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
    stage = PoCExecutionStage(
        client=_InterpretationClient(),
        artifacts=artifacts,
        docker=_Docker(),  # type: ignore[arg-type]
        containers=_Containers(),
    )

    result = await stage(
        current,
        {SimpleStage.POC_CANDIDATE_DONE: candidate},
    )

    assert result.validated_poc_ref is not None
    execution_ref, interpretation_ref, _validated_ref = result.output_refs
    interpretation = json.loads(artifacts.read(interpretation_ref))
    assert interpretation["execution_ref"] == execution_ref.model_dump(mode="json")
    assert "execution_ref" not in interpretation["result"]
