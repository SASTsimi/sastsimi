from __future__ import annotations

from typing import Any

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.stages import PoCCandidateStage


class _RepairClient:
    def __init__(self) -> None:
        self.prompts: list[bytes] = []

    async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
        self.prompts.append(kwargs["prompt"])
        content = (
            "#!/bin/sh\ncookie=fixture_value\nprintf x\n"
            if len(self.prompts) == 1
            else "#!/bin/sh\nfixture_value=x\nprintf '%s' \"$fixture_value\"\n"
        )
        return SimpleLLMCallResult(
            value={"content": content},
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


@pytest.mark.asyncio
async def test_sensitive_candidate_repair_explains_secret_shaped_names(
    tmp_path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-1",
    )
    client = _RepairClient()
    stage = PoCCandidateStage(
        client=client,  # type: ignore[arg-type]
        artifacts=SimpleArtifactRepository(tmp_path, identity),
    )

    result = await stage(checkpoint, {})

    assert result.output_refs
    assert len(client.prompts) == 2
    assert b"concise error type and traceback to stderr" in client.prompts[0]
    assert b"secret-shaped identifiers" in client.prompts[1]
    assert b"cookie, session, token" in client.prompts[1]
