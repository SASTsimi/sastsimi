from __future__ import annotations

from pathlib import Path
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


class _HostPathRepairClient(_RepairClient):
    async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
        self.prompts.append(kwargs["prompt"])
        content = (
            "#!/bin/sh\nprintf '%s\\n' '\\\\attacker.example'\n"
            if len(self.prompts) == 1
            else "#!/bin/sh\npython - <<'PY'\nprint(chr(92) * 2 + 'attacker.example')\nPY\n"
        )
        return SimpleLLMCallResult(
            value={"content": content},
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


class _ExternalUrlRepairClient(_RepairClient):
    async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
        self.prompts.append(kwargs["prompt"])
        content = (
            "#!/bin/sh\nprintf '%s\\n' 'https://attacker.example/path'\n"
            if len(self.prompts) == 1
            else (
                "#!/bin/sh\npython - <<'PY'\n"
                "print('https:' + chr(47) * 2 + 'attacker.example/path')\nPY\n"
            )
        )
        return SimpleLLMCallResult(
            value={"content": content},
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


@pytest.mark.asyncio
async def test_sensitive_candidate_repair_explains_secret_shaped_names(
    tmp_path: Path,
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
        client=client,
        artifacts=SimpleArtifactRepository(tmp_path, identity),
    )

    result = await stage(checkpoint, {})

    assert result.output_refs
    assert len(client.prompts) == 2
    assert b"concise error type and traceback to stderr" in client.prompts[0]
    assert b"secret-shaped identifiers" in client.prompts[1]
    assert b"cookie, session, token" in client.prompts[1]


@pytest.mark.asyncio
async def test_host_path_repair_explains_how_to_build_backslash_url_fixtures(
    tmp_path: Path,
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
    client = _HostPathRepairClient()
    stage = PoCCandidateStage(
        client=client,
        artifacts=SimpleArtifactRepository(tmp_path, identity),
    )

    result = await stage(checkpoint, {})

    assert result.output_refs
    assert len(client.prompts) == 2
    assert b"external-looking and backslash-confused URL fixtures" in client.prompts[0]
    assert b"construct them at runtime" in client.prompts[0]
    assert b"construct backslash-confused URL fixtures at runtime" in client.prompts[1]
    assert b"chr(92)" in client.prompts[1]


@pytest.mark.asyncio
async def test_external_url_repair_keeps_network_off_and_builds_fixture_at_runtime(
    tmp_path: Path,
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
    client = _ExternalUrlRepairClient()
    stage = PoCCandidateStage(
        client=client,
        artifacts=SimpleArtifactRepository(tmp_path, identity),
    )

    result = await stage(checkpoint, {})

    assert result.output_refs
    assert len(client.prompts) == 2
    assert b"external-looking and backslash-confused URL fixtures" in client.prompts[0]
    assert b"construct them at runtime" in client.prompts[0]
    assert b"must not make an external network request" in client.prompts[1]
    assert b"construct the URL fixture at runtime" in client.prompts[1]
