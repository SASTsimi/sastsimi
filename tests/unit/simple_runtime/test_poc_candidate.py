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
from sastsimi.simple_runtime.poc import PoCCandidateRejected, validate_candidate
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.stages import PoCCandidateStage, StageBlocked


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


def _accepts(script: str) -> None:
    validate_candidate(script.encode("utf-8"), allowed_environment_names=frozenset())


def _rejects(script: str) -> str:
    with pytest.raises(PoCCandidateRejected) as raised:
        _accepts(script)
    return str(raised.value)


def test_a_loopback_url_is_not_a_host_path() -> None:
    # The boundary allows loopback hosts by name, so the host-path rule must not
    # reject the "p://" inside "http://" as a Windows drive letter first.
    for host in ("127.0.0.1:8000", "localhost:8000", "0.0.0.0:8000"):
        _accepts(f"#!/bin/sh\ncurl -s http://{host}/probe\n")


def test_an_external_url_is_still_refused() -> None:
    assert (
        _rejects("#!/bin/sh\ncurl -s http://evil.example.com/x\n")
        == "POC_EXTERNAL_URL_FORBIDDEN"
    )


def test_a_windows_host_path_is_still_refused() -> None:
    assert _rejects("#!/bin/sh\ncat C:\\Users\\me\\f\n") == "POC_HOST_PATH_FORBIDDEN"
    assert _rejects("#!/bin/sh\ncat \\\\srv\\share\\f\n") == "POC_HOST_PATH_FORBIDDEN"
    assert _rejects("#!/bin/sh\ncat /mnt/c/Windows/x\n") == "POC_HOST_PATH_FORBIDDEN"
    assert _rejects("#!/bin/sh\ncat /home/me/f\n") == "POC_HOST_PATH_FORBIDDEN"


def test_a_loop_or_read_target_counts_as_declared() -> None:
    # The shell binds these names exactly like an assignment, so a script that
    # iterates is self-contained even though nothing is written with "=".
    _accepts('#!/bin/sh\nfor p in a b; do echo "$p"; done\n')
    _accepts('#!/bin/sh\nprintf a | while read -r line; do echo "$line"; done\n')


def test_an_undeclared_variable_is_still_refused() -> None:
    assert _rejects('#!/bin/sh\necho "$SECRET_TOKEN"\n') == "POC_UNDECLARED_INPUT"
