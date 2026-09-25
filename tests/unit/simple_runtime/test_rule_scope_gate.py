"""The rule scope gate must see a policy the checkout states on its own.

The static stage records a repository's SECURITY.md as its own artifact;
without a way to reach that ref, every hypothesis's scope gate call ended
"official policy missing" even when the checkout stated one plainly.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

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
from sastsimi.simple_runtime.stages import RuleScopeGateStage
from sastsimi.simple_runtime.store import SimpleCheckpointStore


class _Client:
    def __init__(self) -> None:
        self.seen_refs: tuple[Any, ...] = ()

    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
    ) -> SimpleLLMCallResult:
        del output_schema, timeout_ms
        self.prompt = prompt
        return SimpleLLMCallResult(
            value={
                "status": "ALLOW",
                "rationale": "meets every axis",
                "checks": ["Rule 1"],
                "restrictions": [],
                "testing_restriction_compliance": "PASS",
            },
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


def _identity() -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )


def _checkpoint(identity: CheckpointIdentity) -> StageCheckpoint:
    return StageCheckpoint(
        identity=identity,
        stage=SimpleStage.SCOPE_GATE_DONE,
        status=StageStatus.PENDING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="attempt-1",
    )


@pytest.mark.asyncio
async def test_a_policy_ref_handed_at_construction_reaches_the_evaluation(
    tmp_path: Path,
) -> None:
    """The ref bypasses the empty ``prior`` a hypothesis stage actually gets."""

    identity = _identity()
    SimpleCheckpointStore(tmp_path / "data" / "db" / "sastsimi.sqlite3")
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    policy_ref = artifacts.put_json(
        {
            "kind": "simple_repository_security_policy",
            "path": "SECURITY.md",
            "content": "Configuration options are not vulnerabilities.",
        }
    )
    client = _Client()
    stage = RuleScopeGateStage(
        cast(Any, client), artifacts, security_policy_ref=policy_ref
    )

    result = await stage(_checkpoint(identity), {})

    output = artifacts.read(result.output_refs[0])
    assert b'"OFFICIAL_POLICY_MISSING"' not in output
    assert b'"status":"ALLOW"' in output


@pytest.mark.asyncio
async def test_without_a_policy_ref_the_gate_still_falls_back_to_uncertain(
    tmp_path: Path,
) -> None:
    """The prior safe default is unchanged when nothing supplies a policy."""

    identity = _identity()
    SimpleCheckpointStore(tmp_path / "data" / "db" / "sastsimi.sqlite3")
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    stage = RuleScopeGateStage(cast(Any, _Client()), artifacts)

    result = await stage(_checkpoint(identity), {})

    output = artifacts.read(result.output_refs[0])
    assert b'"OFFICIAL_POLICY_MISSING"' in output
    assert b'"status":"UNCERTAIN"' in output
