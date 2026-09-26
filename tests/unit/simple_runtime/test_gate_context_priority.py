"""Revised PoC feedback and requested source stay visible through Gate review."""

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
from sastsimi.simple_runtime.stages import FinalVerificationStage, TechnicalGateStage


class _ContextClient:
    def __init__(self) -> None:
        self.prompts: list[bytes] = []

    async def call(self, **kwargs: Any) -> SimpleLLMCallResult:
        self.prompts.append(kwargs["prompt"])
        if kwargs["agent_name"] == "verification_result":
            value = {
                "verdict": "HOLD",
                "rationale": "More evidence needed",
                "supporting_refs": [],
                "limitations": [],
                "unresolved_conditions": [],
                "required_capabilities": [],
                "provided_capabilities": [],
                "entities": [],
            }
        else:
            value = {
                "status": "ACCEPT",
                "rationale": "Sufficient evidence",
                "checks": [],
                "revision_requests": [],
            }
        return SimpleLLMCallResult(
            value=value,
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


@pytest.mark.asyncio
async def test_source_and_gate_feedback_precede_bulk_in_final_and_gate_prompts(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    bulk_ref = artifacts.put_json({"kind": "bulk", "content": "x" * 300_000})
    source_ref = artifacts.put_json(
        {"kind": "simple_requested_sources", "served": [{"content": "source-marker"}]}
    )
    feedback_ref = artifacts.put_json(
        {
            "kind": "simple_technical_gate",
            "result": {"status": "REVISE", "revision_requests": ["feedback-marker"]},
        }
    )
    candidate_ref = artifacts.put_json({"kind": "simple_poc_candidate"})
    script_ref = artifacts.put_bytes(b"#!/bin/sh\nexit 0\n", "text/x-shellscript")

    def checkpoint(stage: SimpleStage, outputs: tuple = ()) -> StageCheckpoint:
        return StageCheckpoint(
            identity=identity,
            stage=stage,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=outputs,
        )

    prior = {
        SimpleStage.HYPOTHESIS_DONE: checkpoint(
            SimpleStage.HYPOTHESIS_DONE, (bulk_ref,)
        ),
        SimpleStage.POC_CANDIDATE_DONE: checkpoint(
            SimpleStage.POC_CANDIDATE_DONE,
            (candidate_ref, script_ref, source_ref, feedback_ref),
        ),
    }
    client = _ContextClient()
    final = await FinalVerificationStage(client, artifacts)(
        checkpoint(SimpleStage.VERIFICATION_FINAL_DONE), prior
    )  # type: ignore[arg-type]
    prior[SimpleStage.VERIFICATION_FINAL_DONE] = checkpoint(
        SimpleStage.VERIFICATION_FINAL_DONE, final.output_refs
    )
    await TechnicalGateStage(client, artifacts)(
        checkpoint(SimpleStage.TECH_GATE_DONE), prior
    )  # type: ignore[arg-type]

    assert len(client.prompts) == 2
    for prompt in client.prompts:
        assert b"source-marker" in prompt
        assert b"feedback-marker" in prompt
