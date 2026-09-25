"""The verdict rules the design writes down must reach the agent that decides.

A run judged TRUE and wrote a report for a flow whose only source was an
environment variable the operator sets.  The agent had itself recorded, as an
unresolved condition, that it did not know whether anyone but the operator
could set it - which the design calls a HOLD.  Nothing in the prompt said so.
"""

from __future__ import annotations

from typing import Any, cast

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.stages import (
    FinalVerificationStage,
    InitialVerificationStage,
)


def _prompts(tmp_path: Any) -> list[str]:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    stages = [
        InitialVerificationStage(cast(Any, object()), artifacts, cast(Any, object())),
        FinalVerificationStage(cast(Any, object()), artifacts),
    ]
    found: list[str] = []
    for stage in stages:
        for attribute in vars(stage).values():
            instructions = getattr(attribute, "_instructions", None)
            if isinstance(instructions, str) and "Verification Agent" in instructions:
                # Wrapped prose: compare on words, not on where the lines break.
                found.append(" ".join(instructions.split()))
    return found


def test_both_verification_prompts_name_what_crosses_the_trust_boundary(
    tmp_path: Any,
) -> None:
    prompts = _prompts(tmp_path)

    assert len(prompts) == 2
    for prompt in prompts:
        assert "cookie" in prompt
        assert "uploaded file" in prompt
        # The case that produced the report: operator configuration.
        assert "environment variable" in prompt
        assert "HOLD" in prompt


def test_the_final_prompt_refuses_a_true_that_assumes_attacker_control(
    tmp_path: Any,
) -> None:
    final = [p for p in _prompts(tmp_path) if "Decide TRUE" in p]

    assert len(final) == 1
    assert "established, not" in final[0]
    assert "it is a HOLD" in final[0]
