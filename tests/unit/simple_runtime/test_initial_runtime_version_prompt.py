"""Guidance for explicit Python runtimes in offline initial verification."""

from __future__ import annotations

from pathlib import Path

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
from sastsimi.simple_runtime.runner import StageBlocked
from sastsimi.simple_runtime.stages import InitialVerificationStage


@pytest.mark.asyncio
@pytest.mark.parametrize("attempt_number", [1, 2])
async def test_initial_prompt_bounds_explicit_python_runtime_to_local_digest(
    tmp_path: Path, attempt_number: int
) -> None:
    identity = CheckpointIdentity(
        analysis_id="runtime-prompt",
        workspace_id="runtime-prompt-workspace",
        commit_id="a" * 40,
        hypothesis_id="runtime-prompt-hypothesis",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="runtime-prompt-attempt",
        attempt_number=attempt_number,
    )
    prompts: list[bytes] = []

    class _Client:
        async def call(self, **kwargs: object) -> SimpleLLMCallResult:
            prompt = kwargs["prompt"]
            assert isinstance(prompt, bytes)
            prompts.append(prompt)
            return SimpleLLMCallResult(
                value={
                    "initial_assessment": "HOLD",
                    "rationale": "An external prerequisite is unavailable.",
                    "reproduction_goal": "Check the pinned route.",
                    "environment_requirements": [],
                    "unmet_external_prerequisites": ["unavailable service"],
                    "supporting_refs": [],
                    "limitations": [],
                },
                prompt_digest="a" * 64,
                output_digest="b" * 64,
            )

    class _OfflineEnvironment:
        offline_mode = True

        def validate_requirements(
            self, requirements: tuple[str, ...], *, commit_id: str
        ) -> None:
            raise AssertionError("external prerequisites must stop before validation")

        async def prepare(self, *_args: object) -> None:
            raise AssertionError("external prerequisites must stop before preparation")

    result = await InitialVerificationStage(
        _Client(),
        artifacts,
        _OfflineEnvironment(),  # type: ignore[arg-type]
    )(checkpoint, {})

    assert result.verdict == "HOLD"
    assert len(prompts) == 1
    prompt = prompts[0]
    assert b"python:X.Y[.Z]" in prompt
    assert b"already-local" in prompt
    assert b"digest" in prompt
    assert b"Alpine" in prompt
    if attempt_number == 2:
        assert b"On this retry" in prompt
        assert b"python:X.Y[.Z]" in prompt.split(b"On this retry", 1)[1]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure_code",
    [
        "POC_OFFLINE_PYTHON_RUNTIME_CONFLICT",
        "POC_OFFLINE_PYTHON_RUNTIME_MISMATCH",
    ],
)
async def test_initial_verification_runtime_conflict_or_mismatch_is_blocked(
    tmp_path: Path, failure_code: str
) -> None:
    identity = CheckpointIdentity(
        analysis_id="runtime-block",
        workspace_id="runtime-block-workspace",
        commit_id="a" * 40,
        hypothesis_id="runtime-block-hypothesis",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="runtime-block-attempt",
        attempt_number=1,
    )

    class _Client:
        async def call(self, **_kwargs: object) -> SimpleLLMCallResult:
            return SimpleLLMCallResult(
                value={
                    "initial_assessment": "TRUE",
                    "rationale": "A runtime reproduction is needed.",
                    "reproduction_goal": "Exercise the pinned route.",
                    "environment_requirements": ["python:3.6.2"],
                    "unmet_external_prerequisites": [],
                    "supporting_refs": [],
                    "limitations": [],
                },
                prompt_digest="a" * 64,
                output_digest="b" * 64,
            )

    class _OfflineEnvironment:
        offline_mode = True

        def validate_requirements(
            self, requirements: tuple[str, ...], *, commit_id: str
        ) -> None:
            assert requirements == ("python:3.6.2",)
            assert commit_id == identity.commit_id

        async def prepare(self, *_args: object) -> None:
            raise ValueError(failure_code)

    with pytest.raises(StageBlocked) as blocked:
        await InitialVerificationStage(
            _Client(),
            artifacts,
            _OfflineEnvironment(),  # type: ignore[arg-type]
        )(checkpoint, {})

    assert blocked.value.failure.code == failure_code
    assert blocked.value.failure.retryable is False
