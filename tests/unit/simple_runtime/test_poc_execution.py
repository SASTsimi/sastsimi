from __future__ import annotations

import hashlib
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
    StageFailure,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.runner import StageBlocked, StageFailed
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


class _DisprovingClient(_InterpretationClient):
    def __init__(self) -> None:
        self.calls = 0

    async def call(self, **_kwargs: Any) -> SimpleLLMCallResult:
        self.calls += 1
        return SimpleLLMCallResult(
            value={
                "outcome": "DISPROVED",
                "rationale": "The observation contradicts the hypothesis.",
                "limitations": [],
            },
            prompt_digest="e" * 64,
            output_digest="f" * 64,
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
        self.acquired = 0
        self.released: list[str] = []

    async def acquire(self, _checkpoint: StageCheckpoint) -> str:
        self.acquired += 1
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
    recipe_ref = artifacts.put_json(
        {
            "kind": "simple_environment_recipe",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "hypothesis_id": identity.hypothesis_id,
            "attempt_id": "attempt-1",
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
        output_refs=input_refs,
        attempt_id="attempt-1",
        recipe_ref=recipe_ref,
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


def _poc_with_recipe(
    tmp_path: Path,
    *,
    recipe_source: str | None,
    degraded: bool,
    corrupt_recipe: bool = False,
    recipe_attempt_id: str = "attempt-environment-gate",
    recipe_image_digest: str | None = f"sha256:{'2' * 64}",
    client: _InterpretationClient | None = None,
    docker: _Docker | None = None,
    offline_metadata: bool = True,
) -> tuple[
    PoCExecutionStage,
    StageCheckpoint,
    dict[SimpleStage, StageCheckpoint],
    SimpleArtifactRepository,
    _Containers,
]:
    identity = CheckpointIdentity(
        analysis_id="analysis-environment-gate",
        workspace_id="workspace-environment-gate",
        commit_id="b" * 40,
        hypothesis_id="hypothesis-environment-gate",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    content_ref = artifacts.put_bytes(
        b"#!/bin/sh\nset -eu\nprintf REPRODUCED\n", "text/x-shellscript"
    )
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "content_ref": content_ref.model_dump(mode="json"),
            "attempt_id": "attempt-environment-gate",
        }
    )
    recipe_ref = None
    if recipe_source is not None:
        offline_fields: dict[str, object] = {}
        if recipe_source == "GENERATED_OFFLINE_WHEELS" and offline_metadata:
            wheel_bytes = b"validated test wheel bundle"
            wheel_ref = artifacts.put_bytes(wheel_bytes, "application/x-tar")
            dockerfile_ref = artifacts.put_bytes(
                b"FROM sastsimi-offline-base:verified\n", "text/x-dockerfile"
            )
            offline_fields = {
                "wheel_archive_ref": wheel_ref.model_dump(mode="json"),
                "wheel_archive_sha256": hashlib.sha256(wheel_bytes).hexdigest(),
                "manifest_sha256": "a" * 64,
                "context_sha256": "b" * 64,
                "base_image_digest": "sha256:" + "c" * 64,
                "build_network": "none",
                "dockerfile_ref": dockerfile_ref.model_dump(mode="json"),
            }
        recipe_ref = (
            artifacts.put_bytes(b"{", "application/json")
            if corrupt_recipe
            else artifacts.put_json(
                {
                    "kind": "simple_environment_recipe",
                    "analysis_id": identity.analysis_id,
                    "workspace_id": identity.workspace_id,
                    "commit_id": identity.commit_id,
                    "hypothesis_id": identity.hypothesis_id,
                    "attempt_id": recipe_attempt_id,
                    "dockerfile_source": recipe_source,
                    "degraded": degraded,
                    "status": "BUILT",
                    **offline_fields,
                    **(
                        {"image_digest": recipe_image_digest}
                        if recipe_image_digest is not None
                        else {}
                    ),
                }
            )
        )
    refs = (candidate_ref, content_ref)
    candidate = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=refs,
        attempt_id="attempt-environment-gate",
        recipe_ref=recipe_ref,
        image_digest=f"sha256:{'2' * 64}",
    )
    current = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_EXECUTION_DONE,
        status=StageStatus.PENDING,
        input_refs=refs,
        input_hash=input_reference_hash(refs),
        attempt_id="attempt-environment-gate",
    )
    containers = _Containers()
    stage = PoCExecutionStage(
        client=client or _InterpretationClient(),
        artifacts=artifacts,
        docker=docker or _Docker(),  # type: ignore[arg-type]
        containers=containers,
    )
    return (
        stage,
        current,
        {SimpleStage.POC_CANDIDATE_DONE: candidate},
        artifacts,
        containers,
    )


@pytest.mark.asyncio
async def test_verified_offline_recipe_may_reach_poc_validation(tmp_path: Path) -> None:
    stage, current, prior, artifacts, containers = _poc_with_recipe(
        tmp_path, recipe_source="GENERATED_OFFLINE_WHEELS", degraded=False
    )

    result = await stage(current, prior)

    assert result.validated_poc_ref is not None
    assert json.loads(artifacts.read(result.validated_poc_ref))["kind"] == (
        "simple_validated_poc"
    )
    assert containers.acquired == 1


@pytest.mark.asyncio
async def test_offline_recipe_without_provenance_cannot_validate_poc(
    tmp_path: Path,
) -> None:
    stage, current, prior, _artifacts, containers = _poc_with_recipe(
        tmp_path,
        recipe_source="GENERATED_OFFLINE_WHEELS",
        degraded=False,
        offline_metadata=False,
    )
    with pytest.raises(StageFailed) as failed:
        await stage(current, prior)
    assert failed.value.failure.code == "POC_ENVIRONMENT_RECIPE_INVALID"
    assert containers.acquired == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("recipe_source", "degraded"),
    [
        ("GENERATED_NO_INSTALL", True),
        ("GENERATED_NO_INSTALL", False),
        ("GENERATED", True),
    ],
)
async def test_supported_poc_in_degraded_image_is_not_validated(
    tmp_path: Path, recipe_source: str, degraded: bool
) -> None:
    stage, current, prior, artifacts, containers = _poc_with_recipe(
        tmp_path, recipe_source=recipe_source, degraded=degraded
    )

    with pytest.raises(StageBlocked) as blocked:
        await stage(current, prior)

    assert blocked.value.failure.code == "POC_ENVIRONMENT_UNVERIFIED"
    assert blocked.value.failure.retryable is False
    evidence = blocked.value.failure.evidence_refs
    assert prior[SimpleStage.POC_CANDIDATE_DONE].recipe_ref in evidence
    assert any(
        json.loads(artifacts.read(ref)).get("kind") == "simple_poc_environment_check"
        for ref in evidence
        if artifacts.read(ref).startswith(b"{")
    )
    assert containers.acquired == 0
    assert containers.released == []


@pytest.mark.asyncio
async def test_source_only_import_failure_is_classified_before_running_poc(
    tmp_path: Path,
) -> None:
    class _ImportFailureDocker(_Docker):
        def __init__(self) -> None:
            self.calls = 0

        async def execute(self, *_args: Any, **_kwargs: Any) -> DockerCommandOutcome:
            self.calls += 1
            return DockerCommandOutcome(
                2,
                b"",
                b"ModuleNotFoundError: No module named 'werkzeug'\n",
                False,
            )

    docker = _ImportFailureDocker()
    client = _DisprovingClient()
    stage, current, prior, artifacts, containers = _poc_with_recipe(
        tmp_path,
        recipe_source="GENERATED_NO_INSTALL",
        degraded=True,
        client=client,
        docker=docker,
    )

    with pytest.raises(StageBlocked) as blocked:
        await stage(current, prior)

    assert blocked.value.failure.code == "POC_ENVIRONMENT_UNVERIFIED"
    assert blocked.value.failure.retryable is False
    assert docker.calls == 0
    assert client.calls == 0
    assert containers.acquired == 0
    assert containers.released == []
    checks = [
        json.loads(artifacts.read(ref))
        for ref in blocked.value.failure.evidence_refs
        if artifacts.read(ref).startswith(b"{")
    ]
    assert any(item.get("decision") == "UNVERIFIED_DEPENDENCIES" for item in checks)


@pytest.mark.asyncio
async def test_degraded_image_with_wrong_recipe_digest_fails_integrity(
    tmp_path: Path,
) -> None:
    stage, current, prior, _artifacts, containers = _poc_with_recipe(
        tmp_path,
        recipe_source="GENERATED_NO_INSTALL",
        degraded=True,
        recipe_image_digest=f"sha256:{'3' * 64}",
    )

    with pytest.raises(StageFailed) as failed:
        await stage(current, prior)

    assert failed.value.failure.code == "POC_ENVIRONMENT_RECIPE_INVALID"
    assert containers.acquired == 0
    assert containers.released == []


@pytest.mark.asyncio
@pytest.mark.parametrize("corrupt_recipe", [False, True])
async def test_supported_poc_without_valid_recipe_fails_integrity(
    tmp_path: Path, corrupt_recipe: bool
) -> None:
    stage, current, prior, _artifacts, containers = _poc_with_recipe(
        tmp_path,
        recipe_source="GENERATED" if corrupt_recipe else None,
        degraded=False,
        corrupt_recipe=corrupt_recipe,
    )

    with pytest.raises(StageFailed) as failed:
        await stage(current, prior)

    assert failed.value.failure.code == "POC_ENVIRONMENT_RECIPE_INVALID"
    assert failed.value.failure.retryable is False
    assert containers.acquired == 0
    assert containers.released == []


@pytest.mark.asyncio
async def test_supported_poc_can_reuse_normal_recipe_from_prior_attempt(
    tmp_path: Path,
) -> None:
    stage, current, prior, _artifacts, containers = _poc_with_recipe(
        tmp_path,
        recipe_source="GENERATED",
        degraded=False,
        recipe_attempt_id="attempt-before-poc-retry",
    )

    result = await stage(current, prior)

    assert result.validated_poc_ref is not None
    assert containers.released == ["a" * 64]


@pytest.mark.asyncio
@pytest.mark.parametrize("recipe_image_digest", [None, f"sha256:{'3' * 64}"])
async def test_poc_recipe_must_bind_the_executed_image(
    tmp_path: Path, recipe_image_digest: str | None
) -> None:
    stage, current, prior, _artifacts, containers = _poc_with_recipe(
        tmp_path,
        recipe_source="GENERATED",
        degraded=False,
        recipe_image_digest=recipe_image_digest,
    )

    with pytest.raises(StageFailed) as failed:
        await stage(current, prior)

    assert failed.value.failure.code == "POC_ENVIRONMENT_RECIPE_INVALID"
    assert failed.value.failure.retryable is False
    assert containers.acquired == 0
    assert containers.released == []


@pytest.mark.asyncio
@pytest.mark.parametrize("matching_lineage", [True, False])
async def test_legacy_recipe_without_digest_requires_original_initial_checkpoint(
    tmp_path: Path, matching_lineage: bool
) -> None:
    stage, current, prior, _artifacts, containers = _poc_with_recipe(
        tmp_path,
        recipe_source="GENERATED",
        degraded=False,
        recipe_image_digest=None,
    )
    candidate = prior[SimpleStage.POC_CANDIDATE_DONE]
    prior[SimpleStage.VERIFICATION_INITIAL_DONE] = StageCheckpoint(
        identity=current.identity,
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        recipe_ref=candidate.recipe_ref,
        image_digest=(
            candidate.image_digest if matching_lineage else f"sha256:{'4' * 64}"
        ),
    )

    if matching_lineage:
        result = await stage(current, prior)
        assert result.validated_poc_ref is not None
    else:
        with pytest.raises(StageFailed) as failed:
            await stage(current, prior)
        assert failed.value.failure.code == "POC_ENVIRONMENT_RECIPE_INVALID"
    assert containers.released == (["a" * 64] if matching_lineage else [])


@pytest.mark.asyncio
@pytest.mark.parametrize("client_type", [_DisprovingClient, _InconclusiveClient])
async def test_degraded_image_cannot_disprove_or_conclude_poc(
    tmp_path: Path, client_type: type[_InterpretationClient]
) -> None:
    stage, current, prior, _artifacts, containers = _poc_with_recipe(
        tmp_path,
        recipe_source="GENERATED_NO_INSTALL",
        degraded=True,
        client=client_type(),
    )

    with pytest.raises(StageBlocked) as blocked:
        await stage(current, prior)

    assert blocked.value.failure.code == "POC_ENVIRONMENT_UNVERIFIED"
    assert blocked.value.failure.retryable is False
    assert containers.acquired == 0
    assert containers.released == []


@pytest.mark.asyncio
async def test_interpretation_failure_preserves_provider_diagnostic_ref(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-invalid-output",
        workspace_id="workspace-invalid-output",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-invalid-output",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    diagnostic_ref = artifacts.put_json({"kind": "simple_llm_invalid_output"})
    content_ref = artifacts.put_bytes(
        b"#!/bin/sh\nprintf observed\n", "text/x-shellscript"
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
            "attempt_id": "attempt-invalid-output",
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
        attempt_id="attempt-invalid-output",
        recipe_ref=recipe_ref,
        image_digest=f"sha256:{'1' * 64}",
    )
    current = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_EXECUTION_DONE,
        status=StageStatus.PENDING,
        input_refs=refs,
        input_hash=input_reference_hash(refs),
        attempt_id="attempt-invalid-output",
    )

    class _InvalidInterpretationClient:
        async def call(self, **_kwargs: Any) -> StageFailure:
            return StageFailure(
                code="INVALID_OUTPUT",
                retryable=True,
                safe_message="Codex returned invalid structured output",
                evidence_refs=(diagnostic_ref,),
            )

    stage = PoCExecutionStage(
        client=_InvalidInterpretationClient(),
        artifacts=artifacts,
        docker=_Docker(),  # type: ignore[arg-type]
        containers=_Containers(),
    )

    with pytest.raises(StageBlocked) as blocked:
        await stage(current, {SimpleStage.POC_CANDIDATE_DONE: candidate})

    failure_refs = blocked.value.failure.evidence_refs
    assert diagnostic_ref in failure_refs
    assert len(failure_refs) == 4
    assert json.loads(artifacts.read(failure_refs[0]))["kind"] == "simple_poc_execution"


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
    recipe_ref = artifacts.put_json(
        {
            "kind": "simple_environment_recipe",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "hypothesis_id": identity.hypothesis_id,
            "attempt_id": "attempt-inconclusive",
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
        attempt_id="attempt-inconclusive",
        recipe_ref=recipe_ref,
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
    recipe_ref = artifacts.put_json(
        {
            "kind": "simple_environment_recipe",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "hypothesis_id": identity.hypothesis_id,
            "attempt_id": "attempt-error",
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
        attempt_id="attempt-error",
        recipe_ref=recipe_ref,
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


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("exit_code", "error_line", "python_traceback", "on_stdout", "blocks"),
    [
        (0, b"ModuleNotFoundError: No module named 'django'", True, False, True),
        (
            1,
            b"ImportError: cannot import name 'settings' from 'app'",
            True,
            False,
            True,
        ),
        (1, b"ModuleNotFoundError: No module named 'django'", True, True, True),
        (1, b"/usr/local/bin/python: No module named app", False, False, True),
        (0, b"ImportError: expected diagnostic text only", False, False, False),
    ],
)
async def test_python_import_traceback_blocks_before_disproof_interpretation(
    tmp_path: Path,
    exit_code: int,
    error_line: bytes,
    python_traceback: bool,
    on_stdout: bool,
    blocks: bool,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-import-error",
        workspace_id="workspace-import-error",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-import-error",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    content_ref = artifacts.put_bytes(
        b"#!/bin/sh\npython -m app\n", "text/x-shellscript"
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
            "attempt_id": "attempt-import-error",
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
        attempt_id="attempt-import-error",
        recipe_ref=recipe_ref,
        image_digest=f"sha256:{'1' * 64}",
    )
    current = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_EXECUTION_DONE,
        status=StageStatus.PENDING,
        input_refs=refs,
        input_hash=input_reference_hash(refs),
        attempt_id="attempt-import-error",
    )
    stderr = (
        (
            (
                b"Traceback (most recent call last):\n"
                b'  File "<stdin>", line 1, in <module>\n'
            )
            if python_traceback
            else b""
        )
        + error_line
        + b"\n"
    )

    class _ImportErrorDocker(_Docker):
        async def execute(self, *_args: Any, **_kwargs: Any) -> DockerCommandOutcome:
            return DockerCommandOutcome(
                exit_code,
                stderr if on_stdout else b"",
                b"" if on_stdout else stderr,
                False,
            )

    client = _DisprovingClient()
    containers = _Containers()
    stage = PoCExecutionStage(
        client=client,
        artifacts=artifacts,
        docker=_ImportErrorDocker(),  # type: ignore[arg-type]
        containers=containers,
    )

    if not blocks:
        result = await stage(current, {SimpleStage.POC_CANDIDATE_DONE: candidate})
        assert result.validated_poc_ref is None
        assert json.loads(artifacts.read(result.output_refs[1]))["result"][
            "outcome"
        ] == ("DISPROVED")
        assert client.calls == 1
        return

    with pytest.raises(StageBlocked) as blocked:
        await stage(current, {SimpleStage.POC_CANDIDATE_DONE: candidate})

    assert blocked.value.failure.code == "POC_EXECUTION_FAILED"
    assert blocked.value.failure.retryable is True
    assert client.calls == 0
    assert containers.released == ["a" * 64]
    execution_ref, stdout_ref, stderr_ref, _cleanup_ref = (
        blocked.value.failure.evidence_refs
    )
    observation_ref = stdout_ref if on_stdout else stderr_ref
    assert artifacts.read(observation_ref) == stderr
    assert json.loads(artifacts.read(execution_ref))[
        "stdout_ref" if on_stdout else "stderr_ref"
    ] == observation_ref.model_dump(mode="json")
