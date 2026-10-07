"""Fail-closed terminal evidence for deterministic runtime environment blocks."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from shutil import rmtree

import pytest

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.sandbox.docker_adapter import DockerCommandOutcome, DockerOperationError
from sastsimi.simple_runtime.artifacts import (
    SimpleArtifactRepository,
    verified_terminal_projection,
)
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
    terminal_initial_outcome,
)
from sastsimi.simple_runtime.portable_docker import DependencyBundleResolutionError
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.recovery import (
    RecoveryAction,
    RecoveryCategory,
    RecoveryDecision,
    RecoveryResolution,
)
from sastsimi.simple_runtime.runner import SimpleRuntimeRunner
from sastsimi.simple_runtime.stages import (
    InitialVerificationStage,
    ReproductionEnvironment,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _checkpoint_with_environment_block(
    tmp_path: Path,
    *,
    attempt_id: str = "attempt-1",
    timed_out: bool = False,
    receipt_attempt_id: str | None = None,
    pinned_requirements: tuple[str, ...] | None = ("aiohttp==3.5.3",),
) -> tuple[SimpleArtifactRepository, StageCheckpoint]:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    initial_ref = artifacts.put_json(
        {
            "kind": "simple_initial_verification",
            "attempt_id": attempt_id,
            "result": {
                "initial_assessment": "TRUE",
                "unmet_external_prerequisites": [],
            },
        }
    )
    stderr_ref = artifacts.put_bytes(
        b"ERROR: No matching distribution found for aiohttp==3.5.3\n",
        "text/plain",
    )
    receipt = {
        "kind": "simple_dependency_bundle_attempt",
        "identity": identity.model_dump(mode="json"),
        "attempt_id": receipt_attempt_id or attempt_id,
        "status": "FAILED",
        "dependency_bundle_source": "AUTO_RESOLVED",
        "base_image_digest": "sha256:" + "b" * 64,
        "manifest_sha256": "c" * 64,
        "dependency_resolution_input_kind": "TARGET_MANIFEST",
        "requirements_sha256": "d" * 64,
        "requirement_count": 1,
        "error_code": "POC_AUTO_BUNDLE_DOWNLOAD_FAILED",
        "stderr_ref": stderr_ref.model_dump(mode="json"),
        "stdout_ref": None,
        "timed_out": timed_out,
    }
    if pinned_requirements is not None:
        receipt["pinned_requirement_provenance"] = {
            "kind": "simple_pinned_requirement_provenance_v1",
            "source_kind": "TARGET_MANIFEST",
            "source_path": "requirements.txt",
            "source_sha256": "c" * 64,
            "requirements": list(pinned_requirements),
        }
    receipt_ref = artifacts.put_json(receipt)
    block_ref = artifacts.put_json(
        {
            "kind": "simple_initial_environment_block_v1",
            "identity": identity.model_dump(mode="json"),
            "attempt_id": attempt_id,
            "classification": "PINNED_BINARY_DISTRIBUTION_UNAVAILABLE",
            "initial_verification_ref": initial_ref.model_dump(mode="json"),
            "dependency_bundle_attempt_ref": receipt_ref.model_dump(mode="json"),
        }
    )
    checkpoint = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(initial_ref, receipt_ref, block_ref),
        attempt_id=attempt_id,
        verdict="HOLD",
        environment_block_ref=block_ref,
    )
    return artifacts, checkpoint


def test_terminal_initial_accepts_only_runtime_generated_pinned_binary_block(
    tmp_path: Path,
) -> None:
    artifacts, checkpoint = _checkpoint_with_environment_block(tmp_path)

    assert terminal_initial_outcome(checkpoint) == "INCONCLUSIVE"
    assert artifacts.verified_terminal_initial_outcome(checkpoint) == "INCONCLUSIVE"


def test_terminal_projection_does_not_recreate_missing_artifact_directories(
    tmp_path: Path,
) -> None:
    _artifacts, checkpoint = _checkpoint_with_environment_block(tmp_path)
    paths = RuntimePaths(tmp_path)
    absent = (paths.staging, paths.artifacts / "sha256", paths.quarantine)
    for path in absent:
        rmtree(path)

    projected = verified_terminal_projection((checkpoint,), tmp_path)

    assert projected[0].status is StageStatus.BLOCKED
    assert projected[0].error_code == "INITIAL_VERIFICATION_EVIDENCE_INVALID"
    assert all(not path.exists() for path in absent)


def test_terminal_initial_rejects_agent_only_requirement_with_no_pinned_origin(
    tmp_path: Path,
) -> None:
    """A pip: extra must not impersonate a target-manifest binary pin."""

    artifacts, checkpoint = _checkpoint_with_environment_block(
        tmp_path,
        pinned_requirements=("sample-pkg==1.0",),
    )

    with pytest.raises(ValueError, match="INITIAL_VERIFICATION_EVIDENCE_INVALID"):
        artifacts.verified_terminal_initial_outcome(checkpoint)


@pytest.mark.parametrize(
    "marker",
    ("sys_platform == 'win32'", "sys_platform == 'linux'"),
)
def test_terminal_initial_rejects_pin_without_resolver_marker_evidence(
    tmp_path: Path, marker: str
) -> None:
    artifacts, checkpoint = _checkpoint_with_environment_block(
        tmp_path,
        pinned_requirements=(f"aiohttp==3.5.3; {marker}",),
    )

    with pytest.raises(ValueError, match="INITIAL_VERIFICATION_EVIDENCE_INVALID"):
        artifacts.verified_terminal_initial_outcome(checkpoint)


def test_terminal_initial_rejects_legacy_receipt_without_pinned_origin(
    tmp_path: Path,
) -> None:
    """A receipt hash alone cannot prove which target dependency failed."""

    artifacts, checkpoint = _checkpoint_with_environment_block(
        tmp_path,
        pinned_requirements=None,
    )

    with pytest.raises(ValueError, match="INITIAL_VERIFICATION_EVIDENCE_INVALID"):
        artifacts.verified_terminal_initial_outcome(checkpoint)


@pytest.mark.parametrize(
    ("timed_out", "receipt_attempt_id"),
    [(True, None), (False, "different-attempt")],
)
def test_terminal_initial_rejects_unlinked_or_timeout_environment_receipt(
    tmp_path: Path,
    timed_out: bool,
    receipt_attempt_id: str | None,
) -> None:
    artifacts, checkpoint = _checkpoint_with_environment_block(
        tmp_path,
        timed_out=timed_out,
        receipt_attempt_id=receipt_attempt_id,
    )

    assert terminal_initial_outcome(checkpoint) == "INCONCLUSIVE"
    with pytest.raises(ValueError, match="INITIAL_VERIFICATION_EVIDENCE_INVALID"):
        artifacts.verified_terminal_initial_outcome(checkpoint)


@pytest.mark.asyncio
async def test_initial_stage_preserves_agent_output_and_terminalizes_receipted_block(
    tmp_path: Path,
) -> None:
    artifacts, completed_template = _checkpoint_with_environment_block(tmp_path)
    receipt_ref = completed_template.output_refs[1]
    checkpoint = completed_template.model_copy(
        update={
            "status": StageStatus.RUNNING,
            "output_refs": (),
            "environment_block_ref": None,
        }
    )

    class _Client:
        async def call(self, **_kwargs: object) -> SimpleLLMCallResult:
            return SimpleLLMCallResult(
                value={
                    "initial_assessment": "TRUE",
                    "rationale": "A dynamic reproduction is needed.",
                    "reproduction_goal": "Exercise the pinned route.",
                    "environment_requirements": ["pip:aiohttp==3.5.3"],
                    "unmet_external_prerequisites": [],
                    "supporting_refs": [],
                    "limitations": [],
                },
                prompt_digest="a" * 64,
                output_digest="b" * 64,
            )

    class _Environment:
        async def prepare(
            self,
            _checkpoint: StageCheckpoint,
            _prior: Mapping[SimpleStage, StageCheckpoint],
            _requirements: tuple[str, ...],
        ) -> ReproductionEnvironment:
            error = DockerOperationError(
                "POC_AUTO_BUNDLE_DOWNLOAD_FAILED",
                DockerCommandOutcome(
                    1,
                    b"",
                    b"No matching distribution found for aiohttp==3.5.3\n",
                    False,
                ),
            )
            raise DependencyBundleResolutionError(error, (receipt_ref,))

    result = await InitialVerificationStage(_Client(), artifacts, _Environment())(
        checkpoint, {}
    )

    assert result.verdict == "HOLD"
    assert result.environment_block_ref is not None
    assert result.external_prerequisites_ref is None
    assert len(result.output_refs) == 3
    completed = checkpoint.model_copy(
        update={
            "status": StageStatus.SUCCEEDED,
            "output_refs": result.output_refs,
            "environment_block_ref": result.environment_block_ref,
            "verdict": result.verdict,
        }
    )
    assert artifacts.verified_terminal_initial_outcome(completed) == "INCONCLUSIVE"


@pytest.mark.asyncio
async def test_recovery_stop_is_persisted_then_promoted_only_from_linked_receipt(
    tmp_path: Path,
) -> None:
    artifacts, template = _checkpoint_with_environment_block(tmp_path / "data")
    blocked = template.model_copy(
        update={
            "status": StageStatus.BLOCKED,
            "output_refs": template.output_refs[:2],
            "environment_block_ref": None,
            "verdict": None,
            "error_code": "POC_AUTO_BUNDLE_DOWNLOAD_FAILED",
            "retryable": True,
            "attempt_number": 1,
        }
    )
    store = SimpleCheckpointStore(
        tmp_path / "state" / "sastsimi.sqlite3", artifact_data_dir=tmp_path / "data"
    )
    store.save_checkpoint(blocked)
    decision_ref = artifacts.put_json({"kind": "simple_recovery_decision"})
    stopped = store.record_recovery_stop(
        blocked,
        RecoveryResolution(
            decision=RecoveryDecision(
                category=RecoveryCategory.TERMINAL,
                action=RecoveryAction.STOP,
                diagnosis="pinned distribution is unavailable",
                guidance="do not repeat the same resolver download",
            ),
            decision_ref=decision_ref,
        ),
    )

    assert stopped.retryable is False
    assert store.require(blocked.identity, blocked.stage).retryable is False, (
        "a recorded STOP must not replay the identical download on resume"
    )
    outcome = await SimpleRuntimeRunner(
        store, {}, recovery=None, cleanup_artifacts=artifacts
    )._recover_existing(stopped)
    assert outcome is not None
    assert outcome is not False
    assert outcome.status is StageStatus.SUCCEEDED
    promoted = store.require(blocked.identity, blocked.stage)

    assert promoted.status is StageStatus.SUCCEEDED
    assert promoted.verdict == "HOLD"
    assert promoted.environment_block_ref is not None
    assert terminal_initial_outcome(promoted) == "INCONCLUSIVE"
    assert store.verified_terminal_initial_outcome(promoted) == "INCONCLUSIVE"


@pytest.mark.asyncio
async def test_resume_keeps_invalid_environment_receipt_blocked(tmp_path: Path) -> None:
    artifacts, template = _checkpoint_with_environment_block(
        tmp_path / "data", timed_out=True
    )
    blocked = template.model_copy(
        update={
            "status": StageStatus.BLOCKED,
            "output_refs": template.output_refs[:2],
            "environment_block_ref": None,
            "verdict": None,
            "error_code": "POC_AUTO_BUNDLE_DOWNLOAD_FAILED",
            "retryable": False,
            "attempt_number": 1,
        }
    )
    store = SimpleCheckpointStore(
        tmp_path / "state" / "sastsimi.sqlite3", artifact_data_dir=tmp_path / "data"
    )
    store.save_checkpoint(blocked)

    outcome = await SimpleRuntimeRunner(
        store, {}, recovery=None, cleanup_artifacts=artifacts
    )._recover_existing(blocked)

    assert outcome is not None
    assert outcome is not False
    assert outcome.status is StageStatus.BLOCKED
    assert outcome.error_code == "POC_AUTO_BUNDLE_DOWNLOAD_FAILED"
    assert store.require(blocked.identity, blocked.stage) == blocked
