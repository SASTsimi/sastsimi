from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.simple_runtime.application import SimpleAnalysisApplication
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
    terminal_poc_outcome,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _seed(
    tmp_path: Path,
    *,
    stdout: bytes = b"".join(
        (
            b"precondition=False\n",
            b"SASTSIMI_POC_DISPROVED: missing precondition\n",
        )
    ),
    stderr: bytes = b"",
    exit_code: int = 1,
    interpretation_outcome: str = "INCONCLUSIVE",
    cleanup_status: str = "REMOVED",
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-exit-one",
        workspace_id="workspace-one",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-one",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    attempt_id = "attempt-five"
    container_id = "container-five"
    image_digest = "sha256:" + "b" * 64
    recipe_ref = artifacts.put_json(
        {
            "kind": "simple_environment_recipe",
            "status": "BUILT",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "hypothesis_id": identity.hypothesis_id,
            "attempt_id": "environment-attempt",
            "dockerfile_source": "GENERATED",
            "degraded": False,
            "image_digest": image_digest,
        }
    )
    initial = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(recipe_ref,),
        attempt_id="initial-attempt",
        recipe_ref=recipe_ref,
        image_digest=image_digest,
    )
    store.save_checkpoint(initial)
    content_ref = artifacts.put_bytes(b"print('observation')\n", "text/x-python")
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "attempt_id": attempt_id,
            "content_ref": content_ref.model_dump(mode="json"),
            "content_digest": content_ref.content_hash,
        }
    )
    candidate = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_CANDIDATE_DONE,
        stage_version=STAGE_VERSION[SimpleStage.POC_CANDIDATE_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(candidate_ref, content_ref),
        attempt_id=attempt_id,
        attempt_number=5,
        recipe_ref=recipe_ref,
        image_digest=image_digest,
    )
    store.save_checkpoint(candidate)
    stdout_ref = artifacts.put_bytes(stdout, "text/plain")
    stderr_ref = artifacts.put_bytes(stderr, "text/plain")
    execution_ref = artifacts.put_json(
        {
            "kind": "simple_poc_execution",
            "attempt_id": attempt_id,
            "candidate_ref": candidate_ref.model_dump(mode="json"),
            "content_ref": content_ref.model_dump(mode="json"),
            "stdout_ref": stdout_ref.model_dump(mode="json"),
            "stderr_ref": stderr_ref.model_dump(mode="json"),
            "container_id": container_id,
            "image_digest": image_digest,
            "timed_out": False,
            "exit_code": exit_code,
        }
    )
    interpretation_ref = artifacts.put_json(
        {
            "kind": "simple_dynamic_interpretation",
            "execution_ref": execution_ref.model_dump(mode="json"),
            "result": {"outcome": interpretation_outcome},
        }
    )
    cleanup_ref = artifacts.put_json(
        {
            "kind": "simple_container_cleanup",
            "attempt_id": attempt_id,
            "container_id": container_id,
            "status": cleanup_status,
        }
    )
    inputs = (candidate_ref, content_ref)
    blocked = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.POC_EXECUTION_DONE,
        stage_version=STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE],
        status=StageStatus.BLOCKED,
        input_refs=inputs,
        input_hash=input_reference_hash(inputs),
        output_refs=(
            execution_ref,
            stdout_ref,
            stderr_ref,
            interpretation_ref,
            cleanup_ref,
        ),
        error_code="RECOVERY_EXHAUSTED",
        retryable=False,
        attempt_id=attempt_id,
        attempt_number=5,
        recipe_ref=recipe_ref,
        image_digest=image_digest,
    )
    store.save_checkpoint(blocked)
    return store, artifacts, blocked


def test_exact_exit_one_inconclusive_evidence_promotes_to_hold(tmp_path: Path) -> None:
    store, artifacts, blocked = _seed(tmp_path)

    completed = store.promote_exit_one_inconclusive_execution(
        blocked, artifacts=artifacts
    )

    assert completed.status is StageStatus.SUCCEEDED
    assert completed.verdict == "HOLD"
    assert completed.error_code is None
    assert completed.validated_poc_ref is None
    assert completed.output_refs == (
        blocked.output_refs[0],
        blocked.output_refs[3],
        blocked.output_refs[4],
    )
    assert terminal_poc_outcome(completed) == "INCONCLUSIVE"
    assert store.require(blocked.identity, blocked.stage) == completed
    with pytest.raises(ValueError, match="STALE"):
        store.promote_exit_one_inconclusive_execution(blocked, artifacts=artifacts)


@pytest.mark.parametrize(
    ("change", "value"),
    [
        ("stdout", b"ordinary failure\n"),
        ("stderr", b"Traceback: missing package\n"),
        ("exit_code", 2),
        ("interpretation_outcome", "DISPROVED"),
        ("cleanup_status", "BLOCKED"),
    ],
)
def test_exit_one_promotion_rejects_unproven_observations(
    tmp_path: Path, change: str, value: object
) -> None:
    changes: dict[str, Any] = {change: value}
    store, artifacts, blocked = _seed(tmp_path, **changes)

    with pytest.raises(ValueError, match="UNVERIFIED"):
        store.promote_exit_one_inconclusive_execution(blocked, artifacts=artifacts)
    assert store.require(blocked.identity, blocked.stage) == blocked


def test_resume_preflight_promotes_only_once(tmp_path: Path) -> None:
    store, _, blocked = _seed(tmp_path)
    app = cast(
        SimpleAnalysisApplication,
        SimpleNamespace(_store=store, _data_dir=tmp_path),
    )

    assert (
        SimpleAnalysisApplication._promote_legacy_inconclusive_pocs(
            app, blocked.identity.analysis_id
        )
        == 1
    )
    assert (
        SimpleAnalysisApplication._promote_legacy_inconclusive_pocs(
            app, blocked.identity.analysis_id
        )
        == 0
    )
    assert store.require(blocked.identity, blocked.stage).verdict == "HOLD"


@pytest.mark.parametrize("missing", ("recipe", "candidate_image"))
def test_promotion_requires_a_bound_built_environment(
    tmp_path: Path, missing: str
) -> None:
    store, artifacts, blocked = _seed(tmp_path)
    candidate = store.require(blocked.identity, SimpleStage.POC_CANDIDATE_DONE)
    if missing == "recipe":
        candidate = candidate.model_copy(update={"recipe_ref": None})
        blocked = blocked.model_copy(update={"recipe_ref": None})
        store.save_checkpoint(blocked)
    else:
        candidate = candidate.model_copy(update={"image_digest": None})
    store.save_checkpoint(candidate)

    with pytest.raises(ValueError, match="UNVERIFIED"):
        store.promote_exit_one_inconclusive_execution(blocked, artifacts=artifacts)
