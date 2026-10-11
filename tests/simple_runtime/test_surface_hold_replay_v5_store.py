"""A v5 HOLD replay is a one-shot, exact-child SQLite transition."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import Literal, TypedDict

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    MAX_RECOVERY_ATTEMPTS,
    STAGE_VERSION,
    CandidateTerminal,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_hold_replay_v5 import (
    HoldReplayDecision,
    classify_hold_replay,
)

SOURCE = b"def probe(value):\n    return value == 'fresh-input'\n"
PROOF_TYPE = {
    "initial": "PREREQUISITE_CONTRADICTION",
    "generated": "GENERATED_INPUT_TEST_PATH",
    "exhausted": "NEW_DECISIVE_TEST_PATH",
}


class _ReviewRefs(TypedDict, total=False):
    review_plan_ref: StoredDataRef
    review_context_ref: StoredDataRef
    review_result_ref: StoredDataRef


class _IsolatedPocArtifactRepository(SimpleArtifactRepository):
    def verified_terminal_poc_outcome(
        self, _checkpoint: StageCheckpoint | None
    ) -> Literal["INCONCLUSIVE"] | None:
        # This test exercises the store's CAS; PoC validation is covered elsewhere.
        return "INCONCLUSIVE"


def _repo(tmp_path: Path) -> tuple[Path, str]:
    workspace = tmp_path / "repo"
    (workspace / "pkg").mkdir(parents=True)
    (workspace / "pkg/probe.py").write_bytes(SOURCE)
    subprocess.run(["git", "init", "-q", str(workspace)], check=True)
    subprocess.run(
        ["git", "-C", str(workspace), "add", "--", "pkg/probe.py"], check=True
    )
    subprocess.run(
        [
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    commit = (
        subprocess.check_output(["git", "-C", str(workspace), "rev-parse", "HEAD"])
        .decode("ascii")
        .strip()
    )
    return workspace, commit


def _seed(
    tmp_path: Path, category: str = "initial"
) -> tuple[
    SimpleCheckpointStore,
    SimpleArtifactRepository,
    SimpleAnalysisRun,
    StageCheckpoint,
    StageCheckpoint | None,
    dict[str, object],
]:
    workspace, commit = _repo(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="A-001",
        workspace_id="workspace",
        commit_id=commit,
        hypothesis_id="hypothesis",
    )
    data_dir = tmp_path / "data"
    artifact_type = (
        SimpleArtifactRepository
        if category == "initial"
        else _IsolatedPocArtifactRepository
    )
    artifacts = artifact_type(data_dir, identity)
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    v4_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v4"})
    certificate_ref = artifacts.put_json({"kind": "python_scope_certificate"})
    v5_ref = artifacts.put_json(
        {
            "kind": "simple_surface_enrichment_plan_v5",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "scope_fingerprint": "scope",
            "v4_plan_ref": v4_ref.model_dump(mode="json"),
            "v4_plan_hash": v4_ref.content_hash,
            "expected_parts": [],
            "targets": [],
            "target_surface_ids": [],
        }
    )
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/repository",
        workspace_path=workspace,
        candidate_pipeline_version=2,
        candidate_scope_fingerprint="scope",
        hypothesis_ids=(identity.hypothesis_id or "",),
        surface_enrichment_plan_ref=v4_ref,
        surface_enrichment_v5_plan_ref=v5_ref,
        python_scope_certificate_ref=certificate_ref,
    )
    store.save_analysis_run(run)
    candidate: StageCheckpoint | None = None
    if category == "initial":
        old_ref = artifacts.put_json(
            {
                "kind": "simple_initial_verification",
                "attempt_id": "try-1",
                "result": {
                    "unmet_external_prerequisites": ["fresh-input is unavailable"]
                },
            }
        )
        child = StageCheckpoint(
            identity=identity,
            stage=SimpleStage.VERIFICATION_INITIAL_DONE,
            stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(old_ref,),
            external_prerequisites_ref=old_ref,
            attempt_id="try-1",
            attempt_number=1,
            verdict="HOLD",
        )
    else:
        content_ref = artifacts.put_bytes(b"stale", "text/plain")
        candidate_ref = artifacts.put_json(
            {
                "kind": "simple_poc_candidate",
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
            attempt_id="candidate-1",
            attempt_number=1,
        )
        store.save_checkpoint(candidate)
        execution_ref = artifacts.put_json(
            {
                "kind": "simple_poc_execution",
                "candidate_ref": candidate_ref.model_dump(mode="json"),
                "content_ref": content_ref.model_dump(mode="json"),
            }
        )
        interpretation_ref = artifacts.put_json(
            {"kind": "simple_dynamic_interpretation", "outcome": "INCONCLUSIVE"}
        )
        stop_ref = (
            artifacts.put_json(
                {
                    "kind": "simple_recovery_decision",
                    "decision": {"action": "STOP", "category": "GENERATED_INPUT"},
                }
            )
            if category == "generated"
            else None
        )
        child = StageCheckpoint(
            identity=identity,
            stage=SimpleStage.POC_EXECUTION_DONE,
            stage_version=STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=(candidate_ref, content_ref),
            input_hash=input_reference_hash((candidate_ref, content_ref)),
            output_refs=(execution_ref, interpretation_ref),
            poc_stop_decision_ref=stop_ref,
            attempt_id="try-1",
            attempt_number=1 if stop_ref else MAX_RECOVERY_ATTEMPTS,
            verdict="HOLD",
        )
        old_ref = stop_ref or interpretation_ref
    store.save_checkpoint(child)
    checkpoint_sha256 = hashlib.sha256(canonical_bytes(child)).hexdigest()
    source_sha256 = hashlib.sha256(SOURCE).hexdigest()
    material_ref = (
        artifacts.put_json(
            {
                "kind": (
                    "simple_surface_replay_test_input_v1"
                    if category == "generated"
                    else "simple_surface_replay_execution_prerequisite_v1"
                ),
                "identity": identity.model_dump(mode="json"),
                "checkpoint_sha256": checkpoint_sha256,
                "source_sha256": source_sha256,
                "value": "fresh-input" if category == "generated" else "new test path",
            }
        )
        if category != "initial"
        else None
    )
    new_ref = artifacts.put_json(
        {
            "kind": "simple_surface_replay_new_evidence_v1",
            "identity": identity.model_dump(mode="json"),
            "checkpoint_sha256": checkpoint_sha256,
            "proof_type": PROOF_TYPE[category],
            "source_path": "pkg/probe.py",
            "source_sha256": source_sha256,
            "material_ref": material_ref.model_dump(mode="json")
            if material_ref
            else None,
        }
    )
    proof_ref = artifacts.put_json(
        {
            "kind": "simple_surface_hold_replay_proof_v1",
            "identity": identity.model_dump(mode="json"),
            "checkpoint_sha256": checkpoint_sha256,
            "proof_type": PROOF_TYPE[category],
            "old_output_refs": [
                ref.model_dump(mode="json") for ref in child.output_refs
            ],
            "old_evidence_ref": old_ref.model_dump(mode="json"),
            "new_evidence_ref": new_ref.model_dump(mode="json"),
            "source_path": "pkg/probe.py",
            "source_sha256": source_sha256,
            "source_sites": [
                {
                    "line": 2,
                    "sha256": hashlib.sha256(SOURCE.splitlines()[1]).hexdigest(),
                }
            ],
            "claim": "fresh-input is unavailable" if category == "initial" else None,
        }
    )
    evidence: dict[str, object] = {
        "kind": "simple_surface_hold_replay_evidence_v1",
        "identity": identity.model_dump(mode="json"),
        "checkpoint_sha256": checkpoint_sha256,
        "workspace_path": str(workspace),
        "proof_ref": proof_ref.model_dump(mode="json"),
    }
    return store, artifacts, run, child, candidate, evidence


def _decision(
    child: StageCheckpoint,
    artifacts: SimpleArtifactRepository,
    evidence: dict[str, object],
) -> HoldReplayDecision:
    result = classify_hold_replay(child.identity, child, evidence, artifacts)
    assert result.action != "KEEP_HOLD", result.reason
    return result


def _markers(store: SimpleCheckpointStore) -> list[tuple[str, str, str]]:
    with sqlite3.connect(store.database_path) as connection:
        return connection.execute(
            "SELECT action, old_checkpoint_ref_json, marker_ref_json "
            "FROM simple_surface_hold_replay_markers ORDER BY rowid"
        ).fetchall()


def _review_refs(
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
    run: SimpleAnalysisRun,
    child: StageCheckpoint,
) -> tuple[StoredDataRef, StoredDataRef, StoredDataRef]:
    context_ref = artifacts.put_json(
        {
            "kind": "simple_surface_context_v5",
            "analysis_id": child.identity.analysis_id,
            "workspace_id": child.identity.workspace_id,
            "commit_id": child.identity.commit_id,
            "scope_fingerprint": "scope",
            "static_bundle_hash": "static",
            "surface_index_hash": "index",
            "surface_id": "surface-1",
            "source_sha256": "s" * 64,
            "graph_hash": "g" * 64,
            "part_index": 0,
            "part_count": 1,
        }
    )
    result_ref = artifacts.put_json(
        {
            "kind": "simple_surface_hypothesis_result_v5",
            "analysis_id": child.identity.analysis_id,
            "surface_id": "surface-1",
            "context_id": "context-1",
            "context_hash": context_ref.content_hash,
            "part_index": 0,
            "part_count": 1,
            "static_bundle_hash": "static",
            "graph_hash": "g" * 64,
            "status": "NO_HYPOTHESIS",
            "validation_status": "VALID",
            "seed_ids": [],
            "response": {},
        }
    )
    assert run.surface_enrichment_v5_plan_ref is not None
    plan = json.loads(artifacts.read(run.surface_enrichment_v5_plan_ref))
    plan.update(
        {
            "static_bundle_hash": "static",
            "index_hash": "index",
            "target_surface_ids": ["surface-1"],
            "targets": [{"surface_id": "surface-1", "graph_hash": "g" * 64}],
            "child_checkpoint_hashes": {
                child.identity.hypothesis_id: hashlib.sha256(
                    canonical_bytes(child)
                ).hexdigest()
            },
            "expected_parts": [
                {
                    "surface_id": "surface-1",
                    "context_id": "context-1",
                    "context_hash": context_ref.content_hash,
                    "part_index": 0,
                    "part_count": 1,
                    "source_sha256": "s" * 64,
                }
            ],
        }
    )
    plan_ref = artifacts.put_json(plan)
    store.save_analysis_run(
        run.model_copy(update={"surface_enrichment_v5_plan_ref": plan_ref})
    )
    parent = child.identity.model_copy(update={"hypothesis_id": None})
    store.commit_surface_exploration(
        parent,
        "scope",
        "surface-1",
        "context-1",
        static_bundle_hash="static",
        index_hash="index",
        context_hash=context_ref.content_hash,
        source_sha256="s" * 64,
        status="NO_HYPOTHESIS",
        result_ref=result_ref,
        registrations=(),
        proposal_version=5,
    )
    return plan_ref, context_ref, result_ref


@pytest.mark.parametrize(
    ("category", "expected_action", "restart"),
    [
        ("initial", "REPLAY_INITIAL_ONCE", SimpleStage.VERIFICATION_INITIAL_DONE),
        ("generated", "REGENERATE_POC_ONCE", SimpleStage.POC_CANDIDATE_DONE),
        ("exhausted", "REEXECUTE_POC_ONCE", SimpleStage.POC_EXECUTION_DONE),
    ],
)
def test_exact_hold_replay_reopens_only_selected_stage_once(
    tmp_path: Path, category: str, expected_action: str, restart: SimpleStage
) -> None:
    store, artifacts, _, child, candidate, evidence = _seed(tmp_path, category)
    decision = _decision(child, artifacts, evidence)
    assert decision.action == expected_action

    pending = store.prepare_surface_hold_replay(child, decision, artifacts)

    assert pending is not None
    assert pending.stage is restart
    assert pending.status is StageStatus.PENDING
    replayed = candidate if category == "generated" else child
    assert replayed is not None
    assert pending.attempt_number == replayed.attempt_number
    assert pending.output_refs == ()
    assert pending.input_refs[: len(replayed.input_refs)] == replayed.input_refs
    assert len(pending.input_refs) == len(replayed.input_refs) + 1
    assert store.require(child.identity, restart) == pending
    if category == "generated":
        assert store.get(child.identity, SimpleStage.POC_EXECUTION_DONE) is None
    elif category == "exhausted":
        assert (
            store.require(child.identity, SimpleStage.POC_CANDIDATE_DONE) == candidate
        )
    rows = _markers(store)
    assert len(rows) == 1
    assert rows[0][0] == expected_action
    old_ref = StoredDataRef.model_validate_json(rows[0][1])
    marker_ref = StoredDataRef.model_validate_json(rows[0][2])
    old = json.loads(artifacts.read(old_ref))
    marker = json.loads(artifacts.read(marker_ref))
    assert old["checkpoint_sha256"] == decision.checkpoint_sha256
    assert marker["old_checkpoint_ref"] == old_ref.model_dump(mode="json")
    assert marker["decision"]["action"] == expected_action
    with pytest.raises(ValueError, match="SURFACE_HOLD_REPLAY_"):
        store.prepare_surface_hold_replay(child, decision, artifacts)


def test_keep_hold_saves_review_without_mutating_child(tmp_path: Path) -> None:
    store, artifacts, run, child, _, _ = _seed(tmp_path)
    plan_ref, context_ref, result_ref = _review_refs(store, artifacts, run, child)
    decision = classify_hold_replay(child.identity, child, {}, artifacts)
    assert decision.action == "KEEP_HOLD"

    assert (
        store.prepare_surface_hold_replay(
            child,
            decision,
            artifacts,
            review_plan_ref=plan_ref,
            review_context_ref=context_ref,
            review_result_ref=result_ref,
        )
        is None
    )
    assert store.require(child.identity, child.stage) == child
    assert _markers(store)[0][0] == "KEEP_HOLD"
    marker_ref = StoredDataRef.model_validate_json(_markers(store)[0][2])
    marker = json.loads(artifacts.read(marker_ref))
    assert marker["review_plan_ref"] == plan_ref.model_dump(mode="json")
    assert marker["review_context_ref"] == context_ref.model_dump(mode="json")
    assert marker["review_result_ref"] == result_ref.model_dump(mode="json")
    assert marker["decision"]["evidence_refs"] == []
    assert (
        store.prepare_surface_hold_replay(
            child,
            decision,
            artifacts,
            review_plan_ref=plan_ref,
            review_context_ref=context_ref,
            review_result_ref=result_ref,
        )
        is None
    )
    assert len(_markers(store)) == 1


def test_keep_hold_requires_exact_saved_v5_review_refs(tmp_path: Path) -> None:
    store, artifacts, run, child, _, _ = _seed(tmp_path)
    plan_ref, context_ref, result_ref = _review_refs(store, artifacts, run, child)
    decision = classify_hold_replay(child.identity, child, {}, artifacts)
    wrong_ref = artifacts.put_json({"kind": "unrelated"})

    cases: tuple[_ReviewRefs, ...] = (
        {},
        {
            "review_plan_ref": wrong_ref,
            "review_context_ref": context_ref,
            "review_result_ref": result_ref,
        },
        {
            "review_plan_ref": plan_ref,
            "review_context_ref": wrong_ref,
            "review_result_ref": result_ref,
        },
        {
            "review_plan_ref": plan_ref,
            "review_context_ref": context_ref,
            "review_result_ref": wrong_ref,
        },
    )
    for refs in cases:
        with pytest.raises(ValueError, match="SURFACE_HOLD_REVIEW_UNVERIFIED"):
            store.prepare_surface_hold_replay(child, decision, artifacts, **refs)
    assert _markers(store) == []
    assert store.require(child.identity, child.stage) == child


def test_keep_hold_rejects_stale_v5_progress_result(tmp_path: Path) -> None:
    store, artifacts, run, child, _, _ = _seed(tmp_path)
    plan_ref, context_ref, result_ref = _review_refs(store, artifacts, run, child)
    decision = classify_hold_replay(child.identity, child, {}, artifacts)
    replacement = artifacts.put_json({"kind": "unrelated"})
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE simple_surface_exploration_progress SET result_ref_json = ? "
            "WHERE analysis_id = ? AND surface_id = ? AND context_id = ?",
            (
                replacement.model_dump_json(),
                child.identity.analysis_id,
                "surface-1",
                "context-1",
            ),
        )

    with pytest.raises(ValueError, match="SURFACE_HOLD_REVIEW_UNVERIFIED"):
        store.prepare_surface_hold_replay(
            child,
            decision,
            artifacts,
            review_plan_ref=plan_ref,
            review_context_ref=context_ref,
            review_result_ref=result_ref,
        )
    assert _markers(store) == []


def test_crash_rolls_back_marker_and_checkpoint_and_allows_exact_retry(
    tmp_path: Path,
) -> None:
    store, artifacts, _, child, _, evidence = _seed(tmp_path)
    decision = _decision(child, artifacts, evidence)

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_surface_hold_replay(
            child, decision, artifacts, fail_before_commit=True
        )

    assert store.require(child.identity, child.stage) == child
    assert _markers(store) == []
    assert store.prepare_surface_hold_replay(child, decision, artifacts) is not None
    assert len(_markers(store)) == 1


def test_forged_action_or_missing_v5_plan_cannot_reopen(tmp_path: Path) -> None:
    store, artifacts, run, child, _, evidence = _seed(tmp_path)
    decision = _decision(child, artifacts, evidence)
    forged = replace(
        decision,
        action="REEXECUTE_POC_ONCE",
        restart_stage=SimpleStage.POC_EXECUTION_DONE,
    )
    with pytest.raises(ValueError, match="SURFACE_HOLD_REPLAY_"):
        store.prepare_surface_hold_replay(child, forged, artifacts)
    store.save_analysis_run(
        run.model_copy(update={"surface_enrichment_v5_plan_ref": None})
    )
    with pytest.raises(ValueError, match="SURFACE_HOLD_REPLAY_"):
        store.prepare_surface_hold_replay(child, decision, artifacts)
    assert store.require(child.identity, child.stage) == child
    assert _markers(store) == []


def test_source_mutation_after_classification_cannot_reopen(tmp_path: Path) -> None:
    store, artifacts, run, child, _, evidence = _seed(tmp_path)
    decision = _decision(child, artifacts, evidence)
    assert run.workspace_path is not None
    (run.workspace_path / "pkg/probe.py").write_bytes(
        b"def probe(value):\n    return False\n"
    )

    with pytest.raises(ValueError, match="SURFACE_HOLD_REPLAY_PROOF_INVALID"):
        store.prepare_surface_hold_replay(child, decision, artifacts)

    assert store.require(child.identity, child.stage) == child
    assert _markers(store) == []


def test_changed_saved_child_cannot_reopen_from_stale_decision(tmp_path: Path) -> None:
    store, artifacts, _, child, _, evidence = _seed(tmp_path)
    decision = _decision(child, artifacts, evidence)
    store.save_checkpoint(child.model_copy(update={"attempt_number": 2}))

    with pytest.raises(ValueError, match="SURFACE_HOLD_REPLAY_STALE"):
        store.prepare_surface_hold_replay(child, decision, artifacts)

    assert _markers(store) == []


def test_proven_replay_invalidates_prior_terminal_without_generic_retry(
    tmp_path: Path,
) -> None:
    store, artifacts, run, child, _, evidence = _seed(tmp_path)
    terminal = CandidateTerminal(
        status="COMPLETE",
        bundle_hash="bundle",
        scope_fingerprint="scope",
        decision_counts={},
        deep_counts={},
        hypothesis_count=1,
    )
    store.save_analysis_run(run.model_copy(update={"candidate_terminal": terminal}))
    decision = _decision(child, artifacts, evidence)

    pending = store.prepare_surface_hold_replay(child, decision, artifacts)

    assert pending is not None
    assert pending.status is StageStatus.PENDING
    assert store.require_analysis_run(run.analysis_id).candidate_terminal is None
    assert len(_markers(store)) == 1


def test_competing_store_instances_admit_one_replay(tmp_path: Path) -> None:
    store, artifacts, _, child, _, evidence = _seed(tmp_path)
    decision = _decision(child, artifacts, evidence)
    second = SimpleCheckpointStore(store.database_path)

    def attempt(current: SimpleCheckpointStore) -> str:
        try:
            result = current.prepare_surface_hold_replay(child, decision, artifacts)
            return "prepared" if result is not None else "kept"
        except ValueError:
            return "stale"

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(attempt, (store, second)))

    assert sorted(outcomes) == ["prepared", "stale"]
    assert len(_markers(store)) == 1
