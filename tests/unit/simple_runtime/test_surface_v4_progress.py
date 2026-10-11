"""Store-level v4 surface progress remains atomic and fail-closed on replay."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.recovery import (
    RecoveryAction,
    RecoveryCategory,
    RecoveryDecision,
    RecoveryResolution,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _identity() -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="analysis-v4",
        workspace_id="workspace-v4",
        commit_id="a" * 40,
        hypothesis_id=None,
    )


def _pending(
    identity: CheckpointIdentity,
    hypothesis_ref: StoredDataRef,
    context_ref: StoredDataRef,
) -> StageCheckpoint:
    refs = (hypothesis_ref, context_ref)
    return StageCheckpoint(
        identity=identity.model_copy(update={"hypothesis_id": "hypothesis-v4"}),
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.PENDING,
        input_refs=refs,
        input_hash=input_reference_hash(refs),
    )


def _commit(
    store: SimpleCheckpointStore,
    identity: CheckpointIdentity,
    result_ref: StoredDataRef,
    context_ref: StoredDataRef,
    registrations: tuple[tuple[str, StoredDataRef, StageCheckpoint], ...],
    *,
    proposal_version: int = 4,
) -> bool:
    return store.commit_surface_exploration(
        identity,
        "scope-v4",
        "surface-v4",
        "surface-v4:part-0",
        static_bundle_hash="b" * 64,
        index_hash="c" * 64,
        context_hash=context_ref.content_hash,
        source_sha256="d" * 64,
        status="HYPOTHESES" if registrations else "NO_HYPOTHESIS",
        result_ref=result_ref,
        registrations=registrations,
        proposal_version=proposal_version,
    )


def test_v4_progress_is_exact_key_atomic_and_durable(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    context_ref = artifacts.put_json({"kind": "simple_surface_context_v4"})
    result_ref = artifacts.put_json({"kind": "simple_surface_hypothesis_result_v4"})
    hypothesis_ref = artifacts.put_json({"kind": "simple_hypothesis_seed"})
    pending = _pending(identity, hypothesis_ref, context_ref)
    registrations = (("hypothesis-v4", hypothesis_ref, pending),)

    assert _commit(store, identity, result_ref, context_ref, registrations)
    reopened = SimpleCheckpointStore(store.database_path)
    saved = reopened.list_surface_exploration_progress(identity, "scope-v4")
    assert saved[("surface-v4", "surface-v4:part-0")].proposal_version == 4
    assert saved[("surface-v4", "surface-v4:part-0")].hypothesis_ids == (
        "hypothesis-v4",
    )
    assert reopened.get(pending.identity, SimpleStage.PRO_CON_DONE) == pending
    assert not _commit(reopened, identity, result_ref, context_ref, registrations)
    assert len(reopened.list_surface_exploration_progress(identity, "scope-v4")) == 1


def test_v4_replay_rejects_unproven_recovery_ref(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    context_ref = artifacts.put_json({"kind": "simple_surface_context_v4"})
    result_ref = artifacts.put_json({"kind": "simple_surface_hypothesis_result_v4"})
    hypothesis_ref = artifacts.put_json({"kind": "simple_hypothesis_seed"})
    recovery_ref = artifacts.put_json({"kind": "recovery_decision"})
    pending = _pending(identity, hypothesis_ref, context_ref)
    registrations = (("hypothesis-v4", hypothesis_ref, pending),)
    assert _commit(store, identity, result_ref, context_ref, registrations)

    evolved_refs = (*pending.input_refs, recovery_ref)
    evolved = pending.model_copy(
        update={
            "status": StageStatus.RUNNING,
            "input_refs": evolved_refs,
            "input_hash": input_reference_hash(evolved_refs),
            "recovery_decision_refs": (recovery_ref,),
        }
    )
    store.save_checkpoint(evolved)
    with pytest.raises(ValueError, match="SURFACE_EXPLORATION_V4_CORRUPT"):
        store.list_surface_exploration_progress(identity, "scope-v4")


def test_v4_replay_accepts_real_prepare_recovery_evidence(
    tmp_path: Path,
) -> None:
    identity = _identity()
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    context_ref = artifacts.put_json({"kind": "simple_surface_context_v4"})
    result_ref = artifacts.put_json({"kind": "simple_surface_hypothesis_result_v4"})
    hypothesis_ref = artifacts.put_json({"kind": "simple_hypothesis_seed"})
    pending = _pending(identity, hypothesis_ref, context_ref)
    registrations = (("hypothesis-v4", hypothesis_ref, pending),)
    assert _commit(store, identity, result_ref, context_ref, registrations)

    running = store.mark_running(
        pending.identity,
        SimpleStage.PRO_CON_DONE,
        pending.input_refs,
        attempt_id="attempt-v4",
    )
    evidence_ref = artifacts.put_json({"kind": "failure-evidence"})
    failed = store.mark_failure(
        running,
        StageFailure(
            code="PRO_CON_INVALID_OUTPUT",
            retryable=True,
            safe_message="invalid output",
            evidence_refs=(evidence_ref,),
        ),
        StageStatus.BLOCKED,
    )
    decision_ref = artifacts.put_json({"kind": "simple_recovery_decision"})
    recovered = store.prepare_recovery(
        failed,
        RecoveryResolution(
            decision=RecoveryDecision(
                category=RecoveryCategory.GENERATED_INPUT,
                action=RecoveryAction.RETRY_STAGE,
                diagnosis="retry structured response",
                guidance="retry once",
            ),
            decision_ref=decision_ref,
        ),
        SimpleStage.PRO_CON_DONE,
    )
    assert recovered.input_refs == (
        hypothesis_ref,
        context_ref,
        evidence_ref,
        decision_ref,
    )
    assert len(store.list_surface_exploration_progress(identity, "scope-v4")) == 1
    assert not _commit(store, identity, result_ref, context_ref, registrations)

    unbound = artifacts.put_json({"kind": "unbound"})
    unbound_refs = (*recovered.input_refs, unbound)
    store.save_checkpoint(
        recovered.model_copy(
            update={
                "input_refs": unbound_refs,
                "input_hash": input_reference_hash(unbound_refs),
            }
        )
    )
    with pytest.raises(ValueError, match="SURFACE_EXPLORATION_V4_CORRUPT"):
        store.list_surface_exploration_progress(identity, "scope-v4")

    foreign_identity = identity.model_copy(update={"workspace_id": "other-workspace"})
    foreign_ref = SimpleArtifactRepository(
        tmp_path / "artifacts", foreign_identity
    ).put_json({"kind": "foreign-recovery"})
    foreign_refs = (*pending.input_refs, foreign_ref)
    store.save_checkpoint(
        recovered.model_copy(
            update={
                "input_refs": foreign_refs,
                "input_hash": input_reference_hash(foreign_refs),
                "recovery_decision_refs": (foreign_ref,),
            }
        )
    )
    with pytest.raises(ValueError, match="SURFACE_EXPLORATION_V4_CORRUPT"):
        store.list_surface_exploration_progress(identity, "scope-v4")


def test_v4_conflict_does_not_register_a_second_child(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    context_ref = artifacts.put_json({"kind": "simple_surface_context_v4"})
    result_ref = artifacts.put_json({"kind": "simple_surface_hypothesis_result_v4"})
    replacement = artifacts.put_json({"kind": "changed-result"})
    hypothesis_ref = artifacts.put_json({"kind": "simple_hypothesis_seed"})
    registrations = (
        (
            "hypothesis-v4",
            hypothesis_ref,
            _pending(identity, hypothesis_ref, context_ref),
        ),
    )
    assert _commit(store, identity, result_ref, context_ref, registrations)
    with pytest.raises(ValueError, match="SURFACE_EXPLORATION_CONFLICT"):
        _commit(store, identity, replacement, context_ref, registrations)
    assert store.hypothesis_count(identity) == 1


@pytest.mark.parametrize("corruption", ("candidate_ref", "child_ref", "version"))
def test_corrupt_v4_registration_or_version_blocks_replay(
    tmp_path: Path, corruption: str
) -> None:
    identity = _identity()
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    context_ref = artifacts.put_json({"kind": "simple_surface_context_v4"})
    result_ref = artifacts.put_json({"kind": "simple_surface_hypothesis_result_v4"})
    hypothesis_ref = artifacts.put_json({"kind": "simple_hypothesis_seed"})
    replacement = artifacts.put_json({"kind": "replacement-seed"})
    pending = _pending(identity, hypothesis_ref, context_ref)
    registrations = (("hypothesis-v4", hypothesis_ref, pending),)
    assert _commit(store, identity, result_ref, context_ref, registrations)

    with sqlite3.connect(store.database_path) as connection:
        if corruption == "candidate_ref":
            connection.execute(
                "UPDATE simple_candidate_hypotheses SET hypothesis_ref_json = ? "
                "WHERE analysis_id = ? AND hypothesis_id = ?",
                (replacement.model_dump_json(), identity.analysis_id, "hypothesis-v4"),
            )
        elif corruption == "child_ref":
            tampered = pending.model_copy(
                update={
                    "input_refs": (replacement, context_ref),
                    "input_hash": input_reference_hash((replacement, context_ref)),
                }
            )
            connection.execute(
                "UPDATE simple_runtime_checkpoints SET checkpoint_json = ? "
                "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
                (
                    tampered.model_dump_json(),
                    identity.analysis_id,
                    "hypothesis-v4",
                    SimpleStage.PRO_CON_DONE.value,
                ),
            )
        else:
            connection.execute(
                "UPDATE simple_surface_exploration_progress SET proposal_version = 5 "
                "WHERE analysis_id = ?",
                (identity.analysis_id,),
            )

    with pytest.raises(ValueError, match="SURFACE_EXPLORATION_"):
        store.list_surface_exploration_progress(identity, "scope-v4")
    with pytest.raises(ValueError, match="SURFACE_EXPLORATION_"):
        _commit(store, identity, result_ref, context_ref, registrations)


def test_v4_transaction_rolls_back_invalid_second_child(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    context_ref = artifacts.put_json({"kind": "simple_surface_context_v4"})
    result_ref = artifacts.put_json({"kind": "simple_surface_hypothesis_result_v4"})
    one = artifacts.put_json({"kind": "simple_hypothesis_seed", "number": 1})
    two = artifacts.put_json({"kind": "simple_hypothesis_seed", "number": 2})
    with pytest.raises(ValueError, match="CANDIDATE_HYPOTHESIS_CHECKPOINT_INVALID"):
        _commit(
            store,
            identity,
            result_ref,
            context_ref,
            (
                ("hypothesis-v4", one, _pending(identity, one, context_ref)),
                ("hypothesis-wrong", two, _pending(identity, two, context_ref)),
            ),
        )
    assert store.list_surface_exploration_progress(identity, "scope-v4") == {}
    assert store.hypothesis_count(identity) == 0
