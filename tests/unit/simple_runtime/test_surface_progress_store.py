"""Durable, atomic progress for individual surface context parts."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _identity(analysis_id: str = "analysis-1") -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id=analysis_id,
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )


def _pending(
    identity: CheckpointIdentity,
    hypothesis_id: str,
    proposal_ref: StoredDataRef,
    context_ref: StoredDataRef,
) -> StageCheckpoint:
    refs = (proposal_ref, context_ref)
    return StageCheckpoint(
        identity=identity.model_copy(update={"hypothesis_id": hypothesis_id}),
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.PENDING,
        input_refs=refs,
        input_hash=input_reference_hash(refs),
    )


def test_surface_part_commit_survives_reopen_and_replays_after_child_progress(
    tmp_path: Path,
) -> None:
    identity = _identity()
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    context_ref = artifacts.put_json({"kind": "surface-context", "part": 0})
    result_ref = artifacts.put_json({"kind": "surface-result", "part": 0})
    proposals = tuple(
        artifacts.put_json({"kind": "proposal", "number": number})
        for number in range(2)
    )
    registrations = tuple(
        (
            f"hypothesis-{number}",
            ref,
            _pending(identity, f"hypothesis-{number}", ref, context_ref),
        )
        for number, ref in enumerate(proposals)
    )

    assert store.commit_surface_exploration(
        identity,
        "scope-1",
        "surface-1",
        "surface-1:part-0",
        static_bundle_hash="b" * 64,
        index_hash="c" * 64,
        context_hash=context_ref.content_hash,
        source_sha256="d" * 64,
        status="HYPOTHESES",
        result_ref=result_ref,
        registrations=registrations,
    )
    reopened = SimpleCheckpointStore(store.database_path)
    progress = reopened.list_surface_exploration_progress(identity, "scope-1")
    assert tuple(progress) == (("surface-1", "surface-1:part-0"),)
    saved = progress[("surface-1", "surface-1:part-0")]
    assert saved.surface_id == "surface-1"
    assert saved.context_id == "surface-1:part-0"
    assert saved.static_bundle_hash == "b" * 64
    assert saved.index_hash == "c" * 64
    assert saved.context_hash == context_ref.content_hash
    assert saved.source_sha256 == "d" * 64
    assert saved.status == "HYPOTHESES"
    assert saved.result_ref == result_ref
    assert saved.hypothesis_ids == ("hypothesis-0", "hypothesis-1")
    for hypothesis_id, _, pending in registrations:
        assert reopened.has_hypothesis(identity, hypothesis_id)
        assert reopened.get(pending.identity, SimpleStage.PRO_CON_DONE) == pending

    first = registrations[0][2]
    advanced = first.model_copy(update={"status": StageStatus.SUCCEEDED})
    reopened.save_checkpoint(advanced)
    regenerated = tuple(
        (
            hypothesis_id,
            proposal_ref,
            pending.model_copy(
                update={"updated_at": pending.updated_at + timedelta(seconds=1)}
            ),
        )
        for hypothesis_id, proposal_ref, pending in registrations
    )
    assert not reopened.commit_surface_exploration(
        identity,
        "scope-1",
        "surface-1",
        "surface-1:part-0",
        static_bundle_hash="b" * 64,
        index_hash="c" * 64,
        context_hash=context_ref.content_hash,
        source_sha256="d" * 64,
        status="HYPOTHESES",
        result_ref=result_ref,
        registrations=regenerated,
    )
    assert reopened.get(first.identity, SimpleStage.PRO_CON_DONE) == advanced


def test_second_look_version_is_durable_and_conflict_checked(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    result_ref = artifacts.put_json({"kind": "simple_surface_hypothesis_result_v2"})
    options = dict(
        static_bundle_hash="b" * 64,
        index_hash="c" * 64,
        context_hash="d" * 64,
        source_sha256="e" * 64,
        status="NO_HYPOTHESIS",
        result_ref=result_ref,
        registrations=(),
        proposal_version=2,
    )

    assert store.commit_surface_exploration(
        identity, "scope-1", "surface-1", "context-v2", **options
    )
    reopened = SimpleCheckpointStore(store.database_path)
    record = reopened.list_surface_exploration_progress(identity, "scope-1")[
        ("surface-1", "context-v2")
    ]
    assert record.proposal_version == 2
    assert not reopened.commit_surface_exploration(
        identity, "scope-1", "surface-1", "context-v2", **options
    )
    with pytest.raises(ValueError, match="SURFACE_EXPLORATION_CONFLICT"):
        reopened.commit_surface_exploration(
            identity,
            "scope-1",
            "surface-1",
            "context-v2",
            **(options | {"proposal_version": 1}),
        )


def test_legacy_surface_progress_table_migrates_without_losing_rows(
    tmp_path: Path,
) -> None:
    identity = _identity()
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    result_ref = artifacts.put_json({"kind": "old-result"})
    store.commit_surface_exploration(
        identity,
        "scope-1",
        "surface-1",
        "context-v1",
        static_bundle_hash="b" * 64,
        index_hash="c" * 64,
        context_hash="d" * 64,
        source_sha256=None,
        status="NO_HYPOTHESIS",
        result_ref=result_ref,
        registrations=(),
    )
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "ALTER TABLE simple_surface_exploration_progress DROP COLUMN proposal_version"
        )

    reopened = SimpleCheckpointStore(store.database_path)
    saved = reopened.list_surface_exploration_progress(identity, "scope-1")

    assert saved[("surface-1", "context-v1")].proposal_version == 1
    assert saved[("surface-1", "context-v1")].result_ref == result_ref


def test_surface_progress_rejects_corrupt_registration_snapshot(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    result_ref = artifacts.put_json({"kind": "result"})
    store.commit_surface_exploration(
        identity,
        "scope-1",
        "surface-1",
        "context-1",
        static_bundle_hash="b" * 64,
        index_hash="c" * 64,
        context_hash="d" * 64,
        source_sha256=None,
        status="NO_HYPOTHESIS",
        result_ref=result_ref,
        registrations=(),
    )
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "UPDATE simple_surface_exploration_progress "
            "SET registrations_json = ? WHERE surface_id = ?",
            ('[["hypothesis-1"]]', "surface-1"),
        )
    with pytest.raises(ValueError, match="SURFACE_EXPLORATION_REGISTRATIONS_CORRUPT"):
        store.list_surface_exploration_progress(identity, "scope-1")


def test_surface_part_conflict_rejects_changed_binding_or_registration(
    tmp_path: Path,
) -> None:
    identity = _identity()
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    context_ref = artifacts.put_json({"kind": "context"})
    result_ref = artifacts.put_json({"kind": "result"})
    different_result_ref = artifacts.put_json({"kind": "different-result"})
    proposal_ref = artifacts.put_json({"kind": "proposal"})
    other_proposal_ref = artifacts.put_json({"kind": "other-proposal"})
    registration = (
        "hypothesis-1",
        proposal_ref,
        _pending(identity, "hypothesis-1", proposal_ref, context_ref),
    )

    def commit(
        *,
        static_bundle_hash: str = "b" * 64,
        index_hash: str = "c" * 64,
        context_hash: str = context_ref.content_hash,
        source_sha256: str | None = "d" * 64,
        status: str = "HYPOTHESES",
        result_ref: StoredDataRef = result_ref,
        registrations: tuple[tuple[str, StoredDataRef, StageCheckpoint], ...] = (
            registration,
        ),
    ) -> bool:
        return store.commit_surface_exploration(
            identity,
            "scope-1",
            "surface-1",
            "context-1",
            static_bundle_hash=static_bundle_hash,
            index_hash=index_hash,
            context_hash=context_hash,
            source_sha256=source_sha256,
            status=status,
            result_ref=result_ref,
            registrations=registrations,
        )

    assert commit()

    changes: tuple[Callable[[], bool], ...] = (
        lambda: commit(static_bundle_hash="e" * 64),
        lambda: commit(index_hash="e" * 64),
        lambda: commit(context_hash="e" * 64),
        lambda: commit(source_sha256=None),
        lambda: commit(status="NO_HYPOTHESIS", registrations=()),
        lambda: commit(result_ref=different_result_ref),
        lambda: commit(
            registrations=(
                (
                    "hypothesis-2",
                    other_proposal_ref,
                    _pending(identity, "hypothesis-2", other_proposal_ref, context_ref),
                ),
            )
        ),
    )
    for commit_changed in changes:
        with pytest.raises(ValueError, match="SURFACE_EXPLORATION_CONFLICT"):
            commit_changed()
    assert not store.has_hypothesis(identity, "hypothesis-2")
    assert len(store.list_surface_exploration_progress(identity, "scope-1")) == 1


def test_surface_part_transaction_rolls_back_on_invalid_second_registration(
    tmp_path: Path,
) -> None:
    identity = _identity()
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    context_ref = artifacts.put_json({"kind": "context"})
    result_ref = artifacts.put_json({"kind": "result"})
    good_ref = artifacts.put_json({"kind": "good-proposal"})
    bad_ref = artifacts.put_json({"kind": "bad-proposal"})
    with pytest.raises(ValueError, match="CANDIDATE_HYPOTHESIS_CHECKPOINT_INVALID"):
        store.commit_surface_exploration(
            identity,
            "scope-1",
            "surface-1",
            "context-1",
            static_bundle_hash="b" * 64,
            index_hash="c" * 64,
            context_hash=context_ref.content_hash,
            source_sha256=None,
            status="HYPOTHESES",
            result_ref=result_ref,
            registrations=(
                (
                    "hypothesis-good",
                    good_ref,
                    _pending(identity, "hypothesis-good", good_ref, context_ref),
                ),
                (
                    "hypothesis-bad",
                    bad_ref,
                    _pending(identity, "wrong-child", bad_ref, context_ref),
                ),
            ),
        )
    assert store.list_surface_exploration_progress(identity, "scope-1") == {}
    assert not store.has_hypothesis(identity, "hypothesis-good")
    assert not store.has_hypothesis(identity, "hypothesis-bad")


@pytest.mark.parametrize(
    "status", ("NO_HYPOTHESIS", "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS")
)
def test_terminal_surface_part_progress_is_scoped_and_durable(
    tmp_path: Path, status: str
) -> None:
    identity = _identity()
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    result_ref = artifacts.put_json({"status": status})
    assert store.commit_surface_exploration(
        identity,
        "scope-1",
        "surface-1",
        "context-1",
        static_bundle_hash="b" * 64,
        index_hash="c" * 64,
        context_hash="d" * 64,
        source_sha256=None,
        status=status,
        result_ref=result_ref,
        registrations=(),
    )
    reopened = SimpleCheckpointStore(store.database_path)
    assert reopened.commit_surface_exploration(
        identity,
        "scope-1",
        "surface-1",
        "context-2",
        static_bundle_hash="b" * 64,
        index_hash="c" * 64,
        context_hash="e" * 64,
        source_sha256=None,
        status=status,
        result_ref=result_ref,
        registrations=(),
    )
    progress = reopened.list_surface_exploration_progress(identity, "scope-1")
    assert set(progress) == {
        ("surface-1", "context-1"),
        ("surface-1", "context-2"),
    }
    assert progress[("surface-1", "context-1")].status == status
    assert progress[("surface-1", "context-1")].hypothesis_ids == ()
    assert reopened.list_surface_exploration_progress(identity, "other-scope") == {}
    assert (
        reopened.list_surface_exploration_progress(
            _identity("other-analysis"), "scope-1"
        )
        == {}
    )
    assert not reopened.commit_surface_exploration(
        identity,
        "scope-1",
        "surface-1",
        "context-1",
        static_bundle_hash="b" * 64,
        index_hash="c" * 64,
        context_hash="d" * 64,
        source_sha256=None,
        status=status,
        result_ref=result_ref,
        registrations=(),
    )


def test_existing_v1_survey_row_is_preserved_when_surface_table_is_added(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "CREATE TABLE simple_hypothesis_survey_progress ("
            "analysis_id TEXT NOT NULL, bundle_hash TEXT NOT NULL, "
            "item_key TEXT NOT NULL, ref_json TEXT NOT NULL, "
            "PRIMARY KEY (analysis_id, bundle_hash, item_key))"
        )
        connection.execute(
            "INSERT INTO simple_hypothesis_survey_progress VALUES (?, ?, ?, ?)",
            ("analysis-1", "bundle-1", "legacy-page", '{"legacy":true}'),
        )
    SimpleCheckpointStore(database_path)
    with sqlite3.connect(database_path) as connection:
        assert connection.execute(
            "SELECT analysis_id, bundle_hash, item_key, ref_json "
            "FROM simple_hypothesis_survey_progress"
        ).fetchall() == [("analysis-1", "bundle-1", "legacy-page", '{"legacy":true}')]
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name='simple_surface_exploration_progress'"
            ).fetchone()
            is not None
        )
