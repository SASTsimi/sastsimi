"""Integrity checks for the one-shot late Django migration fixture replay."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import StageCheckpoint, input_reference_hash
from sastsimi.simple_runtime.recovery import late_fixture_replay_binding
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from tests.simple_runtime.test_poc_django_migration_fixture_replay import (
    _attempt_six_fixture_rejection,
)


def _late_running(
    tmp_path: Path,
) -> tuple[
    SimpleCheckpointStore,
    SimpleArtifactRepository,
    StageCheckpoint,
    StageCheckpoint,
]:
    store, artifacts, stopped = _attempt_six_fixture_rejection(tmp_path)
    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        stopped, artifacts
    )
    running = store.mark_running(
        pending.identity,
        pending.stage,
        pending.input_refs,
        attempt_id="late-integrity-attempt-7",
    )
    return store, artifacts, stopped, running


def test_missing_late_marker_fails_closed_but_unrelated_attempt_seven_does_not(
    tmp_path: Path,
) -> None:
    _, artifacts, _, running = _late_running(tmp_path)
    missing_marker = running.model_copy(update={"recovery_decision_refs": ()})
    with pytest.raises(ValueError, match="LATE_REPLAY_UNBOUND"):
        late_fixture_replay_binding(missing_marker, artifacts)

    unrelated = running.model_copy(
        update={
            "identity": running.identity.model_copy(
                update={"hypothesis_id": "unrelated-attempt-seven"}
            ),
            "input_refs": (),
            "input_hash": input_reference_hash(()),
            "recovery_decision_refs": (),
        }
    )
    unrelated_artifacts = SimpleArtifactRepository(
        artifacts.data_dir, unrelated.identity, create_dirs=False
    )
    assert late_fixture_replay_binding(unrelated, unrelated_artifacts) is None

    forged_input_only = unrelated.model_copy(
        update={
            "input_refs": running.input_refs,
            "input_hash": running.input_hash,
        }
    )
    with pytest.raises(ValueError, match="LATE_REPLAY_UNBOUND"):
        late_fixture_replay_binding(forged_input_only, unrelated_artifacts)


def test_self_consistent_forged_late_marker_is_not_durable_decision(
    tmp_path: Path,
) -> None:
    _, artifacts, _, running = _late_running(tmp_path)
    marker = json.loads(artifacts.read(running.recovery_decision_refs[-1]))
    marker["guidance"] = "forged guidance"
    forged_ref = artifacts.put_json(marker)
    forged_inputs = (*running.input_refs[:-1], forged_ref)
    forged = running.model_copy(
        update={
            "input_refs": forged_inputs,
            "input_hash": input_reference_hash(forged_inputs),
            "recovery_decision_refs": (
                *running.recovery_decision_refs[:-1],
                forged_ref,
            ),
        }
    )
    with pytest.raises(ValueError, match="LATE_REPLAY_UNBOUND"):
        late_fixture_replay_binding(forged, artifacts)


def test_self_consistent_forged_parent_and_source_projection_are_unbound(
    tmp_path: Path,
) -> None:
    _, artifacts, _, running = _late_running(tmp_path)
    marker = json.loads(artifacts.read(running.recovery_decision_refs[-1]))
    parent_ref = StoredDataRef.model_validate(marker["parent_fixture_decision_ref"])
    parent = json.loads(artifacts.read(parent_ref))
    projection = parent["fixture_source_projection"]
    assert isinstance(projection, dict)
    modules = projection["verified_project_modules"]
    assert isinstance(modules, list)
    modules.append("forged.config.settings")
    forged_parent_ref = artifacts.put_json(parent)

    old_ref = StoredDataRef.model_validate(marker["old_checkpoint_ref"])
    old = StageCheckpoint.model_validate_json(artifacts.read(old_ref))
    old_inputs = tuple(
        forged_parent_ref if ref == parent_ref else ref for ref in old.input_refs
    )
    assert old_inputs != old.input_refs
    forged_old = old.model_copy(
        update={
            "input_refs": old_inputs,
            "input_hash": input_reference_hash(old_inputs),
            "recovery_decision_refs": (
                *old.recovery_decision_refs[:-1],
                forged_parent_ref,
            ),
        }
    )
    forged_old_ref = artifacts.put_json(forged_old.model_dump(mode="json"))
    marker["parent_fixture_decision_ref"] = forged_parent_ref.model_dump(mode="json")
    marker["old_checkpoint_ref"] = forged_old_ref.model_dump(mode="json")
    marker["old_checkpoint_hash"] = hashlib.sha256(
        canonical_bytes(forged_old.model_dump(mode="json"))
    ).hexdigest()
    marker["source_projection_hash"] = hashlib.sha256(
        canonical_bytes(projection)
    ).hexdigest()
    forged_marker_ref = artifacts.put_json(marker)
    forged_inputs = tuple(
        dict.fromkeys(
            (
                *forged_old.input_refs,
                *forged_old.output_refs,
                forged_old_ref,
                forged_marker_ref,
            )
        )
    )
    forged = running.model_copy(
        update={
            "input_refs": forged_inputs,
            "input_hash": input_reference_hash(forged_inputs),
            "recovery_decision_refs": (
                *forged_old.recovery_decision_refs,
                forged_marker_ref,
            ),
        }
    )
    with pytest.raises(ValueError, match="LATE_REPLAY_UNBOUND"):
        late_fixture_replay_binding(forged, artifacts)


def test_late_reader_requires_pinned_source_before_model_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, artifacts, _, running = _late_running(tmp_path)
    marker = json.loads(artifacts.read(running.recovery_decision_refs[-1]))
    parent_ref = StoredDataRef.model_validate(marker["parent_fixture_decision_ref"])
    parent = json.loads(artifacts.read(parent_ref))
    source_ref = StoredDataRef.model_validate(parent["settings_source_refs"][0])
    original_read = artifacts.read_bounded

    def missing_source(ref: StoredDataRef, max_bytes: int) -> bytes:
        if ref == source_ref:
            raise OSError("missing pinned source CAS object")
        return original_read(ref, max_bytes)

    monkeypatch.setattr(artifacts, "read_bounded", missing_source)
    with pytest.raises(ValueError, match="LATE_REPLAY_UNBOUND"):
        late_fixture_replay_binding(running, artifacts)


def test_late_preflight_requires_original_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, artifacts, stopped = _attempt_six_fixture_rejection(tmp_path)
    parent = json.loads(artifacts.read(stopped.recovery_decision_refs[-1]))
    execution_ref = StoredDataRef.model_validate(
        parent["settings_execution_checkpoint_ref"]
    )
    execution = StageCheckpoint.model_validate_json(artifacts.read(execution_ref))
    cleanup_ref = execution.output_refs[3]
    original_read = artifacts.read_bounded

    def missing_cleanup(ref: StoredDataRef, max_bytes: int) -> bytes:
        if ref == cleanup_ref:
            raise OSError("missing original cleanup CAS object")
        return original_read(ref, max_bytes)

    monkeypatch.setattr(artifacts, "read_bounded", missing_cleanup)
    with pytest.raises(ValueError, match="LATE_REPLAY_EVIDENCE_INVALID"):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            stopped, artifacts
        )
    assert store.require(stopped.identity, stopped.stage) == stopped


def test_late_preflight_rejects_unbound_original_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, artifacts, stopped = _attempt_six_fixture_rejection(tmp_path)
    parent = json.loads(artifacts.read(stopped.recovery_decision_refs[-1]))
    execution_ref = StoredDataRef.model_validate(
        parent["settings_execution_checkpoint_ref"]
    )
    execution = StageCheckpoint.model_validate_json(artifacts.read(execution_ref))
    cleanup_ref = execution.output_refs[3]
    original_read = artifacts.read_bounded

    def forged_cleanup(ref: StoredDataRef, max_bytes: int) -> bytes:
        if ref == cleanup_ref:
            return canonical_bytes(
                {
                    "kind": "simple_container_cleanup",
                    "attempt_id": execution.attempt_id,
                    "container_id": "forged-container",
                    "status": "REMOVED",
                }
            )
        return original_read(ref, max_bytes)

    monkeypatch.setattr(artifacts, "read_bounded", forged_cleanup)
    with pytest.raises(ValueError, match="LATE_REPLAY_EVIDENCE_INVALID"):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            stopped, artifacts
        )
    assert store.require(stopped.identity, stopped.stage) == stopped
