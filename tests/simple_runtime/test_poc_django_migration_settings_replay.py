"""A pinned, one-shot replay for a generated Django migration-graph setup error."""

from __future__ import annotations

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.django_migration_graph_omission import (
    django_migration_settings_replay_forbidden,
)
from sastsimi.simple_runtime.models import (
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageStatus,
)
from sastsimi.simple_runtime.poc import PoCCandidateRejected
from sastsimi.simple_runtime.recovery import migration_settings_replay_binding
from sastsimi.simple_runtime.stages import (
    _reject_migration_settings_replay_content,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from tests.unit.simple_runtime.test_django_migration_graph_omission import (
    APP,
    CANDIDATE,
    ERROR,
    MIGRATION,
    OUTPUT,
    PROJECT,
    REPAIRED,
)


def _exhausted_migration_attempt(
    tmp_path: Path, *, exit_code: int = 2
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    """Seed an exhausted attempt with a tracked migration and two project settings."""

    from tests.simple_runtime.test_poc_extract_exhaustion_replay import (
        _exhausted_extract,
    )

    workspace = tmp_path / "data" / "workspaces" / "workspace-1"
    pinned = {
        "demodesk/config/settings.py": PROJECT,
        "standalone/config/settings.py": PROJECT,
        "src/helpdesk/settings.py": APP,
        "src/helpdesk/migrations/0028_kbitem_team.py": MIGRATION,
    }
    for path, content in pinned.items():
        target = workspace / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
    subprocess.run(
        ("git", "init", "-q", str(workspace)), check=True, capture_output=True
    )
    subprocess.run(
        ("git", "-C", str(workspace), "add", "."), check=True, capture_output=True
    )
    subprocess.run(
        (
            "git",
            "-C",
            str(workspace),
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@invalid.test",
            "commit",
            "-qm",
            "fixture",
        ),
        check=True,
        capture_output=True,
    )
    commit = subprocess.run(
        ("git", "-C", str(workspace), "rev-parse", "HEAD"),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    store, artifacts, exhausted = _exhausted_extract(
        tmp_path,
        seed_commit_id=commit,
        stderr=ERROR,
        stdout=OUTPUT,
        execution_patch={"exit_code": exit_code},
        candidate_content=CANDIDATE,
    )
    run = store.require_analysis_run(exhausted.identity.analysis_id)
    assert run.static_coverage_ref is not None
    manifest_ref = artifacts.put_json(
        {"kind": "simple_tracked_sources", "paths": sorted(pinned)}
    )
    static_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "analysis_id": exhausted.identity.analysis_id,
            "workspace_id": exhausted.identity.workspace_id,
            "commit_id": exhausted.identity.commit_id,
            "source_manifest_ref": manifest_ref.model_dump(mode="json"),
            "poc_source_manifest_ref": manifest_ref.model_dump(mode="json"),
            "static_coverage_ref": run.static_coverage_ref.model_dump(mode="json"),
        }
    )
    store.save_analysis_run(run.model_copy(update={"static_bundle_ref": static_ref}))
    root_identity = exhausted.identity.model_copy(update={"hypothesis_id": None})
    static = store.require(root_identity, SimpleStage.STATIC_DONE)
    store.save_checkpoint(
        static.model_copy(update={"output_refs": (*static.output_refs, static_ref)})
    )
    return store, artifacts, exhausted


def test_migration_graph_omission_replays_only_exhausted_poc(tmp_path: Path) -> None:
    store, artifacts, exhausted = _exhausted_migration_attempt(tmp_path)
    prior_static = store.require(
        exhausted.identity.model_copy(update={"hypothesis_id": None}),
        SimpleStage.STATIC_DONE,
    )
    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        exhausted, artifacts
    )
    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 3
    assert store.get(exhausted.identity, SimpleStage.POC_EXECUTION_DONE) is None
    assert store.require(prior_static.identity, SimpleStage.STATIC_DONE) == prior_static
    with pytest.raises(ValueError, match="POC_DJANGO_MIGRATION_SETTINGS_EXHAUSTION_"):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            exhausted, artifacts
        )
    running = store.mark_running(
        exhausted.identity,
        pending.stage,
        pending.input_refs,
        attempt_id="new-attempt",
    )
    binding = migration_settings_replay_binding(running, artifacts)
    assert binding is not None
    assert binding[0] == "HELPDESK_TEAMS_MODE_ENABLED"
    assert django_migration_settings_replay_forbidden(REPAIRED, binding[0]) is False
    assert django_migration_settings_replay_forbidden(CANDIDATE, binding[0]) is True
    _reject_migration_settings_replay_content(running, artifacts, REPAIRED)
    with pytest.raises(
        PoCCandidateRejected,
        match="POC_DJANGO_MIGRATION_SETTINGS_REPLAY_UNSUPPORTED",
    ):
        _reject_migration_settings_replay_content(running, artifacts, CANDIDATE)


@pytest.mark.parametrize("change", ["untracked_settings", "changed_tracked_settings"])
def test_replay_rejects_settings_outside_pinned_source(
    tmp_path: Path, change: str
) -> None:
    store, artifacts, exhausted = _exhausted_migration_attempt(tmp_path)
    workspace = store.require_analysis_run(
        exhausted.identity.analysis_id
    ).workspace_path
    assert workspace is not None
    if change == "untracked_settings":
        other = workspace / "extra" / "settings.py"
        other.parent.mkdir(parents=True)
        other.write_bytes(PROJECT)
    else:
        (workspace / "demodesk" / "config" / "settings.py").write_bytes(
            PROJECT + b"\nDEBUG = True\n"
        )
    with pytest.raises(
        ValueError, match="POC_DJANGO_MIGRATION_SETTINGS_EXHAUSTION_EVIDENCE_INVALID"
    ):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            exhausted, artifacts
        )
    assert (
        store.require(exhausted.identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    )


def test_replay_rejects_different_exit_code(tmp_path: Path) -> None:
    store, artifacts, exhausted = _exhausted_migration_attempt(tmp_path, exit_code=1)
    with pytest.raises(
        ValueError, match="POC_DJANGO_MIGRATION_SETTINGS_EXHAUSTION_EVIDENCE_INVALID"
    ):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            exhausted, artifacts
        )


def _blocked_migration_candidate_attempt(
    tmp_path: Path, *, diagnostic_reason: str = "OTHER_VALIDATOR_REJECTION"
) -> tuple[
    SimpleCheckpointStore,
    SimpleArtifactRepository,
    StageCheckpoint,
    StoredDataRef,
]:
    """Preserve the first replay, then seed an exhausted validator rejection."""

    store, artifacts, exhausted = _exhausted_migration_attempt(tmp_path)
    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        exhausted, artifacts
    )
    original_rule_ref = pending.recovery_decision_refs[-1]
    running = store.mark_running(
        pending.identity,
        pending.stage,
        pending.input_refs,
        attempt_id="migration-candidate-attempt-4",
    )
    diagnostic_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate_rejection_diagnostic",
            "reason": diagnostic_reason,
            "line_count": 2,
            "branch_count": 0,
            "inconclusive_line_count": 0,
            "exit_two_line_count": 0,
            "exit_zero_line_count": 0,
        }
    )
    failed = store.mark_failure(
        running,
        StageFailure(
            code="POC_DJANGO_MIGRATION_SETTINGS_REPLAY_UNSUPPORTED",
            retryable=True,
            safe_message="Candidate omitted the pinned migration setting",
            evidence_refs=(diagnostic_ref,),
        ),
        StageStatus.BLOCKED,
    )
    stopped = store.mark_recovery_exhausted(failed)
    root_identity = stopped.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    root_running = root.model_copy(
        update={
            "status": StageStatus.RUNNING,
            "attempt_id": "migration-root-attempt-4",
            "error_code": None,
            "retryable": False,
        }
    )
    store.save_checkpoint(root_running)
    store.mark_failure(
        root_running,
        StageFailure(
            code=(
                "CANDIDATE_CHILD_ERROR_BOUND:RECOVERY_EXHAUSTED:"
                f"{stopped.identity.hypothesis_id}:{stopped.attempt_id}"
            ),
            retryable=False,
            safe_message="Child candidate validation exhausted",
        ),
        StageStatus.BLOCKED,
    )
    return store, artifacts, stopped, original_rule_ref


def test_migration_candidate_replay_is_one_shot_and_retains_source_rule(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, original_rule_ref = _blocked_migration_candidate_attempt(
        tmp_path
    )
    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        stopped, artifacts
    )
    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 4
    assert original_rule_ref in pending.input_refs
    assert original_rule_ref in pending.recovery_decision_refs
    assert store.get(stopped.identity, SimpleStage.POC_EXECUTION_DONE) is None
    marker_ref = pending.recovery_decision_refs[-1]
    marker = json.loads(artifacts.read(marker_ref))
    assert marker["kind"] == "simple_poc_django_migration_settings_candidate_replay"
    assert marker["old_attempt_id"] == stopped.attempt_id
    assert marker["old_attempt_number"] == 4
    assert marker["original_migration_rule_ref"] == original_rule_ref.model_dump(
        mode="json"
    )
    assert marker["diagnostic_ref"] == stopped.output_refs[0].model_dump(mode="json")
    with pytest.raises(ValueError, match="POC_DJANGO_MIGRATION_SETTINGS_EXHAUSTION_"):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            stopped, artifacts
        )
    running = store.mark_running(
        pending.identity,
        pending.stage,
        pending.input_refs,
        attempt_id="migration-candidate-attempt-5",
    )
    assert running.attempt_number == 5


def test_migration_candidate_replay_rejects_stale_or_altered_lineage(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, _ = _blocked_migration_candidate_attempt(tmp_path)
    with pytest.raises(ValueError, match="POC_DJANGO_MIGRATION_SETTINGS_EXHAUSTION_"):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            stopped.model_copy(update={"attempt_id": "other-attempt"}), artifacts
        )
    with pytest.raises(ValueError, match="POC_DJANGO_MIGRATION_SETTINGS_EXHAUSTION_"):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            stopped.model_copy(update={"error_code": "OTHER_ERROR"}), artifacts
        )
    before = store.require(stopped.identity, stopped.stage)
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            stopped, artifacts, fail_before_commit=True
        )
    assert store.require(stopped.identity, stopped.stage) == before


def test_migration_candidate_replay_rejects_changed_pinned_checkout(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, _ = _blocked_migration_candidate_attempt(tmp_path)
    workspace = store.require_analysis_run(stopped.identity.analysis_id).workspace_path
    assert workspace is not None
    (workspace / "demodesk" / "config" / "settings.py").write_bytes(
        PROJECT + b"\nDEBUG = True\n"
    )
    with pytest.raises(
        ValueError,
        match="POC_DJANGO_MIGRATION_SETTINGS_EXHAUSTION_EVIDENCE_INVALID",
    ):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            stopped, artifacts
        )
    assert store.require(stopped.identity, stopped.stage) == stopped


def test_migration_candidate_replay_rejects_unrelated_diagnostic(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, _ = _blocked_migration_candidate_attempt(
        tmp_path, diagnostic_reason="OTHER_FAILURE"
    )
    with pytest.raises(
        ValueError,
        match="POC_DJANGO_MIGRATION_SETTINGS_EXHAUSTION_EVIDENCE_INVALID",
    ):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            stopped, artifacts
        )


def test_migration_candidate_replay_rejects_misbound_original_event(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, _ = _blocked_migration_candidate_attempt(tmp_path)
    with sqlite3.connect(store.database_path) as connection:
        rows = connection.execute(
            "SELECT rowid, event_json FROM agent_activity_events WHERE analysis_id = ?",
            (stopped.identity.analysis_id,),
        ).fetchall()
        matching = [
            (rowid, json.loads(raw))
            for rowid, raw in rows
            if json.loads(raw).get("error_code") == "POC_EXTRACT_EXHAUSTION_REPLAYED"
        ]
        assert len(matching) == 1
        rowid, event = matching[0]
        event["stage"] = SimpleStage.POC_CANDIDATE_DONE.value
        connection.execute(
            "UPDATE agent_activity_events SET event_json = ? WHERE rowid = ?",
            (json.dumps(event), rowid),
        )
    with pytest.raises(
        ValueError, match="POC_DJANGO_MIGRATION_SETTINGS_EXHAUSTION_EVENT_INVALID"
    ):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            stopped, artifacts
        )
