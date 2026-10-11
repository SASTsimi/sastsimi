"""One post-anchor PoC replan for a source-bound migration fixture gap."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import cast

import pytest

from sastsimi.observability.agent_activity import ActivityKind
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    MAX_RECOVERY_ATTEMPTS,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageResult,
    StageStatus,
)
from sastsimi.simple_runtime.poc import PoCCandidateRejected
from sastsimi.simple_runtime.provider import SimpleLLMClient
from sastsimi.simple_runtime.recovery import (
    late_fixture_replay_binding,
    migration_settings_replay_binding,
)
from sastsimi.simple_runtime.stages import (
    PoCCandidateStage,
    _reject_migration_settings_replay_content,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_poc_closed_runtime_exhaustion_replay import (
    _CLOSED_ERROR,
)
from tests.simple_runtime.test_poc_django_migration_settings_replay import (
    _exhausted_migration_attempt,
)
from tests.unit.simple_runtime.test_django_migration_fixture_source_gap import (
    CANDIDATE,
    ERROR,
    NATIVE_REPLAN,
)


def _attempt_five_migration_failure(
    tmp_path: Path, *, last_stderr: bytes | None = None, exit_code: int = 2
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    content = CANDIDATE.replace(b"FORUM_", b"HELPDESK_").replace(b"forum", b"helpdesk")
    store, artifacts, attempt_three = _exhausted_migration_attempt(
        tmp_path, stderr=_CLOSED_ERROR, candidate_content=content
    )
    first = store.prepare_poc_closed_runtime_exhaustion_replay(attempt_three, artifacts)
    running_four = store.mark_running(
        first.identity,
        SimpleStage.POC_CANDIDATE_DONE,
        first.input_refs,
        attempt_id="migration-anchor-attempt-4",
    )
    failed_four = store.mark_failure(
        running_four,
        StageFailure(
            code="HYPOTHESIS_ANCHOR_INVALID",
            retryable=False,
            safe_message="Pinned evidence could not be validated",
        ),
        StageStatus.FAILED,
    )
    root_id = first.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_id, SimpleStage.HYPOTHESIS_DONE)
    running_root = store.mark_running(
        root_id,
        SimpleStage.HYPOTHESIS_DONE,
        root.input_refs,
        attempt_id="migration-anchor-root-4",
    )
    store.mark_failure(
        running_root,
        StageFailure(
            code=(
                "CANDIDATE_CHILD_ERROR_BOUND:HYPOTHESIS_ANCHOR_INVALID:"
                f"{first.identity.hypothesis_id}:{failed_four.attempt_id}"
            ),
            retryable=False,
            safe_message="Child PoC candidate could not validate pinned evidence",
        ),
        StageStatus.FAILED,
    )
    second = store.prepare_poc_anchor_failure_replay(failed_four, artifacts)
    running_five = store.mark_running(
        second.identity,
        SimpleStage.POC_CANDIDATE_DONE,
        second.input_refs,
        attempt_id="migration-attempt-5",
    )
    content_ref = artifacts.put_bytes(content, "text/x-shellscript")
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "attempt_id": running_five.attempt_id,
            "content_ref": content_ref.model_dump(mode="json"),
            "content_digest": hashlib.sha256(content).hexdigest(),
        }
    )
    candidate = store.complete(
        running_five, StageResult(output_refs=(candidate_ref, content_ref))
    )
    running_execution = store.mark_running(
        candidate.identity,
        SimpleStage.POC_EXECUTION_DONE,
        (candidate_ref, content_ref),
        attempt_id=running_five.attempt_id or "",
        inherit_from=candidate,
    )
    stdout_ref = artifacts.put_bytes(b"", "text/plain")
    redacted_error = ERROR.replace(b"  at ", b"  in ")
    for line in (b":40", b":71", b":92", b":115", b":127", b":133"):
        redacted_error = redacted_error.replace(line, b"")
    stderr_ref = artifacts.put_bytes(
        redacted_error if last_stderr is None else last_stderr, "text/plain"
    )
    execution_ref = artifacts.put_json(
        {
            "kind": "simple_poc_execution",
            "attempt_id": running_execution.attempt_id,
            "candidate_ref": candidate_ref.model_dump(mode="json"),
            "content_ref": content_ref.model_dump(mode="json"),
            "stdout_ref": stdout_ref.model_dump(mode="json"),
            "stderr_ref": stderr_ref.model_dump(mode="json"),
            "exit_code": exit_code,
            "timed_out": False,
            "container_id": "migration-container-5",
            "image_digest": running_execution.image_digest,
        }
    )
    cleanup_ref = artifacts.put_json(
        {
            "kind": "simple_container_cleanup",
            "attempt_id": running_execution.attempt_id,
            "container_id": "migration-container-5",
            "status": "REMOVED",
        }
    )
    evidence = (execution_ref, stdout_ref, stderr_ref, cleanup_ref)
    blocked = store.mark_failure(
        running_execution,
        StageFailure(
            code="POC_EXECUTION_FAILED",
            retryable=True,
            safe_message="PoC execution failed",
            evidence_refs=evidence,
        ),
        StageStatus.BLOCKED,
    )
    exhausted = store.mark_recovery_exhausted(blocked)
    root = store.require(root_id, SimpleStage.HYPOTHESIS_DONE)
    running_root = store.mark_running(
        root_id,
        SimpleStage.HYPOTHESIS_DONE,
        root.input_refs,
        attempt_id="migration-root-5",
    )
    store.mark_failure(
        running_root,
        StageFailure(
            code=(
                "CANDIDATE_CHILD_ERROR_BOUND:RECOVERY_EXHAUSTED:"
                f"{first.identity.hypothesis_id}:{exhausted.attempt_id}"
            ),
            retryable=False,
            safe_message="Child PoC exhausted automatic recovery",
        ),
        StageStatus.BLOCKED,
    )
    return store, artifacts, exhausted


def _attempt_six_fixture_rejection(
    tmp_path: Path,
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store, artifacts, fifth = _attempt_five_migration_failure(tmp_path)
    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        fifth, artifacts
    )
    running = store.mark_running(
        pending.identity,
        pending.stage,
        pending.input_refs,
        attempt_id="fixture-candidate-attempt-6",
    )
    diagnostic_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate_rejection_diagnostic",
            "reason": "OTHER_VALIDATOR_REJECTION",
            "line_count": 29,
            "branch_count": 0,
            "inconclusive_line_count": 0,
            "exit_two_line_count": 0,
            "exit_zero_line_count": 0,
        }
    )
    rejected = store.mark_failure(
        running,
        StageFailure(
            code="POC_DJANGO_MIGRATION_FIXTURE_REPLAY_UNSUPPORTED",
            retryable=True,
            safe_message="PoC candidate is not self-contained",
            evidence_refs=(diagnostic_ref,),
        ),
        StageStatus.BLOCKED,
    )
    exhausted = store.mark_recovery_exhausted(rejected)
    root_id = exhausted.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_id, SimpleStage.HYPOTHESIS_DONE)
    running_root = store.mark_running(
        root_id,
        SimpleStage.HYPOTHESIS_DONE,
        root.input_refs,
        attempt_id="fixture-root-attempt-6",
    )
    store.mark_failure(
        running_root,
        StageFailure(
            code=(
                "CANDIDATE_CHILD_ERROR_BOUND:RECOVERY_EXHAUSTED:"
                f"{exhausted.identity.hypothesis_id}:{exhausted.attempt_id}"
            ),
            retryable=False,
            safe_message="Child PoC exhausted automatic recovery",
        ),
        StageStatus.BLOCKED,
    )
    return store, artifacts, exhausted


def test_attempt_six_fixture_rejection_queues_only_one_late_candidate(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_six_fixture_rejection(tmp_path)
    root_id = exhausted.identity.model_copy(update={"hypothesis_id": None})
    static_before = store.require(root_id, SimpleStage.STATIC_DONE)
    old_data = tuple(artifacts.read(ref) for ref in exhausted.output_refs)
    old_refs = exhausted.recovery_decision_refs

    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        exhausted, artifacts
    )

    assert pending.status is StageStatus.PENDING
    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.attempt_number == MAX_RECOVERY_ATTEMPTS + 3
    assert pending.recovery_decision_refs[:-1] == old_refs
    assert store.require(root_id, SimpleStage.STATIC_DONE) == static_before
    assert tuple(artifacts.read(ref) for ref in exhausted.output_refs) == old_data
    marker = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert marker["historical_rejection_reason"] == "UNKNOWN"
    assert marker["parent_fixture_decision_ref"] == old_refs[-1].model_dump(mode="json")
    with pytest.raises(ValueError):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            exhausted, artifacts
        )

    running = store.mark_running(
        pending.identity,
        pending.stage,
        pending.input_refs,
        attempt_id="fixture-candidate-attempt-7",
    )
    assert running.attempt_number == MAX_RECOVERY_ATTEMPTS + 4
    binding = late_fixture_replay_binding(running, artifacts)
    assert binding is not None
    assert binding["old"] == exhausted


def test_late_fixture_replay_precommit_crash_does_not_consume_one_shot(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_six_fixture_rejection(tmp_path)
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            exhausted, artifacts, fail_before_commit=True
        )
    assert store.require(exhausted.identity, exhausted.stage) == exhausted
    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        exhausted, artifacts
    )
    assert pending.status is StageStatus.PENDING


def test_late_fixture_replay_refuses_changed_pinned_source(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_six_fixture_rejection(tmp_path)
    source = tmp_path / "data/workspaces/workspace-1/demodesk/config/settings.py"
    source.write_bytes(source.read_bytes() + b"\nDEBUG = True\n")
    with pytest.raises(ValueError, match="LATE_REPLAY_EVIDENCE_INVALID"):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            exhausted, artifacts
        )
    assert store.require(exhausted.identity, exhausted.stage) == exhausted


def test_late_fixture_replay_refuses_unresolved_codex_call(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_six_fixture_rejection(tmp_path)
    assert store.begin_codex_call("active-fixture-call", exhausted.identity.analysis_id)
    with pytest.raises(ValueError, match="LATE_REPLAY_CODEX_UNRESOLVED"):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            exhausted, artifacts
        )
    assert store.require(exhausted.identity, exhausted.stage) == exhausted


def test_late_fixture_replay_refuses_unexited_child(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_six_fixture_rejection(tmp_path)
    with sqlite3.connect(store.database_path) as connection:
        connection.execute(
            "INSERT INTO simple_codex_child_spawns "
            "(call_id, analysis_id, phase, status) VALUES (?, ?, 'EXEC', 'SPAWNING')",
            ("unexited-fixture-child", exhausted.identity.analysis_id),
        )
    with pytest.raises(ValueError, match="LATE_REPLAY_CODEX_UNRESOLVED"):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            exhausted, artifacts
        )
    assert store.require(exhausted.identity, exhausted.stage) == exhausted


def test_source_bound_attempt_five_replays_once_without_claiming_missing_node(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_five_migration_failure(tmp_path)
    static = store.require(
        exhausted.identity.model_copy(update={"hypothesis_id": None}),
        SimpleStage.STATIC_DONE,
    )
    previous_evidence = tuple(artifacts.read(ref) for ref in exhausted.output_refs)
    old_refs = exhausted.recovery_decision_refs

    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        exhausted, artifacts
    )

    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 5
    assert pending.recovery_decision_refs[:-1] == old_refs
    assert store.require(static.identity, static.stage) == static
    assert store.get(exhausted.identity, SimpleStage.POC_EXECUTION_DONE) is None
    assert (
        tuple(artifacts.read(ref) for ref in exhausted.output_refs) == previous_evidence
    )
    rule = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert rule["decision_origin"] == "RULE"
    assert rule["migration_fixture_replay"] is True
    assert rule["original_error"]["code"] == "POC_EXECUTION_FAILED"
    assert "unknown" in rule["decision"]["guidance"].lower()
    assert "migrate" in rule["decision"]["guidance"].lower()
    assert "MIGRATION_MODULES" not in rule["decision"]["guidance"]
    events = AgentActivityStore(store.database_path).list_analysis(
        exhausted.identity.analysis_id, hypothesis_id=exhausted.identity.hypothesis_id
    )
    assert (
        sum(
            event.kind is ActivityKind.DECISION_RECORDED
            and event.error_code == "POC_DJANGO_MIGRATION_FIXTURE_REPLAYED"
            for event in events
        )
        == 1
    )
    with pytest.raises(ValueError):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            exhausted, artifacts
        )

    running = store.mark_running(
        pending.identity,
        pending.stage,
        pending.input_refs,
        attempt_id="migration-replan-attempt-6",
    )
    assert migration_settings_replay_binding(running, artifacts) is None
    original = CANDIDATE.replace(b"FORUM_", b"HELPDESK_").replace(b"forum", b"helpdesk")
    with pytest.raises(
        PoCCandidateRejected, match="POC_DJANGO_MIGRATION_FIXTURE_REPLAY_UNSUPPORTED"
    ):
        _reject_migration_settings_replay_content(running, artifacts, original)
    cosmetic = original.replace(
        b"from django.core.management import call_command",
        b"print('replanned fixture')\nfrom django.core.management import call_command",
    )
    with pytest.raises(
        PoCCandidateRejected, match="POC_DJANGO_MIGRATION_FIXTURE_REPLAY_UNSUPPORTED"
    ):
        _reject_migration_settings_replay_content(running, artifacts, cosmetic)
    repaired = original.replace(
        b"root.rglob('settings.py')", b"root.glob('config/settings.py')"
    )
    with pytest.raises(
        PoCCandidateRejected, match="POC_DJANGO_MIGRATION_FIXTURE_REPLAY_UNSUPPORTED"
    ):
        _reject_migration_settings_replay_content(running, artifacts, repaired)
    native_replan = NATIVE_REPLAN
    _reject_migration_settings_replay_content(running, artifacts, native_replan)
    bypassed = repaired.replace(
        b"fixture_settings.update(project_flags)",
        b"fixture_settings['MIGRATION_MODULES'] = {'helpdesk': None}\n"
        b"fixture_settings.update(project_flags)",
    )
    with pytest.raises(
        PoCCandidateRejected, match="POC_DJANGO_MIGRATION_FIXTURE_REPLAY_UNSUPPORTED"
    ):
        _reject_migration_settings_replay_content(running, artifacts, bypassed)


@pytest.mark.parametrize(
    ("last_stderr", "exit_code"),
    [
        (b"ImportError\n", 2),
        (b"NodeNotFoundError\nmissing node not safely redacted\n", 2),
        (b"", 2),
        (ERROR, 0),
        (ERROR, 1),
    ],
)
def test_unproven_migration_failure_does_not_replay(
    tmp_path: Path, last_stderr: bytes, exit_code: int
) -> None:
    store, artifacts, exhausted = _attempt_five_migration_failure(
        tmp_path, last_stderr=last_stderr, exit_code=exit_code
    )
    with pytest.raises(
        ValueError, match="POC_DJANGO_MIGRATION_FIXTURE_EXHAUSTION_EVIDENCE_INVALID"
    ):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            exhausted, artifacts
        )
    assert store.require(exhausted.identity, exhausted.stage) == exhausted


def test_mutated_pinned_project_source_does_not_replay(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_five_migration_failure(tmp_path)
    project = tmp_path / "data/workspaces/workspace-1/demodesk/config/settings.py"
    project.write_bytes(project.read_bytes() + b"\nDEBUG = True\n")
    with pytest.raises(
        ValueError, match="POC_DJANGO_MIGRATION_FIXTURE_EXHAUSTION_EVIDENCE_INVALID"
    ):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            exhausted, artifacts
        )
    assert store.require(exhausted.identity, exhausted.stage) == exhausted


def test_fail_before_commit_does_not_consume_replay(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_five_migration_failure(tmp_path)
    with pytest.raises(RuntimeError):
        store.prepare_poc_django_migration_settings_exhaustion_replay(
            exhausted, artifacts, fail_before_commit=True
        )
    assert store.require(exhausted.identity, exhausted.stage) == exhausted
    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        exhausted, artifacts
    )
    assert pending.status is StageStatus.PENDING


def test_prompt_requires_bounded_pinned_source_facts_not_raw_streams(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_five_migration_failure(tmp_path)
    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        exhausted, artifacts
    )

    stage = PoCCandidateStage(
        client=cast(SimpleLLMClient, object()), artifacts=artifacts
    )
    repair_refs = stage._current_repair_refs(pending.input_refs)
    assert len(repair_refs) == 2
    diagnostic_ref, excluded = stage._closed_runtime_repair_context(
        pending, *repair_refs
    )
    assert diagnostic_ref is not None
    assert set(excluded) == set(exhausted.output_refs[1:3])
    decision_ref = pending.recovery_decision_refs[-1]
    assert len(artifacts.read(decision_ref)) < 64 * 1024
    prompt_context = artifacts.prompt_context_prioritized(
        (*repair_refs, diagnostic_ref, decision_ref), (), max_bytes=256 * 1024
    )
    assert b"verified_project_modules" in prompt_context
    assert b"demodesk.config.settings" in prompt_context
    assert b"optional_dependency_nodes" in prompt_context
    assert b"NodeNotFoundError" in prompt_context
    assert b"missing_node" in prompt_context
    assert b"  in build_graph" not in prompt_context
    assert b"Traceback (most recent call last)" not in prompt_context
    assert len(prompt_context) <= 256 * 1024
