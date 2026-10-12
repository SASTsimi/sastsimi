"""One post-anchor PoC replan for a source-bound migration fixture gap."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import cast

import pytest

import sastsimi.simple_runtime.stages as stages
from sastsimi.observability.agent_activity import ActivityKind
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    MAX_RECOVERY_ATTEMPTS,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.poc import PoCCandidateRejected
from sastsimi.simple_runtime.provider import SimpleLLMCallResult, SimpleLLMClient
from sastsimi.simple_runtime.recovery import (
    late_fixture_replay_binding,
    migration_settings_replay_binding,
)
from sastsimi.simple_runtime.runner import StageBlocked, StageFailed
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


def test_attempt_seven_keeps_original_fixture_guard_and_closed_feedback(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_six_fixture_rejection(tmp_path)
    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        exhausted, artifacts
    )
    running = store.mark_running(
        pending.identity,
        pending.stage,
        pending.input_refs,
        attempt_id="fixture-guard-attempt-7",
    )
    original = CANDIDATE.replace(b"FORUM_", b"HELPDESK_").replace(b"forum", b"helpdesk")
    with pytest.raises(
        PoCCandidateRejected,
        match="POC_DJANGO_MIGRATION_FIXTURE_REPLAY_UNSUPPORTED",
    ) as caught:
        _reject_migration_settings_replay_content(running, artifacts, original)
    assert caught.value.reason_code == "UNCHANGED_CANDIDATE"
    guidance = stages._fixture_repair_guidance(caught.value.reason_code)
    assert "UNCHANGED_CANDIDATE" in guidance
    assert "django.setup()" in guidance
    assert "call_command('migrate')" in guidance
    assert "HELPDESK_" not in guidance
    for rejected in (
        original.replace(
            b"fixture_settings.update(project_flags)",
            b"fixture_settings['MIGRATION_MODULES'] = {}\n"
            b"fixture_settings.update(project_flags)",
        ),
        NATIVE_REPLAN.replace(b"demodesk.config.settings", b"other.config.settings"),
        NATIVE_REPLAN.replace(b"django.setup()\n", b""),
    ):
        with pytest.raises(PoCCandidateRejected) as blocked:
            _reject_migration_settings_replay_content(running, artifacts, rejected)
        assert blocked.value.reason_code in {
            "INVALID_PYTHON_OR_MIGRATION_BYPASS",
            "SYNTHETIC_SETTINGS_OR_MUTATION",
            "SETUP_MIGRATE_ORDER_INVALID",
        }
    _reject_migration_settings_replay_content(running, artifacts, NATIVE_REPLAN)


@pytest.mark.asyncio
async def test_attempt_seven_bootstrap_repair_uses_bounded_prelude(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _attempt_six_fixture_rejection(tmp_path)
    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        exhausted, artifacts
    )
    running = store.mark_running(
        pending.identity,
        pending.stage,
        pending.input_refs,
        attempt_id="fixture-bootstrap-feedback-attempt-7",
    )
    rejected = NATIVE_REPLAN.replace(
        b"call_command('migrate', run_syncdb=True)",
        b"fixture_probe = 'untrusted_marker_987654'\n"
        b"call_command('migrate', run_syncdb=True)",
    )

    class _RejectedBootstrapClient:
        def __init__(self) -> None:
            self.prompts: list[bytes] = []

        async def call(self, **kwargs: object) -> SimpleLLMCallResult:
            self.prompts.append(cast(bytes, kwargs["prompt"]))
            return SimpleLLMCallResult(
                value={"content": rejected.decode("utf-8")},
                prompt_digest="a" * 64,
                output_digest="b" * 64,
            )

    client = _RejectedBootstrapClient()
    with pytest.raises(StageBlocked) as blocked:
        stage = PoCCandidateStage(
            client=cast(SimpleLLMClient, client), artifacts=artifacts
        )
        await stage(running, {})

    assert (
        blocked.value.failure.code
        == "POC_DJANGO_MIGRATION_FIXTURE_REPLAY_UNSUPPORTED"
    )
    assert len(client.prompts) == 2
    retry_prompt = client.prompts[1]
    assert b"PINNED_PROJECT_BOOTSTRAP_MISSING" in retry_prompt
    assert b"exactly six unconditional top-level statements" in retry_prompt
    assert b"os.environ['DJANGO_SETTINGS_MODULE']" in retry_prompt
    assert b"no other statements before migration" in retry_prompt
    assert b"untrusted_marker_987654" not in retry_prompt
    assert b"untrusted_marker_987654" not in b"".join(
        artifacts.read(ref) for ref in blocked.value.failure.evidence_refs
    )


def test_fixture_repair_feedback_rejects_untrusted_reason_code() -> None:
    assert stages._fixture_repair_guidance("untrusted_marker_987654") == ""


def test_attempt_seven_rejects_forged_parent_marker(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_six_fixture_rejection(tmp_path)
    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        exhausted, artifacts
    )
    running = store.mark_running(
        pending.identity,
        pending.stage,
        pending.input_refs,
        attempt_id="fixture-forged-attempt-7",
    )
    marker = json.loads(artifacts.read(running.recovery_decision_refs[-1]))
    marker["parent_fixture_decision_ref"] = exhausted.output_refs[0].model_dump(
        mode="json"
    )
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
    with pytest.raises(
        PoCCandidateRejected, match="POC_DJANGO_MIGRATION_FIXTURE_REPLAY_UNBOUND"
    ):
        _reject_migration_settings_replay_content(forged, artifacts, NATIVE_REPLAN)


def test_attempt_seven_prompt_omits_saved_candidate_body(tmp_path: Path) -> None:
    store, artifacts, exhausted = _attempt_six_fixture_rejection(tmp_path)
    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        exhausted, artifacts
    )
    running = store.mark_running(
        pending.identity,
        pending.stage,
        pending.input_refs,
        attempt_id="fixture-private-context-attempt-7",
    )
    hidden = stages._late_fixture_candidate_context_exclusions(running, artifacts)
    assert hidden
    assert any(
        ref in running.input_refs and b"HELPDESK_" in artifacts.read(ref)
        for ref in hidden
    )
    context = json.loads(
        artifacts.prompt_context_prioritized(
            (running.recovery_decision_refs[-1],),
            tuple(ref for ref in running.input_refs if ref not in hidden),
        )
    )
    context_refs = {
        json.dumps(item["reference"], sort_keys=True)
        for item in context["exact_inputs"]
    }
    assert all(
        json.dumps(ref.model_dump(mode="json"), sort_keys=True) not in context_refs
        for ref in hidden
    )


def test_unbound_fixture_marker_is_not_sent_to_candidate_repair() -> None:
    with pytest.raises(StageFailed) as caught:
        stages._raise_if_candidate_integrity_error(
            PoCCandidateRejected("POC_DJANGO_MIGRATION_FIXTURE_REPLAY_UNBOUND")
        )
    assert caught.value.failure.code == "POC_DJANGO_MIGRATION_FIXTURE_REPLAY_UNBOUND"
    stages._raise_if_candidate_integrity_error(
        PoCCandidateRejected(
            "POC_DJANGO_MIGRATION_FIXTURE_REPLAY_UNSUPPORTED",
            reason_code="SETUP_MIGRATE_ORDER_INVALID",
        )
    )


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
