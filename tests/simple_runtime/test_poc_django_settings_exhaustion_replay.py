"""One source-bound replay after an exhausted Django migration settings gap."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from sastsimi.contracts.poc_candidate import PoCCandidateRejected
from sastsimi.observability.agent_activity import ActivityKind
from sastsimi.simple_runtime import recovery, stages
from sastsimi.simple_runtime.models import (
    SimpleStage,
    StageFailure,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_poc_validator_correction_replay import (
    _blocked_validator_candidate,
)

_PINNED_FILES = {
    "standalone/config/settings.py": (
        "import os\n"
        "HELPDESK_TEAMS_MODE_ENABLED = (\n"
        "    os.getenv('HELPDESK_TEAMS_MODE_ENABLED', 'false').lower() == 'true'\n"
        ")\n"
        "INSTALLED_APPS = ['django.contrib.auth', 'helpdesk']\n"
    ),
    "src/helpdesk/settings.py": (
        "from django.conf import settings\n"
        "HELPDESK_UI_ENABLED = getattr(settings, 'HELPDESK_UI_ENABLED', True)\n"
        "HELPDESK_TEAMS_MODE_ENABLED = getattr("
        "settings, 'HELPDESK_TEAMS_MODE_ENABLED', True)\n"
        "if HELPDESK_TEAMS_MODE_ENABLED:\n"
        "    HELPDESK_TEAMS_MIGRATION_DEPENDENCIES = getattr(\n"
        "        settings, 'HELPDESK_TEAMS_MIGRATION_DEPENDENCIES', "
        "[('pinax_teams', '0001')]\n"
        "    )\n"
        "else:\n"
        "    HELPDESK_TEAMS_MIGRATION_DEPENDENCIES = []\n"
    ),
    "src/helpdesk/migrations/0028_team.py": (
        "from helpdesk import settings as helpdesk_settings\n"
        "class Migration:\n"
        "    dependencies = [('helpdesk', '0027')] + "
        "helpdesk_settings.HELPDESK_TEAMS_MIGRATION_DEPENDENCIES\n"
    ),
}
_CANDIDATE = b"""#!/bin/sh
cd /workspace || exit 2
python - <<'PY'
from django.conf import settings
from django.urls import reverse
settings.configure(
    ROOT_URLCONF='standalone.config.urls',
    INSTALLED_APPS=['django.contrib.auth', 'helpdesk'],
)
import django
django.setup()
from django.core.management import call_command
call_command('migrate', interactive=False, run_syncdb=True)
reverse('helpdesk:followup_edit', args=[1, 1])
PY
"""
_STDERR = (
    b"NodeNotFoundError\nTraceback (most recent call last):\n"
    b"  at unresolved_frame:10\n  at call_command:195\n"
    b"  at build_graph:313\n  at validate_consistency:200\n"
)


def _exhausted_settings_attempt(tmp_path: Path):  # type: ignore[no-untyped-def]
    store, artifacts, stopped9 = _blocked_validator_candidate(
        tmp_path, file_changes=_PINNED_FILES
    )
    run = store.require_analysis_run(stopped9.identity.analysis_id)
    assert run.static_coverage_ref is not None
    manifest_ref = artifacts.put_json(
        {
            "kind": "simple_tracked_sources",
            "paths": sorted(_PINNED_FILES),
        }
    )
    static_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "analysis_id": stopped9.identity.analysis_id,
            "workspace_id": stopped9.identity.workspace_id,
            "commit_id": stopped9.identity.commit_id,
            "source_manifest_ref": manifest_ref.model_dump(mode="json"),
            "poc_source_manifest_ref": manifest_ref.model_dump(mode="json"),
            "static_coverage_ref": run.static_coverage_ref.model_dump(mode="json"),
        }
    )
    store.save_analysis_run(run.model_copy(update={"static_bundle_ref": static_ref}))
    root_identity = stopped9.identity.model_copy(update={"hypothesis_id": None})
    static = store.require(root_identity, SimpleStage.STATIC_DONE)
    store.save_checkpoint(
        static.model_copy(
            update={
                "output_refs": (*static.output_refs, static_ref),
            }
        )
    )
    pending = store.prepare_poc_generated_input_replay(stopped9, artifacts)
    identity = pending.identity
    candidate_running = store.mark_running(
        identity, pending.stage, pending.input_refs, attempt_id="attempt-10"
    )
    content_ref = artifacts.put_bytes(_CANDIDATE, "text/x-shellscript")
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "attempt_id": "attempt-10",
            "content_ref": content_ref.model_dump(mode="json"),
            "content_digest": hashlib.sha256(_CANDIDATE).hexdigest(),
        }
    )
    candidate = store.complete(
        candidate_running, StageResult(output_refs=(candidate_ref, content_ref))
    )
    execution_running = store.mark_running(
        identity,
        SimpleStage.POC_EXECUTION_DONE,
        (candidate_ref, content_ref),
        attempt_id="attempt-10",
        inherit_from=candidate,
    )
    stdout_ref = artifacts.put_bytes(b"", "text/plain")
    stderr_ref = artifacts.put_bytes(_STDERR, "text/plain")
    execution_ref = artifacts.put_json(
        {
            "kind": "simple_poc_execution",
            "attempt_id": "attempt-10",
            "candidate_ref": candidate_ref.model_dump(mode="json"),
            "content_ref": content_ref.model_dump(mode="json"),
            "stdout_ref": stdout_ref.model_dump(mode="json"),
            "stderr_ref": stderr_ref.model_dump(mode="json"),
            "exit_code": 2,
            "timed_out": False,
            "container_id": "owned-container-10",
            "image_digest": execution_running.image_digest,
        }
    )
    cleanup_ref = artifacts.put_json(
        {
            "kind": "simple_container_cleanup",
            "attempt_id": "attempt-10",
            "container_id": "owned-container-10",
            "status": "REMOVED",
        }
    )
    failed = store.mark_failure(
        execution_running,
        StageFailure(
            code="POC_EXECUTION_FAILED",
            retryable=True,
            safe_message="Django migration graph failed",
            evidence_refs=(execution_ref, stdout_ref, stderr_ref, cleanup_ref),
        ),
        StageStatus.BLOCKED,
    )
    exhausted = store.mark_recovery_exhausted(failed)
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    root_running = root.model_copy(
        update={
            "status": StageStatus.RUNNING,
            "attempt_id": "root-attempt-10",
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
                f"{identity.hypothesis_id}:{exhausted.attempt_id}"
            ),
            retryable=False,
            safe_message="Tenth PoC exhausted recovery",
        ),
        StageStatus.BLOCKED,
    )
    return store, artifacts, exhausted


def test_settings_replay_is_one_shot_and_preserves_lineage(tmp_path: Path) -> None:
    store, artifacts, exhausted = _exhausted_settings_attempt(tmp_path)
    identity = exhausted.identity
    prior_candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    initial = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
    events_before = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id
    )

    pending = store.prepare_poc_django_settings_exhaustion_replay(exhausted, artifacts)

    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 10
    assert pending.recovery_decision_refs[:-1] == exhausted.recovery_decision_refs
    assert all(ref in pending.input_refs for ref in prior_candidate.output_refs)
    assert all(ref in pending.input_refs for ref in exhausted.output_refs)
    assert store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE) == initial
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    marker = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert marker["settings_mismatch_replay"] is True
    assert marker["settings_flag"] == "HELPDESK_TEAMS_MODE_ENABLED"
    events_after = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id
    )
    assert len(events_after) == len(events_before) + 1
    added = [event for event in events_after if event not in events_before]
    assert len(added) == 1
    assert added[0].kind is ActivityKind.DECISION_RECORDED
    assert added[0].error_code == "POC_DJANGO_SETTINGS_EXHAUSTION_REPLAYED"
    with pytest.raises(ValueError, match="POC_DJANGO_SETTINGS_EXHAUSTION_"):
        store.prepare_poc_django_settings_exhaustion_replay(exhausted, artifacts)

    running = store.mark_running(
        identity, pending.stage, pending.input_refs, attempt_id="attempt-11"
    )
    binding = recovery.settings_replay_binding(running, artifacts)
    assert binding is not None
    assert binding[0] == "HELPDESK_TEAMS_MODE_ENABLED"
    fixed = _CANDIDATE.replace(
        b"INSTALLED_APPS=[", b"HELPDESK_TEAMS_MODE_ENABLED=False, INSTALLED_APPS=["
    )
    stages._reject_settings_replay_content(running, artifacts, fixed)
    stages._reject_candidate_app_replay_content(running, artifacts, fixed)
    # A historical URLConf replay in this lineage no longer qualifies for
    # automatic execution: source provenance cannot be proved in the runner.
    with pytest.raises(PoCCandidateRejected, match="POC_URLCONF_REPLAY_UNSUPPORTED"):
        stages._reject_urlconf_replay_content(running, artifacts, fixed)
    with pytest.raises(Exception, match="POC_DJANGO_SETTINGS_REPLAY_UNSUPPORTED"):
        stages._reject_settings_replay_content(running, artifacts, _CANDIDATE)


def test_settings_replay_rejects_stale_or_unpinned_evidence(tmp_path: Path) -> None:
    store, artifacts, exhausted = _exhausted_settings_attempt(tmp_path)
    identity = exhausted.identity
    with pytest.raises(ValueError, match="POC_DJANGO_SETTINGS_EXHAUSTION_STALE"):
        store.prepare_poc_django_settings_exhaustion_replay(
            exhausted.model_copy(update={"attempt_id": "wrong"}), artifacts
        )
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_poc_django_settings_exhaustion_replay(
            exhausted, artifacts, fail_before_commit=True
        )
    assert store.require(identity, exhausted.stage) == exhausted
    run = store.require_analysis_run(identity.analysis_id)
    workspace = run.workspace_path
    assert workspace is not None
    project = workspace / "standalone" / "config" / "settings.py"
    project.write_text("HELPDESK_TEAMS_MODE_ENABLED = True\n", encoding="utf-8")
    with pytest.raises(
        ValueError, match="POC_DJANGO_SETTINGS_EXHAUSTION_EVIDENCE_INVALID"
    ):
        store.prepare_poc_django_settings_exhaustion_replay(exhausted, artifacts)
    assert store.require(identity, exhausted.stage) == exhausted


def test_settings_replay_binding_rejects_forged_marker(tmp_path: Path) -> None:
    store, artifacts, exhausted = _exhausted_settings_attempt(tmp_path)
    pending = store.prepare_poc_django_settings_exhaustion_replay(exhausted, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-11"
    )
    marker = json.loads(artifacts.read(running.recovery_decision_refs[-1]))
    forged_ref = artifacts.put_json(dict(marker, settings_flag="WRONG_FLAG"))
    inputs = tuple(
        forged_ref if ref == running.recovery_decision_refs[-1] else ref
        for ref in running.input_refs
    )
    forged = running.model_copy(
        update={
            "input_refs": inputs,
            "input_hash": input_reference_hash(inputs),
            "recovery_decision_refs": (
                *running.recovery_decision_refs[:-1],
                forged_ref,
            ),
        }
    )
    with pytest.raises(ValueError, match="POC_DJANGO_SETTINGS_REPLAY_UNBOUND"):
        recovery.settings_replay_binding(forged, artifacts)
