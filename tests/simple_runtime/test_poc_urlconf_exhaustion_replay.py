"""One bounded replay when a generated PoC miswires a pinned Django URLConf."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.interfaces.cli.main import main
from sastsimi.observability.agent_activity import ActivityKind
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.sandbox.docker_adapter import DockerAdapter
from sastsimi.simple_runtime import recovery
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.poc import PoCCandidateRejected
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.runner import StageBlocked, StageFailed
from sastsimi.simple_runtime.stages import PoCCandidateStage, PoCExecutionStage
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_legacy_import_stop_replan import _PinnedStaticStub
from tests.simple_runtime.test_poc_fixture_dependency_replay import (
    _exhausted_attempt_four,
)
from tests.unit.interfaces.test_public_simple_cli import _config, _PublicApplication

_APP_CANDIDATE = b"""#!/bin/sh
cd /workspace || exit 2
python - <<'PY'
from django.conf import settings
print('Pinned source matched', flush=True)
settings.configure(INSTALLED_APPS=['django.contrib.auth', 'django_mailbox', 'helpdesk'])
stage = 'import'
import django
django.setup()
from django.test import Client
Client().get('/target/')
PY
"""
_APP_STDERR = b"""ModuleNotFoundError: django_mailbox
Traceback (most recent call last):
  at unresolved_frame:105
  at setup:24
  at populate:91
  at create:193
  at import_module:90
  at _gcd_import:1387
  at _find_and_load:1360
  at _find_and_load_unlocked:1324
"""
_APP_STDOUT = b"Pinned source matched\n"


def _candidate() -> bytes:
    lines = [
        "from django.conf import settings",
        "from django.urls import reverse",
        "print('Pinned follow-up view source matched', flush=True)",
        "settings.configure(ROOT_URLCONF='helpdesk.urls')",
    ]
    lines.extend("" for _ in range(89 - len(lines)))
    lines.append("reverse('helpdesk:followup_edit', args=[1, 1])")
    lines.append("print('Repository follow-up edit HTTP route resolved')")
    return (
        b"#!/bin/sh\ncd /workspace || exit 2\npython - <<'PY'\n"
        + "\n".join(lines).encode()
        + b"\nPY\n"
    )


_STDERR = (
    b"NoReverseMatch\nTraceback (most recent call last):\n"
    b"  at unresolved_frame:90\n  at reverse:92\n"
)
_STDOUT = b"Pinned follow-up view source matched\n"


class _NoLLM:
    def __init__(self) -> None:
        self.calls = 0

    async def call(self, **_kwargs: object) -> SimpleLLMCallResult:
        self.calls += 1
        raise AssertionError("LLM must not be reached for URLConf-bound replay")


class _NoContainer:
    def __init__(self) -> None:
        self.acquires = 0
        self.releases = 0

    async def acquire(self, *_args: object) -> str:
        self.acquires += 1
        raise AssertionError("Docker acquire must not be reached")

    async def release(self, _checkpoint: StageCheckpoint, _container_id: str) -> bool:
        self.releases += 1
        raise AssertionError("Docker release must not be reached")


def _checkout(tmp_path: Path, *, file_changes: dict[str, str] | None = None) -> str:
    root = tmp_path / "data" / "workspaces" / "workspace-1"
    files = {
        "settings.py": "INSTALLED_APPS = ['django.contrib.auth', 'helpdesk']\n",
        "pyproject.toml": (
            '[project]\nname = "target"\nversion = "1"\ndependencies = ["django"]\n'
        ),
        "src/helpdesk/urls.py": (
            "from django.urls import path\n"
            "from helpdesk import settings as helpdesk_settings\n"
            "app_name = 'helpdesk'\nurlpatterns = []\n"
            "if helpdesk_settings.HELPDESK_UI_ENABLED:\n"
            "    urlpatterns += [path('tickets/<int:ticket_id>/followup_edit/"
            "<int:followup_id>/', object(), name='followup_edit')]\n"
        ),
        "src/helpdesk/settings.py": (
            "from django.conf import settings\n"
            "HELPDESK_UI_ENABLED = getattr(settings, 'HELPDESK_UI_ENABLED', True)\n"
        ),
        "standalone/config/urls.py": (
            "from django.urls import include, path\n"
            "urlpatterns = [path('', include('helpdesk.urls', "
            "namespace='helpdesk'))]\n"
        ),
    }
    files.update(file_changes or {})
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    for args in (
        ("init", "-q"),
        ("add", "."),
        (
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-q",
            "-m",
            "pinned source",
        ),
    ):
        subprocess.run(("git", *args), cwd=root, check=True, capture_output=True)
    return subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _exhausted_urlconf(
    tmp_path: Path,
    *,
    file_changes: dict[str, str] | None = None,
    candidate_content: bytes | None = None,
    stderr: bytes = _STDERR,
    stdout: bytes = _STDOUT,
    execution_patch: dict[str, object] | None = None,
    cleanup_status: str = "REMOVED",
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    commit = _checkout(tmp_path, file_changes=file_changes)
    store, artifacts, fourth = _exhausted_attempt_four(
        tmp_path,
        candidate_content=_APP_CANDIDATE,
        stdout=_APP_STDOUT,
        stderr=_APP_STDERR,
        seed_commit_id=commit,
        failure_code="POC_RUNTIME_IMPORT_FAILED",
    )
    identity = fourth.identity
    dockerfile_ref = artifacts.put_bytes(
        b"FROM python:3.12\nWORKDIR /workspace\nCOPY . /workspace\n",
        "text/x-dockerfile",
    )
    recipe_ref = artifacts.put_json(
        {
            "kind": "simple_environment_recipe",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "hypothesis_id": identity.hypothesis_id,
            "attempt_id": "attempt-1",
            "dockerfile_source": "GENERATED",
            "status": "BUILT",
            "degraded": False,
            "image_digest": fourth.image_digest,
            "dockerfile_ref": dockerfile_ref.model_dump(mode="json"),
        }
    )
    for stage in (
        SimpleStage.VERIFICATION_INITIAL_DONE,
        SimpleStage.POC_CANDIDATE_DONE,
        SimpleStage.POC_EXECUTION_DONE,
    ):
        saved = store.require(identity, stage)
        store.save_checkpoint(saved.model_copy(update={"recipe_ref": recipe_ref}))
    fourth = store.require(identity, SimpleStage.POC_EXECUTION_DONE)
    pending = store.prepare_poc_candidate_app_exhaustion_replay(fourth, artifacts)
    candidate_running = store.mark_running(
        identity,
        SimpleStage.POC_CANDIDATE_DONE,
        pending.input_refs,
        attempt_id="attempt-5",
    )
    content = candidate_content if candidate_content is not None else _candidate()
    content_ref = artifacts.put_bytes(content, "text/x-shellscript")
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "attempt_id": "attempt-5",
            "content_ref": content_ref.model_dump(mode="json"),
            "content_digest": hashlib.sha256(content).hexdigest(),
        }
    )
    candidate = store.complete(
        candidate_running, StageResult(output_refs=(candidate_ref, content_ref))
    )
    execution_running = store.mark_running(
        identity,
        SimpleStage.POC_EXECUTION_DONE,
        (candidate_ref, content_ref),
        attempt_id="attempt-5",
        inherit_from=candidate,
    )
    stdout_ref = artifacts.put_bytes(stdout, "text/plain")
    stderr_ref = artifacts.put_bytes(stderr, "text/plain")
    receipt: dict[str, object] = {
        "kind": "simple_poc_execution",
        "attempt_id": "attempt-5",
        "candidate_ref": candidate_ref.model_dump(mode="json"),
        "content_ref": content_ref.model_dump(mode="json"),
        "stdout_ref": stdout_ref.model_dump(mode="json"),
        "stderr_ref": stderr_ref.model_dump(mode="json"),
        "exit_code": 2,
        "timed_out": False,
        "container_id": "owned-container-5",
        "image_digest": execution_running.image_digest,
    }
    receipt.update(execution_patch or {})
    execution_ref = artifacts.put_json(receipt)
    cleanup_ref = artifacts.put_json(
        {
            "kind": "simple_container_cleanup",
            "attempt_id": "attempt-5",
            "container_id": "owned-container-5",
            "status": cleanup_status,
        }
    )
    evidence = (execution_ref, stdout_ref, stderr_ref, cleanup_ref)
    failed = store.mark_failure(
        execution_running,
        StageFailure(
            code="POC_EXECUTION_FAILED",
            retryable=True,
            safe_message="PoC route resolution failed",
            evidence_refs=evidence,
        ),
        StageStatus.BLOCKED,
    )
    exhausted = store.mark_recovery_exhausted(failed)
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    root_running = root.model_copy(
        update={
            "status": StageStatus.RUNNING,
            "attempt_id": "root-attempt-5",
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
                f"{identity.hypothesis_id}:attempt-5"
            ),
            retryable=False,
            safe_message="Fifth PoC exhausted automatic recovery",
        ),
        StageStatus.BLOCKED,
    )
    return store, artifacts, exhausted


def _blocked_candidate_constraint(
    tmp_path: Path, *, file_changes: dict[str, str] | None = None
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store, artifacts, exhausted = _exhausted_urlconf(
        tmp_path, file_changes=file_changes
    )
    pending = store.prepare_poc_urlconf_exhaustion_replay(exhausted, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-6"
    )
    diagnostic_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate_rejection_diagnostic",
            "reason": "OTHER_VALIDATOR_REJECTION",
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
            code="POC_CANDIDATE_APP_REPLAY_UNSUPPORTED",
            retryable=True,
            safe_message="Candidate still references a forbidden app",
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
            "attempt_id": "root-attempt-6",
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
            safe_message="Child candidate validation blocked",
        ),
        StageStatus.BLOCKED,
    )
    return store, artifacts, stopped


def test_candidate_constraint_replay_is_one_shot_and_preserves_prior_evidence(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped = _blocked_candidate_constraint(tmp_path)
    before = AgentActivityStore(store.database_path).list_analysis(
        stopped.identity.analysis_id
    )
    pending = store.prepare_poc_candidate_constraint_replay(stopped, artifacts)
    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 6
    assert pending.recipe_ref == stopped.recipe_ref
    assert all(ref in pending.input_refs for ref in stopped.input_refs)
    assert all(ref in pending.input_refs for ref in stopped.output_refs)
    assert store.get(stopped.identity, SimpleStage.POC_EXECUTION_DONE) is None
    marker_ref = pending.recovery_decision_refs[-1]
    marker = json.loads(artifacts.read(marker_ref))
    assert marker["kind"] == "simple_poc_candidate_constraint_replay"
    assert marker["old_attempt_id"] == stopped.attempt_id
    assert (
        len(
            AgentActivityStore(store.database_path).list_analysis(
                stopped.identity.analysis_id
            )
        )
        == len(before) + 1
    )
    with pytest.raises(ValueError, match="POC_CANDIDATE_CONSTRAINT_REPLAY_"):
        store.prepare_poc_candidate_constraint_replay(stopped, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-7"
    )
    assert running.attempt_number == 7
    assert recovery.urlconf_replay_binding(running, artifacts) is not None
    assert recovery.candidate_app_replay_unsupported_app(running, artifacts) == (
        "django_mailbox"
    )


def test_candidate_constraint_replay_rejects_unrelated_or_tampered_stop(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped = _blocked_candidate_constraint(tmp_path)
    with pytest.raises(ValueError, match="POC_CANDIDATE_CONSTRAINT_REPLAY_INVALID"):
        store.prepare_poc_candidate_constraint_replay(
            stopped.model_copy(update={"attempt_number": 5}), artifacts
        )
    with pytest.raises(ValueError, match="POC_CANDIDATE_CONSTRAINT_REPLAY_STALE"):
        store.prepare_poc_candidate_constraint_replay(
            stopped.model_copy(update={"attempt_id": "other-candidate"}), artifacts
        )
    before = store.require(stopped.identity, stopped.stage)
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_poc_candidate_constraint_replay(
            stopped, artifacts, fail_before_commit=True
        )
    assert store.require(stopped.identity, stopped.stage) == before
    pending = store.prepare_poc_candidate_constraint_replay(stopped, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-7"
    )
    marker = pending.recovery_decision_refs[-1]
    without_marker = running.model_copy(
        update={
            "recovery_decision_refs": running.recovery_decision_refs[:-1],
        }
    )
    with pytest.raises(ValueError, match="POC_URLCONF_REPLAY_UNBOUND"):
        recovery.urlconf_replay_binding(without_marker, artifacts)
    assert marker in running.recovery_decision_refs


def _blocked_urlconf_constraint(
    tmp_path: Path, *, file_changes: dict[str, str] | None = None
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store, artifacts, stopped6 = _blocked_candidate_constraint(
        tmp_path, file_changes=file_changes
    )
    pending = store.prepare_poc_candidate_constraint_replay(stopped6, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-7"
    )
    diagnostic_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate_rejection_diagnostic",
            "reason": "OTHER_VALIDATOR_REJECTION",
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
            code="POC_URLCONF_REPLAY_UNSUPPORTED",
            retryable=True,
            safe_message="Candidate used dynamic URLConf",
            evidence_refs=(diagnostic_ref,),
        ),
        StageStatus.BLOCKED,
    )
    stopped7 = store.mark_recovery_exhausted(failed)
    root_identity = stopped7.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    root_running = root.model_copy(
        update={
            "status": StageStatus.RUNNING,
            "attempt_id": "root-attempt-7",
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
                f"{stopped7.identity.hypothesis_id}:{stopped7.attempt_id}"
            ),
            retryable=False,
            safe_message="Seventh candidate exhausted automatic recovery",
        ),
        StageStatus.BLOCKED,
    )
    return store, artifacts, stopped7


_LAYOUT_CANDIDATE = b"""#!/bin/sh
cd /workspace || exit 2
python - <<'PY'
import os
class HarnessError(Exception): pass
try:
    print('Pinned follow-up view source matched')
    root = '/workspace/src'
    if not os.path.isfile(root + '/standalone/config/urls.py'):
        raise HarnessError('project_import_layout')
    from django.conf import settings
    from django.urls import reverse
    settings.configure(ROOT_URLCONF='standalone.config.urls')
    reverse('helpdesk:followup_edit', args=[1, 1])
except HarnessError:
    raise
PY
"""


def _blocked_layout_execution(
    tmp_path: Path, *, file_changes: dict[str, str] | None = None
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store, artifacts, stopped7 = _blocked_urlconf_constraint(
        tmp_path, file_changes=file_changes
    )
    pending = store.prepare_poc_urlconf_candidate_replay(stopped7, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-8"
    )
    content_ref = artifacts.put_bytes(_LAYOUT_CANDIDATE, "text/x-shellscript")
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "attempt_id": "attempt-8",
            "content_ref": content_ref.model_dump(mode="json"),
            "content_digest": hashlib.sha256(_LAYOUT_CANDIDATE).hexdigest(),
        }
    )
    saved = store.complete(
        running, StageResult(output_refs=(candidate_ref, content_ref))
    )
    execution = store.mark_running(
        saved.identity,
        SimpleStage.POC_EXECUTION_DONE,
        (candidate_ref, content_ref),
        attempt_id="attempt-8",
        inherit_from=saved,
    )
    stdout_ref = artifacts.put_bytes(
        b"Pinned follow-up view source matched\n", "text/plain"
    )
    stderr_ref = artifacts.put_bytes(
        b"HarnessError\nTraceback (most recent call last):\n  at unresolved_frame:7\n",
        "text/plain",
    )
    execution_ref = artifacts.put_json(
        {
            "kind": "simple_poc_execution",
            "attempt_id": "attempt-8",
            "candidate_ref": candidate_ref.model_dump(mode="json"),
            "content_ref": content_ref.model_dump(mode="json"),
            "stdout_ref": stdout_ref.model_dump(mode="json"),
            "stderr_ref": stderr_ref.model_dump(mode="json"),
            "exit_code": 2,
            "timed_out": False,
            "container_id": "owned-container-8",
            "image_digest": execution.image_digest,
        }
    )
    cleanup_ref = artifacts.put_json(
        {
            "kind": "simple_container_cleanup",
            "attempt_id": "attempt-8",
            "container_id": "owned-container-8",
            "status": "REMOVED",
        }
    )
    failed = store.mark_failure(
        execution,
        StageFailure(
            code="POC_EXECUTION_FAILED",
            retryable=True,
            safe_message="Generated prerequisite path failed",
            evidence_refs=(execution_ref, stdout_ref, stderr_ref, cleanup_ref),
        ),
        StageStatus.BLOCKED,
    )
    stopped8 = store.mark_recovery_exhausted(failed)
    root_identity = stopped8.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    root_running = root.model_copy(
        update={
            "status": StageStatus.RUNNING,
            "attempt_id": "root-attempt-8",
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
                f"{stopped8.identity.hypothesis_id}:{stopped8.attempt_id}"
            ),
            retryable=False,
            safe_message="Eighth PoC exhausted recovery",
        ),
        StageStatus.BLOCKED,
    )
    return store, artifacts, stopped8


def test_generated_input_replay_is_one_shot_and_binds_runtime_layout(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped = _blocked_layout_execution(tmp_path)
    before = AgentActivityStore(store.database_path).list_analysis(
        stopped.identity.analysis_id
    )
    pending = store.prepare_poc_generated_input_replay(stopped, artifacts)
    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 8
    assert pending.recovery_decision_refs[:-1] == stopped.recovery_decision_refs
    assert all(ref in pending.input_refs for ref in stopped.output_refs)
    marker = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert marker["layout_failed_path"] == "/workspace/src/standalone/config/urls.py"
    assert marker["layout_corrected_path"] == "/workspace/standalone/config/urls.py"
    assert (
        len(
            AgentActivityStore(store.database_path).list_analysis(
                stopped.identity.analysis_id
            )
        )
        == len(before) + 1
    )
    with pytest.raises(ValueError, match="POC_GENERATED_INPUT_REPLAY_"):
        store.prepare_poc_generated_input_replay(stopped, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-9"
    )
    assert recovery.urlconf_replay_binding(running, artifacts) is not None
    assert recovery.candidate_app_replay_unsupported_app(running, artifacts) == (
        "django_mailbox"
    )
    tenth = running.model_copy(
        update={"attempt_number": 10, "attempt_id": "attempt-10"}
    )
    with pytest.raises(ValueError, match="POC_URLCONF_REPLAY_UNBOUND"):
        recovery.urlconf_replay_binding(tenth, artifacts)


def test_generated_input_replay_rolls_back_and_rejects_tampered_stop(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped = _blocked_layout_execution(tmp_path)
    before = store.require(stopped.identity, stopped.stage)
    events = AgentActivityStore(store.database_path).list_analysis(
        stopped.identity.analysis_id
    )
    with pytest.raises(ValueError, match="POC_GENERATED_INPUT_REPLAY_INVALID"):
        store.prepare_poc_generated_input_replay(
            stopped.model_copy(update={"attempt_number": 7}), artifacts
        )
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_poc_generated_input_replay(
            stopped, artifacts, fail_before_commit=True
        )
    assert store.require(stopped.identity, stopped.stage) == before
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            stopped.identity.analysis_id
        )
        == events
    )
    pending = store.prepare_poc_generated_input_replay(stopped, artifacts)
    markerless = pending.model_copy(
        update={"recovery_decision_refs": pending.recovery_decision_refs[:-1]}
    )
    with pytest.raises(ValueError, match="POC_URLCONF_REPLAY_UNBOUND"):
        recovery.urlconf_replay_binding(
            markerless.model_copy(
                update={"attempt_number": 9, "attempt_id": "attempt-9"}
            ),
            artifacts,
        )
    marker = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    marker["layout_execution_checkpoint_hash"] = "0" * 64
    forged_ref = artifacts.put_json(marker)
    forged_refs = (*pending.input_refs, forged_ref)
    forged = pending.model_copy(
        update={
            "attempt_number": 9,
            "attempt_id": "attempt-9",
            "input_refs": forged_refs,
            "input_hash": input_reference_hash(forged_refs),
            "recovery_decision_refs": (
                *pending.recovery_decision_refs[:-1],
                forged_ref,
            ),
        }
    )
    with pytest.raises(ValueError, match="POC_URLCONF_REPLAY_UNBOUND"):
        recovery.urlconf_replay_binding(forged, artifacts)


async def _assert_urlconf_bound_stages_block_before_downstream(
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
    running: StageCheckpoint,
    content: bytes,
) -> StageCheckpoint:
    client = _NoLLM()
    before = AgentActivityStore(store.database_path).list_analysis(
        running.identity.analysis_id
    )
    with pytest.raises(StageBlocked) as candidate_error:
        await PoCCandidateStage(client=client, artifacts=artifacts)(running, {})
    assert candidate_error.value.failure.code == "POC_URLCONF_ORIGIN_UNVERIFIED"
    assert candidate_error.value.failure.evidence_refs == ()
    assert client.calls == 0
    assert store.require(running.identity, running.stage) == running
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            running.identity.analysis_id
        )
        == before
    )
    attempt_id = running.attempt_id
    assert attempt_id is not None
    content_ref = artifacts.put_bytes(content, "text/x-shellscript")
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "attempt_id": attempt_id,
            "content_ref": content_ref.model_dump(mode="json"),
            "content_digest": hashlib.sha256(content).hexdigest(),
        }
    )
    saved = store.complete(
        running, StageResult(output_refs=(candidate_ref, content_ref))
    )
    execution = store.mark_running(
        saved.identity,
        SimpleStage.POC_EXECUTION_DONE,
        (candidate_ref, content_ref),
        attempt_id=attempt_id,
        inherit_from=saved,
    )
    containers = _NoContainer()
    before = AgentActivityStore(store.database_path).list_analysis(
        running.identity.analysis_id
    )
    with pytest.raises(StageBlocked) as execution_error:
        await PoCExecutionStage(
            client=client,
            artifacts=artifacts,
            docker=cast(DockerAdapter, object()),
            containers=containers,
        )(execution, {SimpleStage.POC_CANDIDATE_DONE: saved})
    assert execution_error.value.failure.code == "POC_URLCONF_ORIGIN_UNVERIFIED"
    assert execution_error.value.failure.evidence_refs == ()
    assert client.calls == 0
    assert containers.acquires == containers.releases == 0
    assert store.require(saved.identity, saved.stage) == saved
    assert store.require(execution.identity, execution.stage) == execution
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            running.identity.analysis_id
        )
        == before
    )
    return saved


@pytest.mark.asyncio
async def test_attempt9_fixed_candidate_blocks_before_llm_and_docker(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped = _blocked_layout_execution(tmp_path)
    pending = store.prepare_poc_generated_input_replay(stopped, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-9"
    )
    fixed = _LAYOUT_CANDIDATE.replace(
        b"root = '/workspace/src'", b"root = '/workspace'"
    )
    from sastsimi.simple_runtime import stages

    stages._reject_candidate_app_replay_content(running, artifacts, fixed)
    with pytest.raises(StageBlocked) as guard_error:
        stages._reject_urlconf_replay_content(running, artifacts, fixed)
    assert guard_error.value.failure.code == "POC_URLCONF_ORIGIN_UNVERIFIED"
    await _assert_urlconf_bound_stages_block_before_downstream(
        store, artifacts, running, fixed
    )


@pytest.mark.asyncio
async def test_generated_input_replay_preserves_import_roots_before_llm_block(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped = _blocked_layout_execution(tmp_path)
    pending = store.prepare_poc_generated_input_replay(stopped, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-9"
    )
    marker = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert marker["layout_failed_path"] == "/workspace/src/standalone/config/urls.py"
    assert marker["layout_corrected_path"] == "/workspace/standalone/config/urls.py"
    client = _NoLLM()
    before = AgentActivityStore(store.database_path).list_analysis(
        running.identity.analysis_id
    )
    with pytest.raises(StageBlocked) as error:
        await PoCCandidateStage(client=client, artifacts=artifacts)(running, {})
    assert error.value.failure.code == "POC_URLCONF_ORIGIN_UNVERIFIED"
    assert error.value.failure.evidence_refs == ()
    assert client.calls == 0
    assert store.require(running.identity, running.stage) == running
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            running.identity.analysis_id
        )
        == before
    )


@pytest.mark.asyncio
async def test_application_generated_input_flag_replays_only_bound_attempt8(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, stopped = _blocked_layout_execution(tmp_path)
    identity = stopped.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=_PinnedStaticStub(tmp_path / "data" / "workspaces"),
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )

    async def static_scope(*_args: object) -> None:
        return None

    async def resume_locked(_analysis_id: str) -> SimpleAnalysisOutcome:
        return SimpleAnalysisOutcome(
            identity=identity.model_copy(update={"hypothesis_id": None}),
            display_analysis_id="A-001",
            status="RUNNING",
            current_stage=SimpleStage.POC_CANDIDATE_DONE,
        )

    monkeypatch.setattr(application, "_assert_completed_static_scope", static_scope)
    monkeypatch.setattr(application, "_resume_locked", resume_locked)
    monkeypatch.setattr(
        application, "_verify_registered_candidate_proposals", lambda _root: None
    )
    await application.resume(identity.analysis_id)
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == stopped
    await application.resume(
        identity.analysis_id,
        repair_poc_generated_input_hypothesis=identity.hypothesis_id,
    )
    assert (
        store.require(identity, SimpleStage.POC_CANDIDATE_DONE).status
        is StageStatus.PENDING
    )
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None


def test_urlconf_candidate_replay_is_one_shot_and_preserves_chain(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped = _blocked_urlconf_constraint(tmp_path)
    pending = store.prepare_poc_urlconf_candidate_replay(stopped, artifacts)
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 7
    assert pending.recovery_decision_refs[:-1] == stopped.recovery_decision_refs
    assert all(ref in pending.input_refs for ref in stopped.input_refs)
    marker = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert marker["kind"] == "simple_poc_urlconf_candidate_replay"
    assert marker["old_attempt_id"] == stopped.attempt_id
    with pytest.raises(ValueError, match="POC_URLCONF_CANDIDATE_REPLAY_"):
        store.prepare_poc_urlconf_candidate_replay(stopped, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-8"
    )
    assert running.attempt_number == 8
    assert recovery.urlconf_replay_binding(running, artifacts) is not None
    assert recovery.candidate_app_replay_unsupported_app(running, artifacts) == (
        "django_mailbox"
    )
    ninth = running.model_copy(update={"attempt_number": 9, "attempt_id": "attempt-9"})
    with pytest.raises(ValueError, match="POC_URLCONF_REPLAY_UNBOUND"):
        recovery.urlconf_replay_binding(ninth, artifacts)


def test_urlconf_candidate_replay_rolls_back_and_rejects_missing_marker(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped = _blocked_urlconf_constraint(tmp_path)
    with pytest.raises(ValueError, match="POC_URLCONF_CANDIDATE_REPLAY_INVALID"):
        store.prepare_poc_urlconf_candidate_replay(
            stopped.model_copy(update={"attempt_number": 6}), artifacts
        )
    before = store.require(stopped.identity, stopped.stage)
    events_before = AgentActivityStore(store.database_path).list_analysis(
        stopped.identity.analysis_id
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_poc_urlconf_candidate_replay(
            stopped, artifacts, fail_before_commit=True
        )
    assert store.require(stopped.identity, stopped.stage) == before
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            stopped.identity.analysis_id
        )
        == events_before
    )
    pending = store.prepare_poc_urlconf_candidate_replay(stopped, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-8"
    )
    unbound = running.model_copy(
        update={"recovery_decision_refs": running.recovery_decision_refs[:-1]}
    )
    with pytest.raises(ValueError, match="POC_URLCONF_REPLAY_UNBOUND"):
        recovery.urlconf_replay_binding(unbound, artifacts)


@pytest.mark.asyncio
async def test_attempt8_pinned_candidate_blocks_before_llm_and_docker(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped = _blocked_urlconf_constraint(tmp_path)
    pending = store.prepare_poc_urlconf_candidate_replay(stopped, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-8"
    )
    fixed = _candidate().replace(
        b"ROOT_URLCONF='helpdesk.urls'",
        b"ROOT_URLCONF='standalone.config.urls'",
    )
    from sastsimi.simple_runtime import stages

    stages._reject_candidate_app_replay_content(running, artifacts, fixed)
    with pytest.raises(StageBlocked) as guard_error:
        stages._reject_urlconf_replay_content(running, artifacts, fixed)
    assert guard_error.value.failure.code == "POC_URLCONF_ORIGIN_UNVERIFIED"
    await _assert_urlconf_bound_stages_block_before_downstream(
        store, artifacts, running, fixed
    )


def test_urlconf_replay_reseeds_only_one_candidate_with_lineage(tmp_path: Path) -> None:
    store, artifacts, exhausted = _exhausted_urlconf(tmp_path)
    identity = exhausted.identity
    previous = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    before = AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)

    pending = store.prepare_poc_urlconf_exhaustion_replay(exhausted, artifacts)

    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 5
    assert pending.recipe_ref == exhausted.recipe_ref
    assert pending.image_digest == exhausted.image_digest
    assert previous.output_refs[0] in pending.input_refs
    assert all(ref in pending.input_refs for ref in exhausted.output_refs)
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    rule = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert rule["urlconf_replay"] is True
    assert rule["decision"]["action"] == "REGENERATE_INPUT"
    assert "namespace" in rule["decision"]["guidance"]
    assert "standalone.config.urls" in rule["decision"]["guidance"]
    assert "or install a dependency" in rule["decision"]["guidance"]
    assert rule["original_error"]["code"] == "POC_EXECUTION_FAILED"
    after = AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)
    assert len(after) == len(before) + 1
    new_events = {event.event_id: event for event in after if event not in before}
    assert len(new_events) == 1
    replay_event = next(iter(new_events.values()))
    assert replay_event.kind is ActivityKind.DECISION_RECORDED
    assert replay_event.error_code == "POC_URLCONF_EXHAUSTION_REPLAYED"
    with pytest.raises(ValueError, match="POC_URLCONF_EXHAUSTION_"):
        store.prepare_poc_urlconf_exhaustion_replay(exhausted, artifacts)


def test_urlconf_replay_guard_rederives_bound_signature(tmp_path: Path) -> None:
    store, artifacts, exhausted = _exhausted_urlconf(tmp_path)
    pending = store.prepare_poc_urlconf_exhaustion_replay(exhausted, artifacts)

    assert recovery.urlconf_replay_binding(pending, artifacts) == (
        ("helpdesk.urls", "helpdesk", "followup_edit", 2),
        ("standalone.config.urls",),
    )


def test_urlconf_replay_guard_rejects_unbound_marker_ref(tmp_path: Path) -> None:
    store, artifacts, exhausted = _exhausted_urlconf(tmp_path)
    pending = store.prepare_poc_urlconf_exhaustion_replay(exhausted, artifacts)
    marker = pending.recovery_decision_refs[-1]
    unbound = pending.model_copy(
        update={"input_refs": tuple(ref for ref in pending.input_refs if ref != marker)}
    )
    with pytest.raises(ValueError, match="POC_URLCONF_REPLAY_UNBOUND"):
        recovery.urlconf_replay_binding(unbound, artifacts)


def test_urlconf_proof_accepts_literal_include_plus_django_static(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_urlconf(
        tmp_path,
        file_changes={
            "standalone/config/urls.py": (
                "from django.urls import include, path\n"
                "from django.conf.urls.static import static\n"
                "from django.conf import settings\n"
                "urlpatterns = [path('', include('helpdesk.urls', "
                "namespace='helpdesk'))] + static(settings.MEDIA_URL, "
                "document_root=settings.MEDIA_ROOT)\n"
            )
        },
    )
    pending = store.prepare_poc_urlconf_exhaustion_replay(exhausted, artifacts)
    assert recovery.urlconf_replay_binding(pending, artifacts) == (
        ("helpdesk.urls", "helpdesk", "followup_edit", 2),
        ("standalone.config.urls",),
    )


def test_urlconf_replay_guard_blocks_both_wirings_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, artifacts, exhausted = _exhausted_urlconf(tmp_path)
    pending = store.prepare_poc_urlconf_exhaustion_replay(exhausted, artifacts)
    from sastsimi.simple_runtime import stages

    assert recovery.migration_settings_replay_binding(pending, artifacts) is None
    fixed = _candidate().replace(
        b"ROOT_URLCONF='helpdesk.urls'", b"ROOT_URLCONF='standalone.config.urls'"
    )
    before = AgentActivityStore(store.database_path).list_analysis(
        pending.identity.analysis_id
    )
    for content in (_candidate(), fixed):
        with pytest.raises(StageBlocked) as error:
            stages._reject_urlconf_replay_content(pending, artifacts, content)
        assert error.value.failure.code == "POC_URLCONF_ORIGIN_UNVERIFIED"
        assert error.value.failure.evidence_refs == ()
        assert store.require(pending.identity, pending.stage) == pending
        assert (
            AgentActivityStore(store.database_path).list_analysis(
                pending.identity.analysis_id
            )
            == before
        )

    predecessor = pending.model_copy(update={"recovery_decision_refs": ()})
    assert recovery.urlconf_replay_binding(predecessor, artifacts) is None
    monkeypatch.setattr(
        stages,
        "settings_replay_binding",
        lambda _checkpoint, _artifacts: ("HELPDESK_TEAMS_MODE_ENABLED", predecessor),
    )
    with pytest.raises(StageBlocked) as error:
        stages._reject_urlconf_replay_content(pending, artifacts, fixed)
    assert error.value.failure.code == "POC_URLCONF_ORIGIN_UNVERIFIED"


def test_non_migration_marker_cannot_bypass_migration_replay_validation(
    tmp_path: Path,
) -> None:
    from tests.simple_runtime.test_poc_django_migration_settings_replay import (
        _blocked_migration_candidate_attempt,
    )

    store, artifacts, stopped, _ = _blocked_migration_candidate_attempt(tmp_path)
    pending = store.prepare_poc_django_migration_settings_exhaustion_replay(
        stopped, artifacts
    )
    running = store.mark_running(
        pending.identity,
        pending.stage,
        pending.input_refs,
        attempt_id="altered-migration-marker",
    )
    marker_ref = running.recovery_decision_refs[-1]
    marker = json.loads(artifacts.read(marker_ref))
    marker["kind"] = "other_replay"
    altered_ref = artifacts.put_json(marker)
    inputs = tuple(
        altered_ref if ref == marker_ref else ref for ref in running.input_refs
    )
    altered = running.model_copy(
        update={
            "input_refs": inputs,
            "input_hash": input_reference_hash(inputs),
            "recovery_decision_refs": (
                *running.recovery_decision_refs[:-1],
                altered_ref,
            ),
        }
    )

    with pytest.raises(
        ValueError, match="POC_DJANGO_MIGRATION_SETTINGS_REPLAY_UNBOUND"
    ):
        recovery.migration_settings_replay_binding(altered, artifacts)


@pytest.mark.asyncio
async def test_urlconf_replay_pinned_candidate_blocks_running_and_saved_execution(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_urlconf(tmp_path)
    pending = store.prepare_poc_urlconf_exhaustion_replay(exhausted, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-6"
    )
    fixed = _candidate().replace(
        b"ROOT_URLCONF='helpdesk.urls'",
        b"ROOT_URLCONF='standalone.config.urls'",
    )
    from sastsimi.simple_runtime import stages

    with pytest.raises(StageBlocked) as running_error:
        stages._reject_urlconf_replay_content(running, artifacts, fixed)
    assert running_error.value.failure.code == "POC_URLCONF_ORIGIN_UNVERIFIED"
    beyond_one_shot = running.model_copy(
        update={"attempt_number": running.attempt_number + 1, "attempt_id": "attempt-7"}
    )
    with pytest.raises(PoCCandidateRejected, match="POC_URLCONF_REPLAY_UNSUPPORTED"):
        stages._reject_urlconf_replay_content(beyond_one_shot, artifacts, fixed)
    saved = await _assert_urlconf_bound_stages_block_before_downstream(
        store, artifacts, running, fixed
    )
    with pytest.raises(StageBlocked) as saved_error:
        stages._reject_urlconf_replay_content(saved, artifacts, fixed)
    assert saved_error.value.failure.code == "POC_URLCONF_ORIGIN_UNVERIFIED"


@pytest.mark.asyncio
async def test_saved_settings_replay_with_urlconf_marker_blocks_before_docker(
    tmp_path: Path,
) -> None:
    from tests.simple_runtime.test_poc_django_settings_exhaustion_replay import (
        _CANDIDATE as settings_candidate,
    )
    from tests.simple_runtime.test_poc_django_settings_exhaustion_replay import (
        _exhausted_settings_attempt,
    )

    store, artifacts, exhausted = _exhausted_settings_attempt(tmp_path)
    pending = store.prepare_poc_django_settings_exhaustion_replay(exhausted, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-11"
    )
    records = [
        json.loads(artifacts.read(ref)) for ref in running.recovery_decision_refs
    ]
    assert any(record.get("urlconf_replay") is True for record in records)
    assert any(record.get("settings_mismatch_replay") is True for record in records)
    assert recovery.settings_replay_binding(running, artifacts) is not None
    with pytest.raises(ValueError, match="POC_URLCONF_REPLAY_UNBOUND"):
        recovery.urlconf_replay_binding(running, artifacts)
    fixed = settings_candidate.replace(
        b"INSTALLED_APPS=[", b"HELPDESK_TEAMS_MODE_ENABLED=False, INSTALLED_APPS=["
    )
    client = _NoLLM()
    before = AgentActivityStore(store.database_path).list_analysis(
        running.identity.analysis_id
    )
    with pytest.raises(StageFailed) as candidate_error:
        await PoCCandidateStage(client=client, artifacts=artifacts)(running, {})
    assert candidate_error.value.failure.code == "HYPOTHESIS_ANCHOR_INVALID"
    assert candidate_error.value.failure.evidence_refs == ()
    assert client.calls == 0
    assert store.require(running.identity, running.stage) == running
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            running.identity.analysis_id
        )
        == before
    )

    content_ref = artifacts.put_bytes(fixed, "text/x-shellscript")
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "attempt_id": "attempt-11",
            "content_ref": content_ref.model_dump(mode="json"),
            "content_digest": hashlib.sha256(fixed).hexdigest(),
        }
    )
    saved = store.complete(
        running, StageResult(output_refs=(candidate_ref, content_ref))
    )
    execution = store.mark_running(
        saved.identity,
        SimpleStage.POC_EXECUTION_DONE,
        (candidate_ref, content_ref),
        attempt_id="attempt-11",
        inherit_from=saved,
    )
    containers = _NoContainer()
    before = AgentActivityStore(store.database_path).list_analysis(
        running.identity.analysis_id
    )
    with pytest.raises(StageBlocked) as error:
        await PoCExecutionStage(
            client=client,
            artifacts=artifacts,
            docker=cast(DockerAdapter, object()),
            containers=containers,
        )(execution, {SimpleStage.POC_CANDIDATE_DONE: saved})
    assert error.value.failure.code == "POC_URLCONF_REPLAY_UNSUPPORTED"
    assert error.value.failure.evidence_refs == (candidate_ref, content_ref)
    assert client.calls == 0
    assert containers.acquires == containers.releases == 0
    assert store.require(saved.identity, saved.stage) == saved
    assert store.require(execution.identity, execution.stage) == execution
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            running.identity.analysis_id
        )
        == before
    )


@pytest.mark.asyncio
async def test_urlconf_replay_blocks_before_candidate_save_or_llm(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_urlconf(tmp_path)
    pending = store.prepare_poc_urlconf_exhaustion_replay(exhausted, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-6"
    )
    client = _NoLLM()
    before = AgentActivityStore(store.database_path).list_analysis(
        running.identity.analysis_id
    )
    with pytest.raises(StageBlocked) as error:
        await PoCCandidateStage(client=client, artifacts=artifacts)(running, {})
    assert error.value.failure.code == "POC_URLCONF_ORIGIN_UNVERIFIED"
    assert error.value.failure.evidence_refs == ()
    assert client.calls == 0
    assert store.require(running.identity, running.stage) == running
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            running.identity.analysis_id
        )
        == before
    )


@pytest.mark.asyncio
async def test_candidate_replay_keeps_prior_app_constraint_before_llm_block(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_urlconf(tmp_path)
    pending = store.prepare_poc_urlconf_exhaustion_replay(exhausted, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-6"
    )
    assert recovery.candidate_app_replay_unsupported_app(running, artifacts) == (
        "django_mailbox"
    )
    assert recovery.urlconf_replay_binding(running, artifacts) is not None
    client = _NoLLM()
    before = AgentActivityStore(store.database_path).list_analysis(
        running.identity.analysis_id
    )
    with pytest.raises(StageBlocked) as error:
        await PoCCandidateStage(client=client, artifacts=artifacts)(running, {})
    assert error.value.failure.code == "POC_URLCONF_ORIGIN_UNVERIFIED"
    assert error.value.failure.evidence_refs == ()
    assert client.calls == 0
    assert store.require(running.identity, running.stage) == running
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            running.identity.analysis_id
        )
        == before
    )


@pytest.mark.asyncio
async def test_attempt8_keeps_urlconf_and_app_constraint_before_llm_block(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped = _blocked_urlconf_constraint(tmp_path)
    pending = store.prepare_poc_urlconf_candidate_replay(stopped, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-8"
    )
    assert recovery.candidate_app_replay_unsupported_app(running, artifacts) == (
        "django_mailbox"
    )
    assert recovery.urlconf_replay_binding(running, artifacts) is not None
    client = _NoLLM()
    before = AgentActivityStore(store.database_path).list_analysis(
        running.identity.analysis_id
    )
    with pytest.raises(StageBlocked) as error:
        await PoCCandidateStage(client=client, artifacts=artifacts)(running, {})
    assert error.value.failure.code == "POC_URLCONF_ORIGIN_UNVERIFIED"
    assert error.value.failure.evidence_refs == ()
    assert client.calls == 0
    assert store.require(running.identity, running.stage) == running
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            running.identity.analysis_id
        )
        == before
    )


@pytest.mark.asyncio
async def test_urlconf_replay_rejects_saved_bad_candidate_before_docker(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_urlconf(tmp_path)
    pending = store.prepare_poc_urlconf_exhaustion_replay(exhausted, artifacts)
    running = store.mark_running(
        pending.identity, pending.stage, pending.input_refs, attempt_id="attempt-6"
    )
    content = _candidate()
    content_ref = artifacts.put_bytes(content, "text/x-shellscript")
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "attempt_id": "attempt-6",
            "content_ref": content_ref.model_dump(mode="json"),
            "content_digest": hashlib.sha256(content).hexdigest(),
        }
    )
    saved = store.complete(
        running, StageResult(output_refs=(candidate_ref, content_ref))
    )
    execution = store.mark_running(
        saved.identity,
        SimpleStage.POC_EXECUTION_DONE,
        (candidate_ref, content_ref),
        attempt_id="attempt-6",
        inherit_from=saved,
    )

    client = _NoLLM()
    containers = _NoContainer()
    before = AgentActivityStore(store.database_path).list_analysis(
        execution.identity.analysis_id
    )
    with pytest.raises(StageBlocked) as error:
        await PoCExecutionStage(
            client=client,
            artifacts=artifacts,
            docker=cast(DockerAdapter, object()),
            containers=containers,
        )(execution, {SimpleStage.POC_CANDIDATE_DONE: saved})
    assert error.value.failure.code == "POC_URLCONF_ORIGIN_UNVERIFIED"
    assert error.value.failure.evidence_refs == ()
    assert client.calls == 0
    assert containers.acquires == containers.releases == 0
    assert store.require(saved.identity, saved.stage) == saved
    assert store.require(execution.identity, execution.stage) == execution
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            execution.identity.analysis_id
        )
        == before
    )


@pytest.mark.parametrize(
    "change",
    [
        {"file_changes": {"standalone/config/urls.py": "urlpatterns = []\n"}},
        {
            "file_changes": {
                "standalone/config/urls.py": (
                    "from django.urls import include, path\n"
                    "urlpatterns = [path('', include('helpdesk.urls', "
                    "namespace='helpdesk')) if False else path('', object())]\n"
                )
            }
        },
        {
            "file_changes": {
                "src/helpdesk/urls.py": "app_name = 'helpdesk'\nurlpatterns = []\n"
            }
        },
        {
            "file_changes": {
                "src/helpdesk/urls.py": (
                    "from django.urls import path\n"
                    "from helpdesk import settings as helpdesk_settings\n"
                    "app_name = 'helpdesk'\nurlpatterns = []\n"
                    "if helpdesk_settings.HELPDESK_UI_ENABLED:\n"
                    "    urlpatterns += [path('tickets/<int:ticket_id>/"
                    "followup_edit/<int:followup_id>/', object(), "
                    "name='followup_edit')]\n"
                    "urlpatterns = []\n"
                )
            }
        },
        {"file_changes": {"src/helpdesk/settings.py": "HELPDESK_UI_ENABLED = False\n"}},
        {"candidate_content": _candidate().replace(b"'helpdesk.urls'", b"chosen_root")},
        {"stderr": b"NoReverseMatch\nTraceback: unrelated\n"},
        {"stdout": _STDOUT + b"Repository follow-up edit HTTP route resolved\n"},
        {"execution_patch": {"exit_code": 1}},
        {"execution_patch": {"timed_out": True}},
        {"execution_patch": {"candidate_ref": None}},
        {"cleanup_status": "UNKNOWN"},
    ],
)
def test_urlconf_replay_fails_closed_without_mutating_checkpoint(
    tmp_path: Path, change: dict[str, object]
) -> None:
    typed_change: dict[str, Any] = change
    store, artifacts, exhausted = _exhausted_urlconf(tmp_path, **typed_change)
    identity = exhausted.identity
    candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    before = AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)

    with pytest.raises(ValueError, match="POC_URLCONF_EXHAUSTION_"):
        store.prepare_poc_urlconf_exhaustion_replay(exhausted, artifacts)

    assert store.require(identity, SimpleStage.POC_CANDIDATE_DONE) == candidate
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    assert (
        AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)
        == before
    )


@pytest.mark.asyncio
async def test_application_replays_urlconf_only_with_explicit_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, exhausted = _exhausted_urlconf(tmp_path)
    identity = exhausted.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=_PinnedStaticStub(tmp_path / "data" / "workspaces"),
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )

    async def static_scope(*_args: object) -> None:
        return None

    async def resume_locked(_analysis_id: str) -> SimpleAnalysisOutcome:
        return SimpleAnalysisOutcome(
            identity=identity.model_copy(update={"hypothesis_id": None}),
            display_analysis_id="A-001",
            status="RUNNING",
            current_stage=SimpleStage.POC_CANDIDATE_DONE,
        )

    monkeypatch.setattr(application, "_assert_completed_static_scope", static_scope)
    monkeypatch.setattr(application, "_resume_locked", resume_locked)
    monkeypatch.setattr(
        application, "_verify_registered_candidate_proposals", lambda _root: None
    )
    await application.resume(identity.analysis_id)
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted

    before = AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)
    with pytest.raises(ValueError, match="POC_URLCONF_EXHAUSTION_ORIGIN_UNVERIFIED"):
        await application.resume(
            identity.analysis_id,
            repair_poc_urlconf_exhaustion_hypothesis=identity.hypothesis_id,
        )
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    assert (
        AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)
        == before
    )


@pytest.mark.asyncio
async def test_application_replays_exact_candidate_constraint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, stopped = _blocked_candidate_constraint(tmp_path)
    identity = stopped.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=_PinnedStaticStub(tmp_path / "data" / "workspaces"),
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )

    async def static_scope(*_args: object) -> None:
        return None

    async def resume_locked(_analysis_id: str) -> SimpleAnalysisOutcome:
        return SimpleAnalysisOutcome(
            identity=identity.model_copy(update={"hypothesis_id": None}),
            display_analysis_id="A-001",
            status="RUNNING",
            current_stage=SimpleStage.POC_CANDIDATE_DONE,
        )

    monkeypatch.setattr(application, "_assert_completed_static_scope", static_scope)
    monkeypatch.setattr(application, "_resume_locked", resume_locked)
    monkeypatch.setattr(
        application, "_verify_registered_candidate_proposals", lambda _root: None
    )
    await application.resume(identity.analysis_id)
    assert store.require(identity, stopped.stage) == stopped
    await application.resume(
        identity.analysis_id,
        repair_poc_candidate_constraint_hypothesis=identity.hypothesis_id,
    )
    assert store.require(identity, stopped.stage).status is StageStatus.PENDING


@pytest.mark.asyncio
async def test_application_replays_exact_urlconf_candidate_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, stopped = _blocked_urlconf_constraint(tmp_path)
    identity = stopped.identity
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=_PinnedStaticStub(tmp_path / "data" / "workspaces"),
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )

    async def static_scope(*_args: object) -> None:
        return None

    async def resume_locked(_analysis_id: str) -> SimpleAnalysisOutcome:
        return SimpleAnalysisOutcome(
            identity=identity.model_copy(update={"hypothesis_id": None}),
            display_analysis_id="A-001",
            status="RUNNING",
            current_stage=SimpleStage.POC_CANDIDATE_DONE,
        )

    monkeypatch.setattr(application, "_assert_completed_static_scope", static_scope)
    monkeypatch.setattr(application, "_resume_locked", resume_locked)
    monkeypatch.setattr(
        application, "_verify_registered_candidate_proposals", lambda _root: None
    )
    await application.resume(identity.analysis_id)
    assert store.require(identity, stopped.stage) == stopped
    before = AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)
    with pytest.raises(
        ValueError, match="POC_URLCONF_CANDIDATE_REPLAY_ORIGIN_UNVERIFIED"
    ):
        await application.resume(
            identity.analysis_id,
            repair_poc_urlconf_candidate_hypothesis=identity.hypothesis_id,
        )
    assert store.require(identity, stopped.stage) == stopped
    assert (
        AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)
        == before
    )


def test_cli_forwards_urlconf_replay_in_plain_and_progress_modes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_urlconf_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("plain", repair_poc_urlconf_exhaustion_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_poc_urlconf_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("progress", repair_poc_urlconf_exhaustion_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = Application()
    for extra, mode in [(["--format", "json"], "plain"), ([], "progress")]:
        assert main(
            [
                "resume",
                "A-001",
                "--repair-poc-urlconf-exhaustion",
                "hypothesis-1",
                *extra,
            ],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (mode, "hypothesis-1")
        capsys.readouterr()


def test_cli_forwards_candidate_constraint_plain_and_progress(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_candidate_constraint_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("plain", repair_poc_candidate_constraint_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_poc_candidate_constraint_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("progress", repair_poc_candidate_constraint_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = Application()
    for extra, mode in [(["--format", "json"], "plain"), ([], "progress")]:
        assert main(
            [
                "resume",
                "A-001",
                "--repair-poc-candidate-constraint",
                "hypothesis-1",
                *extra,
            ],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (mode, "hypothesis-1")
        capsys.readouterr()


def test_cli_forwards_urlconf_candidate_plain_and_progress(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_urlconf_candidate_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("plain", repair_poc_urlconf_candidate_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_poc_urlconf_candidate_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("progress", repair_poc_urlconf_candidate_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = Application()
    for extra, mode in [(["--format", "json"], "plain"), ([], "progress")]:
        assert main(
            [
                "resume",
                "A-001",
                "--repair-poc-urlconf-candidate",
                "hypothesis-1",
                *extra,
            ],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (mode, "hypothesis-1")
        capsys.readouterr()


def test_cli_forwards_generated_input_plain_and_progress(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_generated_input_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("plain", repair_poc_generated_input_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_poc_generated_input_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("progress", repair_poc_generated_input_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = Application()
    for extra, mode in [(["--format", "json"], "plain"), ([], "progress")]:
        assert main(
            ["resume", "A-001", "--repair-poc-generated-input", "hypothesis-1", *extra],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (mode, "hypothesis-1")
        capsys.readouterr()


def test_cli_maps_only_urlconf_integrity_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class InvalidReplay(_PublicApplication):
        def resume(self, analysis_id: str, **_kwargs: object) -> dict[str, object]:
            del analysis_id
            raise ValueError("POC_URLCONF_EXHAUSTION_EVIDENCE_INVALID")

    code = main(
        [
            "resume",
            "A-001",
            "--repair-poc-urlconf-exhaustion",
            "hypothesis-1",
            "--format",
            "json",
        ],
        public_application=InvalidReplay(),
        user_config_store=_config(tmp_path),
    )
    assert code == int(ExitCode.INTEGRITY_ERROR)
    assert "POC_URLCONF_EXHAUSTION_EVIDENCE_INVALID" in capsys.readouterr().err
