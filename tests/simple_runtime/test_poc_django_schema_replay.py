from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.interfaces.cli.main import main
from sastsimi.observability.agent_activity import ActivityKind
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
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
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_legacy_import_stop_replan import _PinnedStaticStub
from tests.simple_runtime.test_poc_django_settings_exhaustion_replay import (
    _exhausted_settings_attempt,
)
from tests.simple_runtime.test_poc_source_gap_replay import _exhausted_source_gap
from tests.unit.interfaces.test_public_simple_cli import _config, _PublicApplication

_SCRIPT = b"""#!/bin/sh
python - <<'PY'
import django
django.setup()
stage = 'database_setup'
from django.db import connection
from helpdesk.models import Queue, Ticket
with connection.schema_editor() as editor:
    for model in (Queue, Ticket):
        editor.create_model(model)
stage = 'fixture_setup'
queue = Queue.objects.create(title='fixture_value')
response = client.get('/helpdesk/')
PY
"""
_STDERR = (
    b"OperationalError: fixture_setup\n"
    b"Traceback (function names only):\n"
    b"  in __len__\n"
    b"  in _fetch_all\n"
    b"  in __iter__\n"
    b"  in execute_sql\n"
    b"  in execute\n"
    b"  in _execute_with_wrappers\n"
    b"  in _execute\n"
    b"  in __exit__\n"
    b"  in _execute\n"
    b"  in execute\n"
)


def _exhausted_sixth(
    tmp_path: Path,
    *,
    stderr: bytes = _STDERR,
    stdout: bytes = b"",
    cleanup_status: str = "REMOVED",
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store, artifacts, fifth = _exhausted_source_gap(tmp_path)
    identity = fifth.identity
    pending = store.prepare_poc_source_gap_exhaustion_replay(fifth, artifacts)
    candidate_running = store.mark_running(
        identity,
        SimpleStage.POC_CANDIDATE_DONE,
        pending.input_refs,
        attempt_id="attempt-6",
    )
    content_ref = artifacts.put_bytes(_SCRIPT, "text/x-shellscript")
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "attempt_id": "attempt-6",
            "content_ref": content_ref.model_dump(mode="json"),
            "content_digest": hashlib.sha256(_SCRIPT).hexdigest(),
        }
    )
    candidate = store.complete(
        candidate_running,
        StageResult(output_refs=(candidate_ref, content_ref)),
    )
    execution_running = store.mark_running(
        identity,
        SimpleStage.POC_EXECUTION_DONE,
        (candidate_ref, content_ref),
        attempt_id="attempt-6",
        inherit_from=candidate,
    )
    stdout_ref = artifacts.put_bytes(stdout, "text/plain")
    stderr_ref = artifacts.put_bytes(stderr, "text/plain")
    execution_ref = artifacts.put_json(
        {
            "kind": "simple_poc_execution",
            "attempt_id": "attempt-6",
            "candidate_ref": candidate_ref.model_dump(mode="json"),
            "content_ref": content_ref.model_dump(mode="json"),
            "stdout_ref": stdout_ref.model_dump(mode="json"),
            "stderr_ref": stderr_ref.model_dump(mode="json"),
            "exit_code": 2,
            "timed_out": False,
            "container_id": "owned-container-6",
            "image_digest": execution_running.image_digest,
        }
    )
    cleanup_ref = artifacts.put_json(
        {
            "kind": "simple_container_cleanup",
            "attempt_id": "attempt-6",
            "container_id": "owned-container-6",
            "status": cleanup_status,
        }
    )
    evidence = (execution_ref, stdout_ref, stderr_ref, cleanup_ref)
    failed = store.mark_failure(
        execution_running,
        StageFailure(
            code="POC_EXECUTION_FAILED",
            retryable=True,
            safe_message="PoC fixture setup failed",
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
                f"{identity.hypothesis_id}:attempt-6"
            ),
            retryable=False,
            safe_message="Sixth PoC exhausted automatic recovery",
        ),
        StageStatus.BLOCKED,
    )
    return store, artifacts, exhausted


def test_django_schema_replay_requires_exact_sixth_fixture_failure_and_runs_once(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_sixth(tmp_path)
    before = AgentActivityStore(store.database_path).list_analysis(
        exhausted.identity.analysis_id
    )

    pending = store.prepare_poc_django_schema_exhaustion_replay(exhausted, artifacts)

    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 6
    assert store.get(exhausted.identity, SimpleStage.POC_EXECUTION_DONE) is None
    rule = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert rule["explicit_exhaustion_replay"] is True
    assert rule["decision"]["action"] == "REGENERATE_INPUT"
    after = AgentActivityStore(store.database_path).list_analysis(
        exhausted.identity.analysis_id
    )
    new = [
        event
        for event in after
        if event.event_id not in {old.event_id for old in before}
    ]
    assert len(new) == 1
    assert new[0].kind is ActivityKind.DECISION_RECORDED
    assert new[0].error_code == "POC_DJANGO_SCHEMA_EXHAUSTION_REPLAYED"
    with pytest.raises(ValueError, match="POC_DJANGO_SCHEMA_EXHAUSTION_"):
        store.prepare_poc_django_schema_exhaustion_replay(exhausted, artifacts)


@pytest.mark.parametrize(
    "change",
    [
        {"stderr": b"OperationalError: other_fixture\n"},
        {"stdout": b"SASTSIMI_POC_REPRODUCED\n"},
        {"cleanup_status": "UNKNOWN"},
    ],
)
def test_django_schema_replay_rejects_other_evidence_without_mutation(
    tmp_path: Path, change: dict[str, object]
) -> None:
    typed_change: dict[str, Any] = change
    store, artifacts, exhausted = _exhausted_sixth(tmp_path, **typed_change)
    before = AgentActivityStore(store.database_path).list_analysis(
        exhausted.identity.analysis_id
    )
    with pytest.raises(ValueError, match="POC_DJANGO_SCHEMA_EXHAUSTION_"):
        store.prepare_poc_django_schema_exhaustion_replay(exhausted, artifacts)
    assert (
        store.require(exhausted.identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    )
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            exhausted.identity.analysis_id
        )
        == before
    )


def test_django_schema_replay_requires_sixth_attempt_and_all_prior_markers(
    tmp_path: Path,
) -> None:
    prior_store, prior_artifacts, fifth = _exhausted_source_gap(tmp_path / "fifth")
    with pytest.raises(ValueError, match="POC_DJANGO_SCHEMA_EXHAUSTION_INVALID"):
        prior_store.prepare_poc_django_schema_exhaustion_replay(fifth, prior_artifacts)

    store, artifacts, sixth = _exhausted_sixth(tmp_path / "sixth")
    altered = sixth.model_copy(
        update={"recovery_decision_refs": sixth.recovery_decision_refs[:-1]}
    )
    store.save_checkpoint(altered)
    with pytest.raises(ValueError, match="POC_DJANGO_SCHEMA_EXHAUSTION_PRIOR_INVALID"):
        store.prepare_poc_django_schema_exhaustion_replay(altered, artifacts)


def test_django_schema_replay_rejects_changed_root_and_unresolved_call(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_sixth(tmp_path)
    root_identity = exhausted.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    store.save_checkpoint(root.model_copy(update={"error_code": "other-child"}))
    with pytest.raises(
        ValueError, match="POC_DJANGO_SCHEMA_EXHAUSTION_ROOT_BOUND_INVALID"
    ):
        store.prepare_poc_django_schema_exhaustion_replay(exhausted, artifacts)
    store.save_checkpoint(root)
    assert store.begin_codex_call("unresolved", exhausted.identity.analysis_id)
    with pytest.raises(
        ValueError, match="POC_DJANGO_SCHEMA_EXHAUSTION_CODEX_UNRESOLVED"
    ):
        store.prepare_poc_django_schema_exhaustion_replay(exhausted, artifacts)


def test_django_schema_replay_rolls_back_marker_and_checkpoint_together(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_sixth(tmp_path)
    before = AgentActivityStore(store.database_path).list_analysis(
        exhausted.identity.analysis_id
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_poc_django_schema_exhaustion_replay(
            exhausted, artifacts, fail_before_commit=True
        )
    assert (
        store.require(exhausted.identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    )
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            exhausted.identity.analysis_id
        )
        == before
    )


def test_application_requires_explicit_django_schema_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, exhausted = _exhausted_sixth(tmp_path)
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
    asyncio.run(application.resume(identity.analysis_id))
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    asyncio.run(
        application.resume(
            identity.analysis_id,
            repair_poc_django_schema_exhaustion_hypothesis=identity.hypothesis_id,
        )
    )
    assert (
        store.require(identity, SimpleStage.POC_CANDIDATE_DONE).status
        is StageStatus.PENDING
    )
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None


def test_application_requires_explicit_django_settings_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, exhausted = _exhausted_settings_attempt(tmp_path)
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
    asyncio.run(application.resume(identity.analysis_id))
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    asyncio.run(
        application.resume(
            identity.analysis_id,
            repair_poc_django_settings_exhaustion_hypothesis=identity.hypothesis_id,
        )
    )
    assert (
        store.require(identity, SimpleStage.POC_CANDIDATE_DONE).status
        is StageStatus.PENDING
    )
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_REPAIR_CONFLICT"):
        asyncio.run(
            application.resume(
                identity.analysis_id,
                repair_poc_django_settings_exhaustion_hypothesis=identity.hypothesis_id,
                repair_poc_django_schema_exhaustion_hypothesis=identity.hypothesis_id,
            )
        )


def test_cli_forwards_django_schema_replay_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_django_schema_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("plain", repair_poc_django_schema_exhaustion_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_poc_django_schema_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(
                ("progress", repair_poc_django_schema_exhaustion_hypothesis)
            )
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = Application()
    for extra, path in [(["--format", "json"], "plain"), ([], "progress")]:
        assert main(
            [
                "resume",
                "A-001",
                "--repair-poc-django-schema-exhaustion",
                "hypothesis-1",
                *extra,
            ],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (path, "hypothesis-1")
        capsys.readouterr()


def test_cli_forwards_django_settings_replay_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_django_settings_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(
                ("plain", repair_poc_django_settings_exhaustion_hypothesis)
            )
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_poc_django_settings_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(
                ("progress", repair_poc_django_settings_exhaustion_hypothesis)
            )
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = Application()
    for extra, path in [(["--format", "json"], "plain"), ([], "progress")]:
        assert main(
            [
                "resume",
                "A-001",
                "--repair-poc-django-settings-exhaustion",
                "hypothesis-1",
                *extra,
            ],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (path, "hypothesis-1")
        capsys.readouterr()


def test_cli_forwards_django_relation_settings_replay_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_django_relation_settings_exhaustion_hypothesis: str
            | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(
                ("plain", repair_poc_django_relation_settings_exhaustion_hypothesis)
            )
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_poc_django_relation_settings_exhaustion_hypothesis: str
            | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(
                ("progress", repair_poc_django_relation_settings_exhaustion_hypothesis)
            )
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = Application()
    for extra, path in [(["--format", "json"], "plain"), ([], "progress")]:
        assert main(
            [
                "resume",
                "A-001",
                "--repair-poc-django-relation-settings-exhaustion",
                "hypothesis-1",
                *extra,
            ],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (path, "hypothesis-1")
        capsys.readouterr()
