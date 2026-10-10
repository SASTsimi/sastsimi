"""One explicit replay after a previously replayed PoC reaches fixture dependencies."""

from __future__ import annotations

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
from tests.simple_runtime.test_poc_fixture_exhaustion_replay import _exhausted_fixture
from tests.unit.interfaces.test_public_simple_cli import _config, _PublicApplication

_CANDIDATE = (
    b"django.setup()\n"
    b"phase = 'schema'\n"
    b"with connection.schema_editor() as editor: editor.create_model(model)\n"
    b"print('Schema: created=26 skipped_unrelated=1')\n"
    b"phase = 'fixtures'\n"
    b"User.objects.create(username='fixture')\n"
)
_STDOUT = b"Schema: created=26 skipped_unrelated=1\n"
_STDERR = (
    b"OperationalError during fixtures\n"
    b"Traceback: execute > _execute_with_wrappers > _execute > __exit__ > "
    b"_execute > execute\n"
)


def _exhausted_attempt_four(
    tmp_path: Path,
    *,
    candidate_content: bytes = _CANDIDATE,
    stdout: bytes = _STDOUT,
    stderr: bytes = _STDERR,
    execution_patch: dict[str, object] | None = None,
    cleanup_status: str = "REMOVED",
    seed_commit_id: str = "a" * 40,
    failure_code: str = "POC_EXECUTION_FAILED",
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store, artifacts, third = _exhausted_fixture(
        tmp_path, seed_commit_id=seed_commit_id
    )
    identity = third.identity
    pending = store.prepare_poc_fixture_exhaustion_replay(third, artifacts)
    candidate_running = store.mark_running(
        identity,
        SimpleStage.POC_CANDIDATE_DONE,
        pending.input_refs,
        attempt_id="attempt-4",
    )
    content_ref = artifacts.put_bytes(candidate_content, "text/x-shellscript")
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "attempt_id": "attempt-4",
            "content_ref": content_ref.model_dump(mode="json"),
            "content_digest": hashlib.sha256(candidate_content).hexdigest(),
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
        attempt_id="attempt-4",
        inherit_from=candidate,
    )
    stdout_ref = artifacts.put_bytes(stdout, "text/plain")
    stderr_ref = artifacts.put_bytes(stderr, "text/plain")
    receipt: dict[str, object] = {
        "kind": "simple_poc_execution",
        "attempt_id": "attempt-4",
        "candidate_ref": candidate_ref.model_dump(mode="json"),
        "content_ref": content_ref.model_dump(mode="json"),
        "stdout_ref": stdout_ref.model_dump(mode="json"),
        "stderr_ref": stderr_ref.model_dump(mode="json"),
        "exit_code": 2,
        "timed_out": False,
        "container_id": "owned-container-4",
        "image_digest": execution_running.image_digest,
    }
    receipt.update(execution_patch or {})
    execution_ref = artifacts.put_json(receipt)
    cleanup_ref = artifacts.put_json(
        {
            "kind": "simple_container_cleanup",
            "attempt_id": "attempt-4",
            "container_id": "owned-container-4",
            "status": cleanup_status,
        }
    )
    evidence = (execution_ref, stdout_ref, stderr_ref, cleanup_ref)
    failed = store.mark_failure(
        execution_running,
        StageFailure(
            code=failure_code,
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
            "attempt_id": "root-attempt-4",
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
                f"{identity.hypothesis_id}:attempt-4"
            ),
            retryable=False,
            safe_message="Fourth PoC exhausted automatic recovery",
        ),
        StageStatus.BLOCKED,
    )
    return store, artifacts, exhausted


def test_dependency_replay_preserves_four_attempts_and_reseeds_one_candidate(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_attempt_four(tmp_path)
    identity = exhausted.identity
    events_before = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    prior_marker = next(
        event
        for event in events_before
        if event.error_code == "POC_FIXTURE_EXHAUSTION_REPLAYED"
    )

    pending = store.prepare_poc_fixture_dependency_exhaustion_replay(
        exhausted, artifacts
    )

    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 4
    assert pending.recipe_ref == exhausted.recipe_ref
    assert pending.image_digest == exhausted.image_digest
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    assert all(ref in pending.input_refs for ref in exhausted.output_refs)
    assert prior_marker.output_refs[0] in pending.recovery_decision_refs
    rule = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert rule["explicit_exhaustion_replay"] is True
    assert rule["decision"]["action"] == "REGENERATE_INPUT"
    assert "related" in rule["decision"]["guidance"]
    assert "repository-supported settings" in rule["decision"]["guidance"]
    assert "Do not disable foreign-key enforcement" in rule["decision"]["guidance"]
    assert "vulnerability" in rule["decision"]["guidance"]
    assert "helpdesk_kbitem" not in json.dumps(rule)
    events_after = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    assert len(events_after) == len(events_before) + 1
    assert events_after[-1].kind is ActivityKind.DECISION_RECORDED
    assert events_after[-1].error_code == "POC_FIXTURE_DEPENDENCY_EXHAUSTION_REPLAYED"
    with pytest.raises(ValueError, match="POC_FIXTURE_DEPENDENCY_EXHAUSTION_"):
        store.prepare_poc_fixture_dependency_exhaustion_replay(exhausted, artifacts)


def test_empty_output_user_creation_fixture_error_reseeds_only_one_candidate(
    tmp_path: Path,
) -> None:
    candidate_content = (
        b"django.setup()\n"
        b"stage = 'database_setup'\n"
        b"with connection.schema_editor() as editor:\n"
        b"    editor.create_model(model)\n"
        b"account = User.objects.create_user(username='fixture')\n"
        b"response = client.get(route)\n"
    )
    stderr = (
        b"OperationalError: harness_runtime\n"
        b"Traceback (function names only):\n"
        b"  in _insert\n"
        b"  in execute_sql\n"
        b"  in execute\n"
        b"  in _execute_with_wrappers\n"
        b"  in _execute\n"
        b"  in __exit__\n"
        b"  in _execute\n"
        b"  in execute\n"
    )
    store, artifacts, exhausted = _exhausted_attempt_four(
        tmp_path,
        candidate_content=candidate_content,
        stderr=stderr,
        stdout=b"",
    )

    pending = store.prepare_poc_fixture_dependency_exhaustion_replay(
        exhausted, artifacts
    )

    assert pending.status is StageStatus.PENDING
    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.attempt_number == 4
    assert store.get(exhausted.identity, SimpleStage.POC_EXECUTION_DONE) is None
    assert any(
        b"signals" in artifacts.read(ref) for ref in pending.recovery_decision_refs
    )
    with pytest.raises(ValueError, match="POC_FIXTURE_DEPENDENCY_EXHAUSTION_"):
        store.prepare_poc_fixture_dependency_exhaustion_replay(exhausted, artifacts)


@pytest.mark.parametrize(
    "change",
    [
        {"stdout": b"Schema: created=26 skipped_unrelated=0\n"},
        {"stdout": b"Schema: created=26 skipped_unrelated=1\nother output\n"},
        {"stderr": b"OperationalError\nTraceback: execute"},
        {"candidate_content": b"django.setup()\nUser.objects.create()\n"},
        {"execution_patch": {"exit_code": 1}},
        {"execution_patch": {"timed_out": True}},
        {"execution_patch": {"candidate_ref": None}},
        {"cleanup_status": "UNKNOWN"},
    ],
)
def test_dependency_replay_rejects_mismatched_evidence_without_mutation(
    tmp_path: Path, change: dict[str, object]
) -> None:
    typed_change: dict[str, Any] = change
    store, artifacts, exhausted = _exhausted_attempt_four(tmp_path, **typed_change)
    identity = exhausted.identity
    candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    events = AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)

    with pytest.raises(
        ValueError, match="POC_FIXTURE_DEPENDENCY_EXHAUSTION_EVIDENCE_INVALID"
    ):
        store.prepare_poc_fixture_dependency_exhaustion_replay(exhausted, artifacts)

    assert store.require(identity, SimpleStage.POC_CANDIDATE_DONE) == candidate
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    assert (
        AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)
        == events
    )


def test_dependency_replay_requires_prior_attested_replay_and_current_root(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_attempt_four(tmp_path)
    identity = exhausted.identity
    old_refs = exhausted.recovery_decision_refs
    store.save_checkpoint(exhausted.model_copy(update={"recovery_decision_refs": ()}))
    altered = store.require(identity, SimpleStage.POC_EXECUTION_DONE)
    with pytest.raises(
        ValueError, match="POC_FIXTURE_DEPENDENCY_EXHAUSTION_PRIOR_INVALID"
    ):
        store.prepare_poc_fixture_dependency_exhaustion_replay(altered, artifacts)
    store.save_checkpoint(
        exhausted.model_copy(update={"recovery_decision_refs": old_refs})
    )

    root_identity = identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    store.save_checkpoint(root.model_copy(update={"error_code": "other-child"}))
    with pytest.raises(
        ValueError, match="POC_FIXTURE_DEPENDENCY_EXHAUSTION_ROOT_BOUND_INVALID"
    ):
        store.prepare_poc_fixture_dependency_exhaustion_replay(exhausted, artifacts)


def test_dependency_replay_rejects_unresolved_call_and_rolls_back(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_attempt_four(tmp_path)
    identity = exhausted.identity
    events = AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)
    assert store.begin_codex_call("unfinished", identity.analysis_id)
    with pytest.raises(
        ValueError, match="POC_FIXTURE_DEPENDENCY_EXHAUSTION_CODEX_UNRESOLVED"
    ):
        store.prepare_poc_fixture_dependency_exhaustion_replay(exhausted, artifacts)
    assert (
        AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)
        == events
    )


@pytest.mark.asyncio
async def test_application_requires_explicit_dependency_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, exhausted = _exhausted_attempt_four(tmp_path)
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
    await application.resume(
        identity.analysis_id,
        repair_poc_fixture_dependency_exhaustion_hypothesis=identity.hypothesis_id,
    )
    assert (
        store.require(identity, SimpleStage.POC_CANDIDATE_DONE).status
        is StageStatus.PENDING
    )
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None


def test_cli_forwards_explicit_dependency_replay_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_fixture_dependency_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(
                ("plain", repair_poc_fixture_dependency_exhaustion_hypothesis)
            )
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_poc_fixture_dependency_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(
                ("progress", repair_poc_fixture_dependency_exhaustion_hypothesis)
            )
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = Application()
    for extra, path in [(["--format", "json"], "plain"), ([], "progress")]:
        assert main(
            [
                "resume",
                "A-001",
                "--repair-poc-fixture-dependency-exhaustion",
                "hypothesis-1",
                *extra,
            ],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (path, "hypothesis-1")
        capsys.readouterr()
