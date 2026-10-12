"""Explicit one-shot replay of an exhausted, bound Django PoC setup failure."""

from __future__ import annotations

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
from sastsimi.simple_runtime.models import SimpleStage, StageCheckpoint, StageStatus
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_legacy_import_stop_replan import _PinnedStaticStub
from tests.simple_runtime.test_poc_extract_exhaustion_replay import _exhausted_extract
from tests.unit.interfaces.test_public_simple_cli import _config, _PublicApplication

_DJANGO_SETUP = (
    b"django.setup()\n"
    b"call_command('migrate', interactive=False)\n"
    b"with connection.schema_editor() as editor: editor.create_model(Ticket)\n"
)
_SCHEMA_ERRORS = (
    b"NodeNotFoundError during schema\n"
    b"Traceback: build_graph > validate_consistency > raise_error\n",
    b"ValueError during schema\n"
    b"Traceback: foreign_related_fields > resolve_related_fields\n",
    b"ValueError: harness_runtime\n"
    b"Traceback (function names only):\n"
    b"  in db_parameters\n"
    b"  in target_field\n"
    b"  in __get__\n"
    b"  in foreign_related_fields\n"
    b"  in __get__\n"
    b"  in related_fields\n"
    b"  in resolve_related_fields\n"
    b"  in resolve_related_fields\n",
    b"OperationalError\nTraceback (most recent call last):\n"
    b"  frame 1: _insert\n  frame 2: execute_sql\n  frame 3: execute\n",
    b"OperationalError: writable_storage\n"
    b"Traceback: execute > _execute_with_wrappers > _execute\n",
)


def _exhausted_fixture(
    tmp_path: Path, **changes: object
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    options: dict[str, Any] = {
        "stderr": _SCHEMA_ERRORS[1],
        "candidate_content": _DJANGO_SETUP,
        "execution_patch": {"exit_code": 2},
    }
    options.update(changes)
    return _exhausted_extract(tmp_path, **options)


@pytest.mark.parametrize("stderr", _SCHEMA_ERRORS)
def test_fixture_replay_preserves_evidence_and_reseeds_only_candidate(
    tmp_path: Path, stderr: bytes
) -> None:
    store, artifacts, exhausted = _exhausted_fixture(tmp_path, stderr=stderr)
    identity = exhausted.identity
    old_candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    old_events = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    pending = store.prepare_poc_fixture_exhaustion_replay(exhausted, artifacts)

    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 3
    assert pending.recipe_ref == exhausted.recipe_ref
    assert pending.image_digest == exhausted.image_digest
    assert old_candidate.output_refs[0] in pending.input_refs
    assert all(ref in pending.input_refs for ref in exhausted.output_refs)
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    assert artifacts.read(exhausted.output_refs[2]) == stderr
    rule = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert rule["explicit_exhaustion_replay"] is True
    assert rule["decision_origin"] == "RULE"
    assert rule["decision"]["action"] == "REGENERATE_INPUT"
    assert "Django" in rule["decision"]["guidance"]
    assert rule["original_error"]["code"] == "POC_EXECUTION_FAILED"
    assert all(ref in pending.input_refs for ref in exhausted.recovery_decision_refs)
    new_events = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    assert len(new_events) == len(old_events) + 1
    assert new_events[-1].kind is ActivityKind.DECISION_RECORDED
    assert new_events[-1].error_code == "POC_FIXTURE_EXHAUSTION_REPLAYED"
    with pytest.raises(ValueError, match="POC_FIXTURE_EXHAUSTION_"):
        store.prepare_poc_fixture_exhaustion_replay(exhausted, artifacts)


@pytest.mark.parametrize(
    "changes",
    [
        {"stderr": b"ValueError\nTraceback: unrelated"},
        {
            "stderr": (
                b"ValueError: harness_runtime\n"
                b"Traceback (function names only):\n"
                b"  in foreign_related_fields\n"
                b"  in resolve_related_fields\n"
            )
        },
        {"candidate_content": b"print('no schema setup')"},
        {"execution_patch": {"exit_code": 1}},
        {"execution_patch": {"timed_out": True}},
        {"execution_patch": {"candidate_ref": None}},
        {"cleanup_status": "UNKNOWN"},
    ],
)
def test_fixture_replay_refuses_unbound_or_unrelated_evidence_without_mutation(
    tmp_path: Path, changes: dict[str, object]
) -> None:
    store, artifacts, exhausted = _exhausted_fixture(tmp_path, **changes)
    identity = exhausted.identity
    candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    events = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    with pytest.raises(ValueError, match="POC_FIXTURE_EXHAUSTION_EVIDENCE_INVALID"):
        store.prepare_poc_fixture_exhaustion_replay(exhausted, artifacts)

    assert store.require(identity, SimpleStage.POC_CANDIDATE_DONE) == candidate
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            identity.analysis_id, hypothesis_id=identity.hypothesis_id
        )
        == events
    )


def test_fixture_replay_requires_bound_root_and_no_unresolved_codex_call(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_fixture(tmp_path)
    identity = exhausted.identity
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    store.save_checkpoint(root.model_copy(update={"error_code": "other-child"}))
    with pytest.raises(ValueError, match="POC_FIXTURE_EXHAUSTION_ROOT_BOUND_INVALID"):
        store.prepare_poc_fixture_exhaustion_replay(exhausted, artifacts)
    store.save_checkpoint(root)

    assert store.begin_codex_call("unresolved-call", identity.analysis_id)
    with pytest.raises(ValueError, match="POC_FIXTURE_EXHAUSTION_CODEX_UNRESOLVED"):
        store.prepare_poc_fixture_exhaustion_replay(exhausted, artifacts)
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted


def test_fixture_replay_rolls_back_marker_and_checkpoint_together(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_fixture(tmp_path)
    identity = exhausted.identity
    events = AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_poc_fixture_exhaustion_replay(
            exhausted, artifacts, fail_before_commit=True
        )

    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    assert (
        AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)
        == events
    )


@pytest.mark.asyncio
async def test_application_replays_fixture_only_with_explicit_flag_and_pinned_preflight(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, exhausted = _exhausted_fixture(tmp_path)
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
        repair_poc_fixture_exhaustion_hypothesis=identity.hypothesis_id,
    )
    assert (
        store.require(identity, SimpleStage.POC_CANDIDATE_DONE).status
        is StageStatus.PENDING
    )
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None


def test_cli_forwards_explicit_fixture_replay_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_fixture_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("plain", repair_poc_fixture_exhaustion_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_poc_fixture_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("progress", repair_poc_fixture_exhaustion_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = Application()
    for extra, path in [(["--format", "json"], "plain"), ([], "progress")]:
        assert main(
            [
                "resume",
                "A-001",
                "--repair-poc-fixture-exhaustion",
                "hypothesis-1",
                *extra,
            ],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (path, "hypothesis-1")
        capsys.readouterr()
