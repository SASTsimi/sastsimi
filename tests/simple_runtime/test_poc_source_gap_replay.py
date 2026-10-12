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
from tests.simple_runtime.test_poc_fixture_dependency_replay import (
    _exhausted_attempt_four,
)
from tests.unit.interfaces.test_public_simple_cli import _config, _PublicApplication

_SCRIPT = (
    b"django.setup()\n"
    b"stage = 'database_setup'\n"
    b"with connection.schema_editor() as editor:\n"
    b"    editor.create_model(model)\n"
    b"account = User.objects.create(username='fixture')\n"
    b"response = client.get(route)\n"
)
_STDERR = (
    b"OperationalError: fixture_setup\n"
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


def _exhausted_source_gap(
    tmp_path: Path,
    *,
    refused_path: str = "package/models.py",
    refusal_reason: str = "PROMPT_BUDGET_EXHAUSTED",
    tracked_paths: list[str] | None = None,
    source_record_kind: str = "simple_requested_sources",
    attach_source: bool = True,
    unrelated_source_first: bool = False,
    malformed_requested_first: bool = False,
    execution_patch: dict[str, object] | None = None,
    cleanup_status: str = "REMOVED",
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store, artifacts, fourth = _exhausted_attempt_four(tmp_path)
    identity = fourth.identity
    pending = store.prepare_poc_fixture_dependency_exhaustion_replay(fourth, artifacts)
    run = store.require_analysis_run(identity.analysis_id)
    assert run.static_coverage_ref is not None
    workspace = run.workspace_path
    assert workspace is not None
    file_path = workspace / "package" / "models.py"
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text("class FixtureModel: pass\n", encoding="utf-8")
    manifest_ref = artifacts.put_json(
        {
            "kind": "simple_tracked_sources",
            "paths": tracked_paths
            if tracked_paths is not None
            else ["package/models.py"],
        }
    )
    static_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "source_manifest_ref": manifest_ref.model_dump(mode="json"),
            "poc_source_manifest_ref": manifest_ref.model_dump(mode="json"),
            "static_coverage_ref": run.static_coverage_ref.model_dump(mode="json"),
        }
    )
    store.save_analysis_run(run.model_copy(update={"static_bundle_ref": static_ref}))
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    static = store.require(root_identity, SimpleStage.STATIC_DONE)
    # Retarget the synthetic historical seed before the fifth attempt without
    # trying to append a second completion event under the same stage event ID.
    connection = store._connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        store._upsert_checkpoint_connection(
            connection,
            static.model_copy(
                update={"output_refs": (run.repository_profile_ref, static_ref)}
            ),
        )
        connection.commit()
    finally:
        connection.close()
    source_ref = artifacts.put_json(
        {
            "kind": source_record_kind,
            "served": [],
            "refused": [{"path": refused_path, "reason": refusal_reason}],
            "served_bytes": 0,
        }
    )
    source_refs = []
    if unrelated_source_first:
        source_refs.append(
            artifacts.put_bytes(b"not-json", "text/plain").model_dump(mode="json")
        )
    if malformed_requested_first:
        source_refs.append(
            artifacts.put_json(
                {"kind": "simple_requested_sources", "served": [], "refused": "bad"}
            ).model_dump(mode="json")
        )
    if attach_source:
        source_refs.append(source_ref.model_dump(mode="json"))
    pro_con = store.require(identity, SimpleStage.PRO_CON_DONE)
    requested_ref = artifacts.put_json(
        {
            "kind": "simple_pro_evidence",
            "result": {"requested_paths": ["package/models.py"]},
        }
    )
    connection = store._connect()
    try:
        connection.execute("BEGIN IMMEDIATE")
        store._upsert_checkpoint_connection(
            connection,
            pro_con.model_copy(
                update={"output_refs": (*pro_con.output_refs, requested_ref)}
            ),
        )
        connection.commit()
    finally:
        connection.close()
    candidate_running = store.mark_running(
        identity,
        SimpleStage.POC_CANDIDATE_DONE,
        pending.input_refs,
        attempt_id="attempt-5",
    )
    content_ref = artifacts.put_bytes(_SCRIPT, "text/x-shellscript")
    candidate_ref = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "attempt_id": "attempt-5",
            "content_ref": content_ref.model_dump(mode="json"),
            "content_digest": hashlib.sha256(_SCRIPT).hexdigest(),
            "source_refs": source_refs,
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
        attempt_id="attempt-5",
        inherit_from=candidate,
    )
    stdout_ref = artifacts.put_bytes(b"", "text/plain")
    stderr_ref = artifacts.put_bytes(_STDERR, "text/plain")
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
            safe_message="PoC setup failed",
            evidence_refs=evidence,
        ),
        StageStatus.BLOCKED,
    )
    exhausted = store.mark_recovery_exhausted(failed)
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


def test_source_gap_replay_requires_requested_pinned_python_and_reseeds_once(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_source_gap(tmp_path)
    identity = exhausted.identity
    before = AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)

    pending = store.prepare_poc_source_gap_exhaustion_replay(exhausted, artifacts)

    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 5
    assert pending.recipe_ref == exhausted.recipe_ref
    assert pending.image_digest == exhausted.image_digest
    assert all(ref in pending.input_refs for ref in exhausted.output_refs)
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    rule = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert rule["explicit_exhaustion_replay"] is True
    assert rule["decision"]["action"] == "REGENERATE_INPUT"
    assert "pinned" in rule["decision"]["guidance"]
    assert "vulnerability" in rule["decision"]["guidance"]
    assert "package/models.py" not in json.dumps(rule)
    after = AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)
    assert len(after) == len(before) + 1
    new_events = [
        event
        for event in after
        if event.event_id not in {old.event_id for old in before}
    ]
    assert len(new_events) == 1
    assert new_events[0].kind is ActivityKind.DECISION_RECORDED
    assert new_events[0].error_code == "POC_SOURCE_GAP_EXHAUSTION_REPLAYED"
    with pytest.raises(ValueError, match="POC_SOURCE_GAP_EXHAUSTION_"):
        store.prepare_poc_source_gap_exhaustion_replay(exhausted, artifacts)


def test_source_gap_replay_ignores_unrelated_non_json_ref_before_valid_evidence(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_source_gap(
        tmp_path, unrelated_source_first=True
    )

    pending = store.prepare_poc_source_gap_exhaustion_replay(exhausted, artifacts)

    assert pending.status is StageStatus.PENDING


def test_source_gap_replay_rejects_malformed_requested_source_even_if_later_valid(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_source_gap(
        tmp_path, malformed_requested_first=True
    )
    before = AgentActivityStore(store.database_path).list_analysis(
        exhausted.identity.analysis_id
    )

    with pytest.raises(ValueError, match="POC_SOURCE_GAP_EXHAUSTION_EVIDENCE_INVALID"):
        store.prepare_poc_source_gap_exhaustion_replay(exhausted, artifacts)

    assert (
        store.require(exhausted.identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    )
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            exhausted.identity.analysis_id
        )
        == before
    )


@pytest.mark.parametrize(
    "change",
    [
        {"refused_path": "package/missing.py"},
        {"refused_path": "package/models.js"},
        {"refused_path": "../package/models.py"},
        {"refusal_reason": "TOTAL_BUDGET_EXHAUSTED"},
        {"source_record_kind": "other"},
        {"attach_source": False},
        {"tracked_paths": ["different/models.py"]},
        {"execution_patch": {"exit_code": 1}},
        {"execution_patch": {"timed_out": True}},
        {"cleanup_status": "UNKNOWN"},
    ],
)
def test_source_gap_replay_rejects_unrelated_or_unbound_evidence_without_mutation(
    tmp_path: Path, change: dict[str, object]
) -> None:
    typed_change: dict[str, Any] = change
    store, artifacts, exhausted = _exhausted_source_gap(tmp_path, **typed_change)
    identity = exhausted.identity
    candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    before = AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)
    with pytest.raises(ValueError, match="POC_SOURCE_GAP_EXHAUSTION_"):
        store.prepare_poc_source_gap_exhaustion_replay(exhausted, artifacts)
    assert store.require(identity, SimpleStage.POC_CANDIDATE_DONE) == candidate
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    assert (
        AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)
        == before
    )


def test_source_gap_replay_rejects_changed_root_and_unresolved_child(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_source_gap(tmp_path)
    root_identity = exhausted.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    store.save_checkpoint(root.model_copy(update={"error_code": "other-child"}))
    with pytest.raises(
        ValueError, match="POC_SOURCE_GAP_EXHAUSTION_ROOT_BOUND_INVALID"
    ):
        store.prepare_poc_source_gap_exhaustion_replay(exhausted, artifacts)
    store.save_checkpoint(root)
    assert store.begin_codex_call("unresolved", exhausted.identity.analysis_id)
    with pytest.raises(ValueError, match="POC_SOURCE_GAP_EXHAUSTION_CODEX_UNRESOLVED"):
        store.prepare_poc_source_gap_exhaustion_replay(exhausted, artifacts)


def test_source_gap_replay_requires_both_prior_markers_and_exact_fifth_attempt(
    tmp_path: Path,
) -> None:
    old_store, old_artifacts, fourth = _exhausted_attempt_four(tmp_path / "fourth")
    with pytest.raises(ValueError, match="POC_SOURCE_GAP_EXHAUSTION_INVALID"):
        old_store.prepare_poc_source_gap_exhaustion_replay(fourth, old_artifacts)

    store, artifacts, fifth = _exhausted_source_gap(tmp_path / "fifth")
    altered = fifth.model_copy(update={"recovery_decision_refs": ()})
    store.save_checkpoint(altered)
    with pytest.raises(ValueError, match="POC_SOURCE_GAP_EXHAUSTION_PRIOR_INVALID"):
        store.prepare_poc_source_gap_exhaustion_replay(altered, artifacts)


def test_source_gap_replay_marker_and_checkpoint_rollback_together(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_source_gap(tmp_path)
    before = AgentActivityStore(store.database_path).list_analysis(
        exhausted.identity.analysis_id
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_poc_source_gap_exhaustion_replay(
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


def test_application_requires_explicit_source_gap_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, exhausted = _exhausted_source_gap(tmp_path)
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
    with pytest.raises(ValueError, match="LEGACY_IMPORT_STOP_REPAIR_CONFLICT"):
        asyncio.run(
            application.resume(
                identity.analysis_id,
                repair_poc_source_gap_exhaustion_hypothesis=identity.hypothesis_id,
                repair_poc_fixture_dependency_exhaustion_hypothesis=identity.hypothesis_id,
            )
        )
    asyncio.run(
        application.resume(
            identity.analysis_id,
            repair_poc_source_gap_exhaustion_hypothesis=identity.hypothesis_id,
        )
    )
    assert (
        store.require(identity, SimpleStage.POC_CANDIDATE_DONE).status
        is StageStatus.PENDING
    )
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None


def test_cli_forwards_explicit_source_gap_replay_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_source_gap_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("plain", repair_poc_source_gap_exhaustion_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_poc_source_gap_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(("progress", repair_poc_source_gap_exhaustion_hypothesis))
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = Application()
    for extra, path in [(["--format", "json"], "plain"), ([], "progress")]:
        assert main(
            [
                "resume",
                "A-001",
                "--repair-poc-source-gap-exhaustion",
                "hypothesis-1",
                *extra,
            ],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (path, "hypothesis-1")
        capsys.readouterr()
