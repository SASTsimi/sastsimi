"""One explicit replay for a pinned local module lost by a generated PoC."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TypedDict
from uuid import uuid4

import pytest

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

_LOCAL_IMPORT_STDERR = (
    b"ModuleNotFoundError: package_fixture\n"
    b"Traceback: _gcd_import -> _find_and_load -> exec_module\n"
)
_CANDIDATE = (
    b"#!/bin/sh\ncd /workspace\npython3 - <<'PY'\n"
    b"import importlib, sys\n"
    b"sys.path[:] = ['/workspace/package_fixture']\n"
    b"importlib.import_module('handlers')\nPY\n"
)


class _ImportOverrides(TypedDict, total=False):
    stderr: bytes
    stdout: bytes
    execution_patch: dict[str, object]
    cleanup_status: str


def _exhausted_import(
    tmp_path: Path,
    *,
    budget_root: bool = False,
    stderr: bytes = _LOCAL_IMPORT_STDERR,
    stdout: bytes = b"",
    execution_patch: dict[str, object] | None = None,
    cleanup_status: str = "REMOVED",
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint]:
    store, artifacts, exhausted = _exhausted_extract(
        tmp_path,
        stderr=stderr,
        stdout=stdout,
        execution_patch=(
            execution_patch if execution_patch is not None else {"exit_code": 2}
        ),
        cleanup_status=cleanup_status,
        failure_code="POC_RUNTIME_IMPORT_FAILED",
        candidate_content=_CANDIDATE,
        root_error_code=("LLM_TOKEN_BUDGET_EXHAUSTED" if budget_root else None),
    )
    workspace = tmp_path / "data" / "workspaces" / exhausted.identity.workspace_id
    package = workspace / "package_fixture"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "handlers.py").write_text("import package_fixture\n", encoding="utf-8")
    return store, artifacts, exhausted


@pytest.mark.parametrize("budget_root", [False, True])
def test_local_import_exhaustion_replays_only_candidate_once(
    tmp_path: Path, budget_root: bool
) -> None:
    store, artifacts, exhausted = _exhausted_import(tmp_path, budget_root=budget_root)
    identity = exhausted.identity
    initial = store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE)
    original_events = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    pending = store.prepare_poc_local_import_exhaustion_replay(exhausted, artifacts)

    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 3
    assert pending.image_digest == exhausted.image_digest
    assert pending.recipe_ref == exhausted.recipe_ref
    assert store.require(identity, SimpleStage.VERIFICATION_INITIAL_DONE) == initial
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    assert all(ref in pending.input_refs for ref in exhausted.output_refs)
    rule = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert rule["decision"]["action"] == "REGENERATE_INPUT"
    assert rule["original_error"]["code"] == "POC_RUNTIME_IMPORT_FAILED"
    assert rule["diagnostic_excerpt"] == _LOCAL_IMPORT_STDERR.decode().strip()
    assert rule["explicit_exhaustion_replay"] is True
    events = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    assert events[:-1] == original_events
    assert events[-1].kind is ActivityKind.DECISION_RECORDED
    assert events[-1].error_code == "POC_LOCAL_IMPORT_EXHAUSTION_REPLAYED"
    with pytest.raises(ValueError, match="POC_LOCAL_IMPORT_EXHAUSTION_"):
        store.prepare_poc_local_import_exhaustion_replay(exhausted, artifacts)


def test_local_import_replay_allows_prior_stdout_diagnostics(tmp_path: Path) -> None:
    store, artifacts, exhausted = _exhausted_import(
        tmp_path,
        budget_root=True,
        stdout=b"DIRECT_CONTROL=True\nDIRECT_ALTERED_QUERY=True\n",
    )

    pending = store.prepare_poc_local_import_exhaustion_replay(exhausted, artifacts)

    assert pending.status is StageStatus.PENDING
    rule = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert rule["diagnostic_excerpt"] == _LOCAL_IMPORT_STDERR.decode().strip()
    assert "DIRECT_CONTROL" not in rule["diagnostic_excerpt"]


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        (
            {"stderr": b"ModuleNotFoundError: jwt\nTraceback: exec_module\n"},
            "EVIDENCE_INVALID",
        ),
        ({"stderr": _LOCAL_IMPORT_STDERR + b"other error\n"}, "EVIDENCE_INVALID"),
        ({"cleanup_status": "BLOCKED"}, "EVIDENCE_INVALID"),
        ({"execution_patch": {"exit_code": 1}}, "EVIDENCE_INVALID"),
        (
            {"execution_patch": {"candidate_ref": None, "exit_code": 2}},
            "EVIDENCE_INVALID",
        ),
        (
            {
                "stdout": b"ModuleNotFoundError: jwt\nTraceback: exec_module\n",
            },
            "EVIDENCE_INVALID",
        ),
        ({"stdout": b"REPRODUCED\n"}, "EVIDENCE_INVALID"),
    ],
)
def test_local_import_replay_rejects_unproven_or_unsafe_execution_without_mutation(
    tmp_path: Path, overrides: _ImportOverrides, expected: str
) -> None:
    store, artifacts, exhausted = _exhausted_import(tmp_path, **overrides)
    identity = exhausted.identity
    candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    events = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )

    with pytest.raises(ValueError, match="POC_LOCAL_IMPORT_EXHAUSTION_" + expected):
        store.prepare_poc_local_import_exhaustion_replay(exhausted, artifacts)

    assert store.require(identity, SimpleStage.POC_CANDIDATE_DONE) == candidate
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            identity.analysis_id, hypothesis_id=identity.hypothesis_id
        )
        == events
    )


def test_local_import_replay_requires_exact_budget_root_event(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted = _exhausted_import(tmp_path, budget_root=True)
    root_id = exhausted.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_id, SimpleStage.HYPOTHESIS_DONE)
    store.save_checkpoint(root.model_copy(update={"attempt_id": "different-root"}))

    with pytest.raises(
        ValueError, match="POC_LOCAL_IMPORT_EXHAUSTION_ROOT_BOUND_INVALID"
    ):
        store.prepare_poc_local_import_exhaustion_replay(exhausted, artifacts)


def test_local_import_replay_requires_source_import_proof(tmp_path: Path) -> None:
    store, artifacts, exhausted = _exhausted_import(tmp_path)
    workspace = tmp_path / "data" / "workspaces" / exhausted.identity.workspace_id
    (workspace / "package_fixture" / "handlers.py").write_text(
        "import os\n", encoding="utf-8"
    )

    with pytest.raises(
        ValueError, match="POC_LOCAL_IMPORT_EXHAUSTION_EVIDENCE_INVALID"
    ):
        store.prepare_poc_local_import_exhaustion_replay(exhausted, artifacts)


def test_local_import_replay_refuses_active_run_and_codex_call(tmp_path: Path) -> None:
    store, artifacts, exhausted = _exhausted_import(tmp_path)
    identity = exhausted.identity
    unrelated = store.require(identity, SimpleStage.PRO_CON_DONE)
    store.save_checkpoint(unrelated.model_copy(update={"status": StageStatus.PENDING}))
    with pytest.raises(ValueError, match="POC_LOCAL_IMPORT_EXHAUSTION_RUN_ACTIVE"):
        store.prepare_poc_local_import_exhaustion_replay(exhausted, artifacts)
    store.save_checkpoint(unrelated)

    assert store.begin_codex_call("unresolved-local-import", identity.analysis_id)
    with pytest.raises(
        ValueError, match="POC_LOCAL_IMPORT_EXHAUSTION_CODEX_UNRESOLVED"
    ):
        store.prepare_poc_local_import_exhaustion_replay(exhausted, artifacts)


def test_local_import_replay_refuses_existing_marker(tmp_path: Path) -> None:
    store, artifacts, exhausted = _exhausted_import(tmp_path)
    identity = exhausted.identity
    anchor = store.stage_activity(
        identity, SimpleStage.POC_EXECUTION_DONE, exhausted.attempt_id or ""
    )[-1]
    AgentActivityStore(store.database_path).append(
        anchor.model_copy(
            update={
                "event_id": uuid4().hex,
                "sequence": 9_999,
                "kind": ActivityKind.DECISION_RECORDED,
                "error_code": "POC_LOCAL_IMPORT_EXHAUSTION_REPLAYED",
                "output_refs": (),
            }
        )
    )

    with pytest.raises(
        ValueError, match="POC_LOCAL_IMPORT_EXHAUSTION_ALREADY_REPLAYED"
    ):
        store.prepare_poc_local_import_exhaustion_replay(exhausted, artifacts)


@pytest.mark.asyncio
async def test_explicit_resume_routes_local_import_to_candidate_replay(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, exhausted = _exhausted_import(tmp_path, budget_root=True)
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
        repair_fallback_poc_stop_hypothesis=identity.hypothesis_id,
    )
    assert store.require(identity, SimpleStage.POC_CANDIDATE_DONE).status is (
        StageStatus.PENDING
    )
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
