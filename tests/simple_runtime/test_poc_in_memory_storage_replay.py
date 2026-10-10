"""Explicit one-shot replay for a generated file-only SQLite PoC."""

from __future__ import annotations

import asyncio
import json
import subprocess
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

_STDERR = (
    b"RuntimeError: storage_path_unverified\n"
    b"Traceback (function names only): <module> -> main -> "
    b"configure_sqlite_storage\n"
)
_MEMORY_SOURCE = (
    b"import sqlite3\n"
    b"def make_server():\n"
    b"    return sqlite3.connect(':memory:', isolation_level=None)\n"
)
_FILE_SOURCE = (
    b"import sqlite3\ndef make_server():\n    return sqlite3.connect('app.sqlite3')\n"
)
_CANDIDATE = b"""#!/bin/sh
python3 - <<'PY'
import sqlite3
from pathlib import Path
root = Path('/workspace')

def configure_sqlite_storage():
    candidates = list(root.rglob('*.db'))
    if len(candidates) != 1:
        raise RuntimeError('storage_path_unverified')
    original_connect = sqlite3.connect

def main():
    server_source = root / 'app' / 'server.py'
    assert server_source.is_file()
    configure_sqlite_storage()

main()
PY"""


def _git(*args: str, cwd: Path) -> str:
    result = subprocess.run(
        ["git", "-C", str(cwd), *args],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    return result.stdout.strip()


def _exhausted_memory(
    tmp_path: Path,
    *,
    source: bytes = _MEMORY_SOURCE,
    candidate_content: bytes = _CANDIDATE,
    stderr: bytes = _STDERR,
    stdout: bytes = b"",
    execution_patch: dict[str, object] | None = None,
    cleanup_status: str = "REMOVED",
    manifest_paths: list[str] | None = None,
    extra_source: bytes | None = None,
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint, Path]:
    workspace = tmp_path / "data" / "workspaces" / "workspace-1"
    (workspace / "app").mkdir(parents=True)
    (workspace / "app" / "server.py").write_bytes(source)
    if extra_source is not None:
        (workspace / "app" / "route.py").write_bytes(extra_source)
    _git("init", "-q", cwd=workspace)
    _git("config", "user.name", "Fixture", cwd=workspace)
    _git("config", "user.email", "fixture@example.invalid", cwd=workspace)
    _git("add", "app", cwd=workspace)
    _git("commit", "-qm", "pinned source", cwd=workspace)
    commit = _git("rev-parse", "HEAD", cwd=workspace)
    store, artifacts, exhausted = _exhausted_extract(
        tmp_path,
        seed_commit_id=commit,
        stderr=stderr,
        stdout=stdout,
        candidate_content=candidate_content,
        execution_patch={"exit_code": 2, **(execution_patch or {})},
        cleanup_status=cleanup_status,
    )
    identity = exhausted.identity
    run = store.require_analysis_run(identity.analysis_id)
    assert run.static_coverage_ref is not None
    manifest_ref = artifacts.put_json(
        {
            "kind": "simple_tracked_sources",
            "paths": (
                manifest_paths if manifest_paths is not None else ["app/server.py"]
            ),
        }
    )
    bundle_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "static_coverage_ref": run.static_coverage_ref.model_dump(mode="json"),
            "source_manifest_ref": manifest_ref.model_dump(mode="json"),
            "poc_source_manifest_ref": manifest_ref.model_dump(mode="json"),
        }
    )
    store.save_analysis_run(run.model_copy(update={"static_bundle_ref": bundle_ref}))
    root = identity.model_copy(update={"hypothesis_id": None})
    static = store.require(root, SimpleStage.STATIC_DONE)
    store.save_checkpoint(
        static.model_copy(
            update={"output_refs": (run.repository_profile_ref, bundle_ref)}
        )
    )
    return store, artifacts, exhausted, workspace


def test_pinned_in_memory_error_reseeds_only_candidate_once(tmp_path: Path) -> None:
    store, artifacts, exhausted, _ = _exhausted_memory(tmp_path)
    identity = exhausted.identity
    before = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    old_candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)

    pending = store.prepare_poc_in_memory_storage_exhaustion_replay(
        exhausted, artifacts
    )

    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 3
    assert pending.recipe_ref == exhausted.recipe_ref
    assert pending.image_digest == exhausted.image_digest
    assert old_candidate.output_refs[0] in pending.input_refs
    assert all(ref in pending.input_refs for ref in exhausted.output_refs)
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None
    assert artifacts.read(exhausted.output_refs[2]) == _STDERR
    rule = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert rule["decision_origin"] == "RULE"
    assert rule["explicit_exhaustion_replay"] is True
    assert rule["decision"]["action"] == "REGENERATE_INPUT"
    assert "no file" in rule["decision"]["guidance"]
    assert rule["original_error"]["code"] == "POC_EXECUTION_FAILED"
    after = AgentActivityStore(store.database_path).list_analysis(
        identity.analysis_id, hypothesis_id=identity.hypothesis_id
    )
    assert len(after) == len(before) + 1
    assert after[-1].kind is ActivityKind.DECISION_RECORDED
    assert after[-1].error_code == "POC_IN_MEMORY_STORAGE_EXHAUSTION_REPLAYED"
    with pytest.raises(ValueError, match="POC_IN_MEMORY_STORAGE_EXHAUSTION_"):
        store.prepare_poc_in_memory_storage_exhaustion_replay(exhausted, artifacts)


@pytest.mark.parametrize(
    "changes",
    [
        {"source": _FILE_SOURCE},
        {"stderr": _STDERR + b"later error\n"},
        {"stdout": b"target reached\n"},
        {"candidate_content": b"#!/bin/sh\nexit 2\n"},
        {"execution_patch": {"exit_code": 1}},
        {"execution_patch": {"timed_out": True}},
        {"execution_patch": {"candidate_ref": None}},
        {"cleanup_status": "UNKNOWN"},
        {"manifest_paths": ["app/other.py"]},
    ],
)
def test_unproven_or_unbound_storage_error_does_not_mutate(
    tmp_path: Path, changes: dict[str, object]
) -> None:
    typed_changes: dict[str, Any] = changes
    store, artifacts, exhausted, _ = _exhausted_memory(tmp_path, **typed_changes)
    identity = exhausted.identity
    old_candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    events = AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)

    with pytest.raises(ValueError, match="POC_IN_MEMORY_STORAGE_EXHAUSTION_"):
        store.prepare_poc_in_memory_storage_exhaustion_replay(exhausted, artifacts)

    assert store.require(identity, SimpleStage.POC_CANDIDATE_DONE) == old_candidate
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    assert (
        AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)
        == events
    )


def test_modified_checkout_rejected_even_when_committed_blob_is_in_memory(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted, workspace = _exhausted_memory(tmp_path)
    (workspace / "app" / "server.py").write_bytes(_FILE_SOURCE)
    with pytest.raises(ValueError, match="POC_IN_MEMORY_STORAGE_EXHAUSTION_"):
        store.prepare_poc_in_memory_storage_exhaustion_replay(exhausted, artifacts)


def test_other_claimed_source_with_file_backed_sqlite_rejects_replay(
    tmp_path: Path,
) -> None:
    candidate = _CANDIDATE.replace(
        b"    server_source = root / 'app' / 'server.py'\n",
        b"    route_source = root / 'app' / 'route.py'\n"
        b"    server_source = root / 'app' / 'server.py'\n",
    )
    store, artifacts, exhausted, _ = _exhausted_memory(
        tmp_path,
        candidate_content=candidate,
        extra_source=b"import sqlite3\nconnection = sqlite3 . connect('file.db')\n",
        manifest_paths=["app/route.py", "app/server.py"],
    )
    with pytest.raises(ValueError, match="POC_IN_MEMORY_STORAGE_EXHAUSTION_"):
        store.prepare_poc_in_memory_storage_exhaustion_replay(exhausted, artifacts)


def test_root_or_unresolved_call_prevents_storage_replay(tmp_path: Path) -> None:
    store, artifacts, exhausted, _ = _exhausted_memory(tmp_path)
    identity = exhausted.identity
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    store.save_checkpoint(root.model_copy(update={"error_code": "other-child"}))
    with pytest.raises(ValueError, match="ROOT_BOUND_INVALID"):
        store.prepare_poc_in_memory_storage_exhaustion_replay(exhausted, artifacts)
    store.save_checkpoint(root)
    assert store.begin_codex_call("unresolved-call", identity.analysis_id)
    with pytest.raises(ValueError, match="CODEX_UNRESOLVED"):
        store.prepare_poc_in_memory_storage_exhaustion_replay(exhausted, artifacts)


def test_storage_replay_marker_and_checkpoint_roll_back_atomically(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted, _ = _exhausted_memory(tmp_path)
    identity = exhausted.identity
    events = AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_poc_in_memory_storage_exhaustion_replay(
            exhausted, artifacts, fail_before_commit=True
        )
    assert store.require(identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    assert (
        AgentActivityStore(store.database_path).list_analysis(identity.analysis_id)
        == events
    )


def test_application_requires_explicit_in_memory_storage_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, exhausted, _ = _exhausted_memory(tmp_path)
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
            repair_poc_in_memory_storage_exhaustion_hypothesis=identity.hypothesis_id,
        )
    )
    assert (
        store.require(identity, SimpleStage.POC_CANDIDATE_DONE).status
        is StageStatus.PENDING
    )
    assert store.get(identity, SimpleStage.POC_EXECUTION_DONE) is None


def test_cli_forwards_explicit_in_memory_storage_replay_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_in_memory_storage_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(
                ("plain", repair_poc_in_memory_storage_exhaustion_hypothesis)
            )
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_poc_in_memory_storage_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(
                ("progress", repair_poc_in_memory_storage_exhaustion_hypothesis)
            )
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = Application()
    for extra, route in [(["--format", "json"], "plain"), ([], "progress")]:
        assert main(
            [
                "resume",
                "A-001",
                "--repair-poc-in-memory-storage-exhaustion",
                "hypothesis-1",
                *extra,
            ],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (route, "hypothesis-1")
        capsys.readouterr()
