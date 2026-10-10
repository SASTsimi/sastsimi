"""A bounded one-shot replay for a variadic HTTP server constructor PoC."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from sastsimi.interfaces.cli.exit_codes import ExitCode
from sastsimi.interfaces.cli.main import main
from sastsimi.observability.agent_activity import ActivityKind
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
from tests.simple_runtime.test_poc_in_memory_storage_replay import _exhausted_memory
from tests.unit.interfaces.test_public_simple_cli import _config, _PublicApplication

_SERVER_SOURCE = b"""import sqlite3
from http.server import ThreadingHTTPServer

def make_server():
    return sqlite3.connect(':memory:', isolation_level=None)

class VulnHTTPServer(ThreadingHTTPServer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
"""
_CANDIDATE = b"""#!/bin/sh
python3 - <<'PY'
import inspect
from pathlib import Path
root = Path('/workspace')

def server_arguments(server_class, handler_class):
    args, kwargs = [], {}
    for name, parameter in inspect.signature(server_class).parameters.items():
        if parameter.kind in (
            inspect.Parameter.VAR_POSITIONAL,
            inspect.Parameter.VAR_KEYWORD,
        ):
            continue
    return args, kwargs

def main():
    server_source = root / 'app' / 'server.py'
    server_class = importlib.import_module('app.server').VulnHTTPServer
    arguments = server_arguments(server_class, handler_class)
    server = server_class(*arguments[0], **arguments[1])
    response = client.get('/docs')

main()
PY
"""
_STDERR = (
    b"TypeError: runtime_failure\n"
    b"Traceback (function names only): <module> -> main -> __init__\n"
)


def _exhausted_fourth(
    tmp_path: Path,
    *,
    source: bytes = _SERVER_SOURCE,
    candidate_content: bytes = _CANDIDATE,
    stderr: bytes = _STDERR,
    stdout: bytes = b"",
    cleanup_status: str = "REMOVED",
) -> tuple[SimpleCheckpointStore, SimpleArtifactRepository, StageCheckpoint, Path]:
    store, artifacts, third, workspace = _exhausted_memory(
        tmp_path,
        source=source,
    )
    identity = third.identity
    pending = store.prepare_poc_in_memory_storage_exhaustion_replay(third, artifacts)
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
    execution_ref = artifacts.put_json(
        {
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
    )
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
            code="POC_EXECUTION_FAILED",
            retryable=True,
            safe_message="PoC constructor failed",
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
    return store, artifacts, exhausted, workspace


def test_server_constructor_replay_preserves_prior_and_runs_once(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted, _workspace = _exhausted_fourth(tmp_path)
    before = AgentActivityStore(store.database_path).list_analysis(
        exhausted.identity.analysis_id
    )

    pending = store.prepare_poc_server_constructor_exhaustion_replay(
        exhausted, artifacts
    )

    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_number == 4
    assert store.get(exhausted.identity, SimpleStage.POC_EXECUTION_DONE) is None
    rule = json.loads(artifacts.read(pending.recovery_decision_refs[-1]))
    assert rule["explicit_exhaustion_replay"] is True
    assert rule["decision"]["category"] == "GENERATED_INPUT"
    assert rule["decision"]["action"] == "REGENERATE_INPUT"
    after = AgentActivityStore(store.database_path).list_analysis(
        exhausted.identity.analysis_id
    )
    old_ids = {event.event_id for event in before}
    new = [event for event in after if event.event_id not in old_ids]
    assert len(new) == 1
    assert new[0].kind is ActivityKind.DECISION_RECORDED
    assert new[0].error_code == "POC_SERVER_CONSTRUCTOR_EXHAUSTION_REPLAYED"
    with pytest.raises(ValueError, match="POC_SERVER_CONSTRUCTOR_EXHAUSTION_"):
        store.prepare_poc_server_constructor_exhaustion_replay(exhausted, artifacts)


@pytest.mark.parametrize(
    "change",
    [
        {"stderr": b"TypeError: unrelated\n"},
        {"stdout": b"SASTSIMI_POC_REPRODUCED\n"},
        {"cleanup_status": "UNKNOWN"},
    ],
)
def test_server_constructor_replay_rejects_unbound_evidence(
    tmp_path: Path, change: dict[str, object]
) -> None:
    typed_change: dict[str, Any] = change
    store, artifacts, exhausted, _workspace = _exhausted_fourth(
        tmp_path, **typed_change
    )
    before = AgentActivityStore(store.database_path).list_analysis(
        exhausted.identity.analysis_id
    )
    with pytest.raises(ValueError, match="POC_SERVER_CONSTRUCTOR_EXHAUSTION_"):
        store.prepare_poc_server_constructor_exhaustion_replay(exhausted, artifacts)
    assert (
        store.require(exhausted.identity, SimpleStage.POC_EXECUTION_DONE) == exhausted
    )
    assert (
        AgentActivityStore(store.database_path).list_analysis(
            exhausted.identity.analysis_id
        )
        == before
    )


def test_server_constructor_replay_requires_prior_and_pinned_source(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted, workspace = _exhausted_fourth(tmp_path)
    source_file = workspace / "app" / "server.py"
    source_file.write_bytes(_SERVER_SOURCE + b"# changed after commit\n")
    with pytest.raises(ValueError, match="POC_SERVER_CONSTRUCTOR_EXHAUSTION_"):
        store.prepare_poc_server_constructor_exhaustion_replay(exhausted, artifacts)
    source_file.write_bytes(_SERVER_SOURCE)
    altered = exhausted.model_copy(update={"recovery_decision_refs": ()})
    store.save_checkpoint(altered)
    with pytest.raises(
        ValueError, match="POC_SERVER_CONSTRUCTOR_EXHAUSTION_PRIOR_INVALID"
    ):
        store.prepare_poc_server_constructor_exhaustion_replay(altered, artifacts)


def test_server_constructor_replay_rejects_other_root_and_unresolved_call(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted, _workspace = _exhausted_fourth(tmp_path)
    root_identity = exhausted.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    store.save_checkpoint(root.model_copy(update={"error_code": "other-child"}))
    with pytest.raises(
        ValueError, match="POC_SERVER_CONSTRUCTOR_EXHAUSTION_ROOT_BOUND_INVALID"
    ):
        store.prepare_poc_server_constructor_exhaustion_replay(exhausted, artifacts)
    store.save_checkpoint(root)
    assert store.begin_codex_call("unresolved", exhausted.identity.analysis_id)
    with pytest.raises(
        ValueError, match="POC_SERVER_CONSTRUCTOR_EXHAUSTION_CODEX_UNRESOLVED"
    ):
        store.prepare_poc_server_constructor_exhaustion_replay(exhausted, artifacts)


def test_server_constructor_replay_marker_and_checkpoint_are_atomic(
    tmp_path: Path,
) -> None:
    store, artifacts, exhausted, _workspace = _exhausted_fourth(tmp_path)
    before = AgentActivityStore(store.database_path).list_analysis(
        exhausted.identity.analysis_id
    )
    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_poc_server_constructor_exhaustion_replay(
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


def test_cli_forwards_server_constructor_replay_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class Application(_PublicApplication):
        def __init__(self) -> None:
            self.seen: list[tuple[str, str | None]] = []

        def resume(
            self,
            analysis_id: str,
            *,
            repair_poc_server_constructor_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(
                ("plain", repair_poc_server_constructor_exhaustion_hypothesis)
            )
            return {"analysis_id": analysis_id, "status": "RUNNING"}

        def resume_with_progress(
            self,
            analysis_id: str,
            _callback: object,
            *,
            repair_poc_server_constructor_exhaustion_hypothesis: str | None = None,
            **_kwargs: object,
        ) -> dict[str, object]:
            self.seen.append(
                ("progress", repair_poc_server_constructor_exhaustion_hypothesis)
            )
            return {"analysis_id": analysis_id, "status": "RUNNING"}

    application = Application()
    for extra, path in [(["--format", "json"], "plain"), ([], "progress")]:
        assert main(
            [
                "resume",
                "A-001",
                "--repair-poc-server-constructor-exhaustion",
                "hypothesis-1",
                *extra,
            ],
            public_application=application,
            user_config_store=_config(tmp_path),
        ) == int(ExitCode.OK)
        assert application.seen[-1] == (path, "hypothesis-1")
        capsys.readouterr()
