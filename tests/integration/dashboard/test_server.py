from __future__ import annotations

import hashlib
import json
import threading
import urllib.error
import urllib.request
import zipfile
from contextlib import contextmanager
from datetime import UTC, datetime
from io import BytesIO

import pytest

from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.dashboard.server import create_server
from sastsimi.observability.agent_activity import ActivityKind, AgentActivityEvent
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore


def seed(data_dir) -> None:
    database = data_dir / "db" / "sastsimi.sqlite3"
    AnalysisDisplayIdStore(database).get_or_allocate("analysis-1")
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(data_dir, identity)
    llm_request = artifacts.put_json(
        {
            "kind": "simple_llm_request",
            "invocation_id": "simple-1",
            "provider": "codex-cli",
            "model": "gpt-test",
            "prompt": "api_key=do-not-show",
            "output_schema": {"type": "object"},
        }
    )
    llm_response = artifacts.put_json(
        {
            "kind": "simple_llm_response",
            "invocation_id": "simple-1",
            "provider": "codex-cli",
            "model": "gpt-test",
            "response": {"verdict": "TRUE"},
            "usage": {"input_tokens": 10, "output_tokens": 4},
        }
    )
    hypothesis_request = artifacts.put_json(
        {
            "kind": "simple_llm_request",
            "invocation_id": "simple-hypothesis",
            "provider": "codex-cli",
            "model": "gpt-test",
            "prompt": "review static facts",
            "output_schema": {"type": "object"},
        }
    )
    hypothesis_response = artifacts.put_json(
        {
            "kind": "simple_llm_response",
            "invocation_id": "simple-hypothesis",
            "provider": "codex-cli",
            "model": "gpt-test",
            "response": {"hypotheses": []},
            "usage": {"input_tokens": None, "output_tokens": None},
        }
    )
    hypothesis_proposal = artifacts.put_json(
        {
            "kind": "simple_hypothesis_proposal",
            "llm_request_ref": hypothesis_request.model_dump(mode="json"),
            "llm_response_ref": hypothesis_response.model_dump(mode="json"),
        }
    )
    poc = artifacts.put_json(
        {
            "kind": "simple_validated_poc",
            "result": "reproduced",
            "llm_request_ref": llm_request.model_dump(mode="json"),
            "llm_response_ref": llm_response.model_dump(mode="json"),
        }
    )
    static_bundle = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "opengrep_findings": [{"path": "app.py"}],
            "codeql_findings": [],
            "codeql_executed": True,
        }
    )
    store = SimpleCheckpointStore(database)
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id="analysis-1",
            display_analysis_id="A-001",
            workspace_id="workspace-1",
            commit_id="commit-1",
            repository="https://example.invalid/repository.git",
            profile_ref="profile-test",
            provider="codex-cli",
            model="gpt-test",
            static_bundle_ref=static_bundle,
            hypothesis_ids=("hypothesis-1",),
        )
    )
    store.save_success(
        StageCheckpoint(
            identity=identity.model_copy(update={"hypothesis_id": None}),
            stage=SimpleStage.HYPOTHESIS_DONE,
            status=StageStatus.PENDING,
            input_refs=(),
            input_hash=input_reference_hash(()),
        ),
        outputs=(hypothesis_proposal,),
    )
    store.save_success(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.POC_CANDIDATE_DONE,
            status=StageStatus.PENDING,
            input_refs=(),
            input_hash=input_reference_hash(()),
            validated_poc_ref=poc,
        ),
        outputs=(poc,),
    )
    AgentActivityStore(database).append(
        AgentActivityEvent(
            event_id="event-llm-1",
            analysis_id="analysis-1",
            workspace_id="workspace-1",
            commit_id="commit-1",
            hypothesis_id="hypothesis-1",
            stage="POC_CANDIDATE_DONE",
            agent_role="PoC Agent",
            attempt_id="attempt-1",
            sequence=1,
            kind=ActivityKind.STAGE_COMPLETED,
            status="SUCCEEDED",
            summary_ko="PoC 후보를 생성했습니다.",
            output_refs=(poc,),
            tool_result_refs=(llm_request, llm_response),
            provider="codex-cli",
            model="gpt-test",
            prompt_digest="0" * 64,
            output_digest="1" * 64,
            started_at=datetime.now(UTC),
        )
    )
    finding_ref = StoredDataRef(
        stored_data_id=StoredDataId("finding-stored"),
        data_kind="finding",
        content_hash=hashlib.sha256(b"finding").hexdigest(),
        workspace_id=WorkspaceId("workspace-1"),
        commit_id=CommitId("commit-1"),
        record_id=None,
    )
    FindingDisplayIdStore(database).get_or_allocate("analysis-1", finding_ref)
    report = data_dir / "reports" / "analysis-1" / "F-001.md"
    report.parent.mkdir(parents=True)
    report.write_text("# 한국어 보고서", encoding="utf-8")
    report.with_name("F-001.en.md").write_text("# English report", encoding="utf-8")
    logs = data_dir / "logs" / "analysis-1.log"
    logs.parent.mkdir(parents=True)
    logs.write_text("stage=POC_CANDIDATE_DONE status=SUCCEEDED\n", encoding="utf-8")


@contextmanager
def running_server(data_dir):
    server = create_server(data_dir, host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def request(url: str, *, method: str = "GET"):
    try:
        return urllib.request.urlopen(
            urllib.request.Request(url, method=method), timeout=5
        )
    except urllib.error.HTTPError as error:
        return error


def test_server_is_local_read_only_and_serves_current_state(tmp_path) -> None:
    seed(tmp_path)
    with running_server(tmp_path) as base:
        response = request(f"{base}/api/analyses")
        payload = json.loads(response.read())
        assert response.status == 200
        assert payload[0]["analysis_id"] == "analysis-1"
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert request(f"{base}/api/analyses", method="POST").status == 405
        assert request(f"{base}/analyses/A-001").status == 200
        assert (
            json.loads(request(f"{base}/api/analyses/A-001").read())["analysis_id"]
            == "analysis-1"
        )
        assert request(f"{base}/reports/analysis-1/F-001.md").read().decode() == (
            "# 한국어 보고서"
        )


def test_server_serves_redacted_artifacts_reports_logs_and_bundle(tmp_path) -> None:
    seed(tmp_path)
    with running_server(tmp_path) as base:
        detail = json.loads(request(f"{base}/api/analyses/A-001").read())
        assert detail["static_tools"][1] == {
            "tool": "OpenGrep",
            "status": "NOT_STARTED",
            "finding_count": 1,
        }
        assert detail["commit_id"] == "commit-1"
        assert detail["profile_ref"] == "profile-test"
        assert detail["provider"] == "codex-cli"
        assert detail["model"] == "gpt-test"
        assert len(detail["llm_invocations"]) == 2
        invocation = next(
            item
            for item in detail["llm_invocations"]
            if item["invocation_id"] == "simple-1"
        )
        hypothesis_invocation = next(
            item
            for item in detail["llm_invocations"]
            if item["invocation_id"] == "simple-hypothesis"
        )
        assert hypothesis_invocation["stage"] == "HYPOTHESIS_DONE"
        assert hypothesis_invocation["agent_role"] == "Hypothesis Agent"
        request_id = invocation["request_artifact_id"]
        artifact = json.loads(
            request(f"{base}/api/analyses/A-001/artifacts/{request_id}").read()
        )
        assert "do-not-show" not in json.dumps(artifact)
        assert "[REDACTED:CREDENTIAL]" in json.dumps(artifact)

        downloaded = request(
            f"{base}/api/analyses/A-001/artifacts/{request_id}?download=1"
        )
        assert downloaded.headers["Content-Disposition"].startswith("attachment;")
        assert "do-not-show" not in downloaded.read().decode()

        report = json.loads(
            request(f"{base}/api/analyses/A-001/reports/F-001").read()
        )
        assert report["markdown"] == "# 한국어 보고서"
        assert "POC_CANDIDATE_DONE" in request(
            f"{base}/api/analyses/A-001/logs/download"
        ).read().decode()

        bundle = request(f"{base}/api/analyses/A-001/bundle.zip").read()
        with zipfile.ZipFile(BytesIO(bundle)) as archive:
            names = set(archive.namelist())
            assert "manifest.json" in names
            assert "reports/F-001.md" in names
            assert "reports/en/F-001.md" in names
            assert "logs/console.log" in names
            assert any(
                name.startswith("artifacts/simple_validated_poc-")
                for name in names
            )

        selected_bundle = request(
            f"{base}/api/analyses/A-001/bundle.zip?selected=1&artifact={request_id}"
        ).read()
        with zipfile.ZipFile(BytesIO(selected_bundle)) as archive:
            names = set(archive.namelist())
            assert "manifest.json" in names
            assert "logs/console.log" not in names
            assert "reports/F-001.md" not in names
            assert len([name for name in names if name.startswith("artifacts/")]) == 1
        assert request(
            f"{base}/api/analyses/A-001/artifacts/..%2Fsecret"
        ).status == 404
        assert request(
            f"{base}/api/analyses/A-001/bundle.zip?selected=1&artifact={'0' * 64}"
        ).status == 404


def test_server_rejects_non_loopback_bind(tmp_path) -> None:
    with pytest.raises(ValueError, match="DASHBOARD_LOOPBACK_ONLY"):
        create_server(tmp_path, host="0.0.0.0", port=8765)


# mypy: disable-error-code="no-untyped-def"
