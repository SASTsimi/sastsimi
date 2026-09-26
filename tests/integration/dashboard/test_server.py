from __future__ import annotations

import hashlib
import json
import threading
import urllib.error
import urllib.request
from contextlib import contextmanager

import pytest

from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.dashboard.server import create_server
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def seed(data_dir) -> None:
    database = data_dir / "db" / "sastsimi.sqlite3"
    AnalysisDisplayIdStore(database).get_or_allocate("analysis-1")
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    SimpleCheckpointStore(database).save_success(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.POC_CANDIDATE_DONE,
            status=StageStatus.PENDING,
            input_refs=(),
            input_hash=input_reference_hash(()),
        ),
        outputs=(),
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
    artifacts = SimpleArtifactRepository(data_dir, identity)
    gate_ref = artifacts.put_json(
        {"kind": "simple_technical_gate", "result": {"status": "ACCEPT"}}
    )
    store = SimpleCheckpointStore(database)
    for stage, inputs, outputs in (
        (SimpleStage.TECH_GATE_DONE, (), (gate_ref,)),
        (SimpleStage.FINDING_DONE, (), (finding_ref,)),
        (
            SimpleStage.REPORT_DONE,
            (finding_ref,),
            (
                artifacts.put_json({"kind": "draft"}),
                artifacts.put_bytes(b"# report", "text/markdown"),
            ),
        ),
    ):
        store.save_checkpoint(
            StageCheckpoint(
                identity=identity,
                stage=stage,
                stage_version=STAGE_VERSION[stage],
                status=StageStatus.SUCCEEDED,
                input_refs=inputs,
                input_hash=input_reference_hash(inputs),
                output_refs=outputs,
                gate_decision="ACCEPT" if stage is SimpleStage.TECH_GATE_DONE else None,
                markdown_path=str(report) if stage is SimpleStage.REPORT_DONE else None,
            )
        )


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


def test_server_rejects_non_loopback_bind(tmp_path) -> None:
    with pytest.raises(ValueError, match="DASHBOARD_LOOPBACK_ONLY"):
        create_server(tmp_path, host="0.0.0.0", port=8765)


# mypy: disable-error-code="no-untyped-def"
