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

from sastsimi.contracts.ids import CommitId, RecordId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.dashboard.server import create_server
from sastsimi.observability.agent_activity import ActivityKind, AgentActivityEvent
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_group_report_projection import _reported_case
from tests.support.current_bundle import attach_current_bundle


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
    poc_source = artifacts.put_bytes(b"#!/bin/sh\nprintf ok\n", "text/x-shellscript")
    poc_candidate = artifacts.put_json(
        {
            "kind": "simple_poc_candidate",
            "content_ref": poc_source.model_dump(mode="json"),
            "attempt_id": "candidate-attempt",
        }
    )
    poc_stdout = artifacts.put_bytes(b"ok", "text/plain")
    poc_stderr = artifacts.put_bytes(b"", "text/plain")
    poc_execution = artifacts.put_json(
        {
            "kind": "simple_poc_execution",
            "candidate_ref": poc_candidate.model_dump(mode="json"),
            "content_ref": poc_source.model_dump(mode="json"),
            "attempt_id": "dynamic-attempt",
            "stdout_ref": poc_stdout.model_dump(mode="json"),
            "stderr_ref": poc_stderr.model_dump(mode="json"),
            "exit_code": 0,
        }
    )
    poc = artifacts.put_json(
        {
            "kind": "simple_validated_poc",
            "result": "reproduced",
            "candidate_ref": poc_candidate.model_dump(mode="json"),
            "content_ref": poc_source.model_dump(mode="json"),
            "execution_ref": poc_execution.model_dump(mode="json"),
            "attempt_id": "dynamic-attempt",
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
            stage_version=STAGE_VERSION[SimpleStage.POC_CANDIDATE_DONE],
            status=StageStatus.PENDING,
            input_refs=(),
            input_hash=input_reference_hash(()),
            attempt_id="candidate-attempt",
        ),
        outputs=(poc_candidate, poc_source),
    )
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.POC_EXECUTION_DONE,
            stage_version=STAGE_VERSION[SimpleStage.POC_EXECUTION_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=(poc_candidate, poc_source),
            input_hash=input_reference_hash((poc_candidate, poc_source)),
            output_refs=(poc_execution,),
            attempt_id="dynamic-attempt",
            validated_poc_ref=poc,
        )
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
            output_refs=(poc_candidate, poc_source),
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
        record_id=RecordId("finding-record"),
    )
    FindingDisplayIdStore(database).get_or_allocate("analysis-1", finding_ref)
    report = data_dir / "reports" / "analysis-1" / "F-001.md"
    report.parent.mkdir(parents=True)
    report.write_text("# 한국어 보고서", encoding="utf-8")
    report.with_name("F-001.en.md").write_text("# English report", encoding="utf-8")
    logs = data_dir / "logs" / "analysis-1.log"
    logs.parent.mkdir(parents=True)
    logs.write_text("stage=POC_CANDIDATE_DONE status=SUCCEEDED\n", encoding="utf-8")
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
                artifacts.put_bytes("# 한국어 보고서".encode(), "text/markdown"),
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
                validated_poc_ref=(
                    poc
                    if stage in {SimpleStage.FINDING_DONE, SimpleStage.REPORT_DONE}
                    else None
                ),
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


def request(url: str, *, method: str = "GET", timeout: float = 5):
    try:
        return urllib.request.urlopen(
            urllib.request.Request(url, method=method), timeout=timeout
        )
    except urllib.error.HTTPError as error:
        return error


def test_server_serves_verified_group_zip_and_denies_unknown_group(tmp_path) -> None:
    run, _checkpoints, group, data_dir, _database, _store = _reported_case(tmp_path)
    with running_server(data_dir) as base:
        endpoint = (
            f"{base}/api/analyses/{run.analysis_id}/groups/{group.group_id}/bundle.zip"
        )
        response = request(endpoint)
        assert response.status == 200
        assert response.headers["Content-Type"] == "application/zip"
        assert "attachment" in response.headers["Content-Disposition"]
        with zipfile.ZipFile(BytesIO(response.read())) as zipped:
            assert "members/F-002/poc.py" in zipped.namelist()
        assert request(endpoint.replace(group.group_id, "f" * 64)).status == 404


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


def test_server_hides_report_when_saved_poc_source_is_process_local(tmp_path) -> None:
    seed(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    source = SimpleArtifactRepository(tmp_path, identity).put_bytes(
        b"""#!/bin/sh
python3 - <<'PY'
import pickle
class LocalFixture: pass
client = app.test_client()
value = pickle.dumps(LocalFixture())
client.set_cookie('value', value)
client.get('/cookie')
PY
""",
        "text/x-shellscript",
    )
    store.save_checkpoint(
        candidate.model_copy(update={"output_refs": (candidate.output_refs[0], source)})
    )
    old_report = tmp_path / "reports" / "analysis-1" / "F-001.md"

    with running_server(tmp_path) as base:
        detail = json.loads(request(f"{base}/api/analyses/A-001").read())
        assert detail["reports"] == []
        assert detail["finding_count"] == 0
        assert request(f"{base}/reports/analysis-1/F-001.md").status == 404
        assert request(f"{base}/api/analyses/A-001/reports/F-001").status == 404

    assert old_report.read_text(encoding="utf-8") == "# 한국어 보고서"


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

        report = json.loads(request(f"{base}/api/analyses/A-001/reports/F-001").read())
        assert report["markdown"] == "# 한국어 보고서"
        assert (
            "POC_CANDIDATE_DONE"
            in request(f"{base}/api/analyses/A-001/logs/download").read().decode()
        )

        bundle = request(f"{base}/api/analyses/A-001/bundle.zip").read()
        with zipfile.ZipFile(BytesIO(bundle)) as archive:
            names = set(archive.namelist())
            assert "manifest.json" in names
            assert "reports/F-001.md" in names
            assert "reports/en/F-001.md" not in names
            assert "logs/console.log" in names
            assert any(
                name.startswith("artifacts/simple_validated_poc-") for name in names
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
        assert request(f"{base}/api/analyses/A-001/artifacts/..%2Fsecret").status == 404
        assert (
            request(
                f"{base}/api/analyses/A-001/bundle.zip?selected=1&artifact={'0' * 64}"
            ).status
            == 404
        )


def test_server_exposes_bounded_static_coverage_for_blocked_run(tmp_path) -> None:
    seed(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    coverage_ref = SimpleArtifactRepository(tmp_path, identity).put_json(
        {
            "kind": "simple_static_coverage_v1",
            "analysis_id": "analysis-1",
            "workspace_id": "workspace-1",
            "commit_id": "commit-1",
            "fingerprint": "f" * 64,
            "expected_count": 2,
            "verified_count": 1,
            "gaps": [
                {
                    "path": "src/app.ts",
                    "rule_id": "rule.js",
                    "reason": "parse_or_scan_error",
                }
            ],
            "unsupported": [],
            "ast_parse_error_count": 0,
            "ast_truncated": False,
            "codeql_configured": True,
            "codeql_executed": False,
            "codeql_scope": "python_only",
        }
    )
    SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3").save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.STATIC_DONE,
            status=StageStatus.BLOCKED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(coverage_ref,),
            error_code="STATIC_COVERAGE_INCOMPLETE",
            retryable=False,
        )
    )
    with running_server(tmp_path) as base:
        payload = json.loads(request(f"{base}/api/analyses/A-001").read())
    assert payload["static_coverage_expected"] == 2
    assert payload["static_coverage_verified"] == 1
    assert payload["static_codeql_configured"] is True
    assert payload["static_codeql_executed"] is False
    assert payload["static_codeql_scope"] == "python_only"
    assert payload["static_coverage_gap_preview"] == [
        {"path": "src/app.ts", "rule_id": "rule.js", "reason": "parse_or_scan_error"}
    ]


def test_static_tools_show_actual_fallback_and_partial_ast(tmp_path) -> None:
    seed(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    coverage = artifacts.put_json(
        {
            "kind": "simple_static_coverage_v1",
            "analysis_id": "analysis-1",
            "workspace_id": "workspace-1",
            "commit_id": "commit-1",
            "expected_count": 2,
            "verified_count": 2,
            "gaps": [],
            "unsupported": [],
            "ast_parse_error_count": 1,
            "ast_truncated": False,
            "engine_verified_counts": {"opengrep": 0, "semgrep": 2},
            "codeql_configured": True,
            "codeql_executed": False,
            "codeql_scope": "python_only",
        }
    )
    bundle = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "static_coverage_ref": coverage.model_dump(mode="json"),
            "opengrep_findings": [],
            "codeql_findings": [],
            "codeql_executed": False,
        }
    )
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    run = store.require_analysis_run("analysis-1")
    store.save_analysis_run(run.model_copy(update={"static_bundle_ref": bundle}))
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.STATIC_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(coverage, bundle),
        )
    )
    with running_server(tmp_path) as base:
        detail = json.loads(request(f"{base}/api/analyses/A-001").read())
    tools = {item["tool"]: item["status"] for item in detail["static_tools"]}
    assert tools["AST"] == "PARTIAL"
    assert tools["OpenGrep"] == "SKIPPED"
    assert tools["Semgrep CE"] == "SUCCEEDED"
    assert tools["CodeQL"] == "SKIPPED"


def test_large_artifact_projection_blocks_incomplete_whole_zip(tmp_path) -> None:
    seed(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    original = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    extras = tuple(
        artifacts.put_json({"kind": "extra", "index": index}) for index in range(513)
    )
    store.save_checkpoint(
        original.model_copy(update={"output_refs": original.output_refs + extras})
    )
    with running_server(tmp_path) as base:
        detail = json.loads(request(f"{base}/api/analyses/A-001").read())
        response = request(f"{base}/api/analyses/A-001/bundle.zip")
        selected = request(
            f"{base}/api/analyses/A-001/bundle.zip?selected=1"
            f"&artifact={detail['artifacts'][0]['artifact_id']}",
            timeout=15,
        )
    assert detail["artifact_projection_complete"] is False
    assert detail["artifact_omitted_count"] >= 1
    assert response.status == 409
    assert json.loads(response.read())["error"] == "incomplete_export"
    assert selected.status == 200


def test_server_restricts_persisted_legacy_allow_markdown(tmp_path) -> None:
    seed(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    gate_ref = artifacts.put_json({"result": {"status": "ALLOW"}})
    SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3").save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.SCOPE_GATE_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(gate_ref,),
        )
    )
    old_path = tmp_path / "reports" / "analysis-1" / "F-001.md"
    old_text = "# Legacy\n- 상태: CONFIRMED\n- 외부 제출·공개 허용: 예\n"
    old_path.write_text(old_text, encoding="utf-8")

    with running_server(tmp_path) as base:
        detail = json.loads(request(f"{base}/api/analyses/A-001").read())
        public = request(f"{base}/reports/analysis-1/F-001.md").read().decode()
        preview = json.loads(
            request(f"{base}/api/analyses/A-001/reports/F-001").read()
        )["markdown"]
        download = (
            request(f"{base}/api/analyses/A-001/reports/F-001/download").read().decode()
        )
        with zipfile.ZipFile(
            BytesIO(request(f"{base}/api/analyses/A-001/bundle.zip").read())
        ) as archive:
            bundled = archive.read("reports/F-001.md").decode()

    assert detail["hypotheses"][0]["scope_status"] == "UNCERTAIN"
    assert detail["hypotheses"][0]["external_disclosure_allowed"] is False
    assert "허용: 예" not in public
    assert "제보 불가" in public
    assert preview == download == bundled == public
    assert old_path.read_text(encoding="utf-8") == old_text


def test_server_serves_exact_report_artifact_not_mutated_file(tmp_path) -> None:
    seed(tmp_path)
    report_path = tmp_path / "reports" / "analysis-1" / "F-001.md"
    report_path.write_text("# altered after generation", encoding="utf-8")

    with running_server(tmp_path) as base:
        public = request(f"{base}/reports/analysis-1/F-001.md").read().decode()
        preview = json.loads(
            request(f"{base}/api/analyses/A-001/reports/F-001").read()
        )["markdown"]
        download = (
            request(f"{base}/api/analyses/A-001/reports/F-001/download").read().decode()
        )

    assert public == "# 한국어 보고서"
    assert preview == download == public


def test_server_downloads_only_current_manifest_files(tmp_path) -> None:
    seed(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    finding = FindingDisplayIdStore.resolve_existing(
        store.database_path, "analysis-1", "F-001"
    )
    attach_current_bundle(tmp_path, identity, finding, "F-001")
    poc = b"#!/bin/sh\nprintf ok\n"
    (tmp_path / "reports" / "analysis-1" / "F-001.en.md").write_text(
        "# unverified disk change", encoding="utf-8"
    )

    with running_server(tmp_path) as base:
        detail = json.loads(request(f"{base}/api/analyses/A-001").read())
        report = detail["reports"][0]
        urls = report["attachment_urls"]
        assert report["english_available"] is True
        assert report["english_view_url"] is None
        assert report["english_download_url"] == urls["report_en.md"]
        english = request(f"{base}{report['english_download_url']}")
        assert english.read() == b"# English report\n"
        assert (
            english.headers["Content-Disposition"]
            == 'attachment; filename="report_en.md"'
        )
        response = request(f"{base}{urls['poc.sh']}")
        assert response.status == 200
        assert response.read() == poc
        assert (
            response.headers["Content-Disposition"] == 'attachment; filename="poc.sh"'
        )
        assert response.headers["Cache-Control"] == "no-store"
        assert request(f"{base}{urls['poc.sh']}", method="HEAD").status == 200
        assert request(f"{base}{urls['bundle.zip']}").read()[:2] == b"PK"
        with zipfile.ZipFile(
            BytesIO(request(f"{base}/api/analyses/A-001/bundle.zip").read())
        ) as archive:
            assert archive.read("reports/en/F-001.md") == b"# English report\n"
            assert archive.read("reports/F-001.md") == "# 한국어 보고서\n".encode()
            assert archive.read("reports/F-001/poc.sh") == poc
            assert "reports/F-001/evidence/provenance.json" in archive.namelist()
        assert (
            request(f"{base}/reports/analysis-1/F-001/files/%2e%2e/poc.sh").status
            == 404
        )
        assert (
            request(f"{base}/reports/analysis-1/F-001/files/manifest.json").status
            == 404
        )
        (tmp_path / "reports" / "analysis-1" / "F-001" / "bundle.zip").write_bytes(
            b"tampered"
        )
        broken = request(f"{base}/api/analyses/A-001/bundle.zip")
        assert broken.status == 409
        assert json.loads(broken.read())["error"] == "incomplete_export"


def test_server_rejects_non_loopback_bind(tmp_path) -> None:
    with pytest.raises(ValueError, match="DASHBOARD_LOOPBACK_ONLY"):
        create_server(tmp_path, host="0.0.0.0", port=8765)


def test_server_exposes_bounded_static_coverage_pages(tmp_path) -> None:
    seed(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    coverage = artifacts.put_json(
        {
            "kind": "simple_static_coverage_v1",
            "analysis_id": "analysis-1",
            "workspace_id": "workspace-1",
            "commit_id": "commit-1",
            "expected_count": 2,
            "verified_count": 1,
            "gaps": [
                {"path": "src/file.ts", "rule_id": "rule.js", "reason": "scan_error"}
            ],
            "unsupported": [{"extension": "", "file_count": 1}],
            "unsupported_files": [
                {"path": "tools/launcher", "reason": "unsupported_extension"}
            ],
            "ast_parse_error_count": 0,
            "ast_truncated": False,
        }
    )
    bundle = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "static_coverage_ref": coverage.model_dump(mode="json"),
        }
    )
    SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3").save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.STATIC_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(
                artifacts.put_json({"kind": "simple_repository_profile"}),
                bundle,
            ),
        )
    )

    with running_server(tmp_path) as base:
        page = json.loads(
            request(
                f"{base}/api/analyses/analysis-1/static-coverage?kind=unsupported&limit=1"
            ).read()
        )
        assert page["total"] == 1
        assert page["items"] == [
            {"path": "tools/launcher", "reason": "unsupported_extension"}
        ]
        invalid = request(f"{base}/api/analyses/analysis-1/static-coverage?limit=101")
        assert invalid.code == 400


def test_event_cursor_keeps_late_written_event(tmp_path) -> None:
    seed(tmp_path)
    with running_server(tmp_path) as base:
        initial = json.loads(request(f"{base}/api/analyses/A-001/events").read())
        assert [item["event_id"] for item in initial] == ["event-llm-1"]
        AgentActivityStore(tmp_path / "db" / "sastsimi.sqlite3").append(
            AgentActivityEvent(
                event_id="event-late-write",
                analysis_id="analysis-1",
                workspace_id="workspace-1",
                commit_id="commit-1",
                hypothesis_id="hypothesis-1",
                stage="POC_EXECUTION_DONE",
                agent_role="PoC Agent",
                attempt_id="attempt-late-write",
                sequence=1,
                kind=ActivityKind.STAGE_COMPLETED,
                status="SUCCEEDED",
                summary_ko="뒤늦게 기록된 이벤트",
                started_at=datetime(2020, 1, 1, tzinfo=UTC),
            )
        )
        later = json.loads(
            request(f"{base}/api/analyses/A-001/events?after=event-llm-1").read()
        )
    assert [item["event_id"] for item in later] == ["event-late-write"]


# mypy: disable-error-code="no-untyped-def"
