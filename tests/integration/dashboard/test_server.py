from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request
import zipfile
from contextlib import contextmanager
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

import pytest

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
            "analysis_id": "analysis-1",
            "hypothesis_id": "hypothesis-1",
            "proposal": {
                "title": "Unsafe command flow",
                "vulnerability_type": "Command Injection",
                "summary": "User input can reach a process execution call.",
                "code_locations": ["app.py:10", "app.py:24"],
                "source": "request.args['command']",
                "sink": "subprocess.run(command)",
                "rationale": "The value is not validated before execution.",
            },
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
            "ast_summary": {
                "facts": [{"path": "app.py", "line": 10, "name": "request.args"}]
            },
            "opengrep_findings": [
                {
                    "path": "app.py",
                    "line": 24,
                    "check_id": "opengrep.command-injection",
                }
            ],
            "codeql_findings": [
                {
                    "path": "app.py",
                    "line": 24,
                    "rule_id": "py/command-line-injection",
                }
            ],
            "codeql_executed": True,
        }
    )
    finding_ref = artifacts.put_json(
        {
            "kind": "simple_finding",
            "status": "CONFIRMED_INTERNAL",
            "analysis_id": "analysis-1",
            "hypothesis_id": "hypothesis-1",
            "validated_poc_ref": poc.model_dump(mode="json"),
            "source_refs": [
                static_bundle.model_dump(mode="json"),
                hypothesis_proposal.model_dump(mode="json"),
            ],
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
    store.save_success(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.FINDING_DONE,
            status=StageStatus.PENDING,
            input_refs=(poc,),
            input_hash=input_reference_hash((poc,)),
            validated_poc_ref=poc,
            verdict="TRUE",
        ),
        outputs=(finding_ref,),
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
                markdown_path=str(report) if stage is SimpleStage.REPORT_DONE else None,
            )
        )


@contextmanager
def running_server(data_dir, *, demo: bool = False):
    server = create_server(data_dir, host="127.0.0.1", port=0, demo=demo)
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


def test_demo_mode_uses_synthetic_memory_data_without_touching_database(
    tmp_path,
) -> None:
    expected = json.loads(
        (
            Path(__file__).resolve().parents[2] / "fixtures" / "dashboard_demo.json"
        ).read_text(encoding="utf-8")
    )
    with running_server(tmp_path, demo=True) as base:
        meta = json.loads(request(f"{base}/api/meta").read())
        analyses = json.loads(request(f"{base}/api/analyses").read())
        detail = json.loads(request(f"{base}/api/analyses/DEMO-001").read())
        cells = json.loads(
            request(
                f"{base}/api/analyses/DEMO-001/status-cells?offset=0&limit=2"
            ).read()
        )
        events = json.loads(request(f"{base}/api/analyses/DEMO-001/events").read())
        page = request(base).read().decode()
        assert meta == {"demo": True}
        assert 'id="demo-banner"' in page
        assert analyses[0]["analysis_id"] == expected["analysis_id"]
        assert analyses[0]["repository"] == expected["repository"]
        assert detail["display_analysis_id"] == expected["display_analysis_id"]
        assert detail["hypothesis_count"] == expected["hypothesis_count"]
        assert detail["kpis"]["confirmed_findings"] == expected["confirmed_findings"]
        assert cells["total"] >= 2
        assert len(cells["items"]) == 2
        assert events and all(
            event["analysis_id"] == "demo-analysis" for event in events
        )
        assert request(f"{base}/api/analyses/DEMO-001/bundle.zip").status == 404
        assert request(f"{base}/api/analyses", method="POST").status == 405
    assert list(tmp_path.iterdir()) == []


def test_live_dashboard_metadata_is_not_demo(tmp_path) -> None:
    with running_server(tmp_path) as base:
        assert json.loads(request(f"{base}/api/meta").read()) == {"demo": False}


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
        page = request(f"{base}/analyses/A-001").read().decode()
        assert 'id="presentation-toggle"' in page
        assert 'id="kpi-grid"' in page
        assert 'id="status-grid"' in page
        assert 'id="execution-history"' in page
        assert 'id="compare-analysis"' in page
        assert 'id="replay-toggle"' in page
        assert 'id="finding-traces"' in page
        assert 'id="artifact-relations"' in page
        assert 'id="readiness"' in page
        assert 'id="usage"' in page
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
        assert detail["static_tools"][2]["finding_count"] == 1
        overlap = next(
            item
            for item in detail["static_tool_findings"]
            if item["location"] == "app.py:24"
        )
        assert overlap["overlap"] is True
        assert overlap["tools"] == ["CodeQL", "OpenGrep"]
        assert detail["commit_id"] == "commit-1"
        assert detail["profile_ref"] == "profile-test"
        assert detail["provider"] == "codex-cli"
        assert detail["model"] == "gpt-test"
        assert detail["hypotheses"][0]["source"] == "request.args['command']"
        assert detail["hypotheses"][0]["sink"] == "subprocess.run(command)"
        assert detail["hypotheses"][0]["vulnerability_type"] == ("Command Injection")
        assert detail["usage"] == {
            "invocation_count": 2,
            "succeeded_count": 2,
            "failed_count": 0,
            "retry_count": 0,
            "known_usage_count": 1,
            "unknown_usage_count": 1,
            "input_tokens": 10,
            "output_tokens": 4,
            "total_tokens": 14,
            "elapsed_ms": 0,
        }
        readiness = {item["key"]: item for item in detail["readiness"]}
        assert readiness["exact-target"]["status"] == "READY"
        assert readiness["llm-provider"]["status"] == "READY"
        assert readiness["static-core"]["status"] == "WAITING"
        assert readiness["presentation-output"]["status"] == "READY"
        assert detail["presentation_bundle_url"].endswith("/presentation.zip")
        assert detail["reports"][0]["english_available"] is False
        assert detail["reports"][0]["english_view_url"] is None
        assert detail["artifact_relations"]
        trace = detail["finding_traces"][0]
        assert trace["display_id"] == "F-001"
        assert trace["hypothesis_id"] == "hypothesis-1"
        assert trace["source"] == "request.args['command']"
        assert trace["sink"] == "subprocess.run(command)"
        assert trace["validated_poc"] is True
        assert trace["poc_artifact_ids"]
        assert trace["evidence_artifact_ids"]
        assert trace["english_available"] is False
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
        assert request(f"{base}/api/analyses/A-001/reports/F-001?lang=en").status == 404
        assert (
            request(f"{base}/api/analyses/A-001/reports/F-001/download?lang=en").status
            == 404
        )
        assert request(f"{base}/api/analyses/A-001/reports/F-001?lang=fr").status == 404
        assert (
            "POC_CANDIDATE_DONE"
            in request(f"{base}/api/analyses/A-001/logs/download").read().decode()
        )

        assert (
            json.loads(
                request(f"{base}/api/analyses/A-001/events?after=event-llm-1").read()
            )
            == []
        )
        assert (
            request(f"{base}/api/analyses/A-001/events?after=missing-event").status
            == 404
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

        presentation = request(f"{base}/api/analyses/A-001/presentation.zip").read()
        with zipfile.ZipFile(BytesIO(presentation)) as archive:
            names = set(archive.namelist())
            assert "presentation/README.md" in names
            assert "presentation/summary.json" in names
            assert "reports/F-001.md" in names
            assert "reports/en/F-001.md" not in names
            summary = json.loads(archive.read("presentation/summary.json"))
            assert summary["analysis_id"] == "analysis-1"
            assert summary["english_report_ids"] == []

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
            f"&artifact={detail['artifacts'][0]['artifact_id']}"
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
        urls = detail["reports"][0]["attachment_urls"]
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


def test_status_cells_endpoint_pages_and_rejects_invalid_request(tmp_path) -> None:
    seed(tmp_path)
    with running_server(tmp_path) as base:
        response = request(f"{base}/api/analyses/A-001/status-cells?offset=0&limit=1")
        payload = json.loads(response.read())
        assert response.status == 200
        assert payload["total"] == 1
        assert len(payload["items"]) == 1
        assert payload["items"][0]["id"] == "hypothesis-1"
        assert request(f"{base}/api/analyses/A-001/status-cells?limit=0").status == 400
        assert request(f"{base}/api/analyses/analysis-other/status-cells").status == 404


def test_verified_markdown_artifact_has_safe_preview_and_download(tmp_path) -> None:
    seed(tmp_path)
    with running_server(tmp_path) as base:
        detail = json.loads(request(f"{base}/api/analyses/A-001").read())
        markdown = next(
            item
            for item in detail["artifacts"]
            if item["media_type"] == "text/markdown"
        )
        payload = json.loads(request(f"{base}{markdown['view_url']}").read())
        assert payload["rendered_html"].startswith("<h1>")
        assert payload["truncated"] is False
        assert payload["download_url"] == markdown["download_url"]
        assert request(f"{base}{markdown['download_url']}").read().startswith(b"#")
        report = json.loads(request(f"{base}/api/analyses/A-001/reports/F-001").read())
        assert report["rendered_html"].startswith("<h1>")
        assert report["truncated"] is False
        assert request(f"{base}/api/analyses/A-001/reports/%2e%2e").status == 404


def test_verified_markdown_attachments_have_sanitized_preview(tmp_path) -> None:
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
    with running_server(tmp_path) as base:
        detail = json.loads(request(f"{base}/api/analyses/A-001").read())
        assert detail["reports"][0]["english_available"] is True
        english = json.loads(
            request(f"{base}/api/analyses/A-001/reports/F-001?lang=en").read()
        )
        assert english["markdown"] == "# English report\n"
        assert english["rendered_html"] == "<h1>English report</h1>\n"
        assert (
            request(f"{base}/api/analyses/A-001/reports/F-001/download?lang=en").read()
            == b"# English report\n"
        )
        previews = detail["reports"][0]["attachment_preview_urls"]
        assert set(previews) == {"report_en.md", "report_kr.md"}
        payload = json.loads(request(f"{base}{previews['report_en.md']}").read())
        assert payload["rendered_html"].startswith("<h1>English report</h1>")
        assert payload["download_url"].endswith("/files/report_en.md")
        assert (
            request(f"{base}/reports/analysis-1/F-001/files/poc.sh/preview").status
            == 404
        )


def test_legacy_text_artifact_can_use_markdown_view_without_media_metadata(
    tmp_path,
) -> None:
    seed(tmp_path)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )
    markdown_ref = SimpleArtifactRepository(tmp_path, identity).put_bytes(
        b"**bold**", "text/markdown"
    )
    SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3").save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.CWE_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(markdown_ref,),
        )
    )
    with running_server(tmp_path) as base:
        payload = json.loads(
            request(
                f"{base}/api/analyses/A-001/artifacts/{markdown_ref.content_hash}"
            ).read()
        )
        assert payload["media_type"] == "text/plain"
        assert "<strong>bold</strong>" in payload["rendered_html"]
        assert payload["content"] == "**bold**"


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
