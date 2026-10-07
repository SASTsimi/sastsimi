"""Old PoC checkpoints remain historical evidence until they are revalidated."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from shutil import rmtree

import pytest

from sastsimi.composition.simple_runtime_composition import (
    PublicSimpleRuntimeApplication,
)
from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.config.user_config import SimpleExecutionProfile, UserConfig
from sastsimi.dashboard.query import DashboardNotFound, DashboardQuery
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.run_lease import analysis_run_lease
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _readers(
    data_dir: Path,
) -> tuple[PublicSimpleRuntimeApplication, DashboardQuery, SimpleCheckpointStore]:
    config = UserConfig(
        data_dir=data_dir,
        profile_path=data_dir / "profile.toml",
        auth_mode="API_KEY",
        provider="openai",
        model="configured-model",
        credential_ref="env:OPENAI_API_KEY",
        execution_profile="LIGHTWEIGHT",
        max_cost_minor_units=10_000,
        max_tokens=100_000,
        max_elapsed_seconds=3_600,
        docker_network="NONE",
        enabled_tools=(),
        detected_versions={},
        setup_ready=True,
    )
    profile = SimpleExecutionProfile(
        provider_profile_ref="local-openai",
        provider="openai",
        model="configured-model",
        auth_mode="API_KEY",
        credential_ref="env:OPENAI_API_KEY",
        data_dir=data_dir,
        workspace_root=data_dir / "workspaces",
        max_cost_minor_units=10_000,
        max_tokens=100_000,
        max_elapsed_seconds=3_600,
        docker_network="NONE",
        tools={},
    )
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    return (
        PublicSimpleRuntimeApplication(config, profile),
        DashboardQuery(data_dir),
        store,
    )


def _complete_poc_analysis(
    data_dir: Path,
    *,
    include_report: bool = True,
) -> tuple[PublicSimpleRuntimeApplication, DashboardQuery, SimpleCheckpointStore]:
    application, dashboard, store = _readers(data_dir)
    analysis_id = "analysis-poc-revalidation"
    display = AnalysisDisplayIdStore(store.database_path).get_or_allocate(analysis_id)
    root = CheckpointIdentity(
        analysis_id=analysis_id,
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    child = root.model_copy(update={"hypothesis_id": "hypothesis-1"})
    artifacts = SimpleArtifactRepository(data_dir, child)
    content_ref = artifacts.put_bytes(b"#!/bin/sh\nprintf ok\n", "text/x-shellscript")
    candidate_ref = artifacts.put_json({"kind": "simple_poc_candidate"})
    validated_ref = artifacts.put_json({"kind": "simple_validated_poc"})
    gate_ref = artifacts.put_json(
        {"kind": "simple_technical_gate", "result": {"status": "ACCEPT"}}
    )
    finding_ref = artifacts.put_json({"kind": "simple_finding"})
    draft_ref = artifacts.put_json({"kind": "simple_report_draft"})
    report_ref = artifacts.put_bytes(b"# Old report", "text/markdown")
    report_path = data_dir / "reports" / analysis_id / "F-001.md"
    report_path.parent.mkdir(parents=True)
    report_path.write_bytes(b"# Old report")
    assert (
        FindingDisplayIdStore(store.database_path).get_or_allocate(
            analysis_id, finding_ref
        )
        == "F-001"
    )
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=analysis_id,
            display_analysis_id=display,
            workspace_id=root.workspace_id,
            commit_id=root.commit_id,
            repository="https://example.invalid/repo.git",
            hypothesis_ids=(child.hypothesis_id or "",),
        )
    )
    for stage in (SimpleStage.STATIC_DONE, SimpleStage.HYPOTHESIS_DONE):
        store.save_checkpoint(
            StageCheckpoint(
                identity=root,
                stage=stage,
                stage_version=STAGE_VERSION[stage],
                status=StageStatus.SUCCEEDED,
                input_refs=(),
                input_hash=input_reference_hash(()),
            )
        )
    for stage in HYPOTHESIS_STAGES:
        if stage is SimpleStage.REPORT_DONE and not include_report:
            continue
        input_refs = (finding_ref,) if stage is SimpleStage.REPORT_DONE else ()
        output_refs = (
            (candidate_ref, content_ref)
            if stage is SimpleStage.POC_CANDIDATE_DONE
            else (draft_ref, report_ref)
            if stage is SimpleStage.REPORT_DONE
            else (finding_ref,)
            if stage is SimpleStage.FINDING_DONE
            else (gate_ref,)
            if stage is SimpleStage.TECH_GATE_DONE
            else ()
        )
        store.save_checkpoint(
            StageCheckpoint(
                identity=child,
                stage=stage,
                stage_version=STAGE_VERSION[stage],
                status=StageStatus.SUCCEEDED,
                input_refs=input_refs,
                input_hash=input_reference_hash(input_refs),
                output_refs=output_refs,
                verdict=(
                    "TRUE"
                    if stage
                    in {SimpleStage.VERIFICATION_FINAL_DONE, SimpleStage.FINDING_DONE}
                    else None
                ),
                validated_poc_ref=(
                    validated_ref if stage is SimpleStage.POC_EXECUTION_DONE else None
                ),
                gate_decision="ACCEPT" if stage is SimpleStage.TECH_GATE_DONE else None,
                markdown_path=(
                    str(report_path) if stage is SimpleStage.REPORT_DONE else None
                ),
            )
        )
    return application, dashboard, store


def _downgrade_poc(store: SimpleCheckpointStore, version: str = "2") -> None:
    poc = store.require(_hypothesis_identity(), SimpleStage.POC_EXECUTION_DONE)
    store.save_checkpoint(poc.model_copy(update={"stage_version": version}))


def _replace_saved_poc_source(
    data_dir: Path, store: SimpleCheckpointStore, content: bytes
) -> None:
    identity = _hypothesis_identity()
    candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    source_ref = SimpleArtifactRepository(data_dir, identity).put_bytes(
        content, "text/x-shellscript"
    )
    store.save_checkpoint(
        candidate.model_copy(
            update={"output_refs": (candidate.output_refs[0], source_ref)}
        )
    )


def test_process_local_poc_source_is_not_counted_or_served(
    tmp_path: Path,
) -> None:
    application, dashboard, store = _complete_poc_analysis(tmp_path)
    report_path = tmp_path / "reports" / "analysis-poc-revalidation" / "F-001.md"
    original_report = report_path.read_bytes()
    _replace_saved_poc_source(
        tmp_path,
        store,
        b"""#!/bin/sh
python3 - <<'PY'
import pickle
class LocalFixture:
    pass
client = app.test_client()
payload = pickle.dumps(LocalFixture())
client.set_cookie('value', payload)
client.get('/cookie')
PY
""",
    )

    status = application.status("A-001")
    assert status["finding_count"] == 0
    assert status["raw_finding_count"] == 1
    result = application.result("A-001")
    assert result["finding_count"] == 0
    assert result["raw_finding_count"] == 1
    assert result["findings"] == []
    reads: tuple[Callable[[], object], ...] = (
        lambda: application.poc("F-001"),
        lambda: application.report("F-001"),
        lambda: application.export_report("F-001"),
        lambda: application.export_report_bundle("F-001"),
    )
    for read in reads:
        with pytest.raises(LookupError):
            read()

    detail = dashboard.get_analysis("A-001")
    assert detail.finding_count == 0
    assert detail.confirmed_finding_count == 0
    assert detail.reports == ()
    assert detail.hypotheses[0].verdict is None
    assert detail.hypotheses[0].validated_poc is False
    shell = dashboard.get_analysis_shell("A-001")
    assert shell.kpis.confirmed_findings == 0
    assert shell.validated_poc_count == 0
    dashboard_reads: tuple[Callable[[], object], ...] = (
        lambda: dashboard.report_path("analysis-poc-revalidation", "F-001"),
        lambda: dashboard.report_content("analysis-poc-revalidation", "F-001"),
        lambda: dashboard.report_attachment(
            "analysis-poc-revalidation", "F-001", "bundle.zip"
        ),
    )
    for read in dashboard_reads:
        with pytest.raises(DashboardNotFound):
            read()
    assert report_path.read_bytes() == original_report
    assert (
        store.require(_hypothesis_identity(), SimpleStage.REPORT_DONE).status
        is StageStatus.SUCCEEDED
    )


def test_process_local_poc_hides_finding_artifact_before_report(
    tmp_path: Path,
) -> None:
    _application, dashboard, store = _complete_poc_analysis(
        tmp_path, include_report=False
    )
    finding_ref = store.require(
        _hypothesis_identity(), SimpleStage.FINDING_DONE
    ).output_refs[0]
    _replace_saved_poc_source(
        tmp_path,
        store,
        b"""import pickle
class LocalFixture:
    pass
payload = pickle.dumps(LocalFixture())
client = app.test_client()
client.set_cookie('value', payload)
client.get('/cookie')
""",
    )

    with pytest.raises(DashboardNotFound):
        dashboard.artifact_bytes("A-001", finding_ref.content_hash)
    assert not any(
        artifact.artifact_id == finding_ref.content_hash
        for artifact in dashboard.get_analysis("A-001").artifacts
    )


def test_dashboard_reads_do_not_recreate_missing_artifact_store(
    tmp_path: Path,
) -> None:
    _application, dashboard, _store = _complete_poc_analysis(tmp_path)
    paths = RuntimePaths(tmp_path)
    absent = (paths.staging, paths.artifacts / "sha256", paths.quarantine)
    for path in absent:
        rmtree(path)

    assert dashboard.get_analysis_shell("A-001").validated_poc_count == 0
    assert dashboard.get_analysis("A-001").confirmed_finding_count == 0
    for path in absent:
        assert not path.exists()


def test_unreadable_saved_poc_source_fails_closed_without_deleting_report(
    tmp_path: Path,
) -> None:
    application, dashboard, store = _complete_poc_analysis(tmp_path)
    identity = _hypothesis_identity()
    candidate = store.require(identity, SimpleStage.POC_CANDIDATE_DONE)
    lost_source_ref = candidate.output_refs[1].model_copy(
        update={"content_hash": "f" * 64}
    )
    store.save_checkpoint(
        candidate.model_copy(
            update={"output_refs": (candidate.output_refs[0], lost_source_ref)}
        )
    )

    assert application.result("A-001")["finding_count"] == 0
    assert dashboard.get_analysis("A-001").confirmed_finding_count == 0
    with pytest.raises(LookupError):
        application.report("F-001")
    with pytest.raises(DashboardNotFound):
        dashboard.report_content("analysis-poc-revalidation", "F-001")
    assert (tmp_path / "reports" / "analysis-poc-revalidation" / "F-001.md").is_file()


def test_status_and_result_require_revalidation_for_old_successful_poc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(STAGE_VERSION, SimpleStage.POC_EXECUTION_DONE, "3")
    application, _dashboard, store = _complete_poc_analysis(tmp_path)
    assert application.status("A-001")["status"] == "COMPLETE"
    assert application.result("A-001")["finding_count"] == 1

    _downgrade_poc(store)

    status = application.status("A-001")
    result = application.result("A-001")
    assert status["status"] == "PAUSED"
    assert status["error_code"] == "POC_REVALIDATION_REQUIRED"
    assert status["resume_action"] == "REVALIDATE_POC"
    percent = status["percent"]
    assert isinstance(percent, int)
    assert percent < 100
    assert result["finding_count"] == 0
    assert result["findings"] == []


def test_public_poc_and_report_do_not_serve_old_poc_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(STAGE_VERSION, SimpleStage.POC_EXECUTION_DONE, "3")
    application, _dashboard, store = _complete_poc_analysis(tmp_path)
    assert application.poc("F-001").startswith("#!/bin/sh")
    assert application.report("F-001")

    _downgrade_poc(store)

    with pytest.raises(LookupError):
        application.poc("F-001")
    with pytest.raises(LookupError):
        application.report("F-001")
    with pytest.raises(LookupError):
        application.export_report("F-001")


def test_dashboard_hides_old_poc_verdict_and_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(STAGE_VERSION, SimpleStage.POC_EXECUTION_DONE, "3")
    _application, dashboard, store = _complete_poc_analysis(tmp_path)
    current = dashboard.get_analysis("A-001")
    assert current.reports
    assert current.finding_count == 1
    assert dashboard.report_path("analysis-poc-revalidation", "F-001").is_file()

    _downgrade_poc(store)

    detail = dashboard.get_analysis("A-001")
    hypothesis = detail.hypotheses[0]
    assert detail.status == "PAUSED"
    assert detail.error_code == "POC_REVALIDATION_REQUIRED"
    assert detail.resume_action == "REVALIDATE_POC"
    assert detail.finding_count == 0
    assert detail.reports == ()
    assert hypothesis.verdict is None
    assert hypothesis.validated_poc is False
    assert hypothesis.completed_count == HYPOTHESIS_STAGES.index(
        SimpleStage.POC_EXECUTION_DONE
    )
    assert hypothesis.completed_count < hypothesis.stage_count
    assert detail.completed_count == 2 + hypothesis.completed_count
    assert detail.completed_count < detail.stage_count
    assert dashboard.list_analyses()[0].completed_count == detail.completed_count
    gate = store.require(_hypothesis_identity(), SimpleStage.TECH_GATE_DONE)
    store.save_checkpoint(gate.model_copy(update={"gate_decision": "REJECT"}))
    assert dashboard.get_analysis("A-001").hypotheses[0].disposition is None
    with pytest.raises(DashboardNotFound):
        dashboard.report_path("analysis-poc-revalidation", "F-001")
    with pytest.raises(DashboardNotFound):
        dashboard.report_content("analysis-poc-revalidation", "F-001")


def _hypothesis_identity() -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="analysis-poc-revalidation",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )


def test_active_resume_does_not_appear_paused_with_stale_poc(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(STAGE_VERSION, SimpleStage.POC_EXECUTION_DONE, "3")
    application, dashboard, store = _complete_poc_analysis(tmp_path)
    _downgrade_poc(store)

    with analysis_run_lease(tmp_path, "analysis-poc-revalidation"):
        assert application.status("A-001")["status"] == "RUNNING"
        detail = dashboard.get_analysis("A-001")
        assert detail.status == "RUNNING"
        assert detail.hypotheses[0].status == "RUNNING"


def test_legacy_final_without_poc_keeps_its_terminal_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(STAGE_VERSION, SimpleStage.POC_EXECUTION_DONE, "3")
    application, dashboard, store = _readers(tmp_path)
    root = CheckpointIdentity(
        analysis_id="analysis-no-poc",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    child = root.model_copy(update={"hypothesis_id": "hypothesis-no-poc"})
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(root.analysis_id)
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=root.analysis_id,
            display_analysis_id="A-001",
            workspace_id=root.workspace_id,
            commit_id=root.commit_id,
            repository="https://example.invalid/repo.git",
            hypothesis_ids=(child.hypothesis_id or "",),
        )
    )
    store.save_checkpoint(
        StageCheckpoint(
            identity=child,
            stage=SimpleStage.VERIFICATION_FINAL_DONE,
            stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_FINAL_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            verdict="FALSE",
        )
    )

    assert application.status("A-001")["status"] == "COMPLETE"
    assert dashboard.get_analysis("A-001").status == "COMPLETE"


def test_version_one_poc_predates_source_only_fallback_and_keeps_read_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(STAGE_VERSION, SimpleStage.POC_EXECUTION_DONE, "3")
    application, dashboard, store = _complete_poc_analysis(tmp_path)
    _downgrade_poc(store, "1")

    # The source-only fallback was introduced with PoC stage version 2. Version 1
    # still reruns on resume via the generic version check, but is not masked here.
    assert application.status("A-001")["status"] == "COMPLETE"
    assert application.result("A-001")["finding_count"] == 1
    assert dashboard.get_analysis("A-001").status == "COMPLETE"
