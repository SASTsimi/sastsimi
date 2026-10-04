"""Group exports recheck the exact current member closure without writes."""

from __future__ import annotations

import hashlib
import io
import json
import os
import sqlite3
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from sastsimi.composition.simple_runtime_composition import (
    PublicSimpleRuntimeApplication,
)
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.dashboard.query import DashboardNotFound, DashboardQuery
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.reporting.bilingual_bundle import BundleFile
from sastsimi.reporting.bundle_files import publish_bundle
from sastsimi.reporting.grouped_bundle import GroupBundleUnavailable
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.finding_group_projection import (
    project_current_finding_groups,
)
from sastsimi.simple_runtime.finding_groups import FindingGroup
from sastsimi.simple_runtime.group_report_projection import (
    _read_only_artifact_reader,
    current_group_bundle,
    current_report_groups,
)
from sastsimi.simple_runtime.models import (
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
)
from sastsimi.simple_runtime.scope_policy import project_scope_review
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from tests.simple_runtime.test_finding_group_projection import _case, _checkpoint


def _reported_case(
    tmp_path: Path,
    *,
    second_severity: str = "High",
    repository: str = "https://example.test/repo",
) -> tuple[
    SimpleAnalysisRun,
    list[StageCheckpoint],
    FindingGroup,
    Path,
    Path,
    SimpleCheckpointStore,
]:
    run, original, eligible, data_dir, database, _workspace = _case(tmp_path)
    run = run.model_copy(update={"repository": repository})
    output: list[StageCheckpoint] = []
    fresh_refs = {}
    by_hypothesis = {
        hypothesis: {
            item.stage: item
            for item in original
            if item.identity.hypothesis_id == hypothesis
        }
        for hypothesis in ("hyp-1", "hyp-2")
    }
    for number, hypothesis in enumerate(("hyp-1", "hyp-2"), 1):
        stages = by_hypothesis[hypothesis]
        identity = stages[SimpleStage.FINDING_DONE].identity
        artifacts = SimpleArtifactRepository(data_dir, identity)
        candidate_ref, content_ref = stages[SimpleStage.POC_CANDIDATE_DONE].output_refs[
            :2
        ]
        _, stdout_ref, stderr_ref = stages[SimpleStage.POC_EXECUTION_DONE].output_refs
        attempt = f"attempt-{number}"
        execution_ref = artifacts.put_json(
            {
                "kind": "simple_poc_execution",
                "candidate_ref": candidate_ref.model_dump(mode="json"),
                "content_ref": content_ref.model_dump(mode="json"),
                "stdout_ref": stdout_ref.model_dump(mode="json"),
                "stderr_ref": stderr_ref.model_dump(mode="json"),
                "attempt_id": attempt,
            }
        )
        validated_ref = artifacts.put_json(
            {
                "kind": "simple_validated_poc",
                "candidate_ref": candidate_ref.model_dump(mode="json"),
                "content_ref": content_ref.model_dump(mode="json"),
                "execution_ref": execution_ref.model_dump(mode="json"),
                "attempt_id": attempt,
            }
        )
        final_ref = artifacts.put_json(
            {
                "kind": "simple_verification_result",
                "result": {"verdict": "TRUE"},
                "source_refs": [
                    validated_ref.model_dump(mode="json"),
                    execution_ref.model_dump(mode="json"),
                ],
            }
        )
        stages[SimpleStage.POC_EXECUTION_DONE] = _checkpoint(
            identity,
            SimpleStage.POC_EXECUTION_DONE,
            (execution_ref, stdout_ref, stderr_ref),
            validated=validated_ref,
            attempt_id=attempt,
        )
        stages[SimpleStage.VERIFICATION_FINAL_DONE] = _checkpoint(
            identity,
            SimpleStage.VERIFICATION_FINAL_DONE,
            (final_ref,),
            validated=validated_ref,
            verdict="TRUE",
        )
        source_refs = [
            ref.model_dump(mode="json")
            for stage, item in stages.items()
            if stage is not SimpleStage.FINDING_DONE
            for ref in item.output_refs
        ]
        finding_ref = artifacts.put_json(
            {
                "kind": "simple_finding",
                "analysis_id": run.analysis_id,
                "hypothesis_id": hypothesis,
                "validated_poc_ref": validated_ref.model_dump(mode="json"),
                "scope_gate_status": "UNCERTAIN",
                "source_refs": source_refs,
            }
        )
        stages[SimpleStage.FINDING_DONE] = _checkpoint(
            identity,
            SimpleStage.FINDING_DONE,
            (finding_ref,),
            validated=validated_ref,
            verdict="TRUE",
        )
        display_id = f"F-{number:03d}"
        fresh_refs[display_id] = finding_ref
        scope_status = str(
            project_scope_review(
                stages[SimpleStage.SCOPE_GATE_DONE],
                artifacts,
                policy_snapshot_ref=run.policy_snapshot_ref,
                repository_url=run.repository,
            )["status"]
        )
        poc_bytes = artifacts.read(content_ref)
        provenance = {
            "schema_version": 1,
            "analysis_id": run.analysis_id,
            "display_id": display_id,
            "finding_id": hypothesis,
            "repository": (
                "[REDACTED:LOCAL_REPOSITORY]"
                if run.repository.startswith("file:")
                else run.repository
            ),
            "tested_commit": run.commit_id,
            "cwe": "CWE-78",
            "ecosystem": "pip",
            "package_name": "example",
            "affected_versions": "<= 1.0",
            "patched_versions": None,
            "severity": second_severity if number == 2 else "High",
            "technical_status": "ACCEPT",
            "scope_status": scope_status,
            "report_permission": "REVIEW_REQUIRED",
            "static_coverage": None,
            "execution": {"command": "python poc.py", "exit_code": 0},
            "poc": {
                "path": "poc.py",
                "original_sha256": content_ref.content_hash,
                "attachment_sha256": hashlib.sha256(poc_bytes).hexdigest(),
                "redacted": False,
            },
            "sources": {
                key: ref.model_dump(mode="json")
                for key, ref in {
                    "finding": finding_ref,
                    "poc": content_ref,
                    "validated_poc": validated_ref,
                    "execution": execution_ref,
                    "technical": stages[SimpleStage.TECH_GATE_DONE].output_refs[0],
                    "scope": stages[SimpleStage.SCOPE_GATE_DONE].output_refs[0],
                    "stdout": stdout_ref,
                    "stderr": stderr_ref,
                }.items()
            },
        }
        report_en = f"# Finding {display_id}\n".encode()
        report_kr = f"# 결과 {display_id}\n".encode()
        published = publish_bundle(
            root=data_dir,
            analysis_id=run.analysis_id,
            display_id=display_id,
            finding_ref=finding_ref,
            files=(
                BundleFile("report_en.md", report_en, "text/markdown; charset=utf-8"),
                BundleFile("report_kr.md", report_kr, "text/markdown; charset=utf-8"),
                BundleFile("poc.py", poc_bytes, "text/x-python; charset=utf-8"),
                BundleFile(
                    "evidence/provenance.json",
                    canonical_bytes(provenance),
                    "application/json",
                ),
            ),
            put_artifact=artifacts.put_bytes,
        )
        markdown_path = (
            data_dir.resolve() / "reports" / run.analysis_id / f"{display_id}.md"
        )
        markdown_path.write_bytes(report_kr)
        report_ref = artifacts.put_bytes(report_kr, "text/markdown")
        summary_ref = artifacts.put_json(
            {"kind": "simple_report", "finding_id": hypothesis}
        )
        stages[SimpleStage.REPORT_DONE] = _checkpoint(
            identity,
            SimpleStage.REPORT_DONE,
            (summary_ref, report_ref),
            inputs=(finding_ref,),
            validated=validated_ref,
        ).model_copy(
            update={
                "bundle_manifest_ref": published.manifest_ref,
                "bundle_archive_ref": published.archive_ref,
                "markdown_path": str(markdown_path),
                "report_ref": report_ref,
            }
        )
        output.extend(stages.values())
    with sqlite3.connect(database) as connection:
        for number, display_id in enumerate(("F-001", "F-002"), 1):
            finding_ref = fresh_refs[display_id]
            connection.execute(
                "UPDATE finding_display_ids SET finding_hash=?, finding_ref_json=? "
                "WHERE analysis_id=? AND display_number=?",
                (
                    finding_ref.content_hash,
                    finding_ref.model_dump_json(),
                    run.analysis_id,
                    number,
                ),
            )
    store = SimpleCheckpointStore(database)
    store.save_analysis_run(run)
    for checkpoint in output:
        store.save_checkpoint(checkpoint)
    projection = project_current_finding_groups(
        run, output, fresh_refs, data_dir=data_dir, database_path=database
    )
    assert projection.visible_group_count == 1
    return run, output, projection.groups[0], data_dir, database, store


def test_current_group_bundle_contains_verified_original_member_evidence(
    tmp_path: Path,
) -> None:
    run, checkpoints, group, data_dir, database, _store = _reported_case(tmp_path)
    before = database.read_bytes()
    archive = current_group_bundle(
        run, checkpoints, group, data_dir=data_dir, database_path=database
    )
    assert database.read_bytes() == before
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        assert zipped.read("members/F-001/poc.py") == b"print(1)"
        assert zipped.read("members/F-002/poc.py") == b"print(1)"
        assert group.group_id.encode() in zipped.read("report_en.md")


def test_current_group_bundle_rejects_unverifiable_local_repository_provenance(
    tmp_path: Path,
) -> None:
    run, checkpoints, group, data_dir, database, _store = _reported_case(
        tmp_path,
        repository="file:///C:/local/fixture",
    )
    with pytest.raises(GroupBundleUnavailable) as error:
        current_group_bundle(
            run, checkpoints, group, data_dir=data_dir, database_path=database
        )
    assert error.value.code == "GROUP_REPOSITORY_UNVERIFIABLE"


def test_group_reader_does_not_create_missing_runtime_directories(
    tmp_path: Path,
) -> None:
    run, checkpoints, _group, data_dir, _database, _store = _reported_case(tmp_path)
    identity = next(
        item.identity for item in checkpoints if item.stage is SimpleStage.FINDING_DONE
    )
    staging = data_dir / "staging"
    staging.rename(data_dir / "staging_saved")
    with pytest.raises(
        GroupBundleUnavailable, match="GROUP_ARTIFACT_STORE_UNAVAILABLE"
    ):
        _read_only_artifact_reader(data_dir, identity)
    assert not staging.exists()


def test_current_report_groups_recomputes_ids_without_allocating(
    tmp_path: Path,
) -> None:
    run, checkpoints, group, data_dir, database, _store = _reported_case(tmp_path)
    before = database.read_bytes()
    projected = current_report_groups(
        run, checkpoints, data_dir=data_dir, database_path=database
    )
    assert projected.groups[0].group_id == group.group_id
    assert database.read_bytes() == before


def test_stale_report_or_changed_archive_withholds_group_only(tmp_path: Path) -> None:
    run, checkpoints, group, data_dir, database, _store = _reported_case(tmp_path)
    stale = [
        item.model_copy(update={"status": "FAILED"})
        if item.identity.hypothesis_id == "hyp-2"
        and item.stage is SimpleStage.REPORT_DONE
        else item
        for item in checkpoints
    ]
    with pytest.raises(GroupBundleUnavailable, match="GROUP_MEMBER_STALE"):
        current_group_bundle(
            run, stale, group, data_dir=data_dir, database_path=database
        )
    bundle = data_dir / "reports" / run.analysis_id / "F-002" / "bundle.zip"
    bundle.write_bytes(b"tampered")
    with pytest.raises(GroupBundleUnavailable, match="GROUP_MEMBER_STALE"):
        current_group_bundle(
            run, checkpoints, group, data_dir=data_dir, database_path=database
        )


def test_group_export_abstains_on_conflicting_member_facts(tmp_path: Path) -> None:
    run, checkpoints, group, data_dir, database, _store = _reported_case(
        tmp_path, second_severity="Low"
    )
    with pytest.raises(GroupBundleUnavailable, match="GROUP_FACT_CONFLICT"):
        current_group_bundle(
            run, checkpoints, group, data_dir=data_dir, database_path=database
        )


def test_missing_member_manifest_or_changed_pinned_source_withholds_group(
    tmp_path: Path,
) -> None:
    run, checkpoints, group, data_dir, database, _store = _reported_case(tmp_path)
    manifest = data_dir / "reports" / run.analysis_id / "F-002" / "manifest.json"
    manifest.unlink()
    with pytest.raises(GroupBundleUnavailable, match="GROUP_MEMBER_STALE"):
        current_group_bundle(
            run, checkpoints, group, data_dir=data_dir, database_path=database
        )
    changed_root = tmp_path / "changed"
    changed_root.mkdir()
    second = _reported_case(changed_root)
    second_run, second_checkpoints, second_group, second_data, second_db, _ = second
    assert second_run.workspace_path is not None
    source = second_run.workspace_path / "app.py"
    source.write_bytes(source.read_bytes() + b"\n# changed\n")
    with pytest.raises(GroupBundleUnavailable, match="GROUP_NOT_CURRENT"):
        current_group_bundle(
            second_run,
            second_checkpoints,
            second_group,
            data_dir=second_data,
            database_path=second_db,
        )


def test_legacy_singleton_or_client_forged_group_is_denied(tmp_path: Path) -> None:
    run, checkpoints, group, data_dir, database, _store = _reported_case(tmp_path)
    forged = group.__class__(
        group_id=group.group_id,
        representative_id="F-001",
        member_ids=("F-001",),
        members=group.members[:1],
        status="PROVEN_SAME_FLOW",
        scope_status=group.scope_status,
    )
    with pytest.raises(GroupBundleUnavailable, match="GROUP_NOT_CURRENT"):
        current_group_bundle(
            run, checkpoints, forged, data_dir=data_dir, database_path=database
        )


def test_public_group_export_reuses_current_evidence_without_new_finding_ids(
    tmp_path: Path,
) -> None:
    run, _checkpoints, group, data_dir, database, store = _reported_case(tmp_path)
    AnalysisDisplayIdStore(database).get_or_allocate(run.analysis_id)
    application = PublicSimpleRuntimeApplication.__new__(PublicSimpleRuntimeApplication)
    application._config = SimpleNamespace(data_dir=data_dir)  # type: ignore[assignment]
    application._store = store
    application._display = AnalysisDisplayIdStore(database)
    before = database.read_bytes()
    relative = application.export_report_group("A-001", group.group_id)
    assert relative.startswith(f"reports/{run.analysis_id}/groups/{group.group_id}/")
    path = data_dir / relative
    if os.name == "nt":
        path = Path("\\\\?\\" + str(path))
    archive = path.read_bytes()
    assert b"report_en.md" in archive
    assert application.export_report_group("A-001", group.group_id) == relative
    assert database.read_bytes() == before
    with pytest.raises((ValueError, LookupError)):
        application.export_report_group("A-001", "../unsafe")
    with pytest.raises(GroupBundleUnavailable, match="GROUP_NOT_CURRENT"):
        application.export_report_group("A-001", "f" * 64)


def test_dashboard_group_download_and_outputs_tab_keep_raw_reports(
    tmp_path: Path,
) -> None:
    run, _checkpoints, group, data_dir, _database, _store = _reported_case(tmp_path)
    query = DashboardQuery(data_dir)
    body = query.group_bundle_bytes(run.analysis_id, group.group_id)
    with zipfile.ZipFile(io.BytesIO(body)) as zipped:
        assert "members/F-002/report_en.md" in zipped.namelist()
    outputs = query.get_analysis_tab(run.analysis_id, "outputs")
    reports = outputs["reports"]
    groups = outputs["finding_groups"]
    assert isinstance(reports, list) and all(isinstance(item, dict) for item in reports)
    assert isinstance(groups, list) and isinstance(groups[0], dict)
    assert {item["display_id"] for item in reports} == {"F-001", "F-002"}
    assert groups[0]["bundle_url"] == (
        f"/api/analyses/{run.analysis_id}/groups/{group.group_id}/bundle.zip"
    )
    with pytest.raises(DashboardNotFound):
        query.group_bundle_bytes(run.analysis_id, "f" * 64)


def test_dashboard_keeps_current_group_when_other_report_lacks_group_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, _checkpoints, group, data_dir, _database, _store = _reported_case(tmp_path)
    query = DashboardQuery(data_dir)
    original_reports = query._reports(run.analysis_id)
    legacy_row = original_reports[0].model_copy(update={"display_id": "F-099"})
    monkeypatch.setattr(
        query, "_reports", lambda _analysis_id: (*original_reports, legacy_row)
    )
    tab = query.get_analysis_tab(run.analysis_id, "outputs")
    reports = tab["reports"]
    groups = tab["finding_groups"]
    assert isinstance(reports, list) and len(reports) == 3
    assert isinstance(groups, list) and isinstance(groups[0], dict)
    assert groups[0]["group_id"] == group.group_id
    assert groups[0]["bundle_url"]


def test_presentation_summary_lists_only_default_root_reports(tmp_path: Path) -> None:
    run, _checkpoints, _group, data_dir, _database, _store = _reported_case(tmp_path)
    query = DashboardQuery(data_dir)
    members = query.presentation_bundle_members(run.analysis_id)
    assert "reports/F-001.md" in members
    assert "reports/originals/F-002/report_kr.md" in members
    assert "reports/en/F-001.md" in members
    summary = json.loads(members["presentation/summary.json"])
    assert summary["english_report_ids"] == ["F-001"]
    assert summary["original_member_report_ids"] == ["F-002"]
    explicit = query.bundle_members(run.analysis_id, report_ids=frozenset({"F-002"}))
    assert "reports/F-002.md" in explicit
    assert "reports/originals/F-002/report_kr.md" not in explicit
