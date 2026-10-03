from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from sastsimi.composition.simple_runtime_composition import (
    PublicSimpleRuntimeApplication,
)
from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.config.user_config import SimpleExecutionProfile, UserConfig
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.dashboard.query import DashboardQuery
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.reporting.finding_display_id import FindingDisplayIdStore
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.ast_facts import collect_python_ast
from sastsimi.simple_runtime.candidates import CandidateOrigin, StaticCandidate
from sastsimi.simple_runtime.finding_group_projection import (
    project_current_finding_groups,
)
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

FIXTURE = (
    Path(__file__).resolve().parents[1] / "fixtures/finding_groups/antony_routes.py"
)


def _checkpoint(
    identity: CheckpointIdentity,
    stage: SimpleStage,
    refs: tuple[StoredDataRef, ...],
    *,
    inputs: tuple[StoredDataRef, ...] = (),
    validated: StoredDataRef | None = None,
    verdict: str | None = None,
    gate: str | None = None,
    attempt_id: str | None = None,
) -> StageCheckpoint:
    return StageCheckpoint.model_validate(
        {
            "identity": identity,
            "stage": stage,
            "stage_version": STAGE_VERSION[stage],
            "status": StageStatus.SUCCEEDED,
            "input_refs": inputs,
            "input_hash": input_reference_hash(inputs),
            "output_refs": refs,
            "validated_poc_ref": validated,
            "verdict": verdict,
            "gate_decision": gate,
            "attempt_id": attempt_id,
        }
    )


def _case(
    tmp_path: Path,
) -> tuple[
    SimpleAnalysisRun, list[StageCheckpoint], dict[str, StoredDataRef], Path, Path, Path
]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "app.py").write_bytes(FIXTURE.read_bytes())
    data_dir = tmp_path / "data"
    database = RuntimePaths(data_dir).database
    SimpleCheckpointStore(database)
    identity = CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="commit",
        hypothesis_id="hyp-1",
    )
    artifacts = SimpleArtifactRepository(data_dir, identity)
    summary = collect_python_ast(
        workspace, ["app.py"], artifacts, max_source_bytes=100_000
    )
    static_ref = artifacts.put_json(
        {"kind": "simple_static_fact_bundle", "ast_summary": summary}
    )
    run = SimpleAnalysisRun(
        analysis_id="analysis",
        display_analysis_id="A-001",
        workspace_id="workspace",
        commit_id="commit",
        repository="https://example.test/repo",
        workspace_path=workspace,
        static_bundle_ref=static_ref,
        candidate_scope_fingerprint="scope",
    )
    evidence_ref = artifacts.put_json({"kind": "evidence"})
    candidate = StaticCandidate(
        candidate_id="candidate-1",
        kind="FLOW",
        path="app.py",
        line=7,
        end_line=8,
        evidence_ref=evidence_ref,
        evidence_key="key",
        origins=(
            CandidateOrigin(
                engine="codeql",
                rule_id="py/command-injection",
                artifact_ref=evidence_ref,
                result_index=0,
            ),
        ),
    )
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO simple_static_candidates "
            "(analysis_id, workspace_id, commit_id, scope_fingerprint, "
            "candidate_id, candidate_json) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                "analysis",
                "workspace",
                "commit",
                "scope",
                "candidate-1",
                candidate.model_dump_json(),
            ),
        )
    checkpoints: list[StageCheckpoint] = []
    eligible: dict[str, StoredDataRef] = {}
    ids = FindingDisplayIdStore(database)
    for index in (1, 2):
        current = identity.model_copy(update={"hypothesis_id": f"hyp-{index}"})
        proposal = artifacts.put_json(
            {
                "kind": "simple_hypothesis_proposal",
                "analysis_id": "analysis",
                "hypothesis_id": f"hyp-{index}",
                **(
                    {"candidate_id": "candidate-1"}
                    if index == 1
                    else {"surface_id": "surface-1"}
                ),
                "proposal": {
                    "code_locations": ["app.py:8"],
                    "title": f"proposal {index}",
                },
            }
        )
        pro = artifacts.put_json({"kind": "simple_pro_con"})
        content = artifacts.put_bytes(b"print(1)", "text/x-python")
        poc = artifacts.put_json(
            {
                "kind": "simple_poc_candidate",
                "content_ref": content.model_dump(mode="json"),
            }
        )
        execution = artifacts.put_json(
            {
                "kind": "simple_poc_execution",
                "candidate_ref": poc.model_dump(mode="json"),
                "content_ref": content.model_dump(mode="json"),
                "attempt_id": f"attempt-{index}",
            }
        )
        validated = artifacts.put_json(
            {
                "kind": "simple_validated_poc",
                "candidate_ref": poc.model_dump(mode="json"),
                "content_ref": content.model_dump(mode="json"),
                "execution_ref": execution.model_dump(mode="json"),
                "attempt_id": f"attempt-{index}",
            }
        )
        final = artifacts.put_json({"kind": "simple_verification_final"})
        cwe = artifacts.put_json(
            {"kind": "simple_cwe_label", "result": {"primary_cwe": "CWE-78"}}
        )
        technical = artifacts.put_json(
            {"kind": "simple_technical_gate", "result": {"status": "ACCEPT"}}
        )
        scope = artifacts.put_json(
            {"kind": "simple_rule_scope_gate", "result": {"status": "UNCERTAIN"}}
        )
        stages = [
            _checkpoint(
                current, SimpleStage.PRO_CON_DONE, (pro,), inputs=(proposal, static_ref)
            ),
            _checkpoint(current, SimpleStage.POC_CANDIDATE_DONE, (poc, content)),
            _checkpoint(
                current,
                SimpleStage.POC_EXECUTION_DONE,
                (execution,),
                validated=validated,
                attempt_id=f"attempt-{index}",
            ),
            _checkpoint(
                current,
                SimpleStage.VERIFICATION_FINAL_DONE,
                (final,),
                validated=validated,
                verdict="TRUE",
            ),
            _checkpoint(current, SimpleStage.CWE_DONE, (cwe,)),
            _checkpoint(
                current, SimpleStage.TECH_GATE_DONE, (technical,), gate="ACCEPT"
            ),
            _checkpoint(current, SimpleStage.SCOPE_GATE_DONE, (scope,)),
        ]
        source_refs = [
            ref.model_dump(mode="json") for stage in stages for ref in stage.output_refs
        ]
        finding = artifacts.put_json(
            {
                "kind": "simple_finding",
                "analysis_id": "analysis",
                "hypothesis_id": f"hyp-{index}",
                "validated_poc_ref": validated.model_dump(mode="json"),
                "scope_gate_status": "UNCERTAIN",
                "source_refs": source_refs,
            }
        )
        stages.append(
            _checkpoint(
                current,
                SimpleStage.FINDING_DONE,
                (finding,),
                validated=validated,
                verdict="TRUE",
            )
        )
        checkpoints.extend(stages)
        eligible[ids.get_or_allocate("analysis", finding)] = finding
    return run, checkpoints, eligible, data_dir, database, workspace


def _project(
    case: tuple[
        SimpleAnalysisRun,
        list[StageCheckpoint],
        dict[str, StoredDataRef],
        Path,
        Path,
        Path,
    ],
):
    run, checkpoints, eligible, data_dir, database, _workspace = case
    return project_current_finding_groups(
        run, checkpoints, eligible, data_dir=data_dir, database_path=database
    )


def test_current_verified_candidate_and_surface_findings_group_read_only(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path)
    _, _, _, data_dir, _, _ = case
    before = {path.relative_to(data_dir) for path in data_dir.rglob("*")}
    result = _project(case)
    assert (
        result.raw_count,
        result.visible_group_count,
        result.undetermined_count,
    ) == (2, 1, 0)
    assert result.groups[0].member_ids == ("F-001", "F-002")
    assert result.groups[0].members[0].candidate_origins[0].engine == "codeql"
    assert _project(case) == result
    assert {path.relative_to(data_dir) for path in data_dir.rglob("*")} == before


def test_non_true_or_rejected_gate_never_groups(tmp_path: Path) -> None:
    case = _case(tmp_path)
    run, checkpoints, eligible, data_dir, database, _ = case
    changed = [
        item.model_copy(update={"verdict": "FALSE"})
        if item.identity.hypothesis_id == "hyp-2"
        and item.stage is SimpleStage.VERIFICATION_FINAL_DONE
        else item
        for item in checkpoints
    ]
    result = project_current_finding_groups(
        run, changed, eligible, data_dir=data_dir, database_path=database
    )
    assert result.raw_count == 1
    assert result.groups[0].member_ids == ("F-001",)
    rejected = [
        item.model_copy(update={"gate_decision": "REJECT"})
        if item.identity.hypothesis_id == "hyp-1"
        and item.stage is SimpleStage.TECH_GATE_DONE
        else item
        for item in checkpoints
    ]
    result = project_current_finding_groups(
        run, rejected, eligible, data_dir=data_dir, database_path=database
    )
    assert result.raw_count == 1


def test_stale_finding_and_legacy_proposal_do_not_join_group(tmp_path: Path) -> None:
    case = _case(tmp_path)
    run, checkpoints, eligible, data_dir, database, _ = case
    stale = [
        item.model_copy(update={"status": StageStatus.FAILED})
        if item.identity.hypothesis_id == "hyp-2"
        and item.stage is SimpleStage.FINDING_DONE
        else item
        for item in checkpoints
    ]
    assert (
        project_current_finding_groups(
            run, stale, eligible, data_dir=data_dir, database_path=database
        ).raw_count
        == 1
    )
    identity = CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="commit",
        hypothesis_id="hyp-2",
    )
    artifacts = SimpleArtifactRepository(data_dir, identity)
    old = artifacts.put_json(
        {
            "kind": "simple_hypothesis_proposal",
            "analysis_id": "analysis",
            "hypothesis_id": "hyp-2",
            "proposal": {"code_locations": ["app.py:8"]},
        }
    )
    legacy = []
    for item in checkpoints:
        if (
            item.identity.hypothesis_id == "hyp-2"
            and item.stage is SimpleStage.PRO_CON_DONE
        ):
            inputs = (old, *item.input_refs[1:])
            item = item.model_copy(
                update={
                    "input_refs": inputs,
                    "input_hash": input_reference_hash(inputs),
                }
            )
        legacy.append(item)
    projected = project_current_finding_groups(
        run, legacy, eligible, data_dir=data_dir, database_path=database
    )
    assert (
        projected.raw_count,
        projected.visible_group_count,
        projected.undetermined_count,
    ) == (2, 2, 1)


def test_changed_pinned_source_abstains_without_mutating_record(tmp_path: Path) -> None:
    case = _case(tmp_path)
    _, _, _, _, _, workspace = case
    (workspace / "app.py").write_bytes(FIXTURE.read_bytes() + b"\n# changed\n")
    result = _project(case)
    assert (
        result.raw_count,
        result.visible_group_count,
        result.undetermined_count,
    ) == (2, 2, 2)


def test_corrupt_required_finding_reference_fails_closed(tmp_path: Path) -> None:
    case = _case(tmp_path)
    run, checkpoints, eligible, data_dir, database, _ = case
    first = next(iter(eligible))
    corrupted = {
        **eligible,
        first: eligible[first].model_copy(update={"content_hash": "f" * 64}),
    }
    with pytest.raises(ValueError, match="FINDING_GROUP"):
        project_current_finding_groups(
            run, checkpoints, corrupted, data_dir=data_dir, database_path=database
        )


def test_dashboard_folds_only_presentation_and_keeps_each_report_path(
    tmp_path: Path,
) -> None:
    run, checkpoints, eligible, data_dir, database, _ = _case(tmp_path)
    store = SimpleCheckpointStore(database)
    store.save_analysis_run(run)
    for item in checkpoints:
        store.save_checkpoint(item)
    report_dir = data_dir / "reports" / run.analysis_id
    report_dir.mkdir(parents=True)
    for display_id, finding_ref in eligible.items():
        identity = next(
            item.identity
            for item in checkpoints
            if item.stage is SimpleStage.FINDING_DONE
            and finding_ref in item.output_refs
        )
        artifacts = SimpleArtifactRepository(data_dir, identity)
        report_path = report_dir / f"{display_id}.md"
        report_path.write_text(f"# {display_id}\n", encoding="utf-8")
        report = _checkpoint(
            identity,
            SimpleStage.REPORT_DONE,
            (
                artifacts.put_json({"kind": "draft"}),
                artifacts.put_bytes(f"# {display_id}\n".encode(), "text/markdown"),
            ),
            inputs=(finding_ref,),
        ).model_copy(update={"markdown_path": str(report_path)})
        store.save_checkpoint(report)
    detail = DashboardQuery(data_dir).get_analysis(run.analysis_id)
    assert detail.finding_count == 2
    assert detail.finding_group_count == 1
    assert detail.finding_group_undetermined_count == 0
    assert detail.finding_groups[0].member_ids == ("F-001", "F-002")
    assert tuple(item.display_id for item in detail.reports) == ("F-001", "F-002")
    query = DashboardQuery(data_dir)
    assert query.report_path(run.analysis_id, "F-001").name == "F-001.md"
    assert query.report_path(run.analysis_id, "F-002").name == "F-002.md"
    exported = query.bundle_members(run.analysis_id, include_logs=False)
    assert "reports/F-001.md" in exported
    assert "reports/F-002.md" in exported


def test_public_result_preserves_raw_count_and_adds_proven_group_count(
    tmp_path: Path,
) -> None:
    run, checkpoints, _eligible, data_dir, database, _ = _case(tmp_path)
    store = SimpleCheckpointStore(database)
    store.save_analysis_run(run)
    for item in checkpoints:
        store.save_checkpoint(item)
    assert AnalysisDisplayIdStore(database).get_or_allocate(run.analysis_id) == "A-001"
    config = UserConfig(
        data_dir=data_dir,
        profile_path=tmp_path / "profile.toml",
        auth_mode="API_KEY",
        provider="openai",
        model="test-model",
        credential_ref="env:OPENAI_API_KEY",
        execution_profile="LIGHTWEIGHT",
        max_cost_minor_units=100,
        max_tokens=1000,
        max_elapsed_seconds=3600,
        docker_network="NONE",
        enabled_tools=(),
        detected_versions={},
        setup_ready=True,
    )
    profile = SimpleExecutionProfile(
        provider_profile_ref="test",
        provider="openai",
        model="test-model",
        auth_mode="API_KEY",
        credential_ref="env:OPENAI_API_KEY",
        data_dir=data_dir,
        workspace_root=data_dir / "workspaces",
        max_cost_minor_units=100,
        max_tokens=1000,
        max_elapsed_seconds=3600,
        docker_network="NONE",
        tools={},
    )
    result = PublicSimpleRuntimeApplication(config, profile).result("A-001")
    assert result["finding_count"] == 2
    assert result["findings"] == ["F-001", "F-002"]
    assert result["finding_group_count"] == 1
    assert result["finding_group_undetermined_count"] == 0
    groups = result["finding_groups"]
    assert isinstance(groups, tuple)
    assert groups[0]["member_ids"] == ("F-001", "F-002")
