from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.refs import StoredDataRef
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
