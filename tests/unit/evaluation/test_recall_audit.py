from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Literal

import pytest

from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.candidates import CandidateOrigin, StaticCandidate
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CandidateTerminal,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.recall_audit import Oracle, OracleCase, audit_analysis
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _saved_run(
    tmp_path: Path,
    *,
    terminal: Literal["COMPLETE", "PARTIAL"] = "COMPLETE",
    static_disposition: Literal["FULL", "PARTIAL"] = "FULL",
    static_proof: bool = True,
    manifest_paths: tuple[str, ...] = ("app.py",),
    coverage_overrides: dict[str, object] | None = None,
) -> tuple[Path, Path]:
    data_dir = tmp_path / "data"
    database = RuntimePaths(data_dir).database
    store = SimpleCheckpointStore(database)
    static_identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    static_artifacts = SimpleArtifactRepository(data_dir, static_identity)
    coverage = {
        "kind": "simple_static_coverage_v1",
        "analysis_id": "analysis-1",
        "workspace_id": "workspace-1",
        "commit_id": "a" * 40,
        "fingerprint": "scope-1",
        "expected_count": 1,
        "verified_count": 1,
        "gaps": [],
        "unsupported": [],
        "unsupported_files": [],
        "excluded_test_files": [],
        "out_of_scope_product_files": [],
        "unavailable_paths": [],
        "unavailable": False,
        "ast_parse_errors": [],
        "ast_parse_error_count": 0,
        "ast_oversize_paths": [],
        "ast_oversize_count": 0,
        "ast_truncated": False,
        "engine_errors": [],
        "codeql_configured": False,
        "codeql_error": None,
    }
    coverage.update(coverage_overrides or {})
    coverage_ref = static_artifacts.put_json(coverage)
    manifest_ref = static_artifacts.put_json(
        {"kind": "simple_tracked_sources", "paths": list(manifest_paths)}
    )
    bundle_ref = static_artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "analysis_id": "analysis-1",
            "workspace_id": "workspace-1",
            "commit_id": "a" * 40,
            "source_manifest_ref": manifest_ref.model_dump(mode="json"),
            "static_coverage_ref": coverage_ref.model_dump(mode="json"),
        }
    )
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id="analysis-1",
            display_analysis_id="A-001",
            workspace_id="workspace-1",
            commit_id="a" * 40,
            repository="https://example.test/python-repo",
            static_bundle_ref=bundle_ref if static_proof else None,
            static_coverage_ref=coverage_ref if static_proof else None,
            static_disposition=static_disposition,
            candidate_pipeline_version=2,
            candidate_scope_fingerprint="scope-1",
            candidate_terminal=CandidateTerminal(
                status=terminal,
                bundle_hash=bundle_ref.content_hash,
                scope_fingerprint="scope-1",
                decision_counts={},
                deep_counts={},
                hypothesis_count=0,
                producer_finished=True,
            ),
        )
    )
    if static_proof:
        static_checkpoint = StageCheckpoint(
            identity=static_identity,
            stage=SimpleStage.STATIC_DONE,
            stage_version=STAGE_VERSION[SimpleStage.STATIC_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(coverage_ref, bundle_ref),
        )
        with sqlite3.connect(database) as connection:
            connection.execute(
                "INSERT INTO simple_runtime_checkpoints "
                "(analysis_id, hypothesis_key, stage, checkpoint_json, input_hash, "
                "updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    "analysis-1",
                    "",
                    SimpleStage.STATIC_DONE.value,
                    static_checkpoint.model_dump_json(),
                    static_checkpoint.input_hash,
                    static_checkpoint.updated_at.isoformat(),
                ),
            )
        root_ref = static_artifacts.put_json({"kind": "simple_surface_index"})
        root_checkpoint = StageCheckpoint(
            identity=static_identity,
            stage=SimpleStage.HYPOTHESIS_DONE,
            stage_version=STAGE_VERSION[SimpleStage.HYPOTHESIS_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=(bundle_ref,),
            input_hash=input_reference_hash((bundle_ref,)),
            output_refs=(root_ref,),
        )
        with sqlite3.connect(database) as connection:
            connection.execute(
                "INSERT INTO simple_runtime_checkpoints "
                "(analysis_id, hypothesis_key, stage, checkpoint_json, input_hash, "
                "updated_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    "analysis-1",
                    "",
                    SimpleStage.HYPOTHESIS_DONE.value,
                    root_checkpoint.model_dump_json(),
                    root_checkpoint.input_hash,
                    root_checkpoint.updated_at.isoformat(),
                ),
            )
    return data_dir, database


def _oracle(
    *,
    vetted_candidate_ids: tuple[str, ...] = (),
    vetted_hypothesis_ids: tuple[str, ...] = (),
    finding_inventory_reviewed: bool = False,
) -> Oracle:
    return Oracle(
        repository="https://example.test/python-repo",
        commit="a" * 40,
        cases=(
            OracleCase(
                case_id="sql-1",
                cwe="CWE-89",
                path="app.py",
                source_line=10,
                sink_line=20,
                rationale="Vetted request parameter reaches SQL execution.",
                vetted_candidate_ids=vetted_candidate_ids,
                vetted_hypothesis_ids=vetted_hypothesis_ids,
                finding_inventory_reviewed=finding_inventory_reviewed,
            ),
        ),
    )


def _ref(data_dir: Path) -> StoredDataRef:
    return SimpleArtifactRepository(
        data_dir,
        CheckpointIdentity(
            analysis_id="analysis-1",
            workspace_id="workspace-1",
            commit_id="a" * 40,
            hypothesis_id="hyp-1",
        ),
    ).put_json({"fixture": "evidence"})


def _candidate(
    data_dir: Path,
    database: Path,
    *,
    candidate_id: str = "candidate-1",
    kind: Literal["ENTRY_POINT", "FLOW", "HINT"] = "FLOW",
    line: int = 20,
    decision: str = "INCLUDE",
    deep_status: str = "COMPLETE",
) -> None:
    ref = _ref(data_dir)
    candidate = StaticCandidate(
        candidate_id=candidate_id,
        kind=kind,
        path="app.py",
        line=line,
        end_line=line,
        evidence_ref=ref,
        origins=(
            CandidateOrigin(
                engine="codeql",
                rule_id="py/sql-injection",
                artifact_ref=ref,
                result_index=0,
            ),
        ),
        evidence_key=candidate_id,
    )
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO simple_static_candidates "
            "(analysis_id, workspace_id, commit_id, scope_fingerprint, "
            "candidate_id, candidate_json, decision, deep_status) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "analysis-1",
                "workspace-1",
                "a" * 40,
                "scope-1",
                candidate_id,
                candidate.model_dump_json(),
                decision,
                deep_status,
            ),
        )
    store = SimpleCheckpointStore(database)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    run = store.require_analysis_run("analysis-1")
    assert run.candidate_terminal is not None
    store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_terminal": run.candidate_terminal.model_copy(
                    update={
                        "decision_counts": store.candidate_counts(identity, "scope-1"),
                        "deep_counts": store.candidate_deep_counts(identity, "scope-1"),
                    }
                )
            }
        )
    )


def _link(database: Path, candidate_id: str = "candidate-1") -> None:
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO simple_candidate_hypotheses "
            "(analysis_id, workspace_id, commit_id, hypothesis_id) "
            "VALUES (?, ?, ?, ?)",
            ("analysis-1", "workspace-1", "a" * 40, "hyp-1"),
        )
        connection.execute(
            "INSERT INTO simple_candidate_hypothesis_links "
            "(analysis_id, workspace_id, commit_id, scope_fingerprint, "
            "candidate_id, hypothesis_id) VALUES (?, ?, ?, ?, ?, ?)",
            ("analysis-1", "workspace-1", "a" * 40, "scope-1", candidate_id, "hyp-1"),
        )


def _checkpoint(
    database: Path,
    stage: SimpleStage,
    *,
    status: StageStatus = StageStatus.SUCCEEDED,
    verdict: str | None = None,
    validated: StoredDataRef | None = None,
    output_refs: tuple[StoredDataRef, ...] = (),
    input_refs: tuple[StoredDataRef, ...] = (),
    gate: str | None = None,
    attempt_id: str | None = None,
) -> None:
    value = StageCheckpoint.model_validate(
        {
            "identity": CheckpointIdentity(
                analysis_id="analysis-1",
                workspace_id="workspace-1",
                commit_id="a" * 40,
                hypothesis_id="hyp-1",
            ),
            "stage": stage,
            "stage_version": STAGE_VERSION[stage],
            "status": status,
            "input_refs": input_refs,
            "input_hash": input_reference_hash(input_refs),
            "output_refs": output_refs,
            "validated_poc_ref": validated,
            "verdict": verdict,
            "gate_decision": gate,
            "attempt_id": attempt_id,
        }
    )
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO simple_runtime_checkpoints "
            "(analysis_id, hypothesis_key, stage, checkpoint_json, input_hash, "
            "updated_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                "analysis-1",
                "hyp-1",
                stage.value,
                value.model_dump_json(),
                value.input_hash,
                value.updated_at.isoformat(),
            ),
        )


def _verified_finding_chain(data_dir: Path, database: Path) -> StoredDataRef:
    artifacts = SimpleArtifactRepository(
        data_dir,
        CheckpointIdentity(
            analysis_id="analysis-1",
            workspace_id="workspace-1",
            commit_id="a" * 40,
            hypothesis_id="hyp-1",
        ),
    )
    proposal = artifacts.put_json({"kind": "simple_hypothesis_proposal"})
    pro = artifacts.put_json({"kind": "simple_pro_con"})
    content = artifacts.put_bytes(b"print('poc')", "text/x-python")
    poc = artifacts.put_json({"content_ref": content.model_dump(mode="json")})
    execution = artifacts.put_json(
        {
            "candidate_ref": poc.model_dump(mode="json"),
            "content_ref": content.model_dump(mode="json"),
            "attempt_id": "attempt-1",
        }
    )
    stdout = artifacts.put_bytes(b"ok", "text/plain")
    stderr = artifacts.put_bytes(b"", "text/plain")
    validated = artifacts.put_json(
        {
            "candidate_ref": poc.model_dump(mode="json"),
            "content_ref": content.model_dump(mode="json"),
            "execution_ref": execution.model_dump(mode="json"),
            "attempt_id": "attempt-1",
        }
    )
    final = artifacts.put_json(
        {
            "kind": "simple_verification_result",
            "result": {"verdict": "TRUE"},
            "source_refs": [
                validated.model_dump(mode="json"),
                execution.model_dump(mode="json"),
            ],
        }
    )
    cwe = artifacts.put_json(
        {"kind": "simple_cwe_label", "result": {"primary_cwe": "CWE-89"}}
    )
    technical = artifacts.put_json(
        {"kind": "simple_technical_gate", "result": {"status": "ACCEPT"}}
    )
    scope = artifacts.put_json({"kind": "simple_rule_scope_gate"})
    stages = (
        (SimpleStage.PRO_CON_DONE, (pro,)),
        (SimpleStage.POC_CANDIDATE_DONE, (poc, content)),
        (SimpleStage.POC_EXECUTION_DONE, (execution, stdout, stderr)),
        (SimpleStage.VERIFICATION_FINAL_DONE, (final,)),
        (SimpleStage.CWE_DONE, (cwe,)),
        (SimpleStage.TECH_GATE_DONE, (technical,)),
        (SimpleStage.SCOPE_GATE_DONE, (scope,)),
    )
    source_refs = [
        ref.model_dump(mode="json") for _stage, refs in stages for ref in refs
    ]
    finding = artifacts.put_json(
        {
            "kind": "simple_finding",
            "analysis_id": "analysis-1",
            "hypothesis_id": "hyp-1",
            "validated_poc_ref": validated.model_dump(mode="json"),
            "source_refs": source_refs,
        }
    )
    report = artifacts.put_json(
        {"kind": "report", "finding_ref": finding.model_dump(mode="json")}
    )
    _checkpoint(
        database, SimpleStage.PRO_CON_DONE, output_refs=(pro,), input_refs=(proposal,)
    )
    _checkpoint(database, SimpleStage.POC_CANDIDATE_DONE, output_refs=(poc, content))
    _checkpoint(
        database,
        SimpleStage.POC_EXECUTION_DONE,
        output_refs=(execution, stdout, stderr),
        validated=validated,
        attempt_id="attempt-1",
    )
    _checkpoint(
        database,
        SimpleStage.VERIFICATION_FINAL_DONE,
        output_refs=(final,),
        validated=validated,
        verdict="TRUE",
    )
    _checkpoint(database, SimpleStage.CWE_DONE, output_refs=(cwe,))
    _checkpoint(
        database, SimpleStage.TECH_GATE_DONE, output_refs=(technical,), gate="ACCEPT"
    )
    _checkpoint(database, SimpleStage.SCOPE_GATE_DONE, output_refs=(scope,))
    _checkpoint(
        database,
        SimpleStage.FINDING_DONE,
        output_refs=(finding,),
        validated=validated,
        verdict="TRUE",
    )
    _checkpoint(
        database,
        SimpleStage.REPORT_DONE,
        input_refs=(finding,),
        output_refs=(report,),
        validated=validated,
    )
    return validated


def test_complete_scan_without_candidate_reports_static_gap_without_writing(
    tmp_path: Path,
) -> None:
    data_dir, database = _saved_run(tmp_path)
    before = database.read_bytes()

    result = audit_analysis(
        data_dir, "analysis-1", _oracle(finding_inventory_reviewed=True)
    )

    assert result["cases"][0]["first_gap"] == "STATIC_CANDIDATE"
    assert result["cases"][0]["status"] == "MISSED"
    assert result["counts"] == {"MISSED": 1}
    assert database.read_bytes() == before


def test_lost_candidate_row_does_not_become_a_static_miss(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    store = SimpleCheckpointStore(database)
    run = store.require_analysis_run("analysis-1")
    assert run.candidate_terminal is not None
    store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_terminal": run.candidate_terminal.model_copy(
                    update={
                        "decision_counts": {"INCLUDE": 1},
                        "deep_counts": {"COMPLETE": 1},
                    }
                )
            }
        )
    )

    result = audit_analysis(
        data_dir, "analysis-1", _oracle(finding_inventory_reviewed=True)
    )

    assert result["analysis_complete"] is False
    assert result["cases"][0]["status"] == "INCOMPLETE"
    assert result["cases"][0]["first_gap"] == "CANDIDATE_LEDGER_MISMATCH"


def test_full_python_scan_with_stub_file_is_measurable(tmp_path: Path) -> None:
    data_dir, _ = _saved_run(tmp_path, manifest_paths=("app.py", "types.pyi"))

    result = audit_analysis(
        data_dir, "analysis-1", _oracle(finding_inventory_reviewed=True)
    )

    assert result["analysis_complete"] is True
    assert result["cases"][0]["status"] == "MISSED"


def test_mixed_repository_partial_is_measurable_for_fully_scanned_python(
    tmp_path: Path,
) -> None:
    data_dir, _ = _saved_run(
        tmp_path,
        terminal="PARTIAL",
        static_disposition="PARTIAL",
        coverage_overrides={
            "out_of_scope_product_files": [
                {"path": "frontend/app.ts", "reason": "NON_PYTHON"}
            ]
        },
    )

    result = audit_analysis(
        data_dir, "analysis-1", _oracle(finding_inventory_reviewed=True)
    )

    assert result["analysis_complete"] is True
    assert result["cases"][0]["status"] == "MISSED"
    assert result["cases"][0]["first_gap"] == "STATIC_CANDIDATE"


def test_partial_with_uncovered_attack_surface_remains_incomplete(
    tmp_path: Path,
) -> None:
    data_dir, database = _saved_run(
        tmp_path,
        terminal="PARTIAL",
        static_disposition="PARTIAL",
        coverage_overrides={
            "out_of_scope_product_files": [
                {"path": "frontend/app.ts", "reason": "NON_PYTHON"}
            ]
        },
    )
    store = SimpleCheckpointStore(database)
    run = store.require_analysis_run("analysis-1")
    assert run.candidate_terminal is not None
    store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_terminal": run.candidate_terminal.model_copy(
                    update={"surface_counts": {"UNCOVERED": 1}}
                )
            }
        )
    )

    result = audit_analysis(
        data_dir, "analysis-1", _oracle(finding_inventory_reviewed=True)
    )

    assert result["analysis_complete"] is False
    assert result["cases"][0]["status"] == "INCOMPLETE"


@pytest.mark.parametrize(
    "stage",
    [SimpleStage.VERIFICATION_INITIAL_DONE, SimpleStage.VERIFICATION_FINAL_DONE],
)
def test_hold_verdict_is_not_a_measured_miss(
    tmp_path: Path, stage: SimpleStage
) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    _checkpoint(database, stage, verdict="HOLD")

    result = audit_analysis(
        data_dir,
        "analysis-1",
        _oracle(
            vetted_candidate_ids=("candidate-1",),
            vetted_hypothesis_ids=("hyp-1",),
            finding_inventory_reviewed=True,
        ),
    )

    assert result["cases"][0]["status"] == "INCOMPLETE"
    assert result["cases"][0]["first_gap"] == "HOLD_VERIFICATION"


@pytest.mark.parametrize(
    "limitation",
    [
        {"unsupported": [{"extension": ".py", "file_count": 1}]},
        {"out_of_scope_product_files": ["app.py"]},
        {"ast_oversize_count": 1, "ast_oversize_paths": ["app.py"]},
        {"ast_parse_error_count": 1},
        {"codeql_error": "query failed"},
        {"unavailable": True},
    ],
)
def test_static_limitation_is_not_a_measured_miss(
    tmp_path: Path, limitation: dict[str, object]
) -> None:
    data_dir, _ = _saved_run(tmp_path, coverage_overrides=limitation)

    result = audit_analysis(
        data_dir, "analysis-1", _oracle(finding_inventory_reviewed=True)
    )

    assert result["analysis_complete"] is False
    assert result["cases"][0]["status"] == "INCOMPLETE"


def test_blocked_root_hypothesis_evidence_is_not_a_static_miss(
    tmp_path: Path,
) -> None:
    data_dir, database = _saved_run(tmp_path)
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT checkpoint_json FROM simple_runtime_checkpoints "
            "WHERE analysis_id = ? AND hypothesis_key = '' AND stage = ?",
            ("analysis-1", SimpleStage.HYPOTHESIS_DONE.value),
        ).fetchone()
        assert row is not None
        checkpoint = StageCheckpoint.model_validate_json(row[0]).model_copy(
            update={
                "status": StageStatus.BLOCKED,
                "error_code": "HYPOTHESIS_EVIDENCE_INVALID",
            }
        )
        connection.execute(
            "UPDATE simple_runtime_checkpoints SET checkpoint_json = ? "
            "WHERE analysis_id = ? AND hypothesis_key = '' AND stage = ?",
            (
                checkpoint.model_dump_json(),
                "analysis-1",
                SimpleStage.HYPOTHESIS_DONE.value,
            ),
        )

    result = audit_analysis(
        data_dir, "analysis-1", _oracle(finding_inventory_reviewed=True)
    )

    assert result["analysis_complete"] is False
    assert result["cases"][0]["status"] == "INCOMPLETE"
    assert result["cases"][0]["first_gap"] == "ROOT_HYPOTHESIS_UNVERIFIED"


def test_partial_scan_is_not_counted_as_a_false_negative(tmp_path: Path) -> None:
    data_dir, _ = _saved_run(tmp_path, terminal="PARTIAL")

    result = audit_analysis(data_dir, "analysis-1", _oracle())

    assert result["cases"][0]["status"] == "INCOMPLETE"
    assert result["counts"] == {"INCOMPLETE": 1}
    assert result["analysis_complete"] is False


def test_full_static_evidence_is_traced_separately_from_partial_pipeline(
    tmp_path: Path,
) -> None:
    data_dir, database = _saved_run(tmp_path, terminal="PARTIAL")
    _candidate(data_dir, database, deep_status="NO_HYPOTHESIS")

    result = audit_analysis(
        data_dir,
        "analysis-1",
        _oracle(vetted_candidate_ids=("candidate-1",), finding_inventory_reviewed=True),
    )

    assert result["cases"][0]["candidate_ids"] == ["candidate-1"]
    assert result["cases"][0]["status"] == "INCOMPLETE"
    assert result["cases"][0]["first_gap"] == "PIPELINE_UNFINISHED"


def test_complete_marker_without_static_evidence_is_not_a_measured_miss(
    tmp_path: Path,
) -> None:
    data_dir, _ = _saved_run(tmp_path, static_proof=False)

    result = audit_analysis(data_dir, "analysis-1", _oracle())

    assert result["cases"][0]["status"] == "INCOMPLETE"
    assert result["cases"][0]["first_gap"] == "STATIC_EVIDENCE_UNVERIFIED"


def test_oracle_path_outside_scanned_product_files_is_not_a_miss(
    tmp_path: Path,
) -> None:
    data_dir, _ = _saved_run(tmp_path)
    oracle = _oracle(finding_inventory_reviewed=True)
    other = oracle.cases[0]
    out_of_scope = Oracle(
        repository=oracle.repository,
        commit=oracle.commit,
        cases=(
            OracleCase(
                case_id=other.case_id,
                cwe=other.cwe,
                path="tests/test_app.py",
                source_line=other.source_line,
                sink_line=other.sink_line,
                rationale=other.rationale,
                finding_inventory_reviewed=True,
            ),
        ),
    )

    result = audit_analysis(data_dir, "analysis-1", out_of_scope)

    assert result["cases"][0]["status"] == "INCOMPLETE"
    assert result["cases"][0]["first_gap"] == "ORACLE_OUT_OF_SCOPE"


def test_stale_manual_candidate_mapping_is_incomplete_not_static_miss(
    tmp_path: Path,
) -> None:
    data_dir, _ = _saved_run(tmp_path)

    result = audit_analysis(
        data_dir,
        "analysis-1",
        _oracle(
            vetted_candidate_ids=("candidate-from-other-run",),
            finding_inventory_reviewed=True,
        ),
    )

    assert result["cases"][0]["status"] == "INCOMPLETE"
    assert result["cases"][0]["first_gap"] == "ORACLE_CANDIDATE_MAPPING_INVALID"


def test_excluded_flow_is_attributed_to_discovery(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database, decision="EXCLUDE", deep_status="NO_HYPOTHESIS")

    result = audit_analysis(
        data_dir,
        "analysis-1",
        _oracle(vetted_candidate_ids=("candidate-1",), finding_inventory_reviewed=True),
    )

    assert result["cases"][0]["candidate_ids"] == ["candidate-1"]
    assert result["cases"][0]["first_gap"] == "DISCOVERY"
    assert result["cases"][0]["status"] == "MISSED"


def test_unlinked_entry_point_is_possible_not_detected(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(
        data_dir, database, kind="ENTRY_POINT", line=10, deep_status="NO_HYPOTHESIS"
    )

    result = audit_analysis(data_dir, "analysis-1", _oracle())

    assert result["cases"][0]["candidate_ids"] == ["candidate-1"]
    assert result["cases"][0]["status"] == "POSSIBLE"
    assert result["cases"][0]["first_gap"] == "HYPOTHESIS"


def test_verified_finding_for_linked_flow_is_detected(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    _verified_finding_chain(data_dir, database)

    result = audit_analysis(
        data_dir,
        "analysis-1",
        _oracle(
            vetted_candidate_ids=("candidate-1",),
            vetted_hypothesis_ids=("hyp-1",),
        ),
    )

    assert result["cases"][0]["status"] == "DETECTED"
    assert result["cases"][0]["hypothesis_ids"] == ["hyp-1"]


def test_corrupt_current_poc_is_not_counted_as_detected(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    validated = _verified_finding_chain(data_dir, database)
    artifact = (
        RuntimePaths(data_dir).artifacts
        / "sha256"
        / validated.content_hash[:2]
        / validated.content_hash[2:]
    )
    artifact.write_bytes(b"corrupt")

    result = audit_analysis(
        data_dir,
        "analysis-1",
        _oracle(
            vetted_candidate_ids=("candidate-1",),
            vetted_hypothesis_ids=("hyp-1",),
        ),
    )

    assert result["cases"][0]["status"] == "INCOMPLETE"
    assert result["cases"][0]["first_gap"] == "FINDING_EVIDENCE_UNVERIFIED"


def test_partial_pipeline_reports_stale_confirmed_finding_evidence(
    tmp_path: Path,
) -> None:
    data_dir, database = _saved_run(tmp_path, terminal="PARTIAL")
    _verified_finding_chain(data_dir, database)
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            "SELECT checkpoint_json FROM simple_runtime_checkpoints "
            "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
            ("analysis-1", "hyp-1", SimpleStage.VERIFICATION_FINAL_DONE.value),
        ).fetchone()
        assert row is not None
        stale = StageCheckpoint.model_validate_json(row[0]).model_copy(
            update={"stage_version": "old"}
        )
        connection.execute(
            "UPDATE simple_runtime_checkpoints SET checkpoint_json = ? "
            "WHERE analysis_id = ? AND hypothesis_key = ? AND stage = ?",
            (
                stale.model_dump_json(),
                "analysis-1",
                "hyp-1",
                SimpleStage.VERIFICATION_FINAL_DONE.value,
            ),
        )

    result = audit_analysis(
        data_dir,
        "analysis-1",
        _oracle(vetted_hypothesis_ids=("hyp-1",)),
    )

    assert result["cases"][0]["status"] == "INCOMPLETE"
    assert result["cases"][0]["first_gap"] == "FINDING_EVIDENCE_UNVERIFIED"


def test_vetted_free_exploration_finding_detects_without_candidate_link(
    tmp_path: Path,
) -> None:
    data_dir, database = _saved_run(tmp_path)
    _verified_finding_chain(data_dir, database)

    result = audit_analysis(
        data_dir,
        "analysis-1",
        _oracle(vetted_hypothesis_ids=("hyp-1",)),
    )

    assert result["cases"][0]["candidate_ids"] == []
    assert result["cases"][0]["hypothesis_ids"] == ["hyp-1"]
    assert result["cases"][0]["status"] == "DETECTED"
    assert result["counts"] == {"DETECTED": 1}


def test_multiple_candidates_are_one_ground_truth_case(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database, candidate_id="candidate-1")
    _candidate(data_dir, database, candidate_id="candidate-2")

    result = audit_analysis(
        data_dir,
        "analysis-1",
        _oracle(vetted_candidate_ids=("candidate-1", "candidate-2")),
    )

    assert result["cases"][0]["candidate_ids"] == ["candidate-1", "candidate-2"]
    assert len(result["cases"]) == 1
    assert sum(result["counts"].values()) == 1


def test_missing_candidate_table_is_error_not_no_candidates(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    with sqlite3.connect(database) as connection:
        connection.execute("DROP TABLE simple_static_candidates")

    with pytest.raises(sqlite3.OperationalError):
        audit_analysis(data_dir, "analysis-1", _oracle())


def test_failed_poc_is_execution_error_not_disproof(tmp_path: Path) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database)
    _link(database)
    _checkpoint(database, SimpleStage.POC_EXECUTION_DONE, status=StageStatus.FAILED)

    result = audit_analysis(
        data_dir, "analysis-1", _oracle(vetted_candidate_ids=("candidate-1",))
    )

    assert result["cases"][0]["status"] == "INCOMPLETE"
    assert result["cases"][0]["first_gap"] == "POC_EXECUTION_ERROR"


def test_same_sink_without_vetted_candidate_identity_is_not_a_discovery_miss(
    tmp_path: Path,
) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database, decision="EXCLUDE", deep_status="NO_HYPOTHESIS")

    result = audit_analysis(data_dir, "analysis-1", _oracle())

    assert result["cases"][0]["status"] == "POSSIBLE"
    assert result["cases"][0]["first_gap"] == "CANDIDATE_IDENTITY_UNVERIFIED"


def test_unreviewed_free_exploration_cannot_be_declared_missed(
    tmp_path: Path,
) -> None:
    data_dir, _ = _saved_run(tmp_path)

    result = audit_analysis(data_dir, "analysis-1", _oracle())

    assert result["cases"][0]["status"] == "POSSIBLE"
    assert result["cases"][0]["first_gap"] == "FINDING_INVENTORY_UNREVIEWED"


def test_vetted_inconclusive_candidate_is_hypothesis_gap_after_full_review(
    tmp_path: Path,
) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(data_dir, database, deep_status="INCONCLUSIVE")

    result = audit_analysis(
        data_dir,
        "analysis-1",
        _oracle(vetted_candidate_ids=("candidate-1",), finding_inventory_reviewed=True),
    )

    assert result["cases"][0]["status"] == "MISSED"
    assert result["cases"][0]["first_gap"] == "HYPOTHESIS"


def test_unvetted_nearby_candidate_error_does_not_override_discovery_miss(
    tmp_path: Path,
) -> None:
    data_dir, database = _saved_run(tmp_path)
    _candidate(
        data_dir,
        database,
        candidate_id="candidate-1",
        decision="EXCLUDE",
        deep_status="NO_HYPOTHESIS",
    )
    _candidate(data_dir, database, candidate_id="candidate-2")
    _link(database, candidate_id="candidate-2")
    _checkpoint(database, SimpleStage.POC_EXECUTION_DONE, status=StageStatus.FAILED)

    result = audit_analysis(
        data_dir,
        "analysis-1",
        _oracle(vetted_candidate_ids=("candidate-1",), finding_inventory_reviewed=True),
    )

    assert result["cases"][0]["candidate_ids"] == ["candidate-1", "candidate-2"]
    assert result["cases"][0]["status"] == "MISSED"
    assert result["cases"][0]["first_gap"] == "DISCOVERY"


def test_oracle_commit_mismatch_refuses_comparison(tmp_path: Path) -> None:
    data_dir, _ = _saved_run(tmp_path)
    oracle = _oracle()
    wrong = Oracle(repository=oracle.repository, commit="c" * 40, cases=oracle.cases)

    try:
        audit_analysis(data_dir, "analysis-1", wrong)
    except ValueError as error:
        assert str(error) == "RECALL_ORACLE_TARGET_MISMATCH"
    else:
        raise AssertionError("comparison must fail for a different commit")
