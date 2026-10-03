from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import cast

import pytest

from sastsimi.composition.simple_runtime_composition import (
    PublicSimpleRuntimeApplication,
)
from sastsimi.config.user_config import SimpleExecutionProfile, UserConfig
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attack_surfaces import AttackSurface, SurfaceIndex
from sastsimi.simple_runtime.models import (
    CandidateTerminal,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageFailure,
    StageResult,
    StageStatus,
)


def _application(
    tmp_path: Path,
) -> tuple[PublicSimpleRuntimeApplication, CheckpointIdentity]:
    data_dir = tmp_path / "data"
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
    app = PublicSimpleRuntimeApplication(config, profile)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    AnalysisDisplayIdStore(app._store.database_path).get_or_allocate(
        identity.analysis_id
    )
    return app, identity


def _coverage(
    tmp_path: Path,
    app: PublicSimpleRuntimeApplication,
    identity: CheckpointIdentity,
    *,
    coverage_updates: dict[str, object] | None = None,
    mismatch_run_ref: bool = False,
    broken_ref: bool = False,
    omit_fields: tuple[str, ...] = (),
    blocked: bool = False,
) -> None:
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    coverage: dict[str, object] = {
        "kind": "simple_static_coverage_v1",
        "analysis_id": identity.analysis_id,
        "workspace_id": identity.workspace_id,
        "commit_id": identity.commit_id,
        "fingerprint": "f" * 64,
        "expected_count": 25,
        "verified_count": 2,
        "gaps": [
            {
                "path": f"pkg/file_{index}.py",
                "rule_id": "rule.eval",
                "reason": "scan_gap",
            }
            for index in range(23)
        ],
        "unavailable_paths": [
            {"path": f"pkg/unavailable_{index}.py", "reason": "scan_unavailable"}
            for index in range(21)
        ],
        "unsupported_files": [
            {"path": f"pkg/unsupported_{index}.py", "reason": "no_applicable_rule"}
            for index in range(22)
        ],
        "excluded_test_files": [
            {"path": f"tests/test_{index}.py", "reason": "test-directory:tests"}
            for index in range(24)
        ],
        "out_of_scope_product_files": [
            {"path": f"web/app_{index}.ts", "reason": "non_python_product_source"}
            for index in range(4)
        ],
    }
    if coverage_updates:
        coverage.update(coverage_updates)
    for field in omit_fields:
        coverage.pop(field)
    coverage_ref = artifacts.put_json(coverage)
    if broken_ref:
        coverage_ref = coverage_ref.model_copy(update={"content_hash": "0" * 64})
    bundle_ref = artifacts.put_json(
        {
            "kind": "simple_static_fact_bundle",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "static_coverage_ref": coverage_ref.model_dump(mode="json"),
        }
    )
    checkpoint = app._store.mark_running(
        identity, SimpleStage.STATIC_DONE, (), attempt_id="test-static"
    )
    if blocked:
        app._store.mark_failure(
            checkpoint,
            StageFailure(
                code="STATIC_COVERAGE_NO_VERIFIED_RESULTS",
                retryable=False,
                safe_message="static incomplete",
                evidence_refs=(coverage_ref, bundle_ref),
            ),
            StageStatus.BLOCKED,
        )
    else:
        profile_ref = artifacts.put_json({"kind": "profile"})
        app._store.complete(
            checkpoint, StageResult(output_refs=(profile_ref, bundle_ref))
        )
    run_ref = (
        artifacts.put_json({"kind": "stale-coverage"})
        if mismatch_run_ref
        else coverage_ref
    )
    app._store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id="A-001",
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="https://github.com/example/repo",
            static_bundle_ref=None if blocked else bundle_ref,
            static_coverage_ref=None if blocked else run_ref,
            static_disposition="PARTIAL",
        )
    )


def test_status_projects_bounded_distinct_static_coverage_categories(
    tmp_path: Path,
) -> None:
    app, identity = _application(tmp_path)
    _coverage(tmp_path, app, identity)

    status = app.status("A-001")

    assert status["static_coverage_status"] == "AVAILABLE"
    assert (status["static_coverage_verified"], status["static_coverage_expected"]) == (
        2,
        25,
    )
    assert status["static_coverage_gap_count"] == 23
    gap_preview = status["static_coverage_gap_preview"]
    assert isinstance(gap_preview, list)
    assert gap_preview[0] == {
        "path": "pkg/file_0.py",
        "rule_id": "rule.eval",
        "reason": "scan_gap",
    }
    assert len(gap_preview) == 20
    assert status["static_coverage_gap_truncated_count"] == 3
    assert status["static_coverage_unavailable_path_count"] == 21
    unavailable_preview = status["static_coverage_unavailable_path_preview"]
    assert isinstance(unavailable_preview, list)
    assert len(unavailable_preview) == 20
    assert status["static_coverage_unavailable_path_truncated_count"] == 1
    assert status["static_coverage_unsupported_count"] == 22
    unsupported_preview = status["static_coverage_unsupported_preview"]
    assert isinstance(unsupported_preview, list)
    assert len(unsupported_preview) == 20
    assert status["static_coverage_unsupported_truncated_count"] == 2
    assert status["static_excluded_test_file_count"] == 24
    excluded_preview = status["static_excluded_test_file_preview"]
    assert isinstance(excluded_preview, list)
    assert excluded_preview[0] == {
        "path": "tests/test_0.py",
        "reason": "test-directory:tests",
    }
    assert status["static_excluded_test_file_truncated_count"] == 4
    assert status["static_out_of_scope_product_count"] == 4
    assert status["static_out_of_scope_product_truncated_count"] == 0


def test_cli_status_partial_requires_final_candidate_marker(tmp_path: Path) -> None:
    app, identity = _application(tmp_path)
    _coverage(tmp_path, app, identity)
    run = app._store.require_analysis_run(identity.analysis_id)
    assert run.static_bundle_ref is not None
    checkpoint = app._store.mark_running(
        identity, SimpleStage.HYPOTHESIS_DONE, (), attempt_id="test-hypothesis"
    )
    app._store.complete(checkpoint, StageResult(output_refs=(run.static_bundle_ref,)))
    app._store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_pipeline_version": 1,
                "candidate_scope_fingerprint": "f" * 64,
                "candidate_terminal": CandidateTerminal(
                    status="PARTIAL",
                    bundle_hash=run.static_bundle_ref.content_hash,
                    scope_fingerprint="f" * 64,
                    decision_counts={},
                    deep_counts={},
                    hypothesis_count=0,
                ),
            }
        )
    )

    assert app.status("A-001")["status"] == "PARTIAL"


def test_status_accepts_exclusion_reason_with_joined_evidence(tmp_path: Path) -> None:
    app, identity = _application(tmp_path)
    excluded = [
        {
            "path": "web/button.spec.ts",
            "reason": "test-basename+content:javascript-typescript",
        }
    ]
    _coverage(
        tmp_path,
        app,
        identity,
        coverage_updates={"excluded_test_files": excluded},
    )

    status = app.status("A-001")

    assert status["static_coverage_status"] == "AVAILABLE"
    assert status["static_excluded_test_file_count"] == 1
    assert status["static_excluded_test_file_preview"] == excluded


@pytest.mark.parametrize(
    "corruption",
    [
        "run_ref",
        "artifact_ref",
        "analysis_id",
        "workspace_id",
        "commit_id",
        "fingerprint",
    ],
)
def test_status_rejects_stale_or_cross_run_static_coverage(
    tmp_path: Path, corruption: str
) -> None:
    app, identity = _application(tmp_path)
    _coverage(
        tmp_path,
        app,
        identity,
        mismatch_run_ref=corruption == "run_ref",
        broken_ref=corruption == "artifact_ref",
        coverage_updates={corruption: "other-run"}
        if corruption in {"analysis_id", "workspace_id", "commit_id", "fingerprint"}
        else None,
    )

    status = app.status("A-001")

    assert status["static_coverage_status"] == "UNAVAILABLE"
    assert status["static_coverage_expected"] is None
    assert status["static_coverage_gap_count"] is None


def test_status_marks_old_missing_scope_categories_unknown(tmp_path: Path) -> None:
    app, identity = _application(tmp_path)
    _coverage(
        tmp_path,
        app,
        identity,
        omit_fields=("excluded_test_files", "out_of_scope_product_files"),
    )

    status = app.status("A-001")

    assert status["static_coverage_status"] == "AVAILABLE"
    assert status["static_excluded_test_file_count"] is None
    assert status["static_out_of_scope_product_count"] is None


def test_blocked_static_stage_discloses_its_exact_coverage_evidence(
    tmp_path: Path,
) -> None:
    app, identity = _application(tmp_path)
    _coverage(tmp_path, app, identity, blocked=True)

    status = app.status("A-001")

    assert status["status"] == "BLOCKED"
    assert status["static_coverage_status"] == "AVAILABLE"
    assert status["static_coverage_gap_count"] == 23
    assert status["static_excluded_test_file_count"] == 24


def test_status_marks_static_artifact_database_error_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, identity = _application(tmp_path)
    _coverage(tmp_path, app, identity)

    def read_failure(_repository: SimpleArtifactRepository, _ref: object) -> bytes:
        raise sqlite3.DatabaseError("artifact record unavailable")

    monkeypatch.setattr(SimpleArtifactRepository, "read", read_failure)
    status = app.status("A-001")

    assert status["static_coverage_status"] == "UNAVAILABLE"
    assert status["static_coverage_expected"] is None


def test_v2_public_status_exposes_scoped_surface_progress(tmp_path: Path) -> None:
    app, identity = _application(tmp_path)
    _coverage(tmp_path, app, identity)
    run = app._store.require_analysis_run(identity.analysis_id)
    assert run.static_bundle_ref is not None
    app._store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_pipeline_version": 2,
                "candidate_scope_fingerprint": "scope-1",
            }
        )
    )
    index = SurfaceIndex(
        scope_fingerprint="scope-1",
        static_bundle_hash=run.static_bundle_ref.content_hash,
        ast_manifest_hash="ast-hash",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        candidate_inventory_hash="inventory-hash",
        candidate_count=0,
        surfaces=(
            AttackSurface(
                surface_id="auth-surface",
                type="AUTHORIZATION",
                path="pkg/auth.py",
                symbol="check_access" + "x" * (1024 * 1024),
                line=1,
                linked_candidate_ids=(),
                evidence_refs=(),
                detector="AST",
            ),
        ),
        static_gaps=(),
    )
    index_ref = SimpleArtifactRepository(tmp_path / "data", identity).put_json(
        index.to_json()
    )
    app._store.save_attack_surface_index(
        identity,
        "scope-1",
        static_bundle_hash=run.static_bundle_ref.content_hash,
        ast_manifest_hash="ast-hash",
        candidate_inventory_hash="inventory-hash",
        candidate_count=0,
        index_ref=index_ref,
    )

    context_ref = SimpleArtifactRepository(tmp_path / "data", identity).put_json(
        {"kind": "simple_surface_hypothesis_result_v1", "context_id": "part-1"}
    )
    app._store.commit_surface_exploration(
        identity,
        "scope-1",
        "auth-surface",
        "part-1",
        static_bundle_hash=run.static_bundle_ref.content_hash,
        index_hash=index_ref.content_hash,
        context_hash="context-part-1",
        source_sha256=None,
        status="NO_HYPOTHESIS",
        result_ref=context_ref,
        registrations=(),
    )

    status = app.status("A-001")
    assert status["percentage_kind"] == "known_checkpoint_fraction"
    phase_counts = cast(dict[str, dict[str, int]], status["phase_counts"])
    assert phase_counts["surface"] == {
        "recorded_contexts": 1,
        "recorded_surfaces": 1,
        "completed": 0,
        "total": 1,
    }

    coverage = {
        **index.to_json(),
        "kind": "simple_attack_surface_coverage_v1",
        "surfaces": [{**index.surfaces[0].to_json(), "coverage_status": "COVERED"}],
        "complete": True,
    }
    coverage_ref = SimpleArtifactRepository(tmp_path / "data", identity).put_json(
        coverage
    )
    missing_coverage_ref = index_ref.model_copy(update={"content_hash": "0" * 64})
    checkpoint = app._store.mark_running(
        identity, SimpleStage.HYPOTHESIS_DONE, (), attempt_id="test-producer"
    )
    app._store.complete(
        checkpoint,
        StageResult(output_refs=(index_ref, coverage_ref, missing_coverage_ref)),
    )
    terminal = CandidateTerminal(
        status="PARTIAL",
        bundle_hash=run.static_bundle_ref.content_hash,
        scope_fingerprint="scope-1",
        decision_counts={},
        deep_counts={},
        hypothesis_count=0,
        surface_index_hash=index_ref.content_hash,
        surface_coverage_hash=coverage_ref.content_hash,
        surface_counts={"COVERED": 1, "UNCOVERED": 0, "INSUFFICIENT": 0},
        producer_finished=True,
    )
    app._store.save_analysis_run(
        app._store.require_analysis_run(identity.analysis_id).model_copy(
            update={"candidate_terminal": terminal}
        )
    )
    verified = app.status("A-001")
    verified_phases = cast(dict[str, dict[str, int]], verified["phase_counts"])
    assert verified_phases["surface"]["covered"] == 1

    app._store.save_analysis_run(
        app._store.require_analysis_run(identity.analysis_id).model_copy(
            update={
                "candidate_terminal": terminal.model_copy(
                    update={"surface_coverage_hash": "0" * 64}
                )
            }
        )
    )
    unverified = app.status("A-001")
    unverified_phases = cast(dict[str, dict[str, int]], unverified["phase_counts"])
    assert unverified_phases["surface"] == {
        "recorded_contexts": 1,
        "recorded_surfaces": 1,
        "completed": 0,
        "total": 1,
    }
