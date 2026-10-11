"""Read-boundary proof checks for the saved v2 attack-surface projection."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from sastsimi.composition.simple_runtime_composition import (
    PublicSimpleRuntimeApplication,
)
from sastsimi.config.user_config import SimpleExecutionProfile, UserConfig
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import CommitId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.dashboard.query import DashboardQuery
from sastsimi.progress.projector import (
    ProgressProjector,
    read_surface_scope_certificate,
    verified_surface_coverage_counts,
)
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attack_surfaces import (
    AttackSurface,
    StaticGap,
    SurfaceIndex,
)
from sastsimi.simple_runtime.models import (
    CandidateTerminal,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _sha(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _ref(payload: object) -> StoredDataRef:
    digest = _sha(payload)
    return StoredDataRef(
        stored_data_id=StoredDataId(digest),
        data_kind="artifact",
        content_hash=digest,
        workspace_id=WorkspaceId("workspace-1"),
        commit_id=CommitId("c" * 40),
        record_id=None,
    )


def _proof(
    static_bundle_hash: str = "a" * 64,
) -> tuple[SurfaceIndex, dict[str, object], dict[str, object], CandidateTerminal]:
    index = SurfaceIndex(
        scope_fingerprint="scope-1",
        static_bundle_hash=static_bundle_hash,
        ast_manifest_hash="b" * 64,
        workspace_id="workspace-1",
        commit_id="c" * 40,
        candidate_inventory_hash="d" * 64,
        candidate_count=0,
        surfaces=(
            AttackSurface(
                surface_id="surface-1",
                type="AST_ENTRY",
                path="app.py",
                symbol="entry",
                line=8,
                linked_candidate_ids=(),
                evidence_refs=(),
                detector="AST",
            ),
        ),
        static_gaps=(
            StaticGap(
                path="web/app.js",
                rule_id="STATIC_SCOPE",
                reason="NON_PYTHON_PRODUCT_FILE",
            ),
        ),
        index_version=2,
    )
    index_ref = _ref(index.to_json())
    raw_gaps = index.to_json()["static_gaps"]
    certificate: dict[str, object] = {
        "kind": "simple_python_scope_recertification_v1",
        "analysis_id": "analysis-1",
        "workspace_id": "workspace-1",
        "commit_id": "c" * 40,
        "scope_fingerprint": "scope-1",
        "index_ref": index_ref.model_dump(mode="json"),
        "index_hash": index_ref.content_hash,
        "coverage_ref": _ref({"kind": "simple_static_coverage_v1"}).model_dump(
            mode="json"
        ),
        "raw_static_gaps": raw_gaps,
        "raw_coverage_gaps": [],
        "raw_out_of_scope_product_files": [
            {"path": "web/app.js", "reason": "NON_PYTHON_PRODUCT_FILE"}
        ],
        "file_decisions": [],
        "effective_static_gaps": [],
    }
    certificate_ref = _ref(certificate)
    proof: dict[str, object] = {
        "kind": "simple_attack_surface_coverage_v2",
        "scope_fingerprint": index.scope_fingerprint,
        "static_bundle_hash": index.static_bundle_hash,
        "ast_manifest_hash": index.ast_manifest_hash,
        "candidate_inventory_hash": index.candidate_inventory_hash,
        "candidate_count": index.candidate_count,
        "index_hash": index_ref.content_hash,
        "original_coverage_ref": _ref({"kind": "original-v1"}).model_dump(mode="json"),
        "scope_certificate_ref": certificate_ref.model_dump(mode="json"),
        "scope_certificate_hash": certificate_ref.content_hash,
        "raw_static_gaps": raw_gaps,
        "effective_python_gaps": [],
        "surfaces": [
            {
                "surface_id": "surface-1",
                "path": "app.py",
                "line": 8,
                "coverage_status": "COVERED",
                "verified_roles": [],
                "evidence_refs": [_ref({"kind": "review"}).model_dump(mode="json")],
                "unresolved_reason_codes": [],
            }
        ],
        "pending_candidate_count": 0,
        "pending_child_count": 0,
        "complete": True,
    }
    terminal = CandidateTerminal(
        status="COMPLETE",
        bundle_hash=index.static_bundle_hash,
        scope_fingerprint=index.scope_fingerprint,
        decision_counts={},
        deep_counts={},
        hypothesis_count=0,
        surface_index_hash=index_ref.content_hash,
        surface_coverage_hash=_sha(proof),
        surface_proof_version=2,
        scope_certificate_hash=certificate_ref.content_hash,
        surface_counts={"COVERED": 1, "UNCOVERED": 0, "INSUFFICIENT": 0},
        producer_finished=True,
    )
    return index, certificate, proof, terminal


def _review_artifacts(
    tmp_path: Path, index: SurfaceIndex, certificate: dict[str, object]
) -> SimpleArtifactRepository:
    artifacts = SimpleArtifactRepository(
        tmp_path,
        CheckpointIdentity(
            analysis_id="analysis-1",
            workspace_id=index.workspace_id,
            commit_id=index.commit_id,
            hypothesis_id=None,
        ),
    )
    for payload in (
        index.to_json(),
        certificate,
        {"kind": "simple_static_coverage_v1"},
        {"kind": "original-v1"},
        {"kind": "review"},
    ):
        artifacts.put_json(payload)
    return artifacts


def test_v2_verified_counts_distinguish_raw_and_effective(tmp_path: Path) -> None:
    index, certificate, proof, terminal = _proof()
    assert verified_surface_coverage_counts(
        proof,
        index,
        terminal,
        certificate_payload=certificate,
        artifacts=_review_artifacts(tmp_path, index, certificate),
    ) == {
        "COVERED": 1,
        "UNCOVERED": 0,
        "INSUFFICIENT": 0,
        "RAW_STATIC_GAP_COUNT": 1,
        "EFFECTIVE_PYTHON_GAP_COUNT": 0,
        "UNRESOLVED_REASON_COUNT": 0,
    }


def test_v2_missing_or_corrupt_evidence_cas_fails_closed(tmp_path: Path) -> None:
    index, certificate, proof, terminal = _proof()
    artifacts = _review_artifacts(tmp_path, index, certificate)
    evidence_ref = _ref({"kind": "review"})
    assert (
        verified_surface_coverage_counts(
            proof,
            index,
            terminal,
            certificate_payload=certificate,
            artifacts=artifacts,
        )
        is not None
    )
    artifacts.artifacts.path_for(evidence_ref.content_hash).unlink()
    assert (
        verified_surface_coverage_counts(
            proof,
            index,
            terminal,
            certificate_payload=certificate,
            artifacts=artifacts,
        )
        is None
    )
    artifacts.artifacts.path_for(evidence_ref.content_hash).write_bytes(b"corrupt")
    assert (
        verified_surface_coverage_counts(
            proof,
            index,
            terminal,
            certificate_payload=certificate,
            artifacts=artifacts,
        )
        is None
    )


@pytest.mark.parametrize("asset", ["index", "certificate", "static", "original"])
@pytest.mark.parametrize("corrupt", [False, True], ids=["missing", "corrupt"])
def test_v2_referenced_scope_cas_loss_never_shows_complete(
    tmp_path: Path, asset: str, corrupt: bool
) -> None:
    index, certificate, proof, terminal = _proof()
    artifacts = _review_artifacts(tmp_path, index, certificate)
    assert (
        verified_surface_coverage_counts(
            proof, index, terminal, certificate_payload=certificate, artifacts=artifacts
        )["COVERED"]
        == 1
    )
    payload_by_asset: dict[str, object] = {
        "index": index.to_json(),
        "certificate": certificate,
        "static": {"kind": "simple_static_coverage_v1"},
        "original": {"kind": "original-v1"},
    }
    path = artifacts.artifacts.path_for(_ref(payload_by_asset[asset]).content_hash)
    if corrupt:
        path.write_bytes(b"corrupt")
    else:
        path.unlink()
    assert (
        verified_surface_coverage_counts(
            proof, index, terminal, certificate_payload=certificate, artifacts=artifacts
        )
        is None
    )


def test_v2_missing_or_changed_certificate_never_shows_complete(
    tmp_path: Path,
) -> None:
    index, certificate, proof, terminal = _proof()
    artifacts = _review_artifacts(tmp_path, index, certificate)
    assert verified_surface_coverage_counts(proof, index, terminal) is None
    assert (
        verified_surface_coverage_counts(
            proof,
            index,
            terminal,
            certificate_payload={**certificate, "commit_id": "x"},
            artifacts=artifacts,
        )
        is None
    )
    assert (
        verified_surface_coverage_counts(
            {**proof, "effective_python_gaps": [{"path": "app.py"}]},
            index,
            terminal,
            certificate_payload=certificate,
            artifacts=artifacts,
        )
        is None
    )


def test_v2_child_hold_or_wrong_proof_version_cannot_show_complete(
    tmp_path: Path,
) -> None:
    index, certificate, proof, terminal = _proof()
    artifacts = _review_artifacts(tmp_path, index, certificate)
    blocked = {
        **proof,
        "pending_child_count": 1,
        "surfaces": [
            {
                **proof["surfaces"][0],
                "coverage_status": "INSUFFICIENT",
                "unresolved_reason_codes": ["CHILD_HOLD"],
            }
        ],
        "complete": False,
    }
    partial = terminal.model_copy(
        update={
            "status": "PARTIAL",
            "surface_coverage_hash": _sha(blocked),
            "surface_counts": {"COVERED": 0, "UNCOVERED": 0, "INSUFFICIENT": 1},
            "pending_child_count": 1,
        }
    )
    assert verified_surface_coverage_counts(
        blocked, index, partial, certificate_payload=certificate, artifacts=artifacts
    ) == {
        "COVERED": 0,
        "UNCOVERED": 0,
        "INSUFFICIENT": 1,
        "RAW_STATIC_GAP_COUNT": 1,
        "EFFECTIVE_PYTHON_GAP_COUNT": 0,
        "UNRESOLVED_REASON_COUNT": 1,
    }
    assert (
        verified_surface_coverage_counts(
            proof,
            index,
            terminal.model_copy(update={"surface_proof_version": 1}),
            certificate_payload=certificate,
            artifacts=artifacts,
        )
        is None
    )


def test_v2_terminal_can_complete_with_verified_effective_scope_only(
    tmp_path: Path,
) -> None:
    index, certificate, proof, terminal = _proof()
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id=index.workspace_id,
        commit_id=index.commit_id,
        hypothesis_id=None,
    )
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    artifacts = _review_artifacts(tmp_path, index, certificate)
    for stage, refs in (
        (SimpleStage.STATIC_DONE, (_ref({"static": 1}),)),
        (SimpleStage.HYPOTHESIS_DONE, (_ref(index.to_json()), _ref(proof))),
    ):
        store.save_checkpoint(
            StageCheckpoint(
                identity=identity,
                stage=stage,
                status=StageStatus.SUCCEEDED,
                input_refs=(),
                input_hash=input_reference_hash(()),
                output_refs=refs,
            )
        )
    verified = verified_surface_coverage_counts(
        proof, index, terminal, certificate_payload=certificate, artifacts=artifacts
    )
    assert verified is not None
    snapshot = ProgressProjector(store).snapshot(
        identity.analysis_id,
        static_disposition="PARTIAL",
        candidate_pipeline_version=2,
        candidate_counts={},
        candidate_deep_counts={},
        candidate_terminal=terminal,
        candidate_bundle_hash=index.static_bundle_hash,
        candidate_scope_fingerprint=index.scope_fingerprint,
        surface_counts={"TOTAL": 1, "CONTEXT_RECORDS": 1, **verified},
        surface_index_hash=terminal.surface_index_hash,
    )
    assert snapshot.status == "COMPLETE"
    assert snapshot.phase_counts["surface"]["raw_static_gap_count"] == 1
    assert snapshot.phase_counts["surface"]["effective_python_gap_count"] == 0


def test_v4_failure_marker_survives_successful_v1_root_checkpoint(
    tmp_path: Path,
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="c" * 40,
        hypothesis_id=None,
    )
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.HYPOTHESIS_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(_ref({"kind": "saved-v1-root"}),),
        )
    )
    projector = ProgressProjector(store)
    failed = projector.snapshot(
        identity.analysis_id,
        candidate_pipeline_version=2,
        candidate_counts={},
        surface_enrichment_status="BLOCKED",
        surface_enrichment_error_code="SURFACE_SOURCE_UNAVAILABLE",
    )
    assert failed.status == "BLOCKED"
    assert failed.error_code == "SURFACE_SOURCE_UNAVAILABLE"
    assert failed.percent < 100
    active_failure = projector.snapshot(
        identity.analysis_id,
        candidate_pipeline_version=2,
        candidate_counts={},
        analysis_active=True,
        surface_enrichment_status="BLOCKED",
        surface_enrichment_error_code="SURFACE_SOURCE_UNAVAILABLE",
    )
    assert active_failure.status == "BLOCKED"
    legacy = projector.snapshot(
        identity.analysis_id, candidate_pipeline_version=2, candidate_counts={}
    )
    assert legacy.status != "BLOCKED"


def test_v4_running_marker_needs_active_lease(tmp_path: Path) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="c" * 40,
        hypothesis_id=None,
    )
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.HYPOTHESIS_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(_ref({"kind": "saved-v1-root"}),),
        )
    )
    projector = ProgressProjector(store)
    kwargs = {
        "candidate_pipeline_version": 2,
        "candidate_counts": {},
        "surface_enrichment_status": "RUNNING",
    }
    active = projector.snapshot(identity.analysis_id, analysis_active=True, **kwargs)
    assert active.status == "RUNNING"
    assert active.error_code is None
    interrupted = projector.snapshot(
        identity.analysis_id, analysis_active=False, **kwargs
    )
    assert interrupted.status == "PAUSED"
    assert interrupted.error_code == "SURFACE_ENRICHMENT_INTERRUPTED"
    assert interrupted.resume_action == "RESUME_INTERRUPTED"


def test_v2_certificate_loader_rejects_wrong_run_static_ref(tmp_path: Path) -> None:
    _, certificate, _, terminal = _proof()
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="c" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    static_ref = artifacts.put_json({"kind": "simple_static_coverage_v1"})
    certificate_ref = artifacts.put_json(certificate)
    assert (
        read_surface_scope_certificate(artifacts, certificate_ref, static_ref, terminal)
        == certificate
    )
    wrong = artifacts.put_json({"kind": "other-coverage"})
    assert (
        read_surface_scope_certificate(artifacts, certificate_ref, wrong, terminal)
        is None
    )
    assert read_surface_scope_certificate(artifacts, None, static_ref, terminal) is None


@pytest.mark.parametrize("corrupt", [False, True], ids=["missing", "corrupt"])
def test_v2_certificate_loader_rejects_missing_or_corrupt_static_coverage(
    tmp_path: Path, corrupt: bool
) -> None:
    _, certificate, _, terminal = _proof()
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="c" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    static_ref = artifacts.put_json({"kind": "simple_static_coverage_v1"})
    certificate_ref = artifacts.put_json(certificate)
    assert (
        read_surface_scope_certificate(artifacts, certificate_ref, static_ref, terminal)
        == certificate
    )
    path = artifacts.artifacts.path_for(static_ref.content_hash)
    if corrupt:
        path.write_bytes(b"corrupt")
    else:
        path.unlink()
    assert (
        read_surface_scope_certificate(artifacts, certificate_ref, static_ref, terminal)
        is None
    )


def test_cli_and_dashboard_v2_readers_require_exact_certificate(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="c" * 40,
        hypothesis_id=None,
    )
    artifacts = SimpleArtifactRepository(data_dir, identity)
    static_ref = artifacts.put_json({"kind": "static-bundle"})
    static_coverage_ref = artifacts.put_json({"kind": "simple_static_coverage_v1"})
    index, certificate, proof, terminal = _proof(static_ref.content_hash)
    artifacts.put_json({"kind": "review"})
    index_ref = artifacts.put_json(index.to_json())
    certificate_ref = artifacts.put_json(certificate)
    proof_ref = artifacts.put_json(proof)
    artifacts.put_json({"kind": "original-v1"})
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    store.save_attack_surface_index(
        identity,
        index.scope_fingerprint,
        static_bundle_hash=index.static_bundle_hash,
        ast_manifest_hash=index.ast_manifest_hash,
        candidate_inventory_hash=index.candidate_inventory_hash,
        candidate_count=index.candidate_count,
        index_ref=index_ref,
    )
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="local/example",
        static_bundle_ref=static_ref,
        static_coverage_ref=static_coverage_ref,
        static_disposition="PARTIAL",
        candidate_pipeline_version=2,
        candidate_scope_fingerprint=index.scope_fingerprint,
        python_scope_certificate_ref=certificate_ref,
        candidate_terminal=terminal,
    )
    store.save_analysis_run(run)
    checkpoints = [
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.HYPOTHESIS_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(index_ref, proof_ref),
        )
    ]
    store.save_checkpoint(checkpoints[0])
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
    cli_counts, _ = app._surface_metrics(run, identity, index.scope_fingerprint)
    web_counts, _ = DashboardQuery(data_dir)._surface_metrics(run, checkpoints)
    for counts in (cli_counts, web_counts):
        assert counts is not None
        assert counts["COVERED"] == 1
        assert counts["RAW_STATIC_GAP_COUNT"] == 1
        assert counts["EFFECTIVE_PYTHON_GAP_COUNT"] == 0

    failed_run = run.model_copy(
        update={
            "surface_enrichment_plan_ref": artifacts.put_json({"kind": "plan"}),
            "surface_enrichment_status": "BLOCKED",
            "surface_enrichment_error_code": "SURFACE_V4_REPLAY_CORRUPT",
        }
    )
    store.save_analysis_run(failed_run)
    cli_status = app.status(identity.analysis_id)
    assert cli_status["status"] == "BLOCKED"
    assert cli_status["error_code"] == "SURFACE_V4_REPLAY_CORRUPT"
    dashboard_status = DashboardQuery(data_dir).get_analysis(identity.analysis_id)
    assert dashboard_status.status == "BLOCKED"
    assert dashboard_status.error_code == "SURFACE_V4_REPLAY_CORRUPT"
    running_run = failed_run.model_copy(
        update={
            "surface_enrichment_status": "RUNNING",
            "surface_enrichment_error_code": None,
        }
    )
    store.save_analysis_run(running_run)
    interrupted_cli = app.status(identity.analysis_id)
    interrupted_dashboard = DashboardQuery(data_dir).get_analysis(identity.analysis_id)
    assert interrupted_cli["status"] == "PAUSED"
    assert interrupted_cli["error_code"] == "SURFACE_ENRICHMENT_INTERRUPTED"
    assert interrupted_dashboard.status == "PAUSED"
    assert interrupted_dashboard.error_code == "SURFACE_ENRICHMENT_INTERRUPTED"
    preflight_run = failed_run.model_copy(
        update={
            "surface_enrichment_plan_ref": None,
            "python_scope_certificate_ref": None,
            "surface_enrichment_error_code": "SURFACE_V4_PREFLIGHT_FAILED",
        }
    )
    store.save_analysis_run(preflight_run)
    preflight_cli = app.status(identity.analysis_id)
    preflight_dashboard = DashboardQuery(data_dir).get_analysis(identity.analysis_id)
    assert preflight_cli["status"] == "BLOCKED"
    assert preflight_cli["error_code"] == "SURFACE_V4_PREFLIGHT_FAILED"
    assert preflight_dashboard.status == "BLOCKED"
    assert preflight_dashboard.error_code == "SURFACE_V4_PREFLIGHT_FAILED"
    store.save_analysis_run(run)

    unbound = run.model_copy(update={"python_scope_certificate_ref": None})
    for counts, _ in (
        app._surface_metrics(unbound, identity, index.scope_fingerprint),
        DashboardQuery(data_dir)._surface_metrics(unbound, checkpoints),
    ):
        assert counts is not None
        assert "COVERED" not in counts
        assert "EFFECTIVE_PYTHON_GAP_COUNT" not in counts

    reasons = [f"REASON_{number:03d}" for number in range(101)]
    partial_proof = {
        **proof,
        "surfaces": [
            {
                **proof["surfaces"][0],
                "coverage_status": "INSUFFICIENT",
                "unresolved_reason_codes": reasons,
            }
        ],
        "complete": False,
    }
    partial_ref = artifacts.put_json(partial_proof)
    partial_terminal = terminal.model_copy(
        update={
            "status": "PARTIAL",
            "surface_coverage_hash": partial_ref.content_hash,
            "surface_counts": {"COVERED": 0, "UNCOVERED": 0, "INSUFFICIENT": 1},
        }
    )
    partial_run = run.model_copy(update={"candidate_terminal": partial_terminal})
    partial_checkpoint = checkpoints[0].model_copy(
        update={"output_refs": (index_ref, partial_ref)}
    )
    query = DashboardQuery(data_dir)
    partial_counts, _ = query._surface_metrics(partial_run, [partial_checkpoint])
    assert partial_counts is not None
    assert partial_counts["UNRESOLVED_REASON_COUNT"] == 101
    total, preview = query._surface_unresolved_preview(
        partial_run, [partial_checkpoint], partial_counts
    )
    assert total == 101
    assert len(preview) == 100
    assert preview[0] == {
        "surface_id": "surface-1",
        "path": "app.py",
        "reason": "REASON_000",
    }

    artifacts.artifacts.path_for(_ref({"kind": "review"}).content_hash).unlink()
    cli_counts, _ = app._surface_metrics(run, identity, index.scope_fingerprint)
    web_counts, _ = DashboardQuery(data_dir)._surface_metrics(run, checkpoints)
    assert cli_counts is not None and "COVERED" not in cli_counts
    assert web_counts is not None and "COVERED" not in web_counts
    assert app.status(identity.analysis_id)["status"] != "COMPLETE"
