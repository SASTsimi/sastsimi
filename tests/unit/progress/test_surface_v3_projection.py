"""Public v3 surface counts require reevaluated, current pinned proof."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from sastsimi.composition.simple_runtime_composition import (
    PublicSimpleRuntimeApplication,
)
from sastsimi.config.user_config import UserConfig
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.dashboard.query import DashboardQuery
from sastsimi.progress.projector import ProgressProjector
from sastsimi.reporting.coverage_disclosure import CoverageDisclosure
from sastsimi.simple_runtime import stages
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CandidateTerminal,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.stages import ReporterStage
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_coverage_v3 import (
    SurfaceCoverageV3,
    evaluate_surface_coverage_v3,
)
from sastsimi.simple_runtime.surface_proof_read import (
    verified_surface_coverage_counts,
)
from tests.unit.progress.test_progress_projector import _ref, _save
from tests.unit.simple_runtime.test_surface_coverage_v2 import _Case
from tests.unit.simple_runtime.test_surface_coverage_v3 import _v5_case


def test_projector_keeps_v3_reviewed_distinct_and_partial(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="v3-projection",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id=None,
    )
    index_ref = _ref("index").model_copy(update={"content_hash": "b" * 64})
    proof_ref = _ref("proof").model_copy(update={"content_hash": "c" * 64})
    _save(store, identity, SimpleStage.STATIC_DONE)
    _save(
        store,
        identity,
        SimpleStage.HYPOTHESIS_DONE,
        output_refs=(index_ref, proof_ref),
    )
    terminal = CandidateTerminal(
        status="PARTIAL",
        bundle_hash="a" * 64,
        scope_fingerprint="scope-1",
        decision_counts={},
        deep_counts={},
        hypothesis_count=0,
        surface_index_hash="b" * 64,
        surface_coverage_hash="c" * 64,
        surface_proof_version=3,
        scope_certificate_hash="d" * 64,
        surface_counts={"COVERED": 1, "UNCOVERED": 0, "INSUFFICIENT": 1},
        producer_finished=True,
        pending_child_count=0,
    )
    snapshot = ProgressProjector(store).snapshot(
        identity.analysis_id,
        candidate_pipeline_version=2,
        candidate_counts={},
        candidate_deep_counts={},
        candidate_terminal=terminal,
        candidate_bundle_hash="a" * 64,
        candidate_scope_fingerprint="scope-1",
        surface_counts={
            "TOTAL": 2,
            "CONTEXT_RECORDS": 1,
            "COVERED": 1,
            "UNCOVERED": 0,
            "INSUFFICIENT": 1,
            "REVIEWED": 1,
            "RAW_STATIC_GAP_COUNT": 4,
            "EFFECTIVE_PYTHON_GAP_COUNT": 0,
            "UNRESOLVED_REASON_COUNT": 1,
            "REASON_CODE_CONNECTED_ROLE_PROOF_MISSING": 1,
        },
        surface_index_hash="b" * 64,
    )
    assert snapshot.status == "PARTIAL"
    assert snapshot.phase_counts["surface"]["reviewed"] == 1
    assert snapshot.phase_counts["surface"]["covered"] == 1
    assert snapshot.phase_counts["surface"]["insufficient"] == 1
    assert (
        snapshot.phase_counts["surface"]["reason_code_CONNECTED_ROLE_PROOF_MISSING"]
        == 1
    )

    with pytest.raises(ValueError, match="ANALYSIS_PROGRESS_SURFACE_COUNTS_INVALID"):
        ProgressProjector(store).snapshot(
            identity.analysis_id,
            candidate_pipeline_version=2,
            surface_counts={1: 1},  # type: ignore[dict-item]
        )


def _saved_v3_case(
    tmp_path: Path,
) -> tuple[_Case, SurfaceCoverageV3, StoredDataRef, CandidateTerminal]:
    case, prior, _prior_ref, plan, _parts, _graph, _graph_ref = _v5_case(tmp_path)
    for row in case.progress.values():
        case.store.commit_surface_exploration(
            case.identity,
            case.index.scope_fingerprint,
            row.surface_id,
            row.context_id,
            static_bundle_hash=row.static_bundle_hash,
            index_hash=row.index_hash,
            context_hash=row.context_hash,
            source_sha256=row.source_sha256,
            status=row.status,
            result_ref=row.result_ref,
            registrations=(),
            proposal_version=row.proposal_version,
        )
    proof = evaluate_surface_coverage_v3(
        case.identity,
        case.index,
        prior,
        plan,
        case.progress,
        case.store,
        case.artifacts,
    )
    coverage_ref = case.artifacts.put_json(proof.to_json())
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.candidate_terminal is not None
    terminal = run.candidate_terminal.model_copy(
        update={
            "surface_proof_version": 3,
            "surface_coverage_hash": coverage_ref.content_hash,
        }
    )
    case.store.save_analysis_run(
        run.model_copy(update={"candidate_terminal": terminal})
    )
    return case, proof, coverage_ref, terminal


def test_v3_counts_require_current_reevaluated_proof(tmp_path: Path) -> None:
    case, proof, coverage_ref, terminal = _saved_v3_case(tmp_path)
    payload = proof.to_json()
    counts = verified_surface_coverage_counts(
        payload,
        case.index,
        terminal,
        artifacts=case.artifacts,
        coverage_ref=coverage_ref,
        store=case.store,
    )
    assert counts is not None
    assert counts["COVERED"] == 1
    assert counts["INSUFFICIENT"] == 1
    assert counts["REVIEWED"] == 0
    assert counts["UNRESOLVED_REASON_COUNT"] >= 1
    assert (
        sum(value for key, value in counts.items() if key.startswith("REASON_CODE_"))
        == counts["UNRESOLVED_REASON_COUNT"]
    )
    assert (
        verified_surface_coverage_counts(
            payload,
            case.index,
            terminal,
            artifacts=case.artifacts,
            coverage_ref=coverage_ref,
        )
        is None
    )
    forged = deepcopy(payload)
    assert isinstance(forged["surfaces"], list)
    forged["surfaces"][0]["coverage_status"] = "COVERED"
    assert (
        verified_surface_coverage_counts(
            forged,
            case.index,
            terminal,
            artifacts=case.artifacts,
            coverage_ref=coverage_ref,
            store=case.store,
        )
        is None
    )


def test_cli_composition_reads_v3_only_through_verified_ref(tmp_path: Path) -> None:
    case, _proof, coverage_ref, _terminal = _saved_v3_case(tmp_path)
    case.store.save_attack_surface_index(
        case.identity,
        case.index.scope_fingerprint,
        static_bundle_hash=case.index.static_bundle_hash,
        ast_manifest_hash=case.index.ast_manifest_hash,
        candidate_inventory_hash=case.index.candidate_inventory_hash,
        candidate_count=case.index.candidate_count,
        index_ref=case.index_ref,
    )
    checkpoint = StageCheckpoint(
        identity=case.identity,
        stage=SimpleStage.HYPOTHESIS_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(case.index_ref, coverage_ref),
    )
    case.store.save_checkpoint(checkpoint)
    run = case.store.require_analysis_run(case.identity.analysis_id).model_copy(
        update={
            "candidate_pipeline_version": 2,
            "candidate_scope_fingerprint": case.index.scope_fingerprint,
        }
    )
    case.store.save_analysis_run(run)
    app = object.__new__(PublicSimpleRuntimeApplication)
    app._store = case.store
    app._config = cast(UserConfig, SimpleNamespace(data_dir=tmp_path / "data"))

    counts, index_hash = app._surface_metrics(
        run, case.identity, case.index.scope_fingerprint
    )

    assert index_hash == case.index_ref.content_hash
    assert counts is not None
    assert counts["COVERED"] == 1
    assert counts["INSUFFICIENT"] == 1
    assert counts["REVIEWED"] == 0
    dashboard = DashboardQuery(tmp_path / "data")
    web_counts, web_index_hash = dashboard._surface_metrics(run, [checkpoint])
    assert web_index_hash == case.index_ref.content_hash
    assert web_counts is not None
    assert web_counts["COVERED"] == 1
    assert web_counts["INSUFFICIENT"] == 1
    assert web_counts["REVIEWED"] == 0
    reason_count, reason_preview = dashboard._surface_unresolved_preview(
        run, [checkpoint], web_counts
    )
    assert reason_count is not None and reason_count >= 1
    assert reason_preview

    forged = deepcopy(_proof.to_json())
    assert isinstance(forged["surfaces"], list)
    forged["surfaces"][0]["coverage_status"] = "COVERED"
    forged_ref = case.artifacts.put_json(forged)
    assert run.candidate_terminal is not None
    forged_terminal = run.candidate_terminal.model_copy(
        update={
            "status": "COMPLETE",
            "surface_coverage_hash": forged_ref.content_hash,
            "surface_counts": {"COVERED": 2, "UNCOVERED": 0, "INSUFFICIENT": 0},
        }
    )
    forged_run = run.model_copy(update={"candidate_terminal": forged_terminal})
    case.store.save_analysis_run(forged_run)
    forged_checkpoint = checkpoint.model_copy(
        update={"output_refs": (case.index_ref, forged_ref)}
    )
    for projected, _index_hash in (
        app._surface_metrics(forged_run, case.identity, case.index.scope_fingerprint),
        dashboard._surface_metrics(forged_run, [forged_checkpoint]),
    ):
        assert projected is not None
        assert "COVERED" not in projected


def test_child_reporter_uses_analysis_identity_for_v3_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case, _proof, coverage_ref, _terminal = _saved_v3_case(tmp_path)
    case.store.save_attack_surface_index(
        case.identity,
        case.index.scope_fingerprint,
        static_bundle_hash=case.index.static_bundle_hash,
        ast_manifest_hash=case.index.ast_manifest_hash,
        candidate_inventory_hash=case.index.candidate_inventory_hash,
        candidate_count=case.index.candidate_count,
        index_ref=case.index_ref,
    )
    run = case.store.require_analysis_run(case.identity.analysis_id).model_copy(
        update={"candidate_scope_fingerprint": case.index.scope_fingerprint}
    )
    case.store.save_analysis_run(run)
    assert run.static_coverage_ref is not None
    case.store.save_checkpoint(
        StageCheckpoint(
            identity=case.identity,
            stage=SimpleStage.HYPOTHESIS_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(case.index_ref, coverage_ref),
        )
    )
    disclosure = CoverageDisclosure(
        ref=run.static_coverage_ref,
        fingerprint="f" * 64,
        expected_count=1,
        verified_count=1,
        gap_count=0,
        unsupported_count=0,
        gap_reasons=(),
        unsupported_reasons=(),
        engine_errors=(),
    )
    monkeypatch.setattr(
        stages, "coverage_disclosure", lambda *_args, **_kwargs: disclosure
    )
    child_identity = case.identity.model_copy(update={"hypothesis_id": "child-1"})
    reporter = object.__new__(ReporterStage)
    reporter._store = case.store
    reporter._artifacts = SimpleArtifactRepository(
        tmp_path / "data", child_identity, create_dirs=False
    )
    child_checkpoint = StageCheckpoint(
        identity=child_identity,
        stage=SimpleStage.REPORT_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(),
    )

    scoped = reporter._coverage(child_checkpoint)

    assert scoped is not None
    assert scoped.surface_proof_version == 3
    assert scoped.surface_covered_count == 1
    assert scoped.surface_insufficient_count == 1
    assert sum(count for _, count in scoped.surface_unresolved_reasons) == (
        scoped.surface_unresolved_reason_count
    )
