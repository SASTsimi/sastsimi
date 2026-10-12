"""Public v4 surface status requires the current successor proof."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.composition.simple_runtime_composition import (
    PublicSimpleRuntimeApplication,
)
from sastsimi.config.user_config import UserConfig
from sastsimi.dashboard.query import DashboardQuery
from sastsimi.progress.projector import ProgressProjector
from sastsimi.reporting.coverage_disclosure import (
    CoverageDisclosure,
    visible_surface_reason_distribution,
)
from sastsimi.simple_runtime import stages
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CandidateTerminal,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.stages import ReporterStage
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_coverage_v4 import verified_saved_coverage_v4
from sastsimi.simple_runtime.surface_proof_read import (
    verified_surface_coverage_counts,
)
from tests.unit.simple_runtime.test_surface_coverage_v4 import (
    _evaluate,
    _save_v6_part,
    _successor_case,
)


def _saved_v4_case(
    tmp_path: Path, *, old_hold: bool = False
) -> tuple[dict[str, Any], StageCheckpoint, CandidateTerminal]:
    data = _successor_case(tmp_path, old_hold=old_hold)
    _save_v6_part(data)
    case = data["case"]
    for row in case.progress.values():
        if row.proposal_version == 3 and row.status == "HYPOTHESES":
            # This fixture represents a pre-existing v3 row with a completed
            # HOLD child. Persist its legacy registration without introducing
            # a new PENDING child during the successor read-side test.
            proposal_ref = case.artifacts.put_json({"kind": "old-v3-proposal"})
            hypothesis_id = row.hypothesis_ids[0]
            child = case.identity.model_copy(update={"hypothesis_id": hypothesis_id})
            pending = StageCheckpoint(
                identity=child,
                stage=SimpleStage.PRO_CON_DONE,
                status=StageStatus.PENDING,
                input_refs=(proposal_ref,),
                input_hash=input_reference_hash((proposal_ref,)),
            )
            registrations = json.dumps(
                [
                    (
                        hypothesis_id,
                        proposal_ref.model_dump_json(),
                        pending.model_dump(mode="json", exclude={"updated_at"}),
                    )
                ],
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            with case.store._connect() as connection:
                connection.execute(
                    "INSERT INTO simple_surface_exploration_progress "
                    "(analysis_id, workspace_id, commit_id, scope_fingerprint, "
                    "surface_id, context_id, static_bundle_hash, index_hash, "
                    "context_hash, source_sha256, status, proposal_version, "
                    "result_ref_json, registrations_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        case.identity.analysis_id,
                        case.identity.workspace_id,
                        case.identity.commit_id,
                        case.index.scope_fingerprint,
                        row.surface_id,
                        row.context_id,
                        row.static_bundle_hash,
                        row.index_hash,
                        row.context_hash,
                        row.source_sha256,
                        row.status,
                        row.proposal_version,
                        row.result_ref.model_dump_json(),
                        registrations,
                    ),
                )
            continue
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
    proof = _evaluate(data)
    proof_ref = case.artifacts.put_json(proof.to_json())
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.candidate_terminal is not None
    counts = {
        status: sum(row.coverage_status == status for row in proof.surfaces)
        for status in ("COVERED", "UNCOVERED", "INSUFFICIENT")
    }
    terminal = run.candidate_terminal.model_copy(
        update={
            "status": "COMPLETE" if proof.complete else "PARTIAL",
            "surface_proof_version": 4,
            "surface_coverage_hash": proof_ref.content_hash,
            "surface_counts": counts,
            "pending_child_count": proof.pending_child_count,
            "hypothesis_count": 1 if old_hold else 0,
        }
    )
    case.store.save_analysis_run(
        run.model_copy(
            update={
                "candidate_terminal": terminal,
                "candidate_pipeline_version": 2,
                "candidate_scope_fingerprint": case.index.scope_fingerprint,
            }
        )
    )
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
        output_refs=(case.index_ref, proof_ref),
    )
    case.store.save_checkpoint(
        StageCheckpoint(
            identity=case.identity,
            stage=SimpleStage.STATIC_DONE,
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(),
        )
    )
    case.store.save_checkpoint(checkpoint)
    verified_saved_coverage_v4(
        case.identity,
        case.index,
        proof_ref,
        SimpleCheckpointStore(
            case.artifacts.paths.database,
            artifact_data_dir=tmp_path / "data",
            read_only=True,
        ),
        case.artifacts,
    )
    data["proof"] = proof
    data["proof_ref"] = proof_ref
    return data, checkpoint, terminal


def test_v4_read_metrics_require_exact_current_successor(tmp_path: Path) -> None:
    data, checkpoint, terminal = _saved_v4_case(tmp_path)
    case = data["case"]
    proof = data["proof"]
    counts = verified_surface_coverage_counts(
        proof.to_json(),
        case.index,
        terminal,
        artifacts=case.artifacts,
        coverage_ref=data["proof_ref"],
        store=case.store,
    )
    assert counts is not None
    assert counts["COVERED"] == 2
    assert counts["INSUFFICIENT"] == 0
    assert counts["REVIEWED"] == 1
    assert (
        verified_surface_coverage_counts(
            proof.to_json(),
            case.index,
            terminal,
            artifacts=case.artifacts,
            coverage_ref=data["proof_ref"],
        )
        is None
    )
    run = case.store.require_analysis_run(case.identity.analysis_id)
    app = object.__new__(PublicSimpleRuntimeApplication)
    app._store = case.store
    app._config = cast(UserConfig, SimpleNamespace(data_dir=tmp_path / "data"))
    cli_counts, _ = app._surface_metrics(
        run, case.identity, case.index.scope_fingerprint
    )
    dashboard = DashboardQuery(tmp_path / "data")
    web_counts, _ = dashboard._surface_metrics(run, [checkpoint])
    assert cli_counts is not None and cli_counts["COVERED"] == 2
    assert web_counts is not None and web_counts["COVERED"] == 2

    forged = deepcopy(proof.to_json())
    assert isinstance(forged["surfaces"], list)
    forged["surfaces"][0]["coverage_status"] = "INSUFFICIENT"
    assert (
        verified_surface_coverage_counts(
            forged,
            case.index,
            terminal,
            artifacts=case.artifacts,
            coverage_ref=data["proof_ref"],
            store=case.store,
        )
        is None
    )


def test_v4_hold_remains_partial_in_reporting_and_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data, checkpoint, terminal = _saved_v4_case(tmp_path, old_hold=True)
    case = data["case"]
    run = case.store.require_analysis_run(case.identity.analysis_id)
    dashboard = DashboardQuery(tmp_path / "data")
    counts, index_hash = dashboard._surface_metrics(run, [checkpoint])
    assert counts is not None and index_hash == case.index_ref.content_hash
    assert counts["COVERED"] == 1
    assert counts["INSUFFICIENT"] == 1
    assert counts["REASON_CODE_CHILD_HOLD"] == 1
    reason_count, preview = dashboard._surface_unresolved_preview(
        run, [checkpoint], counts
    )
    assert reason_count == 1
    assert preview[0]["reason"] == "CHILD_HOLD"
    snapshot = ProgressProjector(case.store).snapshot(
        case.identity.analysis_id,
        candidate_pipeline_version=2,
        candidate_counts={},
        candidate_deep_counts={},
        candidate_terminal=terminal,
        candidate_bundle_hash=case.index.static_bundle_hash,
        candidate_scope_fingerprint=case.index.scope_fingerprint,
        surface_counts={"TOTAL": 2, "CONTEXT_RECORDS": 1, **counts},
        surface_index_hash=case.index_ref.content_hash,
    )
    assert terminal.status == "PARTIAL"
    assert snapshot.status != "COMPLETE"
    assert snapshot.phase_counts["surface"]["reason_code_CHILD_HOLD"] == 1
    assert run.static_coverage_ref is not None
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
    monkeypatch.setattr(stages, "coverage_disclosure", lambda *_a, **_k: disclosure)
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
    assert scoped.surface_proof_version == 4
    assert scoped.surface_insufficient_count == 1
    assert visible_surface_reason_distribution(scoped) == (("CHILD_HOLD", 1),)
