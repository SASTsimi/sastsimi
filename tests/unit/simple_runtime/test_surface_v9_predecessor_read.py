"""A pinned v9 successor cannot rewrite its completed v8 predecessor proof."""

from __future__ import annotations

import importlib
import json
from dataclasses import replace
from pathlib import Path
from typing import NoReturn, cast

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attack_surfaces import SurfaceIndex
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
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_coverage_v6 import (
    SurfaceCoverageV6,
    surface_coverage_v6_from_json,
)
from sastsimi.simple_runtime.surface_enrichment_v9 import prepare_surface_enrichment_v9
from sastsimi.simple_runtime.surface_enrichment_v9_bindings import (
    prior_v8_progress_snapshot_hash,
)
from sastsimi.simple_runtime.surface_v9_predecessor_read import _FrozenV8Store
from tests.unit.simple_runtime.test_surface_enrichment_v9 import connected_inputs


def _case(
    tmp_path: Path,
) -> tuple[
    SimpleAnalysisRun,
    SimpleArtifactRepository,
    SimpleCheckpointStore,
    CheckpointIdentity,
]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    inputs = connected_inputs(workspace)
    identity: CheckpointIdentity = inputs["identity"]
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(
        data_dir / "db" / "sastsimi.sqlite3", artifact_data_dir=data_dir
    )
    artifacts = SimpleArtifactRepository(data_dir, identity)
    index = inputs["index"]
    index_ref = artifacts.put_json(index.to_json())
    v8_plan = inputs["prior_v8_plan"]
    v8_plan_ref = artifacts.put_json(v8_plan)
    assert index_ref == inputs["index_ref"]
    assert v8_plan_ref == inputs["prior_v8_plan_ref"]

    static_ref = artifacts.put_json(
        {
            "kind": "simple_static_coverage_v1",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "fingerprint": "e" * 64,
            "expected_count": 1,
            "verified_count": 1,
            "gaps": [],
            "unsupported_files": [],
            "engine_errors": [],
        }
    )
    certificate_ref = artifacts.put_json(
        {
            "kind": "simple_python_scope_certificate_v2",
            "analysis_id": identity.analysis_id,
            "workspace_id": identity.workspace_id,
            "commit_id": identity.commit_id,
            "coverage_ref": static_ref.model_dump(mode="json"),
            "index_ref": index_ref.model_dump(mode="json"),
        }
    )
    predecessor = replace(
        inputs["prior_v8_coverage"], scope_certificate_ref=certificate_ref
    )
    coverage_ref = artifacts.put_json(predecessor.to_json())
    inputs.update(
        prior_v8_coverage=predecessor,
        prior_v8_coverage_ref=coverage_ref,
        prior_v8_progress_hash=prior_v8_progress_snapshot_hash({}),
    )
    plan, parts = prepare_surface_enrichment_v9(**inputs)
    assert parts
    plan_ref = artifacts.put_json(plan)
    earlier_plan_refs = tuple(
        artifacts.put_json({"kind": f"earlier_surface_plan_{number}"})
        for number in range(4)
    )
    terminal = CandidateTerminal(
        status="PARTIAL",
        bundle_hash=index.static_bundle_hash,
        scope_fingerprint=index.scope_fingerprint,
        decision_counts={},
        deep_counts={},
        hypothesis_count=1,
        surface_index_hash=index_ref.content_hash,
        surface_coverage_hash=coverage_ref.content_hash,
        surface_proof_version=6,
        scope_certificate_hash=certificate_ref.content_hash,
        surface_counts={"COVERED": 0, "UNCOVERED": 0, "INSUFFICIENT": 1},
        producer_finished=True,
    )
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="example/project",
        workspace_path=workspace,
        static_coverage_ref=static_ref,
        candidate_pipeline_version=2,
        candidate_scope_fingerprint=index.scope_fingerprint,
        candidate_terminal=terminal,
        surface_enrichment_plan_ref=earlier_plan_refs[0],
        surface_enrichment_v5_plan_ref=earlier_plan_refs[1],
        surface_enrichment_v6_plan_ref=earlier_plan_refs[2],
        surface_enrichment_v7_plan_ref=earlier_plan_refs[3],
        surface_enrichment_v8_plan_ref=v8_plan_ref,
        surface_enrichment_v9_plan_ref=plan_ref,
        python_scope_certificate_ref=certificate_ref,
        surface_enrichment_status="RUNNING",
    )
    store.save_analysis_run(run)
    store.save_checkpoint(
        StageCheckpoint(
            identity=identity,
            stage=SimpleStage.HYPOTHESIS_DONE,
            stage_version=STAGE_VERSION[SimpleStage.HYPOTHESIS_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(index_ref, coverage_ref),
            attempt_id="root-attempt",
            attempt_number=1,
        )
    )
    part = parts[0]
    context_ref = artifacts.put_json(part.payload)
    assert context_ref.content_hash == part.context_hash
    hypothesis_ref = artifacts.put_json({"kind": "simple_hypothesis_proposal"})
    child_id = "v9-child"
    child = identity.model_copy(update={"hypothesis_id": child_id})
    inputs_for_child = (hypothesis_ref, context_ref)
    pending_child = StageCheckpoint(
        identity=child,
        stage=SimpleStage.PRO_CON_DONE,
        stage_version=STAGE_VERSION[SimpleStage.PRO_CON_DONE],
        status=StageStatus.PENDING,
        input_refs=inputs_for_child,
        input_hash=input_reference_hash(inputs_for_child),
    )
    context_part = part.payload["context_part"]
    assert isinstance(context_part, dict)
    result_ref = artifacts.put_json(
        {
            "kind": "simple_surface_hypothesis_result_v9",
            "analysis_id": identity.analysis_id,
            "surface_id": part.surface_id,
            "context_id": part.context_id,
            "context_hash": part.context_hash,
            "part_id": part.part_id,
            "part_index": part.part_index,
            "part_count": part.part_count,
            "source_sha256": part.source_sha256,
            "content_sha256": context_part["content_sha256"],
            "static_bundle_hash": index.static_bundle_hash,
            "validation_status": "VALID",
            "validation_feedback": None,
            "status": "HYPOTHESES",
            "reason": "The saved part registered a child for verification.",
            "reviewed_path_ids": [],
            "role_citations": [],
            "review_complete": False,
            "reviewed_parts": [],
            "evidence_locations": [],
            "seed_ids": [child_id],
        }
    )
    assert store.commit_surface_exploration(
        identity,
        index.scope_fingerprint,
        part.surface_id,
        part.context_id,
        static_bundle_hash=index.static_bundle_hash,
        index_hash=index_ref.content_hash,
        context_hash=part.context_hash,
        source_sha256=part.source_sha256,
        status="HYPOTHESES",
        result_ref=result_ref,
        registrations=((child_id, hypothesis_ref, pending_child),),
        proposal_version=9,
    )
    return run, artifacts, store, identity


def _verify(
    run: SimpleAnalysisRun,
    artifacts: SimpleArtifactRepository,
    store: SimpleCheckpointStore,
) -> bool:
    try:
        module = importlib.import_module(
            "sastsimi.simple_runtime.surface_v9_predecessor_read"
        )
    except ModuleNotFoundError:
        pytest.fail("The frozen v9 predecessor verifier is not implemented")
    return cast(bool, module.verified_pending_v9_predecessor(run, artifacts, store))


def test_accepts_pinned_v6_proof_without_counting_v9_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, artifacts, store, identity = _case(tmp_path)
    expected = run.candidate_terminal
    assert expected is not None
    verified: list[tuple[object, tuple[str, ...]]] = []

    def check_frozen(
        identity_arg: CheckpointIdentity,
        index: SurfaceIndex,
        coverage_ref: StoredDataRef,
        frozen_store: _FrozenV8Store,
        root_artifacts: SimpleArtifactRepository,
    ) -> SurfaceCoverageV6:
        del index
        assert identity_arg == identity
        assert coverage_ref.content_hash == expected.surface_coverage_hash
        assert (
            frozen_store.list_surface_exploration_progress(
                identity, expected.scope_fingerprint
            )
            == {}
        )
        pending = frozen_store.list_incomplete_hypotheses(identity)
        verified.append((coverage_ref, pending))
        return surface_coverage_v6_from_json(
            json.loads(root_artifacts.read(coverage_ref))
        )

    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_v9_predecessor_read.verified_saved_coverage_v6",
        check_frozen,
    )

    assert store.list_incomplete_hypotheses(identity) == ("v9-child",)
    assert _verify(run, artifacts, store)
    assert len(verified) == 1
    assert verified[0][1] == ()


def test_rejects_failed_frozen_v6_recomputation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    run, artifacts, store, _identity = _case(tmp_path)

    def reject(*_args: object) -> NoReturn:
        raise ValueError("SURFACE_COVERAGE_V6_VERIFIED_INVALID")

    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_v9_predecessor_read.verified_saved_coverage_v6",
        reject,
    )
    assert not _verify(run, artifacts, store)


def test_rejects_unregistered_incomplete_hypothesis(tmp_path: Path) -> None:
    run, artifacts, store, identity = _case(tmp_path)
    store.upsert_hypothesis(identity, "other-child")

    assert not _verify(run, artifacts, store)


def test_rejects_wrong_predecessor_scope_or_plan(tmp_path: Path) -> None:
    run, artifacts, store, _identity = _case(tmp_path)
    assert run.candidate_terminal is not None
    changed_terminal = run.candidate_terminal.model_copy(update={"status": "COMPLETE"})

    assert not _verify(
        run.model_copy(update={"candidate_terminal": changed_terminal}),
        artifacts,
        store,
    )
    assert not _verify(
        run.model_copy(update={"surface_enrichment_v9_plan_ref": None}),
        artifacts,
        store,
    )
