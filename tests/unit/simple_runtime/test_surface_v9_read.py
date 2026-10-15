"""Read-side v9 coverage must come from its verified successor proof."""

from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CandidateTerminal,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import (
    SimpleCheckpointStore,
    SurfaceExplorationProgressRecord,
)
from sastsimi.simple_runtime.surface_applicability_v9 import assess_optional_analyzers
from sastsimi.simple_runtime.surface_coverage_v2 import _ref
from sastsimi.simple_runtime.surface_coverage_v7 import evaluate_surface_coverage_v7
from sastsimi.simple_runtime.surface_coverage_v7_read import (
    verified_saved_coverage_v7,
)
from sastsimi.simple_runtime.surface_enrichment_v9 import prepare_surface_enrichment_v9
from sastsimi.simple_runtime.surface_enrichment_v9_bindings import (
    prior_v8_progress_snapshot_hash,
)
from sastsimi.simple_runtime.surface_evidence_validation_v9 import (
    validate_saved_v9_result,
)
from sastsimi.simple_runtime.surface_path_proof_v9 import certify_surface_paths
from sastsimi.simple_runtime.surface_proof_read import verified_surface_coverage_counts
from tests.unit.simple_runtime.test_surface_enrichment_v9 import (
    _digest,
    connected_inputs,
)


def test_v9_counts_require_recomputed_proof_and_reject_changed_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = connected_inputs(tmp_path)
    plan, _parts = prepare_surface_enrichment_v9(**inputs)
    plan_ref = _ref(inputs["identity"], _digest(plan))
    proof = evaluate_surface_coverage_v7(
        inputs["identity"],
        inputs["index"],
        inputs["index_ref"],
        inputs["prior_v8_plan_ref"],
        inputs["prior_v8_plan"],
        inputs["prior_v8_coverage_ref"],
        inputs["prior_v8_coverage"],
        plan_ref,
        plan,
        inputs["prior_v8_progress_hash"],
        inputs["applicability"],
        inputs["intrinsic_proofs"],
        inputs["path_certificates"],
        inputs["graphs"],
        {},
        tmp_path,
        pending_candidate_count=0,
        pending_child_count=0,
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", inputs["identity"])
    proof_ref = artifacts.put_json(proof.to_json())
    terminal = CandidateTerminal(
        status="PARTIAL",
        bundle_hash=inputs["index"].static_bundle_hash,
        scope_fingerprint=inputs["index"].scope_fingerprint,
        decision_counts={},
        deep_counts={},
        hypothesis_count=0,
        surface_index_hash=inputs["index_ref"].content_hash,
        surface_coverage_hash=proof_ref.content_hash,
        surface_proof_version=7,
        scope_certificate_hash=proof.scope_certificate_ref.content_hash,
        surface_counts={"COVERED": 0, "UNCOVERED": 0, "INSUFFICIENT": 1},
        producer_finished=True,
    )
    import sastsimi.simple_runtime.surface_proof_read as reader

    monkeypatch.setattr(
        reader, "verified_saved_coverage_v7", lambda *_: proof, raising=False
    )
    counts = verified_surface_coverage_counts(
        proof.to_json(),
        inputs["index"],
        terminal,
        artifacts=artifacts,
        coverage_ref=proof_ref,
        store=cast(SimpleCheckpointStore, object()),
    )
    assert counts is not None
    assert counts["INSUFFICIENT"] == 1
    assert counts["UNRESOLVED_REASON_COUNT"] > 0

    altered = {**proof.to_json(), "complete": True}
    assert (
        verified_surface_coverage_counts(
            altered,
            inputs["index"],
            terminal,
            artifacts=artifacts,
            coverage_ref=proof_ref,
            store=cast(SimpleCheckpointStore, object()),
        )
        is None
    )


def test_v9_known_gap_reason_is_not_hidden_as_other(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    inputs = connected_inputs(tmp_path)
    plan, _parts = prepare_surface_enrichment_v9(**inputs)
    plan_ref = _ref(inputs["identity"], _digest(plan))
    proof = evaluate_surface_coverage_v7(
        inputs["identity"],
        inputs["index"],
        inputs["index_ref"],
        inputs["prior_v8_plan_ref"],
        inputs["prior_v8_plan"],
        inputs["prior_v8_coverage_ref"],
        inputs["prior_v8_coverage"],
        plan_ref,
        plan,
        inputs["prior_v8_progress_hash"],
        inputs["applicability"],
        inputs["intrinsic_proofs"],
        inputs["path_certificates"],
        inputs["graphs"],
        {},
        tmp_path,
        pending_candidate_count=0,
        pending_child_count=0,
    )
    row = replace(
        proof.surfaces[0],
        unresolved_reason_codes=("ROUTE_DOWNSTREAM_UNVERIFIED",),
    )
    proof = replace(proof, surfaces=(row,))
    artifacts = SimpleArtifactRepository(tmp_path / "data", inputs["identity"])
    proof_ref = artifacts.put_json(proof.to_json())
    terminal = CandidateTerminal(
        status="PARTIAL",
        bundle_hash=inputs["index"].static_bundle_hash,
        scope_fingerprint=inputs["index"].scope_fingerprint,
        decision_counts={},
        deep_counts={},
        hypothesis_count=0,
        surface_index_hash=inputs["index_ref"].content_hash,
        surface_coverage_hash=proof_ref.content_hash,
        surface_proof_version=7,
        scope_certificate_hash=proof.scope_certificate_ref.content_hash,
        surface_counts={"COVERED": 0, "UNCOVERED": 0, "INSUFFICIENT": 1},
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_proof_read.verified_saved_coverage_v7",
        lambda *_: proof,
    )
    counts = verified_surface_coverage_counts(
        proof.to_json(),
        inputs["index"],
        terminal,
        artifacts=artifacts,
        coverage_ref=proof_ref,
        store=cast(SimpleCheckpointStore, object()),
    )
    assert counts is not None
    assert counts["REASON_CODE_ROUTE_DOWNSTREAM_UNVERIFIED"] == 1


def _saved_v9_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    workspace = tmp_path / "repo"
    workspace.mkdir()
    inputs = connected_inputs(workspace)
    identity = inputs["identity"]
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    ast_summary: dict[str, object] = {}
    bundle_ref = artifacts.put_json({"ast_summary": ast_summary})
    index = replace(
        inputs["index"],
        static_bundle_hash=bundle_ref.content_hash,
        ast_manifest_hash=_digest(ast_summary),
    )
    index_ref = artifacts.put_json(index.to_json())
    graph = dict(inputs["graphs"]["surface-1"])
    graph["index_hash"] = index_ref.content_hash
    graph["ast_manifest_hash"] = index.ast_manifest_hash
    applicability = assess_optional_analyzers(index, workspace)
    certificate = certify_surface_paths(
        index, index.surfaces[0], graph, applicability, workspace
    )
    v8_plan = dict(inputs["prior_v8_plan"])
    v8_plan.update(
        index_ref=index_ref.model_dump(mode="json"),
        index_hash=index_ref.content_hash,
        static_bundle_hash=index.static_bundle_hash,
        ast_manifest_hash=index.ast_manifest_hash,
    )
    v8_ref = artifacts.put_json(v8_plan)
    parent = replace(
        inputs["prior_v8_coverage"],
        static_bundle_hash=index.static_bundle_hash,
        ast_manifest_hash=index.ast_manifest_hash,
        index_hash=index_ref.content_hash,
        v8_plan_ref=v8_ref,
    )
    parent_ref = artifacts.put_json(parent.to_json())
    prior_hash = prior_v8_progress_snapshot_hash({})
    arguments = {
        **inputs,
        "index": index,
        "index_ref": index_ref,
        "prior_v8_plan_ref": v8_ref,
        "prior_v8_plan": v8_plan,
        "prior_v8_coverage_ref": parent_ref,
        "prior_v8_coverage": parent,
        "prior_v8_progress_hash": prior_hash,
        "applicability": applicability,
        "path_certificates": {"surface-1": certificate},
        "graphs": {"surface-1": graph},
        "workspace": workspace,
    }
    plan, parts = prepare_surface_enrichment_v9(**arguments)
    plan_ref = artifacts.put_json(plan)
    for evidence in (applicability.to_json(), certificate.to_json(), graph):
        artifacts.put_json(evidence)
    completed = {}
    progress: dict[tuple[str, str], SurfaceExplorationProgressRecord] = {}
    for part in parts:
        artifacts.put_json(part.payload)
        detail = cast(dict[str, object], part.payload["context_part"])
        saved = {
            "kind": "simple_surface_hypothesis_result_v9",
            "analysis_id": identity.analysis_id,
            "surface_id": part.surface_id,
            "context_id": part.context_id,
            "context_hash": part.context_hash,
            "part_id": part.part_id,
            "part_index": part.part_index,
            "part_count": part.part_count,
            "source_sha256": part.source_sha256,
            "content_sha256": detail["content_sha256"],
            "static_bundle_hash": index.static_bundle_hash,
            "validation_status": "VALID",
            "validation_feedback": None,
            "status": "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
            "reason": "Evidence does not yet connect every route",
            "reviewed_path_ids": [],
            "role_citations": [],
            "review_complete": False,
            "reviewed_parts": [],
            "evidence_locations": [],
            "seed_ids": [],
        }
        result_ref = artifacts.put_json(saved)
        key = (part.surface_id, part.context_id)
        progress[key] = SurfaceExplorationProgressRecord(
            surface_id=part.surface_id,
            context_id=part.context_id,
            static_bundle_hash=index.static_bundle_hash,
            index_hash=index_ref.content_hash,
            context_hash=part.context_hash,
            source_sha256=part.source_sha256,
            status="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
            result_ref=result_ref,
            hypothesis_ids=(),
            proposal_version=9,
        )
        completed[key] = validate_saved_v9_result(part, saved, ())
    proof = evaluate_surface_coverage_v7(
        identity,
        index,
        index_ref,
        v8_ref,
        v8_plan,
        parent_ref,
        parent,
        plan_ref,
        plan,
        prior_hash,
        applicability,
        {},
        {"surface-1": certificate},
        {"surface-1": graph},
        completed,
        workspace,
        pending_candidate_count=0,
        pending_child_count=0,
    )
    coverage_ref = artifacts.put_json(proof.to_json())
    placeholders = [artifacts.put_json({"step": number}) for number in range(5)]
    terminal = CandidateTerminal(
        status="PARTIAL",
        bundle_hash=index.static_bundle_hash,
        scope_fingerprint=index.scope_fingerprint,
        decision_counts={},
        deep_counts={},
        hypothesis_count=0,
        surface_index_hash=index_ref.content_hash,
        surface_coverage_hash=coverage_ref.content_hash,
        surface_proof_version=7,
        scope_certificate_hash=proof.scope_certificate_ref.content_hash,
        surface_counts={"COVERED": 0, "UNCOVERED": 0, "INSUFFICIENT": 1},
        producer_finished=True,
    )
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="example/repo",
        workspace_path=workspace,
        static_bundle_ref=bundle_ref,
        candidate_scope_fingerprint=index.scope_fingerprint,
        candidate_terminal=terminal,
        surface_enrichment_plan_ref=placeholders[0],
        surface_enrichment_v5_plan_ref=placeholders[1],
        surface_enrichment_v6_plan_ref=placeholders[2],
        surface_enrichment_v7_plan_ref=placeholders[3],
        surface_enrichment_v8_plan_ref=v8_ref,
        surface_enrichment_v9_plan_ref=plan_ref,
        python_scope_certificate_ref=placeholders[4],
    )
    root = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.HYPOTHESIS_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(index_ref, coverage_ref),
    )

    class SavedStore:
        def __init__(self) -> None:
            self.run = run

        def require_analysis_run(self, _analysis_id: str) -> SimpleAnalysisRun:
            return self.run

        def get(self, *_args: object) -> StageCheckpoint:
            return root

        def list_surface_exploration_progress(
            self, *_args: object
        ) -> dict[tuple[str, str], SurfaceExplorationProgressRecord]:
            return progress

        def candidate_counts(self, *_args: object) -> dict[str, int]:
            return {"PENDING": 0, "ERROR": 0}

        def candidate_deep_counts(self, *_args: object) -> dict[str, int]:
            return {"PENDING": 0, "RUNNING": 0, "ERROR": 0}

        def list_incomplete_hypotheses(
            self, *_args: object, **_kwargs: object
        ) -> tuple[()]:
            return ()

        def list_candidate_hypothesis_ids(
            self, *_args: object, **_kwargs: object
        ) -> tuple[()]:
            return ()

    store = SavedStore()
    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_coverage_v7_read.recompute_v9_runtime_evidence",
        lambda *_args: (
            applicability,
            {},
            {"surface-1": certificate},
            {"surface-1": graph},
            {},
        ),
    )
    return {
        "identity": identity,
        "index": index,
        "coverage_ref": coverage_ref,
        "v9_plan_ref": plan_ref,
        "v9_root": root,
        "v9_terminal": terminal,
        "workspace": workspace,
        "graph": graph,
        "path_certificate": certificate,
        "store": store,
        "artifacts": artifacts,
        "proof": proof,
        "progress": progress,
    }


def test_v9_read_recomputes_saved_proof_and_rejects_changed_terminal_bundle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _saved_v9_case(tmp_path, monkeypatch)
    store = cast(SimpleCheckpointStore, case["store"])
    proof = verified_saved_coverage_v7(
        case["identity"],
        case["index"],
        case["coverage_ref"],
        store,
        case["artifacts"],
    )
    assert proof == case["proof"]
    assert proof.complete is False
    assert proof.surfaces[0].coverage_status == "INSUFFICIENT"

    terminal = case["store"].run.candidate_terminal
    assert terminal is not None
    case["store"].run = case["store"].run.model_copy(
        update={
            "candidate_terminal": terminal.model_copy(update={"bundle_hash": "0" * 64})
        }
    )
    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V7_VERIFIED_INVALID"):
        verified_saved_coverage_v7(
            case["identity"],
            case["index"],
            case["coverage_ref"],
            store,
            case["artifacts"],
        )


def test_v9_read_rejects_replaced_agent_review_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _saved_v9_case(tmp_path, monkeypatch)
    progress = case["progress"]
    key = next(iter(progress))
    old = progress[key]
    artifacts = case["artifacts"]
    saved = json.loads(artifacts.read(old.result_ref))
    forged = {**saved, "review_complete": True}
    progress[key] = replace(old, result_ref=artifacts.put_json(forged))

    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V7_VERIFIED_INVALID"):
        verified_saved_coverage_v7(
            case["identity"],
            case["index"],
            case["coverage_ref"],
            cast(SimpleCheckpointStore, case["store"]),
            artifacts,
        )


def test_v9_read_rejects_unfinished_candidate_producer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _saved_v9_case(tmp_path, monkeypatch)
    store = case["store"]
    terminal = store.run.candidate_terminal
    assert terminal is not None
    store.run = store.run.model_copy(
        update={
            "candidate_terminal": terminal.model_copy(
                update={"producer_finished": False}
            )
        }
    )
    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V7_VERIFIED_INVALID"):
        verified_saved_coverage_v7(
            case["identity"],
            case["index"],
            case["coverage_ref"],
            cast(SimpleCheckpointStore, store),
            case["artifacts"],
        )


def test_v9_read_converts_git_source_failure_to_unverified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _saved_v9_case(tmp_path, monkeypatch)

    def missing_source(*_args: object) -> None:
        raise subprocess.CalledProcessError(128, ["git", "cat-file"])

    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_coverage_v7_read.recompute_v9_runtime_evidence",
        missing_source,
    )
    with pytest.raises(ValueError, match="SURFACE_COVERAGE_V7_VERIFIED_INVALID"):
        verified_saved_coverage_v7(
            case["identity"],
            case["index"],
            case["coverage_ref"],
            cast(SimpleCheckpointStore, case["store"]),
            case["artifacts"],
        )
