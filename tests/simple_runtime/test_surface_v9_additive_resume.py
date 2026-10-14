"""v9 resumes an immutable partial v8 run without repeating reviewed parts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.simple_runtime.application import StaticBootstrapResult
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.bootstrap_stages import SurfaceProposalResult
from sastsimi.simple_runtime.models import (
    CandidateTerminal,
    SimpleAnalysisRun,
    SimpleStage,
    StageResult,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_applicability_v9 import (
    assess_optional_analyzers,
)
from sastsimi.simple_runtime.surface_enrichment_v9_bindings import (
    prior_v8_progress_snapshot_hash,
)
from sastsimi.simple_runtime.surface_path_proof_v9 import certify_surface_paths
from tests.simple_runtime.test_saved_surface_enrichment_v5_resume import _application
from tests.unit.simple_runtime.test_surface_enrichment_v9 import connected_inputs


def _digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    inputs = connected_inputs(workspace)
    identity = inputs["identity"]
    data_dir = tmp_path / "data"
    artifacts = SimpleArtifactRepository(data_dir, identity)
    ast_summary: dict[str, object] = {}
    bundle_ref = artifacts.put_json({"ast_summary": ast_summary})
    index = replace(
        inputs["index"],
        static_bundle_hash=bundle_ref.content_hash,
        ast_manifest_hash=_digest(ast_summary),
    )
    index_ref = artifacts.put_json(index.to_json())
    v8_plan = {
        **inputs["prior_v8_plan"],
        "static_bundle_hash": index.static_bundle_hash,
        "ast_manifest_hash": index.ast_manifest_hash,
        "index_hash": index_ref.content_hash,
        "index_ref": index_ref.model_dump(mode="json"),
    }
    v8_ref = artifacts.put_json(v8_plan)
    parent = replace(
        inputs["prior_v8_coverage"],
        static_bundle_hash=index.static_bundle_hash,
        ast_manifest_hash=index.ast_manifest_hash,
        index_hash=index_ref.content_hash,
        v8_plan_ref=v8_ref,
    )
    parent_ref = artifacts.put_json(parent.to_json())
    graph = {
        **inputs["graphs"]["surface-1"],
        "index_hash": index_ref.content_hash,
        "ast_manifest_hash": index.ast_manifest_hash,
    }
    applicability = assess_optional_analyzers(index, workspace)
    certificate = certify_surface_paths(
        index, index.surfaces[0], graph, applicability, workspace
    )
    evidence: tuple[object, ...] = (
        applicability,
        {},
        {"surface-1": certificate},
        {"surface-1": graph},
        {},
    )
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    app = _application(data_dir, store)
    dummy_plan = artifacts.put_json({"kind": "prior-plan"})
    profile_ref = artifacts.put_json({"kind": "repository-profile"})
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/synthetic",
        workspace_path=workspace,
        candidate_scope_fingerprint=index.scope_fingerprint,
        repository_profile_ref=profile_ref,
        static_bundle_ref=bundle_ref,
        candidate_terminal=CandidateTerminal(
            status="PARTIAL",
            bundle_hash=bundle_ref.content_hash,
            scope_fingerprint=index.scope_fingerprint,
            decision_counts={},
            deep_counts={},
            hypothesis_count=0,
            surface_index_hash=index_ref.content_hash,
            surface_coverage_hash=parent_ref.content_hash,
            surface_proof_version=6,
            scope_certificate_hash=parent.scope_certificate_ref.content_hash,
            surface_counts={"COVERED": 0, "UNCOVERED": 0, "INSUFFICIENT": 1},
            producer_finished=True,
        ),
        surface_enrichment_plan_ref=dummy_plan,
        surface_enrichment_v5_plan_ref=dummy_plan,
        surface_enrichment_v6_plan_ref=dummy_plan,
        surface_enrichment_v7_plan_ref=dummy_plan,
        surface_enrichment_v8_plan_ref=v8_ref,
        python_scope_certificate_ref=parent.scope_certificate_ref,
    )
    store.save_analysis_run(run)
    root = store.mark_running(
        identity, SimpleStage.HYPOTHESIS_DONE, (bundle_ref,), attempt_id="v8"
    )
    store.complete(root, StageResult(output_refs=(index_ref, parent_ref)))

    def verified_parent(*args: object) -> object:
        assert args == (identity, index, parent_ref, store, artifacts)
        assert json.loads(artifacts.read(parent_ref)) == parent.to_json()
        assert store.require_analysis_run(identity.analysis_id).candidate_terminal == (
            run.candidate_terminal
        )
        return parent

    monkeypatch.setattr(
        "sastsimi.simple_runtime.application.verified_saved_coverage_v6",
        verified_parent,
    )
    monkeypatch.setattr(app, "_v9_evidence_from_pinned_source", lambda *_: evidence)
    return {
        "app": app,
        "store": store,
        "run": run,
        "identity": identity,
        "artifacts": artifacts,
        "static": StaticBootstrapResult(
            repository_profile_ref=profile_ref,
            static_bundle_ref=bundle_ref,
            workspace_path=workspace,
        ),
        "parent_ref": parent_ref,
        "index_ref": index_ref,
    }


class _DeterministicAgent:
    def __init__(self, artifacts: SimpleArtifactRepository) -> None:
        self.artifacts = artifacts
        self.calls = 0

    async def propose_surface(
        self, identity: object, static: object, context: Any
    ) -> SurfaceProposalResult:
        del identity, static
        self.calls += 1
        payload = json.loads(self.artifacts.read(context.context_ref))
        part = payload["context_part"]
        citations = payload["role_directory"]
        assert citations
        paths = sorted(set(part["path_ids"]))
        result = {
            "kind": "simple_surface_hypothesis_result_v9",
            "analysis_id": payload["analysis_id"],
            "surface_id": context.surface_id,
            "context_id": context.context_id,
            "context_hash": context.context_hash,
            "part_id": part["part_id"],
            "part_index": context.part_index,
            "part_count": context.part_count,
            "source_sha256": context.source_sha256,
            "content_sha256": part["content_sha256"],
            "static_bundle_hash": payload["static_bundle_hash"],
            "status": "NO_HYPOTHESIS",
            "reason": "Deterministic synthetic review of all bound paths.",
            "reviewed_path_ids": paths,
            "role_citations": citations,
            "review_complete": True,
            "reviewed_parts": sorted({row["role"] for row in citations}),
            "evidence_locations": list(
                dict.fromkeys(row["location"] for row in citations)
            ),
            "seed_ids": [],
            "response": {},
            "validation_status": "VALID",
            "validation_feedback": None,
            "attempt_input_refs": [],
            "llm_request_ref": None,
            "llm_response_ref": None,
            "llm_raw_output_ref": None,
        }
        ref = self.artifacts.put_json(result)
        return SurfaceProposalResult(
            surface_id=context.surface_id,
            context_id=context.context_id,
            part_index=context.part_index,
            part_count=context.part_count,
            status="NO_HYPOTHESIS",
            reason=result["reason"],
            seeds=(),
            result_ref=ref,
            reviewed_parts=frozenset(result["reviewed_parts"]),
            evidence_locations=tuple(result["evidence_locations"]),
        )


@pytest.mark.asyncio
async def test_v9_pin_review_terminal_and_resume_reuses_completed_parts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, monkeypatch)
    app = case["app"]
    store = case["store"]
    identity = case["identity"]
    artifacts = case["artifacts"]
    old_progress = store.list_surface_exploration_progress(
        identity, case["run"].candidate_scope_fingerprint
    )
    assert prior_v8_progress_snapshot_hash(
        old_progress
    ) == prior_v8_progress_snapshot_hash({})

    app._prepare_v9_surface_enrichment(case["run"], identity, artifacts)
    pinned = store.require_analysis_run(identity.analysis_id)
    assert pinned.surface_enrichment_v9_plan_ref is not None
    plan, contexts = app._saved_surface_enrichment_v9(pinned, identity, artifacts)
    assert contexts
    agent = _DeterministicAgent(artifacts)
    monkeypatch.setattr(app, "_candidate_hypotheses", agent)

    async def no_children(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(app, "_drain_candidate_children", no_children)
    first = await app._run_v9_surface_enrichment(
        pinned, identity, case["static"], artifacts, plan, contexts
    )
    assert first.status == "COMPLETE"
    assert agent.calls == len(contexts)
    final_run = store.require_analysis_run(identity.analysis_id)
    assert final_run.candidate_terminal is not None
    assert final_run.candidate_terminal.surface_proof_version == 7
    root = store.require(identity, SimpleStage.HYPOTHESIS_DONE)
    assert root.output_refs[0] == case["index_ref"]
    assert (
        root.output_refs[1].content_hash
        == final_run.candidate_terminal.surface_coverage_hash
    )
    assert root.output_refs[1] != case["parent_ref"]
    proof = json.loads(artifacts.read(root.output_refs[1]))
    assert proof["kind"] == "simple_attack_surface_coverage_v7"
    assert proof["missing_v9_parts"] == []
    saved_progress = store.list_surface_exploration_progress(
        identity, pinned.candidate_scope_fingerprint
    )
    assert len(saved_progress) == len(contexts)
    assert all(row.proposal_version == 9 for row in saved_progress.values())

    replay_plan, replay_contexts = app._saved_surface_enrichment_v9(
        final_run, identity, artifacts
    )
    assert replay_plan == plan
    assert replay_contexts == contexts
    second = await app._run_v9_surface_enrichment(
        final_run, identity, case["static"], artifacts, replay_plan, replay_contexts
    )
    assert second.status == first.status
    assert agent.calls == len(contexts)
    assert (
        store.require(identity, SimpleStage.HYPOTHESIS_DONE).output_refs
        == root.output_refs
    )
    assert (
        store.list_surface_exploration_progress(
            identity, pinned.candidate_scope_fingerprint
        )
        == saved_progress
    )


@pytest.mark.asyncio
async def test_v9_resume_rejects_corrupted_saved_review_before_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path, monkeypatch)
    app = case["app"]
    store = case["store"]
    identity = case["identity"]
    artifacts = case["artifacts"]
    app._prepare_v9_surface_enrichment(case["run"], identity, artifacts)
    pinned = store.require_analysis_run(identity.analysis_id)
    plan, contexts = app._saved_surface_enrichment_v9(pinned, identity, artifacts)
    agent = _DeterministicAgent(artifacts)
    monkeypatch.setattr(app, "_candidate_hypotheses", agent)

    async def no_children(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(app, "_drain_candidate_children", no_children)
    await app._run_v9_surface_enrichment(
        pinned, identity, case["static"], artifacts, plan, contexts
    )
    final_run = store.require_analysis_run(identity.analysis_id)
    progress = store.list_surface_exploration_progress(
        identity, pinned.candidate_scope_fingerprint
    )
    key, row = next(iter(progress.items()))
    forged = json.loads(artifacts.read(row.result_ref))
    forged["role_citations"] = []
    forged_ref = artifacts.put_json(forged)
    monkeypatch.setattr(
        store,
        "list_surface_exploration_progress",
        lambda *_args, **_kwargs: {
            **progress,
            key: replace(row, result_ref=forged_ref),
        },
    )

    with pytest.raises(ValueError, match="V9_SAVED_RESULT_INVALID"):
        await app._run_v9_surface_enrichment(
            final_run, identity, case["static"], artifacts, plan, contexts
        )
    assert agent.calls == len(contexts)
