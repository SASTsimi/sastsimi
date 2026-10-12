"""Pinned v4 replay must preserve prior work and never promote weak evidence."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.bootstrap_stages import SurfaceProposalResult
from sastsimi.simple_runtime.models import (
    CandidateTerminal,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageFailure,
    StageResult,
    StageStatus,
)
from sastsimi.simple_runtime.runner import RunOutcome
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_contexts import SurfaceContext
from sastsimi.simple_runtime.surface_enrichment_v4 import prepare_surface_enrichment_v4
from sastsimi.simple_runtime.surface_evidence_validation_v4 import validate_v4_response
from tests.unit.simple_runtime.test_surface_enrichment_v4 import _case


class _SurfaceAgent:
    def __init__(self, result: SurfaceProposalResult | StageFailure) -> None:
        self.result = result
        self.calls = 0

    async def propose_surface(self, *_: object) -> SurfaceProposalResult | StageFailure:
        self.calls += 1
        return self.result


def _setup(tmp_path: Path, *, line_count: int = 3) -> tuple[Any, ...]:
    case = _case(tmp_path, line_count=line_count)
    identity, index, index_ref, static_ref, certificate, coverage = case[:6]
    graphs, artifacts = case[7], case[8]
    data_dir = tmp_path / "artifacts"
    store = SimpleCheckpointStore(
        data_dir / "db" / "sastsimi.sqlite3", artifact_data_dir=data_dir
    )
    coverage_ref = artifacts.put_json(coverage.to_json())
    plan, parts = prepare_surface_enrichment_v4(
        identity,
        "candidate",
        static_ref,
        index,
        index_ref,
        certificate,
        coverage,
        case[6],
        graphs,
        prior_coverage_ref=coverage_ref,
    )
    graph_ref = artifacts.put_json(graphs["surface-target"])
    contexts = tuple(
        SurfaceContext(
            surface_id=part.surface_id,
            context_id=part.context_id,
            context_hash=part.context_hash,
            context_ref=artifacts.put_json(part.payload),
            part_index=part.part_index,
            part_count=part.part_count,
            prompt_bytes=len(canonical_bytes(part.payload)),
            source_sha256=part.source_sha256,
            source_unavailable_reason=None,
            ast_unavailable_reason=None,
            omitted_source_line_count=None,
            omitted_ast_fact_count=None,
        )
        for part in parts
    )
    plan_ref = artifacts.put_json(plan)
    certificate_ref = artifacts.put_json(certificate)
    terminal = CandidateTerminal(
        status="PARTIAL",
        bundle_hash=static_ref.content_hash,
        scope_fingerprint=index.scope_fingerprint,
        decision_counts={},
        deep_counts={},
        hypothesis_count=0,
        surface_index_hash=index_ref.content_hash,
        surface_coverage_hash=coverage_ref.content_hash,
    )
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/v4",
        candidate_pipeline_version=2,
        candidate_scope_fingerprint=index.scope_fingerprint,
        candidate_terminal=terminal,
        surface_enrichment_plan_ref=plan_ref,
        python_scope_certificate_ref=certificate_ref,
    )
    store.save_analysis_run(run)
    old_root = store.mark_running(
        identity, SimpleStage.HYPOTHESIS_DONE, (static_ref,), attempt_id="old-v1"
    )
    store.complete(old_root, StageResult(output_refs=(index_ref, coverage_ref)))
    app = SimpleAnalysisApplication(
        data_dir=data_dir,
        store=store,
        static_bootstrap=None,  # type: ignore[arg-type]
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )
    static = StaticBootstrapResult(
        repository_profile_ref=static_ref,
        static_bundle_ref=static_ref,
        workspace_path=tmp_path,
    )
    return app, store, run, identity, static, artifacts, plan, contexts, graph_ref


def _insufficient_result(
    identity: CheckpointIdentity,
    static: StaticBootstrapResult,
    artifacts: SimpleArtifactRepository,
    context: SurfaceContext,
    graph_ref: StoredDataRef,
) -> SurfaceProposalResult:
    response = {
        "surface_id": context.surface_id,
        "context_id": context.context_id,
        "status": "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
        "reason": "The graph has an unresolved dynamic-dispatch edge.",
        "hypotheses": [],
        "review_evidence": [],
    }
    context_payload = json.loads(artifacts.read(context.context_ref))
    graph_payload = json.loads(artifacts.read(graph_ref))
    checked = validate_v4_response(response, context, context_payload, graph_payload)
    result_ref = artifacts.put_json(
        {
            "kind": "simple_surface_hypothesis_result_v4",
            "analysis_id": identity.analysis_id,
            "surface_id": context.surface_id,
            "context_id": context.context_id,
            "part_index": context.part_index,
            "part_count": context.part_count,
            "context_hash": context.context_hash,
            "static_bundle_hash": static.static_bundle_ref.content_hash,
            "status": checked.status,
            "reason": checked.reason,
            "reviewed_parts": sorted(checked.reviewed_parts),
            "evidence_locations": list(checked.evidence_locations),
            "verified_roles": list(checked.verified_roles),
            "graph_hash": graph_ref.content_hash,
            "graph_ref": graph_ref.model_dump(mode="json"),
            "seed_ids": [],
            "response": response,
            "validation_status": "VALID",
        }
    )
    return SurfaceProposalResult(
        surface_id=context.surface_id,
        context_id=context.context_id,
        part_index=context.part_index,
        part_count=context.part_count,
        status=checked.status,
        reason=checked.reason,
        seeds=(),
        result_ref=result_ref,
        reviewed_parts=checked.reviewed_parts,
        evidence_locations=checked.evidence_locations,
    )


def _partial_proof(certificate_ref: StoredDataRef) -> SimpleNamespace:
    return SimpleNamespace(
        pending_candidate_count=0,
        pending_child_count=0,
        complete=False,
        surfaces=(SimpleNamespace(coverage_status="INSUFFICIENT"),),
        scope_certificate_ref=certificate_ref,
        to_json=lambda: {"kind": "simple_surface_coverage_v2", "complete": False},
    )


@pytest.mark.asyncio
async def test_v4_commits_one_missing_part_and_replay_does_not_call_agent_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, store, run, identity, static, artifacts, plan, contexts, graph_ref = _setup(
        tmp_path
    )
    agent = _SurfaceAgent(
        _insufficient_result(identity, static, artifacts, contexts[0], graph_ref)
    )
    app._candidate_hypotheses = agent
    monkeypatch.setattr(
        "sastsimi.simple_runtime.application.evaluate_surface_coverage_v2",
        lambda *_: _partial_proof(run.python_scope_certificate_ref),
    )
    first = await app._run_v4_surface_enrichment(
        run, identity, static, artifacts, plan, contexts
    )
    assert first.status == "PARTIAL"
    saved = store.require_analysis_run(identity.analysis_id)
    assert saved.surface_enrichment_status == "PARTIAL"
    assert saved.surface_enrichment_error_code is None
    blocked = saved.model_copy(
        update={
            "surface_enrichment_status": "BLOCKED",
            "surface_enrichment_error_code": "PREVIOUS_PROVIDER_FAILURE",
        }
    )
    store.save_analysis_run(blocked)
    second = await app._run_v4_surface_enrichment(
        blocked, identity, static, artifacts, plan, contexts
    )
    assert second.status == "PARTIAL"
    assert agent.calls == 1
    recovered = store.require_analysis_run(identity.analysis_id)
    assert recovered.surface_enrichment_status == "PARTIAL"
    assert recovered.surface_enrichment_error_code is None
    progress = store.list_surface_exploration_progress(
        identity, plan["scope_fingerprint"]
    )
    assert len(progress) == 1
    assert next(iter(progress.values())).proposal_version == 4


@pytest.mark.asyncio
async def test_v4_resumes_only_uncommitted_parts_of_split_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, store, run, identity, static, artifacts, plan, contexts, graph_ref = _setup(
        tmp_path, line_count=900
    )
    assert len(contexts) > 1
    first = _insufficient_result(identity, static, artifacts, contexts[0], graph_ref)
    store.commit_surface_exploration(
        identity,
        plan["scope_fingerprint"],
        contexts[0].surface_id,
        contexts[0].context_id,
        static_bundle_hash=static.static_bundle_ref.content_hash,
        index_hash=plan["index_hash"],
        context_hash=contexts[0].context_hash,
        source_sha256=contexts[0].source_sha256,
        status=first.status,
        result_ref=first.result_ref,
        registrations=(),
        proposal_version=4,
    )

    class PerPartAgent:
        def __init__(self) -> None:
            self.called_context_ids: list[str] = []

        async def propose_surface(
            self,
            _identity: CheckpointIdentity,
            _static: StaticBootstrapResult,
            context: SurfaceContext,
        ) -> SurfaceProposalResult:
            self.called_context_ids.append(context.context_id)
            return _insufficient_result(identity, static, artifacts, context, graph_ref)

    agent = PerPartAgent()
    app._candidate_hypotheses = agent
    monkeypatch.setattr(
        "sastsimi.simple_runtime.application.evaluate_surface_coverage_v2",
        lambda *_: _partial_proof(run.python_scope_certificate_ref),
    )
    outcome = await app._run_v4_surface_enrichment(
        run, identity, static, artifacts, plan, contexts
    )
    assert outcome.status == "PARTIAL"
    assert agent.called_context_ids == [part.context_id for part in contexts[1:]]
    progress = store.list_surface_exploration_progress(
        identity, plan["scope_fingerprint"]
    )
    assert len(progress) == len(contexts)
    assert all(row.proposal_version == 4 for row in progress.values())


@pytest.mark.asyncio
async def test_v4_replay_revalidates_prior_response_instead_of_trusting_progress(
    tmp_path: Path,
) -> None:
    app, store, run, identity, static, artifacts, plan, contexts, _ = _setup(tmp_path)
    malformed = artifacts.put_json({"kind": "simple_surface_hypothesis_result_v4"})
    store.commit_surface_exploration(
        identity,
        plan["scope_fingerprint"],
        contexts[0].surface_id,
        contexts[0].context_id,
        static_bundle_hash=static.static_bundle_ref.content_hash,
        index_hash=plan["index_hash"],
        context_hash=contexts[0].context_hash,
        source_sha256=contexts[0].source_sha256,
        status="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
        result_ref=malformed,
        registrations=(),
        proposal_version=4,
    )
    agent = _SurfaceAgent(
        StageFailure(code="FAILED", retryable=False, safe_message="must not call")
    )
    app._candidate_hypotheses = agent
    old = store.require(identity, SimpleStage.HYPOTHESIS_DONE)
    with pytest.raises(ValueError, match="SURFACE_EXPLORATION_RESULT_INVALID"):
        await app._run_v4_surface_enrichment(
            run, identity, static, artifacts, plan, contexts
        )
    assert agent.calls == 0
    assert store.require(identity, SimpleStage.HYPOTHESIS_DONE) == old


@pytest.mark.asyncio
async def test_v4_agent_failure_preserves_v1_terminal_and_checkpoint(
    tmp_path: Path,
) -> None:
    app, store, run, identity, static, artifacts, plan, contexts, _ = _setup(tmp_path)
    app._candidate_hypotheses = _SurfaceAgent(
        StageFailure(code="FAILED", retryable=False, safe_message="provider failure")
    )
    old = store.require(identity, SimpleStage.HYPOTHESIS_DONE)
    outcome = await app._run_v4_surface_enrichment(
        run, identity, static, artifacts, plan, contexts
    )
    assert outcome.status == "BLOCKED"
    assert store.require(identity, SimpleStage.HYPOTHESIS_DONE) == old
    saved = store.require_analysis_run(identity.analysis_id)
    assert saved.candidate_terminal == run.candidate_terminal
    assert saved.surface_enrichment_status == "BLOCKED"
    assert saved.surface_enrichment_error_code == "HYPOTHESIS_SURFACE_PROVIDER_FAILED"
    assert (
        store.list_surface_exploration_progress(identity, plan["scope_fingerprint"])
        == {}
    )


@pytest.mark.asyncio
async def test_v4_child_failure_does_not_complete_terminal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, store, run, identity, static, artifacts, plan, contexts, graph_ref = _setup(
        tmp_path
    )
    app._candidate_hypotheses = _SurfaceAgent(
        _insufficient_result(identity, static, artifacts, contexts[0], graph_ref)
    )
    old = store.require(identity, SimpleStage.HYPOTHESIS_DONE)

    async def failed_child(*_: object, **__: object) -> RunOutcome:
        return RunOutcome(
            current_stage=SimpleStage.POC_EXECUTION_DONE,
            status=StageStatus.FAILED,
            error_code="CHILD_FAILED",
            hypothesis_id="child-1",
        )

    monkeypatch.setattr(app, "_drain_candidate_children", failed_child)
    outcome = await app._run_v4_surface_enrichment(
        run, identity, static, artifacts, plan, contexts
    )
    assert outcome.status == "FAILED"
    assert outcome.error_code == "CHILD_FAILED"
    assert store.require(identity, SimpleStage.HYPOTHESIS_DONE) == old
    saved = store.require_analysis_run(identity.analysis_id)
    assert saved.candidate_terminal == run.candidate_terminal
    assert saved.surface_enrichment_status == "FAILED"
    assert saved.surface_enrichment_error_code == "CHILD_FAILED"


@pytest.mark.asyncio
async def test_v4_insufficient_result_is_partial_and_preserves_legacy_progress(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, store, run, identity, static, artifacts, plan, contexts, graph_ref = _setup(
        tmp_path
    )
    legacy = _case(tmp_path)[6]
    old_row = next(iter(legacy.values()))
    store.commit_surface_exploration(
        identity,
        plan["scope_fingerprint"],
        old_row.surface_id,
        old_row.context_id,
        static_bundle_hash=old_row.static_bundle_hash,
        index_hash=old_row.index_hash,
        context_hash=old_row.context_hash,
        source_sha256=old_row.source_sha256,
        status=old_row.status,
        result_ref=old_row.result_ref,
        registrations=(),
        proposal_version=3,
    )
    app._candidate_hypotheses = _SurfaceAgent(
        _insufficient_result(identity, static, artifacts, contexts[0], graph_ref)
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.application.evaluate_surface_coverage_v2",
        lambda *_: _partial_proof(run.python_scope_certificate_ref),
    )
    outcome = await app._run_v4_surface_enrichment(
        run, identity, static, artifacts, plan, contexts
    )
    assert outcome.status == "PARTIAL"
    progress = store.list_surface_exploration_progress(
        identity, plan["scope_fingerprint"]
    )
    assert len(progress) == 2
    assert progress[(old_row.surface_id, old_row.context_id)] == old_row
    saved = store.require_analysis_run(identity.analysis_id)
    assert saved.candidate_terminal.status == "PARTIAL"
    assert saved.surface_enrichment_status == "PARTIAL"
    assert saved.surface_enrichment_error_code is None
