"""A pinned v8 role review is additive to immutable v7 evidence."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import NoReturn

import pytest

from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CandidateTerminal,
    SimpleAnalysisRun,
    SimpleStage,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_contexts import SurfaceContext
from tests.simple_runtime.test_saved_surface_enrichment_v5_resume import _application
from tests.unit.simple_runtime.test_surface_coverage_v5 import _v7_case
from tests.unit.simple_runtime.test_surface_enrichment_v8 import (
    _planner_inputs,
    _prepare,
)


def test_v8_is_only_explicit_successor_to_partial_v5(tmp_path: Path) -> None:
    data = _v7_case(tmp_path)
    case = data["case"]
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.candidate_terminal is not None
    ready = run.model_copy(
        update={
            "surface_enrichment_v7_plan_ref": data["v7_plan_ref"],
            "candidate_terminal": run.candidate_terminal.model_copy(
                update={"surface_proof_version": 5, "status": "PARTIAL"}
            ),
        }
    )

    assert SimpleAnalysisApplication._surface_enrichment_round(ready) == "v8"
    assert SimpleAnalysisApplication._surface_enrichment_round(run) == "v6"


def test_v8_dispatch_precedes_v7_without_reopening_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = _v7_case(tmp_path)
    case = data["case"]
    run = case.store.require_analysis_run(case.identity.analysis_id).model_copy(
        update={
            "surface_enrichment_v7_plan_ref": data["v7_plan_ref"],
            "surface_enrichment_v8_plan_ref": data["v7_plan_ref"],
            "candidate_scope_fingerprint": case.index.scope_fingerprint,
        }
    )
    app = _application(tmp_path / "data", case.store)
    expected = SimpleAnalysisOutcome(
        identity=case.identity,
        display_analysis_id=run.display_analysis_id,
        status="PARTIAL",
        current_stage=SimpleStage.HYPOTHESIS_DONE,
    )
    observed: list[str] = []

    def saved_v8(
        *_args: object,
    ) -> tuple[dict[str, object], tuple[SurfaceContext, ...]]:
        observed.append("v8-plan")
        return {"kind": "simple_surface_enrichment_plan_v8"}, ()

    async def run_v8(*_args: object) -> SimpleAnalysisOutcome:
        observed.append("v8-run")
        return expected

    def forbidden_v7(*_args: object) -> NoReturn:
        raise AssertionError("v7 must not run once v8 is pinned")

    monkeypatch.setattr(app, "_saved_surface_enrichment_v8", saved_v8)
    monkeypatch.setattr(app, "_run_v8_surface_enrichment", run_v8)
    monkeypatch.setattr(app, "_saved_surface_enrichment_v7", forbidden_v7)
    static = StaticBootstrapResult(
        repository_profile_ref=case.artifacts.put_json({"kind": "profile"}),
        static_bundle_ref=case.artifacts.put_json({"kind": "bundle"}),
        workspace_path=tmp_path,
    )

    with pytest.raises(StopIteration) as done:
        app._run_candidate_pipeline(run, case.identity, static).send(None)

    assert done.value.value == expected
    assert observed == ["v8-plan", "v8-run"]


@pytest.mark.asyncio
@pytest.mark.parametrize("corruption", ["later_tampered", "extra_row"])
async def test_v8_replay_rejects_invalid_saved_row_before_missing_part_agent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, corruption: str
) -> None:
    inputs = _planner_inputs()
    identity = inputs["identity"]
    index = inputs["index"]
    graph = deepcopy(inputs["graphs"]["surface-1"])
    alternate = deepcopy(graph["paths"][0])
    alternate["path_id"] = "route-to-anchor-alternate"
    alternate["edge_ids"] = [
        edge_id + "-alternate" for edge_id in alternate["edge_ids"]
    ]
    for node in alternate["steps"]:
        node["node_id"] += "-alternate"
    for edge in graph["edges"]:
        copied = deepcopy(edge)
        copied["edge_id"] += "-alternate"
        copied["from_node_id"] += "-alternate"
        copied["to_node_id"] += "-alternate"
        copied["graph_path_id"] = alternate["path_id"]
        graph.setdefault("alternate_edges", []).append(copied)
    graph["edges"].extend(graph.pop("alternate_edges"))
    graph["nodes"].extend(alternate["steps"])
    graph["paths"].append(alternate)
    inputs["graphs"] = {"surface-1": graph}
    plan, parts = _prepare(inputs)
    assert len(parts) == 2

    data_dir = tmp_path / "data"
    artifacts = SimpleArtifactRepository(data_dir, identity)
    index_ref = artifacts.put_json(index.to_json())
    parent_ref = artifacts.put_json(inputs["v5"].to_json())
    v7_ref = artifacts.put_json(inputs["v7_plan"])
    plan_ref = artifacts.put_json(plan)
    assert index_ref == inputs["index_ref"]
    assert parent_ref == inputs["v5_ref"]
    assert v7_ref == inputs["v7_ref"]
    contexts = []
    for part in parts:
        context_ref = artifacts.put_json(part.payload)
        contexts.append(
            SurfaceContext(
                surface_id=part.surface_id,
                context_id=part.context_id,
                context_hash=part.context_hash,
                context_ref=context_ref,
                part_index=part.part_index,
                part_count=part.part_count,
                prompt_bytes=len(artifacts.read(context_ref)),
                source_sha256=part.source_sha256,
                source_unavailable_reason=None,
                ast_unavailable_reason=None,
                omitted_source_line_count=None,
                omitted_ast_fact_count=None,
            )
        )
    progress = dict(inputs["progress"])
    old_row = next(iter(progress.values()))
    later = contexts[1]
    if corruption == "later_tampered":
        progress[(later.surface_id, later.context_id)] = replace(
            old_row,
            surface_id=later.surface_id,
            context_id=later.context_id,
            proposal_version=8,
            context_hash="0" * 64,
        )
    else:
        progress[(later.surface_id, "foreign-context")] = replace(
            old_row,
            surface_id=later.surface_id,
            context_id="foreign-context",
            proposal_version=8,
        )
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    monkeypatch.setattr(
        store, "list_surface_exploration_progress", lambda *_args: progress
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.surface_coverage_v6.read_frozen_parent_v5",
        lambda *_args: inputs["v5"],
    )
    app = _application(data_dir, store)

    class Agent:
        async def propose_surface(self, *_args: object) -> NoReturn:
            raise AssertionError("Agent called before saved progress preflight")

    monkeypatch.setattr(app, "_candidate_hypotheses", Agent())
    static_ref = inputs["index_ref"].model_copy(
        update={"content_hash": index.static_bundle_hash}
    )
    static = StaticBootstrapResult.model_construct(
        repository_profile_ref=static_ref,
        static_bundle_ref=static_ref,
        workspace_path=tmp_path,
    )
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/repository",
        candidate_scope_fingerprint=index.scope_fingerprint,
        candidate_terminal=CandidateTerminal(
            status="PARTIAL",
            bundle_hash=index.static_bundle_hash,
            scope_fingerprint=index.scope_fingerprint,
            decision_counts={},
            deep_counts={},
            hypothesis_count=0,
            surface_proof_version=5,
        ),
        surface_enrichment_plan_ref=index_ref,
        surface_enrichment_v5_plan_ref=parent_ref,
        surface_enrichment_v6_plan_ref=parent_ref,
        surface_enrichment_v7_plan_ref=v7_ref,
        surface_enrichment_v8_plan_ref=plan_ref,
        python_scope_certificate_ref=index_ref,
    )

    with pytest.raises(ValueError, match="SURFACE_EXPLORATION_SCOPE_CHANGED"):
        await app._run_v8_surface_enrichment(
            run, identity, static, artifacts, plan, tuple(contexts)
        )
