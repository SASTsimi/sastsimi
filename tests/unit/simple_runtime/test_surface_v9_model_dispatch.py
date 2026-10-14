"""A v9 successor is optional and never rewrites a pinned v8 run."""

from pathlib import Path
from types import SimpleNamespace
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
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
)
from sastsimi.simple_runtime.surface_contexts import SurfaceContext


def _partial_v8_run(tmp_path: Path) -> SimpleAnalysisRun:
    identity = CheckpointIdentity(
        analysis_id="analysis-v9",
        workspace_id="workspace-v9",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    ref = SimpleArtifactRepository(tmp_path, identity).put_json({"kind": "fixture"})
    return SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/demo",
        candidate_scope_fingerprint="scope-v9",
        candidate_terminal=CandidateTerminal(
            status="PARTIAL",
            bundle_hash="b" * 64,
            scope_fingerprint="scope-v9",
            decision_counts={},
            deep_counts={},
            hypothesis_count=0,
            surface_proof_version=6,
            producer_finished=True,
        ),
        surface_enrichment_plan_ref=ref,
        surface_enrichment_v5_plan_ref=ref,
        surface_enrichment_v6_plan_ref=ref,
        surface_enrichment_v7_plan_ref=ref,
        surface_enrichment_v8_plan_ref=ref,
        python_scope_certificate_ref=ref,
    )


def test_partial_v8_selects_additive_v9_round(tmp_path: Path) -> None:
    run = _partial_v8_run(tmp_path)
    assert SimpleAnalysisApplication._surface_enrichment_round(run) == "v9"
    assert run.surface_enrichment_v9_plan_ref is None


def test_unfinished_v8_producer_does_not_select_v9(tmp_path: Path) -> None:
    run = _partial_v8_run(tmp_path)
    assert run.candidate_terminal is not None
    unfinished = run.model_copy(
        update={
            "candidate_terminal": run.candidate_terminal.model_copy(
                update={"producer_finished": False}
            )
        }
    )
    assert SimpleAnalysisApplication._surface_enrichment_round(unfinished) == "v8"


def test_completed_v9_model_round_trips_without_changing_v8_ref(
    tmp_path: Path,
) -> None:
    prior = _partial_v8_run(tmp_path)
    assert prior.candidate_terminal is not None
    ref = prior.surface_enrichment_v8_plan_ref
    assert ref is not None
    successor = prior.model_copy(
        update={
            "surface_enrichment_v9_plan_ref": ref,
            "candidate_terminal": prior.candidate_terminal.model_copy(
                update={"surface_proof_version": 7}
            ),
        }
    )
    loaded = SimpleAnalysisRun.model_validate_json(successor.model_dump_json())
    assert loaded.surface_enrichment_v8_plan_ref == ref
    assert loaded.surface_enrichment_v9_plan_ref == ref
    assert loaded.candidate_terminal is not None
    assert loaded.candidate_terminal.surface_proof_version == 7


def test_v9_dispatch_precedes_v10_without_reopening_v8_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    prior = _partial_v8_run(tmp_path)
    assert prior.surface_enrichment_v8_plan_ref is not None
    run = prior.model_copy(
        update={"surface_enrichment_v9_plan_ref": prior.surface_enrichment_v8_plan_ref}
    )
    assert run.candidate_terminal is not None
    promoted = run.model_copy(
        update={
            "candidate_terminal": run.candidate_terminal.model_copy(
                update={"surface_proof_version": 7}
            )
        }
    )
    identity = CheckpointIdentity(
        analysis_id=run.analysis_id,
        workspace_id=run.workspace_id,
        commit_id=run.commit_id,
        hypothesis_id=None,
    )
    app = object.__new__(SimpleAnalysisApplication)
    app._data_dir = tmp_path
    monkeypatch.setattr(
        app,
        "_store",
        SimpleNamespace(require_analysis_run=lambda _analysis_id: promoted),
        raising=False,
    )
    expected = SimpleAnalysisOutcome(
        identity=identity,
        display_analysis_id=run.display_analysis_id,
        status="PARTIAL",
        current_stage=SimpleStage.HYPOTHESIS_DONE,
    )
    called: list[str] = []

    def saved_v9(
        *_args: object,
    ) -> tuple[dict[str, object], tuple[SurfaceContext, ...]]:
        called.append("saved-v9")
        return {"kind": "simple_surface_enrichment_plan_v9"}, ()

    async def run_v9(*_args: object) -> SimpleAnalysisOutcome:
        called.append("run-v9")
        return expected

    async def run_v10(*_args: object) -> SimpleAnalysisOutcome:
        called.append("run-v10")
        return expected

    def forbidden_v8(*_args: object) -> NoReturn:
        raise AssertionError("v8 parent must not replay after v9 pin")

    monkeypatch.setattr(app, "_saved_surface_enrichment_v9", saved_v9, raising=False)
    monkeypatch.setattr(app, "_run_v9_surface_enrichment", run_v9, raising=False)
    monkeypatch.setattr(app, "_run_v10_surface_enrichment", run_v10, raising=False)
    monkeypatch.setattr(app, "_saved_surface_enrichment_v8", forbidden_v8)
    static = StaticBootstrapResult(
        repository_profile_ref=prior.surface_enrichment_v8_plan_ref,
        static_bundle_ref=prior.surface_enrichment_v8_plan_ref,
        workspace_path=tmp_path,
    )

    with pytest.raises(StopIteration) as done:
        app._run_candidate_pipeline(run, identity, static).send(None)

    assert done.value.value == expected
    assert called == ["saved-v9", "run-v9", "run-v10"]
