"""A pinned v7 plan dispatches before v6 and replays exact source parts."""

from __future__ import annotations

from pathlib import Path
from typing import NoReturn

import pytest

from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.models import SimpleStage
from sastsimi.simple_runtime.surface_contexts import SurfaceContext
from tests.simple_runtime.test_saved_surface_enrichment_v5_resume import _application
from tests.unit.simple_runtime.test_surface_coverage_v5 import _v7_case


def test_v7_saved_replay_reconstructs_exact_plan_and_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = _v7_case(tmp_path)
    case = data["case"]
    run = case.store.require_analysis_run(case.identity.analysis_id).model_copy(
        update={
            "surface_enrichment_v7_plan_ref": data["v7_plan_ref"],
            "candidate_scope_fingerprint": case.index.scope_fingerprint,
        }
    )
    app = _application(tmp_path / "data", case.store)
    monkeypatch.setattr(
        case.store,
        "list_surface_exploration_progress",
        lambda *_args, **_kwargs: case.progress,
    )

    saved, contexts = app._saved_surface_enrichment_v7(
        run, case.identity, case.artifacts
    )

    assert saved == data["v7_plan"]
    assert [(row.surface_id, row.context_id) for row in contexts] == [
        (part.surface_id, part.context_id) for part in data["v7_parts"]
    ]


def test_v7_dispatch_precedes_v6_without_reopening_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = _v7_case(tmp_path)
    case = data["case"]
    run = case.store.require_analysis_run(case.identity.analysis_id).model_copy(
        update={
            "surface_enrichment_v7_plan_ref": data["v7_plan_ref"],
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

    def saved_v7(
        *_args: object,
    ) -> tuple[dict[str, object], tuple[SurfaceContext, ...]]:
        observed.append("v7-plan")
        return data["v7_plan"], ()

    async def run_v7(*_args: object) -> SimpleAnalysisOutcome:
        observed.append("v7-run")
        return expected

    def forbidden_v6(*_args: object) -> NoReturn:
        raise AssertionError("v6 must not run once v7 is pinned")

    monkeypatch.setattr(app, "_saved_surface_enrichment_v7", saved_v7)
    monkeypatch.setattr(app, "_run_v7_surface_enrichment", run_v7)
    monkeypatch.setattr(app, "_saved_surface_enrichment_v6", forbidden_v6)
    static = StaticBootstrapResult(
        repository_profile_ref=case.artifacts.put_json({"kind": "profile"}),
        static_bundle_ref=case.artifacts.put_json({"kind": "bundle"}),
        workspace_path=tmp_path,
    )

    with pytest.raises(StopIteration) as done:
        app._run_candidate_pipeline(run, case.identity, static).send(None)

    assert done.value.value == expected
    assert observed == ["v7-plan", "v7-run"]


def test_v7_plan_is_only_explicit_successor_to_partial_v4(tmp_path: Path) -> None:
    data = _v7_case(tmp_path)
    case = data["case"]
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.candidate_terminal is not None
    ready = run.model_copy(
        update={
            "candidate_terminal": run.candidate_terminal.model_copy(
                update={"surface_proof_version": 4, "status": "PARTIAL"}
            )
        }
    )

    assert SimpleAnalysisApplication._surface_enrichment_round(ready) == "v7"
    assert SimpleAnalysisApplication._surface_enrichment_round(run) == "v6"
