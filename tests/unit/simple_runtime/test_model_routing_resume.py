from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from sastsimi.composition.simple_runtime_composition import SimpleClientFactory
from sastsimi.config.user_config import SimpleExecutionProfile
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisRequest,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageResult,
)
from sastsimi.simple_runtime.runner import SimpleRuntimeRunner
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from tests.simple_runtime.test_simple_analysis_application import (
    _Hypotheses,
    _ref,
    _Static,
)


def _profile(tmp_path: Path, **changes: Any) -> SimpleExecutionProfile:
    values: dict[str, Any] = {
        "provider_profile_ref": "local-openai",
        "provider": "openai",
        "model": "new-primary",
        "light_model": "new-light",
        "agent_models": {"technical_gate": "new-explicit"},
        "auth_mode": "API_KEY",
        "credential_ref": "env:OPENAI_API_KEY",
        "data_dir": tmp_path,
        "workspace_root": tmp_path / "workspaces",
        "max_cost_minor_units": 1000,
        "docker_network": "NONE",
        "tools": {},
    }
    values.update(changes)
    return SimpleExecutionProfile.model_validate(values)


def _run(
    store: SimpleCheckpointStore,
    *,
    version: int | None = 1,
    routes: dict[str, str] | None = None,
) -> SimpleAnalysisRun:
    analysis_id = "analysis-route-resume"
    display_id = AnalysisDisplayIdStore(store.database_path).get_or_allocate(
        analysis_id
    )
    return SimpleAnalysisRun(
        analysis_id=analysis_id,
        display_analysis_id=display_id,
        workspace_id="workspace-route",
        commit_id="a" * 40,
        repository="https://example.invalid/repo.git",
        provider="openai",
        model="old-primary",
        model_route_version=version,
        model_routes=(
            None
            if version is None
            else routes
            if routes is not None
            else {"cwe_label": "old-light", "technical_gate": "old-explicit"}
        ),
    )


def _identity(run: SimpleAnalysisRun) -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id=run.analysis_id,
        workspace_id=run.workspace_id,
        commit_id=run.commit_id,
        hypothesis_id=None,
    )


def test_new_run_route_snapshot_is_validated_and_legacy_json_loads() -> None:
    base = {
        "analysis_id": "legacy-run",
        "display_analysis_id": "A-001",
        "workspace_id": "workspace-1",
        "commit_id": "a" * 40,
        "repository": "https://example.invalid/repo.git",
    }
    legacy = SimpleAnalysisRun.model_validate(base)
    assert legacy.model_route_version is None
    assert legacy.model_routes is None
    with pytest.raises(ValueError):
        SimpleAnalysisRun.model_validate(
            {**base, "model_route_version": 1, "model": "primary"}
        )


@pytest.mark.asyncio
async def test_new_analysis_saves_routes_and_completed_work_is_not_replayed(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    calls: list[SimpleStage] = []

    def runner_factory(runtime_store, identity, static):
        del identity, static
        handlers = {}
        for stage in tuple(SimpleStage)[2:]:

            async def handle(
                _checkpoint: StageCheckpoint,
                _prior: Mapping[SimpleStage, StageCheckpoint],
                *,
                current: SimpleStage = stage,
            ) -> StageResult:
                calls.append(current)
                return StageResult(
                    output_refs=(_ref(current.value.lower()),),
                    verdict=(
                        "FALSE"
                        if current is SimpleStage.VERIFICATION_FINAL_DONE
                        else None
                    ),
                )

            handlers[stage] = handle
        return SimpleRuntimeRunner(runtime_store, handlers)

    app = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=runner_factory,
        id_factory=iter(("analysis-snapshot", "workspace-1")).__next__,
        provider="openai",
        model="primary",
        model_routes={"cwe_label": "light", "hypothesis": "primary"},
    )
    outcome = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://example.invalid/repo.git",
            commit="a" * 40,
        )
    )
    saved = store.require_analysis_run(outcome.identity.analysis_id)
    assert saved.model_route_version == 1
    assert saved.model_routes == {"cwe_label": "light", "hypothesis": "primary"}
    before = tuple(calls)

    edited = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=runner_factory,
        provider="openai",
        model="new-primary",
        model_routes={"cwe_label": "new-light"},
    )
    resumed = await edited.resume(outcome.display_analysis_id)

    assert outcome.status == "COMPLETE"
    assert resumed.status == "COMPLETE"
    assert tuple(calls) == before
    assert store.require_analysis_run(outcome.identity.analysis_id).model_routes == (
        saved.model_routes
    )


def test_factory_resumes_with_stored_primary_and_routes_not_edited_profile(
    tmp_path: Path,
) -> None:
    profile = _profile(tmp_path)
    factory = SimpleClientFactory(profile)
    run = _run(factory._store)
    factory._store.save_analysis_run(run)
    identity = _identity(run)
    client = factory(identity, SimpleArtifactRepository(tmp_path, identity))

    assert client.client_for_agent("cwe_label")._model == "old-light"
    assert client.client_for_agent("technical_gate")._model == "old-explicit"
    assert client.client_for_agent("hypothesis")._model == "old-primary"


def test_legacy_run_ignores_new_light_policy_but_keeps_explicit_override(
    tmp_path: Path,
) -> None:
    profile = _profile(tmp_path)
    factory = SimpleClientFactory(profile)
    run = _run(factory._store, version=None)
    factory._store.save_analysis_run(run)
    identity = _identity(run)
    client = factory(identity, SimpleArtifactRepository(tmp_path, identity))

    assert client.client_for_agent("cwe_label")._model == "new-primary"
    assert client.client_for_agent("technical_gate")._model == "new-explicit"


@pytest.mark.asyncio
async def test_provider_mismatch_blocks_before_repair_or_database_mutation(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    run = _run(store)
    store.save_analysis_run(run)
    before = store.require_analysis_run(run.analysis_id).model_dump_json()
    with sqlite3.connect(store.database_path) as connection:
        before_attempts = connection.execute(
            "SELECT COUNT(*) FROM simple_llm_attempts"
        ).fetchone()[0]

    app = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=lambda *_args: (_ for _ in ()).throw(
            AssertionError("must not run")
        ),
        provider="codex",
        model="other",
    )
    outcome = await app.resume(
        run.display_analysis_id,
        repair_exhausted_hypothesis="hypothesis-1",
    )

    assert outcome.status == "BLOCKED"
    assert outcome.error_code == "MODEL_ROUTE_PROVIDER_MISMATCH"
    assert store.require_analysis_run(run.analysis_id).model_dump_json() == before
    with sqlite3.connect(store.database_path) as connection:
        assert (
            connection.execute("SELECT COUNT(*) FROM simple_llm_attempts").fetchone()[0]
            == before_attempts
        )
