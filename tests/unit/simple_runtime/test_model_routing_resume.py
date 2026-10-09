from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

import pytest

import sastsimi.composition.simple_runtime_composition as composition
from sastsimi.composition.simple_runtime_composition import (
    PublicSimpleRuntimeApplication,
    SimpleClientFactory,
)
from sastsimi.config.user_config import SimpleExecutionProfile, UserConfig
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisRequest,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.call_queue import RunLimitedClient
from sastsimi.simple_runtime.model_routing import ModelRoutedClient
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageResult,
)
from sastsimi.simple_runtime.runner import SimpleRuntimeRunner, SimpleStageHandler
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
    version: Literal[1] | None = 1,
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

    def runner_factory(
        runtime_store: SimpleCheckpointStore,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
    ) -> SimpleRuntimeRunner:
        del identity, static
        handlers: dict[SimpleStage, SimpleStageHandler] = {}
        for stage in tuple(SimpleStage)[2:]:

            async def handle(
                checkpoint: StageCheckpoint,
                prior: Mapping[SimpleStage, StageCheckpoint],
                *,
                current: SimpleStage = stage,
            ) -> StageResult:
                del checkpoint, prior
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

    assert isinstance(client, ModelRoutedClient)
    cwe_client = client.client_for_agent("cwe_label")
    technical_gate_client = client.client_for_agent("technical_gate")
    hypothesis_client = client.client_for_agent("hypothesis")
    assert isinstance(cwe_client, RunLimitedClient)
    assert isinstance(technical_gate_client, RunLimitedClient)
    assert isinstance(hypothesis_client, RunLimitedClient)
    assert cwe_client._model == "old-light"
    assert technical_gate_client._model == "old-explicit"
    assert hypothesis_client._model == "old-primary"


def test_legacy_run_ignores_new_light_policy_but_keeps_explicit_override(
    tmp_path: Path,
) -> None:
    profile = _profile(tmp_path)
    factory = SimpleClientFactory(profile)
    run = _run(factory._store, version=None)
    factory._store.save_analysis_run(run)
    identity = _identity(run)
    client = factory(identity, SimpleArtifactRepository(tmp_path, identity))

    assert isinstance(client, ModelRoutedClient)
    cwe_client = client.client_for_agent("cwe_label")
    technical_gate_client = client.client_for_agent("technical_gate")
    assert isinstance(cwe_client, RunLimitedClient)
    assert isinstance(technical_gate_client, RunLimitedClient)
    assert cwe_client._model == "new-primary"
    assert technical_gate_client._model == "new-explicit"


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


@pytest.mark.parametrize("with_progress", [False, True])
def test_public_resume_reports_provider_mismatch_without_changing_saved_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_progress: bool
) -> None:
    profile = _profile(
        tmp_path,
        provider="codex",
        model="new-primary",
        light_model="new-light",
        auth_mode="SUBSCRIPTION_LOGIN",
        credential_ref="OFFICIAL_CLIENT_SESSION",
    )
    config = UserConfig(
        data_dir=tmp_path,
        profile_path=tmp_path / "profile.toml",
        auth_mode="SUBSCRIPTION_LOGIN",
        provider="codex",
        model="new-primary",
        light_model="new-light",
        credential_ref="OFFICIAL_CLIENT_SESSION",
        execution_profile="LIGHTWEIGHT",
        max_cost_minor_units=1000,
        docker_network="NONE",
        enabled_tools=(),
        detected_versions={},
        setup_ready=True,
    )
    public = PublicSimpleRuntimeApplication(config, profile)
    run = _run(public._store)
    public._store.save_analysis_run(run)
    public._store.mark_running(
        _identity(run), SimpleStage.STATIC_DONE, (), attempt_id="static-1"
    )
    before = public._store.require_analysis_run(run.analysis_id).model_dump_json()
    app = SimpleAnalysisApplication(
        data_dir=tmp_path,
        store=public._store,
        static_bootstrap=_Static(),
        hypothesis_bootstrap=_Hypotheses(),
        runner_factory=lambda *_args: (_ for _ in ()).throw(
            AssertionError("must not run")
        ),
        provider="codex",
        model="new-primary",
    )
    monkeypatch.setattr(composition, "build_analysis_application", lambda *_: app)

    data = (
        public.resume_with_progress(run.display_analysis_id, lambda _snapshot: None)
        if with_progress
        else public.resume(run.display_analysis_id)
    )

    assert data["status"] == "BLOCKED"
    assert data["current_stage"] == "STATIC_DONE"
    assert data["error_code"] == "MODEL_ROUTE_PROVIDER_MISMATCH"
    assert (
        public._store.require_analysis_run(run.analysis_id).model_dump_json() == before
    )
