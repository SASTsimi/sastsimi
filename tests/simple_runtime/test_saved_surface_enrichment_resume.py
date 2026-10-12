"""Saved v4 enrichment preflight must retain the original v1 proof and data."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.reporting.analysis_display_id import AnalysisDisplayIdStore
from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_contexts import SurfaceContext
from sastsimi.simple_runtime.surface_enrichment_v4 import (
    V4Part,
    prepare_surface_enrichment_v4,
    read_saved_coverage_v1,
)
from tests.unit.simple_runtime.test_surface_enrichment_v4 import _case


def _saved_app(
    tmp_path: Path, identity: CheckpointIdentity
) -> tuple[SimpleAnalysisApplication, SimpleCheckpointStore]:
    data_dir = tmp_path / "live-data"
    store = SimpleCheckpointStore(
        data_dir / "db" / "sastsimi.sqlite3", artifact_data_dir=data_dir
    )
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id="A-001",
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="https://example.invalid/saved",
            candidate_pipeline_version=2,
        )
    )
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(identity.analysis_id)
    return (
        SimpleAnalysisApplication(
            data_dir=data_dir,
            store=store,
            static_bootstrap=None,  # type: ignore[arg-type]
            hypothesis_bootstrap=None,  # type: ignore[arg-type]
            runner_factory=None,  # type: ignore[arg-type]
        ),
        store,
    )


def test_saved_v1_coverage_reader_rejects_mutated_surface_identity(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path)
    index = case[1]
    coverage = case[5]
    artifacts = case[8]
    ref = artifacts.put_json(coverage.to_json())

    assert read_saved_coverage_v1(artifacts, index, ref) == coverage

    corrupt = coverage.to_json()
    corrupt["surfaces"][0]["path"] = "other.py"
    altered_ref = artifacts.put_json(corrupt)
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_COVERAGE_INVALID"):
        read_saved_coverage_v1(artifacts, index, altered_ref)


def test_graph_targets_use_original_index_surfaces_not_reviewed_copies(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path)
    index, coverage = case[1], case[5]
    targets = SimpleAnalysisApplication._saved_graph_targets(index, coverage)
    assert len(targets) == 1
    assert targets[0] is index.surfaces[0]
    assert targets[0] is not coverage.surfaces[0]


def test_v4_plan_and_certificate_refs_round_trip_without_changing_old_runs(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path)
    artifacts = case[8]
    plan_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v4"})
    certificate_ref = artifacts.put_json(
        {"kind": "simple_python_scope_recertification_v1"}
    )
    run = SimpleAnalysisRun(
        analysis_id=case[0].analysis_id,
        display_analysis_id="A-001",
        workspace_id=case[0].workspace_id,
        commit_id=case[0].commit_id,
        repository="https://example.invalid/pinned",
        surface_enrichment_plan_ref=plan_ref,
        python_scope_certificate_ref=certificate_ref,
    )
    assert (
        SimpleAnalysisRun.model_validate_json(
            run.model_dump_json()
        ).surface_enrichment_plan_ref
        == plan_ref
    )
    assert run.python_scope_certificate_ref == certificate_ref

    old = run.model_dump(mode="json")
    old.pop("surface_enrichment_plan_ref")
    old.pop("python_scope_certificate_ref")
    legacy = SimpleAnalysisRun.model_validate_json(json.dumps(old))
    assert legacy.surface_enrichment_plan_ref is None
    assert legacy.python_scope_certificate_ref is None


def test_original_v1_coverage_ref_is_pinned_in_plan_binding(tmp_path: Path) -> None:
    case = _case(tmp_path)
    (
        identity,
        index,
        index_ref,
        static_ref,
        certificate,
        coverage,
        progress,
        graphs,
        artifacts,
    ) = case
    first_ref = artifacts.put_json(coverage.to_json())
    second_ref = artifacts.put_json({"kind": "unrelated-data"})
    first, _ = prepare_surface_enrichment_v4(
        identity,
        "candidate",
        static_ref,
        index,
        index_ref,
        certificate,
        coverage,
        progress,
        graphs,
        prior_coverage_ref=first_ref,
    )
    unpinned, _ = prepare_surface_enrichment_v4(
        identity,
        "candidate",
        static_ref,
        index,
        index_ref,
        certificate,
        coverage,
        progress,
        graphs,
    )
    assert first["original_coverage_ref"] == first_ref.model_dump(mode="json")
    assert first["plan_binding_hash"] != unpinned["plan_binding_hash"]
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_COVERAGE_REF_INVALID"):
        prepare_surface_enrichment_v4(
            identity,
            "candidate",
            static_ref,
            index,
            index_ref,
            certificate,
            coverage,
            progress,
            graphs,
            prior_coverage_ref=second_ref,
        )


@pytest.mark.asyncio
async def test_explicit_resume_prepares_before_dispatch_without_mutating_old_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(
        data_dir / "db" / "sastsimi.sqlite3", artifact_data_dir=data_dir
    )
    run = SimpleAnalysisRun(
        analysis_id="saved-analysis",
        display_analysis_id="A-001",
        workspace_id="saved-workspace",
        commit_id="a" * 40,
        repository="https://example.invalid/saved",
        candidate_pipeline_version=2,
    )
    store.save_analysis_run(run)
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(run.analysis_id)
    application = SimpleAnalysisApplication(
        data_dir=data_dir,
        store=store,
        static_bootstrap=None,  # type: ignore[arg-type]
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )
    calls: list[str] = []

    async def prepare(exact: str) -> None:
        calls.append("prepare:" + exact)

    async def dispatch(exact: str) -> SimpleAnalysisOutcome:
        calls.append("dispatch:" + exact)
        return SimpleAnalysisOutcome(
            identity=CheckpointIdentity(
                analysis_id=exact,
                workspace_id=run.workspace_id,
                commit_id=run.commit_id,
                hypothesis_id=None,
            ),
            display_analysis_id=run.display_analysis_id,
            status="PARTIAL",
            current_stage=SimpleStage.HYPOTHESIS_DONE,
        )

    monkeypatch.setattr(application, "_prepare_surface_enrichment_locked", prepare)
    monkeypatch.setattr(application, "_resume_locked", dispatch)

    old = store.require_analysis_run(run.analysis_id)
    result = await application.resume("A-001", enrich_saved_surface_evidence=True)
    assert result.status == "PARTIAL"
    assert calls == ["prepare:saved-analysis", "dispatch:saved-analysis"]
    assert store.require_analysis_run(run.analysis_id) == old


@pytest.mark.asyncio
async def test_explicit_preflight_failure_is_durable_before_plan_is_pinned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(
        data_dir / "db" / "sastsimi.sqlite3", artifact_data_dir=data_dir
    )
    run = SimpleAnalysisRun(
        analysis_id="saved-analysis",
        display_analysis_id="A-001",
        workspace_id="saved-workspace",
        commit_id="a" * 40,
        repository="https://example.invalid/saved",
        candidate_pipeline_version=2,
    )
    store.save_analysis_run(run)
    AnalysisDisplayIdStore(store.database_path).get_or_allocate(run.analysis_id)
    application = SimpleAnalysisApplication(
        data_dir=data_dir,
        store=store,
        static_bootstrap=None,  # type: ignore[arg-type]
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )

    async def failed_preflight(_: str) -> None:
        raise ValueError("SURFACE_ENRICHMENT_SOURCE_CHANGED")

    async def forbidden_dispatch(_: str) -> None:
        raise AssertionError("must not dispatch after failed preflight")

    monkeypatch.setattr(
        application, "_prepare_surface_enrichment_locked", failed_preflight
    )
    monkeypatch.setattr(application, "_resume_locked", forbidden_dispatch)
    outcome = await application.resume("A-001", enrich_saved_surface_evidence=True)
    saved = store.require_analysis_run(run.analysis_id)
    assert outcome.status == "BLOCKED"
    assert outcome.error_code == "SURFACE_ENRICHMENT_SOURCE_CHANGED"
    assert saved.surface_enrichment_status == "BLOCKED"
    assert saved.surface_enrichment_error_code == outcome.error_code
    assert saved.surface_enrichment_plan_ref is None
    assert saved.candidate_terminal == run.candidate_terminal


@pytest.mark.asyncio
async def test_prepare_pins_plan_and_certificate_before_writing_contexts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path)
    identity, _, _, _, certificate, _, _, graphs, _ = case
    plan, parts = prepare_surface_enrichment_v4(
        identity,
        "candidate",
        case[3],
        case[1],
        case[2],
        certificate,
        case[5],
        case[6],
        graphs,
    )
    app, store = _saved_app(tmp_path, identity)
    observed: list[str] = []

    async def static_scope(*_: object) -> None:
        observed.append("scope")

    def calculate(
        *_: object,
    ) -> tuple[
        dict[str, object],
        tuple[V4Part, ...],
        dict[str, object],
        dict[str, dict[str, object]],
    ]:
        observed.append("calculate")
        return plan, parts, certificate, graphs

    original_put = SimpleArtifactRepository.put_json

    def tracked_put(self: SimpleArtifactRepository, value: object) -> StoredDataRef:
        if isinstance(value, dict):
            observed.append(str(value.get("kind")))
            if value.get("kind") == "simple_surface_context_v4":
                saved = store.require_analysis_run(identity.analysis_id)
                assert saved.surface_enrichment_plan_ref is not None
                assert saved.python_scope_certificate_ref is not None
        return original_put(self, value)

    monkeypatch.setattr(app, "_assert_completed_static_scope", static_scope)
    monkeypatch.setattr(app, "_calculate_saved_surface_enrichment", calculate)
    monkeypatch.setattr(SimpleArtifactRepository, "put_json", tracked_put)
    await app._prepare_surface_enrichment_locked(identity.analysis_id)
    saved = store.require_analysis_run(identity.analysis_id)
    artifacts = SimpleArtifactRepository(app._data_dir, identity)
    assert saved.surface_enrichment_plan_ref is not None
    assert saved.python_scope_certificate_ref is not None
    assert json.loads(artifacts.read(saved.surface_enrichment_plan_ref)) == plan
    assert json.loads(artifacts.read(saved.python_scope_certificate_ref)) == certificate
    assert observed[:4] == [
        "scope",
        "calculate",
        "simple_python_scope_recertification_v1",
        "simple_surface_enrichment_plan_v4",
    ]
    for part in parts:
        assert artifacts.read(app._surface_context_ref(identity, part.context_hash))
    _, contexts = app._saved_surface_enrichment(saved, identity, artifacts)
    assert {context.context_id for context in contexts} == {
        part.context_id for part in parts
    }


@pytest.mark.asyncio
async def test_reprepare_restores_only_missing_unreviewed_part(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path)
    identity, _, _, _, certificate, _, _, graphs, _ = case
    plan, parts = prepare_surface_enrichment_v4(
        identity,
        "candidate",
        case[3],
        case[1],
        case[2],
        certificate,
        case[5],
        case[6],
        graphs,
    )
    app, store = _saved_app(tmp_path, identity)
    artifacts = SimpleArtifactRepository(app._data_dir, identity)
    cert_ref = artifacts.put_json(certificate)
    plan_ref = artifacts.put_json(plan)
    store.save_analysis_run(
        store.require_analysis_run(identity.analysis_id).model_copy(
            update={
                "surface_enrichment_plan_ref": plan_ref,
                "python_scope_certificate_ref": cert_ref,
            }
        )
    )

    async def static_scope(*_: object) -> None:
        return None

    monkeypatch.setattr(app, "_assert_completed_static_scope", static_scope)
    monkeypatch.setattr(
        app,
        "_calculate_saved_surface_enrichment",
        lambda *_: (plan, parts, certificate, graphs),
    )
    original_put = SimpleArtifactRepository.put_json
    interrupted = False

    def interrupt_context_write(
        self: SimpleArtifactRepository, value: object
    ) -> StoredDataRef:
        nonlocal interrupted
        if (
            not interrupted
            and isinstance(value, dict)
            and value.get("kind") == "simple_surface_context_v4"
        ):
            interrupted = True
            raise OSError("simulated crash after manifest pin")
        return original_put(self, value)

    monkeypatch.setattr(SimpleArtifactRepository, "put_json", interrupt_context_write)
    with pytest.raises(OSError, match="simulated crash"):
        await app._prepare_surface_enrichment_locked(identity.analysis_id)
    assert store.require_analysis_run(identity.analysis_id).surface_enrichment_plan_ref
    monkeypatch.setattr(SimpleArtifactRepository, "put_json", original_put)
    await app._prepare_surface_enrichment_locked(identity.analysis_id)
    first = parts[0]
    context_ref = app._surface_context_ref(identity, first.context_hash)
    assert artifacts.read(context_ref)
    saved = store.require_analysis_run(identity.analysis_id)
    assert saved.surface_enrichment_plan_ref == plan_ref
    assert saved.python_scope_certificate_ref == cert_ref


@pytest.mark.asyncio
async def test_plain_resume_preserves_old_partial_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = CheckpointIdentity(
        analysis_id="legacy-partial",
        workspace_id="saved-workspace",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    app, store = _saved_app(tmp_path, identity)
    before = store.require_analysis_run(identity.analysis_id)
    observed: list[str] = []

    async def forbidden_prepare(*_: object) -> None:
        observed.append("unexpected-prepare")

    async def dispatch(exact: str) -> SimpleAnalysisOutcome:
        observed.append(exact)
        return SimpleAnalysisOutcome(
            identity=identity,
            display_analysis_id="A-001",
            status="PARTIAL",
            current_stage=SimpleStage.HYPOTHESIS_DONE,
        )

    monkeypatch.setattr(app, "_prepare_surface_enrichment_locked", forbidden_prepare)
    monkeypatch.setattr(app, "_resume_locked", dispatch)
    outcome = await app.resume("A-001")
    assert outcome.status == "PARTIAL"
    assert observed == [identity.analysis_id]
    assert store.require_analysis_run(identity.analysis_id) == before


@pytest.mark.asyncio
async def test_pinned_v4_run_skips_legacy_candidate_producer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path)
    identity = case[0]
    app, store = _saved_app(tmp_path, identity)
    artifacts = SimpleArtifactRepository(app._data_dir, identity)
    plan_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v4"})
    run = store.require_analysis_run(identity.analysis_id).model_copy(
        update={"surface_enrichment_plan_ref": plan_ref}
    )
    store.save_analysis_run(run)
    static = StaticBootstrapResult(
        repository_profile_ref=case[3],
        static_bundle_ref=case[3],
        workspace_path=tmp_path,
    )
    observed: list[str] = []

    def saved(
        *_: object,
    ) -> tuple[dict[str, object], tuple[SurfaceContext, ...]]:
        observed.append("saved-v4")
        return {"kind": "simple_surface_enrichment_plan_v4"}, ()

    async def v4(*_: object) -> SimpleAnalysisOutcome:
        observed.append("v4-only")
        return SimpleAnalysisOutcome(
            identity=identity,
            display_analysis_id="A-001",
            status="PARTIAL",
            current_stage=SimpleStage.HYPOTHESIS_DONE,
        )

    async def legacy(*_: object) -> SimpleAnalysisOutcome:
        observed.append("wrong-legacy")
        raise AssertionError("legacy pipeline must not repeat")

    monkeypatch.setattr(app, "_saved_surface_enrichment", saved)
    monkeypatch.setattr(app, "_run_v4_surface_enrichment", v4, raising=False)
    monkeypatch.setattr(app, "_run_candidate_pipeline_inner", legacy)
    result = await app._run_candidate_pipeline(run, identity, static)
    assert result.status == "PARTIAL"
    assert observed == ["saved-v4", "v4-only"]
    assert store.require_analysis_run(identity.analysis_id).surface_enrichment_plan_ref
