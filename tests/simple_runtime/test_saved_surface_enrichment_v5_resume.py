"""Saved v5 state is additive to existing v4 proofs and run records."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import NoReturn

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.application import (
    HypothesisBootstrap,
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
    SimpleAnalysisRequest,
    StaticBootstrap,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    CandidateTerminal,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import (
    SimpleCheckpointStore,
    SurfaceExplorationProgressRecord,
)
from sastsimi.simple_runtime.surface_contexts import SurfaceContext
from sastsimi.simple_runtime.surface_enrichment_v5 import prepare_surface_enrichment_v5
from sastsimi.simple_runtime.surface_evidence_validation_v5 import validate_v5_response
from tests.unit.simple_runtime.test_surface_coverage_v4 import (
    _evaluate as _evaluate_v4,
)
from tests.unit.simple_runtime.test_surface_coverage_v4 import (
    _save_v6_part,
    _successor_case,
)
from tests.unit.simple_runtime.test_surface_enrichment_v5 import _case
from tests.unit.simple_runtime.test_surface_enrichment_v6 import (
    _prepare,
    _saved_v3_case,
)
from tests.unit.simple_runtime.test_surface_v4_progress import _commit


def _identity() -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="analysis-v5",
        workspace_id="workspace-v5",
        commit_id="a" * 40,
        hypothesis_id=None,
    )


class _UnusedBootstrap(StaticBootstrap, HypothesisBootstrap):
    async def run(
        self, _request: SimpleAnalysisRequest, _identity: CheckpointIdentity
    ) -> NoReturn:
        raise AssertionError("static bootstrap must not run in this test")

    async def propose(
        self, _identity: CheckpointIdentity, _static: StaticBootstrapResult
    ) -> NoReturn:
        raise AssertionError("hypothesis bootstrap must not run in this test")


def _unused_runner(
    _store: SimpleCheckpointStore,
    _identity: CheckpointIdentity,
    _static: StaticBootstrapResult,
) -> NoReturn:
    raise AssertionError("runtime runner must not run in this test")


def _application(
    data_dir: Path, store: SimpleCheckpointStore
) -> SimpleAnalysisApplication:
    bootstrap = _UnusedBootstrap()
    return SimpleAnalysisApplication(
        data_dir=data_dir,
        store=store,
        static_bootstrap=bootstrap,
        hypothesis_bootstrap=bootstrap,
        runner_factory=_unused_runner,
    )


def test_saved_v6_successor_replays_only_pinned_parts(tmp_path: Path) -> None:
    case = _saved_v3_case(tmp_path)
    identity = case["identity"]
    data_dir = tmp_path / "artifacts"
    artifacts = case["artifacts"]
    plan, parts = _prepare(case)
    plan_ref = artifacts.put_json(plan)
    for graph in case["successor_graphs"].values():
        artifacts.put_json(graph)
    for part in parts:
        assert artifacts.put_json(part.payload).content_hash == part.context_hash
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    app = _application(data_dir, store)
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/repository",
        candidate_scope_fingerprint=case["index"].scope_fingerprint,
        surface_enrichment_plan_ref=case["v4_ref"],
        surface_enrichment_v5_plan_ref=case["v5_ref"],
        surface_enrichment_v6_plan_ref=plan_ref,
        python_scope_certificate_ref=case["prior_v3"].scope_certificate_ref,
    )

    saved, contexts = app._saved_surface_enrichment_v6(run, identity, artifacts)

    assert saved == plan
    assert [(item.surface_id, item.context_id) for item in contexts] == [
        (part.surface_id, part.context_id) for part in parts
    ]


def test_saved_v6_dispatch_precedes_v5_without_replaying_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _saved_v3_case(tmp_path)
    identity = case["identity"]
    artifacts = case["artifacts"]
    plan, _ = _prepare(case)
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/repository",
        candidate_scope_fingerprint=case["index"].scope_fingerprint,
        surface_enrichment_plan_ref=case["v4_ref"],
        surface_enrichment_v5_plan_ref=case["v5_ref"],
        surface_enrichment_v6_plan_ref=artifacts.put_json(plan),
        python_scope_certificate_ref=case["prior_v3"].scope_certificate_ref,
    )
    app = _application(
        tmp_path / "artifacts", SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    )
    expected = SimpleAnalysisOutcome(
        identity=identity,
        display_analysis_id="A-001",
        status="PARTIAL",
        current_stage=SimpleStage.HYPOTHESIS_DONE,
    )
    observed: list[str] = []

    def saved_v6(
        *_args: object,
    ) -> tuple[dict[str, object], tuple[SurfaceContext, ...]]:
        observed.append("v6-plan")
        return plan, ()

    async def run_v6(*_args: object) -> SimpleAnalysisOutcome:
        observed.append("v6-run")
        return expected

    def forbidden_v5(*_args: object) -> NoReturn:
        raise AssertionError("saved v5 must not run once v6 is pinned")

    monkeypatch.setattr(app, "_saved_surface_enrichment_v6", saved_v6)
    monkeypatch.setattr(app, "_run_v6_surface_enrichment", run_v6, raising=False)
    monkeypatch.setattr(app, "_saved_surface_enrichment_v5", forbidden_v5)
    static = StaticBootstrapResult(
        repository_profile_ref=artifacts.put_json({"kind": "repository-profile"}),
        static_bundle_ref=artifacts.put_json({"kind": "static-bundle"}),
        workspace_path=tmp_path,
    )

    with pytest.raises(StopIteration) as done:
        app._run_candidate_pipeline(run, identity, static).send(None)

    assert done.value.value == expected
    assert observed == ["v6-plan", "v6-run"]


def test_completed_v6_replay_verifies_existing_certificate_without_rewrite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = _successor_case(tmp_path)
    case = data["case"]
    _save_v6_part(data)
    proof = _evaluate_v4(data)
    proof_ref = case.artifacts.put_json(proof.to_json())
    run = case.store.require_analysis_run(case.identity.analysis_id)
    assert run.candidate_terminal is not None
    counts = {
        status: sum(row.coverage_status == status for row in proof.surfaces)
        for status in ("COVERED", "UNCOVERED", "INSUFFICIENT")
    }
    completed = run.model_copy(
        update={
            "surface_enrichment_plan_ref": StoredDataRef.model_validate(
                data["plan"]["v4_plan_ref"]
            ),
            "python_scope_certificate_ref": proof.scope_certificate_ref,
            "candidate_scope_fingerprint": case.index.scope_fingerprint,
            "candidate_terminal": run.candidate_terminal.model_copy(
                update={
                    "surface_proof_version": 4,
                    "surface_coverage_hash": proof_ref.content_hash,
                    "surface_counts": counts,
                    "status": "COMPLETE" if proof.complete else "PARTIAL",
                    "pending_child_count": proof.pending_child_count,
                }
            ),
        }
    )
    case.store.save_analysis_run(completed)
    app = _application(tmp_path / "data", case.store)
    plan, contexts = app._saved_surface_enrichment_v6(
        completed, case.identity, case.artifacts
    )
    static = StaticBootstrapResult(
        repository_profile_ref=case.artifacts.put_json({"kind": "profile"}),
        static_bundle_ref=case.artifacts.put_json({"kind": "static-bundle"}),
        workspace_path=tmp_path,
    )
    verified: list[str] = []

    def verify_existing(
        _identity: CheckpointIdentity,
        _index: object,
        ref: StoredDataRef,
        _store: SimpleCheckpointStore,
        _artifacts: SimpleArtifactRepository,
    ) -> object:
        verified.append(ref.content_hash)
        return proof

    monkeypatch.setattr(
        "sastsimi.simple_runtime.application.verified_saved_coverage_v4",
        verify_existing,
    )

    with pytest.raises(StopIteration) as done:
        app._run_v6_surface_enrichment(
            completed, case.identity, static, case.artifacts, plan, contexts
        ).send(None)

    assert done.value.value.status == completed.candidate_terminal.status
    assert verified == [proof_ref.content_hash]
    assert case.store.require_analysis_run(case.identity.analysis_id) == completed


def test_v5_hold_review_scopes_deferred_projection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The app, not each marker, owns the final dashboard refresh."""
    identity = _identity()
    data_dir = tmp_path / "data"
    artifacts = SimpleArtifactRepository(data_dir, identity)
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    app = _application(data_dir, store)
    plan = {"kind": "simple_surface_enrichment_plan_v5", "child_checkpoint_hashes": {}}
    run = SimpleNamespace(surface_enrichment_v5_plan_ref=artifacts.put_json(plan))
    observed: list[str] = []

    @contextmanager
    def guard(analysis_id: str) -> Iterator[None]:
        observed.append(f"start:{analysis_id}")
        try:
            yield
        finally:
            observed.append(f"end:{analysis_id}")

    monkeypatch.setattr(store, "defer_surface_hold_projection", guard)
    app._review_v5_hold_children(
        run,  # type: ignore[arg-type]
        identity,
        SimpleNamespace(surfaces=()),  # type: ignore[arg-type]
        plan,
        (),
        {},
        artifacts,
    )
    assert observed == [
        f"start:{identity.analysis_id}",
        f"end:{identity.analysis_id}",
    ]


def test_v5_hold_review_releases_projection_scope_after_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = _identity()
    data_dir = tmp_path / "data"
    artifacts = SimpleArtifactRepository(data_dir, identity)
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    app = _application(data_dir, store)
    plan = {"kind": "simple_surface_enrichment_plan_v5", "child_checkpoint_hashes": {}}
    run = SimpleNamespace(surface_enrichment_v5_plan_ref=artifacts.put_json(plan))
    observed: list[str] = []

    @contextmanager
    def guard(analysis_id: str) -> Iterator[None]:
        observed.append(f"start:{analysis_id}")
        try:
            yield
        finally:
            observed.append(f"end:{analysis_id}")

    def fail(*_args: object) -> NoReturn:
        raise ValueError("review failed")

    monkeypatch.setattr(store, "defer_surface_hold_projection", guard)
    monkeypatch.setattr(app, "_record_v5_hold_children", fail)
    with pytest.raises(ValueError, match="review failed"):
        app._review_v5_hold_children(
            run,  # type: ignore[arg-type]
            identity,
            SimpleNamespace(surfaces=()),  # type: ignore[arg-type]
            plan,
            (),
            {},
            artifacts,
        )
    assert observed == [
        f"start:{identity.analysis_id}",
        f"end:{identity.analysis_id}",
    ]


def test_old_run_round_trips_without_v5_ref() -> None:
    identity = _identity()
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/repository",
    )
    old = run.model_dump(mode="json")
    old.pop("surface_enrichment_v5_plan_ref", None)
    restored = SimpleAnalysisRun.model_validate_json(json.dumps(old))
    assert restored.surface_enrichment_v5_plan_ref is None


def test_v5_ref_requires_existing_v4_and_certificate(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    v4_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v4"})
    v5_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v5"})
    certificate_ref = artifacts.put_json({"kind": "scope-certificate"})
    base = dict(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/repository",
        surface_enrichment_v5_plan_ref=v5_ref,
    )
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V5_STATE_UNBOUND"):
        SimpleAnalysisRun.model_validate(base)
    run = SimpleAnalysisRun.model_validate(
        {
            **base,
            "surface_enrichment_plan_ref": v4_ref,
            "python_scope_certificate_ref": certificate_ref,
        }
    )
    restored = SimpleAnalysisRun.model_validate_json(run.model_dump_json())
    assert restored.surface_enrichment_v5_plan_ref == v5_ref
    assert restored.surface_enrichment_plan_ref == v4_ref


def test_v6_successor_ref_requires_existing_v5_chain(tmp_path: Path) -> None:
    identity = _identity()
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    v4_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v4"})
    v5_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v5"})
    v6_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v6"})
    certificate_ref = artifacts.put_json({"kind": "scope-certificate"})
    base = dict(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/repository",
        surface_enrichment_plan_ref=v4_ref,
        python_scope_certificate_ref=certificate_ref,
        surface_enrichment_v6_plan_ref=v6_ref,
    )
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V6_STATE_UNBOUND"):
        SimpleAnalysisRun.model_validate(base)
    restored = SimpleAnalysisRun.model_validate_json(
        SimpleAnalysisRun.model_validate(
            {**base, "surface_enrichment_v5_plan_ref": v5_ref}
        ).model_dump_json()
    )
    assert restored.surface_enrichment_v6_plan_ref == v6_ref
    assert restored.surface_enrichment_v5_plan_ref == v5_ref


@pytest.mark.parametrize("legacy_json", [False, True])
def test_v6_plan_pin_preserves_parent_run_and_rejects_stale_writer(
    tmp_path: Path,
    legacy_json: bool,
) -> None:
    identity = _identity()
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    v4_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v4"})
    v5_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v5"})
    v6_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v6"})
    other_ref = artifacts.put_json(
        {"kind": "simple_surface_enrichment_plan_v6", "other": True}
    )
    certificate_ref = artifacts.put_json({"kind": "scope-certificate"})
    terminal = CandidateTerminal(
        status="PARTIAL",
        bundle_hash="b" * 64,
        scope_fingerprint="f" * 64,
        decision_counts={},
        deep_counts={},
        hypothesis_count=0,
        surface_proof_version=3,
        surface_index_hash="i" * 64,
        surface_coverage_hash="c" * 64,
        scope_certificate_hash=certificate_ref.content_hash,
    )
    parent = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/repository",
        surface_enrichment_plan_ref=v4_ref,
        surface_enrichment_v5_plan_ref=v5_ref,
        python_scope_certificate_ref=certificate_ref,
        candidate_terminal=terminal,
    )
    store.save_analysis_run(parent)
    if legacy_json:
        # Existing analyses predate the optional v6 field. Their stored JSON
        # can omit it even though parsing supplies the current None default.
        with store._connect() as connection:
            connection.execute(
                "UPDATE simple_analysis_runs SET run_json = ? WHERE analysis_id = ?",
                (
                    json.dumps(
                        parent.model_dump(
                            mode="json",
                            exclude={"surface_enrichment_v6_plan_ref"},
                        )
                    ),
                    parent.analysis_id,
                ),
            )

    assert store.pin_surface_enrichment_v6_plan(parent, v6_ref)
    saved = store.require_analysis_run(identity.analysis_id)
    assert saved.surface_enrichment_v6_plan_ref == v6_ref
    assert saved.candidate_terminal == terminal
    assert saved.surface_enrichment_v5_plan_ref == v5_ref
    assert not store.pin_surface_enrichment_v6_plan(parent, v6_ref)
    with pytest.raises(ValueError, match="SURFACE_ENRICHMENT_V6_PIN_STALE"):
        store.pin_surface_enrichment_v6_plan(parent, other_ref)


def test_v6_result_kind_requires_complete_pinned_successor_marker() -> None:
    ordinary = {"kind": "simple_surface_context_v5"}
    successor = {
        **ordinary,
        "prior_v3_coverage_hash": "a" * 64,
        "prior_v5_plan_hash": "b" * 64,
        "graph_semantics_revision": "v5-source-bound-3",
    }
    assert SimpleAnalysisApplication._surface_result_kind(ordinary) == (
        "simple_surface_hypothesis_result_v5"
    )
    assert SimpleAnalysisApplication._surface_result_kind(successor) == (
        "simple_surface_hypothesis_result_v6"
    )
    with pytest.raises(ValueError, match="SURFACE_EXPLORATION_RESULT_INVALID"):
        SimpleAnalysisApplication._surface_result_kind(
            {**ordinary, "prior_v3_coverage_hash": "a" * 64}
        )
    with pytest.raises(ValueError, match="SURFACE_EXPLORATION_RESULT_INVALID"):
        SimpleAnalysisApplication._surface_result_kind(
            {**successor, "prior_v5_plan_hash": "not-a-hash"}
        )


def test_terminal_accepts_additive_v4_surface_certificate() -> None:
    terminal = CandidateTerminal(
        status="PARTIAL",
        bundle_hash="b" * 64,
        scope_fingerprint="f" * 64,
        decision_counts={},
        deep_counts={},
        hypothesis_count=0,
        surface_proof_version=4,
        surface_index_hash="i" * 64,
        surface_coverage_hash="c" * 64,
        scope_certificate_hash="s" * 64,
    )
    assert (
        CandidateTerminal.model_validate_json(
            terminal.model_dump_json()
        ).surface_proof_version
        == 4
    )


def test_explicit_enrichment_routes_saved_v3_partial_to_v6_successor(
    tmp_path: Path,
) -> None:
    identity = _identity()
    data_dir = tmp_path / "data"
    artifacts = SimpleArtifactRepository(data_dir, identity)
    v4_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v4"})
    v5_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v5"})
    certificate_ref = artifacts.put_json({"kind": "scope-certificate"})
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/repository",
        surface_enrichment_plan_ref=v4_ref,
        surface_enrichment_v5_plan_ref=v5_ref,
        python_scope_certificate_ref=certificate_ref,
        candidate_terminal=CandidateTerminal(
            status="PARTIAL",
            bundle_hash="b" * 64,
            scope_fingerprint="f" * 64,
            decision_counts={},
            deep_counts={},
            hypothesis_count=0,
            surface_proof_version=3,
            surface_index_hash="i" * 64,
            surface_coverage_hash="c" * 64,
            scope_certificate_hash=certificate_ref.content_hash,
        ),
    )
    assert SimpleAnalysisApplication._surface_enrichment_round(run) == "v6"
    terminal = run.candidate_terminal
    assert terminal is not None
    assert (
        SimpleAnalysisApplication._surface_enrichment_round(
            run.model_copy(
                update={
                    "candidate_terminal": terminal.model_copy(
                        update={"surface_proof_version": 2}
                    )
                }
            )
        )
        == "v5"
    )


def test_explicit_saved_v3_preparation_calls_successor_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = _identity()
    data_dir = tmp_path / "data"
    artifacts = SimpleArtifactRepository(data_dir, identity)
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    app = _application(data_dir, store)
    v4_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v4"})
    v5_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v5"})
    certificate_ref = artifacts.put_json({"kind": "scope-certificate"})
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/repository",
        surface_enrichment_plan_ref=v4_ref,
        surface_enrichment_v5_plan_ref=v5_ref,
        python_scope_certificate_ref=certificate_ref,
        candidate_terminal=CandidateTerminal(
            status="PARTIAL",
            bundle_hash="b" * 64,
            scope_fingerprint="f" * 64,
            decision_counts={},
            deep_counts={},
            hypothesis_count=0,
            surface_proof_version=3,
            surface_index_hash="i" * 64,
            surface_coverage_hash="c" * 64,
            scope_certificate_hash=certificate_ref.content_hash,
        ),
    )
    store.save_analysis_run(run)
    observed: list[str] = []

    async def verified_scope(*_args: object) -> None:
        observed.append("scope")

    def prepared(*_args: object) -> None:
        observed.append("v6")

    def forbidden(*_args: object) -> NoReturn:
        raise AssertionError("saved v5 must not be treated as final")

    monkeypatch.setattr(app, "_assert_completed_static_scope", verified_scope)
    monkeypatch.setattr(app, "_prepare_v6_surface_enrichment", prepared)
    monkeypatch.setattr(app, "_saved_surface_enrichment_v5", forbidden)
    with pytest.raises(StopIteration):
        app._prepare_surface_enrichment_locked(identity.analysis_id).send(None)
    assert observed == ["scope", "v6"]


def test_v5_preparation_pins_plan_without_rewriting_v4(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _case(tmp_path)
    identity = case["identity"]
    data_dir = tmp_path / "artifacts"
    artifacts = SimpleArtifactRepository(data_dir, identity)
    ast_summary: dict[str, list[object]] = {"files": []}
    static_ref = artifacts.put_json({"ast_summary": ast_summary})
    index = replace(
        case["index"],
        static_bundle_hash=static_ref.content_hash,
        ast_manifest_hash=hashlib.sha256(canonical_bytes(ast_summary)).hexdigest(),
    )
    index_ref = artifacts.put_json(index.to_json())
    prior = replace(
        case["prior"],
        static_bundle_hash=static_ref.content_hash,
        ast_manifest_hash=index.ast_manifest_hash,
        index_hash=index_ref.content_hash,
    )
    prior_ref = artifacts.put_json(prior.to_json())
    v4_plan = {
        **case["v4_plan"],
        "static_bundle_ref": static_ref.model_dump(mode="json"),
        "index_ref": index_ref.model_dump(mode="json"),
        "index_hash": index_ref.content_hash,
        "ast_manifest_hash": index.ast_manifest_hash,
    }
    v4_ref = artifacts.put_json(v4_plan)
    graph = {
        **case["graphs"]["surface-missing"],
        "index_hash": index_ref.content_hash,
        "ast_manifest_hash": index.ast_manifest_hash,
    }
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/repository",
        candidate_pipeline_version=2,
        workspace_path=tmp_path,
        candidate_scope_fingerprint=index.scope_fingerprint,
        repository_profile_ref=artifacts.put_json({"kind": "profile"}),
        static_bundle_ref=static_ref,
        static_coverage_ref=artifacts.put_json({"kind": "static-coverage"}),
        candidate_terminal=CandidateTerminal(
            status="PARTIAL",
            bundle_hash=static_ref.content_hash,
            scope_fingerprint=index.scope_fingerprint,
            decision_counts={},
            deep_counts={},
            hypothesis_count=0,
            surface_index_hash=index_ref.content_hash,
            surface_coverage_hash=prior_ref.content_hash,
            scope_certificate_hash=prior.scope_certificate_ref.content_hash,
            surface_proof_version=2,
        ),
        surface_enrichment_plan_ref=v4_ref,
        python_scope_certificate_ref=prior.scope_certificate_ref,
    )
    store.save_analysis_run(run)
    root = store.mark_running(
        identity, SimpleStage.HYPOTHESIS_DONE, (static_ref,), attempt_id="old"
    )
    store.complete(root, StageResult(output_refs=(index_ref, prior_ref)))
    app = _application(data_dir, store)
    monkeypatch.setattr(
        "sastsimi.simple_runtime.application.read_saved_coverage_v2",
        lambda *_: prior,
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.application.index_ast_manifest",
        lambda *_: {"app.py": {"source_sha256": "b" * 64}},
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.application._related_child_ids",
        lambda *_: set(),
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.application.discover_operational_route_maps",
        lambda *_: SimpleNamespace(bindings=(), gaps=()),
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.application.build_python_call_path_index",
        lambda *_: None,
    )
    verified_routes = object()
    monkeypatch.setattr(
        "sastsimi.simple_runtime.application.verify_operational_routes_v5",
        lambda *_: verified_routes,
        raising=False,
    )
    seen_routes: list[object] = []

    def captured_graph(*_args: object, **kwargs: object) -> dict[str, object]:
        seen_routes.append(kwargs.get("verified_routes"))
        return graph

    monkeypatch.setattr(
        "sastsimi.simple_runtime.application.extract_surface_graph_v5",
        captured_graph,
    )
    app._prepare_v5_surface_enrichment(run, identity, artifacts)
    assert seen_routes == [verified_routes]
    saved = store.require_analysis_run(identity.analysis_id)
    assert saved.surface_enrichment_plan_ref == v4_ref
    assert saved.surface_enrichment_v5_plan_ref is not None
    plan = json.loads(artifacts.read(saved.surface_enrichment_v5_plan_ref))
    assert plan["target_surface_ids"] == ["surface-missing"]
    assert len(plan["expected_parts"]) == 1
    assert app._saved_surface_enrichment_v5(saved, identity, artifacts)[0] == plan


def test_version_three_terminal_does_not_change_old_default() -> None:
    base = dict(
        status="PARTIAL",
        bundle_hash="1" * 64,
        scope_fingerprint="2" * 64,
        decision_counts={},
        deep_counts={},
        hypothesis_count=0,
    )
    old = CandidateTerminal.model_validate(base)
    new = CandidateTerminal.model_validate({**base, "surface_proof_version": 3})
    assert old.surface_proof_version == 1
    assert (
        CandidateTerminal.model_validate_json(
            new.model_dump_json()
        ).surface_proof_version
        == 3
    )


@pytest.mark.asyncio
async def test_saved_v5_route_never_recomputes_v4_after_v5_progress(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity = _identity()
    data_dir = tmp_path / "data"
    artifacts = SimpleArtifactRepository(data_dir, identity)
    profile_ref = artifacts.put_json({"kind": "profile"})
    static_ref = artifacts.put_json({"kind": "static-bundle"})
    v4_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v4"})
    v5_ref = artifacts.put_json({"kind": "simple_surface_enrichment_plan_v5"})
    certificate_ref = artifacts.put_json({"kind": "scope-certificate"})
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/repository",
        candidate_pipeline_version=2,
        surface_enrichment_plan_ref=v4_ref,
        surface_enrichment_v5_plan_ref=v5_ref,
        python_scope_certificate_ref=certificate_ref,
    )
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    application = _application(data_dir, store)
    static = StaticBootstrapResult(
        repository_profile_ref=profile_ref,
        static_bundle_ref=static_ref,
        workspace_path=tmp_path,
    )
    expected = SimpleAnalysisOutcome(
        identity=identity,
        display_analysis_id="A-001",
        status="PARTIAL",
        current_stage=SimpleStage.HYPOTHESIS_DONE,
    )

    def never_v4(*_: object) -> None:
        raise AssertionError("v4 recomputation must not receive v5 progress")

    def saved_v5(*_: object) -> tuple[dict[str, object], tuple[object, ...]]:
        return {"kind": "simple_surface_enrichment_plan_v5"}, ()

    async def run_v5(*_: object) -> SimpleAnalysisOutcome:
        return expected

    monkeypatch.setattr(application, "_saved_surface_enrichment", never_v4)
    monkeypatch.setattr(
        application, "_saved_surface_enrichment_v5", saved_v5, raising=False
    )
    monkeypatch.setattr(
        application, "_run_v5_surface_enrichment", run_v5, raising=False
    )

    assert await application._run_candidate_pipeline(run, identity, static) == expected


def test_v5_progress_commits_atomically_and_replays_idempotently(
    tmp_path: Path,
) -> None:
    identity = _identity()
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    store = SimpleCheckpointStore(tmp_path / "ledger.sqlite3")
    context_ref = artifacts.put_json({"kind": "simple_surface_context_v5"})
    result_ref = artifacts.put_json({"kind": "simple_surface_hypothesis_result_v5"})

    assert _commit(store, identity, result_ref, context_ref, (), proposal_version=5)
    progress = store.list_surface_exploration_progress(identity, "scope-v4")
    assert progress[("surface-v4", "surface-v4:part-0")].proposal_version == 5
    assert not _commit(store, identity, result_ref, context_ref, (), proposal_version=5)


def test_saved_v5_plan_reads_only_pinned_parts_without_v4_replanning(
    tmp_path: Path,
) -> None:
    case = _case(tmp_path)
    identity = case["identity"]
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", identity)
    plan, parts = prepare_surface_enrichment_v5(
        identity,
        "candidate",
        case["index"],
        case["index_ref"],
        case["v4_ref"],
        case["prior_ref"],
        case["prior"],
        case["progress"],
        case["graphs"],
        v4_plan=case["v4_plan"],
        child_checkpoint_hashes={},
    )
    plan_ref = artifacts.put_json(plan)
    for graph in case["graphs"].values():
        artifacts.put_json(graph)
    for part in parts:
        assert artifacts.put_json(part.payload).content_hash == part.context_hash
    certificate_ref = artifacts.put_json({"kind": "scope-certificate"})
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/repository",
        candidate_pipeline_version=2,
        candidate_scope_fingerprint=case["index"].scope_fingerprint,
        surface_enrichment_plan_ref=case["v4_ref"],
        surface_enrichment_v5_plan_ref=plan_ref,
        python_scope_certificate_ref=certificate_ref,
    )
    data_dir = tmp_path / "data"
    app = _application(
        data_dir, SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    )

    saved_plan, contexts = app._saved_surface_enrichment_v5(run, identity, artifacts)
    assert saved_plan == plan
    assert [(context.surface_id, context.context_id) for context in contexts] == [
        (part.surface_id, part.context_id) for part in parts
    ]


def test_v5_saved_agent_response_is_revalidated_not_trusted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _case(tmp_path)
    artifacts = SimpleArtifactRepository(tmp_path / "artifacts", case["identity"])
    plan, parts = prepare_surface_enrichment_v5(
        case["identity"],
        "candidate",
        case["index"],
        case["index_ref"],
        case["v4_ref"],
        case["prior_ref"],
        case["prior"],
        case["progress"],
        case["graphs"],
        v4_plan=case["v4_plan"],
        child_checkpoint_hashes={},
    )
    part = parts[0]
    context_ref = artifacts.put_json(part.payload)
    graph_payload = case["graphs"][part.surface_id]
    graph_ref = artifacts.put_json(graph_payload)
    context = SurfaceContext(
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
    response = {
        "surface_id": context.surface_id,
        "context_id": context.context_id,
        "status": "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
        "reason": "No verified request to sink path is present.",
        "hypotheses": [],
        "review_evidence": [],
    }
    checked = validate_v5_response(
        {
            "context_payload": part.payload,
            "graph_payload": graph_payload,
            "context_hash": part.context_hash,
            "context_id": part.context_id,
        },
        response,
    )
    result = {
        "kind": "simple_surface_hypothesis_result_v5",
        "analysis_id": case["identity"].analysis_id,
        "surface_id": context.surface_id,
        "context_id": context.context_id,
        "part_index": context.part_index,
        "part_count": context.part_count,
        "context_hash": context.context_hash,
        "static_bundle_hash": case["index"].static_bundle_hash,
        "status": checked.status,
        "reason": checked.reason,
        "reviewed_parts": sorted(checked.reviewed_parts),
        "evidence_locations": list(checked.evidence_locations),
        "verified_roles": list(checked.verified_roles),
        "verified_path_id": checked.verified_path_id,
        "graph_hash": graph_ref.content_hash,
        "graph_ref": graph_ref.model_dump(mode="json"),
        "seed_ids": [],
        "response": response,
        "validation_status": "VALID",
    }
    result_ref = artifacts.put_json(result)
    SimpleAnalysisApplication._surface_result_valid(
        artifacts,
        context,
        checked.status,
        result_ref,
        case["index"].static_bundle_hash,
        analysis_id=case["identity"].analysis_id,
        expected_seed_ids=(),
    )
    forged = dict(result, verified_path_id="forged-path")
    with pytest.raises(ValueError, match="SURFACE_EXPLORATION_RESULT_INVALID"):
        SimpleAnalysisApplication._surface_result_valid(
            artifacts,
            context,
            checked.status,
            artifacts.put_json(forged),
            case["index"].static_bundle_hash,
            analysis_id=case["identity"].analysis_id,
            expected_seed_ids=(),
        )

    hold_identity = case["identity"].model_copy(
        update={"hypothesis_id": "hypothesis-hold"}
    )
    hold = StageCheckpoint(
        identity=hold_identity,
        stage=SimpleStage.VERIFICATION_INITIAL_DONE,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        verdict="HOLD",
    )
    record = SurfaceExplorationProgressRecord(
        surface_id=context.surface_id,
        context_id=context.context_id,
        static_bundle_hash=case["index"].static_bundle_hash,
        index_hash=case["index_ref"].content_hash,
        context_hash=context.context_hash,
        source_sha256=context.source_sha256,
        status=checked.status,
        result_ref=result_ref,
        hypothesis_ids=(),
        proposal_version=5,
    )
    store = SimpleCheckpointStore(tmp_path / "review.sqlite3")
    captured: list[dict[str, object]] = []

    def record_review(*_args: object, **kwargs: object) -> None:
        captured.append(kwargs)

    monkeypatch.setattr(
        store, "get", lambda _child, stage: hold if stage is hold.stage else None
    )
    monkeypatch.setattr(store, "prepare_surface_hold_replay", record_review)
    monkeypatch.setattr(
        "sastsimi.simple_runtime.application._related_child_ids",
        lambda *_: {"hypothesis-hold"},
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.application.evaluate_v5_hold_replay_signal",
        lambda *_args, **kwargs: SimpleNamespace(
            decision=SimpleNamespace(action="KEEP_HOLD"),
            review_plan_ref=kwargs["plan_ref"],
            review_context_ref=kwargs["context_ref"],
            review_result_ref=result_ref,
        ),
    )
    app = _application(tmp_path / "artifacts", store)
    plan = {**plan, "child_checkpoint_hashes": {"hypothesis-hold": "1" * 64}}
    plan_ref = artifacts.put_json(plan)
    app._review_v5_hold_children(
        SimpleNamespace(surface_enrichment_v5_plan_ref=plan_ref),  # type: ignore[arg-type]
        case["identity"],
        case["index"],
        plan,
        (context,),
        {(context.surface_id, context.context_id): record},
        artifacts,
    )
    assert captured == [
        {
            "review_plan_ref": plan_ref,
            "review_context_ref": context_ref,
            "review_result_ref": result_ref,
        }
    ]
    app._review_v5_hold_children(
        SimpleNamespace(surface_enrichment_v5_plan_ref=plan_ref),  # type: ignore[arg-type]
        case["identity"],
        case["index"],
        {**plan, "child_checkpoint_hashes": {}},
        (context,),
        {(context.surface_id, context.context_id): record},
        artifacts,
    )
    assert len(captured) == 1


@pytest.mark.asyncio
async def test_v5_resume_reuses_completed_part_without_agent_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _case(tmp_path)
    identity = case["identity"]
    data_dir = tmp_path / "artifacts"
    artifacts = SimpleArtifactRepository(data_dir, identity)
    plan, parts = prepare_surface_enrichment_v5(
        identity,
        "candidate",
        case["index"],
        case["index_ref"],
        case["v4_ref"],
        case["prior_ref"],
        case["prior"],
        case["progress"],
        case["graphs"],
        v4_plan=case["v4_plan"],
        child_checkpoint_hashes={},
    )
    part = parts[0]
    context_ref = artifacts.put_json(part.payload)
    graph_ref = artifacts.put_json(case["graphs"][part.surface_id])
    context = SurfaceContext(
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
    response = {
        "surface_id": context.surface_id,
        "context_id": context.context_id,
        "status": "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
        "reason": "The graph has no verified request-to-sink path.",
        "hypotheses": [],
        "review_evidence": [],
    }
    checked = validate_v5_response(
        {
            "context_payload": part.payload,
            "graph_payload": case["graphs"][part.surface_id],
            "context_hash": part.context_hash,
            "context_id": part.context_id,
        },
        response,
    )
    result_ref = artifacts.put_json(
        {
            "kind": "simple_surface_hypothesis_result_v5",
            "analysis_id": identity.analysis_id,
            "surface_id": context.surface_id,
            "context_id": context.context_id,
            "part_index": context.part_index,
            "part_count": context.part_count,
            "context_hash": context.context_hash,
            "static_bundle_hash": case["index"].static_bundle_hash,
            "status": checked.status,
            "reason": checked.reason,
            "reviewed_parts": sorted(checked.reviewed_parts),
            "evidence_locations": list(checked.evidence_locations),
            "verified_roles": list(checked.verified_roles),
            "verified_path_id": checked.verified_path_id,
            "graph_hash": graph_ref.content_hash,
            "graph_ref": graph_ref.model_dump(mode="json"),
            "seed_ids": [],
            "response": response,
            "validation_status": "VALID",
        }
    )
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    store.commit_surface_exploration(
        identity,
        case["index"].scope_fingerprint,
        context.surface_id,
        context.context_id,
        static_bundle_hash=case["index"].static_bundle_hash,
        index_hash=case["index_ref"].content_hash,
        context_hash=context.context_hash,
        source_sha256=context.source_sha256,
        status=checked.status,
        result_ref=result_ref,
        registrations=(),
        proposal_version=5,
    )
    static_ref = StoredDataRef.model_validate(case["v4_plan"]["static_bundle_ref"])
    certificate_ref = artifacts.put_json({"kind": "scope-certificate"})
    plan_ref = artifacts.put_json(plan)
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/repository",
        candidate_pipeline_version=2,
        candidate_scope_fingerprint=case["index"].scope_fingerprint,
        candidate_terminal=CandidateTerminal(
            status="PARTIAL",
            bundle_hash=static_ref.content_hash,
            scope_fingerprint=case["index"].scope_fingerprint,
            decision_counts={},
            deep_counts={},
            hypothesis_count=0,
            surface_index_hash=case["index_ref"].content_hash,
            surface_coverage_hash=case["prior_ref"].content_hash,
            surface_proof_version=2,
        ),
        surface_enrichment_plan_ref=case["v4_ref"],
        surface_enrichment_v5_plan_ref=plan_ref,
        python_scope_certificate_ref=certificate_ref,
    )
    store.save_analysis_run(run)
    root = store.mark_running(
        identity, SimpleStage.HYPOTHESIS_DONE, (static_ref,), attempt_id="old"
    )
    store.complete(
        root, StageResult(output_refs=(case["index_ref"], case["prior_ref"]))
    )
    app = _application(data_dir, store)
    calls = 0

    class Agent:
        async def propose_surface(self, *_: object) -> None:
            nonlocal calls
            calls += 1
            raise AssertionError("completed v5 part must not be requested again")

    monkeypatch.setattr(app, "_candidate_hypotheses", Agent())
    proof = SimpleNamespace(
        complete=False,
        pending_candidate_count=0,
        pending_child_count=0,
        surfaces=(SimpleNamespace(coverage_status="INSUFFICIENT"),),
        scope_certificate_ref=certificate_ref,
        to_json=lambda: {
            "kind": "simple_attack_surface_coverage_v3",
            "complete": False,
        },
    )
    proof_calls = 0
    plan_checks = 0
    review_calls = 0

    def certify_only_after_drain(*_: object) -> SimpleNamespace:
        nonlocal proof_calls
        proof_calls += 1
        assert review_calls == 1
        if proof_calls > 1:
            raise AssertionError("full certification ran before child drain")
        return proof

    def check_plan_before_drain(*_: object) -> None:
        nonlocal plan_checks
        plan_checks += 1

    def review_hold_after_drain(*_: object) -> None:
        nonlocal review_calls
        assert plan_checks == 1
        review_calls += 1

    monkeypatch.setattr(
        "sastsimi.simple_runtime.application.evaluate_surface_coverage_v3",
        certify_only_after_drain,
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.application.validate_surface_plan_v5",
        check_plan_before_drain,
        raising=False,
    )
    monkeypatch.setattr(
        "sastsimi.simple_runtime.application.read_saved_coverage_v2",
        lambda *_: case["prior"],
    )
    monkeypatch.setattr(
        app,
        "_review_v5_hold_children",
        review_hold_after_drain,
        raising=False,
    )
    static = StaticBootstrapResult(
        repository_profile_ref=static_ref,
        static_bundle_ref=static_ref,
        workspace_path=tmp_path,
    )

    outcome = await app._run_v5_surface_enrichment(
        run, identity, static, artifacts, plan, (context,)
    )
    assert outcome.status == "PARTIAL"
    assert calls == 0
    assert plan_checks == 1
    assert review_calls == 1
    assert proof_calls == 1
    terminal = store.require_analysis_run(identity.analysis_id).candidate_terminal
    assert terminal is not None
    assert terminal.surface_proof_version == 3


@pytest.mark.asyncio
async def test_explicit_enrichment_routes_v2_terminal_to_v5_not_v4(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _case(tmp_path)
    identity = case["identity"]
    data_dir = tmp_path / "artifacts"
    artifacts = SimpleArtifactRepository(data_dir, identity)
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    static_ref = StoredDataRef.model_validate(case["v4_plan"]["static_bundle_ref"])
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="https://example.invalid/repository",
        candidate_pipeline_version=2,
        candidate_scope_fingerprint=case["index"].scope_fingerprint,
        candidate_terminal=CandidateTerminal(
            status="PARTIAL",
            bundle_hash=static_ref.content_hash,
            scope_fingerprint=case["index"].scope_fingerprint,
            decision_counts={},
            deep_counts={},
            hypothesis_count=0,
            surface_index_hash=case["index_ref"].content_hash,
            surface_coverage_hash=case["prior_ref"].content_hash,
            surface_proof_version=2,
        ),
        surface_enrichment_plan_ref=case["v4_ref"],
        python_scope_certificate_ref=artifacts.put_json({"kind": "certificate"}),
    )
    store.save_analysis_run(run)
    app = _application(data_dir, store)
    visited: list[str] = []

    async def accepted_scope(*_: object) -> None:
        return None

    def prepare_v5(*_: object) -> None:
        visited.append("v5")

    def reject_v4(*_: object) -> None:
        raise AssertionError("v4 plan must not be recalculated")

    monkeypatch.setattr(app, "_assert_completed_static_scope", accepted_scope)
    monkeypatch.setattr(
        app, "_prepare_v5_surface_enrichment", prepare_v5, raising=False
    )
    monkeypatch.setattr(app, "_calculate_saved_surface_enrichment", reject_v4)
    await app._prepare_surface_enrichment_locked(identity.analysis_id)
    assert visited == ["v5"]
