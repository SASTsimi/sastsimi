"""A pinned V11 successor resumes before the historical V10 path."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import cast

import pytest

from sastsimi.simple_runtime.application import (
    SimpleAnalysisApplication,
    SimpleAnalysisOutcome,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.models import (
    CandidateTerminal,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_child_evidence_v11 import (
    collect_child_hold_targets_v11,
)
from sastsimi.simple_runtime.surface_coverage_v2 import _ref
from sastsimi.simple_runtime.surface_enrichment_v11 import (
    prepare_surface_enrichment_v11,
)
from tests.unit.simple_runtime.test_surface_v10_read import _saved_v10_case


def test_pinned_v11_resume_does_not_replay_v10(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    plan_ref = _ref(identity, "b" * 64)
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="owner/repo",
    ).model_copy(
        update={
            "surface_enrichment_v11_plan_ref": plan_ref,
            "candidate_terminal": CandidateTerminal(
                status="PARTIAL",
                bundle_hash="c" * 64,
                scope_fingerprint="d" * 64,
                decision_counts={},
                deep_counts={},
                hypothesis_count=0,
                surface_proof_version=8,
                producer_finished=True,
            ),
        }
    )
    app = object.__new__(SimpleAnalysisApplication)
    app._data_dir = tmp_path
    calls: list[str] = []

    class Store:
        def clear_stale_hypothesis_claims(self, root: CheckpointIdentity) -> None:
            assert root == identity
            calls.append("clear-claims")

    app._store = cast(SimpleCheckpointStore, Store())
    expected = SimpleAnalysisOutcome(
        identity=identity,
        display_analysis_id=run.display_analysis_id,
        status="PARTIAL",
        current_stage=SimpleStage.HYPOTHESIS_DONE,
    )

    async def v11(*_args: object) -> SimpleAnalysisOutcome:
        calls.append("v11")
        return expected

    async def v10(*_args: object) -> SimpleAnalysisOutcome:
        calls.append("v10")
        return expected

    monkeypatch.setattr(app, "_run_v11_surface_enrichment", v11, raising=False)
    monkeypatch.setattr(app, "_run_v10_surface_enrichment", v10)
    monkeypatch.setattr(app, "_v4_failure_outcome", lambda _run, outcome: outcome)
    static = StaticBootstrapResult(
        repository_profile_ref=plan_ref,
        static_bundle_ref=plan_ref,
        workspace_path=tmp_path,
    )

    assert asyncio.run(app._run_candidate_pipeline(run, identity, static)) == expected
    assert calls == ["clear-claims", "v11"]


def test_blocked_v11_preflight_reactivates_only_through_store_cas(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    plan_ref = _ref(identity, "b" * 64)
    blocked = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="owner/repo",
    ).model_copy(
        update={
            "surface_enrichment_v11_plan_ref": plan_ref,
            "surface_enrichment_status": "BLOCKED",
            "candidate_terminal": CandidateTerminal(
                status="PARTIAL",
                bundle_hash="c" * 64,
                scope_fingerprint="d" * 64,
                decision_counts={},
                deep_counts={},
                hypothesis_count=0,
                surface_proof_version=8,
                producer_finished=True,
            ),
        }
    )
    running = blocked.model_copy(update={"surface_enrichment_status": "RUNNING"})
    calls: list[str] = []

    class Store:
        def clear_stale_hypothesis_claims(self, root: CheckpointIdentity) -> None:
            assert root == identity
            calls.append("clear-claims")

        def resume_surface_enrichment_v11_if_safe(
            self, run: SimpleAnalysisRun, ref: object
        ) -> bool:
            assert run == blocked and ref == plan_ref
            calls.append("cas")
            return True

        def require_analysis_run(self, analysis_id: str) -> SimpleAnalysisRun:
            assert analysis_id == identity.analysis_id
            return running

    app = object.__new__(SimpleAnalysisApplication)
    app._data_dir = tmp_path
    app._store = cast(SimpleCheckpointStore, Store())
    expected = SimpleAnalysisOutcome(
        identity=identity,
        display_analysis_id="A-001",
        status="PARTIAL",
        current_stage=SimpleStage.HYPOTHESIS_DONE,
    )

    async def v11(run: SimpleAnalysisRun, *_args: object) -> SimpleAnalysisOutcome:
        assert run == running
        calls.append("v11")
        return expected

    monkeypatch.setattr(app, "_run_v11_surface_enrichment", v11, raising=False)
    monkeypatch.setattr(app, "_v4_failure_outcome", lambda _run, outcome: outcome)
    static = StaticBootstrapResult(
        repository_profile_ref=plan_ref,
        static_bundle_ref=plan_ref,
        workspace_path=tmp_path,
    )
    assert (
        asyncio.run(app._run_candidate_pipeline(blocked, identity, static)) == expected
    )
    assert calls == ["clear-claims", "cas", "v11"]


def test_v11_failure_uses_latest_run_not_stale_pre_promotion_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    ref = _ref(identity, "b" * 64)
    old = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="owner/repo",
    ).model_copy(
        update={
            "surface_enrichment_v11_plan_ref": ref,
            "surface_enrichment_status": "RUNNING",
        }
    )
    promoted = old.model_copy(update={"surface_enrichment_status": "PARTIAL"})

    class Store:
        def clear_stale_hypothesis_claims(self, root: CheckpointIdentity) -> None:
            assert root == identity

        def require_analysis_run(self, analysis_id: str) -> SimpleAnalysisRun:
            assert analysis_id == identity.analysis_id
            return promoted

    app = object.__new__(SimpleAnalysisApplication)
    app._data_dir = tmp_path
    app._store = cast(SimpleCheckpointStore, Store())
    captured: list[SimpleAnalysisRun] = []

    async def failure(*_args: object) -> SimpleAnalysisOutcome:
        raise RuntimeError("projection failed after commit")

    def save_failure(
        run: SimpleAnalysisRun, outcome: SimpleAnalysisOutcome
    ) -> SimpleAnalysisOutcome:
        captured.append(run)
        return outcome

    monkeypatch.setattr(app, "_run_v11_surface_enrichment", failure, raising=False)
    monkeypatch.setattr(app, "_v4_failure_outcome", save_failure)
    static = StaticBootstrapResult(
        repository_profile_ref=ref,
        static_bundle_ref=ref,
        workspace_path=tmp_path,
    )
    result = asyncio.run(app._run_candidate_pipeline(old, identity, static))
    assert result.status == "BLOCKED"
    assert captured == [promoted]


def test_explicit_enrichment_after_v10_prepares_v11(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    identity = CheckpointIdentity(
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="a" * 40,
        hypothesis_id=None,
    )
    ref = _ref(identity, "b" * 64)
    run = SimpleAnalysisRun(
        analysis_id=identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        repository="owner/repo",
    ).model_copy(
        update={
            "surface_enrichment_v10_plan_ref": ref,
            "candidate_terminal": CandidateTerminal(
                status="PARTIAL",
                bundle_hash="c" * 64,
                scope_fingerprint="d" * 64,
                decision_counts={},
                deep_counts={},
                hypothesis_count=0,
                surface_proof_version=8,
                producer_finished=True,
            ),
        }
    )
    app = object.__new__(SimpleAnalysisApplication)
    app._data_dir = tmp_path
    app._store = type("Store", (), {"require_analysis_run": lambda self, _id: run})()
    calls: list[str] = []

    async def static_scope(_run: object, _identity: object) -> None:
        calls.append("static")

    def prepare_v11(_run: object, _identity: object, _artifacts: object) -> None:
        calls.append("v11")

    monkeypatch.setattr(app, "_assert_completed_static_scope", static_scope)
    monkeypatch.setattr(
        app, "_prepare_v11_surface_enrichment", prepare_v11, raising=False
    )
    asyncio.run(app._prepare_surface_enrichment_locked(identity.analysis_id))
    assert calls == ["static", "v11"]


def test_v11_replays_parent_and_promotes_only_verified_empty_child_set(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    case = _saved_v10_case(tmp_path, monkeypatch)
    identity = case["identity"]
    store = case["store"]
    artifacts = case["artifacts"]
    terminal = store.run.candidate_terminal
    root = store.get()
    v10_ref = store.run.surface_enrichment_v10_plan_ref
    assert terminal is not None and v10_ref is not None
    store.list_checkpoints = lambda *_args: (root,)
    targets, snapshot = collect_child_hold_targets_v11(
        identity, case["index"], case["progress"], cast(SimpleCheckpointStore, store)
    )
    assert not targets
    v10_plan = json.loads(artifacts.read(v10_ref))
    plan_ref = artifacts.put_json(
        prepare_surface_enrichment_v11(
            identity,
            case["coverage"],
            v10_ref,
            case["coverage_ref"],
            terminal,
            root,
            targets,
            snapshot,
            v10_plan["v9_progress_hash"],
        )
    )
    store.run = store.run.model_copy(
        update={
            "surface_enrichment_v11_plan_ref": plan_ref,
            "surface_enrichment_status": "RUNNING",
            "candidate_terminal": terminal.model_copy(update={"status": "PARTIAL"}),
        }
    )
    store.list_surface_child_revalidation_v11 = lambda *_args: {}
    store.require = lambda *_args: store.get()
    promoted: list[tuple[object, ...]] = []

    def promote(*args: object, **kwargs: object) -> bool:
        assert "readers" in kwargs
        promoted.append(args)
        return True

    store.promote_surface_enrichment_v11_coverage = promote
    app = object.__new__(SimpleAnalysisApplication)
    app._data_dir = artifacts.data_dir
    app._store = store
    app._runner_factory = lambda *_args: None  # type: ignore[assignment]
    static = StaticBootstrapResult(
        repository_profile_ref=store.run.static_bundle_ref,
        static_bundle_ref=store.run.static_bundle_ref,
        workspace_path=cast(Path, case["workspace"]),
    )

    outcome = asyncio.run(
        app._run_v11_surface_enrichment(store.run, identity, static, artifacts)
    )

    assert outcome.status in {"COMPLETE", "PARTIAL"}
    assert len(promoted) == 1
    assert promoted[0][0] == store.run
