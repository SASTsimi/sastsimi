"""RED contracts for replaying saved v2 AST/source gaps without rewriting evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import TypedDict, cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.application import (
    HypothesisBootstrap,
    SimpleAnalysisApplication,
    SimpleAnalysisRequest,
    StaticBootstrapResult,
)
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attack_surfaces import (
    ReviewPart,
    surface_index_from_json,
)
from sastsimi.simple_runtime.bootstrap_stages import SurfaceProposalResult
from sastsimi.simple_runtime.file_context import prepare_file_context
from sastsimi.simple_runtime.models import (
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_contexts import SurfaceContext, _surface_payload
from tests.unit.simple_runtime.test_candidate_pipeline import (
    _enable_chaining_pool,
    _SecondLookHypotheses,
    _setup,
    _Static,
)


class _CommitArguments(TypedDict):
    static_bundle_hash: str
    index_hash: str
    context_hash: str
    source_sha256: str | None
    status: str
    registrations: list[tuple[str, StoredDataRef, StageCheckpoint]]
    proposal_version: int


def _identity(hypothesis_id: str | None = None) -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="supplement-analysis",
        workspace_id="supplement-workspace",
        commit_id="a" * 40,
        hypothesis_id=hypothesis_id,
    )


def _saved_report(
    store: SimpleCheckpointStore,
    artifacts: SimpleArtifactRepository,
    number: int,
) -> StageCheckpoint:
    ref = artifacts.put_json({"kind": "saved-report", "number": number})
    checkpoint = StageCheckpoint(
        identity=_identity(f"hypothesis-prior-{number:02d}"),
        stage=SimpleStage.REPORT_DONE,
        stage_version=STAGE_VERSION[SimpleStage.REPORT_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=(ref,),
        input_hash=input_reference_hash((ref,)),
        output_refs=(ref,),
        attempt_id=f"report-attempt-{number:02d}",
        attempt_number=1,
        verdict="TRUE",
        report_ref=ref,
        bundle_manifest_ref=ref,
        bundle_archive_ref=ref,
    )
    store.save_checkpoint(checkpoint)
    return checkpoint


def test_v3_checkpoint_append_preserves_18_v2_rows_and_27_reports(
    tmp_path: Path,
) -> None:
    """A v3 replay must append only; it must not rewrite older verdicts or reports."""

    data_dir = tmp_path / "data"
    artifacts = SimpleArtifactRepository(data_dir, _identity())
    store = SimpleCheckpointStore(
        data_dir / "db" / "sastsimi.sqlite3", artifact_data_dir=data_dir
    )
    prior_reports = tuple(_saved_report(store, artifacts, n) for n in range(27))
    old_result = artifacts.put_json({"kind": "saved-v2-insufficient"})
    positive_result = artifacts.put_json(
        {"kind": "saved-v2-positive", "seed_ids": ["positive-v2-seed"]}
    )
    new_result = artifacts.put_json({"kind": "new-v3-review"})
    positive_hypothesis_ref = artifacts.put_json({"kind": "saved-positive-seed"})
    positive_identity = _identity("positive-v2-seed")
    pending_inputs = (positive_hypothesis_ref,)
    positive_registration = (
        "positive-v2-seed",
        positive_hypothesis_ref,
        StageCheckpoint(
            identity=positive_identity,
            stage=SimpleStage.PRO_CON_DONE,
            stage_version=STAGE_VERSION[SimpleStage.PRO_CON_DONE],
            status=StageStatus.PENDING,
            input_refs=pending_inputs,
            input_hash=input_reference_hash(pending_inputs),
        ),
    )
    for number in range(18):
        old_status = (
            "HYPOTHESES"
            if number == 17
            else "NO_HYPOTHESIS"
            if number >= 15
            else "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS"
        )
        store.commit_surface_exploration(
            _identity(),
            "pinned-scope",
            f"surface-{number:02d}",
            f"old-v2-{number:02d}",
            static_bundle_hash="b" * 64,
            index_hash="c" * 64,
            context_hash="d" * 64,
            source_sha256="e" * 64,
            status=old_status,
            result_ref=positive_result if number == 17 else old_result,
            registrations=[positive_registration] if number == 17 else [],
            proposal_version=2,
        )
    old_progress = store.list_surface_exploration_progress(_identity(), "pinned-scope")

    for number in range(18):
        arguments: _CommitArguments = dict(
            static_bundle_hash="b" * 64,
            index_hash="c" * 64,
            context_hash="f" * 64,
            source_sha256="e" * 64,
            status="NO_HYPOTHESIS",
            registrations=[],
            proposal_version=3,
        )
        assert store.commit_surface_exploration(
            _identity(),
            "pinned-scope",
            f"surface-{number:02d}",
            f"supplement-v3-{number:02d}",
            result_ref=new_result,
            **arguments,
        )
        assert not store.commit_surface_exploration(
            _identity(),
            "pinned-scope",
            f"surface-{number:02d}",
            f"supplement-v3-{number:02d}",
            result_ref=new_result,
            **arguments,
        )

    progress = store.list_surface_exploration_progress(_identity(), "pinned-scope")
    assert len(progress) == 36
    assert {key: progress[key] for key in old_progress} == old_progress
    assert old_progress[("surface-17", "old-v2-17")].status == "HYPOTHESES"
    assert old_progress[("surface-17", "old-v2-17")].result_ref == positive_result
    assert (
        store.require(positive_identity, SimpleStage.PRO_CON_DONE)
        == (positive_registration[2])
    )
    assert sum(record.proposal_version == 3 for record in progress.values()) == 18
    assert (
        tuple(
            store.require(checkpoint.identity, SimpleStage.REPORT_DONE)
            for checkpoint in prior_reports
        )
        == prior_reports
    )


def test_v3_checkpoint_conflict_fails_closed_without_changing_saved_result(
    tmp_path: Path,
) -> None:
    """A duplicate context ID with changed evidence cannot silently replace CAS."""

    data_dir = tmp_path / "data"
    artifacts = SimpleArtifactRepository(data_dir, _identity())
    store = SimpleCheckpointStore(
        data_dir / "db" / "sastsimi.sqlite3", artifact_data_dir=data_dir
    )
    original = artifacts.put_json({"kind": "original-v3-result"})
    changed = artifacts.put_json({"kind": "different-v3-result"})
    arguments: _CommitArguments = dict(
        static_bundle_hash="b" * 64,
        index_hash="c" * 64,
        context_hash="d" * 64,
        source_sha256="e" * 64,
        status="NO_HYPOTHESIS",
        registrations=[],
        proposal_version=3,
    )
    store.commit_surface_exploration(
        _identity(), "scope", "surface", "v3-context", result_ref=original, **arguments
    )

    with pytest.raises(ValueError, match="SURFACE_EXPLORATION_CONFLICT"):
        store.commit_surface_exploration(
            _identity(),
            "scope",
            "surface",
            "v3-context",
            result_ref=changed,
            **arguments,
        )

    progress = store.list_surface_exploration_progress(_identity(), "scope")
    assert progress[("surface", "v3-context")].result_ref == original


def test_saved_supplement_plan_survives_run_reload_without_changing_old_runs(
    tmp_path: Path,
) -> None:
    """A pause before the first v3 call must retain opt-in for plain resume."""

    data_dir = tmp_path / "data"
    artifacts = SimpleArtifactRepository(data_dir, _identity())
    plan_ref = artifacts.put_json(
        {
            "kind": "simple_surface_supplement_plan_v3",
            "analysis_id": _identity().analysis_id,
            "scope_fingerprint": "pinned-scope",
            "parent_context_ids": [f"saved-v2-{n:02d}" for n in range(18)],
        }
    )
    store = SimpleCheckpointStore(
        data_dir / "db" / "sastsimi.sqlite3", artifact_data_dir=data_dir
    )
    run = SimpleAnalysisRun(
        analysis_id=_identity().analysis_id,
        display_analysis_id="A-001",
        workspace_id=_identity().workspace_id,
        commit_id=_identity().commit_id,
        repository="https://github.com/example/pinned-python-repo",
        candidate_pipeline_version=2,
        static_disposition="PARTIAL",
        surface_supplement_plan_ref=plan_ref,
    )
    store.save_analysis_run(run)

    assert store.require_analysis_run(run.analysis_id).surface_supplement_plan_ref == (
        plan_ref
    )
    legacy = run.model_dump(mode="json")
    legacy.pop("surface_supplement_plan_ref")
    assert (
        SimpleAnalysisRun.model_validate_json(
            json.dumps(legacy, sort_keys=True)
        ).surface_supplement_plan_ref
        is None
    )


def _old_v2_context_id(surface_id: str, part_index: int, digest: str) -> str:
    return hashlib.sha256(
        canonical_bytes(
            {
                "kind": "simple_surface_context_id_v2",
                "scope_fingerprint": "scope-1",
                "surface_id": surface_id,
                "part_index": part_index,
                "context_hash": digest,
            }
        )
    ).hexdigest()


def _install_old_ast_orphan(
    tmp_path: Path,
    store: SimpleCheckpointStore,
    identity: CheckpointIdentity,
    *,
    extra_unrelated_v2_gap: bool = False,
    parent_unavailable_implementation: bool = False,
) -> tuple[str, tuple[str, str]]:
    """Build a self-consistent two-part saved v2 context in the test CAS only."""

    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    run = store.require_analysis_run(identity.analysis_id)
    assert run.static_bundle_ref is not None
    assert run.workspace_path is not None
    bundle = json.loads(artifacts.read(run.static_bundle_ref))
    index_record = store.get_attack_surface_index(identity, "scope-1")
    assert index_record is not None
    index = surface_index_from_json(json.loads(artifacts.read(index_record.index_ref)))
    saved_progress = store.list_surface_exploration_progress(identity, "scope-1")
    surface_id = next(surface_id for surface_id, _ in saved_progress)
    surface = next(item for item in index.surfaces if item.surface_id == surface_id)
    prepared = prepare_file_context(
        artifacts, bundle["ast_summary"], run.workspace_path, surface.path
    )
    orphan = next(fact for fact in prepared.ast_facts if fact["line"] != surface.line)
    all_lines = [
        {"line": line, "text": value}
        for line, value in enumerate(prepared.source_lines, start=1)
    ]
    first_facts = [fact for fact in prepared.ast_facts if fact != orphan]
    context_ids: list[str] = []
    rows = [
        (
            all_lines,
            first_facts,
            "NO_HYPOTHESIS",
            ["ENTRY", "SENSITIVE_OPERATION", "TRUST_BOUNDARY"],
        ),
        (
            [all_lines[surface.line - 1]],
            [orphan],
            "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
            [],
        ),
    ]
    if extra_unrelated_v2_gap:
        rows.append(
            (
                [all_lines[surface.line - 1]],
                [],
                "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
                [],
            )
        )
    for part_index, (lines, facts, status, parts) in enumerate(rows):
        payload = _surface_payload(
            index,
            surface,
            prepared,
            lines,
            facts,
            [],
            [],
            source_window_count=len(all_lines),
            ast_nearby_count=len(prepared.ast_facts),
            part_index=part_index,
            part_count=len(rows),
        )
        payload.update(
            kind="simple_surface_context_v2",
            selection_scope="FULL_FILE",
            selected_source_line_count=len(all_lines),
            unavailable_implementation=(
                "CALL_RESULT_IMPLEMENTATION_NOT_IN_SAME_FILE"
                if part_index == 1 and parent_unavailable_implementation
                else None
            ),
        )
        context_ref = artifacts.put_json(payload)
        context_id = _old_v2_context_id(
            surface.surface_id, part_index, context_ref.content_hash
        )
        context_ids.append(context_id)
        locations = [f"{surface.path}:{surface.line}"] if parts else []
        result_ref = artifacts.put_json(
            {
                "kind": "simple_surface_hypothesis_result_v2",
                "analysis_id": identity.analysis_id,
                "surface_id": surface.surface_id,
                "context_id": context_id,
                "part_index": part_index,
                "part_count": len(rows),
                "context_hash": context_ref.content_hash,
                "static_bundle_hash": run.static_bundle_ref.content_hash,
                "status": status,
                "reason": "Pinned fixture evidence",
                "reviewed_parts": parts,
                "evidence_locations": locations,
                "seed_ids": [],
            }
        )
        store.commit_surface_exploration(
            identity,
            "scope-1",
            surface.surface_id,
            context_id,
            static_bundle_hash=run.static_bundle_ref.content_hash,
            index_hash=index_record.index_ref.content_hash,
            context_hash=context_ref.content_hash,
            source_sha256=prepared.source_sha256,
            status=status,
            result_ref=result_ref,
            registrations=[],
            proposal_version=2,
        )
    return surface.surface_id, (context_ids[0], context_ids[1])


class _V3Proposer(_SecondLookHypotheses):
    def __init__(self, data_dir: Path, *, pause_once: bool = False) -> None:
        super().__init__(data_dir, fail_second_once=True)
        self.pause_once = pause_once
        self.v3_calls = 0

    async def propose_surface(
        self,
        identity: CheckpointIdentity,
        static: StaticBootstrapResult,
        context: SurfaceContext,
    ) -> SurfaceProposalResult | StageFailure:
        artifacts = SimpleArtifactRepository(self.data_dir, identity)
        payload = json.loads(artifacts.read(context.context_ref))
        if payload["kind"] != "simple_surface_context_v3":
            return await super().propose_surface(identity, static, context)
        self.v3_calls += 1
        self.context_kinds.append(payload["kind"])
        if self.pause_once:
            self.pause_once = False
            return StageFailure(
                code="LLM_TOKEN_BUDGET_EXHAUSTED",
                retryable=False,
                safe_message="Pause this fixture after persisting the v3 plan",
            )
        location = f"{payload['path']}:{payload['line']}"
        parts: frozenset[ReviewPart] = frozenset(
            {"ENTRY", "SENSITIVE_OPERATION", "TRUST_BOUNDARY"}
        )
        result_ref = artifacts.put_json(
            {
                "kind": "simple_surface_hypothesis_result_v3",
                "analysis_id": identity.analysis_id,
                "surface_id": context.surface_id,
                "context_id": context.context_id,
                "part_index": context.part_index,
                "part_count": context.part_count,
                "context_hash": context.context_hash,
                "static_bundle_hash": static.static_bundle_ref.content_hash,
                "status": "NO_HYPOTHESIS",
                "reason": "Pinned source and AST fact were reviewed together",
                "reviewed_parts": sorted(parts),
                "evidence_locations": [location],
                "seed_ids": [],
            }
        )
        return SurfaceProposalResult(
            surface_id=context.surface_id,
            context_id=context.context_id,
            part_index=context.part_index,
            part_count=context.part_count,
            status="NO_HYPOTHESIS",
            reason="Pinned source and AST fact were reviewed together",
            seeds=(),
            result_ref=result_ref,
            reviewed_parts=parts,
            evidence_locations=(location,),
        )


async def _completed_old_v2_run(
    tmp_path: Path,
    *,
    extra_unrelated_v2_gap: bool = False,
    parent_unavailable_implementation: bool = False,
) -> tuple[
    SimpleAnalysisApplication,
    SimpleCheckpointStore,
    _V3Proposer,
    CheckpointIdentity,
    str,
]:
    app, store, _client, _ = _setup(
        tmp_path,
        decision="EXCLUDE",
        result_count=2,
        with_ast_summary=True,
        pipeline_version=2,
        partial=True,
        source_padding=20,
    )
    proposer = _V3Proposer(tmp_path / "data")
    app._candidate_hypotheses = cast(HypothesisBootstrap, proposer)
    _enable_chaining_pool(app, store, tmp_path / "data")
    first = await app.analyze(
        SimpleAnalysisRequest(
            data_dir=tmp_path / "data",
            repository="https://github.com/example/repo",
            commit="a" * 40,
        )
    )
    assert first.status == "PAUSED", (first.status, first.error_code)
    surface_id, _ = _install_old_ast_orphan(
        tmp_path,
        store,
        first.identity,
        extra_unrelated_v2_gap=extra_unrelated_v2_gap,
        parent_unavailable_implementation=parent_unavailable_implementation,
    )
    resumed = await app.resume("analysis-1")
    assert resumed.status == "PARTIAL", (resumed.status, resumed.error_code)
    return app, store, proposer, first.identity, surface_id


@pytest.mark.asyncio
async def test_same_id_v3_resume_persists_intent_and_reuses_completed_contexts(
    tmp_path: Path,
) -> None:
    """A pause after opt-in resumes with no v1/v2 replay or v3 double count."""

    app, store, proposer, identity, surface_id = await _completed_old_v2_run(tmp_path)
    original = store.list_surface_exploration_progress(identity, "scope-1")
    proposer.pause_once = True

    paused = await app.resume("analysis-1", supplement_saved_v2_ast_orphans=True)
    assert paused.status == "PAUSED", (paused.status, paused.error_code)
    assert store.require_analysis_run("analysis-1").surface_supplement_plan_ref
    old_calls = tuple(proposer.context_kinds)

    finished = await app.resume("analysis-1")
    progress = store.list_surface_exploration_progress(identity, "scope-1")
    assert finished.status in {"PARTIAL", "COMPLETE"}, finished.error_code
    assert {key: progress[key] for key in original} == original
    assert (
        sum(
            record.proposal_version == 3 and record.surface_id == surface_id
            for record in progress.values()
        )
        == 1
    )
    assert proposer.v3_calls == 2  # one paused call, one recorded call

    calls_after_finished = tuple(proposer.context_kinds)
    repeated = await app.resume("analysis-1")
    assert repeated.status == finished.status
    assert tuple(proposer.context_kinds) == calls_after_finished
    assert len(calls_after_finished) == len(old_calls) + 1
    assert proposer.v3_calls == 2
    assert store.list_surface_exploration_progress(identity, "scope-1") == progress


@pytest.mark.asyncio
async def test_v3_opt_in_rejects_changed_pinned_source_without_new_progress(
    tmp_path: Path,
) -> None:
    """A changed checkout is not a reason to relabel an old v2 gap complete."""

    app, store, _proposer, identity, _surface_id = await _completed_old_v2_run(tmp_path)
    original = store.list_surface_exploration_progress(identity, "scope-1")
    source = tmp_path / "checkout" / "app.py"
    source.write_text(
        source.read_text(encoding="utf-8") + "\n# changed\n",
        encoding="utf-8",
    )

    result = await app.resume("analysis-1", supplement_saved_v2_ast_orphans=True)

    assert result.status in {"BLOCKED", "FAILED"}
    assert store.list_surface_exploration_progress(identity, "scope-1") == original
    assert not any(record.proposal_version == 3 for record in original.values())


@pytest.mark.asyncio
async def test_v3_cannot_cover_unrelated_unsupplemented_v2_gap(tmp_path: Path) -> None:
    app, store, _proposer, identity, surface_id = await _completed_old_v2_run(
        tmp_path, extra_unrelated_v2_gap=True
    )
    result = await app.resume("analysis-1", supplement_saved_v2_ast_orphans=True)

    assert result.status == "PARTIAL", (result.status, result.error_code)
    run = store.require_analysis_run(identity.analysis_id)
    terminal = run.candidate_terminal
    assert terminal is not None
    checkpoint = store.require(identity, SimpleStage.HYPOTHESIS_DONE)
    coverage_ref = next(
        ref
        for ref in checkpoint.output_refs
        if ref.content_hash == terminal.surface_coverage_hash
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    coverage = json.loads(artifacts.read(coverage_ref))
    surface = next(
        item for item in coverage["surfaces"] if item["surface_id"] == surface_id
    )
    assert surface["coverage_status"] == "INSUFFICIENT"
    progress = store.list_surface_exploration_progress(identity, "scope-1")
    assert sum(record.proposal_version == 3 for record in progress.values()) == 1


@pytest.mark.asyncio
async def test_v3_cannot_cover_parent_with_unavailable_implementation(
    tmp_path: Path,
) -> None:
    app, store, _proposer, identity, surface_id = await _completed_old_v2_run(
        tmp_path, parent_unavailable_implementation=True
    )
    result = await app.resume("analysis-1", supplement_saved_v2_ast_orphans=True)

    assert result.status == "PARTIAL", (result.status, result.error_code)
    run = store.require_analysis_run(identity.analysis_id)
    terminal = run.candidate_terminal
    assert terminal is not None
    checkpoint = store.require(identity, SimpleStage.HYPOTHESIS_DONE)
    coverage_ref = next(
        ref
        for ref in checkpoint.output_refs
        if ref.content_hash == terminal.surface_coverage_hash
    )
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    coverage = json.loads(artifacts.read(coverage_ref))
    surface = next(
        item for item in coverage["surfaces"] if item["surface_id"] == surface_id
    )
    assert surface["coverage_status"] == "INSUFFICIENT"


@pytest.mark.asyncio
async def test_v3_cannot_cover_a_saved_v2_child_on_prerequisite_hold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app, store, _proposer, identity, surface_id = await _completed_old_v2_run(tmp_path)
    result = await app.resume("analysis-1", supplement_saved_v2_ast_orphans=True)
    assert result.status in {"PARTIAL", "COMPLETE"}, result.error_code
    artifacts = SimpleArtifactRepository(tmp_path / "data", identity)
    progress = store.list_surface_exploration_progress(identity, "scope-1")
    old_key = next(
        key
        for key, record in progress.items()
        if record.surface_id == surface_id
        and record.proposal_version == 2
        and record.status == "NO_HYPOTHESIS"
    )
    old = progress[old_key]
    old_result = json.loads(artifacts.read(old.result_ref))
    old_result["status"] = "HYPOTHESES"
    old_result["seed_ids"] = ["held-child"]
    changed = dict(progress)
    changed[old_key] = replace(
        old,
        status="HYPOTHESES",
        result_ref=artifacts.put_json(old_result),
        hypothesis_ids=("held-child",),
    )
    evidence_ref = artifacts.put_json(
        {
            "kind": "simple_initial_verification",
            "attempt_id": "held-attempt",
            "result": {"unmet_external_prerequisites": ["Backend unavailable"]},
        }
    )
    child = identity.model_copy(update={"hypothesis_id": "held-child"})
    store.save_checkpoint(
        StageCheckpoint(
            identity=child,
            stage=SimpleStage.VERIFICATION_INITIAL_DONE,
            stage_version=STAGE_VERSION[SimpleStage.VERIFICATION_INITIAL_DONE],
            status=StageStatus.SUCCEEDED,
            input_refs=(),
            input_hash=input_reference_hash(()),
            output_refs=(evidence_ref,),
            attempt_id="held-attempt",
            verdict="HOLD",
            external_prerequisites_ref=evidence_ref,
        )
    )
    monkeypatch.setattr(store, "list_surface_exploration_progress", lambda *_: changed)
    static_runner = app._static
    assert isinstance(static_runner, _Static)
    static = static_runner.result
    bundle = json.loads(artifacts.read(static.static_bundle_ref))
    index_record = store.get_attack_surface_index(identity, "scope-1")
    assert index_record is not None
    index = surface_index_from_json(json.loads(artifacts.read(index_record.index_ref)))

    coverage = app._final_surface_coverage(
        identity,
        static,
        "scope-1",
        artifacts,
        bundle["ast_summary"],
        index,
        index_record.index_ref,
        run=store.require_analysis_run(identity.analysis_id),
    )

    assert (
        next(
            item.coverage_status
            for item in coverage.surfaces
            if item.surface_id == surface_id
        )
        == "INSUFFICIENT"
    )
