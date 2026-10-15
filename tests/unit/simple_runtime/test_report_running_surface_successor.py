"""A running successor may disclose static coverage, never unproved surface counts."""

from __future__ import annotations

import hashlib
from dataclasses import replace
from pathlib import Path
from typing import Any, Literal

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime import application as application_module
from sastsimi.simple_runtime.application import SimpleAnalysisApplication
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
    STAGE_VERSION,
    CandidateTerminal,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.runner import StageFailed
from sastsimi.simple_runtime.stages import ReporterStage
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.simple_runtime.surface_enrichment_v9 import prepare_surface_enrichment_v9
from sastsimi.simple_runtime.surface_enrichment_v9_bindings import (
    prior_v8_progress_snapshot_hash,
)
from sastsimi.simple_runtime.surface_evidence_validation_v9 import (
    validate_saved_v9_result,
)
from tests.unit.simple_runtime.test_surface_enrichment_v9 import connected_inputs


class _UnusedReporterClient:
    async def call(self, **_kwargs: Any) -> SimpleLLMCallResult | StageFailure:
        raise AssertionError("Static coverage disclosure must not call the LLM")


def _patch_reporter_predecessor(
    monkeypatch: pytest.MonkeyPatch, *, accepted: bool
) -> None:
    """Exercise Reporter routing; the strict proof reader is tested separately."""
    from sastsimi.simple_runtime import stages, surface_v9_predecessor_read

    def verified(
        run: SimpleAnalysisRun,
        artifacts: SimpleArtifactRepository,
        store: SimpleCheckpointStore,
    ) -> bool:
        return accepted

    # Support both a module import at call time and a bound stage import.
    monkeypatch.setattr(
        surface_v9_predecessor_read, "verified_pending_v9_predecessor", verified
    )
    monkeypatch.setattr(
        stages, "verified_pending_v9_predecessor", verified, raising=False
    )


def _case(
    tmp_path: Path,
    *,
    plan_state: str = "valid",
    terminal_status: Literal["COMPLETE", "PARTIAL"] = "PARTIAL",
) -> tuple[
    ReporterStage,
    StageCheckpoint,
    SimpleCheckpointStore,
    SimpleArtifactRepository,
]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    inputs = connected_inputs(workspace)
    root_identity: CheckpointIdentity = inputs["identity"]
    child_identity = root_identity.model_copy(update={"hypothesis_id": "hypothesis-1"})
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    root_artifacts = SimpleArtifactRepository(data_dir, root_identity)
    child_artifacts = SimpleArtifactRepository(data_dir, child_identity)
    index = inputs["index"]
    index_ref = root_artifacts.put_json(index.to_json())
    v8_plan_ref = root_artifacts.put_json(inputs["prior_v8_plan"])
    assert index_ref == inputs["index_ref"]
    assert v8_plan_ref == inputs["prior_v8_plan_ref"]

    static_ref = root_artifacts.put_json(
        {
            "kind": "simple_static_coverage_v1",
            "analysis_id": root_identity.analysis_id,
            "workspace_id": root_identity.workspace_id,
            "commit_id": root_identity.commit_id,
            "fingerprint": "e" * 64,
            "expected_count": 1,
            "verified_count": 1,
            "gaps": [],
            "unsupported_files": [],
            "engine_errors": [],
        }
    )
    certificate_ref = root_artifacts.put_json(
        {
            "kind": "simple_python_scope_certificate_v2",
            "analysis_id": root_identity.analysis_id,
            "workspace_id": root_identity.workspace_id,
            "commit_id": root_identity.commit_id,
            "coverage_ref": static_ref.model_dump(mode="json"),
            "index_ref": index_ref.model_dump(mode="json"),
        }
    )
    parent = replace(inputs["prior_v8_coverage"], scope_certificate_ref=certificate_ref)
    v8_coverage_ref = root_artifacts.put_json(parent.to_json())
    inputs["prior_v8_coverage"] = parent
    inputs["prior_v8_coverage_ref"] = v8_coverage_ref
    inputs["prior_v8_progress_hash"] = prior_v8_progress_snapshot_hash({})
    plan, parts = prepare_surface_enrichment_v9(**inputs)
    assert parts
    if plan_state == "tampered":
        plan = {**plan, "commit_id": "f" * 40}
    plan_ref = root_artifacts.put_json(plan) if plan_state != "missing" else None
    base_plan_ref = root_artifacts.put_json({"kind": "earlier_surface_plan"})
    v5_plan_ref = root_artifacts.put_json({"kind": "earlier_surface_plan_v5"})
    v6_plan_ref = root_artifacts.put_json({"kind": "earlier_surface_plan_v6"})
    v7_plan_ref = root_artifacts.put_json({"kind": "earlier_surface_plan_v7"})
    terminal = CandidateTerminal(
        status=terminal_status,
        bundle_hash=index.static_bundle_hash,
        scope_fingerprint=index.scope_fingerprint,
        decision_counts={},
        deep_counts={},
        hypothesis_count=1,
        surface_index_hash=index_ref.content_hash,
        surface_coverage_hash=v8_coverage_ref.content_hash,
        surface_proof_version=6,
        scope_certificate_hash=certificate_ref.content_hash,
        surface_counts={"COVERED": 0, "UNCOVERED": 0, "INSUFFICIENT": 1},
        producer_finished=True,
    )
    run = SimpleAnalysisRun(
        analysis_id=root_identity.analysis_id,
        display_analysis_id="A-001",
        workspace_id=root_identity.workspace_id,
        commit_id=root_identity.commit_id,
        repository="example/project",
        workspace_path=workspace,
        static_coverage_ref=static_ref,
        static_disposition="FULL",
        candidate_pipeline_version=2,
        candidate_scope_fingerprint=index.scope_fingerprint,
        candidate_terminal=terminal,
        surface_enrichment_plan_ref=base_plan_ref,
        surface_enrichment_v5_plan_ref=v5_plan_ref,
        surface_enrichment_v6_plan_ref=v6_plan_ref,
        surface_enrichment_v7_plan_ref=v7_plan_ref,
        surface_enrichment_v8_plan_ref=v8_plan_ref,
        surface_enrichment_v9_plan_ref=plan_ref,
        python_scope_certificate_ref=certificate_ref,
        surface_enrichment_status="RUNNING",
    )
    store.save_analysis_run(run)
    store.save_attack_surface_index(
        root_identity,
        index.scope_fingerprint,
        static_bundle_hash=index.static_bundle_hash,
        ast_manifest_hash=index.ast_manifest_hash,
        candidate_inventory_hash=index.candidate_inventory_hash,
        candidate_count=index.candidate_count,
        index_ref=index_ref,
    )
    root_checkpoint = StageCheckpoint(
        identity=root_identity,
        stage=SimpleStage.HYPOTHESIS_DONE,
        stage_version=STAGE_VERSION[SimpleStage.HYPOTHESIS_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(index_ref, v8_coverage_ref),
        attempt_id="root-attempt",
        attempt_number=1,
    )
    store.save_checkpoint(root_checkpoint)
    if plan_ref is not None:
        part = parts[0]
        context_part = part.payload["context_part"]
        assert isinstance(context_part, dict)
        saved_result = {
            "kind": "simple_surface_hypothesis_result_v9",
            "analysis_id": root_identity.analysis_id,
            "surface_id": part.surface_id,
            "context_id": part.context_id,
            "context_hash": part.context_hash,
            "part_id": part.part_id,
            "part_index": part.part_index,
            "part_count": part.part_count,
            "source_sha256": part.source_sha256,
            "content_sha256": context_part["content_sha256"],
            "static_bundle_hash": index.static_bundle_hash,
            "status": "INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
            "reason": "The first source part does not establish the entire flow.",
            "reviewed_path_ids": [],
            "role_citations": [],
            "review_complete": False,
            "reviewed_parts": [],
            "evidence_locations": [],
            "seed_ids": [],
            "response": {},
            "validation_status": "VALID",
            "validation_feedback": None,
            "attempt_input_refs": [],
            "llm_request_ref": None,
            "llm_response_ref": None,
            "llm_raw_output_ref": None,
        }
        validate_saved_v9_result(part, saved_result, ())
        result_ref = root_artifacts.put_json(saved_result)
        assert store.commit_surface_exploration(
            root_identity,
            index.scope_fingerprint,
            part.surface_id,
            part.context_id,
            static_bundle_hash=index.static_bundle_hash,
            index_hash=index_ref.content_hash,
            context_hash=part.context_hash,
            source_sha256=part.source_sha256,
            status="INSUFFICIENT_EVIDENCE_FOR_HYPOTHESIS",
            result_ref=result_ref,
            registrations=(),
            proposal_version=9,
        )
    store.upsert_hypothesis(root_identity, "hypothesis-1")
    child_checkpoint = StageCheckpoint(
        identity=child_identity,
        stage=SimpleStage.REPORT_DONE,
        stage_version=STAGE_VERSION[SimpleStage.REPORT_DONE],
        status=StageStatus.RUNNING,
        input_refs=(),
        input_hash=input_reference_hash(()),
        attempt_id="report-attempt",
        attempt_number=1,
    )
    reporter = ReporterStage(_UnusedReporterClient(), child_artifacts, store=store)
    return reporter, child_checkpoint, store, child_artifacts


def test_running_v9_successor_discloses_verified_static_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_reporter_predecessor(monkeypatch, accepted=True)
    reporter, checkpoint, _store, _artifacts = _case(tmp_path)

    disclosure = reporter._coverage(checkpoint)

    assert disclosure is not None
    assert disclosure.analysis_status == "PARTIAL"
    assert disclosure.partial is False
    assert disclosure.expected_count == 1
    assert disclosure.verified_count == 1
    assert disclosure.surface_proof_version is None
    assert disclosure.surface_reviewed_count is None
    assert disclosure.surface_covered_count is None
    assert disclosure.surface_uncovered_count is None
    assert disclosure.surface_insufficient_count is None
    assert disclosure.surface_unresolved_reason_count is None


@pytest.mark.parametrize(
    ("plan_state", "terminal_status"),
    [
        ("missing", "PARTIAL"),
        ("tampered", "PARTIAL"),
        ("valid", "COMPLETE"),
    ],
)
def test_unbound_or_complete_successor_cannot_bypass_surface_proof(
    tmp_path: Path,
    plan_state: str,
    terminal_status: Literal["COMPLETE", "PARTIAL"],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_reporter_predecessor(monkeypatch, accepted=False)
    reporter, checkpoint, _store, _artifacts = _case(
        tmp_path, plan_state=plan_state, terminal_status=terminal_status
    )

    with pytest.raises(StageFailed) as caught:
        reporter._coverage(checkpoint)

    assert caught.value.failure.code == "REPORT_SURFACE_PROOF_UNVERIFIED"


def _failed_report_case(
    tmp_path: Path,
    *,
    plan_state: str = "valid",
) -> tuple[
    SimpleCheckpointStore,
    SimpleArtifactRepository,
    StageCheckpoint,
    StoredDataRef,
    StageCheckpoint,
]:
    _reporter, current, store, artifacts = _case(tmp_path, plan_state=plan_state)
    identity = current.identity
    prior: dict[SimpleStage, StageCheckpoint] = {}
    prior_refs: list[StoredDataRef] = []
    for stage in HYPOTHESIS_STAGES[:-1]:
        ref = artifacts.put_json({"stage": stage.value})
        inputs = (prior_refs[-1],) if prior_refs else ()
        verdict: Literal["TRUE"] | None = (
            "TRUE"
            if stage in {SimpleStage.VERIFICATION_FINAL_DONE, SimpleStage.FINDING_DONE}
            else None
        )
        validated_poc_ref = ref if stage is SimpleStage.POC_EXECUTION_DONE else None
        saved = StageCheckpoint(
            identity=identity,
            stage=stage,
            stage_version=STAGE_VERSION[stage],
            status=StageStatus.SUCCEEDED,
            input_refs=inputs,
            input_hash=input_reference_hash(inputs),
            output_refs=(ref,),
            attempt_id=f"{stage.value}-attempt",
            attempt_number=1,
            verdict=verdict,
            validated_poc_ref=validated_poc_ref,
        )
        store.save_checkpoint(saved)
        prior[stage] = saved
        prior_refs.append(ref)
    stopped = StageCheckpoint(
        identity=identity,
        stage=SimpleStage.REPORT_DONE,
        stage_version=STAGE_VERSION[SimpleStage.REPORT_DONE],
        status=StageStatus.FAILED,
        input_refs=(prior_refs[-1],),
        input_hash=input_reference_hash((prior_refs[-1],)),
        attempt_id="report-attempt",
        attempt_number=1,
        error_code="REPORT_SURFACE_PROOF_UNVERIFIED",
        retryable=False,
    )
    running = stopped.model_copy(
        update={"status": StageStatus.RUNNING, "error_code": None}
    )
    store.save_checkpoint(running)
    stopped = store.mark_failure(
        running,
        StageFailure(
            code="REPORT_SURFACE_PROOF_UNVERIFIED",
            retryable=False,
            safe_message="Saved attack-surface proof could not be verified",
        ),
        StageStatus.FAILED,
    )
    prose = {
        "title": "Saved issue",
        "summary": "The local test supports the saved finding.",
        "details": "The saved PoC reached the operation.",
        "impact": "The operation can be invoked.",
        "recommendation": "Validate untrusted input.",
        "limitations": ["Deployment behavior needs review."],
        "review_items": ["Confirm the affected deployment."],
    }
    content = {"schema_version": 2, "en": prose, "ko": prose, "citations": []}
    draft_ref = artifacts.put_json(
        {
            "kind": "simple_report_draft",
            "attempt_id": stopped.attempt_id,
            "source_refs": [ref.model_dump(mode="json") for ref in prior_refs],
            "result": content,
            "prompt_digest": "b" * 64,
            "output_digest": hashlib.sha256(canonical_bytes(content)).hexdigest(),
        }
    )
    source_hash = hashlib.sha256(
        canonical_bytes(
            {
                "refs": tuple(prior_refs),
                "finding_attempt_id": prior[SimpleStage.FINDING_DONE].attempt_id,
                "poc_attempt_id": prior[SimpleStage.POC_EXECUTION_DONE].attempt_id,
            }
        )
    ).hexdigest()
    store.save_report_draft(
        identity, source_hash, prior[SimpleStage.FINDING_DONE].output_refs[0], draft_ref
    )
    other_identity = identity.model_copy(update={"hypothesis_id": "hypothesis-2"})
    other_ref = artifacts.put_json({"kind": "other-successful-report"})
    other = StageCheckpoint(
        identity=other_identity,
        stage=SimpleStage.REPORT_DONE,
        stage_version=STAGE_VERSION[SimpleStage.REPORT_DONE],
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=(other_ref,),
        attempt_id="other-report-attempt",
        attempt_number=1,
    )
    store.save_checkpoint(other)
    return store, artifacts, stopped, draft_ref, other


def test_failed_report_replays_only_its_saved_draft_under_running_v9_successor(
    tmp_path: Path,
) -> None:
    store, artifacts, stopped, draft_ref, other = _failed_report_case(tmp_path)
    root_identity = stopped.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    prior = store.prior(stopped.identity, SimpleStage.REPORT_DONE)

    def verified_predecessor(
        run: SimpleAnalysisRun,
        proof_artifacts: SimpleArtifactRepository,
        passed_store: SimpleCheckpointStore,
    ) -> bool:
        return True

    pending = store.prepare_report_surface_proof_replay(
        stopped,
        artifacts,
        verify_saved_coverage=lambda *_args: object(),
        verify_pending_v9_predecessor=verified_predecessor,
    )

    assert pending.status is StageStatus.PENDING
    assert pending.stage is SimpleStage.REPORT_DONE
    assert pending.attempt_id is None
    assert pending.attempt_number == stopped.attempt_number
    assert pending.input_refs == stopped.input_refs
    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == pending
    assert store.require(root_identity, SimpleStage.HYPOTHESIS_DONE) == root
    assert store.prior(stopped.identity, SimpleStage.REPORT_DONE) == prior
    assert store.require(other.identity, SimpleStage.REPORT_DONE) == other
    assert artifacts.read(draft_ref)


def test_application_reopens_v9_report_with_bound_proof_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, stopped, _draft_ref, _other = _failed_report_case(tmp_path)
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=None,  # type: ignore[arg-type]
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )
    monkeypatch.setattr(
        application_module,
        "verified_pending_v9_predecessor",
        lambda *_args: True,
        raising=False,
    )

    application._prepare_report_validator_locked(
        stopped.identity.analysis_id, stopped.identity.hypothesis_id or ""
    )

    assert (
        store.require(stopped.identity, SimpleStage.REPORT_DONE).status
        is StageStatus.PENDING
    )


@pytest.mark.parametrize("damage", ["tampered-plan", "unrelated-in-flight-child"])
def test_failed_report_replay_preserves_checkpoints_when_successor_proof_rejects(
    tmp_path: Path, damage: str
) -> None:
    store, artifacts, stopped, draft_ref, other = _failed_report_case(
        tmp_path,
        plan_state="tampered" if damage == "tampered-plan" else "valid",
    )
    root_identity = stopped.identity.model_copy(update={"hypothesis_id": None})
    if damage == "unrelated-in-flight-child":
        store.upsert_hypothesis(root_identity, "hypothesis-unrelated")
    draft_before = artifacts.read(draft_ref)

    def reject_unverified_predecessor(*_args: object, **_kwargs: object) -> bool:
        return False

    with pytest.raises(ValueError, match="REPORT_SURFACE_PROOF_REPLAY_"):
        store.prepare_report_surface_proof_replay(
            stopped,
            artifacts,
            verify_saved_coverage=lambda *_args: object(),
            verify_pending_v9_predecessor=reject_unverified_predecessor,
        )

    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == stopped
    assert store.require(other.identity, SimpleStage.REPORT_DONE) == other
    assert artifacts.read(draft_ref) == draft_before
