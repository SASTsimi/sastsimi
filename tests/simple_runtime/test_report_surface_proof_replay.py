"""A fixed proof reader may reopen only the exact failed report publication."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.observability.agent_activity import ActivityKind, AgentActivityEvent
from sastsimi.simple_runtime import application as application_module
from sastsimi.simple_runtime.application import SimpleAnalysisApplication
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.attack_surfaces import SurfaceIndex
from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
    CandidateTerminal,
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from sastsimi.storage.agent_activity import AgentActivityStore
from tests.simple_runtime.test_legacy_import_stop_replan import _checkpoint


def _report_content() -> dict[str, object]:
    prose = {
        "title": "Saved issue",
        "summary": "The saved finding is supported by the local test.",
        "details": "The saved PoC reached the operation.",
        "impact": "The operation can be invoked.",
        "recommendation": "Validate untrusted input.",
        "limitations": ["Deployment behavior still needs review."],
        "review_items": ["Confirm the affected deployment."],
    }
    return {"schema_version": 2, "en": prose, "ko": prose, "citations": []}


def _failed_report(
    tmp_path: Path,
) -> tuple[
    SimpleCheckpointStore,
    SimpleArtifactRepository,
    StageCheckpoint,
    StoredDataRef,
    StageCheckpoint,
]:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )
    child_artifacts = SimpleArtifactRepository(data_dir, identity)
    root_identity = identity.model_copy(update={"hypothesis_id": None})
    root_artifacts = SimpleArtifactRepository(data_dir, root_identity)
    index = SurfaceIndex(
        scope_fingerprint="s" * 64,
        static_bundle_hash="b" * 64,
        ast_manifest_hash="a" * 64,
        workspace_id=identity.workspace_id,
        commit_id=identity.commit_id,
        candidate_inventory_hash="c" * 64,
        candidate_count=0,
        surfaces=(),
        static_gaps=(),
    )
    index_ref = root_artifacts.put_json(index.to_json())
    coverage_ref = root_artifacts.put_json(
        {"kind": "simple_attack_surface_coverage_v5"}
    )
    store.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id="A-001",
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="example/repository",
            candidate_pipeline_version=2,
            candidate_scope_fingerprint=index.scope_fingerprint,
            candidate_terminal=CandidateTerminal(
                status="PARTIAL",
                bundle_hash=index.static_bundle_hash,
                scope_fingerprint=index.scope_fingerprint,
                decision_counts={},
                deep_counts={},
                hypothesis_count=1,
                surface_index_hash=index_ref.content_hash,
                surface_coverage_hash=coverage_ref.content_hash,
                surface_proof_version=5,
            ),
        )
    )
    store.save_checkpoint(
        _checkpoint(
            root_identity,
            SimpleStage.HYPOTHESIS_DONE,
            status=StageStatus.SUCCEEDED,
            outputs=(index_ref, coverage_ref),
            attempt_id="root-attempt",
            attempt_number=1,
        )
    )
    store.upsert_hypothesis(root_identity, identity.hypothesis_id or "")
    prior: dict[SimpleStage, StageCheckpoint] = {}
    prior_refs: list[StoredDataRef] = []
    for stage in HYPOTHESIS_STAGES[:-1]:
        ref = child_artifacts.put_json({"stage": stage.value})
        checkpoint = _checkpoint(
            identity,
            stage,
            status=StageStatus.SUCCEEDED,
            inputs=(prior_refs[-1],) if prior_refs else (),
            outputs=(ref,),
            attempt_id=f"{stage.value}-attempt",
            attempt_number=1,
        )
        if stage in {SimpleStage.VERIFICATION_FINAL_DONE, SimpleStage.FINDING_DONE}:
            checkpoint = checkpoint.model_copy(update={"verdict": "TRUE"})
        if stage is SimpleStage.POC_EXECUTION_DONE:
            checkpoint = checkpoint.model_copy(update={"validated_poc_ref": ref})
        store.save_checkpoint(checkpoint)
        prior[stage] = checkpoint
        prior_refs.append(ref)
    stopped = _checkpoint(
        identity,
        SimpleStage.REPORT_DONE,
        status=StageStatus.FAILED,
        inputs=(prior_refs[-1],),
        attempt_id="report-attempt",
        attempt_number=1,
        error_code="REPORT_SURFACE_PROOF_UNVERIFIED",
    )
    store.save_checkpoint(stopped)
    content = _report_content()
    draft_ref = child_artifacts.put_json(
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
    AgentActivityStore(store.database_path).append(
        AgentActivityEvent(
            event_id="report-proof-failure",
            analysis_id=identity.analysis_id,
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            hypothesis_id=identity.hypothesis_id,
            stage=SimpleStage.REPORT_DONE.value,
            agent_role="Reporter Agent",
            attempt_id=stopped.attempt_id or "",
            sequence=1499,
            kind=ActivityKind.STAGE_FAILED,
            status=StageStatus.FAILED.value,
            summary_ko="Saved proof failed validation.",
            input_refs=stopped.input_refs,
            error_code=stopped.error_code,
            started_at=datetime.now(UTC),
        )
    )
    other_identity = identity.model_copy(update={"hypothesis_id": "hypothesis-2"})
    other_report = _checkpoint(
        other_identity,
        SimpleStage.REPORT_DONE,
        status=StageStatus.SUCCEEDED,
        outputs=(child_artifacts.put_json({"kind": "other-report"}),),
        attempt_id="other-report-attempt",
        attempt_number=1,
    )
    store.save_checkpoint(other_report)
    return store, child_artifacts, stopped, draft_ref, other_report


def test_verified_proof_reopens_only_failed_report_with_cached_draft(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, artifacts, stopped, draft_ref, other = _failed_report(tmp_path)
    root_identity = stopped.identity.model_copy(update={"hypothesis_id": None})
    root = store.require(root_identity, SimpleStage.HYPOTHESIS_DONE)
    prior = store.prior(stopped.identity, SimpleStage.REPORT_DONE)
    from sastsimi.simple_runtime import surface_coverage_v5

    def verify_exact_saved_coverage(
        identity: CheckpointIdentity,
        index: SurfaceIndex,
        coverage_ref: StoredDataRef,
        passed_store: SimpleCheckpointStore,
        proof_artifacts: SimpleArtifactRepository,
    ) -> object:
        assert identity == root_identity
        assert index.scope_fingerprint == "s" * 64
        assert coverage_ref == root.output_refs[1]
        assert passed_store is store
        assert proof_artifacts.identity == root_identity
        return object()

    monkeypatch.setattr(
        surface_coverage_v5, "verified_saved_coverage_v5", verify_exact_saved_coverage
    )

    pending = store.prepare_report_surface_proof_replay(
        stopped,
        artifacts,
        verify_saved_coverage=surface_coverage_v5.verified_saved_coverage_v5,
    )

    assert pending.stage is SimpleStage.REPORT_DONE
    assert pending.status is StageStatus.PENDING
    assert pending.attempt_id is None
    assert pending.attempt_number == stopped.attempt_number
    assert pending.input_refs == stopped.input_refs
    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == pending
    assert store.require(root_identity, SimpleStage.HYPOTHESIS_DONE) == root
    assert store.prior(stopped.identity, SimpleStage.REPORT_DONE) == prior
    assert store.require(other.identity, SimpleStage.REPORT_DONE) == other
    assert any(
        event.error_code == "REPORT_SURFACE_PROOF_REPLAYED"
        for event in AgentActivityStore(store.database_path).list_analysis(
            stopped.identity.analysis_id,
            hypothesis_id=stopped.identity.hypothesis_id,
        )
    )
    assert json.loads(artifacts.read(draft_ref))["kind"] == "simple_report_draft"


def test_proof_failure_keeps_failed_checkpoint_and_saved_draft(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, artifacts, stopped, draft_ref, _other = _failed_report(tmp_path)
    from sastsimi.simple_runtime import surface_coverage_v5

    def unverified(*_args: object) -> object:
        raise ValueError("SURFACE_COVERAGE_V5_VERIFIED_INVALID")

    monkeypatch.setattr(surface_coverage_v5, "verified_saved_coverage_v5", unverified)

    with pytest.raises(ValueError, match="REPORT_SURFACE_PROOF_REPLAY_UNVERIFIED"):
        store.prepare_report_surface_proof_replay(
            stopped,
            artifacts,
            verify_saved_coverage=surface_coverage_v5.verified_saved_coverage_v5,
        )

    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == stopped
    assert json.loads(artifacts.read(draft_ref))["kind"] == "simple_report_draft"


def test_wrong_failure_or_missing_cached_draft_cannot_reopen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, artifacts, stopped, _draft_ref, _other = _failed_report(tmp_path)
    from sastsimi.simple_runtime import surface_coverage_v5

    monkeypatch.setattr(
        surface_coverage_v5,
        "verified_saved_coverage_v5",
        lambda *_args: object(),
    )
    wrong = stopped.model_copy(update={"error_code": "REPORT_CONTENT_INVALID"})
    with pytest.raises(ValueError, match="REPORT_SURFACE_PROOF_REPLAY_INVALID"):
        store.prepare_report_surface_proof_replay(
            wrong,
            artifacts,
            verify_saved_coverage=surface_coverage_v5.verified_saved_coverage_v5,
        )
    with store._connect() as connection:
        connection.execute("DELETE FROM simple_report_drafts")
    with pytest.raises(ValueError, match="REPORT_SURFACE_PROOF_REPLAY_DRAFT_INVALID"):
        store.prepare_report_surface_proof_replay(
            stopped,
            artifacts,
            verify_saved_coverage=surface_coverage_v5.verified_saved_coverage_v5,
        )
    assert store.require(stopped.identity, SimpleStage.REPORT_DONE) == stopped


def test_existing_report_repair_option_routes_exact_proof_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _artifacts, stopped, _draft_ref, _other = _failed_report(tmp_path)
    monkeypatch.setattr(
        application_module,
        "verified_saved_coverage_v5",
        lambda *_args: object(),
    )
    application = SimpleAnalysisApplication(
        data_dir=tmp_path / "data",
        store=store,
        static_bootstrap=None,  # type: ignore[arg-type]
        hypothesis_bootstrap=None,  # type: ignore[arg-type]
        runner_factory=None,  # type: ignore[arg-type]
    )

    application._prepare_report_validator_locked(
        stopped.identity.analysis_id, stopped.identity.hypothesis_id or ""
    )

    assert (
        store.require(stopped.identity, SimpleStage.REPORT_DONE).status
        is StageStatus.PENDING
    )
