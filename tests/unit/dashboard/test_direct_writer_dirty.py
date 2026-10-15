"""Direct checkpoint rewrites must not leave a stale dashboard index READY."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.dashboard.read_model import INDEXED_TABS, DashboardReadModel
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.candidates import normalize_candidate_page
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.recovery import (
    RecoveryAction,
    RecoveryCategory,
    RecoveryDecision,
    RecoveryResolution,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from tests.simple_runtime.test_legacy_import_stop_replan import _seed
from tests.unit.simple_runtime.test_call_queue import _cleanup_confirmation


def _ready(model: DashboardReadModel, analysis_id: str) -> None:
    model.replace(
        analysis_id,
        "seed:hold:0",
        {tab: ([], {"tab": tab}) for tab in INDEXED_TABS},
    )


def _status(model: DashboardReadModel, analysis_id: str) -> str:
    with sqlite3.connect(model.database) as connection:
        row = connection.execute(
            "SELECT status FROM dashboard_index_state WHERE analysis_id = ?",
            (analysis_id,),
        ).fetchone()
    assert row is not None
    return str(row[0])


def _identity() -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )


def _pending(identity: CheckpointIdentity) -> StageCheckpoint:
    return StageCheckpoint(
        identity=identity,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.PENDING,
        input_refs=(),
        input_hash=input_reference_hash(()),
    )


def _candidate_setup(
    tmp_path: Path,
) -> tuple[
    SimpleCheckpointStore,
    DashboardReadModel,
    CheckpointIdentity,
    SimpleArtifactRepository,
    str,
]:
    data_dir = tmp_path / "data"
    root = _identity().model_copy(update={"hypothesis_id": None})
    artifacts = SimpleArtifactRepository(data_dir, root)
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    model = DashboardReadModel(data_dir)
    model.initialize()
    raw = {
        "check_id": "python.eval",
        "path": "pkg/example.py",
        "start": {"line": 1},
        "end": {"line": 1},
        "extra": {"message": "candidate", "lines": "eval(value)"},
    }
    raw_ref = artifacts.put_json({"results": [raw]})
    candidate = normalize_candidate_page(
        root, "scope-1", "opengrep", raw_ref, (raw,), 0
    )[0]
    store.upsert_candidate_page(root, "scope-1", raw_ref, 0, 1, (candidate,))
    store.save_candidate_decision(
        root, "scope-1", candidate.candidate_id, "INCLUDE", "test evidence"
    )
    _ready(model, root.analysis_id)
    return store, model, root, artifacts, candidate.candidate_id


def _candidate_pending(
    root: CheckpointIdentity, hypothesis_id: str, proposal: StoredDataRef
) -> StageCheckpoint:
    child = root.model_copy(update={"hypothesis_id": hypothesis_id})
    inputs = (proposal,)
    return StageCheckpoint(
        identity=child,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.PENDING,
        input_refs=inputs,
        input_hash=input_reference_hash(inputs),
    )


def test_replace_from_dirties_index_in_same_checkpoint_commit(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    model = DashboardReadModel(data_dir)
    model.initialize()
    identity = _identity()
    pending = _pending(identity)
    store.save_checkpoint(pending)
    _ready(model, identity.analysis_id)

    store.replace_from(pending)

    assert store.require(identity, SimpleStage.PRO_CON_DONE) == pending
    assert _status(model, identity.analysis_id) == "INCOMPLETE"


def test_replace_from_rollback_preserves_ready_index(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    model = DashboardReadModel(data_dir)
    model.initialize()
    identity = _identity()
    pending = _pending(identity)
    store.save_checkpoint(pending)
    _ready(model, identity.analysis_id)

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.replace_from(pending, fail_before_commit=True)

    assert store.require(identity, SimpleStage.PRO_CON_DONE) == pending
    assert _status(model, identity.analysis_id) == "READY"


def test_invalidate_from_dirties_only_when_checkpoint_deleted(tmp_path: Path) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    model = DashboardReadModel(data_dir)
    model.initialize()
    identity = _identity()
    pending = _pending(identity)
    store.save_checkpoint(pending)
    _ready(model, identity.analysis_id)

    store.invalidate_from(identity, SimpleStage.PRO_CON_DONE, new_inputs=(), force=True)

    assert store.get(identity, SimpleStage.PRO_CON_DONE) is None
    assert _status(model, identity.analysis_id) == "INCOMPLETE"
    _ready(model, identity.analysis_id)
    store.invalidate_from(identity, SimpleStage.PRO_CON_DONE, new_inputs=(), force=True)
    assert _status(model, identity.analysis_id) == "READY"


def test_register_free_hypothesis_dirties_index_and_exact_replay_does_not(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    model = DashboardReadModel(data_dir)
    model.initialize()
    child = _identity()
    root = child.model_copy(update={"hypothesis_id": None})
    proposal = SimpleArtifactRepository(data_dir, child).put_json(
        {"kind": "simple_hypothesis_proposal"}
    )
    pending = StageCheckpoint(
        identity=child,
        stage=SimpleStage.PRO_CON_DONE,
        status=StageStatus.PENDING,
        input_refs=(proposal,),
        input_hash=input_reference_hash((proposal,)),
    )
    _ready(model, child.analysis_id)

    store.register_free_hypothesis(root, child.hypothesis_id or "", proposal, pending)

    assert store.require(child, SimpleStage.PRO_CON_DONE) == pending
    assert _status(model, child.analysis_id) == "INCOMPLETE"
    _ready(model, child.analysis_id)
    store.register_free_hypothesis(root, child.hypothesis_id or "", proposal, pending)
    assert _status(model, child.analysis_id) == "READY"


def test_reopen_token_budget_dirties_only_when_checkpoint_reopened(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    model = DashboardReadModel(data_dir)
    model.initialize()
    identity = _identity()
    failed = _pending(identity).model_copy(
        update={
            "status": StageStatus.FAILED,
            "error_code": "LLM_TOKEN_BUDGET_EXHAUSTED",
        }
    )
    store.save_checkpoint(failed)
    _ready(model, identity.analysis_id)

    assert store.reopen_token_budget_failures(identity.analysis_id) == 1
    assert (
        store.require(identity, SimpleStage.PRO_CON_DONE).status is StageStatus.PENDING
    )
    assert _status(model, identity.analysis_id) == "INCOMPLETE"

    _ready(model, identity.analysis_id)
    assert store.reopen_token_budget_failures(identity.analysis_id) == 0
    assert _status(model, identity.analysis_id) == "READY"


def test_recovery_decision_rolls_back_dirty_marker_with_source(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    model = DashboardReadModel(data_dir)
    model.initialize()
    identity = _identity()
    failed = _pending(identity).model_copy(
        update={
            "status": StageStatus.BLOCKED,
            "error_code": "POC_EXECUTION_FAILED",
            "attempt_id": "recovery-attempt",
            "attempt_number": 1,
        }
    )
    store.save_checkpoint(failed)
    decision_ref = SimpleArtifactRepository(data_dir, identity).put_json(
        {"kind": "simple_recovery_decision"}
    )
    resolution = RecoveryResolution(
        decision=RecoveryDecision(
            category=RecoveryCategory.GENERATED_INPUT,
            action=RecoveryAction.REGENERATE_INPUT,
            diagnosis="Test failure",
            guidance="Use a local test fixture",
        ),
        decision_ref=decision_ref,
    )
    _ready(model, identity.analysis_id)

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.record_recovery_decision(failed, resolution, fail_before_commit=True)
    assert _status(model, identity.analysis_id) == "READY"

    store.record_recovery_decision(failed, resolution)
    assert _status(model, identity.analysis_id) == "INCOMPLETE"


def test_fallback_replan_keeps_index_dirty_if_post_commit_projector_fails(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    seeded, artifacts, stopped, _ = _seed(
        tmp_path,
        stderr=b"TypeError: mismatch\nTraceback: __call__ > handler",
    )
    model = DashboardReadModel(data_dir)
    model.initialize()
    _ready(model, stopped.identity.analysis_id)
    calls: list[str] = []

    def failing_project(_data_dir: Path, analysis_id: str) -> None:
        calls.append(analysis_id)
        raise RuntimeError("projector unavailable")

    store = SimpleCheckpointStore(
        seeded.database_path,
        artifact_data_dir=data_dir,
        post_commit_projection=failing_project,
    )

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_fallback_poc_stop_replan(
            stopped, artifacts, fail_before_commit=True
        )
    assert _status(model, stopped.identity.analysis_id) == "READY"
    assert calls == []

    with pytest.raises(RuntimeError, match="projector unavailable"):
        store.prepare_fallback_poc_stop_replan(stopped, artifacts)
    assert calls == [stopped.identity.analysis_id]
    assert _status(model, stopped.identity.analysis_id) == "INCOMPLETE"
    pending = store.require(stopped.identity, SimpleStage.POC_CANDIDATE_DONE)
    assert pending.status is StageStatus.PENDING


def test_candidate_registration_marks_dirty_without_per_item_projection(
    tmp_path: Path,
) -> None:
    seeded, model, root, artifacts, candidate_id = _candidate_setup(tmp_path)
    projected: list[str] = []
    store = SimpleCheckpointStore(
        seeded.database_path,
        artifact_data_dir=tmp_path / "data",
        post_commit_projection=lambda _data, analysis_id: projected.append(analysis_id),
    )
    proposal = artifacts.put_json({"kind": "proposal"})
    pending = _candidate_pending(root, "H-001", proposal)

    store.register_candidate_hypothesis(
        root, "scope-1", candidate_id, "H-001", proposal, checkpoint=pending
    )
    assert _status(model, root.analysis_id) == "INCOMPLETE"
    assert projected == []

    _ready(model, root.analysis_id)
    store.register_candidate_hypothesis(
        root, "scope-1", candidate_id, "H-001", proposal, checkpoint=pending
    )
    assert _status(model, root.analysis_id) == "READY"
    assert projected == []


def test_candidate_batch_registration_rolls_back_and_marks_once(
    tmp_path: Path,
) -> None:
    store, model, root, artifacts, candidate_id = _candidate_setup(tmp_path)
    proposal_a = artifacts.put_json({"kind": "proposal", "n": 1})
    proposal_b = artifacts.put_json({"kind": "proposal", "n": 2})
    first = _candidate_pending(root, "H-001", proposal_a)
    second = _candidate_pending(root, "H-002", proposal_b)
    wrong = second.model_copy(
        update={"identity": root.model_copy(update={"hypothesis_id": "wrong"})}
    )

    with pytest.raises(ValueError, match="CANDIDATE_HYPOTHESIS_CHECKPOINT_INVALID"):
        store.register_candidate_hypotheses_batch(
            root,
            "scope-1",
            candidate_id,
            (("H-001", proposal_a, first), ("H-002", proposal_b, wrong)),
        )
    assert _status(model, root.analysis_id) == "READY"

    registrations = (
        ("H-001", proposal_a, first),
        ("H-002", proposal_b, second),
    )
    store.register_candidate_hypotheses_batch(
        root, "scope-1", candidate_id, registrations
    )
    assert _status(model, root.analysis_id) == "INCOMPLETE"
    _ready(model, root.analysis_id)
    store.register_candidate_hypotheses_batch(
        root, "scope-1", candidate_id, registrations
    )
    assert _status(model, root.analysis_id) == "READY"


def test_candidate_batch_outcome_dirties_only_first_commit(tmp_path: Path) -> None:
    store, model, root, artifacts, candidate_id = _candidate_setup(tmp_path)
    proposal = artifacts.put_json({"kind": "proposal"})
    result_ref = artifacts.put_json({"kind": "candidate_batch_result"})
    pending = _candidate_pending(root, "H-001", proposal)

    def commit() -> bool:
        return store.commit_candidate_batch_outcome(
            root,
            "scope-1",
            candidate_id,
            batch_id="batch-1",
            static_bundle_hash="a" * 64,
            source_sha256=None,
            context_hash="b" * 64,
            status="HYPOTHESES",
            result_ref=result_ref,
            registrations=(("H-001", proposal, pending),),
        )

    assert commit()
    assert _status(model, root.analysis_id) == "INCOMPLETE"
    _ready(model, root.analysis_id)
    assert not commit()
    assert _status(model, root.analysis_id) == "READY"


def test_codex_cleanup_keeps_index_dirty_if_projector_fails(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    identity = _identity()
    artifacts = SimpleArtifactRepository(data_dir, identity)
    seeded = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    seeded.save_analysis_run(
        SimpleAnalysisRun(
            analysis_id=identity.analysis_id,
            display_analysis_id="A-001",
            workspace_id=identity.workspace_id,
            commit_id=identity.commit_id,
            repository="https://example.invalid/repo.git",
            candidate_pipeline_version=1,
        )
    )
    blocked = _pending(identity).model_copy(
        update={
            "status": StageStatus.BLOCKED,
            "attempt_id": "cleanup-attempt",
            "attempt_number": 1,
            "error_code": "CODEX_PROCESS_CLEANUP_UNCONFIRMED",
            "retryable": False,
            "updated_at": datetime.now(UTC) - timedelta(seconds=2),
        }
    )
    seeded.save_checkpoint(blocked)
    confirmation = _cleanup_confirmation(artifacts, blocked)
    model = DashboardReadModel(data_dir)
    model.initialize()
    _ready(model, identity.analysis_id)
    calls: list[str] = []

    def failing_project(_data_dir: Path, analysis_id: str) -> None:
        calls.append(analysis_id)
        raise RuntimeError("projector unavailable")

    store = SimpleCheckpointStore(
        seeded.database_path,
        artifact_data_dir=data_dir,
        post_commit_projection=failing_project,
    )
    with pytest.raises(RuntimeError, match="projector unavailable"):
        store.confirm_codex_cleanup(blocked, confirmation, artifacts)
    assert calls == [identity.analysis_id]
    assert _status(model, identity.analysis_id) == "INCOMPLETE"

    _ready(model, identity.analysis_id)
    store.confirm_codex_cleanup(blocked, confirmation, artifacts)
    assert calls == [identity.analysis_id]
    assert _status(model, identity.analysis_id) == "READY"


def test_codex_call_reservation_dirties_index_without_rebuilding_each_call(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "data"
    model = DashboardReadModel(data_dir)
    model.initialize()
    identity = _identity()
    projected: list[str] = []
    store = SimpleCheckpointStore(
        data_dir / "db" / "sastsimi.sqlite3",
        artifact_data_dir=data_dir,
        post_commit_projection=lambda _data, analysis_id: projected.append(analysis_id),
    )
    _ready(model, identity.analysis_id)

    assert store.begin_codex_call("call-1", identity.analysis_id)
    assert store.unresolved_codex_call(identity.analysis_id) == "call-1"
    assert _status(model, identity.analysis_id) == "INCOMPLETE"
    assert projected == []

    _ready(model, identity.analysis_id)
    assert not store.begin_codex_call("call-2", identity.analysis_id)
    assert _status(model, identity.analysis_id) == "READY"
    assert projected == []


def test_codex_call_reservation_rolls_back_if_atomic_dirty_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data_dir = tmp_path / "data"
    model = DashboardReadModel(data_dir)
    model.initialize()
    identity = _identity()
    store = SimpleCheckpointStore(data_dir / "db" / "sastsimi.sqlite3")
    _ready(model, identity.analysis_id)

    def fail_marker(_connection: sqlite3.Connection, _analysis_id: str) -> None:
        raise RuntimeError("dirty marker failed")

    monkeypatch.setattr(store, "_mark_dashboard_dirty_connection", fail_marker)
    with pytest.raises(RuntimeError, match="dirty marker failed"):
        store.begin_codex_call("call-1", identity.analysis_id)
    assert store.unresolved_codex_call(identity.analysis_id) is None
    assert _status(model, identity.analysis_id) == "READY"
