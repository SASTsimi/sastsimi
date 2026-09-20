from __future__ import annotations

import hashlib

import pytest

from sastsimi.contracts.ids import CommitId, RecordId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _ref(name: str) -> StoredDataRef:
    digest = hashlib.sha256(name.encode()).hexdigest()
    return StoredDataRef(
        stored_data_id=StoredDataId(f"{name}-stored"),
        data_kind="simple_runtime_test",
        content_hash=digest,
        workspace_id=WorkspaceId("workspace-1"),
        commit_id=CommitId("commit-1"),
        record_id=RecordId(f"{name}-record"),
    )


def _identity() -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="commit-1",
        hypothesis_id="hypothesis-1",
    )


def _checkpoint(
    stage: SimpleStage | str,
    *,
    inputs: tuple[StoredDataRef, ...],
) -> StageCheckpoint:
    return StageCheckpoint(
        identity=_identity(),
        stage=SimpleStage(stage),
        status=StageStatus.PENDING,
        input_refs=inputs,
        input_hash=input_reference_hash(inputs),
    )


def test_resume_reuses_exact_success_and_invalidates_changed_downstream(
    tmp_path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    first = _checkpoint("POC_EXECUTION_DONE", inputs=(_ref("candidate-a"),))
    store.save_success(first, outputs=(_ref("execution-a"),))
    store.save_success(
        _checkpoint("TECH_GATE_DONE", inputs=(_ref("execution-a"),)),
        outputs=(_ref("gate-a"),),
    )

    assert store.reusable(first.identity, first.stage, first.input_refs)
    store.invalidate_from(
        first.identity,
        SimpleStage.POC_EXECUTION_DONE,
        new_inputs=(_ref("candidate-b"),),
    )

    assert not store.reusable(
        first.identity,
        SimpleStage.POC_EXECUTION_DONE,
        (_ref("candidate-b"),),
    )
    assert store.get(first.identity, SimpleStage.TECH_GATE_DONE) is None


def test_failed_transaction_never_publishes_success_or_false(tmp_path) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    current = _checkpoint("POC_EXECUTION_DONE", inputs=(_ref("candidate-a"),))

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.save_success(
            current,
            outputs=(_ref("execution-a"),),
            fail_before_commit=True,
        )

    restored = store.get(current.identity, current.stage)
    assert restored is None or restored.status != StageStatus.SUCCEEDED
    assert store.validated_poc(current.identity) is None
    assert store.verdict(current.identity) is None
