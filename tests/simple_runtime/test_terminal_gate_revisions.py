"""Bounded Gate revision recreates PoC evidence without manufacturing a Finding."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from pathlib import Path

import pytest

from sastsimi.contracts.ids import CommitId, RecordId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.models import (
    HYPOTHESIS_STAGES,
    STAGE_VERSION,
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageResult,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.runner import SimpleRuntimeRunner
from sastsimi.simple_runtime.store import SimpleCheckpointStore


def _ref(name: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(f"{name}-stored"),
        data_kind="simple_runtime_test",
        content_hash=hashlib.sha256(name.encode()).hexdigest(),
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


def _seed_through(store: SimpleCheckpointStore, last: SimpleStage) -> None:
    inputs = (_ref("hypothesis-input"),)
    for stage in HYPOTHESIS_STAGES:
        checkpoint = StageCheckpoint(
            identity=_identity(),
            stage=stage,
            stage_version=STAGE_VERSION[stage],
            status=StageStatus.PENDING,
            input_refs=inputs,
            input_hash=input_reference_hash(inputs),
        )
        output = _ref(f"{stage.value.lower()}-output")
        store.save_success(checkpoint, outputs=(output,))
        inputs = (output,)
        if stage is last:
            return
    raise AssertionError("missing stage")


def _handlers(calls: list[SimpleStage]) -> dict[SimpleStage, object]:
    handlers: dict[SimpleStage, object] = {}
    for stage in HYPOTHESIS_STAGES:

        async def run(
            _checkpoint: StageCheckpoint,
            _prior: Mapping[SimpleStage, StageCheckpoint],
            *,
            current: SimpleStage = stage,
        ) -> StageResult:
            calls.append(current)
            return StageResult(output_refs=(_ref(f"{current.value.lower()}-new"),))

        handlers[stage] = run
    return handlers


@pytest.mark.asyncio
async def test_gate_revision_replays_candidate_and_execution_with_exact_feedback(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    _seed_through(store, SimpleStage.CWE_DONE)
    gate = store.mark_running(
        _identity(),
        SimpleStage.TECH_GATE_DONE,
        store.input_refs_for(_identity(), SimpleStage.TECH_GATE_DONE),
        attempt_id="gate-1",
    )
    feedback = _ref("gate-production-route-request")
    store.complete(gate, StageResult(output_refs=(feedback,), gate_decision="REVISE"))
    calls: list[SimpleStage] = []
    handlers = _handlers(calls)
    candidate_inputs: tuple[StoredDataRef, ...] = ()
    candidate_attempt = ""

    async def candidate(
        checkpoint: StageCheckpoint, _prior: Mapping[SimpleStage, StageCheckpoint]
    ) -> StageResult:
        nonlocal candidate_inputs, candidate_attempt
        calls.append(SimpleStage.POC_CANDIDATE_DONE)
        candidate_inputs = checkpoint.input_refs
        candidate_attempt = checkpoint.attempt_id or ""
        return StageResult(output_refs=(_ref("new-candidate"), _ref("new-script")))

    async def execution(
        checkpoint: StageCheckpoint, _prior: Mapping[SimpleStage, StageCheckpoint]
    ) -> StageResult:
        calls.append(SimpleStage.POC_EXECUTION_DONE)
        assert checkpoint.attempt_id == candidate_attempt
        return StageResult(output_refs=(_ref("new-execution"),))

    async def accepted_gate(
        checkpoint: StageCheckpoint, _prior: Mapping[SimpleStage, StageCheckpoint]
    ) -> StageResult:
        calls.append(SimpleStage.TECH_GATE_DONE)
        assert checkpoint.gate_revision_count == 1
        return StageResult(output_refs=(_ref("gate-accepted"),), gate_decision="ACCEPT")

    handlers[SimpleStage.POC_CANDIDATE_DONE] = candidate
    handlers[SimpleStage.POC_EXECUTION_DONE] = execution
    handlers[SimpleStage.TECH_GATE_DONE] = accepted_gate

    outcome = await SimpleRuntimeRunner(store, handlers).resume_analysis(_identity())

    assert outcome.status is StageStatus.SUCCEEDED
    assert outcome.current_stage is SimpleStage.REPORT_DONE
    assert calls[:5] == [
        SimpleStage.POC_CANDIDATE_DONE,
        SimpleStage.POC_EXECUTION_DONE,
        SimpleStage.VERIFICATION_FINAL_DONE,
        SimpleStage.CWE_DONE,
        SimpleStage.TECH_GATE_DONE,
    ]
    assert candidate_inputs[0] == feedback
    assert (
        store.require(_identity(), SimpleStage.POC_CANDIDATE_DONE).gate_revision_count
        == 1
    )


@pytest.mark.asyncio
async def test_third_gate_revise_is_terminal_and_resume_never_repeats_poc(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    _seed_through(store, SimpleStage.POC_EXECUTION_DONE)
    calls: list[SimpleStage] = []
    attempt_pairs: list[tuple[str, str]] = []
    handlers = _handlers(calls)

    async def candidate(
        checkpoint: StageCheckpoint, _prior: Mapping[SimpleStage, StageCheckpoint]
    ) -> StageResult:
        calls.append(SimpleStage.POC_CANDIDATE_DONE)
        attempt_pairs.append((checkpoint.attempt_id or "", ""))
        return StageResult(
            output_refs=(
                _ref(f"candidate-{len(attempt_pairs)}"),
                _ref(f"script-{len(attempt_pairs)}"),
            )
        )

    async def execution(
        checkpoint: StageCheckpoint, _prior: Mapping[SimpleStage, StageCheckpoint]
    ) -> StageResult:
        calls.append(SimpleStage.POC_EXECUTION_DONE)
        candidate_id, _ = attempt_pairs[-1]
        attempt_pairs[-1] = (candidate_id, checkpoint.attempt_id or "")
        return StageResult(output_refs=(_ref(f"execution-{len(attempt_pairs)}"),))

    async def final_verification(
        checkpoint: StageCheckpoint, _prior: Mapping[SimpleStage, StageCheckpoint]
    ) -> StageResult:
        calls.append(SimpleStage.VERIFICATION_FINAL_DONE)
        return StageResult(
            output_refs=(_ref(f"final-{checkpoint.gate_revision_count}"),),
            validated_poc_ref=_ref("validated-poc"),
            verdict="TRUE",
        )

    async def gate(
        checkpoint: StageCheckpoint, _prior: Mapping[SimpleStage, StageCheckpoint]
    ) -> StageResult:
        calls.append(SimpleStage.TECH_GATE_DONE)
        decision_number = calls.count(SimpleStage.TECH_GATE_DONE)
        assert checkpoint.gate_revision_count == decision_number - 1
        return StageResult(
            output_refs=(_ref(f"revision-request-{decision_number}"),),
            gate_decision="REVISE",
        )

    handlers[SimpleStage.POC_CANDIDATE_DONE] = candidate
    handlers[SimpleStage.POC_EXECUTION_DONE] = execution
    handlers[SimpleStage.VERIFICATION_FINAL_DONE] = final_verification
    handlers[SimpleStage.TECH_GATE_DONE] = gate
    runner = SimpleRuntimeRunner(store, handlers)

    outcome = await runner.resume_analysis(_identity())

    assert outcome.status is StageStatus.SUCCEEDED
    assert outcome.current_stage is SimpleStage.TECH_GATE_DONE
    assert outcome.error_code is None
    assert calls.count(SimpleStage.TECH_GATE_DONE) == 3
    assert calls.count(SimpleStage.POC_CANDIDATE_DONE) == 2
    assert calls.count(SimpleStage.POC_EXECUTION_DONE) == 2
    assert len({candidate_id for candidate_id, _ in attempt_pairs}) == 2
    assert all(
        candidate_id == execution_id for candidate_id, execution_id in attempt_pairs
    )
    assert SimpleStage.SCOPE_GATE_DONE not in calls
    assert SimpleStage.FINDING_DONE not in calls
    assert SimpleStage.REPORT_DONE not in calls
    assert (
        store.require(_identity(), SimpleStage.TECH_GATE_DONE).gate_revision_count == 2
    )
    assert await runner.resume_analysis(_identity()) == outcome
    assert calls.count(SimpleStage.TECH_GATE_DONE) == 3


@pytest.mark.asyncio
async def test_gate_reject_stops_before_scope_finding_and_report(
    tmp_path: Path,
) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    _seed_through(store, SimpleStage.CWE_DONE)
    calls: list[SimpleStage] = []
    handlers = _handlers(calls)

    async def gate(
        _checkpoint: StageCheckpoint, _prior: Mapping[SimpleStage, StageCheckpoint]
    ) -> StageResult:
        calls.append(SimpleStage.TECH_GATE_DONE)
        return StageResult(output_refs=(_ref("gate-rejected"),), gate_decision="REJECT")

    handlers[SimpleStage.TECH_GATE_DONE] = gate
    runner = SimpleRuntimeRunner(store, handlers)

    outcome = await runner.resume_analysis(_identity())

    assert outcome.status is StageStatus.SUCCEEDED
    assert outcome.current_stage is SimpleStage.TECH_GATE_DONE
    assert calls == [SimpleStage.TECH_GATE_DONE]
    assert store.get(_identity(), SimpleStage.FINDING_DONE) is None
    assert await runner.resume_analysis(_identity()) == outcome
    assert calls == [SimpleStage.TECH_GATE_DONE]


def test_gate_rewind_is_atomic_and_idempotent_after_crash(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    _seed_through(store, SimpleStage.CWE_DONE)
    running = store.mark_running(
        _identity(),
        SimpleStage.TECH_GATE_DONE,
        store.input_refs_for(_identity(), SimpleStage.TECH_GATE_DONE),
        attempt_id="gate-1",
    )
    gate = store.complete(
        running,
        StageResult(output_refs=(_ref("gate-feedback"),), gate_decision="REVISE"),
    )
    original_candidate = store.require(_identity(), SimpleStage.POC_CANDIDATE_DONE)

    with pytest.raises(RuntimeError, match="simulated crash"):
        store.prepare_gate_revision(gate, fail_before_commit=True)
    assert (
        store.require(_identity(), SimpleStage.POC_CANDIDATE_DONE) == original_candidate
    )
    assert store.require(_identity(), SimpleStage.TECH_GATE_DONE) == gate

    pending = store.prepare_gate_revision(gate)
    assert pending.status is StageStatus.PENDING
    assert pending.stage is SimpleStage.POC_CANDIDATE_DONE
    assert pending.gate_revision_count == 1
    assert pending.input_refs[0] == gate.output_refs[0]
    assert store.get(_identity(), SimpleStage.TECH_GATE_DONE) is None
    assert store.prepare_gate_revision(gate) == pending


def test_gate_budget_is_independent_of_poc_repair_attempts(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    _seed_through(store, SimpleStage.CWE_DONE)
    candidate = store.require(_identity(), SimpleStage.POC_CANDIDATE_DONE)
    store.save_checkpoint(candidate.model_copy(update={"attempt_number": 3}))
    running = store.mark_running(
        _identity(),
        SimpleStage.TECH_GATE_DONE,
        store.input_refs_for(_identity(), SimpleStage.TECH_GATE_DONE),
        attempt_id="gate-after-repairs",
    )
    gate = store.complete(
        running,
        StageResult(output_refs=(_ref("first-gate-request"),), gate_decision="REVISE"),
    )

    assert gate.gate_revision_count == 0
    assert store.prepare_gate_revision(gate).gate_revision_count == 1


@pytest.mark.asyncio
async def test_stale_candidate_version_reexecutes_poc(tmp_path: Path) -> None:
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    _seed_through(store, SimpleStage.POC_EXECUTION_DONE)
    candidate = store.require(_identity(), SimpleStage.POC_CANDIDATE_DONE)
    store.save_checkpoint(candidate.model_copy(update={"stage_version": "1"}))
    calls: list[SimpleStage] = []

    await SimpleRuntimeRunner(store, _handlers(calls)).resume_analysis(_identity())

    assert SimpleStage.POC_CANDIDATE_DONE in calls
    assert SimpleStage.POC_EXECUTION_DONE in calls
