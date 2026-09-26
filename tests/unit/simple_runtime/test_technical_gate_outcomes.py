"""A Gate decision is durable data, and only an exact ACCEPT is reportable."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal, cast

import pytest
from pydantic import JsonValue

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.chaining import PrimitiveAdmissionStage
from sastsimi.simple_runtime.models import (
    CheckpointIdentity,
    SimpleStage,
    StageCheckpoint,
    StageStatus,
    input_reference_hash,
)
from sastsimi.simple_runtime.provider import SimpleLLMCallResult
from sastsimi.simple_runtime.runner import StageBlocked, StageFailed
from sastsimi.simple_runtime.stages import (
    FindingStage,
    ReporterStage,
    TechnicalGateStage,
)
from sastsimi.simple_runtime.store import SimpleCheckpointStore


class _GateClient:
    def __init__(self, status: str, requests: list[str] | None = None) -> None:
        self.status = status
        self.requests = requests if requests is not None else ["Use a production route"]

    async def call(self, **_kwargs: Any) -> SimpleLLMCallResult:
        value: dict[str, JsonValue] = {
            "status": self.status,
            "rationale": "Exact evidence review",
            "checks": ["source and PoC compared"],
            "revision_requests": cast(JsonValue, self.requests),
        }
        return SimpleLLMCallResult(
            value=value,
            prompt_digest="a" * 64,
            output_digest="b" * 64,
        )


def _identity() -> CheckpointIdentity:
    return CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id="hypothesis-1",
    )


def _checkpoint(
    stage: SimpleStage,
    *,
    outputs: tuple[StoredDataRef, ...] = (),
    verdict: Literal["TRUE", "FALSE", "HOLD"] | None = None,
    validated_poc_ref: StoredDataRef | None = None,
    gate_decision: Literal["ACCEPT", "REVISE", "REJECT"] | None = None,
) -> StageCheckpoint:
    checkpoint = StageCheckpoint(
        identity=_identity(),
        stage=stage,
        status=StageStatus.SUCCEEDED,
        input_refs=(),
        input_hash=input_reference_hash(()),
        output_refs=outputs,
        verdict=verdict,
        validated_poc_ref=validated_poc_ref,
        gate_decision=gate_decision,
    )
    return checkpoint


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", ["ACCEPT", "REVISE", "REJECT"])
async def test_valid_gate_decision_and_exact_artifact_survive_checkpoint_reload(
    tmp_path: Path, decision: str
) -> None:
    artifacts = SimpleArtifactRepository(tmp_path, _identity())
    store = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3")
    running = store.mark_running(
        _identity(), SimpleStage.TECH_GATE_DONE, (), attempt_id="gate-1"
    )

    result = await TechnicalGateStage(_GateClient(decision), artifacts)(running, {})
    completed = store.complete(running, result)
    reloaded = SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3").require(
        _identity(), SimpleStage.TECH_GATE_DONE
    )

    assert completed.status is StageStatus.SUCCEEDED
    assert reloaded.gate_decision == decision
    assert reloaded.output_refs == result.output_refs
    artifact = json.loads(artifacts.read(reloaded.output_refs[0]))
    assert artifact["result"]["status"] == decision


@pytest.mark.asyncio
async def test_empty_revise_request_is_retryable_error_not_terminal_decision(
    tmp_path: Path,
) -> None:
    artifacts = SimpleArtifactRepository(tmp_path, _identity())
    checkpoint = _checkpoint(SimpleStage.TECH_GATE_DONE)

    with pytest.raises(StageBlocked) as raised:
        await TechnicalGateStage(_GateClient("REVISE", []), artifacts)(checkpoint, {})

    assert raised.value.failure.code == "TECH_GATE_REVISION_REQUEST_EMPTY"
    assert raised.value.failure.retryable
    assert len(raised.value.failure.evidence_refs) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("checkpoint_decision", "artifact_decision"),
    [("ACCEPT", "REVISE"), ("REVISE", "ACCEPT"), ("REJECT", "ACCEPT")],
)
async def test_true_finding_and_primitive_refuse_mismatched_gate(
    tmp_path: Path,
    checkpoint_decision: Literal["ACCEPT", "REVISE", "REJECT"],
    artifact_decision: str,
) -> None:
    artifacts = SimpleArtifactRepository(tmp_path, _identity())
    poc_ref = artifacts.put_json({"kind": "simple_validated_poc"})
    verification_ref = artifacts.put_json(
        {"result": {"required_capabilities": [], "provided_capabilities": ["read"]}}
    )
    gate_ref = artifacts.put_json({"result": {"status": artifact_decision}})
    scope_ref = artifacts.put_json(
        {"result": {"status": "ALLOW", "testing_restriction_compliance": "PASS"}}
    )
    prior = {
        SimpleStage.VERIFICATION_FINAL_DONE: _checkpoint(
            SimpleStage.VERIFICATION_FINAL_DONE,
            outputs=(verification_ref,),
            verdict="TRUE",
            validated_poc_ref=poc_ref,
        ),
        SimpleStage.TECH_GATE_DONE: _checkpoint(
            SimpleStage.TECH_GATE_DONE,
            outputs=(gate_ref,),
            gate_decision=checkpoint_decision,
        ),
        SimpleStage.SCOPE_GATE_DONE: _checkpoint(
            SimpleStage.SCOPE_GATE_DONE, outputs=(scope_ref,)
        ),
    }

    with pytest.raises(StageFailed) as finding_error:
        await FindingStage(artifacts)(_checkpoint(SimpleStage.FINDING_DONE), prior)
    with pytest.raises(StageFailed) as primitive_error:
        await PrimitiveAdmissionStage(artifacts)(
            _checkpoint(SimpleStage.PRIMITIVE_ADMISSION_DONE), prior
        )

    assert finding_error.value.failure.code == "FINDING_GATE_NOT_ACCEPTED"
    assert primitive_error.value.failure.code == "PRIMITIVE_GATE_NOT_ACCEPTED"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("checkpoint_decision", "artifact_decision"),
    [("ACCEPT", "REVISE"), ("REVISE", "ACCEPT")],
)
async def test_reporter_refuses_mismatched_gate_before_drafting(
    tmp_path: Path,
    checkpoint_decision: Literal["ACCEPT", "REVISE", "REJECT"],
    artifact_decision: str,
) -> None:
    artifacts = SimpleArtifactRepository(tmp_path, _identity())
    finding_ref = artifacts.put_json({"kind": "simple_finding"})
    poc_ref = artifacts.put_json({"kind": "simple_validated_poc"})
    gate_ref = artifacts.put_json({"result": {"status": artifact_decision}})
    prior = {
        SimpleStage.FINDING_DONE: _checkpoint(
            SimpleStage.FINDING_DONE,
            outputs=(finding_ref,),
            verdict="TRUE",
            validated_poc_ref=poc_ref,
        ),
        SimpleStage.POC_EXECUTION_DONE: _checkpoint(
            SimpleStage.POC_EXECUTION_DONE, validated_poc_ref=poc_ref
        ),
        SimpleStage.TECH_GATE_DONE: _checkpoint(
            SimpleStage.TECH_GATE_DONE,
            outputs=(gate_ref,),
            gate_decision=checkpoint_decision,
        ),
    }

    with pytest.raises(StageFailed) as raised:
        await ReporterStage(_GateClient("ACCEPT"), artifacts)(
            _checkpoint(SimpleStage.REPORT_DONE), prior
        )

    assert raised.value.failure.code == "REPORT_GATE_NOT_ACCEPTED"
