from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest

from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import StaticFactBundle
from sastsimi.contracts.work import (
    AttemptStatus,
    AttemptTrigger,
    SubjectType,
    WorkAttempt,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.orchestration.production_llm_work_handlers import (
    EvidenceBranchWorkHandler,
    HypothesisProposalWorkHandler,
)
from sastsimi.ports.dto import WorkContext
from tests.contract.domain.canonical_fixtures import make


def _ref(kind: str, name: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=name,
        data_kind=kind,
        content_hash=hashlib.sha256(name.encode()).hexdigest(),
        workspace_id="ws1",
        commit_id="c1",
        record_id=f"{name}-record",
    )


def _meta(
    kind: str, name: str, *, hypothesis_id: str | None, attempt_id: str | None
) -> RecordMeta:
    source = make("WorkExecutionState")["meta"]
    return RecordMeta.model_validate(
        source
        | {
            "record_id": f"{name}-record",
            "logical_record_id": f"{name}-logical",
            "record_type": kind,
            "analysis_id": "a1",
            "workspace_id": "ws1",
            "commit_id": "c1",
            "hypothesis_id": hypothesis_id,
            "attempt_id": attempt_id,
            "created_at": datetime(2026, 9, 13, tzinfo=UTC),
        }
    )


def _context(
    work_type: WorkType,
    inputs: tuple[StoredDataRef, ...],
    *,
    hypothesis_id: str | None = None,
    subject_type: SubjectType = SubjectType.ANALYSIS,
    subject_id: str = "a1",
    parent_ref: StoredDataRef | None = None,
) -> WorkContext:
    attempt_id = f"{work_type.value.lower()}-attempt"
    work = WorkExecutionState.model_validate(
        {
            "meta": _meta(
                "work_execution_state",
                f"{work_type.value.lower()}-work",
                hypothesis_id=hypothesis_id,
                attempt_id=None,
            ),
            "work_id": f"{work_type.value.lower()}-work",
            "parent_work_ref": parent_ref,
            "work_type": work_type,
            "subject_type": subject_type,
            "subject_id": subject_id,
            "work_generation": 1,
            "status": WorkStatus.RUNNING,
            "state_version": 3,
            "last_transition_ref": _ref("state_transition", "transition"),
            "last_transition_commit_ref": None,
            "active_attempt_id": attempt_id,
            "input_hash": content_hash(inputs),
            "dedupe_key": "d" * 64,
            "trigger_primitive_ref": None,
            "input_refs": inputs,
            "output_refs": (),
            "gap_ids": (),
            "error_ids": (),
            "waiting_for": (),
            "stop_reason": None,
            "started_at": _meta(
                "work_execution_state",
                "time",
                hypothesis_id=hypothesis_id,
                attempt_id=None,
            ).created_at,
            "finished_at": None,
            "elapsed_ms": 0,
        }
    )
    attempt = WorkAttempt.model_validate(
        {
            "meta": _meta(
                "work_attempt",
                f"{work_type.value.lower()}-attempt-record",
                hypothesis_id=hypothesis_id,
                attempt_id=attempt_id,
            ),
            "work_id": work.work_id,
            "attempt_id": attempt_id,
            "attempt_number": 1,
            "trigger": AttemptTrigger.INITIAL,
            "input_hash": work.input_hash,
            "status": AttemptStatus.RUNNING,
            "output_refs": (),
            "gap_ids": (),
            "error_ids": (),
            "started_at": work.started_at,
            "finished_at": None,
            "elapsed_ms": 0,
        }
    )
    return WorkContext(work, attempt)


class _Records:
    def __init__(self, values: dict[StoredDataRef, object]) -> None:
        self.values = values

    def get_exact(self, ref: object) -> object:
        return self.values[ref]  # type: ignore[index]


class _Calls:
    def __init__(self) -> None:
        self.requests: list[tuple[str, str, tuple[StoredDataRef, ...]]] = []
        self.settled: list[object] = []

    def resolve(
        self,
        *,
        work: WorkExecutionState,
        role: str,
        task_kind: str,
        source_refs: tuple[StoredDataRef, ...],
    ) -> Any:
        self.requests.append((role, task_kind, source_refs))
        return SimpleNamespace(
            work=work,
            decision_ref=_ref("action_decision", "allow"),
            reservation_ref=_ref("budget_reservation", "reserve"),
            call_spec_ref=_ref("llm_call_spec", "spec"),
        )

    def settle(self, call: object, invocation: object) -> None:
        self.settled.append((call, invocation))


@dataclass
class _HypothesisWorkflow:
    output_ref: StoredDataRef

    async def run(self, **kwargs: object) -> Any:
        work = kwargs["work"]
        assert isinstance(work, WorkExecutionState)
        completed = work.model_copy(
            update={
                "status": WorkStatus.SUCCEEDED,
                "active_attempt_id": None,
                "output_refs": (self.output_ref,),
            }
        )
        return SimpleNamespace(
            outcome=SimpleNamespace(
                invocation=SimpleNamespace(result=SimpleNamespace(status="SUCCEEDED"))
            ),
            completed_work=completed,
        )


@pytest.mark.asyncio
async def test_hypothesis_handler_uses_exact_bundle_and_settles_real_call() -> None:
    bundle = StaticFactBundle.model_validate_json(
        __import__("json").dumps(make("StaticFactBundle"))
    )
    bundle_ref = reference(bundle)
    assert isinstance(bundle_ref, StoredDataRef)
    proposal_ref = _ref("hypothesis_proposal", "proposal")
    context = _context(WorkType.HYPOTHESIS_PROPOSAL, (bundle_ref,))
    calls = _Calls()
    handler = HypothesisProposalWorkHandler(
        records=_Records({bundle_ref: bundle}),
        workflow=_HypothesisWorkflow(proposal_ref),
        calls=calls,
        orchestration_identity_ref=_ref("role_identity", "orchestrator"),
    )

    result = await handler.execute(context)

    assert result.output_refs == (proposal_ref,)
    assert calls.requests == [
        ("HYPOTHESIS", "GENERATE_INITIAL", (bundle_ref,))
    ]
    assert len(calls.settled) == 1


@pytest.mark.asyncio
async def test_hypothesis_handler_rejects_exact_ref_mismatch_before_llm_call() -> None:
    bundle = StaticFactBundle.model_validate_json(
        __import__("json").dumps(make("StaticFactBundle"))
    )
    exact_ref = reference(bundle)
    assert isinstance(exact_ref, StoredDataRef)
    wrong_ref = exact_ref.model_copy(update={"content_hash": "f" * 64})
    context = _context(WorkType.HYPOTHESIS_PROPOSAL, (wrong_ref,))
    calls = _Calls()
    handler = HypothesisProposalWorkHandler(
        records=_Records({wrong_ref: bundle}),
        workflow=_HypothesisWorkflow(_ref("hypothesis_proposal", "proposal")),
        calls=calls,
        orchestration_identity_ref=_ref("role_identity", "orchestrator"),
    )

    with pytest.raises(ValueError, match="HYPOTHESIS_STATIC_CLOSURE_MISMATCH"):
        await handler.execute(context)

    assert calls.requests == []


@pytest.mark.asyncio
async def test_evidence_handler_executes_one_claimed_branch_without_waiting() -> None:
    debate_ref = _ref("static_fact_bundle", "facts")
    parent = _context(
        WorkType.VERIFICATION,
        (_ref("vulnerability_hypothesis", "hypothesis"),),
        hypothesis_id="h1",
        subject_type=SubjectType.HYPOTHESIS,
        subject_id="h1",
    ).work.model_copy(
        update={"status": WorkStatus.PENDING, "active_attempt_id": None}
    )
    parent_ref = reference(parent)
    assert isinstance(parent_ref, StoredDataRef)
    context = _context(
        WorkType.PRO_EVIDENCE,
        (debate_ref,),
        hypothesis_id="h1",
        subject_type=SubjectType.HYPOTHESIS,
        subject_id="h1",
        parent_ref=parent_ref,
    )
    output_ref = _ref("pro_evidence_result", "pro")
    calls = _Calls()
    joined: list[tuple[StoredDataRef, StoredDataRef]] = []

    class _Debate:
        async def run_branch(self, **kwargs: object) -> Any:
            assert kwargs["parent_work"] == parent
            assert kwargs["role"] == "PRO"
            return SimpleNamespace(
                output_ref=output_ref,
                invocation=SimpleNamespace(result=SimpleNamespace(status="SUCCEEDED")),
            )

    handler = EvidenceBranchWorkHandler(
        role="PRO",
        records=_Records({parent_ref: parent}),
        debate=_Debate(),
        calls=calls,
        evidence_committed=lambda parent, output: joined.append((parent, output)),
    )

    result = await handler.execute(context)

    assert result.output_refs == (output_ref,)
    assert calls.requests == [("PRO", "COLLECT_SUPPORT", (debate_ref,))]
    assert joined == [(parent_ref, output_ref)]
