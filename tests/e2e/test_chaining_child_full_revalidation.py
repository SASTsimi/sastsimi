from __future__ import annotations

from types import SimpleNamespace

import pytest

from sastsimi.chaining.work_handlers import HypothesisProposalHandler
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.work import WorkAttempt, WorkExecutionState
from sastsimi.ports.dto import WorkContext
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import wire


def _ref(kind: str) -> StoredDataRef:
    return StoredDataRef.model_construct(
        stored_data_id=f"stored-{kind}",
        data_kind=kind,
        content_hash="a" * 64,
        workspace_id="ws1",
        commit_id="c1",
        record_id=f"record-{kind}",
    )


def _context() -> WorkContext:
    source = _ref("chaining_result")
    inputs = (source,)
    meta = wire(
        RecordMeta,
        make("WorkExecutionState")["meta"]
        | {
            "record_type": "work_execution_state",
            "hypothesis_id": None,
            "attempt_id": None,
        },
    )
    work = WorkExecutionState.model_construct(
        meta=meta,
        work_id="child-work",
        work_type="HYPOTHESIS_PROPOSAL",
        subject_type="PROPOSAL",
        subject_id="child-proposal",
        status="RUNNING",
        active_attempt_id="child-attempt",
        input_refs=inputs,
        input_hash=content_hash(inputs),
    )
    attempt = WorkAttempt.model_construct(
        meta=meta.model_copy(update={"attempt_id": "child-attempt"}),
        work_id="child-work",
        attempt_id="child-attempt",
        status="RUNNING",
        input_hash=content_hash(inputs),
    )
    return WorkContext(work, attempt)


class _Registration:
    def __init__(self) -> None:
        self.call: dict[str, object] | None = None

    def register_claimed(self, **kwargs: object) -> object:
        self.call = kwargs
        proposal_ref = _ref("hypothesis_proposal")
        hypothesis_ref = _ref("vulnerability_hypothesis")
        process_ref = _ref("hypothesis_process_state")
        return SimpleNamespace(
            source_result_ref=kwargs["source_result_ref"],
            proposal=SimpleNamespace(
                proposal_id=kwargs["proposal_id"],
                origin="CHAINING",
            ),
            proposal_ref=proposal_ref,
            hypothesis_ref=hypothesis_ref,
            process_ref=process_ref,
            verification_work=WorkExecutionState.model_construct(
                work_id="verification-work",
                work_type="VERIFICATION",
                status="READY",
                active_attempt_id=None,
                output_refs=(),
            ),
        )


@pytest.mark.asyncio
async def test_chaining_child_revalidates_without_inherited_verdict() -> None:
    registration = _Registration()
    context = _context()
    handler = HypothesisProposalHandler(
        registration=registration,  # type: ignore[arg-type]
        requester_identity_ref=_ref("requester_identity"),
    )

    result = await handler.execute(context)

    assert registration.call is not None
    assert registration.call["context"] is context
    assert str(registration.call["proposal_id"]) == "child-proposal"
    assert tuple(ref.data_kind for ref in result.output_refs) == (
        "hypothesis_proposal",
        "vulnerability_hypothesis",
        "hypothesis_process_state",
    )
    assert "verdict" not in registration.call
