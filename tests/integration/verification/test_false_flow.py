from __future__ import annotations

import pytest

from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.verification.verdict_router import VerdictRouter
from tests.integration.verification.test_verification_service import _Fixture


@pytest.mark.asyncio
async def test_exact_debate_inputs_reach_named_falsification_false() -> None:
    """The production finalizer keeps exact invocation provenance and stops FALSE."""
    fixture = _Fixture()
    fixture.queue(
        fixture.assessment_payload(),
        task_kind="ASSESS_INITIAL",
        context_refs=fixture.assessment_context(),
    )
    assessment_outcome = await fixture.service.assess_initial_with_invocation(
        generation=fixture.generation,
        pro_ref=fixture.pro_ref,
        con_ref=fixture.con_ref,
        call=fixture.call,
    )
    assessment_ref = reference(assessment_outcome.record)
    assert isinstance(assessment_ref, StoredDataRef)
    fixture.queue(
        fixture.final_payload(),
        task_kind="FINAL_VERDICT",
        context_refs=(*fixture.assessment_context(), assessment_ref),
    )

    final_outcome = await fixture.service.finalize_without_dynamic_with_invocation(
        generation=fixture.generation,
        assessment_ref=assessment_ref,
        pro_ref=fixture.pro_ref,
        con_ref=fixture.con_ref,
        call=fixture.call,
    )
    result_ref = reference(final_outcome.record)
    assert isinstance(result_ref, StoredDataRef)

    assert final_outcome.record.verdict == "FALSE"
    assert any(
        item.outcome == "DISPROVED"
        for item in final_outcome.record.falsification_results
    )
    assert (
        assessment_outcome.invocation.request.llm_call_id
        != final_outcome.invocation.request.llm_call_id
    )
    assert VerdictRouter(fixture.records).route(result_ref) == ()  # type: ignore[arg-type]
