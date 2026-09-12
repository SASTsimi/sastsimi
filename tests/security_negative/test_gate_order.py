from __future__ import annotations

import pytest

from sastsimi.agents.cwe_labeling import CWELabelingAgent
from sastsimi.contracts.work import WorkType
from sastsimi.reporting.cwe_workflow import CWELabelingService
from sastsimi.runtime.llm_invocation_provenance import (
    validate_llm_invocation_provenance,
)
from tests.integration.reporting.test_cwe_technical_gate import (
    _fixture,
    _gate_call,
    _metadata,
)


@pytest.mark.asyncio
@pytest.mark.parametrize("fault", ["STALE_PROCESS", "UNVALIDATED_POC"])
async def test_cwe_rejects_non_current_validated_true_before_provider(
    fault: str,
) -> None:
    fixture = _fixture()
    work = fixture.work(WorkType.CWE_LABEL, f"fault-{fault.lower()}")
    if fault == "STALE_PROCESS":
        process = fixture.process.model_copy(update={"verification_generation": 2})
        process_ref = fixture.records.add(process)
        poc_ref = fixture.poc_ref
    else:
        process_ref = fixture.process_ref
        invalid = fixture.verification.model_copy(update={"poc_ref": None})
        fixture.verification_ref = fixture.records.add(invalid)
        poc_ref = fixture.poc_ref
    context = (
        fixture.verification_ref,
        fixture.dynamic_ref,
        poc_ref,
        process_ref,
        fixture.evidence_ref,
    )
    call = _gate_call(
        fixture,
        work,
        role="CWE_LABELING",
        task="CLASSIFY_CWE",
        requested_by="CWE_LABELING",
        requester=fixture.cwe_identity,
        action_type="CALL_LLM",
        context=context,
        payload={
            "primary": "CWE-89",
            "alternatives": [],
            "rationale": "must not be consumed",
            "evidence_indexes": [0],
            "uncertainty": None,
        },
    )
    service = CWELabelingService(
        agent=CWELabelingAgent(
            llm_calls=fixture.llm,
            records=fixture.records,
            artifacts=fixture.artifacts,
            metadata_factory=_metadata,
            provenance_validator=validate_llm_invocation_provenance,
        ),
        publisher=fixture.publisher,
        records=fixture.records,
        identity_ref=fixture.cwe_identity,
        taxonomy_version="CWE-4.17",
    )

    with pytest.raises(ValueError, match="STALE_RESULT|VALIDATED_POC_REQUIRED"):
        await service.label(
            work=work,
            process_ref=process_ref,
            verification_ref=fixture.verification_ref,
            dynamic_result_ref=fixture.dynamic_ref,
            poc_ref=poc_ref,
            call=call,
        )

    assert fixture.llm.calls == 0
    assert fixture.publisher.calls == []


@pytest.mark.asyncio
async def test_cwe_provider_cannot_supply_runtime_metadata_or_references() -> None:
    fixture = _fixture()
    work = fixture.work(WorkType.CWE_LABEL, "authority")
    context = (
        fixture.verification_ref,
        fixture.dynamic_ref,
        fixture.poc_ref,
        fixture.process_ref,
        fixture.evidence_ref,
    )
    call = _gate_call(
        fixture,
        work,
        role="CWE_LABELING",
        task="CLASSIFY_CWE",
        requested_by="CWE_LABELING",
        requester=fixture.cwe_identity,
        action_type="CALL_LLM",
        context=context,
        payload={
            "meta": {"record_id": "provider-owned"},
            "verification_result_ref": fixture.verification_ref.model_dump(mode="json"),
            "primary": "CWE-89",
            "alternatives": [],
            "rationale": "invalid authority expansion",
            "evidence_indexes": [0],
            "uncertainty": None,
        },
    )
    service = CWELabelingService(
        agent=CWELabelingAgent(
            llm_calls=fixture.llm,
            records=fixture.records,
            artifacts=fixture.artifacts,
            metadata_factory=_metadata,
            provenance_validator=validate_llm_invocation_provenance,
        ),
        publisher=fixture.publisher,
        records=fixture.records,
        identity_ref=fixture.cwe_identity,
        taxonomy_version="CWE-4.17",
    )

    with pytest.raises(ValueError, match="CWE_OUTPUT_INVALID"):
        await service.label(
            work=work,
            process_ref=fixture.process_ref,
            verification_ref=fixture.verification_ref,
            dynamic_result_ref=fixture.dynamic_ref,
            poc_ref=fixture.poc_ref,
            call=call,
        )

    assert fixture.llm.calls == 1
    assert fixture.publisher.calls == []
