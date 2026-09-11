"""Security-negative checks for Pro/Con role isolation."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import LLMCallSpec, PromptContextBinding, PromptPayload
from sastsimi.verification.debate_service import DebateService

sys.path.append(str(Path(__file__).parents[1] / "integration" / "verification"))

from test_debate_service import (  # type: ignore[import-not-found]  # noqa: E402
    ClaimIds,
    ConcurrentLLMCalls,
    MemoryArtifacts,
    MemoryRecords,
    MetadataFactory,
    RecordingPublisher,
    _authorized_call,
    _output,
    _ref,
    _work,
)


@pytest.mark.asyncio
async def test_cross_role_private_result_stops_parent_without_verdict() -> None:
    """Catches a Con result being added only to the private Pro prompt closure."""
    public_inputs = tuple(
        sorted(
            (
                _ref("static_fact_bundle", "facts"),
                _ref("playbook_application", "application"),
            ),
            key=canonical_bytes,
        )
    )
    parent = _work("VERIFICATION", public_inputs)
    pro_work = _work("PRO", public_inputs, parent=parent)
    con_work = _work("CON", public_inputs, parent=parent)
    records, artifacts = MemoryRecords(), MemoryArtifacts()
    pro_call = _authorized_call(records, "PRO", pro_work, public_inputs)
    con_call = _authorized_call(records, "CON", con_work, public_inputs)
    private_con_ref = _ref("con_evidence_result", "private-con-result")
    original_spec = records.get_exact(pro_call.call_spec_ref)
    assert isinstance(original_spec, LLMCallSpec)
    original_payload = records.get_exact(original_spec.prompt_payload_ref)
    assert isinstance(original_payload, PromptPayload)
    private_binding = PromptContextBinding(
        slot="private-con",
        data_kind=private_con_ref.data_kind,
        source_ref=private_con_ref,
        projected_data_ref=_ref("artifact", "private-con-projection", record=False),
        field_paths=("evidence",),
        trust_class="UNTRUSTED_DATA",
    )
    tainted_payload = original_payload.model_copy(
        update={
            "context_bindings": (*original_payload.context_bindings, private_binding)
        }
    )
    tainted_payload_ref = records.publish(tainted_payload)
    tainted_spec = original_spec.model_copy(
        update={
            "context_refs": (*original_spec.context_refs, private_con_ref),
            "prompt_payload_ref": tainted_payload_ref,
        }
    )
    pro_call.call_spec_ref = records.publish(tainted_spec)
    calls = ConcurrentLLMCalls(
        records,
        artifacts,
        {
            "PRO": _output("PRO", public_inputs[0]),
            "CON": _output("CON", public_inputs[0]),
        },
    )
    publisher = RecordingPublisher(records)
    service = DebateService(
        records=records,
        artifacts=artifacts,
        llm_calls=calls,
        metadata_factory=MetadataFactory(),
        claim_id_factory=ClaimIds(),
        publish_result=publisher,
    )

    with pytest.raises(ValueError, match="CROSS_ROLE_INPUT_DENIED"):
        await service.run(
            verification_work=parent,
            public_input_refs=public_inputs,
            pro_call=pro_call,
            con_call=con_call,
        )

    assert calls.calls == []
    assert publisher.published == []
