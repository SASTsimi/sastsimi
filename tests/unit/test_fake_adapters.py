import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import (
    LLMInvocationRequest,
    LLMInvocationResult,
    ProviderValidationEvidence,
)
from sastsimi.contracts.refs import reference
from sastsimi.ports.static_tool import StaticToolAdapter
from tests.contract.domain.canonical_fixtures import make


@pytest.mark.asyncio
async def test_fake_provider_returns_only_the_configured_exact_invocation() -> None:
    from sastsimi.providers.fake import FakeProviderAdapter

    request = LLMInvocationRequest.model_validate_json(
        canonical_bytes(make("LLMInvocationRequest", "llm_invocation_request"))
    )
    result_payload = make("LLMInvocationResult", "llm_invocation_result") | {
        "status": "FAILED",
        "safe_error": "configured failure",
    }
    result = LLMInvocationResult.model_validate_json(canonical_bytes(result_payload))
    adapter = FakeProviderAdapter({reference(request): result})
    assert await adapter.invoke(request) == result
    unknown = request.model_copy(update={"llm_call_id": "unknown"})
    with pytest.raises(ValueError, match="FAKE_INVOCATION_NOT_CONFIGURED"):
        await adapter.invoke(unknown)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["exception", "mismatch"])
async def test_fake_provider_probe_fails_when_its_own_invoke_fails(
    failure: str,
) -> None:
    """Catches probes that manufacture PASS without exercising adapter behavior."""
    from sastsimi.providers.fake import FakeProviderAdapter

    class FailingInvokeAdapter(FakeProviderAdapter):
        async def invoke(self, request: LLMInvocationRequest) -> LLMInvocationResult:
            if failure == "exception":
                raise ValueError("deterministic invoke failure")
            result = await super().invoke(request)
            return result.model_copy(update={"model": "wrong-model"})

    candidate = ProviderValidationEvidence.model_validate_json(
        canonical_bytes(make("ProviderValidationEvidence"))
    )
    candidate = ProviderValidationEvidence.model_validate(
        candidate.model_dump()
        | {
            "tests": tuple(
                {
                    "test_id": f"PVD-{index:02d}",
                    "result": "NOT_APPLICABLE",
                    "evidence_refs": (reference(candidate),),
                    "safe_summary": "pending observed fake probe",
                }
                for index in range(1, 17)
            )
        }
    )
    observed = await FailingInvokeAdapter({}).probe(candidate)

    assert observed.evidence.tests[0].result == "FAIL"
    assert not any(test.result == "PASS" for test in observed.evidence.tests)


@pytest.mark.asyncio
async def test_fake_static_probe_preserves_exact_profile_reference() -> None:
    from sastsimi.contracts.refs import StoredDataRef
    from sastsimi.static_analysis.fake import FakeStaticToolAdapter

    profile_ref = StoredDataRef.model_validate(
        {
            "stored_data_id": "static-profile-r1",
            "data_kind": "static_tool_profile",
            "content_hash": "a" * 64,
            "workspace_id": "ws1",
            "commit_id": "c1",
            "record_id": "static-profile-r1",
        }
    )
    result = await FakeStaticToolAdapter({}).probe(profile_ref)
    assert result.ref == profile_ref
    assert result.tool_name == "UNKNOWN"
    assert result.available is False


def test_fake_static_adapter_still_implements_the_public_port() -> None:
    from sastsimi.static_analysis.fake import FakeStaticToolAdapter

    assert isinstance(FakeStaticToolAdapter({}), StaticToolAdapter)
