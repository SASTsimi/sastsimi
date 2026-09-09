import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import LLMInvocationRequest, LLMInvocationResult
from sastsimi.contracts.refs import reference
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
