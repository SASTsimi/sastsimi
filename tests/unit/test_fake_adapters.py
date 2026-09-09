import pytest

from sastsimi.contracts.refs import StoredDataRef
from sastsimi.ports.dto import BoundaryRecord
from tests.contract.domain.fixtures import ref, wire


@pytest.mark.asyncio
async def test_fake_provider_returns_only_the_configured_exact_invocation() -> None:
    from sastsimi.providers.fake import FakeProviderAdapter

    request = BoundaryRecord(wire(StoredDataRef, ref("llm_invocation_request")))
    result = BoundaryRecord(wire(StoredDataRef, ref("llm_invocation_result")))
    adapter = FakeProviderAdapter({request.ref: result})
    assert await adapter.invoke(request) == result
    unknown = BoundaryRecord(
        wire(
            StoredDataRef,
            ref("llm_invocation_request")
            | {
                "record_id": "unknown",
            },
        )
    )
    with pytest.raises(ValueError, match="FAKE_INVOCATION_NOT_CONFIGURED"):
        await adapter.invoke(unknown)
