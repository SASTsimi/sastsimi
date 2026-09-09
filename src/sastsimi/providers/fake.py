"""Deterministic reference-only fake; invocation is wrapped by runtime dispatch."""

from collections.abc import Mapping
from types import MappingProxyType

from sastsimi.contracts.refs import RecordRef, reference
from sastsimi.ports.dto import (
    BoundaryRecord,
    CancellationResult,
    CapabilityProbeResult,
    LLMInvocationRequest,
    LLMInvocationResult,
    ProviderProfile,
)


class FakeProviderAdapter:
    def __init__(self, results: Mapping[RecordRef, LLMInvocationResult]) -> None:
        self.results = MappingProxyType(dict(results))

    async def invoke(self, request: LLMInvocationRequest) -> LLMInvocationResult:
        request_ref = (
            request.ref if isinstance(request, BoundaryRecord) else reference(request)
        )
        try:
            return self.results[request_ref]
        except KeyError as error:
            raise ValueError("FAKE_INVOCATION_NOT_CONFIGURED") from error

    async def probe(self, profile: ProviderProfile) -> CapabilityProbeResult:
        profile_ref = (
            profile.ref if isinstance(profile, BoundaryRecord) else reference(profile)
        )
        return BoundaryRecord(profile_ref)

    async def cancel(self, invocation_id: str) -> CancellationResult:
        return CancellationResult(False, "No asynchronous external fake process exists")
