"""Deterministic reference-only fake; invocation is wrapped by runtime dispatch."""

from collections.abc import Mapping
from types import MappingProxyType

from sastsimi.contracts.refs import RecordRef
from sastsimi.ports.dto import (
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
        try:
            return self.results[request.ref]
        except KeyError as error:
            raise ValueError("FAKE_INVOCATION_NOT_CONFIGURED") from error

    async def probe(self, profile: ProviderProfile) -> CapabilityProbeResult:
        raise ValueError("FAKE_PROBE_NOT_CONFIGURED")

    async def cancel(self, invocation_id: str) -> CancellationResult:
        return CancellationResult(False, "No asynchronous external fake process exists")
