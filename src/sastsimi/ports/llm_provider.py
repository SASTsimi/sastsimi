from typing import Protocol, runtime_checkable

from .dto import (
    CancellationResult,
    CapabilityProbeResult,
    LLMInvocationRequest,
    LLMInvocationResult,
    ProviderProfile,
)


@runtime_checkable
class LLMProviderAdapter(Protocol):
    async def probe(self, profile: ProviderProfile) -> CapabilityProbeResult: ...
    async def invoke(self, request: LLMInvocationRequest) -> LLMInvocationResult: ...
    async def cancel(self, invocation_id: str) -> CancellationResult: ...
