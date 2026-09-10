from typing import Protocol, runtime_checkable

from sastsimi.contracts.llm import ProviderValidationEvidence

from .dto import (
    CancellationResult,
    CapabilityProbeResult,
    LLMInvocationRequest,
    LLMInvocationResult,
)


@runtime_checkable
class LLMProviderAdapter(Protocol):
    async def probe(
        self, candidate: ProviderValidationEvidence
    ) -> CapabilityProbeResult: ...
    async def invoke(self, request: LLMInvocationRequest) -> LLMInvocationResult: ...
    async def cancel(self, invocation_id: str) -> CancellationResult: ...
