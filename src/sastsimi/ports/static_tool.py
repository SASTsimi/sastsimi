from typing import Protocol, runtime_checkable

from sastsimi.contracts.refs import StoredDataRef

from .dto import (
    CancellationResult,
    StaticToolRequest,
    ToolCapabilityResult,
    ToolRunResult,
)


@runtime_checkable
class StaticToolAdapter(Protocol):
    async def probe(self, profile_ref: StoredDataRef) -> ToolCapabilityResult: ...
    async def run(self, request: StaticToolRequest) -> ToolRunResult: ...
    async def cancel(self, attempt_id: str) -> CancellationResult: ...
