"""Deterministic static adapter with no real tool behavior."""

from collections.abc import Mapping
from types import MappingProxyType

from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.ports.dto import (
    CancellationResult,
    StaticToolRequest,
    ToolCapabilityResult,
    ToolRunResult,
)


class FakeStaticToolAdapter:
    def __init__(self, results: Mapping[RecordRef, ToolRunResult]) -> None:
        self.results = MappingProxyType(dict(results))

    async def probe(self, profile_ref: StoredDataRef) -> ToolCapabilityResult:
        return ToolCapabilityResult(
            ref=profile_ref,
            available=False,
            tool_name="UNKNOWN",
            tool_kind="STRUCTURE",
            executable_key="unconfigured",
            observed_executable_sha256=None,
            observed_version=None,
            expected_version="unconfigured",
            reason_code="FAKE_CAPABILITY_NOT_CONFIGURED",
        )

    async def run(self, request: StaticToolRequest) -> ToolRunResult:
        try:
            return self.results[reference(request.action)]
        except KeyError as error:
            raise ValueError("FAKE_STATIC_RUN_NOT_CONFIGURED") from error

    async def cancel(self, attempt_id: str) -> CancellationResult:
        return CancellationResult(False, "No asynchronous fake static process exists")
