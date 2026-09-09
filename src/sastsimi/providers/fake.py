"""Deterministic reference-only fake; invocation is wrapped by runtime dispatch."""

from collections.abc import Mapping
from types import MappingProxyType

from sastsimi.contracts.llm import ProviderValidationEvidence
from sastsimi.contracts.refs import RecordRef, reference
from sastsimi.ports.dto import (
    BoundaryRecord,
    CancellationResult,
    CapabilityProbeResult,
    LLMInvocationRequest,
    LLMInvocationResult,
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

    async def probe(
        self, candidate: ProviderValidationEvidence
    ) -> CapabilityProbeResult:
        tests = tuple(
            test.model_copy(
                update={
                    "result": "NOT_APPLICABLE" if test.test_id == "PVD-13" else "PASS",
                    "safe_summary": (
                        "API subscription isolation is not applicable"
                        if test.test_id == "PVD-13"
                        else "Deterministic fake adapter probe passed"
                    ),
                }
            )
            for test in candidate.tests
        )
        evidence = candidate.model_copy(update={"tests": tests})
        return CapabilityProbeResult(evidence=evidence)

    async def cancel(self, invocation_id: str) -> CancellationResult:
        return CancellationResult(False, "No asynchronous external fake process exists")
