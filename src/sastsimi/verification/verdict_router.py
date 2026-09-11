"""Return data-only work registration requests for T10 verdicts."""

from dataclasses import dataclass
from typing import Literal

from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.verification import VerificationResult
from sastsimi.ports.record_store import RecordStore


@dataclass(frozen=True)
class VerdictRoute:
    work_type: Literal["PRIMITIVE_UPDATE"]
    input_refs: tuple[StoredDataRef, ...]


class VerdictRouter:
    """Propose the only T10 route; runtime authorization remains external."""

    def __init__(self, records: RecordStore) -> None:
        self._records = records

    def route(self, result_ref: StoredDataRef) -> tuple[VerdictRoute, ...]:
        value = self._records.get_exact(result_ref)
        if not isinstance(value, VerificationResult) or reference(value) != result_ref:
            raise ValueError("RECORD_REVISION_MISMATCH")
        if value.verdict == "FALSE":
            return ()
        if value.verdict == "TRUE":
            raise ValueError("T11_OUTPUT_REQUIRED")
        return (VerdictRoute("PRIMITIVE_UPDATE", (result_ref,)),)


__all__ = ["VerdictRoute", "VerdictRouter"]
