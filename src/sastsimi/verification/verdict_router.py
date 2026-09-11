"""Return data-only work registration requests for T10 verdicts."""

from dataclasses import dataclass
from typing import Literal, Protocol

from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.verification import VerificationResult


class ExactRecordReader(Protocol):
    def get_exact(self, ref: RecordRef) -> object: ...


@dataclass(frozen=True)
class VerdictRoute:
    work_type: Literal["PRIMITIVE_UPDATE"]
    input_refs: tuple[StoredDataRef, ...]


class VerdictRouter:
    """Propose the only T10 route; runtime authorization remains external."""

    def __init__(self, records: ExactRecordReader) -> None:
        self._records = records

    def route(self, result_ref: StoredDataRef) -> tuple[VerdictRoute, ...]:
        value = self._records.get_exact(result_ref)
        if not isinstance(value, VerificationResult) or reference(value) != result_ref:
            raise ValueError("RECORD_REVISION_MISMATCH")
        if value.verdict == "FALSE":
            return ()
        if value.verdict == "TRUE":
            raise ValueError("T11_OUTPUT_REQUIRED")
        if not value.required_primitive_candidates:
            return ()
        return (VerdictRoute("PRIMITIVE_UPDATE", (result_ref,)),)


__all__ = ["VerdictRoute", "VerdictRouter"]
