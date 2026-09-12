"""Return data-only work registration requests for committed verdicts."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol

from sastsimi.contracts.domain import DomainRecord, exact
from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    DynamicReproductionResult,
    PoCBundle,
)
from sastsimi.contracts.gates import validate_true_dynamic
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.refs import RecordRef, StoredDataRef
from sastsimi.contracts.verification import (
    VerificationResult,
    validate_dynamic_verdict,
)


class ExactRecordReader(Protocol):
    def get_exact(self, ref: RecordRef) -> object: ...


type CurrentProcessResolver = Callable[
    [VerificationResult], HypothesisProcessState | None
]


@dataclass(frozen=True)
class VerdictRoute:
    work_type: Literal["PRIMITIVE_UPDATE", "CWE_LABEL"]
    input_refs: tuple[StoredDataRef, ...]


class VerdictRouter:
    """Propose the only T10 route; runtime authorization remains external."""

    def __init__(
        self,
        records: ExactRecordReader,
        *,
        current_process: CurrentProcessResolver | None = None,
    ) -> None:
        self._records = records
        self._current_process = current_process

    def route(self, result_ref: StoredDataRef) -> tuple[VerdictRoute, ...]:
        value = self._records.get_exact(result_ref)
        if not isinstance(value, VerificationResult):
            raise ValueError("RECORD_REVISION_MISMATCH")
        exact(result_ref, value, value.meta)
        if value.verdict == "FALSE":
            return ()
        if value.verdict == "TRUE":
            self._require_committed_true(value, result_ref)
            return (VerdictRoute("CWE_LABEL", (result_ref,)),)
        if not value.required_primitive_candidates:
            return ()
        return (VerdictRoute("PRIMITIVE_UPDATE", (result_ref,)),)

    def _require_committed_true(
        self, result: VerificationResult, result_ref: StoredDataRef
    ) -> None:
        if self._current_process is None:
            raise ValueError("STALE_RESULT")
        process = self._current_process(result)
        if (
            process is None
            or process.status != "TERMINAL"
            or process.verification_result_ref != result_ref
            or process.verification_work_ref is not None
            or process.meta.analysis_id != result.meta.analysis_id
            or process.meta.workspace_id != result.meta.workspace_id
            or process.meta.commit_id != result.meta.commit_id
            or process.meta.hypothesis_id != result.meta.hypothesis_id
        ):
            raise ValueError("STALE_RESULT")
        if (
            result.dynamic_request_ref is None
            or result.dynamic_result_ref is None
            or result.poc_ref is None
        ):
            raise ValueError("DYNAMIC_CLOSURE_REQUIRED")
        request = self._exact(result.dynamic_request_ref, DynamicReproductionRequest)
        dynamic = self._exact(result.dynamic_result_ref, DynamicReproductionResult)
        poc = self._exact(result.poc_ref, PoCBundle)
        validate_dynamic_verdict(
            result,
            request,
            dynamic,
            poc,
            generation=process.verification_generation,
        )
        validate_true_dynamic(result, dynamic, poc)

    def _exact[T: DomainRecord](self, ref: StoredDataRef, model: type[T]) -> T:
        value = self._records.get_exact(ref)
        if not isinstance(value, model):
            raise ValueError("RECORD_REVISION_MISMATCH")
        exact(ref, value, value.meta)
        return value


def current_process_from(
    records: Callable[[str, str], tuple[object, ...]],
) -> CurrentProcessResolver:
    """Resolve the one current process for an exact verdict scope."""

    def resolve(result: VerificationResult) -> HypothesisProcessState | None:
        candidates = tuple(
            item
            for item in records(
                str(result.meta.analysis_id), "hypothesis_process_state"
            )
            if isinstance(item, HypothesisProcessState)
            and item.meta.hypothesis_id == result.meta.hypothesis_id
        )
        return candidates[0] if len(candidates) == 1 else None

    return resolve


__all__ = [
    "CurrentProcessResolver",
    "VerdictRoute",
    "VerdictRouter",
    "current_process_from",
]
