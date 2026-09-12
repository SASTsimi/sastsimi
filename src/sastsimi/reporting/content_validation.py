"""Fail-closed validation for the final report body proposed by an LLM."""

from __future__ import annotations

from typing import Protocol

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import LLMInvocationRequest
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.reporting import (
    ReportContent,
    parse_validated_report_content,
    validate_report_content,
)
from sastsimi.contracts.static import CodeLocation
from sastsimi.contracts.verification import VerificationResult
from sastsimi.ports.artifact_store import ArtifactStore


class ExactRecordReader(Protocol):
    def get_exact(self, ref: StoredDataRef) -> object: ...


class ReporterOutputSemanticValidator:
    """Reject unsafe or unsupported report output before artifact persistence."""

    def __init__(self, records: ExactRecordReader) -> None:
        self._records = records

    def __call__(self, value: object, request: LLMInvocationRequest) -> None:
        if request.agent_role != "REPORTER" or request.task_kind != "CREATE_DRAFT":
            raise ValueError("REPORTER_OUTPUT_CONTEXT_MISMATCH")
        candidates = tuple(
            ref
            for ref in request.context_refs
            if ref.data_kind == "verification_result"
        )
        if len(candidates) != 1:
            raise ValueError("REPORTER_OUTPUT_CONTEXT_MISMATCH")
        verification = self._records.get_exact(candidates[0])
        if (
            not isinstance(verification, VerificationResult)
            or reference(verification) != candidates[0]
        ):
            raise ValueError("REPORTER_OUTPUT_CONTEXT_MISMATCH")
        content = ReportContent.model_validate_json(canonical_bytes(value))
        allowed = tuple(
            location
            for claim in (
                *verification.supporting_evidence,
                *verification.counter_evidence,
            )
            for location in claim.code_locations
        )
        validate_report_content(
            content.model_dump(mode="json"), allowed_locations=allowed
        )


def read_validated_report_content(
    artifacts: ArtifactStore,
    ref: StoredDataRef,
    *,
    allowed_locations: tuple[CodeLocation, ...],
) -> ReportContent:
    if (
        ref.record_id is not None
        or ref.data_kind != "artifact"
        or str(ref.stored_data_id) != ref.content_hash
    ):
        raise ValueError("REPORT_CONTENT_ARTIFACT_INVALID")
    try:
        with artifacts.open_verified(ref) as stream:
            raw = stream.read()
        content = parse_validated_report_content(
            raw, allowed_locations=allowed_locations
        )
    except ValueError:
        raise
    except Exception as error:
        raise ValueError("REPORT_CONTENT_ARTIFACT_INVALID") from error
    return content


__all__ = [
    "ReportContent",
    "ReporterOutputSemanticValidator",
    "read_validated_report_content",
    "validate_report_content",
]
