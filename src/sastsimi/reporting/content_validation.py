"""Fail-closed validation for the final report body proposed by an LLM."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Protocol

from sastsimi.contracts.base import ContractModel, NonEmptyStr
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import LLMInvocationRequest
from sastsimi.contracts.prompt_redaction import assert_safe_provider_text
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import CodeLocation
from sastsimi.contracts.verification import VerificationResult
from sastsimi.ports.artifact_store import ArtifactStore

_LOCATION = re.compile(
    r"(?<![\w./-])(?P<path>[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)"
    r":(?P<line>[1-9][0-9]*)(?![0-9])"
)
_HIDDEN_REASONING = re.compile(
    r"(?i)(?:chain[ _-]?of[ _-]?thought|hidden[ _-]?reasoning|internal reasoning)"
)


class ReportContent(ContractModel):
    title: NonEmptyStr
    summary: NonEmptyStr
    details: NonEmptyStr
    recommendation: NonEmptyStr
    citations: tuple[CodeLocation, ...]


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


def validate_report_content(
    content: object, *, allowed_locations: tuple[CodeLocation, ...]
) -> bytes:
    """Return canonical safe bytes and reject unsupported ``path:line`` claims."""

    encoded = canonical_bytes(content)
    assert_safe_provider_text(encoded)
    text = encoded.decode("utf-8")
    if _HIDDEN_REASONING.search(text):
        raise ValueError("REPORT_HIDDEN_REASONING_DENIED")
    if isinstance(content, Mapping) and "citations" in content:
        for citation in ReportContent.model_validate_json(encoded).citations:
            if not any(
                location.file_path == citation.file_path
                and location.start_line <= citation.start_line
                and citation.end_line <= location.end_line
                for location in allowed_locations
            ):
                raise ValueError("REPORT_CODE_LOCATION_UNSUPPORTED")
    for match in _LOCATION.finditer(text):
        path, line = match.group("path"), int(match.group("line"))
        if not any(
            location.file_path == path
            and location.start_line <= line <= location.end_line
            for location in allowed_locations
        ):
            raise ValueError("REPORT_CODE_LOCATION_UNSUPPORTED")
    return encoded


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
        content = ReportContent.model_validate_json(raw)
    except ValueError:
        raise
    except Exception as error:
        raise ValueError("REPORT_CONTENT_ARTIFACT_INVALID") from error
    if (
        validate_report_content(
            content.model_dump(mode="json"), allowed_locations=allowed_locations
        )
        != raw
    ):
        raise ValueError("REPORT_CONTENT_ARTIFACT_INVALID")
    return content


__all__ = [
    "ReportContent",
    "ReporterOutputSemanticValidator",
    "read_validated_report_content",
    "validate_report_content",
]
