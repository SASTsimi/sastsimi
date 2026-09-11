"""Fail-closed validation for the final report body proposed by an LLM."""

from __future__ import annotations

import re

from sastsimi.contracts.base import ContractModel, NonEmptyStr
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.prompt_redaction import assert_safe_provider_text
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.static import CodeLocation
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


def validate_report_content(
    content: object, *, allowed_locations: tuple[CodeLocation, ...]
) -> bytes:
    """Return canonical safe bytes and reject unsupported ``path:line`` claims."""

    encoded = canonical_bytes(content)
    assert_safe_provider_text(encoded)
    text = encoded.decode("utf-8")
    if _HIDDEN_REASONING.search(text):
        raise ValueError("REPORT_HIDDEN_REASONING_DENIED")
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
    if validate_report_content(
        content.model_dump(mode="json"), allowed_locations=allowed_locations
    ) != raw:
        raise ValueError("REPORT_CONTENT_ARTIFACT_INVALID")
    return content


__all__ = [
    "ReportContent",
    "read_validated_report_content",
    "validate_report_content",
]
