import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import CommitId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.reporting import (
    evidence_closure,
    parse_validated_report_content,
)
from sastsimi.contracts.static import CodeLocation
from sastsimi.contracts.verification import VerificationResult

from .canonical_fixtures import make
from .fixtures import ref, wire


def test_r14_complete_verification_evidence_reaches_finding() -> None:
    roots = [
        ref(name, record=False)
        for name in ("validation", "falsification", "required_primitive")
    ]
    value = make("VerificationResult") | dict(
        verification_mode="BASIC",
        debate_input_hash=None,
        pro_evidence_ref=None,
        con_evidence_ref=None,
        supporting_evidence=[],
        counter_evidence=[],
        validation_results=[
            dict(
                validation_id="v1",
                completion="COMPLETE",
                evidence_refs=[roots[0]],
                summary="checked",
            )
        ],
        falsification_results=[
            dict(
                question_id="q1",
                outcome="INCONCLUSIVE",
                evidence_refs=[roots[1]],
                rationale="not disproved",
            )
        ],
        required_primitive_candidates=[
            dict(
                draft_id="required",
                entity_refs=[],
                privilege_level=None,
                evidence_refs=[roots[2]],
                description="required condition",
            )
        ],
    )
    result = wire(VerificationResult, value)
    assert set(evidence_closure(result, {})) == {
        wire(StoredDataRef, item) for item in roots
    }


def _report_location() -> CodeLocation:
    return CodeLocation(
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
        file_path="src/app.py",
        start_line=10,
        start_column=None,
        end_line=20,
        end_column=None,
    )


def _bilingual_report() -> dict[str, object]:
    prose = {
        "title": "Example title",
        "summary": "Supported at src/app.py:12",
        "details": "Only this location is supported.",
        "impact": "Potential impact",
        "recommendation": "Review authorization.",
        "limitations": ["Only the tested commit was checked."],
        "review_items": ["Confirm affected versions."],
    }
    return {
        "schema_version": 2,
        "en": prose,
        "ko": prose | {"title": "예시 제목"},
        "citations": [_report_location().model_dump(mode="json")],
    }


def test_report_v1_content_remains_byte_compatible() -> None:
    legacy = {
        "title": "Example",
        "summary": "Supported",
        "details": "Confirmed",
        "recommendation": "Review",
        "citations": [],
    }
    raw = canonical_bytes(legacy)

    content = parse_validated_report_content(raw, allowed_locations=())

    assert canonical_bytes(content.model_dump(mode="json")) == raw


def test_report_v2_preserves_both_languages_and_shared_citations() -> None:
    raw = canonical_bytes(_bilingual_report())

    content = parse_validated_report_content(
        raw, allowed_locations=(_report_location(),)
    )

    assert content.schema_version == 2
    assert content.en.summary == "Supported at src/app.py:12"
    assert content.ko.title == "예시 제목"
    assert content.citations == (_report_location(),)


@pytest.mark.parametrize("language", ["en", "ko"])
def test_report_v2_rejects_unsupported_location_in_either_language(
    language: str,
) -> None:
    value = _bilingual_report()
    prose = value[language]
    assert isinstance(prose, dict)
    prose["details"] = "Unsupported at src/other.py:99"

    with pytest.raises(ValueError, match="REPORT_CODE_LOCATION_UNSUPPORTED"):
        parse_validated_report_content(
            canonical_bytes(value), allowed_locations=(_report_location(),)
        )


def test_report_v2_requires_both_languages() -> None:
    value = _bilingual_report()
    del value["ko"]

    with pytest.raises(ValueError, match="REPORT_LANGUAGE_REQUIRED"):
        parse_validated_report_content(
            canonical_bytes(value), allowed_locations=(_report_location(),)
        )
