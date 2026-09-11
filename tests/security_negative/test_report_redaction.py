import pytest

from sastsimi.contracts.static import CodeLocation
from sastsimi.reporting.content_validation import validate_report_content


def location() -> CodeLocation:
    return CodeLocation(
        workspace_id="ws1",
        commit_id="c1",
        file_path="src/app.py",
        start_line=10,
        start_column=None,
        end_line=20,
        end_column=None,
    )


def test_report_accepts_only_supported_location() -> None:
    encoded = validate_report_content(
        {"summary": "Confirmed at src/app.py:12"},
        allowed_locations=(location(),),
    )

    assert b"src/app.py:12" in encoded


@pytest.mark.parametrize(
    ("content", "error"),
    [
        ({"summary": "Unsupported at src/app.py:21"}, "LOCATION"),
        ({"summary": "authorization=Bearer secret-value"}, "REDACTION"),
        ({"summary": "hidden reasoning: private notes"}, "HIDDEN_REASONING"),
    ],
)
def test_report_rejects_unsafe_or_unsupported_content(
    content: object, error: str
) -> None:
    with pytest.raises(ValueError, match=error):
        validate_report_content(content, allowed_locations=(location(),))
