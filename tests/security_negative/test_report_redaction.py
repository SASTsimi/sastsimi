import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import CommitId, WorkspaceId
from sastsimi.contracts.prompt_redaction import (
    assert_safe_provider_text,
    redact_projected_json,
    render_provider_prompt,
)
from sastsimi.contracts.reporting import validate_report_content
from sastsimi.contracts.static import CodeLocation


def location() -> CodeLocation:
    return CodeLocation(
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
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


def test_report_rejects_ambiguous_authorization_prose() -> None:
    summary = (
        "Confirmed conditional missing authorization: with public ticket viewing "
        "enabled, an anonymous requester can close a resolved ticket."
    )

    with pytest.raises(ValueError, match="PROMPT_REDACTION_FAILED"):
        validate_report_content({"summary": summary}, allowed_locations=())


def test_report_rejects_generic_missing_authorization_prose() -> None:
    summary = (
        "Missing authorization: with delegated access enabled, a request can "
        "change state."
    )

    with pytest.raises(ValueError, match="PROMPT_REDACTION_FAILED"):
        validate_report_content({"summary": summary}, allowed_locations=())


def test_shared_redactor_rejects_multiword_authorization_value() -> None:
    raw = canonical_bytes(
        {"note": "missing authorization: with amber river stone, please rotate it"}
    )

    with pytest.raises(ValueError, match="PROMPT_REDACTION_FAILED"):
        assert_safe_provider_text(raw)


def test_shared_redactor_removes_multiword_authorization_value() -> None:
    raw = canonical_bytes(
        {"note": "missing authorization: with amber river stone, please rotate it"}
    )

    redacted = redact_projected_json(raw)

    assert redacted.categories == ("CREDENTIAL",)
    assert b"amber river stone" not in redacted.data


@pytest.mark.parametrize(
    "authorization",
    [
        'Authorization: Bearer "synthetic_canary_123"',
        'Authorization: Bearer\r\n "synthetic_canary_123"',
        'Authorization:\r\n "synthetic_canary_123"',
        "Authorization: Bearer\r\n synthetic_canary_123",
        'HTTP_AUTHORIZATION=Bearer "synthetic_prefix" "synthetic_canary_123"',
    ],
)
def test_quoted_authorization_value_never_reaches_provider_prompt(
    authorization: str,
) -> None:
    projected = canonical_bytes({"note": authorization})

    rendered = render_provider_prompt(b"# Trusted rules", (("evidence", projected),))

    assert b"synthetic_canary_123" not in rendered
    assert b"[REDACTED:CREDENTIAL]" in rendered


@pytest.mark.parametrize(
    "note",
    [
        'token=Bearer "synthetic_canary_123"',
        'cookie=Bearer "synthetic_canary_123"',
        '{"Authorization":"Bearer\\u0020synthetic_canary_123"}',
    ],
)
def test_other_encoded_credential_values_never_reach_provider_prompt(
    note: str,
) -> None:
    rendered = render_provider_prompt(
        b"# Trusted rules", (("evidence", canonical_bytes({"note": note})),)
    )

    assert b"synthetic_canary_123" not in rendered


def test_encoded_bearer_value_in_trusted_template_is_rejected() -> None:
    with pytest.raises(ValueError, match="PROMPT_REDACTION_FAILED"):
        assert_safe_provider_text(b"Bearer\\u0020synthetic_canary_123")


def test_quoted_authorization_key_in_trusted_template_is_rejected() -> None:
    with pytest.raises(ValueError, match="PROMPT_REDACTION_FAILED"):
        assert_safe_provider_text(b'{"Authorization": "synthetic123"}')


@pytest.mark.parametrize(
    ("content", "error"),
    [
        ({"summary": "Unsupported at src/app.py:21"}, "LOCATION"),
        ({"summary": "authorization=Bearer secret-value"}, "REDACTION"),
        ({"summary": "authorization: secret-value"}, "REDACTION"),
        ({"summary": "Authorization: Bearer abc123"}, "REDACTION"),
        ({"summary": '"Authorization: Bearer abc123"'}, "REDACTION"),
        ({"summary": "authorization: abc123"}, "REDACTION"),
        ({"summary": "missing authorization: secret-value"}, "REDACTION"),
        ({"summary": "missing authorization: with secret-value"}, "REDACTION"),
        (
            {"summary": "missing authorization: with secret token exposed, stop."},
            "REDACTION",
        ),
        (
            {"summary": "missing authorization: with sk-abcdefghij access on, stop."},
            "REDACTION",
        ),
        (
            {"summary": "authorization: with delegated access enabled, stop."},
            "REDACTION",
        ),
        (
            {
                "summary": (
                    "Missing authorization: with public ticket viewing enabled; "
                    "authorization: Bearer secret-value"
                )
            },
            "REDACTION",
        ),
        ({"summary": "hidden reasoning: private notes"}, "HIDDEN_REASONING"),
    ],
)
def test_report_rejects_unsafe_or_unsupported_content(
    content: object, error: str
) -> None:
    with pytest.raises(ValueError, match=error):
        validate_report_content(content, allowed_locations=(location(),))
