import pytest

from sastsimi.contracts.ids import CommitId, WorkspaceId
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


def test_prose_about_a_bearer_token_is_not_a_bearer_token() -> None:
    """A report explaining an authentication defect must be publishable.

    Measured on open-webui: a confirmed finding about plaintext API key
    comparison was refused because its impact paragraph said a stolen key is
    reusable "like a Bearer token".  Matching any non-space run after the
    scheme made every such report unpublishable.
    """

    from sastsimi.contracts.prompt_redaction import redact_untrusted_text

    prose = (
        "탈취한 키 값을 즉시 Bearer 토큰처럼 재사용해 인증할 수 있습니다. "
        "An attacker reuses the stolen value as a bearer token."
    ).encode()

    result = redact_untrusted_text(prose)

    assert result.categories == ()
    assert "Bearer 토큰처럼" in result.data.decode("utf-8")


def test_an_actual_bearer_credential_is_still_removed() -> None:
    from sastsimi.contracts.prompt_redaction import redact_untrusted_text

    # An ``Authorization:`` prefix is caught as a credential first; the bare
    # scheme is what this pattern is responsible for.  Either way the value
    # must not survive.
    for carrier, secret in (
        (b"sent Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", b"eyJhbGci"),
        (b"sent Basic QWxhZGRpbjpvcGVuc2VzYW1l", b"QWxhZGRpbjpvcGVuc2VzYW1l"),
        (b"Authorization: Bearer aB3dEfGh1jKlMn0p", b"aB3dEfGh1jKlMn0p"),
    ):
        result = redact_untrusted_text(carrier)

        assert result.categories, carrier
        assert secret not in result.data, carrier
