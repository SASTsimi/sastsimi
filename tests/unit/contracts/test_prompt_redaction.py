import json

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.prompt_redaction import (
    assert_safe_provider_text,
    redact_projected_json,
    redact_untrusted_text,
    redact_untrusted_text_preserving_lines,
)


@pytest.mark.parametrize(
    "authorization",
    [
        'Authorization: Bearer "synthetic_canary_123"',
        "Authorization: Basic 'synthetic_canary_123'",
        'Authorization: "synthetic_prefix" "synthetic_canary_123"',
        'Authorization: Bearer\r\n "synthetic_canary_123"',
        'Authorization: Bearer\n"synthetic_canary_123"',
        'Authorization:\r\n "synthetic_canary_123"',
        "Authorization: Bearer\r\n synthetic_canary_123",
        'HTTP_AUTHORIZATION=Bearer "synthetic_prefix" "synthetic_canary_123"',
    ],
)
def test_authorization_assignment_redacts_all_quoted_value_parts(
    authorization: str,
) -> None:
    result = redact_projected_json(canonical_bytes({"note": authorization}))

    assert result.data == b'{"note":"[REDACTED:CREDENTIAL]"}'
    assert result.categories == ("CREDENTIAL",)


def test_quoted_authorization_assignment_preserves_separate_code() -> None:
    result = redact_projected_json(
        canonical_bytes(
            {"note": 'authorization = "placeholder"; validate_permissions(user)'}
        )
    )

    assert result.data == (
        b'{"note":"[REDACTED:CREDENTIAL]; validate_permissions(user)"}'
    )
    assert result.categories == ("CREDENTIAL",)


@pytest.mark.parametrize(
    ("assignment", "category"),
    [
        ('token=Bearer "synthetic_canary_123"', "TOKEN"),
        ('token="synthetic_prefix" "synthetic_canary_123"', "TOKEN"),
        ('token="synthetic_prefix" + "synthetic_canary_123"', "TOKEN"),
        ('token=Bearer "synthetic_prefix" + "synthetic_canary_123"', "TOKEN"),
        ('access_token=Bearer "synthetic_canary_123"', "TOKEN"),
        ('cookie=Bearer "synthetic_canary_123"', "COOKIE"),
        ('cookie="synthetic_prefix" "synthetic_canary_123"', "COOKIE"),
        ('cookie="synthetic_prefix" + "synthetic_canary_123"', "COOKIE"),
        ('sessionid=Bearer "synthetic_canary_123"', "COOKIE"),
    ],
)
def test_assignment_redacts_quoted_bearer_suffix(
    assignment: str, category: str
) -> None:
    result = redact_projected_json(canonical_bytes({"note": assignment}))

    assert result.data == b'{"note":"[REDACTED:' + category.encode() + b']"}'
    assert result.categories == (category,)


def test_nested_json_authorization_is_redacted_without_damaging_other_fields() -> None:
    nested = '{"Authorization":"Bearer\\u0020synthetic_canary_123","ok":"value"}'
    result = redact_projected_json(canonical_bytes({"note": nested}))

    assert result.categories == ("CREDENTIAL",)
    assert json.loads(json.loads(result.data)["note"]) == {
        "Authorization": "[REDACTED:CREDENTIAL]",
        "ok": "value",
    }


def test_nonsensitive_nested_json_text_is_preserved() -> None:
    nested = '{"status":"ok"}'

    assert redact_projected_json(canonical_bytes({"note": nested})).data == (
        b'{"note":"{\\"status\\":\\"ok\\"}"}'
    )


def test_nonsensitive_nested_json_float_text_is_preserved() -> None:
    nested = '{"score": 1.25}'

    assert redact_projected_json(canonical_bytes({"note": nested})).data == (
        canonical_bytes({"note": nested})
    )


def test_sensitive_nested_json_with_float_redacts_credential() -> None:
    nested = '{"Authorization":"synthetic123","score":1.25}'

    result = redact_projected_json(canonical_bytes({"note": nested}))

    assert json.loads(json.loads(result.data)["note"]) == {
        "Authorization": "[REDACTED:CREDENTIAL]",
        "score": 1.25,
    }
    assert b"synthetic123" not in result.data


def test_escaped_bearer_space_is_removed_from_source_context() -> None:
    source = b'payload = "{\\"Authorization\\":\\"Bearer\\\\u0020synthetic123\\"}"\n'

    redacted = redact_untrusted_text_preserving_lines(source)

    assert b"synthetic123" not in redacted.data
    assert redacted.data.count(b"\n") == source.count(b"\n")


def test_quoted_authorization_key_redacts_value_in_source_context() -> None:
    source = b'payload = {"Authorization": "synthetic123", "ok": "value"}\n'

    redacted = redact_untrusted_text_preserving_lines(source)

    assert b"synthetic123" not in redacted.data
    assert b'"ok": "value"' in redacted.data
    assert redacted.data.count(b"\n") == source.count(b"\n")


@pytest.mark.parametrize(
    ("source", "unrelated_code"),
    [
        (
            b'headers = {"Authorization": auth_value, "ok": "value"}\n',
            b', "ok": "value"}',
        ),
        (
            b'headers = {"Authorization": f"Bearer {token}", "ok": "value"}\n',
            b', "ok": "value"}',
        ),
        (
            b'headers = {"Authorization": f"Bearer \\"{token}\\"", "ok": "value"}\n',
            b', "ok": "value"}',
        ),
        (
            b'call(Authorization=f"Bearer {token}", keep="important")\n',
            b', keep="important")',
        ),
        (
            b'call(Authorization=auth_value, keep="important")\n',
            b', keep="important")',
        ),
        (
            b'headers = {"Authorization": "synthetic123", "ok": "value"}\n',
            b', "ok": "value"}',
        ),
        (
            b'call(Authorization="synthetic123", keep="important")\n',
            b', keep="important")',
        ),
        (
            b"call(Authorization=auth_value); safe()\n",
            b"); safe()",
        ),
    ],
)
def test_authorization_value_redaction_preserves_following_code(
    source: bytes, unrelated_code: bytes
) -> None:
    redacted = redact_untrusted_text_preserving_lines(source)

    assert b"[REDACTED:CREDENTIAL]" in redacted.data
    assert b"auth_value" not in redacted.data
    assert b"synthetic123" not in redacted.data
    assert unrelated_code in redacted.data


def test_authorization_expression_continuation_remains_fail_closed() -> None:
    source = (
        b'headers = {"Authorization": f"Bearer {token}" + dynamic_suffix, '
        b'"ok": "value"}\n'
    )

    redacted = redact_untrusted_text_preserving_lines(source)

    assert b"Bearer" not in redacted.data
    assert b"dynamic_suffix" not in redacted.data
    assert redacted.data.count(b"\n") == source.count(b"\n")


@pytest.mark.parametrize(
    "reference",
    [
        "env:OPENAI_API_KEY",
        "handle:12345678-1234-1234-1234-123456789abc",
        {"reference": "env:OPENAI_API_KEY"},
    ],
)
def test_symbolic_credential_reference_is_safe_in_raw_json(reference: object) -> None:
    data = canonical_bytes({"providers": [{"credential_ref": reference}]})

    assert redact_untrusted_text(data).data == data
    assert_safe_provider_text(data)


@pytest.mark.parametrize(
    "reference",
    [
        "synthetic_literal_secret",
        "env:lowercase",
        {"reference": "env:OPENAI_API_KEY", "extra": "synthetic_literal_secret"},
        {"reference": "synthetic_literal_secret"},
    ],
)
def test_literal_credential_reference_is_rejected_in_raw_json(
    reference: object,
) -> None:
    data = canonical_bytes({"providers": [{"credential_ref": reference}]})

    with pytest.raises(ValueError, match="PROMPT_REDACTION_FAILED"):
        redact_untrusted_text(data)
    with pytest.raises(ValueError, match="PROMPT_REDACTION_FAILED"):
        assert_safe_provider_text(data)


def test_onboarding_authorization_metadata_is_not_a_credential() -> None:
    data = canonical_bytes(
        {
            "authorization_policy_sha256": "a" * 64,
            "authorization_implementation_key": "RUNTIME_DYNAMIC_AUTHORIZATION_V1",
        }
    )

    assert redact_untrusted_text(data).data == data
    assert_safe_provider_text(data)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("credential_source", "ENVIRONMENT"),
        ("credential_source", "SECRET_STORE"),
        ("credential_source", "OFFICIAL_CLIENT_SESSION"),
        ("token_usage", "SUPPORTED"),
        ("token_usage", "UNSUPPORTED"),
        ("token_usage", "UNVERIFIED"),
        ("session_metadata", "SUPPORTED"),
        ("session_metadata", "UNSUPPORTED"),
        ("session_metadata", "UNVERIFIED"),
        ("token_source", "PROVIDER_REPORTED"),
        ("token_source", "ADAPTER_REPORTED"),
        ("token_source", "UNAVAILABLE"),
        ("input_tokens", 0),
        ("input_tokens", 17),
        ("input_tokens", None),
        ("output_tokens", 0),
        ("output_tokens", None),
        ("total_tokens", 17),
        ("total_tokens", None),
    ],
)
def test_contract_typed_provider_metadata_is_not_masked(
    key: str, value: object
) -> None:
    data = canonical_bytes({"metadata": {key: value}, "ok": "visible"})

    projected = redact_projected_json(data)

    assert projected.data == data
    assert projected.categories == ()
    assert redact_untrusted_text(data).data == data
    assert_safe_provider_text(data)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("credential_source", "synthetic_secret_value"),
        ("credential_source", "Bearer synthetic_canary_123"),
        ("credential_source", "C:\\Users\\example\\secret.txt"),
        ("token_usage", "synthetic_secret_value"),
        ("session_metadata", "sk-synthetic_canary_123"),
        ("token_source", "synthetic_secret_value"),
        ("input_tokens", -1),
        ("input_tokens", True),
        ("input_tokens", 1.5),
        ("input_tokens", "17"),
        ("output_tokens", -1),
        ("total_tokens", False),
        ("session_ref", "SUPPORTED"),
        ("token_unavailable_reason", "SUPPORTED"),
    ],
)
def test_unreviewed_or_invalid_provider_metadata_stays_sensitive(
    key: str, value: object
) -> None:
    data = json.dumps(
        {"metadata": {key: value}, "ok": "visible"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    projected = redact_projected_json(data)

    assert json.loads(projected.data)["metadata"] == {key: "[REDACTED:CREDENTIAL]"}
    assert b'"ok":"visible"' in projected.data
    assert projected.categories == ("CREDENTIAL",)
    try:
        raw_redaction = redact_untrusted_text(data)
    except ValueError as error:
        assert str(error) == "PROMPT_REDACTION_FAILED"
    else:
        assert raw_redaction.data != data
        assert raw_redaction.categories
        assert b"synthetic_canary_123" not in raw_redaction.data
        assert b"secret.txt" not in raw_redaction.data
    with pytest.raises(ValueError, match="PROMPT_REDACTION_FAILED"):
        assert_safe_provider_text(data)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("authorization_policy_sha256", "not_a_digest"),
        ("authorization_implementation_key", "UNREVIEWED_IMPLEMENTATION_V1"),
    ],
)
def test_onboarding_authorization_metadata_rejects_unapproved_values(
    key: str, value: str
) -> None:
    data = canonical_bytes({key: value})

    with pytest.raises(ValueError, match="PROMPT_REDACTION_FAILED"):
        assert_safe_provider_text(data)
