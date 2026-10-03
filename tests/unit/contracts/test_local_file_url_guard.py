"""Stored public bytes must not hide host paths behind JSON escapes."""

import json

from sastsimi.contracts.prompt_redaction import (
    contains_local_file_url,
    redact_local_file_urls_value,
    sandbox_file_urls_only,
)


def test_sandbox_url_guard_rejects_json_escaped_host_url() -> None:
    data = (
        b'{"safe":"file:///tmp/sastsimi-poc-a",'
        b'"unsafe":"\\u0066ile:///C:/Users/alice/private"}'
    )

    assert contains_local_file_url(data)
    assert not sandbox_file_urls_only(data)


def test_sandbox_url_guard_allows_json_escaped_container_url() -> None:
    data = b'{"safe":"\\u0066ile:///tmp/sastsimi-poc-a"}'

    assert contains_local_file_url(data)
    assert sandbox_file_urls_only(data)


def test_sandbox_url_guard_rejects_nested_json_escaped_host_url() -> None:
    data = (
        b'{"safe":"file:///tmp/sastsimi-poc-a",'
        b'"nested":"{\\"unsafe\\":\\"\\\\u0066ile:///C:/Users/alice/private\\"}"}'
    )

    assert contains_local_file_url(data)
    assert not sandbox_file_urls_only(data)


def test_public_projection_redacts_nested_json_escaped_host_url() -> None:
    data = b'{"payload":"{\\"uri\\":\\"\\\\u0066ile:///C:/Users/alice/private\\"}"}'

    projected = redact_local_file_urls_value(json.loads(data))

    assert "private" not in json.dumps(projected)


def test_sandbox_guard_checks_json_text_below_nested_object_fields() -> None:
    data = json.dumps(
        {
            "safe": "file:///tmp/sastsimi-poc-a",
            "deep": {
                "a": {
                    "b": {"payload": '{"uri":"\\u0066ile:///C:/Users/alice/private"}'}
                }
            },
        }
    ).encode()

    assert contains_local_file_url(data)
    assert not sandbox_file_urls_only(data)


def test_deeply_encoded_json_host_url_is_redacted_and_rejected() -> None:
    nested = '{"uri":"\\u0066ile:///C:/Users/alice/private"}'
    for _ in range(4):
        nested = json.dumps({"payload": nested})
    data = json.dumps({"safe": "file:///tmp/sastsimi-poc-a", "nested": nested}).encode()

    assert contains_local_file_url(data)
    assert "private" not in json.dumps(redact_local_file_urls_value(json.loads(data)))
    assert not sandbox_file_urls_only(data)
    assert contains_local_file_url(json.dumps({"nested": nested}).encode())
