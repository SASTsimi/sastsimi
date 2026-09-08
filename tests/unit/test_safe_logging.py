import io
import json
import logging

import pytest


def test_recursive_safe_json_lines() -> None:
    from sastsimi.logging import SafeJsonFormatter, safe_event

    sentinel = "TEST_ONLY_REGISTERED_SECRET"
    fields = {
        "nested": [
            {
                "message": f"prefix {sentinel} suffix",
                "path": r"C:\Users\synthetic\secret.txt",
            },
            "/home/synthetic/secret",
            "src/sastsimi/config/loader.py",
        ],
        "cookie": "TEST_ONLY_COOKIE",
        "session_id": "TEST_ONLY_SESSION",
        "hidden_reasoning": "TEST_ONLY_REASONING",
        "text": "Authorization: Bearer TEST_ONLY_BEARER",
        "key": "sk-testonly1234567890",
        "password_text": "TEST_ONLY_PASSWORD",
    }
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(SafeJsonFormatter(secrets=(sentinel,)))
    logger = logging.Logger("isolated")
    logger.addHandler(handler)
    logger.info(safe_event("config_loaded", fields, trace_id="trace-1"))
    raw = stream.getvalue()
    for forbidden in [
        sentinel,
        "synthetic",
        "TEST_ONLY_COOKIE",
        "TEST_ONLY_SESSION",
        "TEST_ONLY_REASONING",
        "TEST_ONLY_BEARER",
        "sk-testonly1234567890",
        "TEST_ONLY_PASSWORD",
    ]:
        assert forbidden not in raw
    event = json.loads(raw)
    assert event["event"] == "config_loaded"
    assert event["level"] == "INFO"
    assert event["trace_id"] == "trace-1"
    assert "src/sastsimi/config/loader.py" in raw
    assert len(raw.splitlines()) == 1


@pytest.mark.parametrize("value", [object(), float("nan"), {1: "value"}])
def test_unsafe_serialization_is_rejected(value: object) -> None:
    from sastsimi.logging import UnsafeLogEvent, safe_event

    with pytest.raises(UnsafeLogEvent):
        safe_event("event", {"value": value})


def test_cycle_is_rejected() -> None:
    from sastsimi.logging import UnsafeLogEvent, safe_event

    cyclic: list[object] = []
    cyclic.append(cyclic)
    with pytest.raises(UnsafeLogEvent):
        safe_event("event", {"value": cyclic})


def test_formatter_rejects_raw_messages_and_discards_exception() -> None:
    from sastsimi.logging import SafeJsonFormatter, safe_event

    formatter = SafeJsonFormatter()
    record = logging.LogRecord(
        "x", logging.ERROR, "/home/synthetic/x", 1, "TEST_ONLY_RAW_SECRET", (), None
    )
    assert "TEST_ONLY_RAW_SECRET" not in formatter.format(record)
    record.msg = safe_event("failure", {})
    record.exc_info = (ValueError, ValueError("TEST_ONLY_EXCEPTION"), None)
    assert "TEST_ONLY_EXCEPTION" not in formatter.format(record)


@pytest.mark.parametrize(
    "value",
    [
        r"prefix C:\Users\synthetic\file suffix",
        "prefix /home/synthetic/file suffix",
        r"\\server\share\secret",
        "https://user:TEST_ONLY_PASSWORD@example.test",
        "cookie=TEST_ONLY_COOKIE",
        "token=TEST_ONLY_TOKEN",
    ],
)
def test_unlabelled_sensitive_strings_redacted(value: str) -> None:
    from sastsimi.logging import SafeJsonFormatter, safe_event

    record = logging.LogRecord(
        "x", logging.INFO, "", 0, safe_event("event", {"message": value}), (), None
    )
    raw = SafeJsonFormatter().format(record)
    assert value not in raw
    assert "TEST_ONLY" not in raw
    assert "synthetic" not in raw
