from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal
from enum import StrEnum
from uuid import UUID

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes, content_hash


def test_approved_canonical_fixture() -> None:
    value = {"t": datetime(2026, 9, 7, tzinfo=UTC), "n": 1, "b": "한글", "a": None}
    expected = '{"a":null,"b":"한글","n":1,"t":"2026-09-07T00:00:00.000000Z"}'.encode()
    assert canonical_bytes(value) == expected
    assert len(expected) == 63
    assert (
        content_hash(value)
        == "957b116406dddaf7928bd028a12602346873237f935f866530949547422122da"
    )


@pytest.mark.parametrize(
    "value",
    [
        0.1,
        float("nan"),
        float("inf"),
        -float("inf"),
        Decimal("1.2"),
        b"bytes",
        {1: "bad"},
    ],
)
def test_non_json_or_non_integer_numbers_are_rejected(value: object) -> None:
    with pytest.raises((ValueError, TypeError)):
        canonical_bytes(value)


def test_order_sensitive_arrays_and_explicit_semantic_sets() -> None:
    value = {"ordered": [2, 1], "members": [{"id": "b"}, {"id": "a"}]}
    assert (
        canonical_bytes(value, set_list_keys={("members",): "id"})
        == b'{"members":[{"id":"a"},{"id":"b"}],"ordered":[2,1]}'
    )
    assert canonical_bytes([2, 1]) != canonical_bytes([1, 2])
    assert canonical_bytes({"b": 1, "a": None}) == canonical_bytes({"a": None, "b": 1})


def test_unicode_timezone_uuid_and_enum() -> None:
    class Choice(StrEnum):
        YES = "yes"

    assert canonical_bytes("é") != canonical_bytes("e\u0301")
    assert (
        canonical_bytes(datetime(2026, 9, 7, 9, tzinfo=timezone(timedelta(hours=9))))
        == b'"2026-09-07T00:00:00.000000Z"'
    )
    assert (
        canonical_bytes(UUID("AABBCCDD-0000-0000-0000-000000000000"))
        == b'"aabbccdd-0000-0000-0000-000000000000"'
    )
    assert canonical_bytes(Choice.YES) == b'"yes"'
    with pytest.raises(ValueError):
        canonical_bytes(datetime(2026, 9, 7))


def test_hash_rejects_self_referential_members() -> None:
    with pytest.raises(ValueError, match="content_hash"):
        content_hash({"content_hash": "x"})


def test_nested_reference_hashes_are_provenance_not_self_inclusion() -> None:
    import hashlib

    from sastsimi.contracts.refs import StoredDataRef

    ref = StoredDataRef.model_validate_json(
        '{"stored_data_id":"s1","data_kind":"work_attempt","content_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","workspace_id":"w1","commit_id":"c1","record_id":"r1"}'
    )
    for value in ({"ref": ref}, {"refs": [ref]}, {"refs": {"first": ref}}):
        encoded = canonical_bytes(value)
        assert (
            b'"content_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
            in encoded
        )
        assert content_hash(value) == hashlib.sha256(encoded).hexdigest()
    with pytest.raises(ValueError, match="content_hash"):
        content_hash(ref)
