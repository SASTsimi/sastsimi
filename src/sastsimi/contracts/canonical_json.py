"""SASTSIMI Canonical JSON v1. Semantic sorting is opt-in per field path."""

import hashlib
import json
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import Enum
from uuid import UUID

from pydantic import BaseModel

from .base import ContractModel
from .ids import OpaqueId

CANONICAL_JSON_VERSION = "canonical-json-v1"
type SetListPolicy = Mapping[tuple[str, ...], str | None]


def _normalize(
    value: object, policy: SetListPolicy, path: tuple[str, ...], reject_hash: bool
) -> object:
    if isinstance(value, BaseModel):
        if not isinstance(value, (ContractModel, OpaqueId)):
            raise TypeError("Canonical JSON requires a contract model")
        if (
            value.__pydantic_extra__
            or value.__dict__.keys() - type(value).model_fields.keys()
        ):
            raise ValueError("Canonical contract models cannot contain extra members")
        if isinstance(value, OpaqueId):
            return _normalize(value.root, policy, path, reject_hash)
        # Reading fields avoids custom JSON serializers coercing forbidden floats.
        value = {name: getattr(value, name) for name in type(value).model_fields}
    if isinstance(value, Enum):
        return _normalize(value.value, policy, path, reject_hash)
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Canonical datetime must be timezone-aware")
        return (
            value.astimezone(UTC)
            .isoformat(timespec="microseconds")
            .replace("+00:00", "Z")
        )
    if isinstance(value, UUID):
        return str(value)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("JSON object keys must be strings")
        if reject_hash and not path and "content_hash" in value:
            raise ValueError("content_hash member would be self-referential")
        return {
            key: _normalize(item, policy, (*path, key), reject_hash)
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        items = [_normalize(item, policy, (*path, "*"), reject_hash) for item in value]
        if path in policy:
            key = policy[path]

            def sort_key(item: object) -> bytes:
                if key is None:
                    return _encode(item)
                if not isinstance(item, dict) or key not in item:
                    raise ValueError(f"Semantic list item missing key {key}")
                return _encode(item[key])

            items.sort(key=sort_key)
        return items
    raise TypeError(
        f"Unsupported canonical JSON value: {type(value).__name__}; "
        "numbers must be integers"
    )


def _encode(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_bytes(
    value: object, *, set_list_keys: SetListPolicy | None = None
) -> bytes:
    return _encode(_normalize(value, set_list_keys or {}, (), False))


def content_hash(value: object, *, set_list_keys: SetListPolicy | None = None) -> str:
    return hashlib.sha256(
        _encode(_normalize(value, set_list_keys or {}, (), True))
    ).hexdigest()
