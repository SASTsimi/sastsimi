from __future__ import annotations

import pytest

from sastsimi.simple_runtime.provider import _validate_schema


def test_nullable_union_and_array_bounds_are_enforced() -> None:
    schema = {
        "type": "object",
        "required": ["items"],
        "additionalProperties": False,
        "properties": {
            "items": {
                "type": "array",
                "maxItems": 1,
                "items": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            }
        },
    }
    _validate_schema({"items": [None]}, schema)
    with pytest.raises(ValueError):
        _validate_schema({"items": [123]}, schema)
    with pytest.raises(ValueError):
        _validate_schema({"items": ["one", "two"]}, schema)
