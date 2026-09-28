"""Validate survey proposals against the tracked checkout before registration."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from typing import Any

from sastsimi.contracts.canonical_json import canonical_bytes

_FIELDS = ("title", "vulnerability_type", "summary", "source", "sink", "rationale")
_LOCATION = re.compile(r"^(?P<path>[^:]+):(?P<line>[1-9][0-9]*)$")


def validate_proposal(
    raw: object, *, lines: Mapping[str, int]
) -> tuple[dict[str, Any] | None, tuple[str, ...]]:
    if not isinstance(raw, dict):
        return None, ("NOT_AN_OBJECT",)
    errors: list[str] = []
    for key in _FIELDS:
        if not isinstance(raw.get(key), str) or not raw[key].strip():
            errors.append(f"{key} is missing")
    locations = raw.get("code_locations")
    if not isinstance(locations, list) or not locations:
        errors.append("code_locations is missing")
    else:
        for location in locations:
            match = _LOCATION.fullmatch(location) if isinstance(location, str) else None
            if match is None:
                errors.append("invalid code location")
                continue
            path, line = match.group("path"), int(match.group("line"))
            if path not in lines or line > lines[path]:
                errors.append("code location is outside the tracked checkout")
    if errors:
        return None, tuple(errors)
    return dict(raw), ()


def proposal_key(proposal: Mapping[str, Any]) -> str:
    identity = {
        "type": proposal["vulnerability_type"],
        "locations": proposal["code_locations"],
        "source": proposal["source"],
        "sink": proposal["sink"],
    }
    return hashlib.sha256(canonical_bytes(identity)).hexdigest()
