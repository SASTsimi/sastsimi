"""Deterministic fail-closed redaction for provider-visible prompt data."""

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from sastsimi.contracts.canonical_json import canonical_bytes

_SECRET_KEY = re.compile(
    r"(?:api[_-]?key|authorization|bearer|cookie|password|secret|token|session)",
    re.IGNORECASE,
)
_HIDDEN_KEY = re.compile(r"(?:chain[_-]?of[_-]?thought|hidden[_-]?reasoning)", re.I)
_OPAQUE_TOKEN = re.compile(
    r"(?i)(?:\b(?:bearer|basic)\s+[^\s,;]+|\bsk-[A-Za-z0-9_-]{8,}|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}|"
    r"\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{8,}|"
    r"\bglpat-[A-Za-z0-9_-]{8,}|\bxox[A-Za-z0-9]*-[A-Za-z0-9-]{8,}|"
    r"\bAKIA[A-Z0-9]{12,})"
)
_COOKIE_ASSIGNMENT = re.compile(
    r"(?i)\b(?:cookies?|session[_-]?ids?|sessionid)\b\s*[:=]\s*"
    r'(?:"[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;]+)'
)
_TOKEN_ASSIGNMENT = re.compile(
    r"(?i)\b(?:access[_-]?tokens?|refresh[_-]?tokens?|tokens?)\b\s*[:=]\s*"
    r'(?:"[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;]+)'
)
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?keys?|client[_-]?secrets?|passwords?|passwd|pwd|"
    r"secrets?|authorization|auth)\b\s*[:=]\s*"
    r'(?:"[^"\r\n]*"|\'[^\'\r\n]*\'|(?:bearer|basic)\s+[^\s,;]+|[^\s,;]+)'
)
_WINDOWS_PATH = re.compile(r"""(?i)(?<![\w])(?:[A-Z]:[\\/]|\\\\)[^\s,;"']+""")
_POSIX_HOST_PATH = re.compile(
    r"""(?<![\w/])/(?:root|home|Users|tmp|etc|var|opt|srv|usr|private)/[^\s,;"']+"""
)


@dataclass(frozen=True)
class RedactionResult:
    data: bytes
    categories: tuple[str, ...]


def _replace_string(value: str) -> tuple[str, set[str]]:
    result = value
    categories: set[str] = set()
    for pattern, category in (
        (_COOKIE_ASSIGNMENT, "COOKIE"),
        (_TOKEN_ASSIGNMENT, "TOKEN"),
        (_CREDENTIAL_ASSIGNMENT, "CREDENTIAL"),
    ):
        result, count = pattern.subn(f"[REDACTED:{category}]", result)
        if count:
            categories.add(category)
    result, token_count = _OPAQUE_TOKEN.subn("[REDACTED:TOKEN]", result)
    if token_count:
        categories.add("TOKEN")
    result, windows_count = _WINDOWS_PATH.subn("[REDACTED:HOST_ABSOLUTE_PATH]", result)
    result, posix_count = _POSIX_HOST_PATH.subn("[REDACTED:HOST_ABSOLUTE_PATH]", result)
    if windows_count or posix_count:
        categories.add("HOST_ABSOLUTE_PATH")
    return result, categories


def _redact(value: object) -> tuple[object, set[str]]:
    if isinstance(value, Mapping):
        output: dict[str, object] = {}
        categories: set[str] = set()
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("PROMPT_REDACTION_FAILED")
            if _HIDDEN_KEY.fullmatch(key):
                output[key] = "[REDACTED:HIDDEN_REASONING]"
                categories.add("HIDDEN_REASONING")
            elif _SECRET_KEY.search(key):
                output[key] = "[REDACTED:CREDENTIAL]"
                categories.add("CREDENTIAL")
            else:
                output[key], nested = _redact(item)
                categories.update(nested)
        return output, categories
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        items: list[object] = []
        sequence_categories: set[str] = set()
        for item in value:
            redacted, nested = _redact(item)
            items.append(redacted)
            sequence_categories.update(nested)
        return items, sequence_categories
    if isinstance(value, str):
        return _replace_string(value)
    if value is None or isinstance(value, (bool, int)):
        return value, set()
    raise ValueError("PROMPT_REDACTION_FAILED")


def _has_sensitive_string(value: object) -> bool:
    if isinstance(value, Mapping):
        return any(_has_sensitive_string(item) for item in value.values())
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(_has_sensitive_string(item) for item in value)
    if isinstance(value, str):
        return bool(
            _OPAQUE_TOKEN.search(value)
            or _COOKIE_ASSIGNMENT.search(value)
            or _TOKEN_ASSIGNMENT.search(value)
            or _CREDENTIAL_ASSIGNMENT.search(value)
            or _WINDOWS_PATH.search(value)
            or _POSIX_HOST_PATH.search(value)
        )
    return False


def redact_projected_json(data: bytes) -> RedactionResult:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("PROMPT_REDACTION_FAILED") from error
    redacted, categories = _redact(value)
    encoded = canonical_bytes(redacted)
    if _has_sensitive_string(redacted):
        raise ValueError("PROMPT_REDACTION_FAILED")
    return RedactionResult(encoded, tuple(sorted(categories)))


def render_provider_prompt(
    template: bytes, bindings: tuple[tuple[str, bytes], ...]
) -> bytes:
    """Render provider input deterministically from redacted binding artifacts."""
    rendered_bindings: list[dict[str, object]] = []
    for slot, projected in bindings:
        redacted = redact_projected_json(projected).data
        rendered_bindings.append(
            {
                "slot": slot,
                "trust_class": "UNTRUSTED_DATA",
                "sha256": hashlib.sha256(redacted).hexdigest(),
                "data": json.loads(redacted.decode("utf-8")),
            }
        )
    data_section = canonical_bytes({"bindings": rendered_bindings})
    data_section = data_section.replace(b"<", b"\\u003c").replace(b">", b"\\u003e")
    return template + b"\n<UNTRUSTED_DATA>\n" + data_section + b"\n</UNTRUSTED_DATA>\n"
