"""Deterministic fail-closed redaction shared across trusted boundaries."""

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .canonical_json import canonical_bytes

_SECRET_KEY = re.compile(
    r"(?:api[_-]?key|authorization|bearer|cookie|password|passwd|pwd|secret|"
    r"token|session|credential|private[_-]?key|access[_-]?key|database[_-]?(?:url|uri)|"
    r"connection[_-]?(?:url|uri|string)|dsn)",
    re.IGNORECASE,
)
_HIDDEN_KEY = re.compile(r"(?:chain[_-]?of[_-]?thought|hidden[_-]?reasoning)", re.I)
_OPAQUE_TOKEN = re.compile(
    # The value after a scheme must look like a credential.  Matching any
    # non-space run also matched prose - a report explaining that a stolen key
    # is reusable "like a Bearer token" was refused as if it carried one - and
    # a real bearer value is always an ASCII token of some length.
    r"(?i)(?:\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}|\bsk-[A-Za-z0-9_-]{8,}|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}|"
    r"\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{8,}|"
    r"\bglpat-[A-Za-z0-9_-]{8,}|\bxox[A-Za-z0-9]*-[A-Za-z0-9-]{8,}|"
    r"\b(?:AKIA|ASIA)[A-Z0-9]{12,})"
)
_COOKIE_ASSIGNMENT = re.compile(
    r"(?i)\b(?P<key>cookies?|session[_-]?ids?|sessionid)\b\s*[:=]\s*"
    r'(?P<value>"[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;]+)'
)
_TOKEN_ASSIGNMENT = re.compile(
    r"(?i)\b(?P<key>access[_-]?tokens?|refresh[_-]?tokens?|tokens?)\b\s*[:=]\s*"
    r'(?P<value>"[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;]+)'
)
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)\b(?P<key>api[_-]?keys?|client[_-]?secrets?|passwords?|passwd|pwd|"
    r"secrets?|authorization|auth|credentials?|private[_-]?keys?|"
    r"database[_-]?(?:url|uri)|connection[_-]?(?:url|uri|string)|dsn)\b\s*[:=]\s*"
    r'(?P<value>"[^"\r\n]*"|\'[^\'\r\n]*\'|(?:bearer|basic)\s+[^\s,;]+|[^\s,;]+)'
)
# A report quoting code names a credential without carrying one: the header
# template "Authorization: Bearer <MATRIX_ACCESS_TOKEN>" and the keyword
# argument "auth=auth" were refused on healthchecks.  Only a named placeholder
# or a keyword argument passing a same-named variable is exempt; anything
# with a literal value still matches.
_PLACEHOLDER_VALUE = re.compile(
    r"[\"'`]?(?:(?i:bearer|basic)\s+)?"
    r"(?:<[A-Za-z][\w.-]*>|\{[A-Za-z_]\w*\}|\$\{?[A-Z_][A-Z0-9_]*\}?)"
    r"(?![A-Za-z0-9._~+/=-])"
)
_KEYWORD_ARGUMENT = re.compile(r"[A-Za-z_]\w*(?=[,)])")
_ASSIGNMENT_PATTERNS = (
    (_COOKIE_ASSIGNMENT, "COOKIE"),
    (_TOKEN_ASSIGNMENT, "TOKEN"),
    (_CREDENTIAL_ASSIGNMENT, "CREDENTIAL"),
)
_CREDENTIAL_URI = re.compile(
    r"(?i)\b[a-z][a-z0-9+.-]*://[^\s:/?#]+:[^@\s/]+@[^\s,;\"']+"
)
_PRIVATE_KEY = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----[\s\S]*?"
    r"-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.IGNORECASE,
)
_PRIVATE_KEY_HEADER = re.compile(
    r"-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----",
    re.IGNORECASE,
)
_WINDOWS_PATH = re.compile(
    r"(?i)(?<![\w])(?:[A-Z]:[\\/]|\\\\(?![\\\"]))[^\r\n,;\"'<>]+"
)
_POSIX_HOST_PATH = re.compile(
    r"(?<![\w/])/(?:root|home|Users|tmp|etc|var|opt|srv|usr|private)"
    r"(?:/|\b)[^\r\n,;\"'<>]*"
)
_SAFE_SANDBOX_PATHS = {"/tmp/sastsimi-poc-candidate": "SASTSIMI_SAFE_POC_RUNTIME_PATH"}
_POC_SANDBOX_ABSOLUTE_PATH = re.compile(
    r"(?<![\w/])/(?:workspace|tmp|etc|var|opt|srv|usr)(?:/|\b)"
    r"[^\s\r\n,;\"'<>]*"
)


def _protect_safe_sandbox_paths(value: str) -> str:
    for path, marker in _SAFE_SANDBOX_PATHS.items():
        value = value.replace(path, marker)
    return value


def _restore_safe_sandbox_paths(value: str) -> str:
    for path, marker in _SAFE_SANDBOX_PATHS.items():
        value = value.replace(marker, path)
    return value


def _names_no_value(match: re.Match[str]) -> bool:
    value = match.group("value")
    if _PLACEHOLDER_VALUE.match(value):
        return True
    following = match.string[match.end() : match.end() + 1]
    named = _KEYWORD_ARGUMENT.match(value + following)
    return named is not None and named.group(0).lower() == match.group("key").lower()


def _redact_assignments(
    pattern: re.Pattern[str], marker: str, value: str
) -> tuple[str, int]:
    parts: list[str] = []
    count = 0
    position = 0
    for match in pattern.finditer(value):
        if _names_no_value(match):
            continue
        parts.append(value[position : match.start()])
        parts.append(marker)
        position = match.end()
        count += 1
    parts.append(value[position:])
    return "".join(parts), count


def _has_assignment(pattern: re.Pattern[str], value: str) -> bool:
    return any(not _names_no_value(match) for match in pattern.finditer(value))


@dataclass(frozen=True)
class RedactionResult:
    data: bytes
    categories: tuple[str, ...]


def _replace_string(value: str) -> tuple[str, set[str]]:
    if _PRIVATE_KEY.search(value) or _PRIVATE_KEY_HEADER.search(value):
        return "[REDACTED:CREDENTIAL]", {"CREDENTIAL"}

    result = _protect_safe_sandbox_paths(value)
    categories: set[str] = set()
    for pattern, category in _ASSIGNMENT_PATTERNS:
        result, count = _redact_assignments(pattern, f"[REDACTED:{category}]", result)
        if count:
            categories.add(category)
    result, count = _CREDENTIAL_URI.subn("[REDACTED:CREDENTIAL]", result)
    if count:
        categories.add("CREDENTIAL")
    result, token_count = _OPAQUE_TOKEN.subn("[REDACTED:TOKEN]", result)
    if token_count:
        categories.add("TOKEN")
    result, windows_count = _WINDOWS_PATH.subn("[REDACTED:HOST_ABSOLUTE_PATH]", result)
    result, posix_count = _POSIX_HOST_PATH.subn("[REDACTED:HOST_ABSOLUTE_PATH]", result)
    if windows_count or posix_count:
        categories.add("HOST_ABSOLUTE_PATH")
    return _restore_safe_sandbox_paths(result), categories


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
        for key, item in value.items():
            if _SECRET_KEY.search(str(key)) and item != "[REDACTED:CREDENTIAL]":
                return True
            if _has_sensitive_string(item):
                return True
        return False
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return any(_has_sensitive_string(item) for item in value)
    if isinstance(value, str):
        value = _protect_safe_sandbox_paths(value)
        return bool(
            _OPAQUE_TOKEN.search(value)
            or any(
                _has_assignment(pattern, value) for pattern, _ in _ASSIGNMENT_PATTERNS
            )
            or _CREDENTIAL_URI.search(value)
            or _PRIVATE_KEY.search(value)
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


def inspect_poc_candidate_json(data: bytes) -> RedactionResult:
    """Inspect one PoC candidate while preserving sandbox-local POSIX paths.

    PoC candidate content executes only inside the prepared Sandbox.  A script
    may therefore use ordinary container paths needed by the reproduction
    without exposing a host path.  User-home paths, Windows host paths, and all
    secret categories remain subject to the fail-closed checks.
    """

    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("PROMPT_REDACTION_FAILED") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"content"}
        or not isinstance(value["content"], str)
    ):
        raise ValueError("PROMPT_REDACTION_FAILED")
    protected_paths: list[tuple[bytes, bytes]] = []

    def protect_path(match: re.Match[str]) -> str:
        marker = f"SASTSIMI_SANDBOX_ABSOLUTE_PATH_{len(protected_paths)}"
        protected_paths.append((marker.encode("utf-8"), match.group(0).encode("utf-8")))
        return marker

    protected = {
        "content": _POC_SANDBOX_ABSOLUTE_PATH.sub(protect_path, value["content"])
    }
    inspected = redact_projected_json(canonical_bytes(protected))
    restored = inspected.data
    for marker, path in protected_paths:
        restored = restored.replace(marker, path)
    return RedactionResult(restored, inspected.categories)


def redact_untrusted_text(data: bytes) -> RedactionResult:
    """Return deterministic UTF-8 bytes with credentials and host paths removed."""
    value = data.decode("utf-8", errors="replace")
    redacted, categories = _replace_string(value)
    if _has_sensitive_string(redacted):
        raise ValueError("PROMPT_REDACTION_FAILED")
    return RedactionResult(redacted.encode("utf-8"), tuple(sorted(categories)))


def assert_safe_provider_text(data: bytes) -> None:
    """Reject non-JSON provider text containing credentials or host paths."""
    try:
        value = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("PROMPT_REDACTION_FAILED") from error
    redacted, categories = _replace_string(value)
    if categories or redacted != value or _has_sensitive_string(value):
        raise ValueError("PROMPT_REDACTION_FAILED")


def render_provider_prompt(
    template: bytes, bindings: tuple[tuple[str, bytes], ...]
) -> bytes:
    """Render provider input deterministically from redacted binding artifacts."""
    assert_safe_provider_text(template)
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
    rendered = (
        template + b"\n<UNTRUSTED_DATA>\n" + data_section + b"\n</UNTRUSTED_DATA>\n"
    )
    assert_safe_provider_text(rendered)
    return rendered
