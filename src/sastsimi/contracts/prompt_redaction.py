"""Deterministic fail-closed redaction shared across trusted boundaries."""

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .canonical_json import canonical_bytes

_SECRET_KEY = re.compile(
    r"(?:api[_-]?key|authorization|\bauth\b|bearer|cookie|password|passwd|pwd|secret|"
    r"token|session|credential|private[_-]?key|access[_-]?key|database[_-]?(?:url|uri)|"
    r"connection[_-]?(?:url|uri|string)|dsn)",
    re.IGNORECASE,
)
_HIDDEN_KEY = re.compile(r"(?:chain[_-]?of[_-]?thought|hidden[_-]?reasoning)", re.I)
_LOCAL_FILE_URL = re.compile(r"(?i)\bfile:(?!\s)[^\r\n]*")
_LOCAL_FILE_URL_TOKEN = re.compile(r"(?i)\bfile:(?!\s)[^\s\r\n,;\"'<>]*")
_MAX_NESTED_JSON_DEPTH = 16
_OPAQUE_TOKEN = re.compile(
    r"(?i)(?:\b(?:bearer|basic)\s+[^\s,;]+|\bsk-[A-Za-z0-9_-]{8,}|"
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}|"
    r"\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{8,}|"
    r"\bglpat-[A-Za-z0-9_-]{8,}|\bxox[A-Za-z0-9]*-[A-Za-z0-9-]{8,}|"
    r"\b(?:AKIA|ASIA)[A-Z0-9]{12,})"
)
_COOKIE_ASSIGNMENT = re.compile(
    r"(?i)\b(?:cookies?|session[_-]?ids?|sessionid)\b\s*[:=]\s*"
    r'(?:"[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;]+)'
)
_TOKEN_ASSIGNMENT = re.compile(
    r"(?i)\b(?:access[_-]?tokens?|refresh[_-]?tokens?|tokens?)\b\s*[:=]\s*"
    r'(?:"[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;]+)'
)
_AUTHORIZATION_ASSIGNMENT = re.compile(
    r"(?i)\bauthorization\b\s*[:=]\s*"
    r'(?:"[^"\r\n]*"|\'[^\'\r\n]*\'|[^\r\n"\']+)'
)
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?keys?|client[_-]?secrets?|passwords?|passwd|pwd|"
    r"secrets?|authorization|auth|credentials?|private[_-]?keys?|"
    r"database[_-]?(?:url|uri)|connection[_-]?(?:url|uri|string)|dsn)\b\s*[:=]\s*"
    r'(?:"[^"\r\n]*"|\'[^\'\r\n]*\'|(?:bearer|basic)\s+[^\s,;]+|[^\s,;]+)'
)
_ENV_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)\b[A-Z_][A-Z0-9_]*(?:api[_-]?key|secret|token|password|passwd|pwd|"
    r"credential|private[_-]?key|access[_-]?key)[A-Z0-9_]*\b\s*[:=]\s*"
    r'(?:"[^"\r\n]*"|\'[^\'\r\n]*\'|[^\s,;]+)'
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
    r"(?i)(?<![\w])(?:[A-Z]:[\\/]|\\{2,}(?![\\\"]))[^\r\n,;\"'<>]+"
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
_LINE_BREAK = re.compile(r"\r\n|[\r\n]")
_POC_SENSITIVE_RULE_PATTERNS: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("COOKIE_ASSIGNMENT", _COOKIE_ASSIGNMENT, "COOKIE"),
    ("TOKEN_ASSIGNMENT", _TOKEN_ASSIGNMENT, "TOKEN"),
    ("AUTHORIZATION_ASSIGNMENT", _AUTHORIZATION_ASSIGNMENT, "CREDENTIAL"),
    ("CREDENTIAL_ASSIGNMENT", _CREDENTIAL_ASSIGNMENT, "CREDENTIAL"),
    ("ENV_CREDENTIAL_ASSIGNMENT", _ENV_CREDENTIAL_ASSIGNMENT, "CREDENTIAL"),
    ("CREDENTIAL_URI", _CREDENTIAL_URI, "CREDENTIAL"),
    ("OPAQUE_TOKEN", _OPAQUE_TOKEN, "TOKEN"),
    ("WINDOWS_HOST_PATH", _WINDOWS_PATH, "HOST_ABSOLUTE_PATH"),
    ("POSIX_HOST_PATH", _POSIX_HOST_PATH, "HOST_ABSOLUTE_PATH"),
)
POC_SENSITIVE_RULE_CATEGORY = {
    rule_id: category for rule_id, _, category in _POC_SENSITIVE_RULE_PATTERNS
} | {"PRIVATE_KEY_HEADER": "CREDENTIAL"}
POC_SENSITIVE_RULE_IDS = frozenset(
    {"UNCLASSIFIED", "REDACTION_MISMATCH", "PRIVATE_KEY_HEADER"}
    | {rule_id for rule_id, _, _ in _POC_SENSITIVE_RULE_PATTERNS}
)


def _protect_safe_sandbox_paths(value: str) -> str:
    for path, marker in _SAFE_SANDBOX_PATHS.items():
        value = value.replace(path, marker)
    return value


def _restore_safe_sandbox_paths(value: str) -> str:
    for path, marker in _SAFE_SANDBOX_PATHS.items():
        value = value.replace(marker, path)
    return value


@dataclass(frozen=True)
class RedactionResult:
    data: bytes
    categories: tuple[str, ...]


def is_sensitive_name(value: str) -> bool:
    """Use the same sensitive-name policy for source and JSON redaction."""

    return bool(_SECRET_KEY.search(value))


def _replace_string(
    value: str, *, preserve_lines: bool = False
) -> tuple[str, set[str]]:
    if _PRIVATE_KEY.search(value) or _PRIVATE_KEY_HEADER.search(value):
        if preserve_lines:
            raise ValueError("PROMPT_REDACTION_FAILED")
        return "[REDACTED:CREDENTIAL]", {"CREDENTIAL"}

    result = _protect_safe_sandbox_paths(value)
    categories: set[str] = set()

    def replacement(match: re.Match[str], category: str) -> str:
        line_breaks = (
            "".join(_LINE_BREAK.findall(match.group(0))) if preserve_lines else ""
        )
        return f"[REDACTED:{category}]{line_breaks}"

    for pattern, category in (
        (_COOKIE_ASSIGNMENT, "COOKIE"),
        (_TOKEN_ASSIGNMENT, "TOKEN"),
        (_AUTHORIZATION_ASSIGNMENT, "CREDENTIAL"),
        (_CREDENTIAL_ASSIGNMENT, "CREDENTIAL"),
        (_ENV_CREDENTIAL_ASSIGNMENT, "CREDENTIAL"),
        (_CREDENTIAL_URI, "CREDENTIAL"),
    ):

        def replace_current(match: re.Match[str], category: str = category) -> str:
            return replacement(match, category)

        result, count = pattern.subn(replace_current, result)
        if count:
            categories.add(category)
    result, token_count = _OPAQUE_TOKEN.subn(
        lambda match: replacement(match, "TOKEN"), result
    )
    if token_count:
        categories.add("TOKEN")
    result, windows_count = _WINDOWS_PATH.subn(
        lambda match: replacement(match, "HOST_ABSOLUTE_PATH"), result
    )
    result, posix_count = _POSIX_HOST_PATH.subn(
        lambda match: replacement(match, "HOST_ABSOLUTE_PATH"), result
    )
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
            or _COOKIE_ASSIGNMENT.search(value)
            or _TOKEN_ASSIGNMENT.search(value)
            or _AUTHORIZATION_ASSIGNMENT.search(value)
            or _CREDENTIAL_ASSIGNMENT.search(value)
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
    # Check the complete script before masking any path. A credential value
    # can extend past the path matcher (for example, ``/workspace/token= x``).
    # In that case the ordinary redactor must see the whole assignment.
    if any(
        pattern.search(value["content"])
        for pattern in (
            _OPAQUE_TOKEN,
            _COOKIE_ASSIGNMENT,
            _TOKEN_ASSIGNMENT,
            _AUTHORIZATION_ASSIGNMENT,
            _CREDENTIAL_ASSIGNMENT,
            _ENV_CREDENTIAL_ASSIGNMENT,
            _CREDENTIAL_URI,
            _PRIVATE_KEY_HEADER,
        )
    ):
        return redact_projected_json(data)
    protected_paths: list[tuple[bytes, bytes]] = []

    def protect_path(match: re.Match[str]) -> str:
        path = match.group(0)
        marker = f"SASTSIMI_SANDBOX_ABSOLUTE_PATH_{len(protected_paths)}"
        protected_paths.append((marker.encode("utf-8"), path.encode("utf-8")))
        return marker

    protected = {
        "content": _POC_SANDBOX_ABSOLUTE_PATH.sub(protect_path, value["content"])
    }
    inspected = redact_projected_json(canonical_bytes(protected))
    restored = inspected.data
    # Restore later indexes first so _1 cannot corrupt _10 and beyond.
    for marker, path in reversed(protected_paths):
        restored = restored.replace(marker, path)
    return RedactionResult(restored, inspected.categories)


def poc_candidate_sensitive_rule_id(source: str, first_difference: int) -> str:
    """Name only the first matched rule; never return source text or values."""

    if _PRIVATE_KEY_HEADER.search(source):
        return "PRIVATE_KEY_HEADER"
    for rule_id, pattern, _ in _POC_SENSITIVE_RULE_PATTERNS:
        if any(match.start() == first_difference for match in pattern.finditer(source)):
            return rule_id
    # A projected redaction may start inside a matched span after earlier
    # substitutions. Keep this fallback bounded to the same closed rule IDs.
    for rule_id, pattern, _ in _POC_SENSITIVE_RULE_PATTERNS:
        if any(
            match.start() <= first_difference < match.end()
            for match in pattern.finditer(source)
        ):
            return rule_id
    return "REDACTION_MISMATCH"


def redact_untrusted_text(data: bytes) -> RedactionResult:
    """Return deterministic UTF-8 bytes with credentials and host paths removed."""
    value = data.decode("utf-8", errors="replace")
    redacted, categories = _replace_string(value)
    if _has_sensitive_string(redacted):
        raise ValueError("PROMPT_REDACTION_FAILED")
    return RedactionResult(redacted.encode("utf-8"), tuple(sorted(categories)))


def redact_untrusted_text_preserving_lines(data: bytes) -> RedactionResult:
    """Redact a complete source file before paging without shifting line numbers."""

    value = data.decode("utf-8")
    redacted, categories = _replace_string(value, preserve_lines=True)
    if (
        value.count("\r") != redacted.count("\r")
        or value.count("\n") != redacted.count("\n")
        or _replace_string(redacted)[0] != redacted
        or _has_sensitive_string(redacted)
    ):
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


def redact_local_file_urls(value: str) -> str:
    """Remove local repository URLs from a public single-line field or report."""

    return _LOCAL_FILE_URL.sub("[REDACTED:LOCAL_FILE_URL]", value)


def redact_local_file_urls_value(value: object, *, _depth: int = 0) -> object:
    """Redact local URLs in projected JSON, including bounded nested JSON text."""

    if isinstance(value, str):
        if value.lstrip().startswith(("{", "[", '"')):
            if _depth >= _MAX_NESTED_JSON_DEPTH:
                return "[REDACTED:NESTED_JSON_DEPTH]"
            try:
                nested = json.loads(value)
            except ValueError:
                pass
            else:
                projected = redact_local_file_urls_value(nested, _depth=_depth + 1)
                if projected != nested:
                    return json.dumps(projected, ensure_ascii=False, sort_keys=True)
        return redact_local_file_urls(value)
    if isinstance(value, Mapping):
        return {
            redact_local_file_urls_value(
                key, _depth=_depth
            ): redact_local_file_urls_value(item, _depth=_depth)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_local_file_urls_value(item, _depth=_depth) for item in value]
    return value


def contains_local_file_url(data: bytes) -> bool:
    """Find plain or JSON-escaped local URLs before serving stored public bytes."""

    text = data.decode("utf-8", errors="replace")
    if _LOCAL_FILE_URL.search(text):
        return True
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return False

    return bool(redact_local_file_urls_value(parsed) != parsed)


def sandbox_file_urls_only(data: bytes) -> bool:
    """Allow only unambiguous, container-local file URLs in a shell PoC."""

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    texts = [text]
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        parsed = None

    def collect_strings(value: object, depth: int, nested_depth: int) -> bool:
        if depth > 32:
            return False
        if isinstance(value, str):
            texts.append(value)
            if value.lstrip().startswith(("{", "[", '"')):
                if nested_depth >= _MAX_NESTED_JSON_DEPTH:
                    return False
                try:
                    nested = json.loads(value)
                except (ValueError, TypeError):
                    return True
                return collect_strings(nested, depth + 1, nested_depth + 1)
            return True
        if isinstance(value, Mapping):
            return all(
                collect_strings(key, depth + 1, nested_depth)
                and collect_strings(item, depth + 1, nested_depth)
                for key, item in value.items()
            )
        if isinstance(value, list):
            return all(collect_strings(item, depth + 1, nested_depth) for item in value)
        return True

    if parsed is not None and not collect_strings(parsed, 0, 0):
        return False
    urls = [uri for value in texts for uri in _LOCAL_FILE_URL_TOKEN.findall(value)]
    if not urls:
        return False
    for uri in urls:
        if re.fullmatch(r"(?i)file:///tmp(?:/[A-Za-z0-9._-]+)*", uri) is None:
            return False
        if any(part in {".", ".."} for part in uri[11:].split("/")):
            return False
    return True


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
