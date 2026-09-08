"""A single fail-closed JSON Lines boundary for structured events.

Raw logging records and exception details are never serialized. Sensitive
strings are replaced as a whole: partial substitutions are not a safety proof.
"""

import json
import logging
import math
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TextIO

_REDACTED = "[REDACTED]"
_SENSITIVE_KEY = re.compile(
    r"secret|password|token|cookie|session|authorization|api.?key|reasoning|chain.?of.?thought",
    re.IGNORECASE,
)
_SENSITIVE_VALUE = re.compile(
    r"(?:[a-z]:[\\/]|\\\\|(?<![a-z0-9_.-])/(?!/)|"
    r"\b(?:bearer|basic)\s+\S+|"
    r"\b(?:cookie|session(?:_id)?|password|token|api[_-]?key)\s*[:=]|"
    r"\bsk-[a-z0-9_-]+|https?://[^/\s]+:[^/\s]+@)",
    re.IGNORECASE,
)
_IDENTIFIER = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{0,79}")


class UnsafeLogEvent(ValueError):
    """The event cannot be safely represented."""


def _sanitize(value: object, secrets: tuple[str, ...], depth: int = 0) -> object:
    if depth > 20:
        raise UnsafeLogEvent("Event nesting is unsafe")
    if value is None or type(value) in (bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise UnsafeLogEvent("Non-finite event number")
        return value
    if isinstance(value, str):
        if _SENSITIVE_VALUE.search(value) or any(s and s in value for s in secrets):
            return _REDACTED
        return value
    if type(value) is dict:
        result: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise UnsafeLogEvent("Event keys must be strings")
            safe_key = _sanitize(key, secrets, depth + 1)
            if safe_key != key:
                raise UnsafeLogEvent("Unsafe event key")
            result[key] = (
                _REDACTED
                if _SENSITIVE_KEY.search(key)
                else _sanitize(item, secrets, depth + 1)
            )
        return result
    if isinstance(value, (list, tuple)):
        return [_sanitize(item, secrets, depth + 1) for item in value]
    raise UnsafeLogEvent("Unsupported event value")


@dataclass(frozen=True, repr=False)
class SafeEvent:
    name: str
    fields: Mapping[str, object]
    trace_id: str | None = None

    def __repr__(self) -> str:
        # Registered secrets may only become known at emission time.
        return "SafeEvent(<redacted>)"


def safe_event(
    name: str, fields: Mapping[str, object], *, trace_id: str | None = None
) -> SafeEvent:
    if not _IDENTIFIER.fullmatch(name) or (
        trace_id is not None and not _IDENTIFIER.fullmatch(trace_id)
    ):
        raise UnsafeLogEvent("Invalid event identifier")
    # Validate now; format again with registered secrets at the emission boundary.
    _sanitize(dict(fields), ())
    return SafeEvent(name, dict(fields), trace_id)


class SafeJsonFormatter(logging.Formatter):
    def __init__(self, *, secrets: tuple[str, ...] = ()) -> None:
        super().__init__()
        self._secrets = secrets

    def format(self, record: logging.LogRecord) -> str:
        try:
            if not isinstance(record.msg, SafeEvent):
                raise UnsafeLogEvent("Unstructured event")
            event = record.msg
            safe_event(event.name, event.fields, trace_id=event.trace_id)
            payload = _sanitize(
                {
                    "event": event.name,
                    "level": logging.getLevelName(record.levelno),
                    "trace_id": event.trace_id,
                    "fields": dict(event.fields),
                },
                self._secrets,
            )
            return json.dumps(
                payload, sort_keys=True, ensure_ascii=False, allow_nan=False
            )
        except (UnsafeLogEvent, TypeError, ValueError, RecursionError):
            return (
                '{"event":"log_event_rejected","fields":{},'
                '"level":"ERROR","trace_id":null}'
            )


class SafeJsonHandler(logging.Handler):
    """Own serialization and delivery errors without raw logging.handleError.

    The caller owns the stream. A failed write may already have delivered a
    partial sanitized line, so do not retry it. Report only a constant event
    to stderr; if stderr also fails, abandon the diagnostic without recursion.
    """

    def __init__(self, stream: TextIO, *, secrets: tuple[str, ...] = ()) -> None:
        super().__init__()
        self._stream = stream
        self.setFormatter(SafeJsonFormatter(secrets=secrets))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            self._stream.write(self.format(record) + "\n")
            self._stream.flush()
        except Exception:
            self.handleError(record)

    def handleError(self, record: logging.LogRecord) -> None:
        # Never call super(): stdlib prints record.msg, traceback and host paths.
        # Do not interpolate the record, exception, stream or configured secrets.
        try:
            sys.stderr.write(
                '{"event":"log_delivery_failed","fields":{},'
                '"level":"ERROR","trace_id":null}\n'
            )
            sys.stderr.flush()
        except Exception:
            pass
