"""Small production implementations of the trusted clock and ID ports."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from threading import Lock
from uuid import uuid4

from sastsimi.contracts.ids import OpaqueId

_EPSILON = timedelta(microseconds=1)


class SystemClock:
    """Wall-clock time, clamped to never go backward within one instance.

    This host's guest clock is Hyper-V-synced and has been observed jumping
    backward mid-run (`dmesg`: "Time jumped backwards"). Every new record
    revision stamps `created_at` from this clock and `validate_revision`
    (`contracts/records.py`) requires each revision's `created_at` to be
    strictly after its predecessor's - a real backward jump between two
    `now()` calls on the same instance would otherwise fail that invariant
    and abort the work claiming the revision. Clamping preserves real wall
    time whenever it is actually advancing and only diverges from it for the
    duration of a correction, self-healing once real time catches back up.
    """

    def __init__(self) -> None:
        self._last = datetime.now(UTC)
        self._lock = Lock()

    def now(self) -> datetime:
        with self._lock:
            observed = datetime.now(UTC)
            self._last = max(observed, self._last + _EPSILON)
            return self._last

    def monotonic_ms(self) -> int:
        return time.monotonic_ns() // 1_000_000


class UUIDIds:
    def new[T: OpaqueId](self, kind: type[T]) -> T:
        return kind(uuid4().hex)


__all__ = ["SystemClock", "UUIDIds"]
