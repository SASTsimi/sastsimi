"""Small production implementations of the trusted clock and ID ports."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from uuid import uuid4

from sastsimi.contracts.ids import OpaqueId


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic_ms(self) -> int:
        return time.monotonic_ns() // 1_000_000


class UUIDIds:
    def new[T: OpaqueId](self, kind: type[T]) -> T:
        return kind(uuid4().hex)


__all__ = ["SystemClock", "UUIDIds"]
