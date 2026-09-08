from datetime import datetime
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    """now is aware UTC; elapsed time derives only from monotonic_ms."""

    def now(self) -> datetime: ...
    def monotonic_ms(self) -> int: ...
