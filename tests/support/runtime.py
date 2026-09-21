from __future__ import annotations

from datetime import UTC, datetime

from sastsimi.contracts.ids import OpaqueId


class DeterministicClock:
    def __init__(self) -> None:
        self.wall_time = datetime(2026, 9, 8, tzinfo=UTC)
        self.tick = 0

    def now(self) -> datetime:
        return self.wall_time

    def monotonic_ms(self) -> int:
        return self.tick


class SequenceIds:
    def __init__(self) -> None:
        self.index = 0

    def new[T: OpaqueId](self, kind: type[T]) -> T:
        self.index += 1
        return kind(f"test-{kind.__name__.lower()}-{self.index}")
