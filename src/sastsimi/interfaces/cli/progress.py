"""Terminal progress rendering without synthetic time-based progress."""

from __future__ import annotations

from typing import TextIO

from sastsimi.progress.models import ProgressSnapshot


class ProgressRenderer:
    def __init__(self, *, stream: TextIO, is_tty: bool, width: int = 24) -> None:
        self._stream = stream
        self._is_tty = is_tty
        self._width = width
        self._last_stage: str | None = None

    def render(self, snapshot: ProgressSnapshot) -> None:
        stage = snapshot.current_stage or "준비 중"
        if not self._is_tty:
            if stage != self._last_stage:
                self._stream.write(
                    f"현재 단계: {stage} "
                    f"({snapshot.completed_units}/{snapshot.known_units})\n"
                )
                self._last_stage = stage
            return
        filled = round(self._width * snapshot.percent / 100)
        bar = "█" * filled + "-" * (self._width - filled)
        end = (
            "\n"
            if snapshot.status in {"COMPLETE", "BLOCKED", "FAILED"}
            else ""
        )
        self._stream.write(
            f"\r[{bar}] {snapshot.percent:3d}% "
            f"{snapshot.completed_units}/{snapshot.known_units} {stage}{end}"
        )
        self._stream.flush()
        self._last_stage = stage


__all__ = ["ProgressRenderer"]
