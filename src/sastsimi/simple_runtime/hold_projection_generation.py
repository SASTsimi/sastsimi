"""Shared, read-only HOLD marker generation for dashboard projections."""

from __future__ import annotations

import sqlite3


def hold_marker_count(connection: sqlite3.Connection, analysis_id: str) -> int:
    """Return the durable HOLD generation, including legacy databases."""
    exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='simple_surface_hold_replay_markers'"
    ).fetchone()
    if exists is None:
        return 0
    return int(
        connection.execute(
            "SELECT COUNT(*) FROM simple_surface_hold_replay_markers "
            "WHERE analysis_id=? AND action='KEEP_HOLD'",
            (analysis_id,),
        ).fetchone()[0]
    )


def marker_hold_generation(source_marker: str) -> int | None:
    """Legacy source markers have no generation suffix and remain readable."""
    _, separator, raw = source_marker.rpartition(":hold:")
    return int(raw) if separator and raw.isascii() and raw.isdecimal() else None
