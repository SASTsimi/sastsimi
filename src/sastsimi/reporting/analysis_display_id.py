"""Stable human-facing analysis identifiers backed by the runtime database."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

_EXACT_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_DISPLAY_ID = re.compile(r"A-([0-9]{3,})\Z")


class AnalysisDisplayIdStore:
    """Allocate one stable ``A-NNN`` name for each exact analysis identifier."""

    def __init__(self, database_path: str | Path) -> None:
        self._database_path = Path(database_path)
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database_path, timeout=5.0)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_display_ids (
                    analysis_id TEXT PRIMARY KEY,
                    display_number INTEGER NOT NULL UNIQUE
                        CHECK (display_number > 0)
                )
                """
            )

    def get_or_allocate(self, analysis_id: str) -> str:
        self._validate_exact(analysis_id)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT display_number FROM analysis_display_ids WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()
            if row is None:
                number = int(
                    connection.execute(
                        "SELECT COALESCE(MAX(display_number), 0) + 1 "
                        "FROM analysis_display_ids"
                    ).fetchone()[0]
                )
                connection.execute(
                    "INSERT INTO analysis_display_ids (analysis_id, display_number) "
                    "VALUES (?, ?)",
                    (analysis_id, number),
                )
            else:
                number = int(row[0])
            connection.commit()
            return self._format(number)
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def resolve(self, value: str) -> str:
        match = _DISPLAY_ID.fullmatch(value)
        if match is None:
            self._validate_exact(value)
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT 1 FROM analysis_display_ids WHERE analysis_id = ?",
                    (value,),
                ).fetchone()
            if row is None:
                raise LookupError("ANALYSIS_DISPLAY_ID_NOT_FOUND")
            return value
        with self._connect() as connection:
            row = connection.execute(
                "SELECT analysis_id FROM analysis_display_ids WHERE display_number = ?",
                (int(match.group(1)),),
            ).fetchone()
        if row is None:
            raise LookupError("ANALYSIS_DISPLAY_ID_NOT_FOUND")
        return str(row[0])

    @staticmethod
    def _format(number: int) -> str:
        return f"A-{number:03d}"

    @staticmethod
    def _validate_exact(analysis_id: str) -> None:
        if _EXACT_ID.fullmatch(analysis_id) is None or analysis_id.startswith("A-"):
            raise ValueError("ANALYSIS_ID_INVALID")


__all__ = ["AnalysisDisplayIdStore"]
