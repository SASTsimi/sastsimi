"""Stable human-facing Finding identifiers backed by the runtime database."""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path

from sastsimi.contracts.refs import StoredDataRef

_ANALYSIS_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_DISPLAY_ID = re.compile(r"F-([0-9]{3,})\Z")


class FindingDisplayIdStore:
    """Allocate one stable ``F-NNN`` name per exact Finding and analysis."""

    def __init__(self, database_path: str | Path) -> None:
        self._database_path = Path(database_path)
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database_path, timeout=5.0)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS finding_display_ids (
                    analysis_id TEXT NOT NULL,
                    finding_hash TEXT NOT NULL,
                    finding_ref_json TEXT NOT NULL,
                    display_number INTEGER NOT NULL CHECK (display_number > 0),
                    PRIMARY KEY (analysis_id, finding_hash),
                    UNIQUE (analysis_id, display_number)
                )
                """
            )
            connection.commit()
        finally:
            connection.close()

    def get_or_allocate(
        self,
        analysis_id: str,
        finding_ref: StoredDataRef,
    ) -> str:
        self._validate_analysis_id(analysis_id)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT display_number, finding_ref_json
                FROM finding_display_ids
                WHERE analysis_id = ? AND finding_hash = ?
                """,
                (analysis_id, finding_ref.content_hash),
            ).fetchone()
            if row is not None:
                if json.loads(row[1]) != finding_ref.model_dump(mode="json"):
                    raise ValueError("FINDING_DISPLAY_REFERENCE_CONFLICT")
                connection.commit()
                return self._format(int(row[0]))
            number = int(
                connection.execute(
                    """
                    SELECT COALESCE(MAX(display_number), 0) + 1
                    FROM finding_display_ids
                    WHERE analysis_id = ?
                    """,
                    (analysis_id,),
                ).fetchone()[0]
            )
            connection.execute(
                """
                INSERT INTO finding_display_ids (
                    analysis_id,
                    finding_hash,
                    finding_ref_json,
                    display_number
                ) VALUES (?, ?, ?, ?)
                """,
                (
                    analysis_id,
                    finding_ref.content_hash,
                    finding_ref.model_dump_json(),
                    number,
                ),
            )
            connection.commit()
            return self._format(number)
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def resolve(self, analysis_id: str, display_id: str) -> StoredDataRef:
        self._validate_analysis_id(analysis_id)
        match = _DISPLAY_ID.fullmatch(display_id)
        if match is None:
            raise ValueError("FINDING_DISPLAY_ID_INVALID")
        connection = self._connect()
        try:
            row = connection.execute(
                """
                SELECT finding_ref_json
                FROM finding_display_ids
                WHERE analysis_id = ? AND display_number = ?
                """,
                (analysis_id, int(match.group(1))),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise LookupError("FINDING_DISPLAY_ID_NOT_FOUND")
        return StoredDataRef.model_validate_json(row[0])

    @classmethod
    def resolve_existing(
        cls,
        database_path: str | Path,
        analysis_id: str,
        display_id: str,
    ) -> StoredDataRef:
        """Resolve through a read-only connection without creating schema."""

        cls._validate_analysis_id(analysis_id)
        match = _DISPLAY_ID.fullmatch(display_id)
        if match is None:
            raise ValueError("FINDING_DISPLAY_ID_INVALID")
        path = Path(database_path).resolve()
        connection = sqlite3.connect(
            f"file:{path.as_posix()}?mode=ro",
            uri=True,
        )
        try:
            row = connection.execute(
                """
                SELECT finding_ref_json
                FROM finding_display_ids
                WHERE analysis_id = ? AND display_number = ?
                """,
                (analysis_id, int(match.group(1))),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise LookupError("FINDING_DISPLAY_ID_NOT_FOUND")
        return StoredDataRef.model_validate_json(row[0])

    @staticmethod
    def _format(number: int) -> str:
        return f"F-{number:03d}"

    @staticmethod
    def _validate_analysis_id(analysis_id: str) -> None:
        if _ANALYSIS_ID.fullmatch(analysis_id) is None:
            raise ValueError("FINDING_ANALYSIS_ID_INVALID")


__all__ = ["FindingDisplayIdStore"]
