"""Append-only SQLite persistence for safe Agent activity summaries."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.observability.agent_activity import AgentActivityEvent


class AgentActivityStore:
    def __init__(self, database_path: str | Path) -> None:
        self._database_path = Path(database_path)
        self._database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            self.initialize_connection(connection)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    @staticmethod
    def initialize_connection(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_activity_events (
                event_id TEXT PRIMARY KEY,
                analysis_id TEXT NOT NULL,
                hypothesis_key TEXT NOT NULL,
                attempt_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                event_json TEXT NOT NULL,
                started_at TEXT NOT NULL,
                UNIQUE (analysis_id, hypothesis_key, attempt_id, sequence)
            )
            """
        )

    @staticmethod
    def append_connection(
        connection: sqlite3.Connection,
        event: AgentActivityEvent,
    ) -> None:
        encoded = canonical_bytes(event).decode("utf-8")
        current = connection.execute(
            "SELECT event_json FROM agent_activity_events WHERE event_id = ?",
            (event.event_id,),
        ).fetchone()
        if current is not None:
            if str(current[0]) != encoded:
                raise ValueError("AGENT_ACTIVITY_EVENT_CONFLICT")
            return
        try:
            connection.execute(
                """
                INSERT INTO agent_activity_events (
                    event_id, analysis_id, hypothesis_key, attempt_id,
                    sequence, event_json, started_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.analysis_id,
                    event.hypothesis_id or "",
                    event.attempt_id,
                    event.sequence,
                    encoded,
                    event.started_at.isoformat(),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ValueError("AGENT_ACTIVITY_EVENT_CONFLICT") from error

    def append(self, event: AgentActivityEvent) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self.append_connection(connection, event)
            connection.commit()

    def list_analysis(
        self,
        analysis_id: str,
        *,
        hypothesis_id: str | None = None,
    ) -> tuple[AgentActivityEvent, ...]:
        sql = "SELECT event_json FROM agent_activity_events WHERE analysis_id = ?"
        values: tuple[str, ...]
        if hypothesis_id is None:
            values = (analysis_id,)
        else:
            sql += " AND hypothesis_key = ?"
            values = (analysis_id, hypothesis_id)
        sql += " ORDER BY started_at, rowid"
        with self._connect() as connection:
            rows = connection.execute(sql, values).fetchall()
        return tuple(AgentActivityEvent.model_validate_json(row[0]) for row in rows)


__all__ = ["AgentActivityStore"]
