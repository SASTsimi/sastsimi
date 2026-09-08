"""Explicit, short SQLite transactions. No session survives a service call."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import Connection, create_engine, event, inspect, text
from sqlalchemy.pool import NullPool

from .schema_version import HEAD, MigrationRequired


class Database:
    def __init__(self, path: Path) -> None:
        self.recovery_failed = False
        if str(path).startswith(("\\\\", "//")):
            raise ValueError("SQLite requires a local filesystem")
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(
            "sqlite:///" + self.path.as_posix(), poolclass=NullPool
        )

        @event.listens_for(self.engine, "connect")
        def configure(connection: sqlite3.Connection, record: object) -> None:
            connection.isolation_level = None
            for pragma in (
                "foreign_keys=ON",
                "journal_mode=WAL",
                "synchronous=FULL",
                "busy_timeout=5000",
            ):
                connection.execute("PRAGMA " + pragma)

    @contextmanager
    def write(self) -> Iterator[Connection]:
        with self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                yield connection
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    def check_ready(self) -> None:
        with self.engine.connect() as connection:
            if "alembic_version" not in inspect(connection).get_table_names():
                raise MigrationRequired("Pending migration; run sastsimi db upgrade")
            revisions = list(
                connection.execute(
                    text("SELECT version_num FROM alembic_version")
                ).scalars()
            )
            if revisions != [HEAD]:
                raise MigrationRequired("Pending or unknown migration revision")
            if connection.exec_driver_sql("PRAGMA integrity_check").scalar() != "ok":
                raise ValueError("RECOVERY_FAILED: database integrity")
            if connection.exec_driver_sql("PRAGMA foreign_key_check").first():
                raise ValueError("RECOVERY_FAILED: foreign key integrity")
