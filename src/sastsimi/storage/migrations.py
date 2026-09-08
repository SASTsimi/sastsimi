"""Explicit operator migrations; startup only checks the revision."""

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect, text

from .database import Database
from .schema_version import HEAD
from .schema_version import MigrationRequired as MigrationRequired


def config(database: Database) -> Config:
    result = Config()
    result.set_main_option(
        "script_location", str(Path(__file__).resolve().parents[3] / "migrations")
    )
    return result


def check_revision(database: Database) -> None:
    with database.engine.connect() as connection:
        if "alembic_version" not in inspect(connection).get_table_names():
            raise MigrationRequired("Pending migration; run sastsimi db upgrade")
        revisions = list(
            connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalars()
        )
        if revisions != [HEAD]:
            raise MigrationRequired("Pending or unknown migration revision")


def upgrade(database: Database) -> None:
    with database.write() as connection:
        settings = config(database)
        settings.attributes["connection"] = connection
        command.upgrade(settings, "head")


def downgrade(database: Database) -> None:
    with database.write() as connection:
        for table in inspect(connection).get_table_names():
            if table != "alembic_version":
                quoted = connection.dialect.identifier_preparer.quote(table)
                if connection.execute(text(f"SELECT count(*) FROM {quoted}")).scalar():
                    raise ValueError(
                        "Lossy downgrade requires a verified backup "
                        "and explicit approval"
                    )
        settings = config(database)
        settings.attributes["connection"] = connection
        command.downgrade(settings, "base")
