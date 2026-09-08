"""Shared migration identity without a database/migration import cycle."""

HEAD = "0002_authorization"


class MigrationRequired(ValueError):
    exit_code = 3
