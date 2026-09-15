"""Shared migration identity without a database/migration import cycle."""

HEAD = "0008_cancellation_observations"


class MigrationRequired(ValueError):
    exit_code = 3
