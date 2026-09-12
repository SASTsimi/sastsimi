"""Shared migration identity without a database/migration import cycle."""

HEAD = "0006_run_control"


class MigrationRequired(ValueError):
    exit_code = 3
