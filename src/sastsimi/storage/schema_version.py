"""Shared migration identity without a database/migration import cycle."""

HEAD = "0003_runtime_guards"


class MigrationRequired(ValueError):
    exit_code = 3
