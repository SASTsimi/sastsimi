"""Shared migration identity without a database/migration import cycle."""

HEAD = "0005_chaining_matches"


class MigrationRequired(ValueError):
    exit_code = 3
