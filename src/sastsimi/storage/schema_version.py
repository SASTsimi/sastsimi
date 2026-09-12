"""Shared migration identity without a database/migration import cycle."""

HEAD = "0004_prompt_runtime"


class MigrationRequired(ValueError):
    exit_code = 3
