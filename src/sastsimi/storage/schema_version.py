"""Shared migration identity without a database/migration import cycle."""

HEAD = "0006_prompt_analysis_scope"


class MigrationRequired(ValueError):
    exit_code = 3
