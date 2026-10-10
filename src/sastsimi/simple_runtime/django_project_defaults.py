"""Pure syntax checks for default-off Django project settings."""

from __future__ import annotations

import ast


def _django_project_default_false(value: ast.expr, flag: str) -> bool:
    if isinstance(value, ast.Constant) and value.value is False:
        return True
    if (
        not isinstance(value, ast.Compare)
        or len(value.ops) != 1
        or not isinstance(value.ops[0], ast.Eq)
        or len(value.comparators) != 1
        or not isinstance(value.comparators[0], ast.Constant)
        or value.comparators[0].value != "true"
        or not isinstance(value.left, ast.Call)
        or value.left.args
        or value.left.keywords
        or not isinstance(value.left.func, ast.Attribute)
        or value.left.func.attr != "lower"
        or not isinstance(value.left.func.value, ast.Call)
    ):
        return False
    getenv = value.left.func.value
    return (
        isinstance(getenv.func, ast.Attribute)
        and isinstance(getenv.func.value, ast.Name)
        and getenv.func.value.id == "os"
        and getenv.func.attr == "getenv"
        and not getenv.keywords
        and len(getenv.args) == 2
        and isinstance(getenv.args[0], ast.Constant)
        and isinstance(getenv.args[1], ast.Constant)
        and getenv.args[0].value == flag
        and getenv.args[1].value == "false"
    )
