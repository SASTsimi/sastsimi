"""Shared classification for the Python-only static coverage boundary."""

from __future__ import annotations

from pathlib import Path

NON_PYTHON_PRODUCT_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".mts",
        ".cts",
        ".vue",
        ".svelte",
        ".astro",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".kts",
        ".scala",
        ".sc",
        ".cs",
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".cxx",
        ".hh",
        ".hpp",
        ".hxx",
        ".swift",
        ".dart",
        ".rb",
        ".php",
        ".ex",
        ".exs",
        ".erl",
        ".hrl",
        ".hs",
        ".ml",
        ".mli",
        ".lua",
        ".pl",
        ".pm",
        ".r",
        ".jl",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".sql",
        ".graphql",
        ".proto",
    }
)


def out_of_scope_limits_python_coverage(path: str, reason: str) -> bool:
    """Only a known non-Python source with a proven exclusion is harmless here."""

    return not (
        Path(path).suffix.casefold() in NON_PYTHON_PRODUCT_EXTENSIONS
        and reason in {"non_python_product_source", "declared_non_python_entry"}
    )
