"""Remove this host's known paths from quoted repository source."""

from __future__ import annotations

from pathlib import Path


def redact_code(text: str, *, workspace: Path) -> str:
    paths = {str(workspace.resolve()), str(Path.home())}
    for path in sorted(paths, key=len, reverse=True):
        if len(path) > 1:
            text = text.replace(path, "[REDACTED:HOST_ABSOLUTE_PATH]")
    return text
