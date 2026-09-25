"""Bounded, tracked-only source reads requested by an untrusted Agent."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from .code_redaction import redact_code
from .facts import safe_tracked_file

_SPAN = re.compile(r"^(?P<path>[^:]+):(?P<start>\d+)(?:-(?P<end>\d+))?$")
_MAX_TOTAL_BYTES = 256_000


def collect_requested_sources(
    requests: Iterable[str],
    *,
    workspace: Path,
    tracked: Sequence[str] = (),
    already_supplied: Sequence[str] = (),
) -> dict[str, Any]:
    available = set(tracked)
    supplied = set(already_supplied)
    served: list[dict[str, Any]] = []
    refused: list[dict[str, str]] = []
    seen: set[str] = set()
    total = 0
    for request in requests:
        if not isinstance(request, str):
            refused.append({"path": str(request), "reason": "NOT_A_PATH"})
            continue
        match = _SPAN.fullmatch(request)
        path = match.group("path") if match else request
        if (
            not path
            or path.startswith(("/", "\\"))
            or "\\" in path
            or ":" in path
            or "\x00" in path
            or ".." in Path(path).parts
        ):
            refused.append({"path": request, "reason": "PATH_OUTSIDE_REPOSITORY"})
            continue
        if path not in available:
            refused.append({"path": request, "reason": "NOT_TRACKED"})
            continue
        if request in seen or path in supplied:
            continue
        seen.add(request)
        candidate = safe_tracked_file(workspace, path)
        if candidate is None:
            refused.append({"path": request, "reason": "PATH_OUTSIDE_REPOSITORY"})
            continue
        try:
            raw = candidate.read_bytes()
            if len(raw) + total > _MAX_TOTAL_BYTES:
                refused.append({"path": request, "reason": "TOTAL_BUDGET_EXHAUSTED"})
                continue
            text = raw.decode("utf-8")
        except (OSError, UnicodeError):
            refused.append({"path": request, "reason": "UNREADABLE"})
            continue
        if match:
            start = int(match.group("start"))
            end = int(match.group("end") or start)
            lines = text.splitlines()
            if start < 1 or end < start or end > len(lines):
                refused.append({"path": request, "reason": "LINES_OUTSIDE_FILE"})
                continue
            text = "\n".join(
                f"{line}|{lines[line - 1]}" for line in range(start, end + 1)
            )
        served.append(
            {"path": request, "content": redact_code(text, workspace=workspace)}
        )
        total += len(raw)
    return {
        "kind": "simple_requested_sources",
        "served": served,
        "refused": refused,
        "served_bytes": total,
    }
