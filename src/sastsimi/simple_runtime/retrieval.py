"""Bounded retrieval of the repository files an agent asked to read.

The Pro and Con agents are required to name the files they still need, because
a static finding alone rarely settles whether a flow is guarded.  The names are
model output, so every one is checked against the workspace root before a byte
is read, and the result records what was refused as plainly as what was served.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Sequence
from pathlib import Path, PurePosixPath
from typing import Any

_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:(?:/|$)")

# One agent naming a whole package must not crowd out the static evidence, so
# the retrieval is bounded three ways: how many files, how large each one is,
# and how much text the batch may add to the next prompt.
MAX_REQUESTED_FILES = 12
MAX_FILE_BYTES = 64_000
MAX_TOTAL_BYTES = 256_000


def _refusal(path: str, reason: str) -> dict[str, str]:
    return {"path": path, "reason": reason}


def _normalized(request: str) -> str | None:
    """Return the repository-relative POSIX path, or ``None`` when unusable."""

    candidate = unicodedata.normalize("NFC", request).strip()
    if not candidate or "\x00" in candidate:
        return None
    candidate = candidate.replace("\\", "/")
    # A drive letter or a UNC share names a host location, not a file in this
    # repository, so it is refused by name rather than left to fail as missing.
    if _DRIVE_PREFIX.match(candidate) or candidate.startswith("//"):
        return None
    pure = PurePosixPath(candidate)
    if pure.is_absolute() or any(part == ".." for part in pure.parts):
        return None
    parts = [part for part in pure.parts if part not in ("", ".")]
    return "/".join(parts) or None


def collect_requested_sources(
    requests: Iterable[str],
    *,
    workspace: Path,
    already_supplied: Sequence[str] = (),
) -> dict[str, Any]:
    """Read the requested files that lie inside the workspace, within bounds.

    Returns a record carrying the served files and every refusal, so the next
    agent can tell "this file says nothing" from "this file was never read".
    """

    root = workspace.resolve()
    supplied = {value for value in already_supplied}
    served: list[dict[str, Any]] = []
    refused: list[dict[str, str]] = []
    seen: set[str] = set()
    total = 0

    for request in requests:
        if not isinstance(request, str):
            refused.append(_refusal(str(request), "NOT_A_PATH"))
            continue
        relative = _normalized(request)
        if relative is None:
            refused.append(_refusal(request, "PATH_OUTSIDE_REPOSITORY"))
            continue
        # Refusals name the path as the agent wrote it, so it can tell which of
        # its own requests was turned down.
        as_written = request.strip()
        if relative in seen or relative in supplied:
            continue
        seen.add(relative)
        if len(served) >= MAX_REQUESTED_FILES:
            refused.append(_refusal(as_written, "FILE_BUDGET_EXHAUSTED"))
            continue
        try:
            # strict=True resolves symlinks, so a link pointing out of the
            # workspace is caught by the containment check below.
            resolved = (root / relative).resolve(strict=True)
        except (OSError, RuntimeError, ValueError):
            refused.append(_refusal(as_written, "NOT_FOUND"))
            continue
        if resolved != root and root not in resolved.parents:
            refused.append(_refusal(as_written, "PATH_OUTSIDE_REPOSITORY"))
            continue
        if not resolved.is_file():
            refused.append(_refusal(as_written, "NOT_A_FILE"))
            continue
        try:
            raw = resolved.read_bytes()
        except OSError:
            refused.append(_refusal(as_written, "UNREADABLE"))
            continue
        if len(raw) > MAX_FILE_BYTES:
            refused.append(_refusal(as_written, "FILE_TOO_LARGE"))
            continue
        if total + len(raw) > MAX_TOTAL_BYTES:
            refused.append(_refusal(as_written, "TOTAL_BUDGET_EXHAUSTED"))
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            refused.append(_refusal(as_written, "NOT_UTF8_TEXT"))
            continue
        total += len(raw)
        served.append(
            {
                "path": relative,
                "line_count": text.count("\n") + 1,
                "byte_count": len(raw),
                "content": text,
            }
        )

    return {
        "kind": "simple_requested_sources",
        "served": served,
        "refused": refused,
        "served_bytes": total,
        "limits": {
            "max_files": MAX_REQUESTED_FILES,
            "max_file_bytes": MAX_FILE_BYTES,
            "max_total_bytes": MAX_TOTAL_BYTES,
        },
    }


__all__ = [
    "MAX_FILE_BYTES",
    "MAX_REQUESTED_FILES",
    "MAX_TOTAL_BYTES",
    "collect_requested_sources",
]
