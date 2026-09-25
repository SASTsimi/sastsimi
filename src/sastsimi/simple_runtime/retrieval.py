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

from .code_redaction import default_host_paths, redact_code

_DRIVE_PREFIX = re.compile(r"^[A-Za-z]:(?:/|$)")

# One agent naming a whole package must not crowd out the static evidence, so
# the retrieval is bounded by how many files it may name and how much text the
# batch may add to the next prompt.
#
# There is deliberately no per-file ceiling.  One was measured refusing the
# single file a hypothesis was about - open-webui's ``routers/retrieval.py`` is
# 124 KB - while four files nobody had asked a question about were served in
# the same batch.  A file is not less worth reading for being long, and often
# it is longer because it does more; what the prompt can hold is the total, and
# that is the only size this needs to decide.
MAX_REQUESTED_FILES = 12
MAX_TOTAL_BYTES = 384_000


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
        if total + len(raw) > MAX_TOTAL_BYTES:
            refused.append(_refusal(as_written, "TOTAL_BUDGET_EXHAUSTED"))
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            refused.append(_refusal(as_written, "NOT_UTF8_TEXT"))
            continue
        # Repository text reaches a model prompt from here, so a credential a
        # project committed must be removed first, exactly as the static bundle
        # is.  The categories say what was removed without repeating it.
        content, removed = redact_code(text, host_paths=default_host_paths(root))
        total += len(raw)
        served.append(
            {
                "path": relative,
                "line_count": text.count("\n") + 1,
                "byte_count": len(raw),
                "content": content,
                **({"redacted": list(removed)} if removed else {}),
            }
        )

    return {
        "kind": "simple_requested_sources",
        "served": served,
        "refused": refused,
        "served_bytes": total,
        "limits": {
            "max_files": MAX_REQUESTED_FILES,
            "max_total_bytes": MAX_TOTAL_BYTES,
        },
    }


__all__ = [
    "MAX_AST_FILES",
    "MAX_REQUESTED_FILES",
    "MAX_TOTAL_BYTES",
    "collect_requested_ast",
    "collect_requested_sources",
]


MAX_AST_FILES = 40


def collect_requested_ast(
    requests: Iterable[str],
    *,
    facts: Sequence[Any],
) -> dict[str, Any]:
    """Return the parsed facts for the files an agent asked about.

    The facts were being summarised into a map before an agent ever saw them,
    which meant deciding in advance which call names mattered - the same
    judgement a static rule makes, and the reason a rule misses what it was not
    written for.  Nothing is decided here: the file is named, its facts are
    served whole, and a name that has none says so.
    """

    wanted: list[str] = []
    refused: list[dict[str, str]] = []
    for request in requests:
        if not isinstance(request, str):
            refused.append(_refusal(str(request), "NOT_A_PATH"))
            continue
        relative = _normalized(request)
        if relative is None:
            refused.append(_refusal(request, "PATH_OUTSIDE_REPOSITORY"))
            continue
        if relative in wanted:
            continue
        if len(wanted) >= MAX_AST_FILES:
            refused.append(_refusal(request, "FILE_BUDGET_EXHAUSTED"))
            continue
        wanted.append(relative)

    grouped: dict[str, list[Any]] = {path: [] for path in wanted}
    for fact in facts:
        if not isinstance(fact, dict):
            continue
        path = fact.get("path")
        if isinstance(path, str) and path in grouped:
            grouped[path].append(fact)

    served = [
        {"path": path, "fact_count": len(entries), "facts": entries}
        for path, entries in grouped.items()
        if entries
    ]
    refused.extend(
        _refusal(path, "NO_FACTS_FOR_PATH")
        for path, entries in grouped.items()
        if not entries
    )
    return {
        "kind": "simple_requested_ast",
        "served": served,
        "refused": refused,
        "limits": {"max_files": MAX_AST_FILES},
    }
