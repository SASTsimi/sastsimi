"""Bounded, tracked-only source reads requested by an untrusted Agent."""

from __future__ import annotations

import ast
import hashlib
import re
import subprocess
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.prompt_redaction import (
    redact_projected_json,
    redact_untrusted_text,
)

from .code_redaction import redact_code
from .facts import safe_tracked_file

_SPAN = re.compile(r"^(?P<path>[^:]+):(?P<start>\d+)(?:-(?P<end>\d+))?$")
_MAX_TOTAL_BYTES = 256_000
_MAX_SPAN_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_PARTIAL_EXCERPT_BYTES = 16 * 1024


def _line_ranges(numbers: Iterable[int]) -> list[list[int]]:
    ranges: list[list[int]] = []
    for number in numbers:
        if ranges and number == ranges[-1][1] + 1:
            ranges[-1][1] = number
        else:
            ranges.append([number, number])
    return ranges


def _partial_python_source(raw: bytes, *, workspace: Path) -> dict[str, Any] | None:
    """Project only declarations and model relations, never an unmarked prefix."""

    try:
        source = raw.decode("utf-8")
        tree = ast.parse(source)
    except (UnicodeError, SyntaxError, ValueError):
        return None
    lines = source.splitlines()
    relations: list[int] = []
    classes: list[int] = []
    functions: list[int] = []
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in {"ForeignKey", "OneToOneField", "ManyToManyField"}
        ):
            relations.extend(
                range(
                    max(1, node.lineno - 1),
                    min(len(lines), node.end_lineno or node.lineno, node.lineno + 6)
                    + 1,
                )
            )
        elif isinstance(node, ast.ClassDef):
            classes.append(node.lineno)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions.append(node.lineno)
    if not (relations or classes or functions):
        return None
    selected: list[int] = []
    seen: set[int] = set()
    size = 0
    for number in (*relations, *classes, *functions):
        if number in seen:
            continue
        seen.add(number)
        entry_size = len(f"{number}|{lines[number - 1]}\n".encode())
        if size + entry_size > _MAX_PARTIAL_EXCERPT_BYTES:
            continue
        selected.append(number)
        size += entry_size
    if not selected or len(selected) == len(lines):
        return None
    content = redact_code(
        "\n".join(f"{number}|{lines[number - 1]}" for number in sorted(selected)),
        workspace=workspace,
    )
    while len(content.encode("utf-8")) > _MAX_PARTIAL_EXCERPT_BYTES and selected:
        selected.pop()
        content = redact_code(
            "\n".join(f"{number}|{lines[number - 1]}" for number in sorted(selected)),
            workspace=workspace,
        )
    if not selected:
        return None
    included = set(selected)
    return {
        "content": content,
        "partial": True,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "total_line_count": len(lines),
        "included_line_ranges": _line_ranges(sorted(included)),
        "omitted_line_count": len(lines) - len(included),
        "omitted_line_ranges": _line_ranges(
            number for number in range(1, len(lines) + 1) if number not in included
        ),
    }


def collect_requested_sources(
    requests: Iterable[str],
    *,
    workspace: Path,
    tracked: Sequence[str] = (),
    already_supplied: Sequence[str] = (),
    max_total_bytes: int = _MAX_TOTAL_BYTES,
    pinned_commit: str | None = None,
    git_executable: str = "git",
    max_requests: int | None = None,
    max_artifact_bytes: int | None = None,
) -> dict[str, Any]:
    if max_requests is not None and max_requests < 0:
        raise ValueError("max_requests must be non-negative")
    if max_artifact_bytes is not None and max_artifact_bytes < 1024:
        raise ValueError("max_artifact_bytes must be at least 1024")
    available = set(tracked)
    supplied = set(already_supplied)
    served: list[dict[str, Any]] = []
    served_sizes: list[int] = []
    served_raw: list[bytes] = []
    refused: list[dict[str, str]] = []
    seen: set[str] = set()
    total = 0
    for index, request in enumerate(requests):
        if max_requests is not None and index >= max_requests:
            refused.append({"path": str(request), "reason": "REQUEST_LIMIT_EXCEEDED"})
            continue
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
        project_large_python = (
            max_artifact_bytes is not None
            and not match
            and path.lower().endswith((".py", ".pyi"))
        )
        source_read_limit = (
            _MAX_SPAN_SOURCE_BYTES
            if match or project_large_python
            else max_total_bytes - total
        )
        try:
            if pinned_commit is not None:
                raw, reason = _read_pinned_blob(
                    workspace,
                    path,
                    commit=pinned_commit,
                    git_executable=git_executable,
                    remaining=source_read_limit,
                )
                if reason is not None:
                    refused.append({"path": request, "reason": reason})
                    continue
                if raw is None:
                    raise OSError("pinned Git blob is unavailable")
            else:
                candidate = safe_tracked_file(workspace, path)
                if candidate is None:
                    refused.append(
                        {"path": request, "reason": "PATH_OUTSIDE_REPOSITORY"}
                    )
                    continue
                if candidate.stat().st_size > source_read_limit:
                    refused.append(
                        {"path": request, "reason": "TOTAL_BUDGET_EXHAUSTED"}
                    )
                    continue
                raw = candidate.read_bytes()
            text = raw.decode("utf-8")
        except (OSError, UnicodeError):
            refused.append({"path": request, "reason": "UNREADABLE"})
            continue
        if not match and len(raw) + total > max_total_bytes:
            partial = (
                _partial_python_source(raw, workspace=workspace)
                if project_large_python
                else None
            )
            if partial is None:
                refused.append({"path": request, "reason": "TOTAL_BUDGET_EXHAUSTED"})
                continue
            partial_size = len(partial["content"].encode())
            if partial_size + total > max_total_bytes:
                refused.append({"path": request, "reason": "TOTAL_BUDGET_EXHAUSTED"})
                continue
            served.append({"path": request, **partial})
            served_sizes.append(partial_size)
            served_raw.append(b"")
            total += partial_size
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
        content = redact_code(text, workspace=workspace)
        charged_bytes = len(content.encode()) if match else len(raw)
        if charged_bytes + total > max_total_bytes:
            refused.append({"path": request, "reason": "TOTAL_BUDGET_EXHAUSTED"})
            continue
        served.append({"path": request, "content": content})
        served_sizes.append(charged_bytes)
        served_raw.append(raw if not match else b"")
        total += charged_bytes
    result: dict[str, Any] = {
        "kind": "simple_requested_sources",
        "served": served,
        "refused": refused,
        "served_bytes": total,
    }
    if max_artifact_bytes is not None:
        while _projected_size(result) > max_artifact_bytes and served:
            current_size = _projected_size(result)
            did_project = False
            for index in sorted(
                range(len(served)), key=lambda item: served_sizes[item], reverse=True
            ):
                raw = served_raw[index]
                if not raw or not served[index]["path"].lower().endswith(
                    (".py", ".pyi")
                ):
                    continue
                partial = _partial_python_source(raw, workspace=workspace)
                if partial is None:
                    continue
                partial_item = {"path": served[index]["path"], **partial}
                partial_size = len(partial["content"].encode("utf-8"))
                candidate_total = total - served_sizes[index] + partial_size
                candidate_served = served.copy()
                candidate_served[index] = partial_item
                projected_result = {
                    **result,
                    "served": candidate_served,
                    "served_bytes": candidate_total,
                }
                if (
                    candidate_total <= max_total_bytes
                    and _projected_size(projected_result) < current_size
                ):
                    served[index] = partial_item
                    served_sizes[index] = partial_size
                    served_raw[index] = b""
                    total = candidate_total
                    result["served_bytes"] = total
                    did_project = True
                    break
            if did_project:
                continue
            removed = served.pop()
            total -= served_sizes.pop()
            removed_raw = served_raw.pop()
            partial = (
                _partial_python_source(removed_raw, workspace=workspace)
                if removed["path"].lower().endswith((".py", ".pyi"))
                else None
            )
            if partial is not None:
                partial_item = {"path": removed["path"], **partial}
                partial_size = len(partial["content"].encode("utf-8"))
                projected = {
                    **result,
                    "served": [*served, partial_item],
                    "served_bytes": total + partial_size,
                }
                if (
                    total + partial_size <= max_total_bytes
                    and _projected_size(projected) <= max_artifact_bytes
                ):
                    served.append(partial_item)
                    served_sizes.append(partial_size)
                    served_raw.append(b"")
                    total += partial_size
                    result["served_bytes"] = total
                    continue
            refused.append(
                {"path": removed["path"], "reason": "PROMPT_BUDGET_EXHAUSTED"}
            )
            result["served_bytes"] = total
        if _projected_size(result) > max_artifact_bytes:
            result["omitted_refusals"] = len(refused)
            result["refused"] = [
                {"path": "<multiple>", "reason": "PROMPT_BUDGET_EXHAUSTED"}
            ]
    return result


def _projected_size(value: object) -> int:
    raw = canonical_bytes(value)
    try:
        return len(redact_projected_json(raw).data)
    except ValueError:
        return len(redact_untrusted_text(raw).data)


def _read_pinned_blob(
    workspace: Path,
    path: str,
    *,
    commit: str,
    git_executable: str,
    remaining: int,
) -> tuple[bytes | None, str | None]:
    def git(*args: str) -> subprocess.CompletedProcess[bytes]:
        for attempt in range(2):
            try:
                return subprocess.run(
                    (git_executable, "-C", str(workspace), *args),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=10,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                if attempt == 1:
                    raise
        raise AssertionError("unreachable")

    try:
        tree = git("--literal-pathspecs", "ls-tree", "-z", commit, "--", path)
        if tree.returncode != 0:
            return None, "PINNED_SOURCE_UNAVAILABLE"
        exact_suffix = b"\t" + path.encode("utf-8")
        entry = next(
            (item for item in tree.stdout.split(b"\0") if item.endswith(exact_suffix)),
            None,
        )
        if entry is None:
            return None, "NOT_IN_PINNED_COMMIT"
        mode, kind, object_id = entry.split(b"\t", 1)[0].split()
        if mode not in {b"100644", b"100755"} or kind != b"blob":
            return None, "PATH_OUTSIDE_REPOSITORY"
        oid = object_id.decode("ascii")
        size = git("cat-file", "-s", oid)
        if size.returncode != 0:
            return None, "PINNED_SOURCE_UNAVAILABLE"
        if int(size.stdout.strip()) > remaining:
            return None, "TOTAL_BUDGET_EXHAUSTED"
        content = git("cat-file", "blob", oid)
        if content.returncode != 0:
            return None, "PINNED_SOURCE_UNAVAILABLE"
        return content.stdout, None
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        return None, "PINNED_SOURCE_UNAVAILABLE"
