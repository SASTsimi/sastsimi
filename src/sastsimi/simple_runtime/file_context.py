"""Exact, bounded, prompt-safe source context shared by a file's candidates."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.prompt_redaction import (
    redact_projected_json,
    redact_untrusted_text_preserving_lines,
)
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .ast_facts import read_ast_file_facts
from .candidates import StaticCandidate
from .facts import safe_tracked_file

MAX_CONTEXT_SOURCE_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class PreparedFileContext:
    path: str
    source_sha256: str | None
    source_lines: tuple[str, ...]
    source_unavailable_reason: str | None
    ast_file_ref: StoredDataRef | None
    ast_facts: tuple[dict[str, Any], ...]
    ast_unavailable_reason: str | None
    redaction_categories: tuple[str, ...]


def prepare_file_context(
    artifacts: SimpleArtifactRepository,
    ast_summary: Mapping[str, object],
    workspace: Path,
    path: str,
    *,
    manifest_index: Mapping[str, Mapping[str, object]] | None = None,
) -> PreparedFileContext:
    """Read a tracked file once; preserve explicit reasons for unavailable context."""

    source_path = safe_tracked_file(workspace, path)
    if source_path is None:
        raise ValueError("CANDIDATE_CONTEXT_SOURCE_UNSAFE_OR_MISSING")
    before = source_path.lstat()
    if not stat.S_ISREG(before.st_mode) or source_path.is_symlink():
        raise ValueError("CANDIDATE_CONTEXT_SOURCE_UNSAFE_OR_MISSING")
    source_sha256: str | None = None
    source_lines: tuple[str, ...] = ()
    source_reason: str | None = None
    categories: tuple[str, ...] = ()
    if before.st_size > MAX_CONTEXT_SOURCE_BYTES:
        source_reason = "SOURCE_TOO_LARGE"
    else:
        descriptor = os.open(source_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            current = os.fstat(stream.fileno())
            if not stat.S_ISREG(current.st_mode) or (
                current.st_dev,
                current.st_ino,
            ) != (before.st_dev, before.st_ino):
                raise ValueError("CANDIDATE_CONTEXT_SOURCE_CHANGED")
            raw = stream.read(MAX_CONTEXT_SOURCE_BYTES + 1)
        if len(raw) > MAX_CONTEXT_SOURCE_BYTES:
            source_reason = "SOURCE_TOO_LARGE"
        else:
            source_sha256 = hashlib.sha256(raw).hexdigest()
            try:
                redacted = redact_untrusted_text_preserving_lines(raw)
                source_lines = tuple(redacted.data.decode("utf-8").splitlines())
                categories = redacted.categories
            except (UnicodeError, ValueError) as error:
                raise ValueError("CANDIDATE_CONTEXT_REDACTION_FAILED") from error
    ast_ref, ast_facts, ast_reason = read_ast_file_facts(
        artifacts, ast_summary, path, manifest_index=manifest_index
    )
    return PreparedFileContext(
        path=path,
        source_sha256=source_sha256,
        source_lines=source_lines,
        source_unavailable_reason=source_reason,
        ast_file_ref=ast_ref,
        ast_facts=ast_facts,
        ast_unavailable_reason=ast_reason,
        redaction_categories=categories,
    )


def render_file_context(
    prepared: PreparedFileContext, candidates: Sequence[StaticCandidate]
) -> dict[str, object]:
    """Render full nearby lines and facts, with exact omitted counts."""

    if not candidates or any(item.path != prepared.path for item in candidates):
        raise ValueError("CANDIDATE_CONTEXT_FILE_MISMATCH")
    wanted_lines: set[int] = set()
    outside_source: list[dict[str, object]] = []
    for candidate in candidates:
        if candidate.line < 1:
            outside_source.append(
                {
                    "candidate_id": candidate.candidate_id,
                    "reason": "LOCATION_UNAVAILABLE",
                }
            )
            continue
        first = max(1, candidate.line - 1)
        last = max(candidate.line, candidate.end_line) + 1
        if prepared.source_unavailable_reason is None:
            wanted_lines.update(range(first, min(last, len(prepared.source_lines)) + 1))
            if last > len(prepared.source_lines):
                outside_source.append(
                    {
                        "candidate_id": candidate.candidate_id,
                        "reason": "LOCATION_BEYOND_SOURCE",
                        "requested_start": first,
                        "requested_end": last,
                    }
                )
    selected_lines = [
        {"line": number, "text": prepared.source_lines[number - 1]}
        for number in sorted(wanted_lines)
        if number <= len(prepared.source_lines)
    ]
    selected_fact_indexes: set[int] = set()
    for candidate in candidates:
        if not prepared.ast_facts:
            break
        nearest = min(
            range(len(prepared.ast_facts)),
            key=lambda index: (
                abs(int(prepared.ast_facts[index]["line"]) - candidate.line),
                index,
            ),
        )
        selected_fact_indexes.add(nearest)
    payload: dict[str, object] = {
        "kind": "simple_candidate_file_context_v1",
        "path": prepared.path,
        "source_sha256": prepared.source_sha256,
        "source_status": (
            "AVAILABLE" if prepared.source_unavailable_reason is None else "UNAVAILABLE"
        ),
        "source_unavailable_reason": prepared.source_unavailable_reason,
        "source_line_count": (
            len(prepared.source_lines)
            if prepared.source_unavailable_reason is None
            else None
        ),
        "source_lines": selected_lines,
        "omitted_source_line_count": (
            len(prepared.source_lines) - len(selected_lines)
            if prepared.source_unavailable_reason is None
            else None
        ),
        "requested_lines_outside_source": outside_source,
        "ast_file_ref": (
            prepared.ast_file_ref.model_dump(mode="json")
            if prepared.ast_file_ref is not None
            else None
        ),
        "ast_unavailable_reason": prepared.ast_unavailable_reason,
        "ast_total_count": (
            len(prepared.ast_facts) if prepared.ast_unavailable_reason is None else None
        ),
        "ast_facts": [
            prepared.ast_facts[index] for index in sorted(selected_fact_indexes)
        ],
        "ast_omitted_count": (
            len(prepared.ast_facts) - len(selected_fact_indexes)
            if prepared.ast_unavailable_reason is None
            else None
        ),
        "redaction_categories": list(prepared.redaction_categories),
    }
    safe = redact_projected_json(canonical_bytes(payload)).data
    projected = json.loads(safe)
    if not isinstance(projected, dict):
        raise ValueError("CANDIDATE_CONTEXT_REDACTION_FAILED")
    return projected


def build_file_context(
    artifacts: SimpleArtifactRepository,
    ast_summary: Mapping[str, object],
    workspace: Path,
    path: str,
    candidates: Sequence[StaticCandidate],
    *,
    prepared: PreparedFileContext | None = None,
    manifest_index: Mapping[str, Mapping[str, object]] | None = None,
) -> StoredDataRef:
    """Persist one deterministic shared context artifact for a candidate batch."""

    current = prepared or prepare_file_context(
        artifacts, ast_summary, workspace, path, manifest_index=manifest_index
    )
    return artifacts.put_json(render_file_context(current, candidates))
