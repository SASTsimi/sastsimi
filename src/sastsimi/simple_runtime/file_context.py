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
from .call_path_facts import (
    CandidateCallPaths,
    PythonCallPathIndex,
    call_path_step_locations,
)
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


def _selected_source_lines(
    prepared: PreparedFileContext, wanted_lines: set[int]
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    selected = [
        {"line": number, "text": prepared.source_lines[number - 1]}
        for number in sorted(wanted_lines)
        if 1 <= number <= len(prepared.source_lines)
    ]
    outside = [
        {"line": number, "reason": "LOCATION_BEYOND_SOURCE"}
        for number in sorted(wanted_lines)
        if number < 1 or number > len(prepared.source_lines)
    ]
    return selected, outside


def _related_source_payload(
    prepared: PreparedFileContext, locations: set[int]
) -> dict[str, object]:
    wanted = {
        number for location in locations for number in range(location - 1, location + 2)
    }
    selected, outside = _selected_source_lines(prepared, wanted)
    return {
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
        "source_lines": selected,
        "requested_lines_outside_source": outside,
        "redaction_categories": list(prepared.redaction_categories),
    }


def render_file_context(
    prepared: PreparedFileContext,
    candidates: Sequence[StaticCandidate],
    *,
    call_paths: Mapping[str, CandidateCallPaths] | None = None,
    related_prepared: Mapping[str, PreparedFileContext] | None = None,
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
            if max(candidate.line, candidate.end_line) > len(prepared.source_lines):
                outside_source.append(
                    {
                        "candidate_id": candidate.candidate_id,
                        "reason": "LOCATION_BEYOND_SOURCE",
                        "requested_start": first,
                        "requested_end": last,
                    }
                )
    related_locations: dict[str, set[int]] = {}
    call_path_payloads: list[dict[str, object]] = []
    if call_paths is not None:
        for candidate in candidates:
            result = call_paths.get(candidate.candidate_id)
            if result is None:
                raise ValueError("CANDIDATE_CALL_PATH_MISSING")
            call_path_payloads.append(
                {
                    "candidate_id": candidate.candidate_id,
                    "status": result.status,
                    "paths": list(result.paths),
                    "gaps": list(result.gaps),
                }
            )
            for path, line in call_path_step_locations(result.paths):
                related_locations.setdefault(path, set()).add(line)
                if path == prepared.path:
                    wanted_lines.update(range(max(1, line - 1), line + 2))
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
        "kind": (
            "simple_candidate_file_context_v2"
            if call_paths is not None
            else "simple_candidate_file_context_v1"
        ),
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
    if call_paths is not None:
        if related_prepared is None:
            raise ValueError("CANDIDATE_CALL_PATH_RELATED_CONTEXT_MISSING")
        related_payloads: list[dict[str, object]] = []
        for path in sorted(related_locations):
            if path == prepared.path:
                continue
            related = related_prepared.get(path)
            if related is None:
                raise ValueError("CANDIDATE_CALL_PATH_RELATED_CONTEXT_MISSING")
            related_payloads.append(
                _related_source_payload(related, related_locations[path])
            )
        payload["candidate_call_paths"] = call_path_payloads
        payload["related_source_files"] = related_payloads
    safe = redact_projected_json(canonical_bytes(payload)).data
    projected = json.loads(safe)
    if not isinstance(projected, dict):
        raise ValueError("CANDIDATE_CONTEXT_REDACTION_FAILED")
    return projected


def restrict_file_context_to_candidates(
    context: Mapping[str, object], candidate_ids: Sequence[str]
) -> dict[str, object]:
    """Return the prompt-safe v2 slice for only the requested candidate IDs.

    The persisted context stays batch-oriented for checkpoint stability.  A retry
    must nevertheless receive only its own cross-file path proof and source
    snippets; otherwise another candidate's route or unresolved gap can affect
    the LLM's decision.  Primary-file snippets remain shared because batching is
    explicitly file scoped and the existing location validator restricts claims
    to each candidate's visible lines.
    """

    selected_ids = tuple(candidate_ids)
    if not selected_ids or len(selected_ids) != len(set(selected_ids)):
        raise ValueError("CANDIDATE_CONTEXT_REQUEST_IDS_INVALID")
    payload = dict(context)
    if payload.get("kind") != "simple_candidate_file_context_v2":
        return payload
    primary_path = payload.get("path")
    rows = payload.get("candidate_call_paths")
    related = payload.get("related_source_files")
    if (
        not isinstance(primary_path, str)
        or not isinstance(rows, list)
        or not isinstance(related, list)
    ):
        raise ValueError("CANDIDATE_CONTEXT_INVALID")
    by_id: dict[str, dict[str, object]] = {}
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("candidate_id"), str):
            raise ValueError("CANDIDATE_CONTEXT_INVALID")
        candidate_id = row["candidate_id"]
        if candidate_id in by_id:
            raise ValueError("CANDIDATE_CONTEXT_INVALID")
        by_id[candidate_id] = row
    try:
        selected_rows = [by_id[candidate_id] for candidate_id in selected_ids]
    except KeyError as error:
        raise ValueError("CANDIDATE_CONTEXT_REQUEST_IDS_INVALID") from error
    wanted_by_path: dict[str, set[int]] = {}
    for row in selected_rows:
        paths = row.get("paths")
        if not isinstance(paths, list):
            raise ValueError("CANDIDATE_CONTEXT_INVALID")
        for path, line in call_path_step_locations(paths):
            if path == primary_path:
                continue
            wanted_by_path.setdefault(path, set()).update(
                range(max(1, line - 1), line + 2)
            )
    related_by_path: dict[str, dict[str, object]] = {}
    for item in related:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise ValueError("CANDIDATE_CONTEXT_INVALID")
        path = item["path"]
        if path in related_by_path:
            raise ValueError("CANDIDATE_CONTEXT_INVALID")
        related_by_path[path] = item
    selected_related: list[dict[str, object]] = []
    for path in sorted(wanted_by_path):
        source = related_by_path.get(path)
        if source is None:
            raise ValueError("CANDIDATE_CONTEXT_INVALID")
        wanted_lines = wanted_by_path[path]
        selected_source = dict(source)
        source_lines = source.get("source_lines")
        if not isinstance(source_lines, list):
            raise ValueError("CANDIDATE_CONTEXT_INVALID")
        selected_source["source_lines"] = [
            line
            for line in source_lines
            if isinstance(line, dict) and line.get("line") in wanted_lines
        ]
        outside = source.get("requested_lines_outside_source")
        if isinstance(outside, list):
            selected_source["requested_lines_outside_source"] = [
                line
                for line in outside
                if isinstance(line, dict) and line.get("line") in wanted_lines
            ]
        selected_related.append(selected_source)
    payload["candidate_call_paths"] = selected_rows
    payload["related_source_files"] = selected_related
    return payload


def build_file_context(
    artifacts: SimpleArtifactRepository,
    ast_summary: Mapping[str, object],
    workspace: Path,
    path: str,
    candidates: Sequence[StaticCandidate],
    *,
    prepared: PreparedFileContext | None = None,
    manifest_index: Mapping[str, Mapping[str, object]] | None = None,
    call_path_index: PythonCallPathIndex | None = None,
    include_downstream: bool = False,
    include_enclosing: bool = False,
    include_error_response: bool = False,
) -> StoredDataRef:
    """Persist one deterministic shared context artifact for a candidate batch."""

    current = prepared or prepare_file_context(
        artifacts, ast_summary, workspace, path, manifest_index=manifest_index
    )
    if call_path_index is None:
        return artifacts.put_json(render_file_context(current, candidates))
    paths = {
        candidate.candidate_id: call_path_index.for_candidate(
            candidate,
            include_downstream=include_downstream,
            include_enclosing=include_enclosing,
            include_error_response=include_error_response,
        )
        for candidate in candidates
    }
    related_locations: dict[str, set[int]] = {}
    for result in paths.values():
        for related_path, line in call_path_step_locations(result.paths):
            if related_path != current.path:
                related_locations.setdefault(related_path, set()).add(line)
    related_prepared: dict[str, PreparedFileContext] = {}
    unavailable: dict[str, str] = {}
    for related_path, lines in sorted(related_locations.items()):
        try:
            related = prepare_file_context(
                artifacts,
                ast_summary,
                workspace,
                related_path,
                manifest_index=manifest_index,
            )
        except ValueError as error:
            if str(error) not in {
                "CANDIDATE_CONTEXT_SOURCE_UNSAFE_OR_MISSING",
                "CANDIDATE_CONTEXT_SOURCE_CHANGED",
            }:
                raise
            unavailable[related_path] = "RELATED_SOURCE_UNSAFE_OR_MISSING"
            continue
        if related.source_unavailable_reason is not None:
            unavailable[related_path] = (
                "RELATED_SOURCE_TOO_LARGE"
                if related.source_unavailable_reason == "SOURCE_TOO_LARGE"
                else "RELATED_SOURCE_UNAVAILABLE"
            )
        elif any(line > len(related.source_lines) for line in lines):
            unavailable[related_path] = "RELATED_SOURCE_LOCATION_UNAVAILABLE"
        else:
            related_prepared[related_path] = related
    if unavailable:
        available_paths: dict[str, CandidateCallPaths] = {}
        for candidate_id, result in paths.items():
            retained: list[dict[str, object]] = []
            gaps = set(result.gaps)
            for call_path in result.paths:
                missing = {
                    path
                    for path, _line in call_path_step_locations((call_path,))
                    if path in unavailable
                }
                if missing:
                    gaps.update(
                        f"{unavailable[path]}:{path}" for path in sorted(missing)
                    )
                else:
                    retained.append(call_path)
            available_paths[candidate_id] = CandidateCallPaths(
                status="PARTIAL" if gaps or not retained else "AVAILABLE",
                paths=tuple(retained),
                gaps=tuple(sorted(gaps)),
            )
        paths = available_paths
    return artifacts.put_json(
        render_file_context(
            current,
            candidates,
            call_paths=paths,
            related_prepared=related_prepared,
        )
    )
