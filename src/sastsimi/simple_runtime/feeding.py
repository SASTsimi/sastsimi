"""Prepare a bounded fact-or-source feed without silently skipping coverage."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from .code_redaction import redact_code
from .facts import extract_flows, safe_tracked_file

_SOURCE_SUFFIXES = (".py", ".pyi", ".js", ".jsx", ".ts", ".tsx")
_MAX_SOURCE_BYTES = 256_000


@dataclass(frozen=True, slots=True)
class SurveyFeed:
    kind: str
    content: str
    excluded: tuple[str, ...]
    tracked: tuple[str, ...]


def plan_survey_feed(workspace: Path, tracked: Sequence[str]) -> SurveyFeed:
    sources = tuple(
        sorted({path for path in tracked if path.endswith(_SOURCE_SUFFIXES)})
    )
    flows = extract_flows(workspace, sources)
    if flows["entry_points"]:
        excluded_facts = [item["path"] for item in flows["excluded"]]
        selected: list[object] = []
        used = 0
        for entry in flows["entry_points"]:
            size = len(json.dumps(entry, ensure_ascii=False).encode("utf-8")) + 2
            if used + size > _MAX_SOURCE_BYTES - 2048:
                excluded_facts.append("FACTS_BUDGET_EXHAUSTED")
                break
            selected.append(entry)
            used += size
        bounded = {
            **flows,
            "entry_points": selected,
            "truncated": len(selected) < len(flows["entry_points"]),
        }
        content = json.dumps(bounded, ensure_ascii=False, sort_keys=True)
        return SurveyFeed(
            "facts",
            redact_code(content, workspace=workspace),
            tuple(excluded_facts),
            sources,
        )
    remaining = _MAX_SOURCE_BYTES
    parts: list[str] = []
    excluded: list[str] = []
    for path in sources:
        candidate = safe_tracked_file(workspace, path)
        if candidate is None:
            excluded.append(path)
            continue
        try:
            raw = candidate.read_bytes()
            if len(raw) > remaining:
                excluded.append(path)
                continue
            text = raw.decode("utf-8")
        except (OSError, UnicodeError):
            excluded.append(path)
            continue
        numbered = "\n".join(
            f"{number}|{line}" for number, line in enumerate(text.splitlines(), 1)
        )
        rendered = f"### {path}\n{numbered}"
        size = len(rendered.encode("utf-8")) + 2
        if size > remaining:
            excluded.append(path)
            continue
        remaining -= size
        parts.append(rendered)
    return SurveyFeed(
        "code",
        redact_code("\n\n".join(parts), workspace=workspace),
        tuple(excluded),
        sources,
    )
