"""Which agent a model call belongs to, and the run's record of what it cost.

Every call's token counts are appended to one file per run, labelled with the
stage and hypothesis that made it.  The label travels in a context variable,
so no stage has to pass it down to the client by hand.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_LABEL: ContextVar[dict[str, str | None] | None] = ContextVar(
    "sastsimi_call_label", default=None
)


@contextmanager
def labelled(stage: str, hypothesis_id: str | None = None) -> Iterator[None]:
    token = _LABEL.set({"stage": stage, "hypothesis_id": hypothesis_id})
    try:
        yield
    finally:
        _LABEL.reset(token)


def current_label() -> dict[str, str | None]:
    label = _LABEL.get()
    return dict(label) if label else {"stage": None, "hypothesis_id": None}


def usage_path(data_dir: Path, analysis_id: str) -> Path:
    return data_dir / "usage" / f"{analysis_id}.jsonl"


def record_usage(data_dir: Path, analysis_id: str, entry: dict[str, Any]) -> None:
    target = usage_path(data_dir, analysis_id)
    target.parent.mkdir(parents=True, exist_ok=True)
    line = {
        "at": datetime.now(UTC).isoformat(),
        **current_label(),
        **entry,
    }
    with target.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(line, ensure_ascii=False) + "\n")


_SUMMED = (
    "input_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
    "output_tokens",
    "total_cost_usd",
)


def summarize(path: Path) -> dict[str, Any]:
    """Totals for the run and for each stage."""

    total: dict[str, Any] = {"calls": 0, **dict.fromkeys(_SUMMED, 0)}
    stages: dict[str, dict[str, Any]] = {}
    if not path.exists():
        return {"total": total, "stages": stages}
    for raw in path.read_text(encoding="utf-8").splitlines():
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError:
            continue
        bucket = stages.setdefault(
            str(entry.get("stage")), {"calls": 0, **dict.fromkeys(_SUMMED, 0)}
        )
        for target in (total, bucket):
            target["calls"] += 1
            for key in _SUMMED:
                value = entry.get(key)
                if isinstance(value, (int, float)):
                    target[key] += value
    return {"total": total, "stages": stages}


__all__ = ["current_label", "labelled", "record_usage", "summarize", "usage_path"]
