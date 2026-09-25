"""Let an agent read the repository over several rounds instead of one.

A single call had to be given everything it might want up front, which meant
deciding in advance what mattered.  That decision was made by summarising three
megabytes of parsed facts into a map of counts and selected call names - and
choosing which names count is exactly what a static rule does, so it fails the
same way: whatever the list was not written for stays invisible.

An agent here asks instead.  It is given the checkout's file list and the tool
findings, it names the files it wants, it reads them, and what it reads may
make it name more.  When what it has read grows past the budget, the oldest
material is dropped and the agent's own notes about it are kept in its place -
so a long exploration costs a bounded prompt rather than a growing one.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

# How many times an agent may come back for more.  Each round is another call,
# so this bounds both the wall clock and what one hypothesis can spend.
MAX_ROUNDS = 4
# How much read material may sit in the prompt before the oldest is compacted
# away.  The static evidence is already a quarter of a megabyte, and the model
# was measured with a one-million-token window, so this leaves room rather than
# filling it.
COMPACTION_THRESHOLD_BYTES = 320_000


@dataclass(frozen=True, slots=True)
class Round:
    """One request-and-read cycle, as the next prompt will show it."""

    number: int
    requested_paths: tuple[str, ...]
    sources: dict[str, Any] | None
    ast: dict[str, Any] | None
    notes: dict[str, Any]
    """What the agent said after reading - kept when the raw text is dropped."""


@dataclass
class Exploration:
    """The rounds so far, and what of them the next prompt can afford."""

    rounds: list[Round] = field(default_factory=list)
    compacted: list[int] = field(default_factory=list)

    def requested_so_far(self) -> tuple[str, ...]:
        seen: list[str] = []
        for entry in self.rounds:
            for path in entry.requested_paths:
                if path not in seen:
                    seen.append(path)
        return tuple(seen)

    def record(
        self,
        *,
        requested_paths: Sequence[str],
        sources: dict[str, Any] | None,
        ast: dict[str, Any] | None,
        notes: dict[str, Any],
    ) -> None:
        self.rounds.append(
            Round(
                number=len(self.rounds) + 1,
                requested_paths=tuple(requested_paths),
                sources=sources,
                ast=ast,
                notes=notes,
            )
        )

    def compact(self, *, threshold: int = COMPACTION_THRESHOLD_BYTES) -> None:
        """Drop the oldest read material until what is left fits.

        The agent's notes are never dropped: they are what it made of the text,
        and they are two orders of magnitude smaller.  A round whose text is
        gone is named in ``compacted`` so the next prompt can say the files were
        read rather than let them look unread.
        """

        while _weight(self.rounds) > threshold:
            oldest = next(
                (entry for entry in self.rounds if entry.sources or entry.ast),
                None,
            )
            if oldest is None:
                return
            index = self.rounds.index(oldest)
            self.rounds[index] = Round(
                number=oldest.number,
                requested_paths=oldest.requested_paths,
                sources=None,
                ast=None,
                notes=oldest.notes,
            )
            self.compacted.append(oldest.number)

    def as_prompt_document(self) -> dict[str, Any]:
        """Render the history the way the next round will read it."""

        return {
            "kind": "simple_exploration_history",
            "rounds": [
                {
                    "round": entry.number,
                    "requested_paths": list(entry.requested_paths),
                    "notes": entry.notes,
                    **({"sources": entry.sources} if entry.sources else {}),
                    **({"ast": entry.ast} if entry.ast else {}),
                    **(
                        {}
                        if entry.sources or entry.ast
                        else {
                            "read_but_no_longer_quoted": True,
                            "why": (
                                "These files were read in this round.  The text "
                                "was dropped to keep the prompt bounded; the "
                                "notes above are what was made of it.  Ask again "
                                "only if the notes are not enough."
                            ),
                        }
                    ),
                }
                for entry in self.rounds
            ],
            "compacted_rounds": list(self.compacted),
        }


def render_history(document: dict[str, Any]) -> str:
    """The reading so far as Markdown: what was asked, what came back.

    Served files appear as code blocks under their own headings, so the agent
    reads them as it read its batch; a compacted round keeps its notes and
    says the text was dropped.
    """

    from .feeding import fenced

    parts = ["## What you have read so far"]
    for entry in document.get("rounds", ()):
        parts.append(f"### Round {entry['round']}")
        parts.append(
            "Requested: " + ", ".join(f"`{p}`" for p in entry["requested_paths"])
        )
        if entry.get("notes"):
            parts.append(
                "Your notes from that round:\n\n"
                + fenced(
                    json.dumps(entry["notes"], ensure_ascii=False, indent=1), "json"
                )
            )
        sources = entry.get("sources") or {}
        for item in sources.get("served", ()):
            suffix = str(item.get("path", "")).rsplit(".", 1)[-1]
            parts.append(f"#### {item.get('path')}")
            parts.append(
                fenced(str(item.get("content", "")), _FENCE_LANGUAGE.get(suffix, ""))
            )
        refused = list(sources.get("refused", ()))
        ast = entry.get("ast") or {}
        for item in ast.get("served", ()):
            parts.append(f"#### Parsed facts: {item.get('path')}")
            parts.append(
                fenced(json.dumps(item.get("facts", []), ensure_ascii=False), "json")
            )
        refused.extend(ast.get("refused", ()))
        if refused:
            parts.append(
                "Refused:\n"
                + "\n".join(f"- `{r.get('path')}`: {r.get('reason')}" for r in refused)
            )
        if entry.get("read_but_no_longer_quoted"):
            parts.append(f"_{entry['why']}_")
    return "\n\n".join(parts)


def _json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=1)


_FENCE_LANGUAGE = {"py": "python", "js": "javascript", "ts": "typescript", "tsx": "tsx"}


def _weight(rounds: Sequence[Round]) -> int:
    total = 0
    for entry in rounds:
        for served in (entry.sources, entry.ast):
            if not served:
                continue
            for item in served.get("served", ()):
                if not isinstance(item, dict):
                    continue
                count = item.get("byte_count")
                if isinstance(count, int):
                    total += count
                    continue
                facts = item.get("facts")
                if isinstance(facts, list):
                    # A parsed fact was measured at about a hundred bytes.
                    total += len(facts) * 100
    return total


__all__ = [
    "COMPACTION_THRESHOLD_BYTES",
    "MAX_ROUNDS",
    "Exploration",
    "Round",
    "render_history",
]
