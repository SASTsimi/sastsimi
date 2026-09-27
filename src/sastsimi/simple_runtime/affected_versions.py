"""Which tagged releases carry the code a finding was confirmed in.

The analysis runs against one pinned commit, but its checkout is a full clone
with every tag the repository had when it was cloned.  Reading the confirmed
finding's own lines back out of each release tag answers "which released
versions ship this code" from the clone alone - no network, no model.

Two tiers, because an exact match alone undercounts: saleor's
``find_variant_id_when_line_parameter_used`` carries the same bug in 3.20.0
as at the analyzed commit, but gained a return annotation in between.  A
release whose lines are merely similar is reported as such, for a human to
confirm; one with neither is not claimed to be unaffected, only unmatched.
"""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from difflib import SequenceMatcher
from pathlib import Path

_RELEASE_TAG = re.compile(r"v?\d+(?:\.\d+)+")
_TIMEOUT_SECONDS = 120
_MAX_LOCATIONS = 3
_MAX_RUNS = 6
# A proposal's location is where the hypothesis pointed, not always the
# confirmed lines: a whole file (``tasks.py:1-300``) would match almost no
# release, and a single import line almost every one.  Either would read as a
# confident range, so such locations are not used at all.
_MIN_LINES = 3
_MAX_SPAN = 80
# "Similar": at least this share of the lines, in order, within a stretch not
# much longer than the original - so lines scattered across a file do not add
# up to a match.
_SIMILAR_SHARE = 0.7
_SIMILAR_SLACK = 2.0

EXACT, SIMILAR, ABSENT = "exact", "similar", "absent"


@dataclass(frozen=True, slots=True)
class AffectedVersions:
    checked: tuple[str, ...]
    # In version order, for reading off ranges.
    releases: tuple[str, ...]
    exact: tuple[str, ...]
    similar: tuple[str, ...]

    def affected_line(self) -> str:
        total = len(self.releases)
        parts = []
        if self.exact:
            parts.append(
                f"Identical code found in {len(self.exact)} of {total} release "
                f"tags: {_runs(self.releases, self.exact)}."
            )
        if self.similar:
            parts.append(
                f"Similar code (at least {int(_SIMILAR_SHARE * 100)}% of the same "
                f"lines, in order) in {len(self.similar)} more: "
                f"{_runs(self.releases, self.similar)} - likely the same flaw, "
                "confirm by hand."
            )
        if not parts:
            parts.append(f"Not found in any of {total} release tags.")
        parts.append(
            f"Checked against {', '.join(self.checked)} in every release tag of "
            "the analyzed clone; a release not listed may still carry the flaw "
            "in rewritten code - not verified."
        )
        return " ".join(parts)


def find_affected_versions(
    workspace: Path,
    commit: str,
    locations: Sequence[tuple[str, int, int]],
) -> AffectedVersions | None:
    """Return the release tags carrying ``locations``, or ``None``.

    ``None`` means the question could not be asked - no git history, no
    release tags, or no usable lines - and the report keeps its placeholder.
    """

    if not (workspace / ".git").exists():
        return None
    tags = _git(workspace, "tag", "--list", "--sort=v:refname").splitlines()
    releases = [tag for tag in tags if _RELEASE_TAG.fullmatch(tag)] or tags
    if not releases:
        return None
    usable = [
        (path, start, end)
        for path, start, end in locations
        if 0 < start <= end and end - start < _MAX_SPAN
    ]
    snippets: list[tuple[str, list[str]]] = []
    checked: list[str] = []
    for path, start, end in usable[:_MAX_LOCATIONS]:
        source = _blobs(workspace, [f"{commit}:{path}"])[0]
        if source is None:
            continue
        lines = _normalize(source.splitlines()[start - 1 : end])
        if len(lines) >= _MIN_LINES:
            snippets.append((path, lines))
            checked.append(f"{path}:{start}-{end}")
    if not snippets:
        return None
    paths = sorted({path for path, _ in snippets})
    requests = [f"refs/tags/{tag}:{path}" for tag in releases for path in paths]
    blobs = dict(zip(requests, _blobs(workspace, requests), strict=True))
    exact: list[str] = []
    similar: list[str] = []
    for tag in releases:
        files = {
            path: _normalize((blobs[f"refs/tags/{tag}:{path}"] or "").splitlines())
            for path in paths
        }
        # A tag is only as matched as its weakest location.
        grades = [_grade(files[path], lines) for path, lines in snippets]
        if all(grade == EXACT for grade in grades):
            exact.append(tag)
        elif ABSENT not in grades:
            similar.append(tag)
    return AffectedVersions(
        checked=tuple(checked),
        releases=tuple(releases),
        exact=tuple(exact),
        similar=tuple(similar),
    )


def _grade(haystack: list[str], needle: list[str]) -> str:
    size = len(needle)
    if any(
        haystack[index : index + size] == needle
        for index in range(len(haystack) - size + 1)
        if haystack[index] == needle[0]
    ):
        return EXACT
    wanted = set(needle)
    best = 0
    window = int(size * _SIMILAR_SLACK)
    for index, line in enumerate(haystack):
        if line not in wanted:
            continue
        stretch = haystack[index : index + window]
        matcher = SequenceMatcher(None, needle, stretch, autojunk=False)
        best = max(best, sum(block.size for block in matcher.get_matching_blocks()))
    return SIMILAR if best >= size * _SIMILAR_SHARE else ABSENT


def _runs(releases: Sequence[str], chosen: Sequence[str]) -> str:
    wanted = set(chosen)
    runs: list[tuple[str, str]] = []
    start: str | None = None
    previous: str | None = None
    for tag in releases:
        if tag in wanted:
            start = start or tag
            previous = tag
        elif start is not None and previous is not None:
            runs.append((start, previous))
            start = previous = None
    if start is not None and previous is not None:
        runs.append((start, previous))
    text = [first if first == last else f"{first} - {last}" for first, last in runs]
    more = len(text) - _MAX_RUNS
    suffix = f" (+{more} more ranges)" if more > 0 else ""
    return ", ".join(text[:_MAX_RUNS]) + suffix


def _normalize(lines: Sequence[str]) -> list[str]:
    return [line.strip() for line in lines if line.strip()]


def _environment() -> dict[str, str]:
    return {
        **os.environ,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    }


def _git(workspace: Path, *arguments: str) -> str:
    result = subprocess.run(
        ("git", *arguments),
        cwd=workspace,
        capture_output=True,
        env=_environment(),
        timeout=_TIMEOUT_SECONDS,
        check=True,
    )
    return result.stdout.decode("utf-8", errors="replace")


def _blobs(workspace: Path, requests: Sequence[str]) -> list[str | None]:
    """Read many ``<rev>:<path>`` objects in one ``git cat-file`` process."""

    result = subprocess.run(
        ("git", "cat-file", "--batch"),
        cwd=workspace,
        input="".join(f"{request}\n" for request in requests).encode("utf-8"),
        capture_output=True,
        env=_environment(),
        timeout=_TIMEOUT_SECONDS,
        check=True,
    )
    output = result.stdout
    found: list[str | None] = []
    position = 0
    for _ in requests:
        end = output.index(b"\n", position)
        header = output[position:end].split()
        position = end + 1
        if len(header) != 3 or header[1] != b"blob":
            # "missing", "ambiguous", or a tree: nothing to read at that path.
            found.append(None)
            if len(header) == 3:
                position += int(header[2]) + 1
            continue
        size = int(header[2])
        found.append(output[position : position + size].decode("utf-8", "replace"))
        position += size + 1
    return found


__all__ = ["AffectedVersions", "find_affected_versions"]
