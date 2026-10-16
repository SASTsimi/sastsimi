"""Check local Markdown fragments used by repository documentation."""

from __future__ import annotations

import argparse
import re
import subprocess
from pathlib import Path
from urllib.parse import unquote, urlsplit

LINK = re.compile(r"\]\((?P<target>[^)]+)\)")
HEADING = re.compile(r"^ {0,3}#{1,6}\s+(?P<title>.*?)\s*#*\s*$")
HTML_ID = re.compile(r"<a\b[^>]*\bid\s*=\s*['\"](?P<id>[^'\"]+)['\"]", re.I)
FENCE = re.compile(r"^ {0,3}(?P<fence>`{3,}|~{3,})")


def _visible_lines(markdown: str) -> list[str]:
    visible: list[str] = []
    fence_char = ""
    fence_length = 0
    for line in markdown.splitlines():
        match = FENCE.match(line)
        if match:
            fence = match.group("fence")
            if not fence_char:
                fence_char, fence_length = fence[0], len(fence)
                continue
            if fence[0] == fence_char and len(fence) >= fence_length:
                fence_char, fence_length = "", 0
                continue
        if not fence_char:
            visible.append(line)
    return visible


def _github_slug(title: str) -> str:
    title = re.sub(r"\[([^]]+)\]\([^)]*\)", r"\1", title)
    title = re.sub(r"<[^>]+>", "", title)
    title = title.replace("`", "").replace("*", "")
    title = "".join(char for char in title.lower() if char.isalnum() or char in "-_ ")
    return title.replace(" ", "-")


def _anchors(markdown: str) -> set[str]:
    anchors: set[str] = set()
    duplicate_counts: dict[str, int] = {}
    for line in _visible_lines(markdown):
        anchors.update(match.group("id") for match in HTML_ID.finditer(line))
        heading = HEADING.match(line)
        if heading:
            slug = _github_slug(heading.group("title"))
            if slug:
                count = duplicate_counts.get(slug, 0)
                anchors.add(slug if count == 0 else f"{slug}-{count}")
                duplicate_counts[slug] = count + 1
    return anchors


def validate_local_fragments(root: Path, files: list[Path]) -> list[str]:
    """Return missing local-fragment links in sorted, readable form."""
    errors: list[str] = []
    anchor_cache: dict[Path, set[str]] = {}
    for relative_source in sorted(files):
        source = root / relative_source
        if not source.is_file():
            continue
        for line in _visible_lines(source.read_text(encoding="utf-8")):
            for match in LINK.finditer(line):
                raw_target = match.group("target").strip().strip("<>")
                parsed = urlsplit(raw_target)
                if parsed.scheme or parsed.netloc or not parsed.fragment:
                    continue
                target_path = unquote(parsed.path)
                if target_path:
                    target = (
                        root / target_path.lstrip("/")
                        if target_path.startswith("/")
                        else source.parent / target_path
                    )
                else:
                    target = source
                if target.suffix.lower() != ".md" or not target.is_file():
                    continue  # The existing validator checks missing files.
                target = target.resolve()
                if target not in anchor_cache:
                    anchor_cache[target] = _anchors(target.read_text(encoding="utf-8"))
                if unquote(parsed.fragment) not in anchor_cache[target]:
                    errors.append(f"{relative_source.as_posix()} -> {raw_target}")
    return sorted(errors)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    root = args.root.resolve()
    tracked = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--cached", "--", "*.md"],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.splitlines()
    errors = validate_local_fragments(root, [Path(path) for path in tracked])
    for error in errors:
        print(f"missing Markdown fragment: {error}")
    print(f"Checked Markdown fragments in {len(tracked)} files: {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
