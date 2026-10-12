"""Narrow, execution-backed diagnosis of generated PoC source-path assumptions."""

from __future__ import annotations

import re
import shutil
import stat
import subprocess
from pathlib import Path, PurePosixPath

from .recovery import literal_required_python_path as literal_required_python_path
from .recovery import pinned_layout_replay_binding as pinned_layout_replay_binding


def pinned_layout_correction(
    workspace: Path, commit: str, missing: str, dockerfile: bytes
) -> str | None:
    """Map one failed /workspace source-root assumption to a pinned file.

    The caller must separately prove the original ``isfile`` test *executed*
    and failed. Git layout alone is never evidence that a container path is
    absent, because Docker build steps can create files.
    """

    git = shutil.which("git")
    if (
        git is None
        or re.fullmatch(r"[0-9a-f]{40}", commit) is None
        or not missing.startswith("/workspace/")
        or not missing.endswith(".py")
        or len(missing) > 4096
        or b"\x00" in dockerfile
        or re.search(rb"(?m)^WORKDIR /workspace\s*$", dockerfile) is None
        or re.search(rb"(?m)^COPY \. /workspace\s*$", dockerfile) is None
    ):
        return None
    relative = missing.removeprefix("/workspace/")
    parts = PurePosixPath(relative).parts
    if (
        len(parts) < 3
        or any(part in {"", ".", ".."} for part in parts)
        or "\\" in relative
        or "\x00" in relative
    ):
        return None
    prefix, suffix = parts[0], "/".join(parts[1:])
    try:
        root = workspace.resolve(strict=True)
        if workspace.is_symlink() or workspace.is_junction() or not root.is_dir():
            return None

        def run_git(*args: str) -> subprocess.CompletedProcess[bytes]:
            return subprocess.run(
                (git, "-C", str(root), *args),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=10,
                check=False,
            )

        top = run_git("rev-parse", "--show-toplevel")
        head = run_git("rev-parse", "HEAD")
        tree = run_git("ls-tree", "-r", "-z", commit)
        if (
            top.returncode != 0
            or Path(top.stdout.decode("utf-8").strip()).resolve(strict=True) != root
            or head.returncode != 0
            or head.stdout.decode("ascii").strip() != commit
            or tree.returncode != 0
            or len(tree.stdout) > 4 * 1024 * 1024
        ):
            return None
        tracked: set[str] = set()
        for entry in tree.stdout.split(b"\0"):
            if not entry:
                continue
            meta, sep, raw_path = entry.partition(b"\t")
            if not sep or not meta.startswith((b"100644 blob ", b"100755 blob ")):
                return None
            tracked.add(raw_path.decode("utf-8"))
        if relative in tracked or not any(
            path.startswith(prefix + "/") and path.endswith(".py") for path in tracked
        ):
            return None
        matches = [
            path
            for path in tracked
            if path.endswith(".py") and (path == suffix or path.endswith("/" + suffix))
        ]
        if matches != [suffix]:
            return None
        candidate = root
        for part in PurePosixPath(suffix).parts:
            candidate = candidate / part
            attrs = getattr(candidate.lstat(), "st_file_attributes", 0)
            if (
                candidate.is_symlink()
                or candidate.is_junction()
                or attrs & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
            ):
                return None
        if not candidate.is_file():
            return None
        return "/workspace/" + suffix
    except (OSError, UnicodeError, ValueError, subprocess.TimeoutExpired):
        return None
