"""Feed the hypothesis agent the whole checkout, a module at a time.

Letting the agent choose which files to read left it choosing by name: one run
read a handful of files, proposed four hypotheses and never opened the router
whose sanitiser held the target defect.  Summarising the code into facts first
means deciding in advance what matters, which is the judgement a static rule
makes and fails the same way.

So nothing is chosen here.  Every source file goes into exactly one batch,
grouped by directory so that a module is read together, and each batch is
read in full.  Blank lines, comment-only lines and Python docstrings are
dropped and every other line keeps its real number, so a hypothesis names a
location that exists in the checkout; a
file that is generated output rather than code someone wrote is left out and
named as left out, never silently.
"""

from __future__ import annotations

import ast
import re
import warnings
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .code_redaction import default_host_paths, redact_code

SOURCE_SUFFIXES = (".py", ".pyi", ".js", ".jsx", ".ts", ".tsx")
# What one call reads.  The model window was measured at a million tokens; a
# batch this size plus the repository map stays near an eighth of it, which is
# small enough to be read rather than skimmed and to keep clear of the burst
# limit a half-million-token prompt was measured tripping.
BATCH_BYTES = 280_000
# A file this large, or with lines this long, is a bundle or a build output.
_GENERATED_BYTES = 512_000
_GENERATED_LINE_CHARS = 2_000


@dataclass(frozen=True, slots=True)
class FedFile:
    path: str
    text: str
    redacted: tuple[str, ...] = ()
    # Set when the text is not the file's source, such as its entry points.
    language: str | None = None


@dataclass(frozen=True, slots=True)
class Batch:
    number: int
    files: tuple[FedFile, ...]

    @property
    def paths(self) -> tuple[str, ...]:
        return tuple(item.path for item in self.files)

    @property
    def size(self) -> int:
        return sum(len(item.text.encode("utf-8")) for item in self.files)


@dataclass
class Feeding:
    batches: list[Batch] = field(default_factory=list)
    excluded: list[dict[str, str]] = field(default_factory=list)
    signature_map: str = ""
    # ``code``: each batch is source.  ``facts``: each batch is entry points
    # and the calls their input reaches, with the source read on request.
    kind: str = "code"
    unfed: list[str] = field(default_factory=list)

    def coverage(self) -> dict[str, object]:
        """Say where every file went, so a miss can be traced to its cause."""

        return {
            "kind": "simple_hypothesis_feeding",
            "batches": [
                {"batch": batch.number, "paths": list(batch.paths)}
                for batch in self.batches
            ],
            "feed": self.kind,
            "excluded": list(self.excluded),
            "fed_files": sum(len(batch.files) for batch in self.batches),
            "files_read_only_on_request": list(self.unfed),
        }


def _docstring_lines(tree: ast.AST) -> set[int]:
    lines: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            continue
        body = node.body
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
            and body[0].end_lineno is not None
        ):
            lines.update(range(body[0].lineno, body[0].end_lineno + 1))
    return lines


def _render(path: str, text: str) -> str:
    """Return the code as the agent reads it, each line under its real number.

    A hypothesis must name a real location, and re-emitting Python from its
    syntax tree renumbers every line, so the lines are kept where they are and
    numbered: blank lines, comment-only lines and docstrings are dropped, and
    everything else keeps the number it has in the checkout.
    """

    source = text.splitlines()
    dropped: set[int] = set()
    if path.endswith((".py", ".pyi")):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                dropped = _docstring_lines(ast.parse(text, filename=path))
        except (SyntaxError, ValueError, RecursionError):
            dropped = set()
        comment = "#"
    else:
        comment = "//"
    kept: list[str] = []
    for number, line in enumerate(source, start=1):
        stripped = line.strip()
        if not stripped or number in dropped or stripped.startswith(comment):
            continue
        kept.append(f"{number}|{line.rstrip()}")
    return "\n".join(kept)


def _generated_reason(raw: bytes) -> str | None:
    if len(raw) > _GENERATED_BYTES:
        return "GENERATED_OR_BUNDLED_TOO_LARGE"
    if any(len(line) > _GENERATED_LINE_CHARS for line in raw.splitlines()):
        return "GENERATED_OR_MINIFIED"
    return None


def _signatures(path: str, text: str) -> list[str]:
    if not path.endswith((".py", ".pyi")):
        return [path]
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(text, filename=path)
    except (SyntaxError, ValueError, RecursionError):
        return [path]
    lines = [path]
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            lines.append(f"  {node.lineno}: def {node.name}({ast.unparse(node.args)})")
        elif isinstance(node, ast.ClassDef):
            lines.append(f"  {node.lineno}: class {node.name}")
    return lines


def plan_feeding(
    workspace: Path,
    tracked: Sequence[str],
    *,
    batch_bytes: int = BATCH_BYTES,
) -> Feeding:
    """Put every source file in exactly one batch, a directory at a time."""

    feeding = Feeding()
    signatures: list[str] = []
    host_paths = default_host_paths(workspace)
    ordered = sorted(
        (value for value in tracked if value.lower().endswith(SOURCE_SUFFIXES)),
        key=lambda value: (str(PurePosixPath(value).parent), value),
    )
    current: list[FedFile] = []
    current_size = 0
    current_dir: str | None = None

    def close() -> None:
        nonlocal current, current_size
        if current:
            feeding.batches.append(Batch(len(feeding.batches) + 1, tuple(current)))
        current, current_size = [], 0

    for path in ordered:
        try:
            raw = (workspace / path).read_bytes()
        except OSError:
            feeding.excluded.append({"path": path, "reason": "UNREADABLE"})
            continue
        reason = _generated_reason(raw)
        if reason is not None:
            feeding.excluded.append({"path": path, "reason": reason})
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            feeding.excluded.append({"path": path, "reason": "NOT_UTF8_TEXT"})
            continue
        rendered, removed = redact_code(_render(path, text), host_paths=host_paths)
        signatures.extend(_signatures(path, text))
        item = FedFile(path=path, text=rendered, redacted=removed)
        size = len(item.text.encode("utf-8"))
        directory = str(PurePosixPath(path).parent)
        # A new directory starts a new batch once the current one is half full,
        # so a module is read together without leaving batches nearly empty.
        if current and (
            current_size + size > batch_bytes
            or (directory != current_dir and current_size > batch_bytes // 2)
        ):
            close()
        current.append(item)
        current_size += size
        current_dir = directory
    close()
    feeding.signature_map = redact_code("\n".join(signatures), host_paths=host_paths)[0]
    return feeding


_LANGUAGE = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "jsx",
    ".ts": "typescript",
    ".tsx": "tsx",
}


def fenced(text: str, language: str = "") -> str:
    """Wrap ``text`` in a code fence longer than any backtick run inside it.

    Source files and model output can contain triple backticks of their own
    (in Markdown strings, docstrings, templates); a fixed fence would end early
    and turn the rest of the file into prose.
    """

    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{text}\n{fence}"


def render_batch(batch: Batch) -> str:
    """The batch's code as Markdown: a heading and a code block per file."""

    return "\n\n".join(
        f"### {item.path}\n\n"
        + fenced(
            item.text,
            item.language
            if item.language is not None
            else _LANGUAGE.get(PurePosixPath(item.path).suffix, ""),
        )
        for item in batch.files
    )


def plan_fact_feeding(
    flows: dict[str, object],
    code: Feeding,
    *,
    batch_bytes: int = BATCH_BYTES,
) -> Feeding:
    """Batch the entry points by file, in the same one-pass-over-all way.

    Every entry point goes into exactly one batch.  Files with no entry point
    are named so the agent can ask for them; they are not read unless asked,
    which is what this feed trades for its size.
    """

    import json

    feeding = Feeding(
        excluded=list(code.excluded), signature_map=code.signature_map, kind="facts"
    )
    by_file: dict[str, list[object]] = {}
    entries = flows.get("entry_points")
    for entry in entries if isinstance(entries, list) else []:
        if isinstance(entry, dict):
            by_file.setdefault(str(entry.get("file")), []).append(
                {key: value for key, value in entry.items() if key != "file"}
            )
    current: list[FedFile] = []
    size = 0
    for path in sorted(by_file):
        text = json.dumps(by_file[path], ensure_ascii=False, indent=1)
        item = FedFile(path=path, text=text, language="json")
        weight = len(text.encode("utf-8"))
        if current and size + weight > batch_bytes:
            feeding.batches.append(Batch(len(feeding.batches) + 1, tuple(current)))
            current, size = [], 0
        current.append(item)
        size += weight
    if current:
        feeding.batches.append(Batch(len(feeding.batches) + 1, tuple(current)))
    fed = set(by_file)
    feeding.unfed = sorted(
        path for batch in code.batches for path in batch.paths if path not in fed
    )
    return feeding


__all__ = [
    "plan_fact_feeding",
    "BATCH_BYTES",
    "fenced",
    "SOURCE_SUFFIXES",
    "Batch",
    "FedFile",
    "Feeding",
    "plan_feeding",
    "render_batch",
]
