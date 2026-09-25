"""Feed the hypothesis agent the whole checkout, a module at a time.

Letting the agent choose which files to read left it choosing by name: one run
read a handful of files, proposed four hypotheses and never opened the router
whose sanitiser held the target defect.  Summarising the code into facts first
means deciding in advance what matters, which is the judgement a static rule
makes and fails the same way.

So nothing is chosen here.  Every source file goes into exactly one batch,
grouped by directory so that a module is read together, and each batch is
read in full.  Python is re-emitted from its syntax tree without comments or
docstrings - measured at 77% of the original with the logic intact - and a
file that is generated output rather than code someone wrote is left out and
named as left out, never silently.
"""

from __future__ import annotations

import ast
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

    def coverage(self) -> dict[str, object]:
        """Say where every file went, so a miss can be traced to its cause."""

        return {
            "kind": "simple_hypothesis_feeding",
            "batches": [
                {"batch": batch.number, "paths": list(batch.paths)}
                for batch in self.batches
            ],
            "excluded": list(self.excluded),
            "fed_files": sum(len(batch.files) for batch in self.batches),
        }


class _StripDocstrings(ast.NodeTransformer):
    def _strip(self, node: ast.AST) -> ast.AST:
        self.generic_visit(node)
        body = getattr(node, "body", None)
        if (
            isinstance(body, list)
            and body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            node.body = body[1:] or [ast.Pass()]  # type: ignore[attr-defined]
        return node

    visit_Module = _strip  # noqa: N815
    visit_ClassDef = _strip  # noqa: N815
    visit_FunctionDef = _strip  # noqa: N815
    visit_AsyncFunctionDef = _strip  # noqa: N815


def _render(path: str, text: str) -> str:
    """Return the code as the agent reads it: logic kept, commentary dropped."""

    if not path.endswith((".py", ".pyi")):
        return text
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            tree = ast.parse(text, filename=path)
        return ast.unparse(_StripDocstrings().visit(tree))
    except (SyntaxError, ValueError, RecursionError):
        # Unparseable Python is still code; read it as written.
        return text


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


def render_batch(batch: Batch) -> str:
    return "\n\n".join(f"=== FILE {item.path} ===\n{item.text}" for item in batch.files)


__all__ = [
    "BATCH_BYTES",
    "SOURCE_SUFFIXES",
    "Batch",
    "FedFile",
    "Feeding",
    "plan_feeding",
    "render_batch",
]
