"""Isolated parse-only Python worker used by the AST process adapter."""

from __future__ import annotations

import ast
import json
import platform
import sys
from pathlib import Path, PurePosixPath
from typing import Any

JsonObject = dict[str, Any]


def _position(line: str, byte_offset: int) -> int:
    """Convert CPython's UTF-8 byte offset to a one-based code-point column."""

    prefix = line.encode("utf-8")[:byte_offset]
    return len(prefix.decode("utf-8")) + 1


def _location(path: str, node: ast.AST, lines: tuple[str, ...]) -> JsonObject:
    start_line = int(getattr(node, "lineno", 1))
    end_line = int(getattr(node, "end_lineno", start_line) or start_line)
    start_offset = getattr(node, "col_offset", None)
    end_offset = getattr(node, "end_col_offset", None)
    if start_offset is None or end_offset is None:
        start_column = None
        end_column = None
    else:
        start_column = _position(lines[start_line - 1], int(start_offset))
        end_column = _position(lines[end_line - 1], int(end_offset))
    return {
        "file_path": path,
        "start_line": start_line,
        "start_column": start_column,
        "end_line": end_line,
        "end_column": end_column,
    }


def _whole_file(path: str, lines: tuple[str, ...]) -> JsonObject:
    return {
        "file_path": path,
        "start_line": 1,
        "start_column": None,
        "end_line": max(1, len(lines)),
        "end_column": None,
    }


def _key(kind: str, path: str, location: JsonObject, name: str) -> str:
    return (
        f"{kind}:{path}:{location['start_line']}:{location['start_column'] or 0}:{name}"
    )


def _symbol(
    kind: str,
    native_kind: str | None,
    name: str,
    path: str,
    location: JsonObject,
) -> JsonObject:
    return {
        "source_key": _key(kind, path, location, name),
        "symbol_kind": kind,
        "native_kind": native_kind,
        "name": name,
        "location": location,
    }


def _gap(
    code: str,
    reason: str,
    description: str,
    path: str,
    location: JsonObject | None = None,
) -> JsonObject:
    return {
        "stage": "STATIC_ANALYSIS",
        "code": code,
        "reason": reason,
        "description": description,
        "affected_paths": [path],
        "affected_languages": ["Python"],
        "affected_locations": [] if location is None else [location],
        "retryable": False,
    }


class FileExtractor(ast.NodeVisitor):
    """Collect symbols and syntax-only relations without loading the module."""

    ROUTE_METHODS = frozenset(
        {
            "route",
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "options",
            "head",
            "websocket",
        }
    )

    def __init__(self, path: str, source: str, tree: ast.Module) -> None:
        self.path = path
        self.lines = tuple(source.splitlines()) or ("",)
        self.tree = tree
        self.symbols: list[JsonObject] = []
        self.relations: list[JsonObject] = []
        self.gaps: list[JsonObject] = []
        self._scope_names: list[str] = []
        self._scope_keys: list[str] = []
        self._defined_callables: dict[str, list[str]] = {}
        self._relation_order = 0
        whole = _whole_file(path, self.lines)
        file_symbol = _symbol("FILE", "PYTHON_FILE", path, path, whole)
        module_name = path.removesuffix(".py").replace("/", ".")
        module_symbol = _symbol("MODULE", "PYTHON_MODULE", module_name, path, whole)
        self.symbols.extend((file_symbol, module_symbol))
        self.module_key = module_symbol["source_key"]

    def extract(self) -> tuple[list[JsonObject], list[JsonObject], list[JsonObject]]:
        self._collect_definitions(self.tree.body)
        self.visit(self.tree)
        for node in ast.walk(self.tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                FlowExtractor(self, node).run()
        self.symbols.sort(key=lambda item: item["source_key"])
        self.relations.sort(key=lambda item: item["source_key"])
        self.gaps.sort(
            key=lambda item: (
                tuple(item["affected_paths"]),
                json.dumps(item["affected_locations"], sort_keys=True),
                item["code"],
                item["description"],
            )
        )
        return self.symbols, self.relations, self.gaps

    def _collect_definitions(self, body: list[ast.stmt], prefix: str = "") -> None:
        for node in body:
            if isinstance(node, ast.ClassDef):
                name = f"{prefix}.{node.name}" if prefix else node.name
                location = _location(self.path, node, self.lines)
                self.symbols.append(_symbol("TYPE", "CLASS", name, self.path, location))
                self._collect_definitions(node.body, name)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = f"{prefix}.{node.name}" if prefix else node.name
                location = _location(self.path, node, self.lines)
                item = _symbol(
                    "CALLABLE",
                    "ASYNC_FUNCTION"
                    if isinstance(node, ast.AsyncFunctionDef)
                    else "FUNCTION",
                    name,
                    self.path,
                    location,
                )
                self.symbols.append(item)
                self._defined_callables.setdefault(node.name, []).append(
                    item["source_key"]
                )
                self._collect_definitions(node.body, name)

    def _relation(
        self,
        kind: str,
        from_key: str | None,
        from_location: JsonObject,
        to_key: str | None,
        to_location: JsonObject,
    ) -> None:
        self._relation_order += 1
        self.relations.append(
            {
                "source_key": f"relation:{self.path}:{self._relation_order:08d}:{kind}",
                "relation_kind": kind,
                "from_symbol_source_key": from_key,
                "from_location": from_location,
                "to_symbol_source_key": to_key,
                "to_location": to_location,
                "rule_id": None,
            }
        )

    def _owner(self) -> str:
        return self._scope_keys[-1] if self._scope_keys else self.module_key

    def _enter_callable(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        qualified = ".".join((*self._scope_names, node.name))
        location = _location(self.path, node, self.lines)
        key = _key("CALLABLE", self.path, location, qualified)
        self._scope_names.append(node.name)
        self._scope_keys.append(key)
        self._route_relations(node, key)
        for statement in node.body:
            self.visit(statement)
        self._scope_keys.pop()
        self._scope_names.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._enter_callable(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._enter_callable(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._scope_names.append(node.name)
        for statement in node.body:
            self.visit(statement)
        self._scope_names.pop()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            location = _location(self.path, node, self.lines)
            imported = _symbol(
                "MODULE", "IMPORTED_MODULE", alias.name, self.path, location
            )
            self.symbols.append(imported)
            self._relation(
                "IMPORT", self._owner(), location, imported["source_key"], location
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        location = _location(self.path, node, self.lines)
        module = "." * node.level + (node.module or "")
        imported = _symbol("MODULE", "IMPORTED_MODULE", module, self.path, location)
        self.symbols.append(imported)
        self._relation(
            "IMPORT", self._owner(), location, imported["source_key"], location
        )

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name):
            candidates = self._defined_callables.get(node.func.id, [])
            location = _location(self.path, node.func, self.lines)
            if len(candidates) == 1:
                target = candidates[0]
            else:
                item = _symbol(
                    "CALLABLE", "DIRECT_CALL_TARGET", node.func.id, self.path, location
                )
                self.symbols.append(item)
                target = item["source_key"]
                if len(candidates) > 1:
                    self.gaps.append(
                        _gap(
                            "STATIC_CALL_UNRESOLVED",
                            "UNSUPPORTED",
                            "Direct call name resolves to more than one callable.",
                            self.path,
                            location,
                        )
                    )
            self._relation("CALL", self._owner(), location, target, location)
        elif not self._is_route_call(node):
            self.gaps.append(
                _gap(
                    "STATIC_CALL_UNRESOLVED",
                    "UNSUPPORTED",
                    "Dynamic or attribute call target was not guessed.",
                    self.path,
                    _location(self.path, node.func, self.lines),
                )
            )
        self.generic_visit(node)

    def _is_route_call(self, node: ast.Call) -> bool:
        return (
            isinstance(node.func, ast.Attribute)
            and node.func.attr.lower() in self.ROUTE_METHODS
        )

    def _route_relations(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef, handler_key: str
    ) -> None:
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not self._is_route_call(
                decorator
            ):
                continue
            if (
                not decorator.args
                or not isinstance(decorator.args[0], ast.Constant)
                or not isinstance(decorator.args[0].value, str)
            ):
                self.gaps.append(
                    _gap(
                        "STATIC_ROUTE_UNRESOLVED",
                        "UNSUPPORTED",
                        "Route decorator path is not a literal string.",
                        self.path,
                        _location(self.path, decorator, self.lines),
                    )
                )
                continue
            route_call = decorator.func
            if not isinstance(route_call, ast.Attribute):
                raise AssertionError("route predicate failed to narrow attribute")
            method = route_call.attr.upper()
            route_name = f"{method} {decorator.args[0].value}"
            location = _location(self.path, decorator, self.lines)
            route = _symbol(
                "ROUTE", "PYTHON_DECORATOR", route_name, self.path, location
            )
            self.symbols.append(route)
            handler_location = _location(self.path, node, self.lines)
            self._relation(
                "ROUTE_BINDING",
                route["source_key"],
                location,
                handler_key,
                handler_location,
            )


class FlowExtractor:
    """Conservative reaching definitions for one straight-line callable body."""

    BARRIERS = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        ast.TryStar,
        ast.With,
        ast.AsyncWith,
        ast.Match,
        ast.Global,
        ast.Nonlocal,
    )
    COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
    DYNAMIC_NAMES = frozenset(
        {
            "eval",
            "exec",
            "compile",
            "globals",
            "locals",
            "getattr",
            "setattr",
            "delattr",
            "__import__",
        }
    )

    def __init__(
        self, owner: FileExtractor, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        self.owner = owner
        self.node = node
        self.definitions: dict[str, tuple[str, JsonObject]] = {}

    def run(self) -> None:
        for statement in self.node.body:
            self._statement(statement)

    def _statement(self, statement: ast.stmt) -> None:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        if isinstance(statement, self.BARRIERS):
            self._invalidate(statement, "Control-flow or scope boundary is not joined.")
            return
        if isinstance(statement, ast.Assign):
            if len(statement.targets) != 1 or not isinstance(
                statement.targets[0], ast.Name
            ):
                self._invalidate(statement, "Assignment target is not one local name.")
                return
            self._assignment(statement.targets[0], statement.value)
            return
        if isinstance(statement, ast.AnnAssign):
            if not isinstance(statement.target, ast.Name) or statement.value is None:
                self._invalidate(
                    statement, "Annotated assignment is not one initialized local name."
                )
                return
            self._assignment(statement.target, statement.value)
            return
        if isinstance(statement, (ast.AugAssign, ast.Delete)):
            self._invalidate(
                statement, "Mutating assignment invalidates reaching definitions."
            )
            return
        if self._ambiguous_expression(statement):
            self._invalidate(
                statement,
                "Dynamic execution, alias mutation, or comprehension is ambiguous.",
            )
            return
        self._loads(statement)

    def _assignment(self, target: ast.Name, expression: ast.expr) -> None:
        if isinstance(expression, ast.Name) or self._ambiguous_expression(expression):
            self._invalidate(expression, "Alias or dynamic assignment is ambiguous.")
            return
        self._loads(expression)
        expression_location = _location(self.owner.path, expression, self.owner.lines)
        target_location = _location(self.owner.path, target, self.owner.lines)
        name = ".".join((*self.owner._scope_names, target.id))
        symbol = _symbol(
            "DATA", "LOCAL_DEFINITION", name, self.owner.path, target_location
        )
        self.owner.symbols.append(symbol)
        self.owner._relation(
            "DATA_FLOW",
            None,
            expression_location,
            symbol["source_key"],
            target_location,
        )
        self.definitions[target.id] = (symbol["source_key"], target_location)

    def _loads(self, node: ast.AST) -> None:
        for child in ast.walk(node):
            if not isinstance(child, ast.Name) or not isinstance(child.ctx, ast.Load):
                continue
            definition = self.definitions.get(child.id)
            if definition is None:
                continue
            key, location = definition
            self.owner._relation(
                "DATA_FLOW",
                key,
                location,
                None,
                _location(self.owner.path, child, self.owner.lines),
            )

    def _ambiguous_expression(self, node: ast.AST) -> bool:
        for child in ast.walk(node):
            if isinstance(child, self.COMPREHENSIONS):
                return True
            if isinstance(child, ast.Call):
                if (
                    isinstance(child.func, ast.Name)
                    and child.func.id in self.DYNAMIC_NAMES
                ):
                    return True
                if (
                    isinstance(child.func, ast.Attribute)
                    and isinstance(child.func.value, ast.Name)
                    and child.func.value.id in self.definitions
                ):
                    return True
        return False

    def _invalidate(self, node: ast.AST, description: str) -> None:
        self.owner.gaps.append(
            _gap(
                "STATIC_DATA_FLOW_INCOMPLETE",
                "UNSUPPORTED",
                description,
                self.owner.path,
                _location(self.owner.path, node, self.owner.lines),
            )
        )
        self.definitions.clear()


def _safe_file(root: Path, git_path: str) -> Path | None:
    pure = PurePosixPath(git_path)
    if (
        not git_path
        or "\\" in git_path
        or pure.is_absolute()
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        return None
    candidate = root.joinpath(*pure.parts)
    if candidate.is_symlink() or (
        hasattr(candidate, "is_junction") and candidate.is_junction()
    ):
        return None
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    return resolved if resolved.is_file() else None


def analyze(root: Path, manifest: tuple[str, ...]) -> JsonObject:
    root = root.resolve(strict=True)
    symbols: list[JsonObject] = []
    relations: list[JsonObject] = []
    gaps: list[JsonObject] = []
    errors: list[JsonObject] = []
    analyzed: list[str] = []
    skipped: list[str] = []
    received: list[str] = []
    for git_path in sorted(set(manifest)):
        candidate = _safe_file(root, git_path)
        if candidate is None:
            skipped.append(git_path)
            gaps.append(
                _gap(
                    "STATIC_PATH_UNSAFE",
                    "BLOCKED",
                    "Manifest path is not a safe tracked regular file.",
                    git_path,
                )
            )
            continue
        received.append(git_path)
        try:
            source = candidate.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=git_path, mode="exec")
        except (OSError, UnicodeError, SyntaxError) as error:
            skipped.append(git_path)
            gaps.append(
                _gap(
                    "STATIC_PARSE_FAILED",
                    "FAILED",
                    f"Python source could not be parsed: {type(error).__name__}.",
                    git_path,
                )
            )
            continue
        extracted_symbols, extracted_relations, extracted_gaps = FileExtractor(
            git_path, source, tree
        ).extract()
        symbols.extend(extracted_symbols)
        relations.extend(extracted_relations)
        gaps.extend(extracted_gaps)
        analyzed.append(git_path)
    symbols.sort(key=lambda item: item["source_key"])
    relations.sort(
        key=lambda item: (item["from_location"]["file_path"], item["source_key"])
    )
    gaps.sort(
        key=lambda item: (
            tuple(item["affected_paths"]),
            item["code"],
            item["description"],
        )
    )
    return {
        "schema_version": 1,
        "parser_version": platform.python_version(),
        "files": received,
        "analyzed_paths": analyzed,
        "skipped_paths": skipped,
        "symbols": symbols,
        "facts": [],
        "relations": relations,
        "gaps": gaps,
        "errors": errors,
    }


def main(argv: list[str]) -> int:
    payload = analyze(Path.cwd(), tuple(argv[1:]))
    sys.stdout.buffer.write(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
