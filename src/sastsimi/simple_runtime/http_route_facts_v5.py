"""Opt-in, source-bound standard-library HTTP route-to-surface facts.

These paths prove only syntactic reachability.  In particular, a request read
is not evidence that its value flows to the indexed surface.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .attack_surfaces import AttackSurface
from .call_path_facts import CandidateCallPaths
from .facts import safe_tracked_file

_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_SCAN_FILES = 4_000
_MAX_HOPS = 6
_MAX_PATHS = 4
_REQUEST_ATTRIBUTES = frozenset({"path", "headers", "rfile"})
_VERB_METHOD = re.compile(r"do_[A-Z]+\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ReadSite = tuple[tuple[str, str, str], int, str]


@dataclass(frozen=True, slots=True)
class _Method:
    path: str
    source_sha256: str
    class_name: str
    node: ast.FunctionDef | ast.AsyncFunctionDef

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.path, self.class_name, self.node.name)

    @property
    def symbol(self) -> str:
        return f"{self.class_name}.{self.node.name}"


@dataclass(frozen=True, slots=True)
class _Module:
    path: str
    source_sha256: str
    classes: Mapping[str, ast.ClassDef]
    methods: Mapping[tuple[str, str], _Method]
    handler_classes: frozenset[str]
    handler_import_lines: Mapping[str, int]
    gaps: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Instance:
    class_name: str
    constructor_line: int
    branch: tuple[tuple[int, int], ...]


@dataclass(slots=True)
class _State:
    instances: dict[str, _Instance | str] = field(default_factory=dict)
    assigned: set[str] = field(default_factory=set)
    reads: list[tuple[int, str]] = field(default_factory=list)
    branch: tuple[tuple[int, int], ...] = ()

    def fork(self, branch: tuple[int, int]) -> _State:
        return _State(
            instances=dict(self.instances),
            assigned=set(self.assigned),
            reads=list(self.reads),
            branch=(*self.branch, branch),
        )


@dataclass(frozen=True, slots=True)
class _Call:
    target: tuple[str, str, str]
    line: int
    constructor_line: int | None
    constructor_symbol: str | None
    request_reads: tuple[tuple[int, str], ...]
    receiver_is_self: bool


@dataclass(frozen=True, slots=True)
class _MethodFacts:
    calls: tuple[_Call, ...]
    reads_at_line: Mapping[int, tuple[tuple[int, str], ...]]
    gaps: tuple[str, ...]


def _source(workspace: Path, path: str, expected: str) -> bytes:
    """Read a regular tracked file once and bind it to its indexed digest."""

    if not _DIGEST.fullmatch(expected):
        raise ValueError("HTTP_SOURCE_HASH_INVALID")
    source = safe_tracked_file(workspace, path)
    if source is None:
        raise ValueError("HTTP_SOURCE_UNAVAILABLE")
    try:
        before = source.lstat()
        if not stat.S_ISREG(before.st_mode) or source.is_symlink():
            raise ValueError("HTTP_SOURCE_UNAVAILABLE")
        if before.st_size > _MAX_SOURCE_BYTES:
            raise ValueError("HTTP_SOURCE_TOO_LARGE")
        descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            current = os.fstat(stream.fileno())
            if not stat.S_ISREG(current.st_mode) or (
                current.st_dev,
                current.st_ino,
            ) != (before.st_dev, before.st_ino):
                raise ValueError("HTTP_SOURCE_CHANGED")
            raw = stream.read(_MAX_SOURCE_BYTES + 1)
    except OSError as error:
        raise ValueError("HTTP_SOURCE_UNAVAILABLE") from error
    if len(raw) > _MAX_SOURCE_BYTES:
        raise ValueError("HTTP_SOURCE_TOO_LARGE")
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("HTTP_SOURCE_HASH_MISMATCH")
    return raw


def _bound_names(node: ast.AST) -> set[str]:
    """Names a statement can bind in its enclosing scope."""

    names: set[str] = set()
    for item in ast.walk(node):
        if isinstance(item, ast.Name) and isinstance(item.ctx, (ast.Store, ast.Del)):
            names.add(item.id)
        elif isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(item.name)
        elif isinstance(item, ast.Import):
            names.update(
                alias.asname or alias.name.split(".")[0] for alias in item.names
            )
        elif isinstance(item, ast.ImportFrom):
            names.update(alias.asname or alias.name for alias in item.names)
    return names


def _module_bound_names(node: ast.AST) -> set[str]:
    """Find module-scope writes without confusing function locals with globals."""

    names: set[str] = set()

    def visit(item: ast.AST) -> None:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(item.name)
            return
        if isinstance(item, ast.Import):
            names.update(
                alias.asname or alias.name.split(".")[0] for alias in item.names
            )
            return
        if isinstance(item, ast.ImportFrom):
            names.update(alias.asname or alias.name for alias in item.names)
            return
        if isinstance(item, ast.Name) and isinstance(item.ctx, (ast.Store, ast.Del)):
            names.add(item.id)
        for child in ast.iter_child_nodes(item):
            visit(child)

    visit(node)
    return names


def _module(path: str, digest: str, tree: ast.Module) -> _Module:
    source_import_lines: dict[str, int] = {}
    binding_kinds: dict[str, list[str]] = {}
    class_groups: dict[str, list[ast.ClassDef]] = {}
    gaps: set[str] = set()
    for item in tree.body:
        if (
            isinstance(item, ast.ImportFrom)
            and item.level == 0
            and item.module == "http.server"
        ):
            for alias in item.names:
                if alias.name == "BaseHTTPRequestHandler":
                    name = alias.asname or alias.name
                    binding_kinds.setdefault(name, []).append("handler_import")
                    source_import_lines[name] = item.lineno
                else:
                    binding_kinds.setdefault(alias.asname or alias.name, []).append(
                        "other"
                    )
        elif isinstance(item, ast.ClassDef):
            binding_kinds.setdefault(item.name, []).append("class")
        else:
            for name in _module_bound_names(item):
                binding_kinds.setdefault(name, []).append("other")
        if isinstance(item, ast.ClassDef):
            class_groups.setdefault(item.name, []).append(item)
    imports = {
        name: line
        for name, line in source_import_lines.items()
        if binding_kinds[name] == ["handler_import"]
    }
    classes = {
        name: group[0]
        for name, group in class_groups.items()
        if len(group) == 1 and binding_kinds[name] == ["class"]
    }
    if len(classes) != len(class_groups):
        gaps.add("HTTP_CLASS_BINDING_AMBIGUOUS")
    methods: dict[tuple[str, str], _Method] = {}
    for class_name, class_node in classes.items():
        method_groups: dict[str, list[ast.FunctionDef | ast.AsyncFunctionDef]] = {}
        method_bindings: dict[str, list[str]] = {}
        for item in class_node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method_groups.setdefault(item.name, []).append(item)
                method_bindings.setdefault(item.name, []).append("method")
            else:
                for name in _module_bound_names(item):
                    method_bindings.setdefault(name, []).append("other")
        for method_name, group in method_groups.items():
            if len(group) == 1 and method_bindings[method_name] == ["method"]:
                methods[(class_name, method_name)] = _Method(
                    path, digest, class_name, group[0]
                )
            else:
                gaps.add("HTTP_METHOD_BINDING_AMBIGUOUS")
    handler_classes: set[str] = set()
    import_lines: dict[str, int] = {}
    for _ in range(len(classes)):
        previous = len(handler_classes)
        for name, class_node in classes.items():
            if name in handler_classes:
                continue
            direct = [
                base.id for base in class_node.bases if isinstance(base, ast.Name)
            ]
            origins = [
                imports[base]
                for base in direct
                if base in imports and imports[base] < class_node.lineno
            ]
            origins.extend(
                import_lines[base]
                for base in direct
                if base in handler_classes and classes[base].lineno < class_node.lineno
            )
            if origins:
                handler_classes.add(name)
                import_lines[name] = min(origins)
        if len(handler_classes) == previous:
            break
    return _Module(
        path,
        digest,
        classes,
        methods,
        frozenset(handler_classes),
        import_lines,
        tuple(sorted(gaps)),
    )


def _is_request_self(method: _Method) -> bool:
    node = method.node
    if not node.args.posonlyargs and not node.args.args:
        return False
    first = (*node.args.posonlyargs, *node.args.args)[0]
    if first.arg != "self" or node.decorator_list:
        return False
    # Any local rebinding makes `self.path` uncertain, even in one branch.
    for statement in node.body:
        if "self" in _bound_names(statement):
            return False
    return True


def _assigned_in_block(statements: Sequence[ast.stmt]) -> set[str]:
    assigned: set[str] = set()
    for statement in statements:
        assigned.update(_bound_names(statement))
    return assigned


class _MethodAnalyzer:
    def __init__(self, module: _Module, method: _Method, *, request_self: bool) -> None:
        self.module = module
        self.method = method
        self.request_self = request_self
        self.calls: list[_Call] = []
        self.reads_at_line: dict[int, tuple[tuple[int, str], ...]] = {}
        self.gaps: set[str] = set()

    def analyze(self) -> _MethodFacts:
        arguments = self.method.node.args
        parameter_names = {
            argument.arg
            for argument in (
                *arguments.posonlyargs,
                *arguments.args,
                *arguments.kwonlyargs,
            )
        }
        if arguments.vararg is not None:
            parameter_names.add(arguments.vararg.arg)
        if arguments.kwarg is not None:
            parameter_names.add(arguments.kwarg.arg)
        self._block(self.method.node.body, _State(assigned=parameter_names))
        return _MethodFacts(
            tuple(
                sorted(
                    set(self.calls),
                    key=lambda call: (
                        call.line,
                        call.target,
                        call.constructor_line or 0,
                        call.request_reads,
                    ),
                )
            ),
            self.reads_at_line,
            tuple(sorted(self.gaps)),
        )

    def _expression(self, expression: ast.AST, state: _State) -> None:
        # Nested functions/lambdas are not executed by the enclosing method.
        calls: list[ast.Call] = []

        def visit(node: ast.AST) -> None:
            if isinstance(
                node, (ast.Lambda, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                return
            if (
                self.request_self
                and isinstance(node, ast.Attribute)
                and isinstance(node.ctx, ast.Load)
                and isinstance(node.value, ast.Name)
                and node.value.id == "self"
                and node.attr in _REQUEST_ATTRIBUTES
            ):
                read = (node.lineno, node.attr)
                if read not in state.reads:
                    state.reads.append(read)
            if isinstance(node, ast.Call):
                calls.append(node)
            for child in ast.iter_child_nodes(node):
                visit(child)

        visit(expression)
        for node in sorted(
            calls,
            key=lambda item: (item.lineno, item.col_offset),
        ):
            self._call(node, state)

    def _call(self, node: ast.Call, state: _State) -> None:
        func = node.func
        if (
            isinstance(func, ast.Call)
            and isinstance(func.func, ast.Name)
            and func.func.id == "getattr"
        ):
            self.gaps.add("HTTP_DYNAMIC_DISPATCH_UNRESOLVED")
            return
        if not isinstance(func, ast.Attribute) or not isinstance(func.value, ast.Name):
            return
        receiver = func.value.id
        target_class: str
        constructor_line: int | None = None
        constructor_symbol: str | None = None
        if receiver == "self":
            if not _is_request_self(self.method):
                return
            target_class = self.method.class_name
        else:
            binding = state.instances.get(receiver)
            if binding == "BRANCH":
                self.gaps.add("HTTP_BRANCH_ASSIGNMENT_UNRESOLVED")
                return
            if binding == "REASSIGNED":
                self.gaps.add("HTTP_LOCAL_REASSIGNED")
                return
            if not isinstance(binding, _Instance):
                return
            if state.branch[: len(binding.branch)] != binding.branch:
                self.gaps.add("HTTP_BRANCH_ASSIGNMENT_UNRESOLVED")
                return
            target_class = binding.class_name
            constructor_line = binding.constructor_line
            constructor_symbol = target_class
        target = self.module.methods.get((target_class, func.attr))
        if target is None:
            # Inherited stdlib response helpers are outside this local graph.
            if receiver != "self" or target_class not in self.module.handler_classes:
                self.gaps.add("HTTP_LOCAL_METHOD_UNRESOLVED")
            return
        self.calls.append(
            _Call(
                target.key,
                node.lineno,
                constructor_line,
                constructor_symbol,
                tuple(sorted(state.reads)),
                receiver == "self",
            )
        )

    def _bind(self, target: ast.expr, value: ast.expr | None, state: _State) -> None:
        if not isinstance(target, ast.Name):
            return
        name = target.id
        if name in state.assigned:
            state.instances[name] = "REASSIGNED"
            return
        state.assigned.add(name)
        if (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id in self.module.classes
        ):
            if value.func.id in state.assigned:
                self.gaps.add("HTTP_LOCAL_CLASS_SHADOWED")
                state.instances.pop(name, None)
                return
            state.instances[name] = _Instance(value.func.id, value.lineno, state.branch)
        else:
            state.instances.pop(name, None)

    def _block(self, statements: Sequence[ast.stmt], state: _State) -> bool:
        for statement in statements:
            if isinstance(statement, ast.If):
                self._expression(statement.test, state)
                self.reads_at_line[statement.lineno] = tuple(sorted(state.reads))
                body_continues = self._block(
                    statement.body, state.fork((statement.lineno, 0))
                )
                else_continues = self._block(
                    statement.orelse, state.fork((statement.lineno, 1))
                )
                for name in _assigned_in_block((*statement.body, *statement.orelse)):
                    state.instances[name] = "BRANCH"
                    state.assigned.add(name)
                if not body_continues and not else_continues:
                    return False
                continue
            if isinstance(
                statement,
                (
                    ast.For,
                    ast.AsyncFor,
                    ast.While,
                    ast.Try,
                    ast.Match,
                    ast.With,
                    ast.AsyncWith,
                ),
            ):
                # Calls inside a structured branch can be shown; assignments
                # leaving it have no unique branch-local constructor identity.
                for child in ast.iter_child_nodes(statement):
                    if isinstance(child, ast.expr):
                        self._expression(child, state)
                    elif isinstance(child, list):
                        pass
                for index, block in enumerate(_statement_blocks(statement)):
                    self._block(block, state.fork((statement.lineno, index)))
                for name in _bound_names(statement):
                    state.instances[name] = "BRANCH"
                    state.assigned.add(name)
                continue
            if isinstance(
                statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                continue
            if isinstance(statement, ast.Assign):
                self._expression(statement.value, state)
                for target in statement.targets:
                    self._bind(target, statement.value, state)
            elif isinstance(statement, ast.AnnAssign):
                if statement.value is not None:
                    self._expression(statement.value, state)
                self._bind(statement.target, statement.value, state)
            elif isinstance(statement, ast.AugAssign):
                self._expression(statement.value, state)
                self._bind(statement.target, None, state)
            else:
                self._expression(statement, state)
            self.reads_at_line[statement.lineno] = tuple(sorted(state.reads))
            if isinstance(statement, (ast.Return, ast.Raise)):
                return False
        return True


def _statement_blocks(statement: ast.stmt) -> tuple[list[ast.stmt], ...]:
    blocks: list[list[ast.stmt]] = []
    for name in ("body", "orelse", "finalbody"):
        value = getattr(statement, name, None)
        if isinstance(value, list):
            blocks.append([item for item in value if isinstance(item, ast.stmt)])
    if isinstance(statement, ast.Try):
        blocks.extend(handler.body for handler in statement.handlers)
    if isinstance(statement, ast.Match):
        blocks.extend(case.body for case in statement.cases)
    return tuple(blocks)


def _step(
    method: _Method, role: str, line: int, symbol: str, **extra: object
) -> dict[str, object]:
    return {
        "role": role,
        "path": method.path,
        "line": line,
        "end_line": line,
        "symbol": symbol,
        "source_sha256": method.source_sha256,
        **extra,
    }


def verified_http_paths(
    workspace: Path,
    tracked_hashes: Mapping[str, str],
    surface: AttackSurface,
    *,
    max_hops: int = 6,
    max_paths: int = 4,
) -> CandidateCallPaths:
    """Find bounded HTTP-handler paths to one indexed surface, or explain gaps.

    All interpreted Python files must be present in ``tracked_hashes`` and
    byte-match their indexed SHA-256.  The resulting path is syntax context,
    never a taint or vulnerability finding.
    """

    if max_hops < 1 or max_paths < 1:
        raise ValueError("HTTP_PATH_BOUND_INVALID")
    hop_limit = min(max_hops, _MAX_HOPS)
    path_limit = min(max_paths, _MAX_PATHS)
    if surface.path not in tracked_hashes:
        return CandidateCallPaths("PARTIAL", (), ("HTTP_SURFACE_SOURCE_NOT_TRACKED",))
    tracked_python = sorted(path for path in tracked_hashes if path.endswith(".py"))
    if len(tracked_python) > _MAX_SCAN_FILES:
        return CandidateCallPaths("PARTIAL", (), ("HTTP_SCAN_FILE_LIMIT",))
    modules: dict[str, _Module] = {}
    gaps: set[str] = set()
    for path in tracked_python:
        digest = tracked_hashes[path]
        raw = _source(workspace, path, digest)
        try:
            tree = ast.parse(raw.decode("utf-8"), filename=path)
        except (SyntaxError, UnicodeError, RecursionError):
            gaps.add("HTTP_SOURCE_PARSE_ERROR")
            continue
        modules[path] = _module(path, digest, tree)
    methods: dict[tuple[str, str, str], _Method] = {}
    facts: dict[tuple[str, str, str], _MethodFacts] = {}
    request_self_methods: set[tuple[str, str, str]] = set()
    entries: list[tuple[_Method, int]] = []
    for module in modules.values():
        gaps.update(module.gaps)
        for method in module.methods.values():
            methods[method.key] = method
            is_handler_method = method.class_name in module.handler_classes
            is_route_method = (
                is_handler_method
                and _VERB_METHOD.fullmatch(method.node.name) is not None
            )
            request_self = is_handler_method and _is_request_self(method)
            if is_route_method and not request_self:
                gaps.add(
                    "HTTP_REQUEST_SELF_REBOUND"
                    if "self" in _assigned_in_block(method.node.body)
                    else "HTTP_REQUEST_SELF_UNPROVEN"
                )
            if request_self:
                request_self_methods.add(method.key)
            if is_route_method and request_self:
                entries.append((method, module.handler_import_lines[method.class_name]))
            facts[method.key] = _MethodAnalyzer(
                module, method, request_self=request_self
            ).analyze()
    if not entries:
        gaps.add(
            "HTTP_HANDLER_IMPORT_UNPROVEN"
            if not any(module.handler_classes for module in modules.values())
            else "HTTP_ROUTE_METHOD_UNPROVEN"
        )
        return CandidateCallPaths("PARTIAL", (), tuple(sorted(gaps)))
    sink_candidates = [
        method
        for method in methods.values()
        if method.path == surface.path
        and method.node.lineno
        <= surface.line
        <= (method.node.end_lineno or method.node.lineno)
    ]
    if len(sink_candidates) != 1:
        gaps.add("HTTP_SURFACE_METHOD_UNRESOLVED")
        return CandidateCallPaths("PARTIAL", (), tuple(sorted(gaps)))
    sink = sink_candidates[0]
    paths: list[dict[str, object]] = []

    def walk(
        entry: _Method,
        current: _Method,
        steps: list[dict[str, object]],
        reads: tuple[_ReadSite, ...],
        visited: frozenset[tuple[str, str, str]],
        hops: int,
        trusted_request_self: bool,
    ) -> None:
        if len(paths) > path_limit:
            return
        gaps.update(facts[current.key].gaps)
        if current.key == sink.key:
            selected_reads = reads
            if trusted_request_self:
                selected_reads += tuple(
                    (current.key, line, attr)
                    for line, attr in facts[current.key].reads_at_line.get(
                        surface.line, ()
                    )
                )
            if not selected_reads:
                gaps.add("HTTP_REQUEST_INPUT_UNPROVEN")
            context = [
                _step(
                    methods[key],
                    "REQUEST_CONTEXT",
                    line,
                    methods[key].symbol,
                    request_attribute=attr,
                )
                for key, line, attr in dict.fromkeys(selected_reads)
            ]
            path_steps = [steps[0], *context, *steps[1:]]
            path_steps.append(_step(sink, "SINK", surface.line, sink.symbol))
            paths.append(
                {
                    "kind": "stdlib_http_call_path_v5",
                    "provenance": "python_syntax",
                    "assurance": "SYNTACTIC_REACHABILITY",
                    "status": "AVAILABLE" if selected_reads else "PARTIAL",
                    "steps": path_steps,
                    "gaps": [] if selected_reads else ["HTTP_REQUEST_INPUT_UNPROVEN"],
                }
            )
        for call in facts[current.key].calls:
            if len(paths) > path_limit:
                break
            target = methods.get(call.target)
            if target is None:
                gaps.add("HTTP_LOCAL_METHOD_UNRESOLVED")
                continue
            if target.key in visited:
                gaps.add("HTTP_CALL_CYCLE")
                continue
            if hops >= hop_limit:
                gaps.add("HTTP_HOP_LIMIT")
                continue
            next_steps = list(steps)
            if (
                call.constructor_line is not None
                and call.constructor_symbol is not None
            ):
                next_steps.append(
                    _step(
                        current,
                        "CALL",
                        call.constructor_line,
                        call.constructor_symbol,
                        call_kind="LOCAL_CONSTRUCTOR",
                    )
                )
            next_steps.append(_step(current, "CALL", call.line, target.symbol))
            next_reads = reads
            if trusted_request_self:
                next_reads += tuple(
                    (current.key, line, attr) for line, attr in call.request_reads
                )
            walk(
                entry,
                target,
                next_steps,
                next_reads,
                visited | {target.key},
                hops + 1,
                trusted_request_self
                and call.receiver_is_self
                and target.key in request_self_methods,
            )

    for entry, import_line in sorted(entries, key=lambda item: item[0].key):
        if len(paths) > path_limit:
            break
        route = _step(
            entry,
            "ROUTE_ENTRY",
            entry.node.lineno,
            entry.symbol,
            stdlib_handler="http.server.BaseHTTPRequestHandler",
            import_line=import_line,
        )
        walk(entry, entry, [route], (), frozenset({entry.key}), 0, True)
    if len(paths) > path_limit:
        gaps.add("HTTP_PATH_LIMIT")
    selected = tuple(paths[:path_limit])
    if not selected:
        gaps.add("HTTP_ROUTE_TO_SURFACE_UNAVAILABLE")
    frozen_gaps = tuple(sorted(gaps))
    return CandidateCallPaths(
        "AVAILABLE" if selected and not frozen_gaps else "PARTIAL",
        selected,
        frozen_gaps,
    )
