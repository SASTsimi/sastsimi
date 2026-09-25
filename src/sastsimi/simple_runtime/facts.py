"""Route-to-call flows, extracted from the syntax tree without a vocabulary.

The design's static fact layer gives the hypothesis agent routes, flows and
defence candidates rather than raw code.  Deciding which calls are sinks or
sanitizers by name is a list someone wrote, and a list misses what it was not
written for, so nothing here is named in advance:

* an entry point is a function decorated by a call whose attribute is a known
  routing verb (``get``, ``post``, ``api_route``, ``websocket``, ``on`` ...);
* its parameters, less those filled by dependency injection, are input;
* input spreads through assignments, f-strings, attribute access and calls;
* every call that receives input is a step of the flow, and a step whose
  callee is defined in this repository is marked as such - that is where a
  guard or a transformation lives, and the agent is pointed at it.

Which step is a sink and whether a guard holds is the agent's judgement.  The
flow stays within the handler; where it enters a repository function, that
function's location is given so the agent can ask for it.
"""

from __future__ import annotations

import ast
import warnings
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_ROUTE_VERBS = frozenset(
    {
        "route",
        "api_route",
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "options",
        "head",
        "websocket",
        "websocket_route",
        "api_websocket_route",
        "on",
        "event",
    }
)


@dataclass
class Step:
    line: int
    call: str
    arguments: list[str]
    defined_at: list[str] = field(default_factory=list)
    result_to: str | None = None

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "line": self.line,
            "call": self.call,
            "input_arguments": self.arguments,
        }
        if self.defined_at:
            value["defined_in_repository_at"] = self.defined_at
        if self.result_to:
            value["result_assigned_to"] = self.result_to
        return value


def _name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return _name(node.func)
    return None


def _names_in(node: ast.AST) -> set[str]:
    found: set[str] = set()
    for item in ast.walk(node):
        if isinstance(item, ast.Name):
            found.add(item.id)
    return found


def _route_of(decorator: ast.expr) -> dict[str, Any] | None:
    if not isinstance(decorator, ast.Call):
        return None
    verb = decorator.func.attr if isinstance(decorator.func, ast.Attribute) else None
    if verb is None or verb.lower() not in _ROUTE_VERBS:
        return None
    path: str | None = None
    if decorator.args and isinstance(decorator.args[0], ast.Constant):
        value = decorator.args[0].value
        path = value if isinstance(value, str) else None
    methods: list[str] = []
    dependencies: list[str] = []
    for keyword in decorator.keywords:
        if keyword.arg == "dependencies":
            dependencies.append(ast.unparse(keyword.value))
        if keyword.arg == "methods":
            if isinstance(keyword.value, (ast.List, ast.Tuple, ast.Set)):
                methods = [
                    str(item.value)
                    for item in keyword.value.elts
                    if isinstance(item, ast.Constant)
                ]
            else:
                methods = [ast.unparse(keyword.value)]
    return {
        "verb": verb,
        "path": path,
        "methods": methods or [verb.upper()],
        "router": _name(decorator.func.value)
        if isinstance(decorator.func, ast.Attribute)
        else None,
        **({"dependencies": dependencies} if dependencies else {}),
    }


def _injected(argument: ast.arg, default: ast.expr | None) -> bool:
    """A parameter the framework fills from the server side, not the request."""

    return isinstance(default, ast.Call) and _name(default.func) in (
        "Depends",
        "Security",
    )


class _FlowTracer(ast.NodeVisitor):
    """Follow input through one handler body, in source order."""

    def __init__(self, tainted: set[str], defined: dict[str, list[str]]) -> None:
        self.tainted = set(tainted)
        self.defined = defined
        self.steps: list[Step] = []
        self._seen: set[tuple[int, str]] = set()

    def _is_tainted(self, node: ast.AST) -> bool:
        return bool(_names_in(node) & self.tainted)

    def _calls(self, node: ast.AST, result_to: str | None) -> None:
        for item in ast.walk(node):
            if not isinstance(item, ast.Call):
                continue
            inputs = [
                ast.unparse(argument)
                for argument in [*item.args, *(k.value for k in item.keywords)]
                if self._is_tainted(argument)
            ]
            receiver_tainted = isinstance(item.func, ast.Attribute) and (
                self._is_tainted(item.func.value)
            )
            if not inputs and not receiver_tainted:
                continue
            call = _name(item.func) or ast.unparse(item.func)
            key = (item.lineno, call)
            if key in self._seen:
                continue
            self._seen.add(key)
            self.steps.append(
                Step(
                    line=item.lineno,
                    call=call,
                    arguments=inputs or [ast.unparse(item.func.value)],  # type: ignore[attr-defined]
                    defined_at=self._repository_definition(call),
                    result_to=result_to
                    if item is node or _outermost(node) is item
                    else None,
                )
            )

    def _repository_definition(self, call: str) -> list[str]:
        """Where a call's callee is defined in this repository, if it plainly is.

        Matching the last segment alone tied ``connection.get`` on a dict to
        every ``get`` method in the repository.  Only a bare function name, a
        ``self``/``cls`` method or a method named on a class (capitalised) is
        resolved; a method on an object value is left unresolved.
        """

        parts = call.split(".")
        if len(parts) == 1 or parts[0] in ("self", "cls") or parts[-2][:1].isupper():
            return self.defined.get(parts[-1], [])[:5]
        return []

    def _assign(self, targets: Iterable[ast.AST], value: ast.AST | None) -> None:
        if value is None:
            return
        names = [name for target in targets for name in _names_in(target)]
        self._calls(value, ", ".join(names) or None)
        if self._is_tainted(value):
            self.tainted.update(names)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._assign(node.targets, node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._assign([node.target], node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self._assign([node.target], node.value)

    def visit_For(self, node: ast.For) -> None:
        self._assign([node.target], node.iter)
        for statement in [*node.body, *node.orelse]:
            self.visit(statement)

    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        self._assign([node.target], node.iter)
        for statement in [*node.body, *node.orelse]:
            self.visit(statement)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            if item.optional_vars is not None:
                self._assign([item.optional_vars], item.context_expr)
            else:
                self._calls(item.context_expr, None)
        for statement in node.body:
            self.visit(statement)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        for item in node.items:
            if item.optional_vars is not None:
                self._assign([item.optional_vars], item.context_expr)
            else:
                self._calls(item.context_expr, None)
        for statement in node.body:
            self.visit(statement)

    def visit_Expr(self, node: ast.Expr) -> None:
        self._calls(node.value, None)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value is not None:
            self._calls(node.value, "return")

    def visit_If(self, node: ast.If) -> None:
        self._calls(node.test, None)
        for statement in [*node.body, *node.orelse]:
            self.visit(statement)

    def visit_While(self, node: ast.While) -> None:
        self._calls(node.test, None)
        for statement in [*node.body, *node.orelse]:
            self.visit(statement)

    def visit_Try(self, node: ast.Try) -> None:
        for statement in [*node.body, *node.orelse, *node.finalbody]:
            self.visit(statement)
        for handler in node.handlers:
            for statement in handler.body:
                self.visit(statement)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        # A nested function closes over the same input.
        for statement in node.body:
            self.visit(statement)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        for statement in node.body:
            self.visit(statement)


def _outermost(node: ast.AST) -> ast.AST | None:
    while isinstance(node, (ast.Await, ast.Starred)):
        node = node.value
    return node


def _router_dependencies(tree: ast.Module) -> dict[str, str]:
    """``router = APIRouter(dependencies=[...])``: guards on every route of it."""

    found: dict[str, str] = {}
    for node in tree.body:
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        for keyword in node.value.keywords:
            if keyword.arg == "dependencies":
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        found[target.id] = ast.unparse(keyword.value)
    return found


def _parse(path: Path) -> ast.Module | None:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, UnicodeError, SyntaxError, ValueError, RecursionError):
        return None


def extract_flows(workspace: Path, sources: Sequence[str]) -> dict[str, Any]:
    """Every entry point in the checkout and the calls its input reaches."""

    python = [path for path in sources if path.endswith(".py")]
    trees: dict[str, ast.Module] = {}
    unparsed: list[str] = []
    for path in python:
        tree = _parse(workspace / path)
        if tree is None:
            unparsed.append(path)
        else:
            trees[path] = tree
    defined: dict[str, list[str]] = {}
    for path, tree in trees.items():
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                defined.setdefault(node.name, []).append(f"{path}:{node.lineno}")
    entries: list[dict[str, Any]] = []
    for path, tree in trees.items():
        router_guards = _router_dependencies(tree)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            routes = [r for r in map(_route_of, node.decorator_list) if r]
            if not routes:
                continue
            arguments = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
            defaults: list[ast.expr | None] = (
                [None]
                * (
                    len(node.args.posonlyargs)
                    + len(node.args.args)
                    - len(node.args.defaults)
                )
                + list(node.args.defaults)
                + list(node.args.kw_defaults)
            )
            inputs = [
                argument.arg
                for argument, default in zip(arguments, defaults, strict=False)
                if argument.arg not in ("self", "cls")
                and not _injected(argument, default)
            ]
            # What the framework fills in before the handler runs - where
            # authentication and permission checks usually are.
            injected = [
                {"parameter": argument.arg, "dependency": ast.unparse(default)}
                for argument, default in zip(arguments, defaults, strict=False)
                if default is not None and _injected(argument, default)
            ]
            for route in routes:
                guard = router_guards.get(str(route.get("router")))
                if guard:
                    route["router_dependencies"] = guard
            tracer = _FlowTracer(set(inputs), defined)
            for statement in node.body:
                tracer.visit(statement)
            entries.append(
                {
                    "file": path,
                    "line": node.lineno,
                    "handler": node.name,
                    "routes": routes,
                    "inputs": inputs,
                    **({"injected": injected} if injected else {}),
                    "steps": [
                        step.as_dict()
                        for step in sorted(tracer.steps, key=lambda s: s.line)
                    ],
                }
            )
    entries.sort(key=lambda entry: (entry["file"], entry["line"]))
    covered = {entry["file"] for entry in entries}
    return {
        "kind": "simple_route_flows",
        "entry_points": entries,
        "files_with_entry_points": len(covered),
        "python_files": len(python),
        "files_without_entry_points": sorted(set(trees) - covered),
        "unparsed_files": unparsed,
    }


__all__ = ["extract_flows"]
