"""Pure, conservative signals for process-local PoC fixture provenance."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from enum import StrEnum


class PocProvenanceStatus(StrEnum):
    UNVERIFIED_PROCESS_LOCAL_FIXTURE = "UNVERIFIED_PROCESS_LOCAL_FIXTURE"
    NO_LOCAL_FIXTURE_SIGNAL = "NO_LOCAL_FIXTURE_SIGNAL"
    UNKNOWN = "UNKNOWN"


class PocProvenanceEvidence(StrEnum):
    PROCESS_LOCAL_PICKLE_TEST_CLIENT = "PROCESS_LOCAL_PICKLE_TEST_CLIENT"
    PYTHON_AST_UNPARSEABLE = "PYTHON_AST_UNPARSEABLE"
    PYTHON_HEREDOC_INCOMPLETE = "PYTHON_HEREDOC_INCOMPLETE"
    RELEVANT_FLOW_UNRESOLVED = "RELEVANT_FLOW_UNRESOLVED"
    NONE = "NONE"


@dataclass(frozen=True, slots=True)
class PocProvenanceAssessment:
    status: PocProvenanceStatus
    evidence: PocProvenanceEvidence


_PYTHON_HEREDOC = re.compile(
    rb"(?:^|[ \t;])python(?:3(?:\.[0-9]+)?)?[ \t][^\n]*?<<(?P<tabs>-)?[ \t]*"
    rb"(?:'(?P<single>[A-Za-z_][A-Za-z_0-9]*)'|"
    rb'"(?P<double>[A-Za-z_][A-Za-z_0-9]*)"|'
    rb"(?P<bare>[A-Za-z_][A-Za-z_0-9]*))[ \t]*$"
)
_REQUEST_METHODS = frozenset(
    {"get", "post", "put", "patch", "delete", "open", "request"}
)


def _relevant(body: bytes) -> bool:
    return b"pickle" in body and any(
        marker in body for marker in (b"test_client", b"getattr", b"__getattribute__")
    )


def _python_bodies(content: bytes) -> tuple[tuple[bytes, ...], bool]:
    """Extract simple Python here-docs; report incomplete relevant input."""

    lines = content.splitlines()
    bodies: list[bytes] = []
    index = 0
    incomplete = False
    while index < len(lines):
        match = _PYTHON_HEREDOC.search(lines[index])
        if match is None:
            index += 1
            continue
        delimiter = next(
            value
            for value in (
                match.group("single"),
                match.group("double"),
                match.group("bare"),
            )
            if value is not None
        )
        strip_tabs = match.group("tabs") is not None
        start = index + 1
        index = start
        while index < len(lines):
            word = lines[index].lstrip(b"\t") if strip_tabs else lines[index]
            if word == delimiter:
                bodies.append(b"\n".join(lines[start:index]))
                break
            index += 1
        else:
            incomplete = incomplete or _relevant(b"\n".join(lines[start:]))
        index += 1
    return tuple(bodies), incomplete


def _pickle_names(tree: ast.AST) -> tuple[set[str], set[str]]:
    modules = {"pickle"}
    dumps: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(
                alias.asname or "pickle"
                for alias in node.names
                if alias.name == "pickle"
            )
        elif isinstance(node, ast.ImportFrom) and node.module == "pickle":
            dumps.update(
                alias.asname or "dumps" for alias in node.names if alias.name == "dumps"
            )
    return modules, dumps


def _importlib_names(tree: ast.AST) -> tuple[set[str], set[str]]:
    modules: set[str] = set()
    functions: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(
                alias.asname or "importlib"
                for alias in node.names
                if alias.name == "importlib"
            )
        elif isinstance(node, ast.ImportFrom) and node.module == "importlib":
            functions.update(
                alias.asname or "import_module"
                for alias in node.names
                if alias.name == "import_module"
            )
    return modules, functions


def _class_names(body: list[ast.stmt]) -> set[str]:
    """Names defined by the PoC, not classes imported from the repository."""

    names: set[str] = set()
    for statement in body:
        if isinstance(statement, ast.ClassDef):
            names.add(statement.name)
        elif isinstance(statement, (ast.If, ast.For, ast.While, ast.Try, ast.With)):
            for field in ("body", "orelse", "finalbody"):
                nested = getattr(statement, field, None)
                if isinstance(nested, list):
                    names.update(_class_names(nested))
    return names


def _shadows_builtin(tree: ast.Module, name: str) -> bool:
    return any(
        isinstance(node, ast.Name)
        and node.id == name
        and isinstance(node.ctx, (ast.Store, ast.Del))
        or isinstance(node, ast.arg)
        and node.arg == name
        or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and node.name == name
        or isinstance(node, ast.alias)
        and (node.asname or node.name.split(".", 1)[0]) == name
        for node in ast.walk(tree)
    )


def _trusted_os_aliases(tree: ast.Module) -> frozenset[str]:
    """Recognize one explicit top-level stdlib import without local rebinding."""

    candidates = {
        alias.asname or "os"
        for statement in tree.body
        if isinstance(statement, ast.Import)
        for alias in statement.names
        if alias.name == "os"
    }
    trusted: set[str] = set()
    for name in candidates:
        bindings = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.alias)
            and (node.asname or node.name.split(".", 1)[0]) == name
        ]
        if len(bindings) != 1 or bindings[0].name != "os":
            continue
        if any(
            isinstance(node, ast.Name)
            and node.id == name
            and isinstance(node.ctx, (ast.Store, ast.Del))
            or isinstance(node, ast.arg)
            and node.arg == name
            or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name == name
            or isinstance(node, ast.Attribute)
            and node.attr == "system"
            and isinstance(node.value, ast.Name)
            and node.value.id == name
            and isinstance(node.ctx, (ast.Store, ast.Del))
            or isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"setattr", "delattr"}
            and bool(node.args)
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == name
            or isinstance(node, ast.Attribute)
            and node.attr == "__dict__"
            and isinstance(node.value, ast.Name)
            and node.value.id == name
            or isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"vars", "getattr"}
            and bool(node.args)
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == name
            and (
                node.func.id == "vars"
                or len(node.args) >= 2
                and isinstance(node.args[1], ast.Constant)
                and node.args[1].value == "__dict__"
            )
            for node in ast.walk(tree)
        ):
            continue
        trusted.add(name)
    return frozenset(trusted)


def _portable_global_reducer(
    node: ast.ClassDef,
    *,
    os_aliases: frozenset[str],
) -> bool:
    """Recognize only a fixed stdlib command; eval may read PoC-local state."""

    if node.bases or node.keywords or node.decorator_list:
        return False
    methods = [
        statement
        for statement in node.body
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
        and statement.name in {"__reduce__", "__reduce_ex__"}
    ]
    if (
        len(methods) != 1
        or not isinstance(methods[0], ast.FunctionDef)
        or methods[0].name != "__reduce__"
        or methods[0].decorator_list
        or len(methods[0].args.args) != 1
        or methods[0].args.args[0].arg != "self"
        or methods[0].args.posonlyargs
        or methods[0].args.kwonlyargs
        or methods[0].args.vararg is not None
        or methods[0].args.kwarg is not None
    ):
        return False
    body = methods[0].body
    if len(body) != 1 or not isinstance(body[0], ast.Return):
        return False
    returned = body[0].value
    if not isinstance(returned, ast.Tuple) or len(returned.elts) != 2:
        return False
    callable_name, arguments = returned.elts
    if not isinstance(arguments, ast.Tuple) or len(arguments.elts) != 1:
        return False
    if (
        isinstance(callable_name, ast.Attribute)
        and callable_name.attr == "system"
        and isinstance(callable_name.value, ast.Name)
        and callable_name.value.id in os_aliases
    ):
        return isinstance(arguments.elts[0], ast.Constant) and isinstance(
            arguments.elts[0].value, str
        )
    return False


def _reducer_binding_mutated(tree: ast.Module) -> bool:
    """A static reducer is not proof if the PoC can replace it later."""

    methods = {"__reduce__", "__reduce_ex__"}
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and node.attr in methods
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ):
            return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"setattr", "delattr"}
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in methods
        ):
            return True
    return False


class _ScopeScanner(ast.NodeVisitor):
    def __init__(
        self,
        *,
        local_classes: set[str],
        pickle_modules: set[str],
        pickle_dumps: set[str],
        importlib_modules: set[str],
        import_module_functions: set[str],
        str_shadowed: bool,
        local_functions: set[str],
        inherited_class_aliases: set[str] | None = None,
        inherited_class_alias_targets: dict[str, str] | None = None,
        inherited_dumps_aliases: set[str] | None = None,
        inherited_safe_values: set[str] | None = None,
        inherited_opaque_constructors: set[str] | None = None,
        class_serialized_fields: set[tuple[str, str]] | None = None,
        inherited_dynamic_pickle_modules: set[str] | None = None,
    ) -> None:
        self.pickle_modules = pickle_modules
        self.importlib_modules = importlib_modules
        self.import_module_functions = import_module_functions
        self.dynamic_pickle_modules = set(inherited_dynamic_pickle_modules or ())
        self.class_aliases = set(local_classes) | (inherited_class_aliases or set())
        self.class_alias_targets = {name: name for name in local_classes}
        self.class_alias_targets.update(inherited_class_alias_targets or {})
        self.dumps_aliases = set(pickle_dumps) | (inherited_dumps_aliases or set())
        self.safe_values = set(inherited_safe_values or ())
        self.opaque_constructors = set(inherited_opaque_constructors or ())
        self.class_serialized_fields = class_serialized_fields or set()
        self.str_shadowed = str_shadowed
        self.local_functions = local_functions
        self.instances: set[str] = set()
        self.serialized: set[str] = set()
        self.clients: set[str] = set()
        self.sent_clients: set[str] = set()
        self.process_local_serialization = False
        self.unresolved_serialization = False
        self.found = False

    def _local_instance(self, value: ast.AST) -> bool:
        pending = [value]
        while pending:
            node = pending.pop()
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id == "str" and not self.str_shadowed:
                    continue  # A string conversion cannot retain the PoC-only class.
                if node.func.id in self.class_aliases:
                    return True
            if isinstance(node, ast.Name) and node.id in self.instances:
                return True
            pending.extend(ast.iter_child_nodes(node))
        return False

    def _pickle_dumps(self, call: ast.Call) -> bool:
        return self._pickle_dumps_callable(call.func)

    def _pickle_dumps_callable(self, func: ast.AST) -> bool:
        return (
            isinstance(func, ast.Attribute)
            and func.attr == "dumps"
            and isinstance(func.value, ast.Name)
            and func.value.id in self.pickle_modules | self.dynamic_pickle_modules
            or isinstance(func, ast.Name)
            and func.id in self.dumps_aliases
        )

    def _literal_pickle_module(self, value: ast.AST) -> bool:
        if (
            not isinstance(value, ast.Call)
            or len(value.args) != 1
            or value.keywords
            or not isinstance(value.args[0], ast.Constant)
            or value.args[0].value != "pickle"
        ):
            return False
        func = value.func
        return (
            isinstance(func, ast.Attribute)
            and func.attr == "import_module"
            and isinstance(func.value, ast.Name)
            and func.value.id in self.importlib_modules
            or isinstance(func, ast.Name)
            and func.id in self.import_module_functions
        )

    def _known_safe_value(self, value: ast.AST) -> bool:
        if isinstance(value, (ast.Constant, ast.JoinedStr)):
            return True
        if isinstance(value, ast.Name):
            return value.id in self.safe_values
        if isinstance(value, (ast.Tuple, ast.List, ast.Set)):
            return all(self._known_safe_value(item) for item in value.elts)
        if isinstance(value, ast.Dict):
            return all(
                key is not None
                and self._known_safe_value(key)
                and self._known_safe_value(item)
                for key, item in zip(value.keys, value.values, strict=True)
            )
        return (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "str"
            and not self.str_shadowed
        )

    def _inspect_pickle_call(self, call: ast.Call) -> bool:
        if not self._pickle_dumps(call):
            return False
        if not call.args:
            self.unresolved_serialization |= bool(self.class_aliases)
            return False
        local = self._local_instance(call.args[0])
        self.process_local_serialization |= local
        # A value returned by an opaque factory (or selected from a registry)
        # may be a class created only inside this PoC. Without a resolved
        # importable class, a same-process client is not independent proof.
        opaque_instance = any(
            isinstance(node, ast.Call)
            and (
                isinstance(node.func, ast.Name)
                and (
                    node.func.id in self.opaque_constructors
                    or node.func.id in self.local_functions
                    or node.func.id == "type"
                    and len(node.args) >= 3
                    or node.func.id in {"new_class", "make_dataclass"}
                )
                or isinstance(node.func, ast.Call)
                or isinstance(node.func, ast.Attribute)
                and (
                    isinstance(node.func.value, ast.Call)
                    or node.func.attr in {"new_class", "make_dataclass"}
                )
            )
            for node in ast.walk(call.args[0])
        )
        self.unresolved_serialization |= (
            (bool(self.class_aliases) or opaque_instance)
            and not local
            and not self._known_safe_value(call.args[0])
        )
        return local

    def _serialized_value(self, value: ast.AST) -> bool:
        if isinstance(value, ast.Name):
            return value.id in self.serialized
        if (
            isinstance(value, ast.Attribute)
            and isinstance(value.value, ast.Name)
            and (
                self.class_alias_targets.get(value.value.id),
                value.attr,
            )
            in self.class_serialized_fields
        ):
            return True
        if not isinstance(value, ast.Call):
            return False
        if self._pickle_dumps(value):
            return self._inspect_pickle_call(value)
        func = value.func
        if isinstance(func, ast.Attribute):
            if func.attr in {"decode", "encode", "hex"}:
                return self._serialized_value(func.value)
            if (
                func.attr in {"b64encode", "urlsafe_b64encode"}
                and isinstance(func.value, ast.Name)
                and func.value.id == "base64"
                and value.args
            ):
                return self._serialized_value(value.args[0])
        if (
            isinstance(func, ast.Name)
            and func.id in {"str", "bytes", "b64encode", "urlsafe_b64encode"}
            and value.args
        ):
            return self._serialized_value(value.args[0])
        return False

    def _test_client(self, value: ast.AST) -> bool:
        return (
            isinstance(value, ast.Name)
            and value.id in self.clients
            or isinstance(value, ast.Call)
            and isinstance(value.func, ast.Attribute)
            and value.func.attr == "test_client"
        )

    def _assign(self, target: ast.AST, value: ast.AST) -> None:
        if isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
            owner = self.class_alias_targets.get(target.value.id)
            if owner is not None:
                field = (owner, target.attr)
                if self._serialized_value(value):
                    self.class_serialized_fields.add(field)
                elif self._known_safe_value(value) or (
                    isinstance(value, ast.Call)
                    and self._pickle_dumps(value)
                    and bool(value.args)
                    and self._known_safe_value(value.args[0])
                ):
                    self.class_serialized_fields.discard(field)
            return
        if not isinstance(target, ast.Name):
            return
        class_alias = isinstance(value, ast.Name) and value.id in self.class_aliases
        dynamic_pickle_module = self._literal_pickle_module(value) or (
            isinstance(value, ast.Name) and value.id in self.dynamic_pickle_modules
        )
        dumps_alias = self._pickle_dumps_callable(value)
        known_safe = self._known_safe_value(value)
        opaque_constructor = (
            isinstance(value, ast.Name)
            and value.id in self.opaque_constructors
            or isinstance(value, ast.Subscript)
            or isinstance(value, ast.Call)
            and not self._pickle_dumps(value)
            and not self._test_client(value)
            and not known_safe
        )
        local_instance = self._local_instance(value)
        serialized = self._serialized_value(value)
        test_client = self._test_client(value)
        sent_client = isinstance(value, ast.Name) and value.id in self.sent_clients
        if local_instance:
            self.instances.add(target.id)
        else:
            self.instances.discard(target.id)
        if serialized:
            self.serialized.add(target.id)
        else:
            self.serialized.discard(target.id)
        if test_client:
            self.clients.add(target.id)
        else:
            self.clients.discard(target.id)
        if sent_client:
            self.sent_clients.add(target.id)
        else:
            self.sent_clients.discard(target.id)
        if class_alias:
            self.class_aliases.add(target.id)
            if isinstance(value, ast.Name):
                origin = self.class_alias_targets.get(value.id)
                if origin is not None:
                    self.class_alias_targets[target.id] = origin
        else:
            self.class_aliases.discard(target.id)
            self.class_alias_targets.pop(target.id, None)
        if dynamic_pickle_module:
            self.dynamic_pickle_modules.add(target.id)
        else:
            self.dynamic_pickle_modules.discard(target.id)
        if dumps_alias:
            self.dumps_aliases.add(target.id)
        else:
            self.dumps_aliases.discard(target.id)
        if known_safe:
            self.safe_values.add(target.id)
        else:
            self.safe_values.discard(target.id)
        if opaque_constructor:
            self.opaque_constructors.add(target.id)
        else:
            self.opaque_constructors.discard(target.id)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        for target in node.targets:
            self._assign(target, node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
            self._assign(node.target, node.value)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars is not None:
                self._assign(item.optional_vars, item.context_expr)
        for statement in node.body:
            self.visit(statement)

    def visit_Call(self, node: ast.Call) -> None:
        self._inspect_pickle_call(node)
        func = node.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            receiver = func.value.id
            if (
                func.attr == "set_cookie"
                and receiver in self.clients
                and (
                    any(self._serialized_value(arg) for arg in node.args[1:])
                    or any(
                        keyword.arg == "value" and self._serialized_value(keyword.value)
                        for keyword in node.keywords
                    )
                )
            ):
                self.sent_clients.add(receiver)
            elif func.attr in _REQUEST_METHODS and receiver in self.sent_clients:
                self.found = True
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        return  # A separate scanner analyses each function's local bindings.

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        return


def _assess_python(tree: ast.Module) -> PocProvenanceStatus:
    modules, dumps = _pickle_names(tree)
    importlib_modules, import_module_functions = _importlib_names(tree)
    local_functions = {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    str_shadowed = _shadows_builtin(tree, "str")
    os_aliases = _trusted_os_aliases(tree)
    definitions = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    portable_classes = (
        {
            name
            for name in {node.name for node in definitions}
            if all(
                _portable_global_reducer(
                    node,
                    os_aliases=os_aliases,
                )
                for node in definitions
                if node.name == name
            )
        }
        if not _reducer_binding_mutated(tree)
        else set()
    )
    global_classes = _class_names(tree.body)
    class_serialized_fields: set[tuple[str, str]] = set()
    for definition in definitions:
        scanner = _ScopeScanner(
            local_classes=global_classes - portable_classes,
            pickle_modules=modules,
            pickle_dumps=dumps,
            importlib_modules=importlib_modules,
            import_module_functions=import_module_functions,
            str_shadowed=str_shadowed,
            local_functions=local_functions,
        )
        for statement in definition.body:
            scanner.visit(statement)
        class_serialized_fields.update(
            (definition.name, name) for name in scanner.serialized
        )
    global_scanner = _ScopeScanner(
        local_classes=global_classes - portable_classes,
        pickle_modules=modules,
        pickle_dumps=dumps,
        importlib_modules=importlib_modules,
        import_module_functions=import_module_functions,
        str_shadowed=str_shadowed,
        local_functions=local_functions,
        class_serialized_fields=class_serialized_fields,
    )
    for statement in tree.body:
        global_scanner.visit(statement)
    if global_scanner.found:
        return PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
    unresolved = (
        global_scanner.process_local_serialization
        or global_scanner.unresolved_serialization
    )
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        scanner = _ScopeScanner(
            local_classes=(global_classes | _class_names(node.body)) - portable_classes,
            pickle_modules=modules,
            pickle_dumps=dumps,
            importlib_modules=importlib_modules,
            import_module_functions=import_module_functions,
            str_shadowed=str_shadowed,
            local_functions=local_functions,
            inherited_class_aliases=global_scanner.class_aliases,
            inherited_class_alias_targets=global_scanner.class_alias_targets,
            inherited_dumps_aliases=global_scanner.dumps_aliases,
            inherited_safe_values=global_scanner.safe_values,
            inherited_opaque_constructors=global_scanner.opaque_constructors,
            class_serialized_fields=class_serialized_fields,
            inherited_dynamic_pickle_modules=global_scanner.dynamic_pickle_modules,
        )
        for statement in node.body:
            scanner.visit(statement)
        if scanner.found:
            return PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE
        unresolved = (
            unresolved
            or scanner.process_local_serialization
            or scanner.unresolved_serialization
        )
    has_possible_test_client = any(
        isinstance(node, ast.Call)
        and (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in {"test_client", "__getattribute__"}
            or isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
        )
        or isinstance(node, ast.Name)
        and node.id == "getattr"
        for node in ast.walk(tree)
    )
    return (
        PocProvenanceStatus.UNKNOWN
        if unresolved and has_possible_test_client
        else PocProvenanceStatus.NO_LOCAL_FIXTURE_SIGNAL
    )


def assess_poc_provenance(content: bytes) -> PocProvenanceAssessment:
    """Return only an evidence type, never source, fixture data, or identifiers."""

    bodies, incomplete = _python_bodies(content)
    if incomplete:
        return PocProvenanceAssessment(
            PocProvenanceStatus.UNKNOWN,
            PocProvenanceEvidence.PYTHON_HEREDOC_INCOMPLETE,
        )
    if not bodies and _relevant(content):
        return PocProvenanceAssessment(
            PocProvenanceStatus.UNKNOWN,
            PocProvenanceEvidence.RELEVANT_FLOW_UNRESOLVED,
        )
    unknown = False
    for body in bodies:
        if not _relevant(body):
            continue
        try:
            tree = ast.parse(body.decode("utf-8"))
        except (SyntaxError, UnicodeError):
            return PocProvenanceAssessment(
                PocProvenanceStatus.UNKNOWN,
                PocProvenanceEvidence.PYTHON_AST_UNPARSEABLE,
            )
        status = _assess_python(tree)
        if status is PocProvenanceStatus.UNVERIFIED_PROCESS_LOCAL_FIXTURE:
            return PocProvenanceAssessment(
                status,
                PocProvenanceEvidence.PROCESS_LOCAL_PICKLE_TEST_CLIENT,
            )
        unknown = unknown or status is PocProvenanceStatus.UNKNOWN
    if unknown:
        return PocProvenanceAssessment(
            PocProvenanceStatus.UNKNOWN,
            PocProvenanceEvidence.RELEVANT_FLOW_UNRESOLVED,
        )
    return PocProvenanceAssessment(
        PocProvenanceStatus.NO_LOCAL_FIXTURE_SIGNAL,
        PocProvenanceEvidence.NONE,
    )


__all__ = [
    "PocProvenanceAssessment",
    "PocProvenanceEvidence",
    "PocProvenanceStatus",
    "assess_poc_provenance",
]
