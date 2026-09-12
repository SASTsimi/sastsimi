import ast
import importlib.util
from enum import Enum, auto
from pathlib import Path

import pytest

# Baseline §6 / ADR-016. Same-package imports are allowed. Root entrypoint,
# composition root and standalone logging are explicit foundation exceptions.
RULES: dict[str, frozenset[str]] = {
    "__init__": frozenset(),
    "__main__": frozenset({"interfaces"}),
    "contracts": frozenset(),
    "ports": frozenset({"contracts"}),
    "config": frozenset({"contracts"}),
    "prompts": frozenset({"contracts", "ports", "config"}),
    "agents": frozenset({"contracts", "ports", "prompts"}),
    "runtime": frozenset({"contracts", "ports", "config"}),
    "orchestration": frozenset({"contracts", "ports", "runtime"}),
    "verification": frozenset({"contracts", "ports", "runtime", "agents"}),
    "reproduction": frozenset({"contracts", "ports", "runtime", "agents"}),
    "chaining": frozenset({"contracts", "ports", "runtime", "agents"}),
    "reporting": frozenset({"contracts", "ports", "runtime", "agents"}),
    "policy": frozenset({"contracts", "ports", "runtime", "agents", "config"}),
    "evaluation": frozenset({"contracts", "ports", "runtime", "agents", "config"}),
    "providers": frozenset({"contracts", "ports", "config"}),
    "static_analysis": frozenset({"contracts", "ports", "config"}),
    "sandbox": frozenset({"contracts", "ports", "config"}),
    "storage": frozenset({"contracts", "ports", "config"}),
    "interfaces": frozenset({"bootstrap", "orchestration", "runtime", "evaluation"}),
    "logging": frozenset(),
    "bootstrap": frozenset(
        {
            "contracts",
            "ports",
            "config",
            "prompts",
            "agents",
            "runtime",
            "orchestration",
            "verification",
            "reproduction",
            "chaining",
            "reporting",
            "policy",
            "evaluation",
            "providers",
            "static_analysis",
            "sandbox",
            "storage",
            "logging",
        }
    ),
}

# T08 application handlers deliberately call the pure static-analysis layer or
# concrete persistence adapters. Keep these exceptions module-exact so the
# package-wide dependency policy is not weakened for unrelated code.
EXACT_IMPORT_EXCEPTIONS: dict[str, frozenset[str]] = {
    "sastsimi.orchestration.static_external_runner": frozenset(
        {"sastsimi.static_analysis.coordinator"}
    ),
    "sastsimi.orchestration.static_publication": frozenset(
        {
            "sastsimi.static_analysis.coordinator",
            "sastsimi.static_analysis.normalizer",
        }
    ),
    "sastsimi.storage.context_binding": frozenset(
        {"sastsimi.static_analysis.context_retrieval"}
    ),
    # This concrete adapter uses the pure Reporter artifact validator only.
    "sastsimi.storage.report_export": frozenset(
        {"sastsimi.reporting.content_validation"}
    ),
    "sastsimi.verification.context_service": frozenset(
        {
            "sastsimi.static_analysis.context_retrieval",
            "sastsimi.storage",
            "sastsimi.storage.codec",
            "sastsimi.storage.context_policy",
            "sastsimi.storage.models",
            "sastsimi.storage.recovery_service",
            "sastsimi.storage.repositories",
        }
    ),
}

# Reject actual import/code-execution members, including references captured as
# aliases. Ordinary reflection and registry dispatch are not dependency edges.
# This is an architecture rule, not a sandbox or general Python syntax policy.
DYNAMIC_MODULES = frozenset({"importlib", "builtins"})
DYNAMIC_NAMES = frozenset({"__import__", "eval", "exec"})
DYNAMIC_ATTRIBUTES = DYNAMIC_NAMES | {"import_module", "load_module", "exec_module"}


class Access(Enum):
    ORDINARY = auto()
    NAMESPACE = auto()
    GETATTR = auto()
    VARS = auto()
    SCOPE_FUNCTION = auto()
    SCOPE_MAPPING = auto()
    MEMBER_GET = auto()
    SCOPE_GET = auto()
    FORBIDDEN = auto()


BUILTIN_ACCESS = {
    "__builtins__": Access.NAMESPACE,
    "__import__": Access.FORBIDDEN,
    "eval": Access.FORBIDDEN,
    "exec": Access.FORBIDDEN,
    "getattr": Access.GETATTR,
    "vars": Access.VARS,
    "globals": Access.SCOPE_FUNCTION,
    "locals": Access.SCOPE_FUNCTION,
}


class LocalBindings(ast.NodeVisitor):
    """Collect Python function-local names, excluding nested lexical bodies."""

    def __init__(self) -> None:
        self.names: set[str] = set()
        self.external: set[str] = set()
        self.globals: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.names.add(node.id)

    def visit_Import(self, node: ast.Import) -> None:
        self.names.update(
            alias.asname or alias.name.split(".")[0] for alias in node.names
        )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.names.update(alias.asname or alias.name for alias in node.names)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.names.add(node.name)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.names.add(node.name)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        pass

    def visit_Global(self, node: ast.Global) -> None:
        self.external.update(node.names)
        self.globals.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        self.external.update(node.names)


class ImportAccessChecker(ast.NodeVisitor):
    """Track explicit namespace/accessor captures within lexical binding maps.

    This is bounded source analysis, not evaluation of arbitrary calls, data
    structures or control flow. Ordinary Python reflection/dispatch is allowed.
    """

    def __init__(self) -> None:
        self.bindings = dict(BUILTIN_ACCESS)
        self.module_bindings = self.bindings
        self.class_enclosing: dict[str, Access] | None = None

    @staticmethod
    def member(node: ast.AST | None) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    @staticmethod
    def namespace_member(member: str | None) -> Access:
        if member is None or member in DYNAMIC_ATTRIBUTES:
            return Access.FORBIDDEN
        if member in {"__dict__", "__builtins__"}:
            return Access.NAMESPACE
        return BUILTIN_ACCESS.get(member, Access.ORDINARY)

    def access(self, node: ast.AST | None) -> Access:
        """Classify a value without executing it; policy is enforced by visit."""
        if isinstance(node, ast.Name):
            return self.bindings.get(node.id, Access.ORDINARY)
        if isinstance(node, ast.Attribute):
            if node.attr in DYNAMIC_ATTRIBUTES:
                return Access.FORBIDDEN
            owner = self.access(node.value)
            if owner == Access.NAMESPACE:
                return (
                    Access.MEMBER_GET
                    if node.attr == "get"
                    else self.namespace_member(node.attr)
                )
            if owner == Access.SCOPE_MAPPING and node.attr == "get":
                return Access.SCOPE_GET
        if isinstance(node, ast.Subscript):
            owner = self.access(node.value)
            member = self.member(node.slice)
            if owner == Access.NAMESPACE:
                return self.namespace_member(member)
            if owner == Access.SCOPE_MAPPING and member == "__builtins__":
                return Access.NAMESPACE
        if isinstance(node, ast.Call):
            callee = self.access(node.func)
            first = node.args[0] if node.args else None
            if callee == Access.MEMBER_GET:
                return self.namespace_member(self.member(first))
            if callee == Access.SCOPE_GET and self.member(first) == "__builtins__":
                return Access.NAMESPACE
            if callee == Access.SCOPE_FUNCTION:
                return Access.SCOPE_MAPPING
            if callee == Access.VARS and self.access(first) == Access.NAMESPACE:
                return Access.NAMESPACE
            if callee == Access.GETATTR and len(node.args) >= 2:
                member = self.member(node.args[1])
                if self.access(first) == Access.NAMESPACE:
                    return self.namespace_member(member)
                if member in DYNAMIC_ATTRIBUTES:
                    return Access.FORBIDDEN
        return Access.ORDINARY

    def check_expression(self, node: ast.AST) -> None:
        self.generic_visit(node)
        if self.access(node) == Access.FORBIDDEN:
            raise ValueError("Dynamic import/execution machinery requires review")

    visit_Name = check_expression
    visit_Attribute = check_expression
    visit_Subscript = check_expression
    visit_Call = check_expression

    def bind(self, target: ast.AST, value: Access) -> None:
        if isinstance(target, ast.Name):
            self.bindings[target.id] = value
        elif isinstance(target, (ast.Tuple, ast.List)):
            for element in target.elts:
                self.bind(element, Access.ORDINARY)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        value = self.access(node.value)
        for target in node.targets:
            self.bind(target, value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.visit(node.annotation)
        if node.value is not None:
            self.visit(node.value)
            self.bind(node.target, self.access(node.value))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.bindings[alias.asname or alias.name.split(".")[0]] = (
                Access.NAMESPACE
                if alias.name.split(".")[0] in DYNAMIC_MODULES
                else Access.ORDINARY
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            value = (
                self.namespace_member(alias.name)
                if not node.level and node.module in DYNAMIC_MODULES
                else Access.ORDINARY
            )
            if value == Access.FORBIDDEN:
                raise ValueError("Dynamic import machinery binding is not allowed")
            self.bindings[alias.asname or alias.name] = value

    def function_scope(self, args: ast.arguments, body: list[ast.AST]) -> None:
        local = LocalBindings()
        for statement in body:
            local.visit(statement)
        parameters = [*args.posonlyargs, *args.args, *args.kwonlyargs]
        if args.vararg is not None:
            parameters.append(args.vararg)
        if args.kwarg is not None:
            parameters.append(args.kwarg)
        shadowed = (local.names - local.external) | {arg.arg for arg in parameters}
        enclosing = self.bindings
        class_enclosing = self.class_enclosing
        lexical_parent = enclosing if class_enclosing is None else class_enclosing
        self.bindings = {**lexical_parent, **dict.fromkeys(shadowed, Access.ORDINARY)}
        for name in local.globals:
            self.bindings[name] = self.module_bindings.get(name, Access.ORDINARY)
        self.class_enclosing = None
        try:
            for statement in body:
                self.visit(statement)
        finally:
            self.bindings = enclosing
            self.class_enclosing = class_enclosing

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        self.visit(node.args)
        if node.returns is not None:
            self.visit(node.returns)
        self.bindings[node.name] = Access.ORDINARY
        self.function_scope(node.args, list(node.body))

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self.visit(node.args)
        self.function_scope(node.args, [node.body])

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for expression in [*node.decorator_list, *node.bases, *node.keywords]:
            self.visit(expression)
        self.bindings[node.name] = Access.ORDINARY
        enclosing, class_enclosing = self.bindings, self.class_enclosing
        if self.class_enclosing is None:
            self.class_enclosing = enclosing
        self.bindings = dict(enclosing)
        try:
            for statement in node.body:
                self.visit(statement)
        finally:
            self.bindings, self.class_enclosing = enclosing, class_enclosing


def reject_dynamic_access(tree: ast.AST) -> None:
    ImportAccessChecker().visit(tree)


def imports(source: str, module: str) -> list[str]:
    targets: list[str] = []
    package = module.rsplit(".", 1)[0]
    tree = ast.parse(source)
    reject_dynamic_access(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            targets.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if base.split(".")[0] in DYNAMIC_MODULES and any(
                alias.name in DYNAMIC_ATTRIBUTES for alias in node.names
            ):
                raise ValueError("Dynamic import machinery is not allowed")
            if node.level:
                base = importlib.util.resolve_name("." * node.level + base, package)
            if any(alias.name == "*" for alias in node.names):
                raise ValueError("Wildcard imports prevent exact boundary checks")
            if base == "sastsimi":
                targets.extend(f"sastsimi.{alias.name}" for alias in node.names)
            else:
                targets.append(base)
                if base.startswith("sastsimi."):
                    targets.extend(f"{base}.{alias.name}" for alias in node.names)
    return targets


def violations(source: str, module: str) -> list[str]:
    owner = module.split(".")[1]
    if owner not in RULES:
        return [f"Unknown first-party package: {module}"]
    try:
        targets = imports(source, module)
    except (SyntaxError, ValueError, ImportError):
        return [f"Unparseable imports: {module}"]
    errors: list[str] = []
    allowed = RULES[owner] | {owner}
    exact_allowed = EXACT_IMPORT_EXCEPTIONS.get(module, frozenset())
    policy_adapter = module.startswith("sastsimi.policy.adapters.")
    if policy_adapter:
        allowed = frozenset({"contracts", "ports", "config"})
    for target in targets:
        same_policy_adapter_package = policy_adapter and target.startswith(
            "sastsimi.policy.adapters."
        )
        if target == "sastsimi":
            errors.append(f"Ambiguous package import: {module}")
        elif target.startswith("sastsimi."):
            dependency = target.split(".")[1]
            if dependency not in RULES or (
                dependency not in allowed
                and not same_policy_adapter_package
                and not any(
                    target == exception
                    or (
                        exception.count(".") >= 2 and target.startswith(exception + ".")
                    )
                    for exception in exact_allowed
                )
            ):
                errors.append(f"Forbidden dependency: {module} -> {target}")
            elif owner != dependency and any(
                part.startswith("_") for part in target.split(".")[2:]
            ):
                errors.append(f"Private cross-package dependency: {module} -> {target}")
        elif owner in {"agents", "contracts", "ports"} and target.split(".")[0] in {
            "sqlalchemy",
            "sqlite3",
            "docker",
            "openai",
            "anthropic",
        }:
            errors.append(f"Direct adapter dependency: {module} -> {target}")
    return errors


def test_allowed_import_fixture() -> None:
    assert (
        violations(
            "from sastsimi.ports import work_handler", "sastsimi.verification.service"
        )
        == []
    )


def test_policy_adapter_may_import_only_its_adapter_siblings() -> None:
    module = "sastsimi.policy.adapters.__init__"
    assert violations("from .official_http import PolicyHttpTransport", module) == []
    assert violations("from ..program_catalog import ProgramCatalog", module)


@pytest.mark.parametrize(
    ("module", "source"),
    [
        ("sastsimi.providers.fake", "from sastsimi.storage import repositories"),
        (
            "sastsimi.verification.service",
            "import sastsimi.reporting.finding_normalizer",
        ),
        ("sastsimi.contracts.ids", "from sastsimi.runtime import work_service"),
        ("sastsimi.interfaces.cli.main", "from sastsimi.storage import database"),
        ("sastsimi.providers.fake", "from ..storage import database"),
        ("sastsimi.providers.fake", "from sastsimi import storage"),
        ("sastsimi.ports.handler", "import sastsimi.unknown"),
        ("sastsimi.unknown.file", "import os"),
        ("sastsimi.config.loader", "this is invalid python!"),
        ("sastsimi.contracts.ids", "from sastsimi.runtime import *"),
        ("sastsimi.agents.pro", "import sqlalchemy"),
    ],
)
def test_forbidden_import_fixture(module: str, source: str) -> None:
    assert violations(source, module), f"Forbidden import accepted: {module}: {source}"


def test_repository_imports() -> None:
    root = Path(__file__).resolve().parents[2] / "src" / "sastsimi"
    files = sorted(root.rglob("*.py"))
    assert files, "Application package has not been implemented"
    errors = []
    sources: dict[str, str] = {}
    for path in files:
        module = ".".join(("sastsimi", *path.relative_to(root).with_suffix("").parts))
        source = path.read_text(encoding="utf-8")
        errors.extend(violations(source, module))
        sources[module.removesuffix(".__init__")] = source
    errors.extend(cycle_errors(sources))
    assert not errors, "\n".join(errors)


def test_real_static_slice_is_private_and_not_selected_by_cli() -> None:
    root = Path(__file__).resolve().parents[2] / "src" / "sastsimi"
    bootstrap = (root / "bootstrap.py").read_text(encoding="utf-8")
    interfaces = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted((root / "interfaces").rglob("*.py"))
    )

    assert "def _build_real_static_slice(" in bootstrap
    assert "_build_real_static_slice" not in interfaces
    assert "StaticToolCoordinator" not in interfaces
    assert "PythonAstProcessAdapter" not in interfaces
    assert "OpenGrepProcessAdapter" not in interfaces
    assert "CodeQLProcessAdapter" not in interfaces
    assert "build_fake_pipeline" in interfaces


def test_static_analysis_process_creation_is_shell_free_and_suspended() -> None:
    root = Path(__file__).resolve().parents[2] / "src" / "sastsimi" / "static_analysis"
    forbidden_calls = {
        "Popen",
        "run",
        "create_subprocess_shell",
        "system",
    }
    violations_found: list[str] = []
    for path in sorted(root.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = (
                node.func.attr
                if isinstance(node.func, ast.Attribute)
                else node.func.id
                if isinstance(node.func, ast.Name)
                else ""
            )
            if name in forbidden_calls or any(
                keyword.arg == "shell"
                and isinstance(keyword.value, ast.Constant)
                and keyword.value.value is True
                for keyword in node.keywords
            ):
                # Protocol and facade methods named `run` are not process APIs.
                owner = (
                    node.func.value if isinstance(node.func, ast.Attribute) else None
                )
                if name != "run" or (
                    isinstance(owner, ast.Name) and owner.id == "subprocess"
                ):
                    violations_found.append(f"{path.name}:{node.lineno}:{name}")
        if "CreateProcessW" in path.read_text(encoding="utf-8") and (
            path.name != "process_windows.py"
        ):
            violations_found.append(f"{path.name}:CreateProcessW")
    windows_source = (root / "process_windows.py").read_text(encoding="utf-8")
    assert "CREATE_SUSPENDED" in windows_source
    assert "AssignProcessToJobObject" in windows_source
    assert windows_source.index("AssignProcessToJobObject") < windows_source.index(
        "ResumeThread"
    )
    assert not violations_found, "\n".join(violations_found)


def cycle_errors(sources: dict[str, str]) -> list[str]:
    graph: dict[str, set[str]] = {}
    for module, source in sources.items():
        # Package __init__ source resolves relative imports from the package itself.
        origin = (
            module + ".__init__"
            if any(other.startswith(module + ".") for other in sources)
            else module
        )
        targets = imports(source, origin)
        graph[module] = {
            target for target in targets if target in sources and target != module
        }
    visited: set[str] = set()
    active: set[str] = set()

    def visit(module: str) -> bool:
        if module in active:
            return True
        if module in visited:
            return False
        active.add(module)
        if any(visit(target) for target in sorted(graph[module])):
            return True
        active.remove(module)
        visited.add(module)
        return False

    return (
        ["Import cycle detected"]
        if any(visit(module) for module in sorted(graph))
        else []
    )


def test_import_cycles_fail_even_within_allowed_package() -> None:
    sources = {
        "sastsimi.config.a": "from sastsimi.config import b",
        "sastsimi.config.b": "from . import a",
    }
    assert cycle_errors(sources)
    assert cycle_errors({"sastsimi.config.a": "import os"}) == []


@pytest.mark.parametrize(
    "source",
    [
        '__import__("sastsimi.storage")',
        'import importlib; importlib.import_module("sastsimi.storage")',
        "import builtins; builtins.__import__('sastsimi.storage')",
        "from builtins import __import__ as load; load('sastsimi.storage')",
        "import builtins as core; core.__import__('sastsimi.storage')",
        "import builtins as core; load = core.__import__; load('sastsimi.storage')",
        (
            "from builtins import getattr as lookup; "
            "lookup(obj, '__import__')('sastsimi.storage')"
        ),
        "getattr(obj, '__import__')('sastsimi.storage')",
        "obj.__import__('sastsimi.storage')",
        "obj.import_module(module_name)",
        "globals()['__builtins__']['__import__']('sastsimi.storage')",
        "eval(expression)",
        "exec(expression)",
        "from importlib import import_module as load; load('sastsimi.storage')",
        "import importlib as machinery; loader = machinery.import_module",
        "import builtins as core; getattr(core, name)('sastsimi.storage')",
        "import builtins as core; vars(core)['__import__']('sastsimi.storage')",
        "import builtins as core; core.__dict__['__import__']('sastsimi.storage')",
        "lookup = getattr; lookup(obj, '__import__')('sastsimi.storage')",
        (
            "import builtins as core; lookup = core.getattr; "
            "lookup(core, '__import__')('sastsimi.storage')"
        ),
        (
            "import builtins as core; "
            "getattr(core, '__dict__')['__import__']('sastsimi.storage')"
        ),
        "import builtins as core; other = core; getattr(other, name)",
    ],
)
def test_dynamic_imports_cannot_bypass_boundary(source: str) -> None:
    assert violations(source, "sastsimi.providers.fake")


def test_cross_package_private_import_is_rejected() -> None:
    assert violations(
        "from sastsimi.runtime import _private", "sastsimi.verification.service"
    )


@pytest.mark.parametrize(
    "source",
    [
        "import logging; getattr(logging, 'INFO')",
        "vars(config)",
        "factories['local']('relative')",
        "factories.get('local')('relative')",
        "getattr(config, field_name)",
        "getattr(adapter, method_name)('relative')",
        "from builtins import getattr as lookup; lookup(config, field_name)",
        "from builtins import len as size; size(items)",
        "import builtins as core; core.len(items)",
        "import builtins as core; getattr(core, 'len')(items)",
        "import importlib.metadata as metadata; metadata.version('sastsimi')",
        "config.__dict__['path']",
        "lookup = getattr; lookup(config, field_name)",
        "import builtins as core; lookup = core.getattr; lookup(config, field_name)",
    ],
)
def test_benign_reflection_and_factory_dispatch_are_allowed(source: str) -> None:
    assert violations(source, "sastsimi.providers.fake") == []


@pytest.mark.parametrize(
    "source",
    [
        "import importlib; vars(importlib).get('import_module')('sastsimi.storage')",
        "import builtins as core; core.__dict__.get('__import__')('sastsimi.storage')",
        (
            "from builtins import __dict__ as table; "
            "table['__import__']('sastsimi.storage')"
        ),
        (
            "import builtins; other: object = builtins; member='__import__'; "
            "getattr(other, member)('sastsimi.storage')"
        ),
        "from builtins import __dict__ as table; table.get(member)('sastsimi.storage')",
        "import builtins as core; lookup = core.__dict__.get; lookup(member)",
        (
            "import builtins as core\n"
            "def invoke(name):\n"
            "    def unrelated():\n"
            "        core = object()\n"
            "    return getattr(core, name)\n"
        ),
        (
            "def invoke(core, name):\n"
            "    import builtins as core\n"
            "    return getattr(core, name)\n"
        ),
        (
            "def outer():\n"
            "    import builtins as core\n"
            "    def inner(name):\n"
            "        return getattr(core, name)\n"
        ),
    ],
)
def test_known_import_mapping_and_scope_captures_rejected(source: str) -> None:
    assert violations(source, "sastsimi.providers.fake")


@pytest.mark.parametrize(
    "source",
    [
        "factories.get(kind)('relative')",
        "from builtins import __dict__ as table; table.get('len')(items)",
        "from builtins import __dict__ as table; table['len'](items)",
        "other: object = config; getattr(other, member)",
        "import builtins as core; core = config; getattr(core, name)",
        (
            "import builtins as core\n"
            "def invoke(core, name):\n"
            "    return getattr(core, name)\n"
        ),
        "import builtins as core; invoke = lambda core, name: getattr(core, name)",
        (
            "import builtins as core\n"
            "def invoke(name):\n"
            "    core = config\n"
            "    return getattr(core, name)\n"
        ),
        (
            "import builtins as core\n"
            "def invoke(name):\n"
            "    core: object = config\n"
            "    return getattr(core, name)\n"
        ),
        (
            "import builtins as core\n"
            "def invoke(name):\n"
            "    import logging as core\n"
            "    return getattr(core, name)\n"
        ),
    ],
)
def test_unrelated_mapping_and_lexical_shadowing_allowed(source: str) -> None:
    assert violations(source, "sastsimi.providers.fake") == []


@pytest.mark.parametrize(
    "source",
    [
        "import builtins as core; core: object; getattr(core, member)",
        (
            "import builtins as core\n"
            "def outer(core):\n"
            "    def inner(name):\n"
            "        global core\n"
            "        return getattr(core, name)\n"
        ),
        (
            "import builtins as core\n"
            "class Example:\n"
            "    core = config\n"
            "    def invoke(self, name):\n"
            "        return getattr(core, name)\n"
        ),
    ],
)
def test_annotation_and_scope_declarations_preserve_import_binding(source: str) -> None:
    assert violations(source, "sastsimi.providers.fake")


def test_class_field_is_not_a_method_lexical_binding() -> None:
    source = (
        "import builtins\n"
        "core = config\n"
        "class Example:\n"
        "    core = builtins\n"
        "    def invoke(self, name):\n"
        "        return getattr(core, name)\n"
    )
    assert violations(source, "sastsimi.providers.fake") == []
