import ast
import importlib.util
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

# Reject actual import/code-execution members, including references captured as
# aliases. Ordinary reflection and registry dispatch are not dependency edges.
# This is an architecture rule, not a sandbox or general Python syntax policy.
DYNAMIC_MODULES = frozenset({"importlib", "builtins"})
DYNAMIC_NAMES = frozenset({"__import__", "eval", "exec"})
DYNAMIC_ATTRIBUTES = DYNAMIC_NAMES | {"import_module", "load_module", "exec_module"}


def reject_dynamic_access(tree: ast.AST) -> None:
    namespaces = {"__builtins__"}
    getters = {"getattr"}
    mappings = {"vars"}
    nodes = list(ast.walk(tree))
    for node in nodes:
        if isinstance(node, ast.Import):
            namespaces.update(
                alias.asname or alias.name.split(".")[0]
                for alias in node.names
                if alias.name.split(".")[0] in DYNAMIC_MODULES
            )
        elif isinstance(node, ast.ImportFrom) and node.module == "builtins":
            for alias in node.names:
                if alias.name == "getattr":
                    getters.add(alias.asname or alias.name)
                elif alias.name == "vars":
                    mappings.add(alias.asname or alias.name)

    def known_namespace(expression: ast.AST) -> bool:
        if isinstance(expression, ast.Name):
            return expression.id in namespaces
        if isinstance(expression, ast.Attribute):
            return expression.attr == "__dict__" and known_namespace(expression.value)
        if isinstance(expression, ast.Call):
            return (
                accessor(expression.func, mappings, "vars")
                and bool(expression.args)
                and known_namespace(expression.args[0])
            ) or (
                accessor(expression.func, getters, "getattr")
                and len(expression.args) >= 2
                and isinstance(expression.args[1], ast.Constant)
                and expression.args[1].value == "__dict__"
                and known_namespace(expression.args[0])
            )
        if isinstance(expression, ast.Subscript):
            return (
                isinstance(expression.slice, ast.Constant)
                and expression.slice.value == "__builtins__"
                and isinstance(expression.value, ast.Call)
                and isinstance(expression.value.func, ast.Name)
                and expression.value.func.id in {"globals", "locals"}
            )
        return False

    def accessor(expression: ast.AST, aliases: set[str], name: str) -> bool:
        return (isinstance(expression, ast.Name) and expression.id in aliases) or (
            isinstance(expression, ast.Attribute)
            and expression.attr == name
            and known_namespace(expression.value)
        )

    # Follow simple binding captures; the access is checked even without a call.
    changed = True
    while changed:
        changed = False
        for node in nodes:
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Name):
                    continue
                for aliases, name in (
                    (namespaces, ""),
                    (getters, "getattr"),
                    (mappings, "vars"),
                ):
                    captured = (
                        known_namespace(node.value)
                        if aliases is namespaces
                        else accessor(node.value, aliases, name)
                    )
                    if captured and target.id not in aliases:
                        aliases.add(target.id)
                        changed = True

    for node in nodes:
        if isinstance(node, ast.Name) and node.id in DYNAMIC_NAMES:
            raise ValueError("Dynamic imports require explicit architecture review")
        if isinstance(node, ast.Attribute) and node.attr in DYNAMIC_ATTRIBUTES:
            raise ValueError("Dynamic import attribute access is not allowed")
        if isinstance(node, ast.Subscript) and known_namespace(node.value):
            member = node.slice.value if isinstance(node.slice, ast.Constant) else None
            if not isinstance(member, str) or member in DYNAMIC_ATTRIBUTES:
                raise ValueError("Import namespace lookup cannot prove a safe member")
        if not isinstance(node, ast.Call) or len(node.args) < 2:
            continue
        if accessor(node.func, getters, "getattr"):
            member = (
                node.args[1].value if isinstance(node.args[1], ast.Constant) else None
            )
            if (isinstance(member, str) and member in DYNAMIC_ATTRIBUTES) or (
                not isinstance(member, str) and known_namespace(node.args[0])
            ):
                raise ValueError("Dynamic import member lookup is not allowed")


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
    if module.startswith("sastsimi.policy.adapters."):
        allowed = frozenset({"contracts", "ports", "config"})
    for target in targets:
        if target == "sastsimi":
            errors.append(f"Ambiguous package import: {module}")
        elif target.startswith("sastsimi."):
            dependency = target.split(".")[1]
            if dependency not in RULES or dependency not in allowed:
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
