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


def imports(source: str, module: str) -> list[str]:
    targets: list[str] = []
    package = module.rsplit(".", 1)[0]
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Name) and node.id == "__import__":
            raise ValueError("Dynamic imports require explicit architecture review")
        if isinstance(node, ast.Import):
            if any(
                alias.name == "importlib" or alias.name.startswith("importlib.")
                for alias in node.names
            ):
                raise ValueError("Dynamic import machinery is not allowed")
            targets.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if base == "importlib" or base.startswith("importlib."):
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
    ],
)
def test_dynamic_imports_cannot_bypass_boundary(source: str) -> None:
    assert violations(source, "sastsimi.providers.fake")


def test_cross_package_private_import_is_rejected() -> None:
    assert violations(
        "from sastsimi.runtime import _private", "sastsimi.verification.service"
    )
