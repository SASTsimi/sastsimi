"""Pure, fail-closed evidence for an omitted Django migration switch.

The caller must provide *every* project-settings candidate from a verified,
unchanged, pinned Git tree. This module neither opens files nor changes a run.
"""

from __future__ import annotations

import ast
import re
from typing import Literal

from .django_project_defaults import _django_project_default_false
from .django_relation_settings_omission import (
    _literal_collector,
    _path_constructor_is_unshadowed,
    _python_tree,
)

_GRAPH_ERROR = re.compile(
    rb"NodeNotFoundError\r?\ntraceback: handle > __init__ > __init__ > "
    rb"build_graph > validate_consistency > raise_error\r?\n?"
)
_GRAPH_FRAME_ERROR = re.compile(
    rb"NodeNotFoundError\r?\nTraceback \(most recent call last\):\r?\n"
    rb"(?:  (?:at [A-Za-z_][A-Za-z_0-9]*:[0-9]+|in [A-Za-z_][A-Za-z_0-9]*)\r?\n){2,20}"
)


def _name(node: ast.AST | None, value: str) -> bool:
    return isinstance(node, ast.Name) and node.id == value


def _attr(node: ast.AST, owner: str, attribute: str) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and _name(node.value, owner)
        and node.attr == attribute
    )


def _assignments(tree: ast.Module, key: str) -> list[ast.Assign]:
    return [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and _name(node.targets[0], key)
    ]


def _subscript_root(node: ast.AST) -> ast.AST:
    while isinstance(node, ast.Subscript):
        node = node.value
    return node


def _project_apps(tree: ast.Module, flag: str, app_name: str) -> tuple[str, ...] | None:
    flags = _assignments(tree, flag)
    apps = _assignments(tree, "INSTALLED_APPS")
    if len(flags) != 1 or len(apps) != 1:
        return None
    if any(
        isinstance(node, ast.Name)
        and node.id == "INSTALLED_APPS"
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and node is not apps[0].targets[0]
        for node in ast.walk(tree)
    ):
        return None
    parents = {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    if any(
        isinstance(node, ast.Name)
        and node.id == "INSTALLED_APPS"
        and isinstance(node.ctx, ast.Load)
        and not (
            isinstance(parent := parents.get(id(node)), ast.Attribute)
            and parent.value is node
            and parent.attr in {"append", "extend", "insert"}
        )
        for node in ast.walk(tree)
    ):
        return None
    if not _django_project_default_false(flags[0].value, flag):
        return None
    try:
        installed = ast.literal_eval(apps[0].value)
    except (ValueError, TypeError, MemoryError, RecursionError):
        return None
    if (
        not isinstance(installed, (tuple, list))
        or not 1 <= len(installed) <= 64
        or any(not isinstance(item, str) for item in installed)
        or app_name not in installed
    ):
        return None
    # A dynamically added app might satisfy the missing migration node.
    # Only the same default-off switch may conditionally extend this list.
    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and _name(node.func.value, "INSTALLED_APPS")
            and node.func.attr in {"append", "extend", "insert"}
        ):
            continue
        if not any(
            _name(condition.test, flag) and node in tuple(ast.walk(statement))
            for condition in tree.body
            if isinstance(condition, ast.If)
            for statement in condition.body
        ):
            return None
    return tuple(installed)


def _dependency(
    tree: ast.Module, flag: str
) -> tuple[str, tuple[tuple[str, str], ...]] | None:
    defaults = _assignments(tree, flag)
    if len(defaults) != 1:
        return None
    value = defaults[0].value
    if not (
        isinstance(value, ast.Call)
        and _name(value.func, "getattr")
        and len(value.args) == 3
        and _name(value.args[0], "settings")
        and isinstance(value.args[1], ast.Constant)
        and value.args[1].value == flag
        and isinstance(value.args[2], ast.Constant)
        and value.args[2].value is True
    ):
        return None
    branches = [
        node
        for node in tree.body
        if isinstance(node, ast.If) and _name(node.test, flag)
    ]
    if len(branches) != 1:
        return None
    branch = branches[0]
    for statement in branch.body:
        if not (
            isinstance(statement, ast.Assign)
            and len(statement.targets) == 1
            and isinstance(statement.targets[0], ast.Name)
            and isinstance(statement.value, ast.Call)
            and _name(statement.value.func, "getattr")
            and len(statement.value.args) == 3
            and _name(statement.value.args[0], "settings")
        ):
            continue
        name = statement.targets[0].id
        if not (
            isinstance(statement.value.args[1], ast.Constant)
            and statement.value.args[1].value == name
            and name.endswith("MIGRATION_DEPENDENCIES")
            and any(
                isinstance(item, ast.Assign)
                and len(item.targets) == 1
                and _name(item.targets[0], name)
                and isinstance(item.value, (ast.List, ast.Tuple))
                and not item.value.elts
                for item in branch.orelse
            )
        ):
            continue
        try:
            values = ast.literal_eval(statement.value.args[2])
        except (ValueError, TypeError, MemoryError, RecursionError):
            continue
        if (
            isinstance(values, list)
            and values
            and all(
                isinstance(item, tuple)
                and len(item) == 2
                and all(isinstance(part, str) and part for part in item)
                for item in values
            )
        ):
            return name, tuple(values)
    return None


def _migration_uses_dependency(
    tree: ast.Module, app_name: str, dependency_name: str
) -> bool:
    aliases = [
        alias.asname or alias.name
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module == app_name
        for alias in node.names
        if alias.name == "settings"
    ]
    if len(aliases) != 1:
        return False
    alias = aliases[0]
    assignments = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and any(_name(target, "dependencies") for target in node.targets)
    ]
    return (
        len(assignments) == 1
        and isinstance(assignments[0].value, ast.BinOp)
        and (
            isinstance(assignments[0].value.op, ast.Add)
            and isinstance(assignments[0].value.right, ast.Attribute)
            and _attr(assignments[0].value.right, alias, dependency_name)
        )
    )


def _project_scan_root(tree: ast.Module, collector: str) -> str | None:
    """Prove the literal workspace-root scan used by the selected defaults."""

    imports = [
        alias
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module == "pathlib"
        for alias in node.names
        if alias.name == "Path" and alias.asname is None
    ]
    roots = _assignments(tree, "root")
    if (
        len(imports) != 1
        or len(roots) != 1
        or not _path_constructor_is_unshadowed(tree)
    ):
        return None
    assignment = roots[0]
    if not (
        isinstance(assignment.value, ast.Call)
        and _name(assignment.value.func, "Path")
        and len(assignment.value.args) == 1
        and not assignment.value.keywords
        and isinstance(assignment.value.args[0], ast.Constant)
        and assignment.value.args[0].value == "/workspace"
    ):
        return None
    if (
        any(
            isinstance(node, ast.Name)
            and node.id in {"root", "Path"}
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node is not assignment.targets[0]
            for node in ast.walk(tree)
        )
        or any(
            isinstance(node, ast.arg) and node.arg in {"root", "Path"}
            for node in ast.walk(tree)
        )
        or any(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            and node.name == "root"
            or isinstance(node, ast.ExceptHandler)
            and node.name == "root"
            or isinstance(node, (ast.Import, ast.ImportFrom))
            and any(
                alias.asname == "root" or alias.name == "root" for alias in node.names
            )
            or isinstance(node, (ast.Global, ast.Nonlocal))
            and "root" in node.names
            for node in ast.walk(tree)
        )
    ):
        return None
    scans = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.For, ast.AsyncFor))
        and isinstance(node.iter, ast.Call)
        and _attr(node.iter.func, "root", "rglob")
        and len(node.iter.args) == 1
        and not node.iter.keywords
        and isinstance(node.iter.args[0], ast.Constant)
        and node.iter.args[0].value == "settings.py"
        and isinstance(node.target, ast.Name)
    ]
    if len(scans) != 1 or not isinstance(scans[0], ast.For):
        return None
    scan = scans[0]
    if not isinstance(scan.target, ast.Name):
        return None
    if any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "rglob"
        and node is not scan.iter
        for node in ast.walk(tree)
    ):
        return None
    collectors = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _name(node.func, collector)
    ]
    if (
        len(collectors) != 1
        or len(collectors[0].args) != 1
        or not _name(collectors[0].args[0], scan.target.id)
        or collectors[0] not in tuple(ast.walk(scan))
    ):
        return None
    candidates = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and _name(node.targets[0], "candidates")
    ]
    appends = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _attr(node.func, "candidates", "append")
    ]
    if (
        len(candidates) != 1
        or not isinstance(candidates[0].value, ast.List)
        or candidates[0].value.elts
        or candidates[0].lineno >= scan.lineno
        or len(appends) != 1
        or appends[0] not in tuple(ast.walk(scan))
        or len(appends[0].args) != 1
        or not isinstance(appends[0].args[0], (ast.Tuple, ast.List))
    ):
        return None
    owners = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.FunctionDef))
        and candidates[0] in node.body
        and scan in node.body
    ]
    if len(owners) != 1:
        return None
    if (
        any(
            isinstance(node, ast.Name)
            and node.id == "candidates"
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and node is not candidates[0].targets[0]
            for node in ast.walk(tree)
        )
        or any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and _name(node.func.value, "candidates")
            and node is not appends[0]
            for node in ast.walk(tree)
        )
        or any(
            isinstance(node, ast.Subscript)
            and _name(_subscript_root(node), "candidates")
            for node in ast.walk(tree)
        )
    ):
        return None
    return "/workspace"


def django_migration_graph_project_scan_root(candidate: bytes) -> str | None:
    """Expose the proven scan root for the caller's complete manifest check."""

    tree = _python_tree(candidate)
    if tree is None:
        return None
    collector = _literal_collector(tree)
    return None if collector is None else _project_scan_root(tree, collector)


def _literal_defaults_flow(tree: ast.Module, collector: str) -> bool:
    """Recognize direct or bounded candidate-tuple propagation, not eval."""

    if _project_scan_root(tree, collector) is None:
        return False

    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _name(node.func, collector)
    ]
    if len(calls) != 1:
        return False
    if any(
        isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and _name(node.targets[0], "defaults")
        and node.value is calls[0]
        for node in ast.walk(tree)
    ):
        return True
    source = [
        node.targets[0].id
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.value is calls[0]
    ]
    if len(source) != 1:
        return False
    max_assignments = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], (ast.Tuple, ast.List))
        and sum(_name(item, "defaults") for item in node.targets[0].elts) == 1
        and isinstance(node.value, ast.Call)
        and _name(node.value.func, "max")
        and node.value.args
        and _name(node.value.args[0], "candidates")
    ]
    appends = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _attr(node.func, "candidates", "append")
    ]
    defaults_writes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and node.id == "defaults"
        and isinstance(node.ctx, (ast.Store, ast.Del))
    ]
    collector_defs = [
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == collector
    ]
    if len(collector_defs) != 1:
        return False
    collector_nodes = set(ast.walk(collector_defs[0]))
    source_writes = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name)
        and node.id == source[0]
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and node not in collector_nodes
    ]
    if len(max_assignments) != 1 or not isinstance(
        max_assignments[0].targets[0], (ast.Tuple, ast.List)
    ):
        return False
    max_target = max_assignments[0].targets[0]
    return (
        len(defaults_writes) == 1
        and defaults_writes[0] in max_target.elts
        and len(source_writes) == 1
        and len(appends) == 1
        and len(appends[0].args) == 1
        and isinstance(appends[0].args[0], (ast.Tuple, ast.List))
        and any(_name(item, source[0]) for item in appends[0].args[0].elts)
    )


def _candidate_omits(
    tree: ast.Module, flag: str, *, require_explicit_false: bool = False
) -> bool:
    collector = _literal_collector(tree)
    if collector is None or not _literal_defaults_flow(tree, collector):
        return False
    # The collector's literal values cease to be proof if its selected
    # dictionary is mutated or handed to an alias before configuration.
    for node in ast.walk(tree):
        if isinstance(node, ast.Subscript) and _name(_subscript_root(node), "defaults"):
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                return False
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if _name(node.func.value, "defaults") and node.func.attr not in {
                "items",
                "get",
            }:
                return False
        if isinstance(node, ast.Assign) and _name(node.value, "defaults"):
            return False
        if isinstance(node, ast.AugAssign) and _name(node.target, "defaults"):
            return False
    configures = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _attr(node.func, "settings", "configure")
    ]
    migrations = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _name(node.func, "call_command")
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "migrate"
    ]
    setups = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _attr(node.func, "django", "setup")
    ]
    if (
        len(configures) != 1
        or len(migrations) != 1
        or len(setups) != 1
        or not configures[0].lineno < setups[0].lineno < migrations[0].lineno
        or configures[0].args
        or len(configures[0].keywords) != 1
        or configures[0].keywords[0].arg is not None
        or not isinstance(configures[0].keywords[0].value, ast.Name)
    ):
        return False
    config_name = configures[0].keywords[0].value.id
    for node in ast.walk(tree):
        if getattr(node, "lineno", 0) >= migrations[0].lineno:
            continue
        if isinstance(node, (ast.AugAssign, ast.AnnAssign)):
            mutation_target = node.target
            if (
                _name(mutation_target, config_name)
                or isinstance(mutation_target, ast.Subscript)
                and _name(_subscript_root(mutation_target), config_name)
                or isinstance(mutation_target, ast.Attribute)
                and _name(mutation_target.value, "settings")
            ):
                return False
        if isinstance(node, ast.Delete) and any(
            _name(target, config_name)
            or isinstance(target, ast.Subscript)
            and _name(_subscript_root(target), config_name)
            or isinstance(target, ast.Attribute)
            and _name(target.value, "settings")
            for target in node.targets
        ):
            return False
        if isinstance(node, ast.Assign) and _name(node.value, config_name):
            return False
    override: ast.Assign | None = None
    if require_explicit_false:
        owners = [
            node
            for node in ast.walk(tree)
            if isinstance(node, (ast.Module, ast.FunctionDef))
            and any(
                isinstance(statement, ast.Expr) and statement.value is configures[0]
                for statement in node.body
            )
        ]
        if len(owners) != 1:
            return False
        body = owners[0].body
        index = next(
            i
            for i, statement in enumerate(body)
            if isinstance(statement, ast.Expr) and statement.value is configures[0]
        )
        if index == 0:
            return False
        previous = body[index - 1]
        if not isinstance(previous, ast.Assign):
            return False
        override = previous
        if not (
            len(override.targets) == 1
            and isinstance(override.targets[0], ast.Subscript)
            and _name(override.targets[0].value, config_name)
            and isinstance(override.targets[0].slice, ast.Constant)
            and override.targets[0].slice.value == flag
            and isinstance(override.value, ast.Constant)
            and override.value.value is False
        ):
            return False
    definitions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and _name(node.targets[0], config_name)
        and node.lineno < configures[0].lineno
    ]
    if len(definitions) != 1 or not isinstance(definitions[0].value, ast.DictComp):
        return False
    comp = definitions[0].value
    if len(comp.generators) != 1:
        return False
    comp_target = comp.generators[0].target
    if not isinstance(comp_target, (ast.Tuple, ast.List)):
        return False
    if (
        len(comp_target.elts) != 2
        or not all(isinstance(item, ast.Name) for item in comp_target.elts)
        or not isinstance(comp.generators[0].iter, ast.Call)
        or not _attr(comp.generators[0].iter.func, "defaults", "items")
        or comp.generators[0].iter.args
    ):
        return False
    key_node, value_node = comp_target.elts
    if not isinstance(key_node, ast.Name) or not isinstance(value_node, ast.Name):
        return False
    if not _name(comp.key, key_node.id) or not _name(comp.value, value_node.id):
        return False
    key_name = key_node.id
    if not any(
        isinstance(node, ast.Call)
        and _attr(node.func, key_name, "startswith")
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
        and flag.startswith(node.args[0].value)
        for condition in comp.generators[0].ifs
        for node in ast.walk(condition)
    ):
        return False
    # Do not infer omission when any unaccounted write could provide the flag.
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and node.lineno < migrations[0].lineno:
            if _attr(node.func, config_name, "update"):
                if (
                    (require_explicit_false and node.lineno > configures[0].lineno)
                    or len(node.args) != 1
                    or node.keywords
                    or not isinstance(node.args[0], ast.Dict)
                ):
                    return False
                if any(
                    not isinstance(key, ast.Constant)
                    or not isinstance(key.value, str)
                    or key.value == flag
                    for key in node.args[0].keys
                ):
                    return False
            elif isinstance(node.func, ast.Attribute) and _name(
                node.func.value, config_name
            ):
                return False
            if (
                _name(node.func, "setattr")
                and len(node.args) >= 2
                and _name(node.args[0], "settings")
            ):
                return False
        if not isinstance(node, ast.Assign) or node.lineno >= migrations[0].lineno:
            continue
        for target in node.targets:
            if isinstance(target, ast.Subscript) and _name(target.value, config_name):
                if not (
                    isinstance(target.slice, ast.Constant)
                    and isinstance(target.slice.value, str)
                    and (target.slice.value != flag or node is override)
                    and (
                        not require_explicit_false or node.lineno < configures[0].lineno
                    )
                ):
                    return False
            if isinstance(target, ast.Attribute) and _attr(target, "settings", flag):
                return False
    if require_explicit_false:
        allowed_loads: set[ast.AST] = {configures[0].keywords[0].value}
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and _attr(node.func, config_name, "update")
            ):
                allowed_loads.add(node.func.value)
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Subscript) and _name(
                        target.value, config_name
                    ):
                        allowed_loads.add(target.value)
                if _name(node.value, "settings"):
                    return False
        if any(
            isinstance(node, ast.Name)
            and node.id == config_name
            and isinstance(node.ctx, ast.Load)
            and node not in allowed_loads
            for node in ast.walk(tree)
        ):
            return False
    # The resulting app list must come from the pinned literal defaults.
    app_lists = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and isinstance(node.value, ast.Call)
        and _name(node.value.func, "list")
        and len(node.value.args) == 1
        and isinstance(node.value.args[0], ast.Subscript)
        and _name(node.value.args[0].value, "defaults")
        and isinstance(node.value.args[0].slice, ast.Constant)
        and node.value.args[0].slice.value == "INSTALLED_APPS"
    ]
    if len(app_lists) != 1:
        return False
    app_list_target = app_lists[0].targets[0]
    if not isinstance(app_list_target, ast.Name):
        return False
    app_list_name = app_list_target.id
    if (
        any(
            isinstance(node, ast.Name)
            and node.id == app_list_name
            and isinstance(node.ctx, (ast.Store, ast.Del))
            and app_lists[0].lineno < node.lineno < configures[0].lineno
            for node in ast.walk(tree)
        )
        or any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and _name(node.func.value, app_list_name)
            and app_lists[0].lineno < node.lineno < configures[0].lineno
            for node in ast.walk(tree)
        )
        or any(
            isinstance(node, ast.Assign)
            and app_lists[0].lineno < node.lineno < configures[0].lineno
            and any(
                isinstance(target, ast.Subscript) and _name(target.value, app_list_name)
                for target in node.targets
            )
            for node in ast.walk(tree)
        )
    ):
        return False
    return any(
        isinstance(node, ast.Call)
        and _attr(node.func, config_name, "update")
        and node.lineno < configures[0].lineno
        and node.args
        and isinstance(node.args[0], ast.Dict)
        and any(
            isinstance(key, ast.Constant)
            and key.value == "INSTALLED_APPS"
            and _name(value, app_list_name)
            for key, value in zip(node.args[0].keys, node.args[0].values, strict=True)
        )
        for node in ast.walk(tree)
    )


def django_migration_graph_settings_omission(
    stderr: bytes,
    stdout: bytes,
    candidate: bytes,
    projects: tuple[bytes, ...],
    app_settings: bytes,
    migration: bytes,
    *,
    app_name: str,
) -> str | None:
    """Return the one omitted default-off flag, or ``None`` on uncertainty.

    ``projects`` must be all possible pinned project settings files selected
    by the candidate's bounded search, as attested by the caller. The return
    value is a fixture-error diagnosis, never a vulnerability verdict.
    """

    if (
        len(stderr) > 1024
        or _GRAPH_ERROR.fullmatch(stderr) is None
        or len(stdout) > 4096
        or any(
            marker not in stdout
            for marker in (
                b"pinned_source=verified",
                b"project_settings_source=verified",
                b"project_urlconf_source=verified",
            )
        )
        or b"SASTSIMI_POC_INCONCLUSIVE" in stdout
        or re.search(rb"(?i)\b(?:reproduced|confirmed)\b", stdout)
        or not 1 <= len(projects) <= 16
        or any(
            len(source) > 128 * 1024 for source in (*projects, app_settings, migration)
        )
        or re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", app_name) is None
    ):
        return None
    candidate_tree = _python_tree(candidate)
    if candidate_tree is None:
        return None
    try:
        project_trees = [ast.parse(source.decode("utf-8")) for source in projects]
        app_tree = ast.parse(app_settings.decode("utf-8"))
        migration_tree = ast.parse(migration.decode("utf-8"))
    except (UnicodeError, SyntaxError, ValueError):
        return None
    flags = [
        node.targets[0].id
        for node in app_tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id.endswith("MODE_ENABLED")
    ]
    matched: list[str] = []
    for flag in flags:
        dependency = _dependency(app_tree, flag)
        if (
            dependency is None
            or not _migration_uses_dependency(migration_tree, app_name, dependency[0])
            or not _candidate_omits(candidate_tree, flag)
        ):
            continue
        all_apps = [_project_apps(tree, flag, app_name) for tree in project_trees]
        if any(apps is None for apps in all_apps):
            continue
        if all(
            any(label not in apps for label, _node in dependency[1])
            for apps in all_apps
            if apps is not None
        ):
            matched.append(flag)
    return matched[0] if len(matched) == 1 else None


def django_migration_settings_replay_forbidden(content: bytes, flag: str) -> bool:
    """Permit only the verified candidate flow with one immediate false override."""

    if re.fullmatch(r"[A-Z][A-Z_0-9]*", flag) is None:
        return True
    tree = _python_tree(content)
    return tree is None or not _candidate_omits(tree, flag, require_explicit_false=True)


def _synthetic_fixture_scan(
    tree: ast.Module, flag: str, app_name: str
) -> tuple[str, ...] | None:
    """Recognize bounded source selection without executing the PoC."""

    def named_assignments(name: str) -> list[ast.Assign]:
        return [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and _name(node.targets[0], name)
        ]

    roots = named_assignments("root")
    if (
        len(roots) != 1
        or not isinstance(roots[0].value, ast.Call)
        or not _name(roots[0].value.func, "Path")
        or len(roots[0].value.args) != 1
        or not isinstance(roots[0].value.args[0], ast.Constant)
        or roots[0].value.args[0].value != "/workspace"
        or not any(
            isinstance(node, ast.ImportFrom)
            and node.module == "pathlib"
            and any(
                alias.name == "Path" and alias.asname is None for alias in node.names
            )
            for node in ast.walk(tree)
        )
    ):
        return None
    scans = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.For)
        and isinstance(node.iter, ast.Call)
        and _attr(node.iter.func, "root", "rglob")
        and len(node.iter.args) == 1
        and isinstance(node.iter.args[0], ast.Constant)
        and node.iter.args[0].value == "settings.py"
    ]
    if len(scans) != 1 or not any(
        isinstance(node, ast.Break) for node in ast.walk(scans[0])
    ):
        return None
    flags = named_assignments("project_flags")
    if (
        len(flags) != 1
        or not isinstance(flags[0].value, ast.Dict)
        or flags[0].value.keys
    ):
        return None
    collectors = [
        node
        for node in ast.walk(scans[0])
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Subscript)
        and _name(node.targets[0].value, "project_flags")
        and isinstance(node.value, ast.Call)
        and _attr(node.value.func, "ast", "literal_eval")
        and len(node.value.args) == 1
    ]
    if len(collectors) != 1:
        return None
    prefixes = [
        node.args[0].value
        for node in ast.walk(scans[0])
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "startswith"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    ]
    if len(prefixes) != 1 or not flag.startswith(prefixes[0]):
        return None
    if any(
        isinstance(node, ast.Name)
        and node.id in {"root", "project_flags", "Path"}
        and isinstance(node.ctx, (ast.Store, ast.Del))
        and node is not roots[0].targets[0]
        and node is not flags[0].targets[0]
        and node not in tuple(ast.walk(collectors[0].targets[0]))
        for node in ast.walk(tree)
    ):
        return None
    if any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"eval", "exec"}
        for node in ast.walk(tree)
    ):
        return None
    if any(
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value in {flag, "MIGRATION_MODULES", "--fake", "--fake-initial"}
        for node in ast.walk(tree)
    ):
        return None
    configurations = named_assignments("fixture_settings")
    if (
        len(configurations) != 1
        or not isinstance(configurations[0].value, ast.Call)
        or not _name(configurations[0].value.func, "dict")
        or configurations[0].value.args
    ):
        return None
    values = {
        keyword.arg: keyword.value for keyword in configurations[0].value.keywords
    }
    if len(values) != len(configurations[0].value.keywords):
        return None
    try:
        apps = ast.literal_eval(values["INSTALLED_APPS"])
    except (KeyError, TypeError, ValueError, MemoryError, RecursionError):
        return None
    if (
        not isinstance(apps, (tuple, list))
        or not 1 <= len(apps) <= 64
        or not all(isinstance(item, str) for item in apps)
        or app_name not in apps
        or "MIGRATION_MODULES" in values
    ):
        return None
    updates = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _attr(node.func, "fixture_settings", "update")
    ]
    if (
        len(updates) != 1
        or len(updates[0].args) != 1
        or not _name(updates[0].args[0], "project_flags")
        or updates[0].keywords
    ):
        return None
    configures = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _attr(node.func, "settings", "configure")
    ]
    setups = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _attr(node.func, "django", "setup")
    ]
    migrations = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _name(node.func, "call_command")
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "migrate"
    ]
    if (
        len(configures) != 1
        or len(setups) != 1
        or len(migrations) != 1
        or configures[0].args
        or len(configures[0].keywords) != 1
        or configures[0].keywords[0].arg is not None
        or not _name(configures[0].keywords[0].value, "fixture_settings")
        or not configurations[0].lineno < updates[0].lineno < configures[0].lineno
        or not configures[0].lineno < setups[0].lineno < migrations[0].lineno
        or any(
            keyword.arg in {"fake", "fake_initial"}
            for keyword in migrations[0].keywords
        )
    ):
        return None
    if any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in {"get", "post", "request"}
        and node.lineno < migrations[0].lineno
        for node in ast.walk(tree)
    ):
        return None

    def unrelated_key(target: ast.AST) -> bool:
        if not isinstance(target, ast.Subscript) or not _name(
            target.value, "fixture_settings"
        ):
            return False
        key = target.slice
        if (
            isinstance(key, ast.BinOp)
            and isinstance(key.op, ast.Add)
            and isinstance(key.left, ast.Constant)
            and isinstance(key.right, ast.Constant)
            and isinstance(key.left.value, str)
            and isinstance(key.right.value, str)
        ):
            value = key.left.value + key.right.value
        elif isinstance(key, ast.Constant) and isinstance(key.value, str):
            value = key.value
        else:
            return True
        return value in {flag, "INSTALLED_APPS", "MIGRATION_MODULES"}

    if any(
        isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete))
        and any(
            unrelated_key(target)
            for target in (
                node.targets
                if isinstance(node, ast.Assign)
                else [node.target]
                if isinstance(node, (ast.AnnAssign, ast.AugAssign))
                else node.targets
            )
        )
        for node in ast.walk(tree)
    ):
        return None
    return tuple(apps)


def django_migration_fixture_source_gap(
    *,
    stderr: bytes,
    stdout: bytes,
    candidate: bytes,
    projects: tuple[bytes, ...],
    app_settings: bytes,
    migration: bytes,
    app_name: str,
) -> str | None:
    """Prove a synthetic fixture risk, not the missing node or vulnerability."""

    if (
        len(stderr) > 1024
        or _GRAPH_FRAME_ERROR.fullmatch(stderr) is None
        or not (b"  at build_graph:" in stderr or b"  in build_graph\n" in stderr)
        or not (
            b"  at validate_consistency:" in stderr
            or b"  in validate_consistency\n" in stderr
        )
        or stdout
        or not 1 <= len(projects) <= 16
        or any(
            len(source) > 128 * 1024 for source in (*projects, app_settings, migration)
        )
        or re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", app_name) is None
    ):
        return None
    tree = _python_tree(candidate)
    if tree is None:
        return None
    try:
        project_trees = [ast.parse(source.decode("utf-8")) for source in projects]
        app_tree = ast.parse(app_settings.decode("utf-8"))
        migration_tree = ast.parse(migration.decode("utf-8"))
    except (UnicodeError, SyntaxError, ValueError):
        return None
    matches: list[str] = []
    for flag in (
        node.targets[0].id
        for node in app_tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and node.targets[0].id.endswith("MODE_ENABLED")
    ):
        dependency = _dependency(app_tree, flag)
        apps = _synthetic_fixture_scan(tree, flag, app_name)
        if (
            dependency is None
            or apps is None
            or not _migration_uses_dependency(migration_tree, app_name, dependency[0])
            or not any(
                _project_apps(project, flag, app_name) is not None
                for project in project_trees
            )
            or not any(label not in apps for label, _node in dependency[1])
        ):
            continue
        # The candidate's literal collector must be unable to inject this
        # computed flag, regardless of which project settings file it visits.
        if any(
            any(
                isinstance(node, ast.Assign)
                and any(_name(target, flag) for target in node.targets)
                and isinstance(
                    node.value, (ast.Constant, ast.List, ast.Tuple, ast.Dict)
                )
                for node in project.body
            )
            for project in project_trees
        ):
            continue
        matches.append(flag)
    return matches[0] if len(matches) == 1 else None


def django_migration_fixture_source_projection(
    *,
    flag: str,
    app_name: str,
    project_sources: tuple[tuple[str, bytes], ...],
    app_settings: bytes,
    migration: bytes,
) -> dict[str, object] | None:
    """Project only bounded, non-secret AST facts from pinned source blobs."""

    if (
        re.fullmatch(r"[A-Z][A-Z_0-9]*", flag) is None
        or re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", app_name) is None
        or not 1 <= len(project_sources) <= 16
    ):
        return None
    try:
        app_tree = ast.parse(app_settings.decode("utf-8"))
        migration_tree = ast.parse(migration.decode("utf-8"))
        dependency = _dependency(app_tree, flag)
        if dependency is None or not _migration_uses_dependency(
            migration_tree, app_name, dependency[0]
        ):
            return None
        if not 1 <= len(dependency[1]) <= 16 or any(
            len(part) > 128
            or re.fullmatch(
                r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*" if index == 0 else r"[A-Za-z0-9_]+",
                part,
            )
            is None
            for pair in dependency[1]
            for index, part in enumerate(pair)
        ):
            return None
        modules: list[str] = []
        for path, source in project_sources:
            path_match = re.fullmatch(
                r"(?:src/)?([A-Za-z_]\w*(?:/[A-Za-z_]\w*)*)/settings\.py",
                path,
            )
            if path_match is None or len(source) > 128 * 1024:
                return None
            apps = _project_apps(ast.parse(source.decode("utf-8")), flag, app_name)
            if apps is not None:
                modules.append(
                    path.removeprefix("src/").removesuffix(".py").replace("/", ".")
                )
        if not modules or len(modules) != len(set(modules)):
            return None
    except (
        UnicodeError,
        SyntaxError,
        ValueError,
        TypeError,
        MemoryError,
        RecursionError,
    ):
        return None
    return {
        "kind": "simple_django_migration_fixture_source_projection",
        "verified_project_modules": modules,
        "app_name": app_name,
        "project_flag": flag,
        "project_flag_default": False,
        "app_fallback_when_flag_missing": True,
        "gated_migration_dependency": dependency[0],
        "optional_dependency_nodes": [list(pair) for pair in dependency[1]],
        "missing_node": "UNKNOWN",
    }


def django_migration_fixture_closed_diagnostic(
    stderr: bytes,
) -> dict[str, object] | None:
    """Return fixed labels only; never pass free-form migration stderr onward."""

    if (
        len(stderr) > 1024
        or _GRAPH_FRAME_ERROR.fullmatch(stderr) is None
        or not (b"  at build_graph:" in stderr or b"  in build_graph\n" in stderr)
        or not (
            b"  at validate_consistency:" in stderr
            or b"  in validate_consistency\n" in stderr
        )
    ):
        return None
    return {
        "kind": "simple_poc_django_migration_graph_diagnostic_v1",
        "exception_class": "NodeNotFoundError",
        "phase": "MIGRATION_GRAPH_SETUP",
        "function_frames": ["build_graph", "validate_consistency"],
        "missing_node": "UNKNOWN",
    }


FixtureReplayReason = Literal[
    "INVALID_PYTHON_OR_MIGRATION_BYPASS",
    "SYNTHETIC_SETTINGS_OR_MUTATION",
    "PINNED_PROJECT_BOOTSTRAP_MISSING",
    "SETUP_MIGRATE_ORDER_INVALID",
    "REQUEST_BEFORE_MIGRATION",
]


def django_migration_fixture_replay_rejection(
    content: bytes,
    *,
    flag: str | None = None,
    app_name: str | None = None,
    project_modules: tuple[str, ...] | None = None,
) -> FixtureReplayReason | None:
    """Classify rejected fixture replans without disclosing source values.

    The source-bound mode permits only one native pinned project settings
    module, with setup and migration as unconditional top-level calls. Actual
    migration success still requires the subsequent container execution.
    """

    tree = _python_tree(content)
    if tree is None or any(
        marker in content
        for marker in (b"MIGRATION_MODULES", b"--fake", b"fake_initial")
    ):
        return "INVALID_PYTHON_OR_MIGRATION_BYPASS"
    if flag is not None or app_name is not None:
        if (
            flag is None
            or app_name is None
            or re.fullmatch(r"[A-Z][A-Z_0-9]*", flag) is None
            or re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", app_name) is None
            or _synthetic_fixture_scan(tree, flag, app_name) is not None
        ):
            return "SYNTHETIC_SETTINGS_OR_MUTATION"
    if project_modules is not None:
        os_imports = [
            alias
            for node in tree.body
            if isinstance(node, ast.Import)
            for alias in node.names
            if alias.name == "os" and alias.asname is None
        ]
        django_imports = [
            alias
            for node in tree.body
            if isinstance(node, ast.Import)
            for alias in node.names
            if alias.name == "django" and alias.asname is None
        ]
        migration_imports = [
            alias
            for node in tree.body
            if isinstance(node, ast.ImportFrom)
            and node.module == "django.core.management"
            for alias in node.names
            if alias.name == "call_command" and alias.asname is None
        ]
        if (
            len(os_imports) != 1
            or len(django_imports) != 1
            or len(migration_imports) != 1
            or not 1 <= len(project_modules) <= 16
            or len(set(project_modules)) != len(project_modules)
            or any(
                re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", module) is None
                for module in project_modules
            )
            or any(
                isinstance(node, ast.Call) and _attr(node.func, "settings", "configure")
                for node in ast.walk(tree)
            )
            or any(
                isinstance(node, ast.Name) and node.id == "fixture_settings"
                for node in ast.walk(tree)
            )
            or any(
                isinstance(node, ast.Import)
                and any(alias.name == "django.conf" for alias in node.names)
                or isinstance(node, ast.ImportFrom)
                and node.module == "django.conf"
                for node in ast.walk(tree)
            )
            or any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id in {"setattr", "delattr"}
                for node in ast.walk(tree)
            )
            or any(
                isinstance(node, ast.Attribute) and node.attr == "__dict__"
                for node in ast.walk(tree)
            )
            or any(
                isinstance(node, ast.Attribute) and node.attr == "MIGRATION_MODULES"
                for node in ast.walk(tree)
            )
            or any(
                isinstance(node, ast.Name)
                and node.id in {"os", "django", "call_command"}
                and isinstance(node.ctx, (ast.Store, ast.Del))
                for node in ast.walk(tree)
            )
            or any(
                isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                and node.name in {"os", "django", "call_command"}
                for node in ast.walk(tree)
            )
            or any(
                isinstance(node, ast.Attribute)
                and _attr(node, "django", "setup")
                and isinstance(node.ctx, (ast.Store, ast.Del))
                for node in ast.walk(tree)
            )
            or any(
                isinstance(node, ast.Attribute) and _attr(node, "sys", "modules")
                for node in ast.walk(tree)
            )
        ):
            return "PINNED_PROJECT_BOOTSTRAP_MISSING"

        settings_assignments = [
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Subscript)
            and isinstance(node.targets[0].value, ast.Attribute)
            and _attr(node.targets[0].value, "os", "environ")
            and isinstance(node.targets[0].slice, ast.Constant)
            and node.targets[0].slice.value == "DJANGO_SETTINGS_MODULE"
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
            and node.value.value in project_modules
        ]
        if len(settings_assignments) != 1 or any(
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and _attr(node.func, "os", "putenv")
            for node in ast.walk(tree)
        ):
            return "SYNTHETIC_SETTINGS_OR_MUTATION"
        environment_target = settings_assignments[0].targets[0]
        assert isinstance(environment_target, ast.Subscript)
        environment_attributes = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Attribute) and _attr(node, "os", "environ")
        ]
        if environment_attributes != [environment_target.value]:
            return "SYNTHETIC_SETTINGS_OR_MUTATION"
        top_level_calls = [
            node.value
            for node in tree.body
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
        ]
        all_setups = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and _attr(node.func, "django", "setup")
        ]
        all_migrations = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and _name(node.func, "call_command")
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value == "migrate"
        ]
        if any(
            keyword.arg in {"fake", "fake_initial"}
            for node in all_migrations
            for keyword in node.keywords
        ):
            return "INVALID_PYTHON_OR_MIGRATION_BYPASS"
        if (
            len(all_setups) != 1
            or len(all_migrations) != 1
            or all_setups[0] not in top_level_calls
            or all_migrations[0] not in top_level_calls
            or not settings_assignments[0].lineno
            < all_setups[0].lineno
            < all_migrations[0].lineno
            or len(all_migrations[0].args) != 1
            or any(
                keyword.arg
                not in {"run_syncdb", "verbosity", "interactive", "database"}
                or not isinstance(keyword.value, ast.Constant)
                or (
                    keyword.arg == "run_syncdb"
                    and type(keyword.value.value) is not bool
                )
                or (
                    keyword.arg == "verbosity"
                    and (
                        type(keyword.value.value) is not int
                        or not 0 <= keyword.value.value <= 3
                    )
                )
                or (keyword.arg == "interactive" and keyword.value.value is not False)
                or (keyword.arg == "database" and keyword.value.value != "default")
                for keyword in all_migrations[0].keywords
            )
        ):
            return "SETUP_MIGRATE_ORDER_INVALID"
    setups = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and _attr(node.func, "django", "setup")
    ]
    migrations = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and _name(node.func, "call_command")
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == "migrate"
    ]
    if any(
        keyword.arg in {"fake", "fake_initial"}
        for node in migrations
        for keyword in node.keywords
    ):
        return "INVALID_PYTHON_OR_MIGRATION_BYPASS"
    if (
        len(setups) != 1
        or len(migrations) != 1
        or setups[0].lineno >= migrations[0].lineno
    ):
        return "SETUP_MIGRATE_ORDER_INVALID"
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or node.lineno >= migrations[0].lineno:
            continue
        if not isinstance(node.func, ast.Attribute) or node.func.attr not in {
            "get",
            "post",
            "put",
            "patch",
            "delete",
            "request",
            "open",
        }:
            continue
        receiver = node.func.value
        if (isinstance(receiver, ast.Call) and _name(receiver.func, "Client")) or (
            isinstance(receiver, ast.Name)
            and receiver.id in {"client", "browser", "session", "requests"}
        ):
            return "REQUEST_BEFORE_MIGRATION"
    return None


def django_migration_fixture_replay_forbidden(
    content: bytes,
    *,
    flag: str | None = None,
    app_name: str | None = None,
    project_modules: tuple[str, ...] | None = None,
) -> bool:
    """Preserve the historical Boolean guard for all existing callers."""

    return (
        django_migration_fixture_replay_rejection(
            content,
            flag=flag,
            app_name=app_name,
            project_modules=project_modules,
        )
        is not None
    )


__all__ = [
    "django_migration_graph_project_scan_root",
    "django_migration_graph_settings_omission",
    "django_migration_settings_replay_forbidden",
    "django_migration_fixture_source_gap",
    "django_migration_fixture_source_projection",
    "django_migration_fixture_closed_diagnostic",
    "django_migration_fixture_replay_forbidden",
    "django_migration_fixture_replay_rejection",
    "FixtureReplayReason",
]
