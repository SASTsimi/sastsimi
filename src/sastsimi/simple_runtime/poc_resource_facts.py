"""Small commit-pinned route facts for PoC context, never static coverage."""

from __future__ import annotations

import ast
import hashlib
import posixpath
import re
import subprocess
import threading
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from functools import lru_cache
from pathlib import Path, PurePosixPath

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.prompt_redaction import redact_projected_json

from .retrieval import _read_pinned_blob

_MAX_PYTHON_FILES = 24
_MAX_CITED_PYTHON_FILES = 8
_MAX_XML_LOADER_FILES = 16
_MAX_XML_REFERENCE_PROBES = 24
_MAX_PYTHON_FILE_BYTES = 128 * 1024
_MAX_PYTHON_TOTAL_BYTES = 1024 * 1024
_MAX_XML_INDEX_BYTES = 256 * 1024
_MAX_XML_INDEX_RECORD_BYTES = 1024
_MAX_XML_FILES = 4
_MAX_XML_PROBES = 16
_MAX_XML_BYTES = 32 * 1024
_MAX_FACT_BYTES = 8 * 1024
_MAX_ROUTE_FACTS = 8
_SAFE_CLASS = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_SAFE_ROUTE = re.compile(r"/[A-Za-z0-9_./-]{0,127}\Z")
_COMMIT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


class _IndexUnavailable(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _TransientBlobError(Exception):
    pass


def _safe_path(path: str) -> bool:
    pure = PurePosixPath(path)
    return (
        bool(path)
        and len(path) <= 240
        and not pure.is_absolute()
        and ".." not in pure.parts
        and "\\" not in path
        and ":" not in path
        and "\x00" not in path
        and all(ord(char) >= 32 for char in path)
    )


@lru_cache(maxsize=8)
def _pinned_xml_reference_index(
    workspace: str,
    commit: str,
    git_executable: str,
    manifest_digest: str,
    manifest_paths: frozenset[str],
) -> tuple[str, ...]:
    """List pinned Python paths mentioning XML, without reading their contents."""

    del manifest_digest  # The digest partitions cache entries by static manifest.
    if not _COMMIT_ID.fullmatch(commit):
        raise _IndexUnavailable("PYTHON_INDEX_INVALID")
    exact_paths = tuple(sorted(manifest_paths))
    use_exact_paths = (
        len(exact_paths) <= 64
        and sum(len(path.encode("utf-8")) + 1 for path in exact_paths) <= 8192
    )
    command = (
        git_executable,
        "-C",
        workspace,
        "-c",
        "color.grep=false",
        *(("--literal-pathspecs",) if use_exact_paths else ()),
        "grep",
        "-l",
        "-z",
        "--all-match",
        "-i",
        "-F",
        "-e",
        ".xml",
        "-e",
        "parse",
        commit,
        "--",
        *(exact_paths if use_exact_paths else ("*.py",)),
    )
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        raise _IndexUnavailable("PYTHON_INDEX_UNAVAILABLE") from exc
    timed_out = threading.Event()

    def kill_on_timeout() -> None:
        if process.poll() is None:
            timed_out.set()
            try:
                process.kill()
            except OSError:
                pass

    timer = threading.Timer(10, kill_on_timeout)
    timer.daemon = True
    timer.start()
    try:
        if process.stdout is None:
            raise _IndexUnavailable("PYTHON_INDEX_UNAVAILABLE")
        prefix = commit.encode("ascii") + b":"
        paths: set[str] = set()
        selected_bytes = 0
        pending = bytearray()
        dropping_long_record = False
        while chunk := process.stdout.read(4096):
            fragments = chunk.split(b"\0")
            for index, fragment in enumerate(fragments):
                terminated = index < len(fragments) - 1
                if dropping_long_record:
                    if terminated:
                        dropping_long_record = False
                    continue
                if len(pending) + len(fragment) > _MAX_XML_INDEX_RECORD_BYTES:
                    pending.clear()
                    dropping_long_record = not terminated
                    continue
                pending.extend(fragment)
                if not terminated:
                    continue
                item = bytes(pending)
                pending.clear()
                if not item.startswith(prefix):
                    raise _IndexUnavailable("PYTHON_INDEX_INVALID")
                try:
                    path = item[len(prefix) :].decode("utf-8")
                except UnicodeError:
                    continue
                if path not in manifest_paths:
                    continue
                if not path.endswith(".py") or not _safe_path(path):
                    raise _IndexUnavailable("PYTHON_INDEX_INVALID")
                selected_bytes += len(item) + 1
                if selected_bytes > _MAX_XML_INDEX_BYTES:
                    raise _IndexUnavailable("PYTHON_INDEX_BYTE_LIMIT")
                paths.add(path)
        returncode = process.wait()
        if timed_out.is_set():
            raise _IndexUnavailable("PYTHON_INDEX_TIMEOUT")
        if pending or dropping_long_record:
            raise _IndexUnavailable("PYTHON_INDEX_INVALID")
        if returncode == 1:
            return ()
        if returncode != 0:
            raise _IndexUnavailable("PYTHON_INDEX_UNAVAILABLE")
        return tuple(sorted(paths))
    except OSError as exc:
        raise _IndexUnavailable("PYTHON_INDEX_UNAVAILABLE") from exc
    finally:
        timer.cancel()
        if process.poll() is None:
            try:
                process.kill()
            except OSError:
                pass
        process.wait()
        if process.stdout is not None:
            process.stdout.close()


@lru_cache(maxsize=128)
def _cached_pinned_blob(
    workspace: str,
    path: str,
    commit: str,
    git_executable: str,
    remaining: int,
) -> tuple[bytes | None, str | None]:
    result = _read_pinned_blob(
        Path(workspace),
        path,
        commit=commit,
        git_executable=git_executable,
        remaining=remaining,
    )
    if result[1] == "PINNED_SOURCE_UNAVAILABLE":
        raise _TransientBlobError
    return result


def _pinned_blob(
    workspace: str,
    path: str,
    commit: str,
    git_executable: str,
    remaining: int,
) -> tuple[bytes | None, str | None]:
    try:
        return _cached_pinned_blob(workspace, path, commit, git_executable, remaining)
    except _TransientBlobError:
        return None, "PINNED_SOURCE_UNAVAILABLE"


def _candidate_symbols(
    source: ast.AST, path: str, cited_locations: Sequence[str]
) -> set[str]:
    cited_lines = {
        int(number)
        for location in cited_locations
        for location_path, separator, number in [location.rpartition(":")]
        if separator
        and location_path == path
        and number.isascii()
        and number.isdecimal()
    }
    symbols: set[str] = set()
    for line in cited_lines:
        containing = [
            node
            for node in ast.walk(source)
            if isinstance(node, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
            and node.lineno <= line <= (node.end_lineno or node.lineno)
        ]
        classes = [node for node in containing if isinstance(node, ast.ClassDef)]
        choices = classes or containing
        if choices:
            chosen = min(
                choices,
                key=lambda node: (node.end_lineno or node.lineno) - node.lineno,
            )
            if _SAFE_CLASS.fullmatch(chosen.name):
                symbols.add(chosen.name)
    return symbols


def _xml_parse_aliases(source: ast.AST) -> tuple[set[str], set[str]]:
    modules: set[str] = set()
    functions: set[str] = set()
    for node in ast.walk(source):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "xml.etree.ElementTree":
                    modules.add(alias.asname or "xml")
        elif isinstance(node, ast.ImportFrom):
            if node.module == "xml.etree":
                modules.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name == "ElementTree"
                )
            elif node.module == "xml.etree.ElementTree":
                functions.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name == "parse"
                )
    return modules, functions


def _literal_xml_paths(source: ast.AST) -> set[str]:
    found: set[str] = set()
    modules, functions = _xml_parse_aliases(source)
    for node in ast.walk(source):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        func = node.func
        is_parse = (
            isinstance(func, ast.Name)
            and func.id in functions
            or isinstance(func, ast.Attribute)
            and func.attr == "parse"
            and (
                isinstance(func.value, ast.Name)
                and func.value.id in modules
                or isinstance(func.value, ast.Attribute)
                and isinstance(func.value.value, ast.Attribute)
                and isinstance(func.value.value.value, ast.Name)
                and func.value.value.value.id in modules
                and func.value.value.attr == "etree"
                and func.value.attr == "ElementTree"
            )
        )
        if not is_parse:
            continue
        item = node.args[0]
        if (
            isinstance(item, ast.Constant)
            and isinstance(item.value, str)
            and item.value.lower().endswith(".xml")
        ):
            found.add(item.value)
    return found


def _resolved_xml_paths(source_path: str, literal: str) -> tuple[str, ...]:
    if (
        not literal
        or len(literal) > 160
        or literal.startswith(("/", "\\"))
        or "\\" in literal
        or ":" in literal
        or any(ord(char) < 32 for char in literal)
    ):
        return ()
    paths = (
        posixpath.normpath(literal),
        posixpath.normpath(posixpath.join(posixpath.dirname(source_path), literal)),
    )
    return tuple(dict.fromkeys(path for path in paths if _safe_path(path)))


def _routes_from_xml(raw: bytes, symbols: set[str]) -> list[dict[str, str]] | None:
    if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        return None
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return None
    if len(root) > 128:
        return None
    routes: list[dict[str, str]] = []
    for record in root:
        class_nodes = [child for child in record if child.tag == "class"]
        route_nodes = [child for child in record if child.tag == "route"]
        if len(class_nodes) != 1 or len(route_nodes) != 1:
            continue
        class_node, route_node = class_nodes[0], route_nodes[0]
        if len(class_node) or len(route_node):
            continue
        class_name, route = class_node.text, route_node.text
        if (
            class_name is None
            or route is None
            or not _SAFE_CLASS.fullmatch(class_name)
            or not _SAFE_ROUTE.fullmatch(route)
            or route.startswith("//")
            or ".." in PurePosixPath(route).parts
            or class_name not in symbols
        ):
            continue
        routes.append({"class": class_name, "route": route})
    if len(routes) != len({item["class"] for item in routes}):
        return None
    return routes


def collect_poc_resource_facts(
    *,
    workspace: Path,
    commit: str,
    tracked_python_paths: Sequence[str],
    cited_locations: Sequence[str],
    git_executable: str = "git",
) -> dict[str, object] | None:
    """Extract only safe class→route scalars from tracked XML referenced by Python."""

    available_python_paths = {
        path
        for path in set(tracked_python_paths)
        if path.endswith(".py") and _safe_path(path)
    }
    cited_python_paths = sorted(
        {
            path
            for location in cited_locations
            for path, separator, number in [location.rpartition(":")]
            if separator
            and path in available_python_paths
            and number.isascii()
            and number.isdecimal()
            and int(number) > 0
        }
    )
    if not available_python_paths:
        return None
    workspace_key = str(workspace.resolve())
    manifest_digest = hashlib.sha256(
        "\0".join(sorted(available_python_paths)).encode("utf-8")
    ).hexdigest()
    try:
        indexed_paths = _pinned_xml_reference_index(
            workspace_key,
            commit,
            git_executable,
            manifest_digest,
            frozenset(available_python_paths),
        )
        index_reason: str | None = None
    except _IndexUnavailable as exc:
        indexed_paths = ()
        index_reason = exc.reason
    loader_paths = sorted(
        set(indexed_paths)
        .intersection(available_python_paths)
        .difference(cited_python_paths)
    )
    truncated = index_reason is not None
    omitted_reason: str | None = index_reason
    if len(cited_python_paths) > _MAX_CITED_PYTHON_FILES:
        truncated = True
        omitted_reason = omitted_reason or "CITED_FILE_LIMIT"
    if len(loader_paths) > _MAX_XML_REFERENCE_PROBES:
        truncated = True
        omitted_reason = omitted_reason or "XML_REFERENCE_PROBE_LIMIT"
    cited_to_scan = cited_python_paths[:_MAX_CITED_PYTHON_FILES]
    python_paths = cited_to_scan + loader_paths[:_MAX_XML_REFERENCE_PROBES]
    sources: dict[str, tuple[ast.AST, bytes]] = {}
    total = 0
    loader_count = 0
    for path in python_paths:
        remaining = min(_MAX_PYTHON_FILE_BYTES, _MAX_PYTHON_TOTAL_BYTES - total)
        if remaining <= 0:
            truncated = True
            omitted_reason = omitted_reason or "PYTHON_BYTE_LIMIT"
            break
        raw, reason = _pinned_blob(
            workspace_key,
            path,
            commit,
            git_executable,
            remaining,
        )
        if reason == "TOTAL_BUDGET_EXHAUSTED":
            truncated = True
            omitted_reason = omitted_reason or "PYTHON_BYTE_LIMIT"
            continue
        if reason is not None or raw is None:
            truncated = True
            omitted_reason = omitted_reason or "PYTHON_SOURCE_UNAVAILABLE"
            continue
        total += len(raw)
        try:
            parsed_tree = ast.parse(raw.decode("utf-8"), filename=path)
        except (SyntaxError, UnicodeError):
            truncated = True
            omitted_reason = omitted_reason or "PYTHON_AST_UNAVAILABLE"
            continue
        if path not in cited_to_scan:
            if not _literal_xml_paths(parsed_tree):
                continue
            if loader_count >= _MAX_XML_LOADER_FILES:
                truncated = True
                omitted_reason = omitted_reason or "XML_REFERENCE_FILE_LIMIT"
                continue
            loader_count += 1
        if len(sources) >= _MAX_PYTHON_FILES:
            truncated = True
            omitted_reason = omitted_reason or "PYTHON_FILE_LIMIT"
            continue
        sources[path] = (parsed_tree, raw)
    symbols = {
        symbol
        for path, (tree, _raw) in sources.items()
        for symbol in _candidate_symbols(tree, path, cited_locations)
    }
    if not symbols:
        return (
            {
                "kind": "simple_poc_resource_facts_v1",
                "commit_id": commit,
                "routes": [],
                "resources": [],
                "truncated": truncated,
                "omitted_reason": omitted_reason or "CITED_SYMBOL_UNAVAILABLE",
            }
            if truncated
            else None
        )
    if len(symbols) > _MAX_ROUTE_FACTS:
        truncated = True
        omitted_reason = "SYMBOL_LIMIT"
        symbols = set(sorted(symbols)[:_MAX_ROUTE_FACTS])

    routes: list[dict[str, str]] = []
    resources: list[dict[str, object]] = []
    seen_xml: set[str] = set()
    probed_xml: set[str] = set()
    for source_path, (tree, source_raw) in sources.items():
        for literal in sorted(_literal_xml_paths(tree)):
            verified_literal = False
            unavailable_reasons: set[str] = set()
            for xml_path in _resolved_xml_paths(source_path, literal):
                if xml_path in probed_xml:
                    continue
                if len(probed_xml) >= _MAX_XML_PROBES:
                    truncated = True
                    omitted_reason = "XML_PROBE_LIMIT"
                    break
                if len(seen_xml) >= _MAX_XML_FILES:
                    truncated = True
                    omitted_reason = "XML_FILE_LIMIT"
                    break
                probed_xml.add(xml_path)
                xml_raw, reason = _pinned_blob(
                    workspace_key,
                    xml_path,
                    commit,
                    git_executable,
                    _MAX_XML_BYTES,
                )
                if reason == "TOTAL_BUDGET_EXHAUSTED":
                    truncated = True
                    omitted_reason = "XML_BYTE_LIMIT"
                    continue
                if reason is not None or xml_raw is None:
                    unavailable_reasons.add(reason or "PINNED_SOURCE_UNAVAILABLE")
                    continue
                verified_literal = True
                seen_xml.add(xml_path)
                selected = _routes_from_xml(xml_raw, symbols)
                if selected is None:
                    omitted_reason = omitted_reason or "XML_UNSUPPORTED"
                    continue
                if selected:
                    routes.extend(
                        {**item, "resource_path": xml_path} for item in selected
                    )
                    resources.append(
                        {
                            "path": xml_path,
                            "sha256": hashlib.sha256(xml_raw).hexdigest(),
                            "referenced_by": {
                                "path": source_path,
                                "sha256": hashlib.sha256(source_raw).hexdigest(),
                            },
                        }
                    )
            if not verified_literal and unavailable_reasons and omitted_reason is None:
                if "PATH_OUTSIDE_REPOSITORY" in unavailable_reasons:
                    omitted_reason = "XML_NOT_REGULAR"
                elif "PINNED_SOURCE_UNAVAILABLE" in unavailable_reasons:
                    omitted_reason = "XML_UNAVAILABLE"
                else:
                    omitted_reason = "XML_NOT_TRACKED"
    route_by_class: dict[str, dict[str, str]] = {}
    for item in routes:
        existing = route_by_class.setdefault(item["class"], item)
        if existing["route"] != item["route"]:
            routes = []
            resources = []
            omitted_reason = "AMBIGUOUS_ROUTE"
            break
    else:
        routes = list(route_by_class.values())
        if len(routes) > _MAX_ROUTE_FACTS:
            truncated = True
            omitted_reason = "ROUTE_FACT_LIMIT"
            routes = routes[:_MAX_ROUTE_FACTS]
    if truncated or omitted_reason is not None:
        # An unseen/unsupported XML record could map a class to a different route.
        routes = []
        resources = []
    result: dict[str, object] = {
        "kind": "simple_poc_resource_facts_v1",
        "commit_id": commit,
        "routes": routes,
        "resources": resources,
        "truncated": truncated,
    }
    if omitted_reason is not None:
        result["omitted_reason"] = omitted_reason
    if not routes and not truncated and omitted_reason is None:
        return None
    encoded = canonical_bytes(result)
    if len(encoded) > _MAX_FACT_BYTES or redact_projected_json(encoded).data != encoded:
        return None
    return result
