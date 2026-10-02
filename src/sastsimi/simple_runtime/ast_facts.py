from __future__ import annotations

import ast
import hashlib
import json
import os
import stat
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository


def _call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        callee = _call_name(node.func)
        return f"{callee}()" if callee else None
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _call_fact(node: ast.Call, path: str) -> dict[str, object] | None:
    name = _call_name(node.func)
    if name is None:
        return None
    receiver_kind: str | None = None
    if isinstance(node.func, ast.Name):
        callee_kind = "DIRECT"
    elif isinstance(node.func, ast.Attribute):
        callee_kind = "ATTRIBUTE"
        receiver = node.func.value
        if isinstance(receiver, ast.Name):
            receiver_kind = "NAME"
        elif isinstance(receiver, ast.Attribute):
            receiver_kind = "ATTRIBUTE"
        elif isinstance(receiver, ast.Call):
            receiver_kind = "CALL_RESULT"
        else:
            receiver_kind = "OTHER"
    else:
        return None
    attribute_arg_kind: str | None = None
    if callee_kind == "DIRECT" and name == "getattr" and len(node.args) >= 2:
        attribute = node.args[1]
        attribute_arg_kind = (
            "STRING_LITERAL"
            if isinstance(attribute, ast.Constant) and isinstance(attribute.value, str)
            else "NONLITERAL"
        )
    return {
        "kind": "Call",
        "path": path,
        "line": node.lineno,
        "name": name,
        "callee_kind": callee_kind,
        "receiver_kind": receiver_kind,
        "attribute_arg_kind": attribute_arg_kind,
    }


def collect_python_ast(
    workspace: Path,
    tracked: Sequence[str],
    artifacts: SimpleArtifactRepository,
    *,
    max_source_bytes: int,
) -> dict[str, object]:
    """Persist every fact from each safely parsed Python file separately."""

    if max_source_bytes < 1:
        raise ValueError("AST_SOURCE_LIMIT_INVALID")
    root = workspace.resolve(strict=True)
    entries: list[dict[str, object]] = []
    parse_errors: list[str] = []
    oversize_paths: list[str] = []
    fact_count = 0
    for relative in sorted(tracked):
        if not relative.lower().endswith((".py", ".pyi")):
            continue
        path = root / relative
        try:
            before = path.lstat()
            if (
                path.is_symlink()
                or not stat.S_ISREG(before.st_mode)
                or int(getattr(before, "st_file_attributes", 0)) & 0x400
            ):
                raise OSError("AST_SOURCE_NOT_REGULAR")
            resolved = path.resolve(strict=True)
            resolved.relative_to(root)
            if resolved != path:
                raise OSError("AST_SOURCE_PATH_REDIRECTED")
            if before.st_size > max_source_bytes:
                oversize_paths.append(relative)
                continue
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            with os.fdopen(descriptor, "rb") as stream:
                current = os.fstat(stream.fileno())
                if not stat.S_ISREG(current.st_mode) or (
                    before.st_dev,
                    before.st_ino,
                ) != (current.st_dev, current.st_ino):
                    raise OSError("AST_SOURCE_CHANGED")
                raw = stream.read(max_source_bytes + 1)
            if len(raw) > max_source_bytes:
                oversize_paths.append(relative)
                continue
            tree = ast.parse(raw.decode("utf-8"), filename=relative)
        except (OSError, RuntimeError, ValueError, UnicodeError, SyntaxError):
            parse_errors.append(relative)
            continue
        facts: list[dict[str, object]] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                facts.append(
                    {
                        "kind": type(node).__name__,
                        "path": relative,
                        "line": node.lineno,
                        "name": node.name,
                    }
                )
            elif isinstance(node, ast.Call):
                fact = _call_fact(node, relative)
                if fact is not None:
                    facts.append(fact)
        source_sha256 = hashlib.sha256(raw).hexdigest()
        file_ref = artifacts.put_json(
            {
                "kind": "simple_python_ast_file_v2",
                "path": relative,
                "source_sha256": source_sha256,
                "facts": facts,
            }
        )
        entries.append(
            {
                "path": relative,
                "fact_count": len(facts),
                "source_sha256": source_sha256,
                "ref": file_ref.model_dump(mode="json"),
            }
        )
        fact_count += len(facts)
    manifest_ref = artifacts.put_json(
        {
            "kind": "simple_python_ast_manifest_v2",
            "entries": entries,
            "fact_count": fact_count,
            "parsed_file_count": len(entries),
        }
    )
    return {
        "kind": "simple_python_ast",
        "format_version": 3,
        "manifest_ref": manifest_ref.model_dump(mode="json"),
        "fact_count": fact_count,
        "parsed_file_count": len(entries),
        "parse_errors": parse_errors,
        "parse_error_count": len(parse_errors),
        "oversize_paths": oversize_paths,
        "oversize_count": len(oversize_paths),
        "truncated": False,
    }


def _new_manifest(
    artifacts: SimpleArtifactRepository, summary: Mapping[str, object]
) -> list[dict[str, Any]]:
    try:
        version = summary.get("format_version")
        if (
            summary.get("kind") != "simple_python_ast"
            or type(version) is not int
            or version not in {2, 3}
            or summary.get("truncated") is not False
        ):
            raise ValueError("AST_MANIFEST_INVALID")
        expected_files = summary["parsed_file_count"]
        expected_facts = summary["fact_count"]
        if (
            type(expected_files) is not int
            or type(expected_facts) is not int
            or expected_files < 0
            or expected_facts < 0
        ):
            raise ValueError("AST_MANIFEST_INVALID")
        manifest_ref = StoredDataRef.model_validate(summary["manifest_ref"])
        manifest = json.loads(artifacts.read(manifest_ref))
        if (
            not isinstance(manifest, dict)
            or manifest.get("kind") != f"simple_python_ast_manifest_v{version - 1}"
            or manifest.get("parsed_file_count") != expected_files
            or manifest.get("fact_count") != expected_facts
        ):
            raise ValueError("AST_MANIFEST_INVALID")
        entries = manifest.get("entries")
        if not isinstance(entries, list) or len(entries) != expected_files:
            raise ValueError("AST_MANIFEST_INVALID")
        prior_path = ""
        counted = 0
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError("AST_MANIFEST_INVALID")
            path = entry.get("path")
            count = entry.get("fact_count")
            if (
                not isinstance(path, str)
                or not path
                or path <= prior_path
                or path.startswith("/")
                or "\\" in path
                or ".." in Path(path).parts
                or not path.lower().endswith((".py", ".pyi"))
                or type(count) is not int
                or count < 0
            ):
                raise ValueError("AST_MANIFEST_INVALID")
            if version == 3:
                source_sha256 = entry.get("source_sha256")
                if not _valid_sha256(source_sha256):
                    raise ValueError("AST_MANIFEST_INVALID")
            elif "source_sha256" in entry:
                raise ValueError("AST_MANIFEST_INVALID")
            _file_ref(entry)
            counted += count
            prior_path = path
        if counted != expected_facts:
            raise ValueError("AST_MANIFEST_INVALID")
        return entries
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise ValueError("AST_MANIFEST_INVALID") from error


def _file_ref(entry: Mapping[str, object]) -> StoredDataRef:
    ref = StoredDataRef.model_validate(entry["ref"])
    if (
        ref.data_kind != "artifact"
        or ref.record_id is not None
        or str(ref.stored_data_id) != ref.content_hash
    ):
        raise ValueError("AST_MANIFEST_INVALID")
    return ref


def _valid_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _read_file(
    artifacts: SimpleArtifactRepository, entry: Mapping[str, object]
) -> tuple[StoredDataRef, list[dict[str, Any]]]:
    try:
        ref = _file_ref(entry)
        record = json.loads(artifacts.read(ref))
        path = entry["path"]
        facts = record.get("facts") if isinstance(record, dict) else None
        current = "source_sha256" in entry
        if (
            not isinstance(record, dict)
            or record.get("kind")
            != ("simple_python_ast_file_v2" if current else "simple_python_ast_file_v1")
            or record.get("path") != path
            or (
                current
                and (
                    record.get("source_sha256") != entry["source_sha256"]
                    or not _valid_sha256(record.get("source_sha256"))
                )
            )
            or (not current and "source_sha256" in record)
            or not isinstance(facts, list)
            or len(facts) != entry["fact_count"]
        ):
            raise ValueError("AST_MANIFEST_INVALID")
        for fact in facts:
            if (
                not isinstance(fact, dict)
                or fact.get("kind")
                not in {"FunctionDef", "AsyncFunctionDef", "ClassDef", "Call"}
                or fact.get("path") != path
                or type(fact.get("line")) is not int
                or fact["line"] < 1
                or not isinstance(fact.get("name"), str)
                or not fact["name"]
            ):
                raise ValueError("AST_MANIFEST_INVALID")
            if current and fact["kind"] == "Call" and (
                fact.get("callee_kind") not in {"DIRECT", "ATTRIBUTE"}
                or fact.get("receiver_kind")
                not in {None, "NAME", "ATTRIBUTE", "CALL_RESULT", "OTHER"}
                or (
                    fact["callee_kind"] == "DIRECT"
                    and fact.get("receiver_kind") is not None
                )
                or (
                    fact["callee_kind"] == "ATTRIBUTE"
                    and fact.get("receiver_kind") is None
                )
                or fact.get("attribute_arg_kind")
                not in {None, "STRING_LITERAL", "NONLITERAL"}
            ):
                raise ValueError("AST_MANIFEST_INVALID")
        return ref, facts
    except (OSError, ValueError, TypeError, KeyError) as error:
        raise ValueError("AST_MANIFEST_INVALID") from error


def validate_ast_manifest(
    artifacts: SimpleArtifactRepository, summary: Mapping[str, object]
) -> None:
    """Verify every exact file artifact; legacy inline summaries stay readable."""

    if "format_version" not in summary:
        if "manifest_ref" in summary or not isinstance(summary.get("facts"), list):
            raise ValueError("AST_MANIFEST_INVALID")
        return
    for entry in _new_manifest(artifacts, summary):
        _read_file(artifacts, entry)


def index_ast_manifest(
    artifacts: SimpleArtifactRepository, summary: Mapping[str, object]
) -> dict[str, dict[str, Any]]:
    """Build one validated path lookup for a candidate pipeline pass."""

    return {str(entry["path"]): entry for entry in _new_manifest(artifacts, summary)}


def read_ast_file_facts(
    artifacts: SimpleArtifactRepository,
    summary: Mapping[str, object],
    path: str,
    *,
    manifest_index: Mapping[str, Mapping[str, object]] | None = None,
) -> tuple[StoredDataRef | None, tuple[dict[str, Any], ...], str | None]:
    """Read one fully validated file artifact, or name its explicit gap."""

    entry = (
        manifest_index.get(path)
        if manifest_index is not None
        else index_ast_manifest(artifacts, summary).get(path)
    )
    if entry is not None:
        ref, facts = _read_file(artifacts, entry)
        return ref, tuple(facts), None
    parse_errors = summary.get("parse_errors")
    oversize_paths = summary.get("oversize_paths")
    if isinstance(parse_errors, list) and path in parse_errors:
        return None, (), "AST_PARSE_ERROR"
    if isinstance(oversize_paths, list) and path in oversize_paths:
        return None, (), "AST_SOURCE_TOO_LARGE"
    raise ValueError("AST_FOCUS_PATH_UNKNOWN")


def focus_ast_facts(
    artifacts: SimpleArtifactRepository,
    summary: Mapping[str, object],
    *,
    path: str,
    line: int,
    max_bytes: int = 8192,
    manifest_index: Mapping[str, Mapping[str, object]] | None = None,
) -> dict[str, object]:
    """Return one file's nearest facts without passing its manifest to the Agent."""

    if max_bytes < 512 or type(line) is not int:
        raise ValueError("AST_FOCUS_BUDGET_INVALID")
    entry = (
        manifest_index.get(path)
        if manifest_index is not None
        else next(
            (
                item
                for item in _new_manifest(artifacts, summary)
                if item["path"] == path
            ),
            None,
        )
    )
    if entry is None:
        errors = summary.get("parse_errors")
        oversize = summary.get("oversize_paths")
        if path == "":
            reason = "CANDIDATE_LOCATION_UNAVAILABLE"
        elif isinstance(errors, list) and path in errors:
            reason = "AST_PARSE_ERROR"
        elif isinstance(oversize, list) and path in oversize:
            reason = "AST_SOURCE_TOO_LARGE"
        else:
            raise ValueError("AST_FOCUS_PATH_UNKNOWN")
        unavailable: dict[str, object] = {
            "kind": "simple_python_ast_focus_v1",
            "status": "UNAVAILABLE",
            "path": path,
            "line": line,
            "reason": reason,
            "file_ref": None,
            "facts": [],
            "total_count": None,
            "omitted_count": None,
        }
        if len(canonical_bytes(unavailable)) > max_bytes:
            raise ValueError("AST_FOCUS_BUDGET_TOO_SMALL")
        return unavailable
    ref, facts = _read_file(artifacts, entry)
    base: dict[str, object] = {
        "kind": "simple_python_ast_focus_v1",
        "status": "AVAILABLE",
        "path": path,
        "line": line,
        "file_ref": ref.model_dump(mode="json"),
        "facts": [],
        "total_count": len(facts),
        "omitted_count": len(facts),
    }
    if len(canonical_bytes(base)) > max_bytes:
        raise ValueError("AST_FOCUS_BUDGET_TOO_SMALL")
    selected: list[int] = []
    by_distance = sorted(
        range(len(facts)),
        key=lambda index: (abs(int(facts[index]["line"]) - line), index),
    )
    for index in by_distance:
        proposed = sorted((*selected, index))
        base["facts"] = [facts[item] for item in proposed]
        base["omitted_count"] = len(facts) - len(proposed)
        if len(canonical_bytes(base)) > max_bytes:
            break
        selected = proposed
    base["facts"] = [facts[index] for index in selected]
    base["omitted_count"] = len(facts) - len(selected)
    if facts and not selected:
        raise ValueError("AST_FOCUS_BUDGET_TOO_SMALL")
    return base
