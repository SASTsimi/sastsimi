"""Shared validation contract for executable shell PoC candidates."""

from __future__ import annotations

import ast
import json
import re
from urllib.parse import urlsplit

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.prompt_redaction import inspect_poc_candidate_json

_SHELL_VARIABLE = re.compile(
    rb"\$(?:\{(?P<braced>[A-Za-z_][A-Za-z0-9_]*)(?::[-=?+][^}]*)?\}|"
    rb"(?P<plain>[A-Za-z_][A-Za-z0-9_]*))"
)
_SHELL_ASSIGNMENT = re.compile(
    rb"(?m)^[ \t]*(?:export[ \t]+|readonly[ \t]+)?"
    rb"(?P<name>[A-Za-z_][A-Za-z0-9_]*)="
)
_SHELL_EXPORTED_ASSIGNMENT = re.compile(
    rb"(?m)^[ \t]*export[ \t]+(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:=|(?=[ \t]*$))"
)
_HEREDOC_WORD = re.compile(rb"[A-Za-z_][A-Za-z0-9_]*")
_DIRECT_PYTHON_STDIN = re.compile(
    rb"(?:[A-Za-z_][A-Za-z0-9_]*=(?:[A-Za-z0-9_./-]+|\$[A-Za-z_][A-Za-z0-9_]*)[ \t]+)*"
    rb"(?:exec[ \t]+)?python(?:3(?:\.[0-9]+)?)?"
    rb"(?:[ \t]+-(?:B|E|I|S|s|u|q))*[ \t]+-"
    rb'(?:[ \t]+"\$[A-Za-z_][A-Za-z0-9_]*")*'
)
_URL = re.compile(rb"https?://[^\s'\"<>]+", re.IGNORECASE)
_WINDOWS_PATH = re.compile(rb"(?:(?<![A-Za-z0-9_])[A-Za-z]:[\\/]|\\\\)[^\r\n]+")
_FORBIDDEN_HOST_PATHS = (
    b"/var/run/docker.sock",
    b"/run/docker.sock",
    b"/root/",
    b"/home/",
    b"/Users/",
)
_SAFE_PROCESS_VARIABLES = frozenset(
    {"PATH", "PYTHONPATH", "LANG", "LC_ALL", "TMPDIR", "PWD"}
)


class PoCCandidateRejected(ValueError):
    pass


def _python_may_launch_shell(parsed: ast.AST) -> bool:
    shell_calls = {
        "system",
        "popen",
        "create_subprocess_shell",
        "eval",
        "exec",
        "getattr",
        "__import__",
    }
    process_calls = {"run", "Popen", "call", "check_call", "check_output"}
    for node in ast.walk(parsed):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(
            node.value, ast.Attribute
        ):
            if node.value.attr in process_calls:
                return True
        if isinstance(node, ast.Attribute) and node.attr in shell_calls:
            return True
        if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant):
            if node.slice.value in shell_calls:
                return True
        if not isinstance(node, ast.Call):
            continue
        name = (
            node.func.id
            if isinstance(node.func, ast.Name)
            else node.func.attr
            if isinstance(node.func, ast.Attribute)
            else None
        )
        if name in shell_calls:
            return True
        if any(
            keyword.arg == "shell"
            and not (
                isinstance(keyword.value, ast.Constant) and keyword.value.value is False
            )
            for keyword in node.keywords
        ):
            return True
        if name in process_calls and node.args:
            command = node.args[0]
            if isinstance(command, (ast.List, ast.Tuple)):
                words = [
                    item.value
                    for item in command.elts
                    if isinstance(item, ast.Constant) and isinstance(item.value, str)
                ]
                if (
                    words
                    and words[0] in {"sh", "bash", "dash", "zsh"}
                    and "-c" in words
                ):
                    return True
    return False


def _heredocs_on_line(
    line: bytes,
) -> tuple[list[tuple[bytes, bool, bool]], bool] | None:
    """Find simple here-doc redirections outside quotes and comments."""

    if b"<<" in line and (b"$(" in line or b"`" in line):
        return None  # Nested shell syntax needs a full parser.
    found: list[tuple[bytes, bool, bool]] = []
    redirections: list[tuple[int, int]] = []
    quote: int | None = None
    comment_at = len(line)
    index = 0
    while index < len(line):
        current = line[index]
        if quote is not None:
            if current == quote:
                quote = None
            elif quote == ord('"') and current == ord("\\"):
                index += 1
            index += 1
            continue
        if current == ord("\\"):
            if index + 1 >= len(line) or line[index + 1] == ord("\n"):
                return None
            index += 2
            continue
        if current in (ord("'"), ord('"')):
            quote = current
            index += 1
            continue
        if current == ord("#") and (index == 0 or line[index - 1] in b" \t;|&(){}<>"):
            comment_at = index
            break
        if line[index : index + 2] != b"<<":
            index += 1
            continue
        if line[index : index + 3] == b"<<<":
            return None
        position = index + 2
        strip_tabs = line[position : position + 1] == b"-"
        if strip_tabs:
            position += 1
        while line[position : position + 1] in (b" ", b"\t"):
            position += 1
        literal = line[position : position + 1] in (b"'", b'"', b"\\")
        if line[position : position + 1] in (b"'", b'"'):
            end = line.find(line[position : position + 1], position + 1)
            if end < 0:
                return None
            delimiter = line[position + 1 : end]
            position = end + 1
        else:
            if line[position : position + 1] == b"\\":
                position += 1
            match = _HEREDOC_WORD.match(line, position)
            if match is None:
                return None
            delimiter = match.group()
            position = match.end()
        if _HEREDOC_WORD.fullmatch(delimiter) is None or (
            position < len(line) and line[position] not in b" \t\n;|&()<>"
        ):
            return None
        found.append((delimiter, literal, strip_tabs))
        redirections.append((index, position))
        index = position
    if quote is not None:
        return None
    direct_python = False
    if any(literal for _, literal, _ in found):
        command = line[:comment_at]
        for start, end in reversed(redirections):
            command = command[:start] + b" " + command[end:]
        direct_python = (
            _DIRECT_PYTHON_STDIN.fullmatch(command.strip(b" \t\n")) is not None
        )
    return found, direct_python


def _python_heredoc_variables(body: bytes) -> bytes:
    """Ignore literal dictionary keys, not arbitrary Python string contents."""

    if _SHELL_VARIABLE.search(body) is None:
        return b""
    try:
        parsed = ast.parse(body.decode("utf-8"))
    except (UnicodeDecodeError, SyntaxError) as exc:
        raise PoCCandidateRejected("POC_UNDECLARED_INPUT") from exc
    if _python_may_launch_shell(parsed):
        return body
    masked = bytearray(body)
    lines = body.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))
    for node in ast.walk(parsed):
        if not isinstance(node, ast.Dict):
            continue
        for key in node.keys:
            if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
                continue
            if key.end_lineno is None or key.end_col_offset is None:
                continue
            start = offsets[key.lineno - 1] + key.col_offset
            end = offsets[key.end_lineno - 1] + key.end_col_offset
            masked[start:end] = b" " * (end - start)
    return bytes(masked)


def _shell_scan_sources(content: bytes) -> tuple[bytes, bytes, tuple[bytes, ...]]:
    """Return parent shell, expanding text, and separately scoped child bodies."""

    if b"<<" not in content:
        return content, content, ()
    shell = bytearray()
    expanding = bytearray()
    python_body = bytearray()
    nested_body = bytearray()
    nested_bodies: list[bytes] = []
    pending: list[tuple[bytes, bool, bool, bool]] = []
    for line in content.splitlines(keepends=True):
        if pending:
            delimiter, literal, strip_tabs, direct_python = pending[0]
            word = line.removesuffix(b"\n")
            if strip_tabs:
                word = word.lstrip(b"\t")
            if word == delimiter:
                if direct_python:
                    expanding.extend(_python_heredoc_variables(bytes(python_body)))
                elif literal:
                    nested_bodies.append(bytes(nested_body))
                python_body.clear()
                nested_body.clear()
                pending.pop(0)
                shell.extend(line)
                expanding.extend(line)
            elif not literal:
                expanding.extend(line)
            elif direct_python:
                python_body.extend(line)
            else:
                # A quoted body might be piped into a child shell. Its local
                # assignments must not leak into the parent shell's scope.
                nested_body.extend(line)
            continue
        shell.extend(line)
        expanding.extend(line)
        new = _heredocs_on_line(line)
        if new is None:
            raise PoCCandidateRejected("POC_UNDECLARED_INPUT")
        heredocs, direct_python = new
        pending.extend(
            (delimiter, literal, strip_tabs, direct_python)
            for delimiter, literal, strip_tabs in heredocs
        )
    if pending:
        raise PoCCandidateRejected("POC_UNDECLARED_INPUT")
    return bytes(shell), bytes(expanding), tuple(nested_bodies)


def validate_candidate(
    content: bytes,
    *,
    allowed_environment_names: frozenset[str],
) -> bool:
    """Reject placeholder or host-dependent PoC scripts before Docker execution."""

    if not content.startswith(b"#!/bin/sh\n"):
        raise PoCCandidateRejected("POC_SHEBANG_REQUIRED")
    if b"\x00" in content or b"\r" in content:
        raise PoCCandidateRejected("POC_CONTENT_ENCODING_INVALID")
    if _WINDOWS_PATH.search(content) or any(
        path in content for path in _FORBIDDEN_HOST_PATHS
    ):
        raise PoCCandidateRejected("POC_HOST_PATH_FORBIDDEN")
    for match in _URL.finditer(content):
        host = (urlsplit(match.group().decode("utf-8")).hostname or "").lower()
        if host not in {"127.0.0.1", "localhost", "0.0.0.0"}:
            raise PoCCandidateRejected("POC_EXTERNAL_URL_FORBIDDEN")
    shell, expanding, nested_bodies = _shell_scan_sources(content)
    declared = {
        match.group("name").decode("ascii")
        for match in _SHELL_ASSIGNMENT.finditer(shell)
    }
    allowed = _SAFE_PROCESS_VARIABLES | allowed_environment_names | declared
    exported = {
        match.group("name").decode("ascii")
        for match in _SHELL_EXPORTED_ASSIGNMENT.finditer(shell)
    }
    variables = {
        (match.group("braced") or match.group("plain")).decode("ascii")
        for match in _SHELL_VARIABLE.finditer(expanding)
    }
    if variables - allowed:
        raise PoCCandidateRejected("POC_UNDECLARED_INPUT")
    for body in nested_bodies:
        child_declared = {
            match.group("name").decode("ascii")
            for match in _SHELL_ASSIGNMENT.finditer(body)
        }
        child_variables = {
            (match.group("braced") or match.group("plain")).decode("ascii")
            for match in _SHELL_VARIABLE.finditer(body)
        }
        if child_variables - (
            _SAFE_PROCESS_VARIABLES
            | allowed_environment_names
            | exported
            | child_declared
        ):
            raise PoCCandidateRejected("POC_UNDECLARED_INPUT")
    lowered = content.lower()
    if b"inconclusive" in lowered and re.search(rb"\bexit\s+2\b", lowered):
        raise PoCCandidateRejected("POC_PLACEHOLDER_FORBIDDEN")
    inspected = inspect_poc_candidate_json(
        canonical_bytes({"content": content.decode("utf-8")})
    )
    if inspected.categories:
        raise PoCCandidateRejected("POC_SENSITIVE_CONTENT")
    value = json.loads(inspected.data)
    if value.get("content", "").encode("utf-8") != content:
        raise PoCCandidateRejected("POC_SENSITIVE_CONTENT")
    return True


__all__ = ["PoCCandidateRejected", "validate_candidate"]
