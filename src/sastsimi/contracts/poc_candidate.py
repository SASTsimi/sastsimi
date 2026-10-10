"""Shared validation contract for executable shell PoC candidates."""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.prompt_redaction import (
    inspect_poc_candidate_json,
    poc_candidate_sensitive_rule_id,
)

_SHELL_VARIABLE = re.compile(
    rb"\$(?:\{#?(?P<braced>[A-Za-z_][A-Za-z0-9_]*)|"
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
_EXIT_ZERO_LINE = re.compile(rb"exit[ \t]+0(?:[ \t]*#.*)?")
_IF_LINE = re.compile(rb"if[ \t]+.+;[ \t]*then")
_ELIF_LINE = re.compile(rb"elif[ \t]+.+;[ \t]*then")
_INCONCLUSIVE_MARKER = b"SASTSIMI_POC_INCONCLUSIVE"

# Bump only when the meaning of candidate validation changes. Explicit
# code-fix replays may not run twice against the same validator revision.
POC_CANDIDATE_VALIDATOR_REVISION = "2026-10-07-4"


class PoCCandidateRejected(ValueError):
    pass


def candidate_rejection_diagnostic(content: bytes, code: str) -> dict[str, str | int]:
    """Describe a rejected script using only closed enums and numeric shape data."""

    reason = {
        "POC_PLACEHOLDER_FORBIDDEN": "INCONCLUSIVE_EXIT2_UNPROVEN",
        "POC_SHEBANG_REQUIRED": "SHEBANG_MISSING",
        "POC_CONTENT_ENCODING_INVALID": "ENCODING_INVALID",
        "POC_HOST_PATH_FORBIDDEN": "HOST_RESOURCE_FORBIDDEN",
        "POC_EXTERNAL_URL_FORBIDDEN": "NETWORK_RESOURCE_FORBIDDEN",
        "POC_UNDECLARED_INPUT": "UNDECLARED_INPUT",
        "POC_SENSITIVE_CONTENT": "SENSITIVE_CONTENT",
    }.get(code, "OTHER_VALIDATOR_REJECTION")
    lines = tuple(line.strip() for line in content.splitlines())
    try:
        shell, _, _ = _shell_scan_sources(content)
    except PoCCandidateRejected:
        shell = content
    diagnostic: dict[str, str | int] = {
        "reason": reason,
        "line_count": len(lines),
        "branch_count": sum(
            _IF_LINE.fullmatch(line) is not None
            or _ELIF_LINE.fullmatch(line) is not None
            or line == b"else"
            for line in lines
        ),
        "inconclusive_line_count": sum(
            b"inconclusive" in line.lower() for line in lines
        ),
        "exit_two_line_count": sum(
            _has_exit_two_command(line) for line in shell.splitlines()
        ),
        "exit_zero_line_count": sum(
            _EXIT_ZERO_LINE.fullmatch(line) is not None for line in lines
        ),
    }
    if code == "POC_SENSITIVE_CONTENT":
        # No rejected source, matched identifier, or value crosses this boundary.
        # A location/category is enough for one bounded LLM repair attempt.
        diagnostic["sensitive_category"] = "UNCLASSIFIED"
        diagnostic["sensitive_line"] = 0
        diagnostic["sensitive_rule_id"] = "UNCLASSIFIED"
        try:
            source = content.decode("utf-8")
            inspected = inspect_poc_candidate_json(canonical_bytes({"content": source}))
            projected = json.loads(inspected.data)["content"]
            categories = set(inspected.categories) & {
                "COOKIE",
                "TOKEN",
                "CREDENTIAL",
                "HOST_ABSOLUTE_PATH",
            }
            if isinstance(projected, str) and projected != source:
                first_difference = next(
                    (
                        index
                        for index, (before, after) in enumerate(
                            zip(source, projected, strict=False)
                        )
                        if before != after
                    ),
                    min(len(source), len(projected)),
                )
                diagnostic["sensitive_line"] = (
                    source.count("\n", 0, first_difference) + 1
                )
                diagnostic["sensitive_rule_id"] = poc_candidate_sensitive_rule_id(
                    source, first_difference
                )
                diagnostic["sensitive_category"] = (
                    next(iter(categories))
                    if len(categories) == 1
                    else "MULTIPLE_RULES"
                    if categories
                    else "REDACTION_MISMATCH"
                )
        except (UnicodeDecodeError, ValueError, KeyError, TypeError):
            pass
    return diagnostic


def heredocs_on_line(
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
    """Keep literal dollars visible; Python syntax is not a shell-safety proof."""

    return body


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
        new = heredocs_on_line(line)
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


def _shell_tokens(shell: bytes) -> list[bytes]:
    """Split shell words and command separators, preserving quote boundaries."""

    tokens: list[bytes] = []
    word = bytearray()
    in_word = False
    quote: int | None = None
    index = 0
    while index < len(shell):
        current = shell[index]
        if quote is not None:
            if current == quote:
                quote = None
            elif current == ord("\\") and quote == ord('"') and index + 1 < len(shell):
                following = shell[index + 1]
                if following in b'$`"\\\n':
                    if following != ord("\n"):
                        word.append(following)
                    index += 1
                else:
                    word.append(current)
            else:
                word.append(current)
        elif current == ord("\\") and index + 1 < len(shell):
            index += 1
            following = shell[index]
            if following != ord("\n"):
                word.append(following)
                in_word = True
        elif current in (ord("'"), ord('"')):
            quote = current
            in_word = True
        elif current == ord("#") and not in_word:
            end = shell.find(b"\n", index)
            if end < 0:
                break
            index = end - 1
        elif current in b" \t\n;&|(){}<>":
            if in_word:
                tokens.append(bytes(word))
                word.clear()
                in_word = False
            if current not in b" \t<>":
                tokens.append(bytes((current,)))
        else:
            word.append(current)
            in_word = True
        index += 1
    if in_word:
        tokens.append(bytes(word))
    return tokens


def _has_exit_two_command(shell: bytes) -> bool:
    """Find a shell `exit 2` command, excluding comments and other arguments."""

    command_start = True
    exit_argument = False
    for token in _shell_tokens(shell):
        if token in {b"\n", b";", b"&", b"|", b"(", b")", b"{", b"}"}:
            command_start = True
            exit_argument = False
        elif exit_argument:
            if token == b"2":
                return True
            exit_argument = False
        elif command_start:
            if token in {b"then", b"do", b"else", b"!", b"command", b"builtin"}:
                continue
            if token == b"exit":
                exit_argument = True
            elif re.fullmatch(rb"[A-Za-z_][A-Za-z0-9_]*=.*", token):
                continue
            command_start = False
    return False


def _is_direct_marker_print(command: list[bytes]) -> bool:
    """Recognize a literal marker printed by a simple shell command."""

    words = command[:]
    while words and words[0] in {b"then", b"do", b"else"}:
        words.pop(0)
    return (
        len(words) > 1
        and words[0] in {b"printf", b"echo"}
        and any(_INCONCLUSIVE_MARKER in word for word in words[1:])
    )


def _is_direct_exit_two(command: list[bytes]) -> bool:
    words = command[:]
    while words and words[0] in {b"then", b"do", b"else", b"!", b"command", b"builtin"}:
        words.pop(0)
    return len(words) > 1 and words[:2] == [b"exit", b"2"]


def _has_direct_marker_exit_two(shell: bytes) -> bool:
    """Recognize adjacent simple marker-print and literal exit-two commands."""

    tokens = _shell_tokens(shell)
    command: list[bytes] = []
    previous_printed_marker = False
    connector = b"\n"
    separators = {b"\n", b";", b"&", b"|", b"(", b")", b"{", b"}"}
    index = 0
    while index <= len(tokens):
        token = tokens[index] if index < len(tokens) else b"\n"
        if token in separators:
            if command:
                if (
                    previous_printed_marker
                    and connector in {b"\n", b";", b"&&"}
                    and _is_direct_exit_two(command)
                ):
                    return True
                previous_printed_marker = _is_direct_marker_print(command)
                command.clear()
            connector = token
            if token in {b"&", b"|"} and tokens[index + 1 : index + 2] == [token]:
                connector += token
                index += 1
        else:
            command.append(token)
        index += 1
    return False


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
    if _has_direct_marker_exit_two(shell):
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


__all__ = [
    "POC_CANDIDATE_VALIDATOR_REVISION",
    "PoCCandidateRejected",
    "candidate_rejection_diagnostic",
    "validate_candidate",
]
