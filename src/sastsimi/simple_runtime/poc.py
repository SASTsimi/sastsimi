from __future__ import annotations

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
# A loop or read target is bound by the shell exactly like an assignment, so a
# script that iterates is self-contained even though nothing is assigned to the
# name with "=".
_SHELL_BINDING = re.compile(
    rb"(?m)(?:\bfor[ \t]+(?P<loop>[A-Za-z_][A-Za-z0-9_]*)[ \t]+in\b"
    rb"|\bread[ \t]+(?:-[A-Za-z]+[ \t]+)*(?P<read>[A-Za-z_][A-Za-z0-9_]*))"
)
_URL = re.compile(rb"https?://[^\s'\"<>]+", re.IGNORECASE)
# A Windows host path is recognised only by its unambiguous separator: a drive
# letter followed by a backslash, or a UNC prefix.  The forward-slash form is
# indistinguishable from ordinary shell text - "http://host" and a sed command
# such as "s:/a:/b:" both carry a letter, a colon and a slash - so matching it
# rejected the loopback URLs this boundary explicitly allows.  POSIX host paths
# are caught by _FORBIDDEN_HOST_PATHS instead.
_WINDOWS_PATH = re.compile(rb"(?:(?<![A-Za-z0-9_])[A-Za-z]:\\|\\\\)[^\r\n]+")
_FORBIDDEN_HOST_PATHS = (
    b"/var/run/docker.sock",
    b"/run/docker.sock",
    b"/root/",
    b"/home/",
    b"/Users/",
    # The WSL mount of the Windows host, which is how a host drive reaches the
    # filesystem from inside a Linux container on this kind of machine.
    b"/mnt/c/",
)
_SAFE_PROCESS_VARIABLES = frozenset(
    {"PATH", "PYTHONPATH", "LANG", "LC_ALL", "TMPDIR", "PWD"}
)


class PoCCandidateRejected(ValueError):
    pass


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
    declared = {
        match.group("name").decode("ascii")
        for match in _SHELL_ASSIGNMENT.finditer(content)
    }
    declared.update(
        (match.group("loop") or match.group("read")).decode("ascii")
        for match in _SHELL_BINDING.finditer(content)
    )
    allowed = _SAFE_PROCESS_VARIABLES | allowed_environment_names | declared
    variables = {
        (match.group("braced") or match.group("plain")).decode("ascii")
        for match in _SHELL_VARIABLE.finditer(content)
    }
    if variables - allowed:
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
