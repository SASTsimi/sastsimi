"""Bounded, typed recovery decisions for the sequential SimpleRuntime."""

from __future__ import annotations

import ast
import hashlib
import io
import json
import re
import shlex
import sqlite3
import tokenize
from collections.abc import Mapping
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Literal, Protocol

from pydantic import ValidationError

from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.prompt_redaction import (
    redact_projected_json,
    redact_untrusted_text,
)
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .django_project_defaults import _django_project_default_false
from .models import (
    MAX_RECOVERY_ATTEMPTS,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
    StageStatus,
    input_reference_hash,
)
from .provider import SimpleLLMClient

_MAX_ENVIRONMENT_PATCH_BYTES = 8 * 1024
_MAX_IMPORT_DIAGNOSTIC_BYTES = 4 * 1024
_MAX_POC_OUTPUT_BYTES = 1024 * 1024  # PortableDockerRuntime's per-stream cap.
_MAX_REDACTED_RECOVERY_RESPONSE_BYTES = 64 * 1024
_MAX_RECOVERY_DECISION_TEXT_BYTES = 4 * 1024
_MAX_POC_CANDIDATE_BYTES = 96_000
_RECOVERY_TIMEOUT_MS = 120_000
_PLAYWRIGHT_BROWSERS = ("chromium", "firefox", "webkit")
_SANITIZED_TRACE_FRAME = re.compile(rb"  [A-Za-z_][A-Za-z_0-9]*:line [0-9]+")
_SANITIZED_IMPORT_FRAME = re.compile(
    rb"  (?:import_module|_gcd_import|_find_and_load|_load_unlocked|exec_module)"
    rb":line [0-9]+"
)
_SANITIZED_EXTRACT_FAILURE = re.compile(
    rb"Traceback \(sanitized\): extract\r?\n"
    rb"(?:AssertionError|RuntimeError|TypeError|ValueError)\r?\n?"
)
SANITIZED_EXTRACT_RECOVERY_REVISION = 1
DJANGO_POC_FIXTURE_RECOVERY_REVISION = 1
DJANGO_POC_FIXTURE_DEPENDENCY_RECOVERY_REVISION = 1
DJANGO_POC_SOURCE_GAP_RECOVERY_REVISION = 1
DJANGO_POC_SCHEMA_RECOVERY_REVISION = 1
DJANGO_SETTINGS_MISMATCH_RECOVERY_REVISION = 1
DJANGO_RELATION_SETTINGS_RECOVERY_REVISION = 1
DJANGO_RELATION_SETTINGS_SOURCE_BOUND_REVISION = 2
DJANGO_MIGRATION_GRAPH_SETTINGS_SOURCE_BOUND_REVISION = 3
HTTP_SERVER_CONSTRUCTOR_RECOVERY_REVISION = 1
SQLITE_IN_MEMORY_STORAGE_RECOVERY_REVISION = 1
DJANGO_CANDIDATE_APP_RECOVERY_REVISION = 1
DJANGO_URLCONF_RECOVERY_REVISION = 1
POC_REPLAY_GUARD_REVISION = 1
_PLAYWRIGHT_PATCH_PREFIX = (
    "ENV PLAYWRIGHT_BROWSERS_PATH=/opt/sastsimi-playwright-browsers\n"
    "RUN python -m playwright install --with-deps "
)


def _python_import_traceback_spans(
    output: bytes,
) -> tuple[dict[bytes, bytes], bool]:
    """Keep proven spans and whether the final one ends the diagnostic stream."""

    def excerpt(*parts: bytes) -> bytes:
        return b"\n".join(part[:1_024] for part in parts if part)

    def exception_key(line: bytes) -> bytes:
        exception, _, detail = line.partition(b": ")
        if exception == b"ModuleNotFoundError" and detail.startswith(
            b"No module named "
        ):
            detail = detail.removeprefix(b"No module named ")
            if detail[:1] in (b"'", b'"'):
                closing = detail.find(detail[:1], 1)
                if closing > 1:
                    detail = detail[1:closing]
            else:
                detail = detail.split(b";", 1)[0].strip()
        return exception + b":" + detail

    lines = output.splitlines()
    import_lines = (b"ModuleNotFoundError: ", b"ImportError: ")
    standard_header = b"Traceback (most recent call last):"
    active_standard = False
    matches: dict[bytes, bytes] = {}
    last_match_end = -1
    last_match_kind = "single"

    def remember(line: bytes, span: bytes, end: int, kind: str = "single") -> None:
        nonlocal last_match_end, last_match_kind
        matches[exception_key(line)] = span
        last_match_end = end
        last_match_kind = kind

    for index, line in enumerate(lines):
        if line == standard_header:
            active_standard = True
            continue
        import_exception = line.startswith(import_lines) or line in {
            b"ModuleNotFoundError",
            b"ImportError",
        }
        if not import_exception:
            if active_standard and line and not line.startswith((b" ", b"\t")):
                active_standard = False
            continue
        next_line = lines[index + 1] if index + 1 < len(lines) else b""
        if next_line == standard_header:
            remember(line, excerpt(line, next_line), index + 1, "standard_frames")
            active_standard = False
            continue
        if next_line == b"Traceback (functions only):":
            import_frame = next(
                (
                    (frame_index, frame)
                    for frame_index, frame in enumerate(
                        lines[index + 2 : index + 12], index + 2
                    )
                    if b"exec_module" in frame
                ),
                None,
            )
            if import_frame is not None:
                frame_index, frame = import_frame
                remember(
                    line,
                    excerpt(line, next_line, frame),
                    frame_index,
                    "function_frames",
                )
                active_standard = False
                continue
        if next_line.lower().startswith(b"traceback: "):
            import_frames = (
                b"exec_module",
                b"_find_and_load",
                b"_load_unlocked",
                b"_gcd_import",
                b"import_module",
            )
            if any(frame in next_line for frame in import_frames) or (
                line.startswith(b"ModuleNotFoundError")
                and b"unresolved_frame" in next_line
            ):
                remember(line, excerpt(line, next_line), index + 1)
                active_standard = False
                continue
        if active_standard:
            remember(line, excerpt(standard_header, line), index)
            active_standard = False
    trailing = [line for line in lines[last_match_end + 1 :] if line.strip()]
    if last_match_kind == "function_frames":
        terminal = all(line.startswith((b"  at ", b"\tat ")) for line in trailing)
    elif last_match_kind == "standard_frames":
        sanitized = [
            _SANITIZED_TRACE_FRAME.fullmatch(line) is not None for line in trailing
        ]
        if any(sanitized):
            # The PoC harness emits function:line frames after a redacted
            # import exception. Keep this a single, exact frame format: mixed
            # output or later errors cannot authorize dependency replanning.
            terminal = all(sanitized) and any(
                _SANITIZED_IMPORT_FRAME.fullmatch(line) is not None for line in trailing
            )
        else:
            terminal = all(
                line.startswith((b"  File ", b"    ", b"\t", b"  at "))
                or re.fullmatch(rb"  in (?:[A-Za-z_][A-Za-z_0-9]*|<module>)", line)
                is not None
                for line in trailing
            )
    else:
        terminal = not trailing
    return matches, bool(matches) and terminal


def has_python_import_traceback(output: bytes) -> bool:
    """Recognize Python import failures in full and sanitized tracebacks."""

    return bool(_python_import_traceback_spans(output)[0])


def has_python_import_failure(output: bytes) -> bool:
    """Recognize traceback and interpreter-level module import failures."""

    if has_python_import_traceback(output):
        return True
    for line in output.splitlines():
        interpreter, marker, module = (
            line.strip().rsplit(b"/", 1)[-1].partition(b": No module named ")
        )
        if (
            marker
            and interpreter.startswith(b"python")
            and b" " not in interpreter
            and module
        ):
            return True
    return False


_CANDIDATE_HEREDOC = re.compile(
    rb"(?m)^[^\r\n]*\bpython(?:3(?:\.[0-9]+)?)?[ \t]+-[ \t]+"
    rb"<<[ \t]*'(?P<tag>[A-Za-z_][A-Za-z_0-9]*)'[ \t]*\r?$"
)
_CANDIDATE_APP_NAME = re.compile(
    rb"[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*"
)
_CANDIDATE_IMPORT_FRAME = re.compile(rb"  at (?P<name>[A-Za-z_][A-Za-z_0-9]*):[0-9]+")
_CANDIDATE_SECRET_NAME = re.compile(
    rb"secret|token|password|credential|cookie|passwd|api_key", re.I
)


def django_candidate_app_import_failure(
    stderr: bytes, stdout: bytes, candidate: bytes
) -> str | None:
    """Identify an app literal added by a generated PoC before Django setup.

    Repository absence and the execution receipt are verified by the store.
    This helper deliberately accepts only the sanitized setup traceback form.
    """

    if not candidate or len(candidate) > 256 * 1024 or len(stderr) > 4 * 1024:
        return None
    lines = stderr.replace(b"\r\n", b"\n").splitlines()
    if len(lines) < 6 or lines[1] != b"Traceback (most recent call last):":
        return None
    prefix = b"ModuleNotFoundError: "
    if not lines[0].startswith(prefix):
        return None
    raw_name = lines[0].removeprefix(prefix)
    if (
        len(raw_name) > 128
        or _CANDIDATE_APP_NAME.fullmatch(raw_name) is None
        or _CANDIDATE_SECRET_NAME.search(raw_name) is not None
    ):
        return None
    frames = [_CANDIDATE_IMPORT_FRAME.fullmatch(line) for line in lines[2:]]
    if not all(frames):
        return None
    names = [frame.group("name") for frame in frames if frame is not None]
    expected = (b"setup", b"populate", b"create", b"import_module")
    positions = [names.index(name) if name in names else -1 for name in expected]
    if positions != sorted(positions) or any(position < 0 for position in positions):
        return None

    openers = tuple(_CANDIDATE_HEREDOC.finditer(candidate))
    if len(openers) != 1:
        return None
    opener = openers[0]
    remainder = candidate[opener.end() :].lstrip(b"\r\n")
    body_lines = remainder.splitlines(keepends=True)
    ending = next(
        (
            index
            for index, line in enumerate(body_lines)
            if line.strip(b"\r\n") == opener.group("tag")
        ),
        None,
    )
    if ending is None or any(line.strip() for line in body_lines[ending + 1 :]):
        return None
    try:
        tree = ast.parse(b"".join(body_lines[:ending]).decode("utf-8"))
    except (UnicodeError, SyntaxError, ValueError):
        return None

    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    configured = [
        node
        for node in calls
        if isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "settings"
        and node.func.attr == "configure"
    ]
    setup = [
        node
        for node in calls
        if isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "django"
        and node.func.attr == "setup"
    ]
    if (
        len(configured) != 1
        or len(setup) != 1
        or configured[0].lineno >= setup[0].lineno
    ):
        return None
    app_keywords = [
        keyword for keyword in configured[0].keywords if keyword.arg == "INSTALLED_APPS"
    ]
    if len(app_keywords) != 1:
        return None
    try:
        apps = ast.literal_eval(app_keywords[0].value)
    except (ValueError, TypeError, SyntaxError, MemoryError, RecursionError):
        return None
    if (
        not isinstance(apps, (list, tuple))
        or not apps
        or not all(isinstance(app, str) for app in apps)
        or not any(
            app == raw_name.decode("ascii")
            or app.startswith(raw_name.decode("ascii") + ".")
            for app in apps
        )
    ):
        return None
    stage_import = any(
        isinstance(node, ast.Assign)
        and node.lineno < setup[0].lineno
        and any(
            isinstance(target, ast.Name) and target.id == "stage"
            for target in node.targets
        )
        and isinstance(node.value, ast.Constant)
        and node.value.value == "import"
        for node in ast.walk(tree)
    )
    route_calls = [
        node
        for node in calls
        if isinstance(node.func, ast.Attribute)
        and node.func.attr in {"get", "post", "put", "patch", "delete", "request"}
        and node.lineno > setup[0].lineno
    ]
    if not stage_import or not route_calls:
        return None

    # Only literal progress printed before setup may appear on stdout. A
    # success or route observation must never be reclassified as setup noise.
    parents = {
        child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)
    }

    def in_definition(node: ast.AST) -> bool:
        current = parents.get(node)
        while current is not None:
            if isinstance(
                current, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                return True
            current = parents.get(current)
        return False

    progress: list[tuple[int, bytes]] = []
    for node in calls:
        if (
            node.lineno >= setup[0].lineno
            or in_definition(node)
            or not isinstance(node.func, ast.Name)
            or node.func.id != "print"
            or len(node.args) != 1
            or not isinstance(node.args[0], ast.Constant)
            or not isinstance(node.args[0].value, str)
            or any(keyword.arg not in {"flush"} for keyword in node.keywords)
        ):
            continue
        value = node.args[0].value
        if re.search(
            r"(?i)\b(?:reproduced|supported|success|route|inconclusive)\b",
            value,
        ):
            return None
        progress.append((node.lineno, (value + "\n").encode("utf-8")))
    expected_stdout = b"".join(value for _, value in sorted(progress))
    if stdout.replace(b"\r\n", b"\n") != expected_stdout:
        return None
    return raw_name.decode("ascii")


def django_candidate_app_recovery_decision() -> RecoveryDecision:
    """Give candidate-only setup guidance without copying the module name."""

    return RecoveryDecision(
        category=RecoveryCategory.GENERATED_INPUT,
        action=RecoveryAction.REGENERATE_INPUT,
        diagnosis="The generated PoC configured an app absent from pinned source",
        guidance=(
            "Regenerate only the PoC candidate using repository-supported "
            "Django settings and installed apps from the pinned checkout. "
            "Keep the verified source match, complete the required fixture "
            "setup, and exercise the intended route. Do not add a dependency "
            "or change the built environment for this candidate setup error. "
            "This failure is not a vulnerability verdict."
        ),
    )


def candidate_app_replay_unsupported_app(
    checkpoint: StageCheckpoint, artifacts: SimpleArtifactRepository
) -> str | None:
    """Re-derive the unsupported app from this replay's saved CAS evidence."""

    if not checkpoint.recovery_decision_refs:
        return None
    try:
        if len(checkpoint.recovery_decision_refs) > 32:
            raise ValueError("too many recovery decisions")
        markers: list[tuple[StoredDataRef, dict[str, object]]] = []
        unreadable = False
        for ref in checkpoint.recovery_decision_refs:
            try:
                value = json.loads(artifacts.read_bounded(ref, 64 * 1024))
            except (OSError, TypeError, ValueError, UnicodeError, sqlite3.Error):
                unreadable = True
                continue
            if not isinstance(value, dict):
                unreadable = True
                continue
            if (
                value.get("candidate_app_replay")
                or value.get("diagnostic_excerpt")
                == "candidate-only Django app import during setup"
            ):
                markers.append((ref, value))
        if not markers:
            return None
        if len(markers) != 1 or unreadable:
            raise ValueError("ambiguous candidate app replay")
        latest, record = markers[0]
        decision = record.get("decision")
        original_error = record.get("original_error")
        if (
            latest not in checkpoint.input_refs
            or record.get("kind") != "simple_recovery_decision"
            or record.get("identity") != checkpoint.identity.model_dump(mode="json")
            or record.get("stage") != SimpleStage.POC_EXECUTION_DONE.value
            or record.get("decision_origin") != "RULE"
            or record.get("candidate_app_replay") is not True
            or record.get("diagnostic_excerpt")
            != "candidate-only Django app import during setup"
            or record.get("explicit_exhaustion_replay") is not True
            or record.get("recovery_revision") != DJANGO_CANDIDATE_APP_RECOVERY_REVISION
            or not isinstance(decision, dict)
            or decision.get("category") != "GENERATED_INPUT"
            or decision.get("action") != "REGENERATE_INPUT"
            or decision.get("environment_patch") != ""
            or not isinstance(original_error, dict)
            or original_error.get("code") != "POC_RUNTIME_IMPORT_FAILED"
            or not isinstance(record.get("attempt_id"), str)
            or not record["attempt_id"]
        ):
            raise ValueError("unbound candidate app replay")
        evidence = tuple(
            StoredDataRef.model_validate(value)
            for value in original_error["evidence_refs"]
        )
        if len(evidence) != 4 or any(
            ref not in checkpoint.input_refs for ref in evidence
        ):
            raise ValueError("unbound candidate app evidence")
        execution = json.loads(artifacts.read_bounded(evidence[0], 64 * 1024))
        if not isinstance(execution, dict):
            raise ValueError("invalid execution receipt")
        candidate_ref = StoredDataRef.model_validate(execution["candidate_ref"])
        content_ref = StoredDataRef.model_validate(execution["content_ref"])
        if (
            execution.get("kind") != "simple_poc_execution"
            or execution.get("attempt_id") != record["attempt_id"]
            or execution.get("stdout_ref") != evidence[1].model_dump(mode="json")
            or execution.get("stderr_ref") != evidence[2].model_dump(mode="json")
            or candidate_ref not in checkpoint.input_refs
            or content_ref not in checkpoint.input_refs
        ):
            raise ValueError("unbound prior candidate")
        candidate = json.loads(artifacts.read_bounded(candidate_ref, 64 * 1024))
        content = artifacts.read_bounded(content_ref, 1024 * 1024)
        if (
            not isinstance(candidate, dict)
            or candidate.get("kind") != "simple_poc_candidate"
            or candidate.get("attempt_id") != record["attempt_id"]
            or candidate.get("content_ref") != content_ref.model_dump(mode="json")
            or candidate.get("content_digest") != hashlib.sha256(content).hexdigest()
        ):
            raise ValueError("unbound prior candidate content")
        app = django_candidate_app_import_failure(
            artifacts.read_bounded(evidence[2], 1024 * 1024),
            artifacts.read_bounded(evidence[1], 1024 * 1024),
            content,
        )
        if app is None:
            raise ValueError("candidate app diagnostic changed")
        return app
    except (
        KeyError,
        OSError,
        TypeError,
        ValueError,
        UnicodeError,
        sqlite3.Error,
    ) as error:
        raise ValueError("POC_CANDIDATE_APP_REPLAY_UNBOUND") from error


def _candidate_dynamic_dependency_sink(tree: ast.Module) -> bool:
    """Require statically pinned subprocess interpreter, mode, and code/module."""

    sys_names = {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
        if alias.name == "sys"
    }
    subprocess_names = {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
        if alias.name == "subprocess"
    }
    subprocess_functions = {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "subprocess"
        for alias in node.names
        if alias.name in {"run", "Popen", "call", "check_call", "check_output"}
    }
    dynamic_loader_names = {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
        if (
            node.module in {"runpy", "importlib", "builtins"}
            and alias.name
            in {
                "run_module",
                "run_path",
                "import_module",
                "eval",
                "exec",
                "compile",
            }
        )
    }
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if (
            isinstance(node.func, ast.Name)
            and node.func.id
            in {
                "__import__",
                "eval",
                "exec",
                "compile",
                *dynamic_loader_names,
            }
            or isinstance(node.func, ast.Attribute)
            and node.func.attr
            in {
                "__import__",
                "run_module",
                "run_path",
                "import_module",
                "exec_module",
                "load_module",
            }
        ):
            return True
        subprocess_call = (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id in subprocess_names
            and node.func.attr in {"run", "Popen", "call", "check_call", "check_output"}
            or isinstance(node.func, ast.Name)
            and node.func.id in subprocess_functions
        )
        if not subprocess_call:
            continue
        command = (
            node.args[0]
            if node.args
            else next(
                (keyword.value for keyword in node.keywords if keyword.arg == "args"),
                None,
            )
        )
        if isinstance(command, ast.Name):
            assignments = [
                statement
                for statement in tree.body
                if isinstance(statement, ast.Assign)
                and len(statement.targets) == 1
                and isinstance(statement.targets[0], ast.Name)
                and statement.targets[0].id == command.id
                and statement.lineno < node.lineno
            ]
            uses = [
                value
                for value in ast.walk(tree)
                if isinstance(value, ast.Name) and value.id == command.id
            ]
            if (
                len(assignments) != 1
                or len(uses) != 2
                or not isinstance(assignments[0].value, (ast.List, ast.Tuple))
            ):
                return True
            command = assignments[0].value
        if not isinstance(command, (ast.List, ast.Tuple)):
            return True
        arguments = command.elts
        if (
            len(arguments) < 3
            or not isinstance(arguments[0], ast.Attribute)
            or not isinstance(arguments[0].value, ast.Name)
            or arguments[0].value.id not in sys_names
            or arguments[0].attr != "executable"
            or not isinstance(arguments[1], ast.Constant)
            or arguments[1].value not in {"-c", "-m"}
            or not isinstance(arguments[2], ast.Constant)
            or not isinstance(arguments[2].value, str)
        ):
            return True
    return False


def candidate_app_replay_forbidden(content: bytes, unsupported_app: str) -> bool:
    """Reject the unsupported app or package installation in this replay."""

    try:
        if not content.startswith(b"#!/bin/sh\n"):
            return True
        openers = tuple(_CANDIDATE_HEREDOC.finditer(content))
        if not openers:
            if b"<<" in content:
                return True
            script = content.decode("utf-8").lower()
        else:
            tree = _django_candidate_url_tree(content)
            if len(openers) != 1 or tree is None:
                return True
            if _candidate_dynamic_dependency_sink(tree):
                return True
            opener = openers[0]
            if b"#" in opener.group().split(b"python", 1)[0]:
                return True
            remainder = content[opener.end() :].lstrip(b"\r\n")
            body_start = len(content) - len(remainder)
            lines = remainder.splitlines(keepends=True)
            ending = next(
                (
                    index
                    for index, line in enumerate(lines)
                    if line.strip(b"\r\n") == opener.group("tag")
                ),
                None,
            )
            if ending is None:
                return True
            body = b"".join(lines[:ending])
            source = body.decode("utf-8")
            source_lines = source.splitlines(keepends=True)
            for token in tokenize.generate_tokens(io.StringIO(source).readline):
                if token.type != tokenize.COMMENT:
                    continue
                line_index = token.start[0] - 1
                line = source_lines[line_index]
                source_lines[line_index] = (
                    line[: token.start[1]]
                    + " " * (token.end[1] - token.start[1])
                    + line[token.end[1] :]
                )
            script = (
                content[:body_start].decode("utf-8")
                + "".join(source_lines)
                + content[body_start + len(body) :].decode("utf-8")
            ).lower()
    except (IndexError, tokenize.TokenError, UnicodeError, ValueError):
        return True
    compact = re.sub(r"[^a-z0-9]", "", script)
    normalized_app = re.sub(r"[^a-z0-9]", "", unsupported_app.lower())
    return (
        normalized_app in compact
        or re.search(
            r"\b(?:pip[0-9]*|ensurepip|uv|poetry|conda|easy_install|apt|apk|dnf|"
            r"yum|npm|pnpm|yarn|install)\b",
            script,
        )
        is not None
    )


def _django_candidate_url_tree(candidate: bytes) -> ast.Module | None:
    """Extract one direct Python heredoc, or a plain Python candidate."""

    if not candidate or len(candidate) > _MAX_POC_CANDIDATE_BYTES:
        return None
    source = candidate
    if candidate.startswith(b"#!/bin/sh"):
        openers = tuple(_CANDIDATE_HEREDOC.finditer(candidate))
        if len(openers) != 1:
            return None
        opener = openers[0]
        remainder = candidate[opener.end() :].lstrip(b"\r\n")
        lines = remainder.splitlines(keepends=True)
        ending = next(
            (
                index
                for index, line in enumerate(lines)
                if line.strip(b"\r\n") == opener.group("tag")
            ),
            None,
        )
        if ending is None or any(line.strip() for line in lines[ending + 1 :]):
            return None
        source = b"".join(lines[:ending])
    try:
        return ast.parse(source.decode("utf-8"))
    except (UnicodeError, SyntaxError, ValueError):
        return None


def _django_candidate_literal_kwargs_root(
    tree: ast.Module, configure: ast.Call
) -> ast.Constant | None:
    """Resolve only an untouched, immediately expanded literal options dict."""

    if len(configure.args) != 0 or len(configure.keywords) != 1:
        return None
    keyword = configure.keywords[0]
    if keyword.arg is not None or not isinstance(keyword.value, ast.Name):
        return None
    name = keyword.value.id
    assignments: list[tuple[int, ast.Assign]] = []
    for index, node in enumerate(tree.body):
        if (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and node.targets[0].id == name
        ):
            assignments.append((index, node))
    if len(assignments) != 1:
        return None
    index, assignment = assignments[0]
    if index + 1 >= len(tree.body):
        return None
    following = tree.body[index + 1]
    if (
        not isinstance(following, ast.Expr)
        or following.value is not configure
        or not isinstance(assignment.value, ast.Dict)
    ):
        return None
    names = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Name) and node.id == name
    ]
    if (
        len(names) != 2
        or assignment.targets[0] not in names
        or keyword.value not in names
    ):
        return None
    keys = assignment.value.keys
    if not all(
        isinstance(key, ast.Constant) and isinstance(key.value, str) for key in keys
    ):
        return None
    key_names = [key.value for key in keys if isinstance(key, ast.Constant)]
    if len(set(key_names)) != len(key_names):
        return None
    try:
        ast.literal_eval(assignment.value)
    except (ValueError, TypeError, MemoryError, RecursionError):
        return None
    roots = [
        value
        for key, value in zip(keys, assignment.value.values, strict=True)
        if isinstance(key, ast.Constant) and key.value == "ROOT_URLCONF"
    ]
    return roots[0] if len(roots) == 1 and isinstance(roots[0], ast.Constant) else None


def _django_candidate_root_and_reverses(
    tree: ast.Module,
) -> tuple[str, tuple[ast.Call, ...]] | None:
    """Require one literal root and no candidate-side URLConf mutation."""

    configure = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "settings"
        and node.func.attr == "configure"
    ]
    if len(configure) != 1:
        return None
    roots = [
        keyword.value
        for keyword in configure[0].keywords
        if keyword.arg == "ROOT_URLCONF"
    ]
    literal_kwargs = (
        len(configure[0].keywords) == 1 and configure[0].keywords[0].arg is None
    )
    if literal_kwargs:
        literal_root = _django_candidate_literal_kwargs_root(tree, configure[0])
        roots = [literal_root] if literal_root is not None else []
    if (
        len(roots) != 1
        or not isinstance(roots[0], ast.Constant)
        or not isinstance(roots[0].value, str)
        or _CANDIDATE_APP_NAME.fullmatch(roots[0].value.encode("utf-8")) is None
        or not roots[0].value.endswith(".urls")
        or (
            not literal_kwargs
            and any(keyword.arg is None for keyword in configure[0].keywords)
        )
    ):
        return None
    if not any(
        isinstance(node, ast.ImportFrom)
        and node.module == "django.conf"
        and any(item.name == "settings" and item.asname is None for item in node.names)
        for node in ast.walk(tree)
    ) or not any(
        isinstance(node, ast.ImportFrom)
        and node.module == "django.urls"
        and any(item.name == "reverse" and item.asname is None for item in node.names)
        for node in ast.walk(tree)
    ):
        return None
    parents = {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    django_conf_names = {
        alias.asname
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
        if alias.name == "django.conf" and alias.asname is not None
    } | {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module == "django"
        for alias in node.names
        if alias.name == "conf"
    }
    django_module_names = {
        alias.asname or "django"
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
        if alias.name == "django"
        or alias.name == "django.conf"
        and alias.asname is None
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in django_conf_names:
            return None
        if (
            isinstance(node, ast.Attribute)
            and node.attr == "conf"
            and isinstance(node.value, ast.Name)
            and node.value.id in django_module_names
        ):
            return None
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, (ast.Name, ast.Attribute))
            and (
                isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                or isinstance(node.func, ast.Attribute)
                and node.func.attr in {"getattr", "__getattribute__"}
            )
            and node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id in django_module_names
        ):
            return None
        if (
            isinstance(node, ast.ImportFrom)
            and node.module == "django.conf"
            and any(
                item.name == "settings" and item.asname is not None
                for item in node.names
            )
        ):
            return None
        if isinstance(node, ast.Attribute) and node.attr == "settings":
            return None
        if isinstance(node, ast.Name) and node.id == "settings":
            parent = parents.get(id(node))
            if (
                not isinstance(parent, ast.Attribute)
                or parent.attr != "configure"
                or parent.value is not node
            ):
                return None
        if isinstance(node, ast.Attribute) and node.attr == "_wrapped":
            return None
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"globals", "locals", "vars"}
        ):
            return None
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "settings"
            and node.attr
            in {
                "_wrapped",
                "__dict__",
                "__setattr__",
                "__getattribute__",
            }
        ):
            return None
        if (
            isinstance(node, ast.Call)
            and node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "settings"
        ):
            if (
                isinstance(node.func, ast.Name)
                and node.func.id in {"vars", "setattr", "delattr"}
                or isinstance(node.func, ast.Attribute)
                and node.func.attr in {"__setattr__", "__delattr__"}
            ):
                return None
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                or isinstance(node.func, ast.Attribute)
                and node.func.attr == "__getattribute__"
            ) and (
                len(node.args) < 2
                or not isinstance(node.args[1], ast.Constant)
                or node.args[1].value in {"_wrapped", "__dict__", "ROOT_URLCONF"}
            ):
                return None
        if isinstance(node, ast.Call) and (
            isinstance(node.func, ast.Name)
            and node.func.id == "set_urlconf"
            or isinstance(node.func, ast.Attribute)
            and node.func.attr == "set_urlconf"
        ):
            return None
        if isinstance(node, ast.Name) and node.id == "urlpatterns":
            return None
        if isinstance(node, ast.Attribute) and node.attr == "ROOT_URLCONF":
            return None
        if isinstance(node, ast.Subscript) and (
            isinstance(node.slice, ast.Constant)
            and node.slice.value in {"ROOT_URLCONF", "urlpatterns"}
        ):
            return None
    reverses = tuple(
        node
        for node in _candidate_top_level_nodes(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "reverse"
    )
    return roots[0].value, reverses


def _candidate_top_level_nodes(tree: ast.AST) -> list[ast.AST]:
    """Traverse script statements, not uncalled function/class bodies."""

    nodes: list[ast.AST] = []

    def visit(node: ast.AST) -> None:
        if isinstance(
            node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)
        ):
            return
        nodes.append(node)
        for child in ast.iter_child_nodes(node):
            visit(child)

    visit(tree)
    return nodes


def django_urlconf_reverse_failure(
    stderr: bytes, stdout: bytes, candidate: bytes
) -> tuple[str, str, str, int] | None:
    """Classify a failed namespaced reverse at its exact candidate line."""

    if len(stderr) > 4096 or len(stdout) > 4096:
        return None
    match = re.fullmatch(
        rb"NoReverseMatch\r?\nTraceback \(most recent call last\):\r?\n"
        rb"  at unresolved_frame:(?P<line>[0-9]+)\r?\n"
        rb"  at reverse:[0-9]+\r?\n?",
        stderr,
    )
    tree = _django_candidate_url_tree(candidate)
    if match is None or tree is None:
        return None
    binding = _django_candidate_root_and_reverses(tree)
    if binding is None:
        return None
    root, reverses = binding
    failed_line = int(match.group("line"))
    matches = [node for node in reverses if node.lineno == failed_line]
    if len(matches) != 1 or any(node.lineno < failed_line for node in reverses):
        return None
    failed = matches[0]
    if (
        len(failed.args) != 1
        or not isinstance(failed.args[0], ast.Constant)
        or not isinstance(failed.args[0].value, str)
        or failed.args[0].value.count(":") != 1
        or len(failed.keywords) != 1
        or failed.keywords[0].arg != "args"
        or not isinstance(failed.keywords[0].value, (ast.List, ast.Tuple))
    ):
        return None
    namespace, route = failed.args[0].value.split(":")
    if (
        _CANDIDATE_APP_NAME.fullmatch(namespace.encode()) is None
        or _CANDIDATE_APP_NAME.fullmatch(route.encode()) is None
        or root != f"{namespace}.urls"
        or not failed.keywords[0].value.elts
        or not all(
            isinstance(arg, ast.Constant) and isinstance(arg.value, (int, str))
            for arg in failed.keywords[0].value.elts
        )
    ):
        return None
    preceding_prints = [
        node
        for node in _candidate_top_level_nodes(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "print"
        and node.lineno < failed_line
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    ]
    printed = preceding_prints[0].args[0] if len(preceding_prints) == 1 else None
    if (
        len(preceding_prints) != 1
        or not isinstance(printed, ast.Constant)
        or not isinstance(printed.value, str)
        or stdout.replace(b"\r\n", b"\n") != (printed.value + "\n").encode("utf-8")
        or re.search(rb"(?i)\b(?:reproduced|confirmed|route resolved)\b", stdout)
    ):
        return None
    return root, namespace, route, len(failed.keywords[0].value.elts)


def candidate_urlconf_replay_forbidden(
    content: bytes,
    failing: tuple[str, str, str, int],
    project_roots: tuple[str, ...] | None = None,
) -> bool:
    """Legacy structural check, not proof of runtime URL module provenance.

    Production URLConf replays are blocked before execution; keep this parser
    for saved-evidence diagnostics only.
    """

    tree = _django_candidate_url_tree(content)
    if tree is None:
        return True
    binding = _django_candidate_root_and_reverses(tree)
    if binding is None:
        return True
    root, reverses = binding
    if project_roots is not None and root not in project_roots:
        return True
    if project_roots is not None and not any(
        len(node.args) == 1
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == f"{failing[1]}:{failing[2]}"
        and len(node.keywords) == 1
        and node.keywords[0].arg == "args"
        and isinstance(node.keywords[0].value, (ast.List, ast.Tuple))
        and len(node.keywords[0].value.elts) == failing[3]
        for node in reverses
    ):
        return True
    return root == failing[0] and any(
        node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
        and node.args[0].value.startswith(failing[1] + ":")
        for node in reverses
    )


def validator_correction_replay_previous(
    checkpoint: StageCheckpoint, artifacts: SimpleArtifactRepository
) -> StageCheckpoint:
    """Bind the one extra candidate attempt to its blocked predecessor."""

    try:
        if (
            checkpoint.stage is not SimpleStage.POC_CANDIDATE_DONE
            or checkpoint.attempt_number != MAX_RECOVERY_ATTEMPTS + 7
            or checkpoint.status
            not in {StageStatus.PENDING, StageStatus.RUNNING, StageStatus.SUCCEEDED}
            or not checkpoint.recovery_decision_refs
            or len(checkpoint.recovery_decision_refs) > 32
        ):
            raise ValueError("invalid replay checkpoint")
        marker_ref = checkpoint.recovery_decision_refs[-1]
        marker = json.loads(artifacts.read_bounded(marker_ref, 64 * 1024))
        fields = {
            "kind",
            "identity",
            "old_attempt_id",
            "old_attempt_number",
            "old_checkpoint_ref",
            "old_checkpoint_hash",
            "diagnostic_ref",
            "failure_event_id",
            "exhaustion_event_id",
            "root_failure_event_id",
            "layout_replay_event_id",
            "validator_revision",
        }
        if not isinstance(marker, dict) or set(marker) != fields:
            raise ValueError("invalid replay marker")
        old_ref = StoredDataRef.model_validate(marker["old_checkpoint_ref"])
        old = StageCheckpoint.model_validate_json(
            artifacts.read_bounded(old_ref, 256 * 1024)
        )
        diagnostic = (
            json.loads(artifacts.read_bounded(old.output_refs[0], 64 * 1024))
            if len(old.output_refs) == 1
            else None
        )
        numeric = (
            "line_count",
            "branch_count",
            "inconclusive_line_count",
            "exit_two_line_count",
            "exit_zero_line_count",
        )
        inputs = tuple(
            dict.fromkeys((*old.input_refs, *old.output_refs, old_ref, marker_ref))
        )
        if (
            marker["kind"] != "simple_poc_validator_correction_replay"
            or marker["identity"] != checkpoint.identity.model_dump(mode="json")
            or marker["old_attempt_id"] != old.attempt_id
            or marker["old_attempt_number"] != MAX_RECOVERY_ATTEMPTS + 6
            or marker["old_checkpoint_hash"]
            != hashlib.sha256(canonical_bytes(old.model_dump(mode="json"))).hexdigest()
            or len(old.output_refs) != 1
            or marker["diagnostic_ref"] != old.output_refs[0].model_dump(mode="json")
            or marker["validator_revision"] != POC_REPLAY_GUARD_REVISION
            or any(
                not isinstance(marker[field], str) or not marker[field]
                for field in (
                    "failure_event_id",
                    "exhaustion_event_id",
                    "root_failure_event_id",
                    "layout_replay_event_id",
                )
            )
            or old.identity != checkpoint.identity
            or old.stage is not SimpleStage.POC_CANDIDATE_DONE
            or old.stage_version != checkpoint.stage_version
            or old.status is not StageStatus.BLOCKED
            or old.error_code != "RECOVERY_EXHAUSTED"
            or old.retryable
            or old.attempt_number != MAX_RECOVERY_ATTEMPTS + 6
            or not old.attempt_id
            or old.input_hash != input_reference_hash(old.input_refs)
            or old.container_id is not None
            or old.validated_poc_ref is not None
            or old.recovery_origin_stage is not SimpleStage.POC_EXECUTION_DONE
            or old.recipe_ref != checkpoint.recipe_ref
            or old.image_digest != checkpoint.image_digest
            or old.gate_revision_count != checkpoint.gate_revision_count
            or old.recovery_lineage_id != checkpoint.recovery_lineage_id
            or checkpoint.recovery_origin_stage != old.recovery_origin_stage
            or checkpoint.input_refs != inputs
            or checkpoint.input_hash != input_reference_hash(inputs)
            or checkpoint.recovery_decision_refs
            != (*old.recovery_decision_refs, marker_ref)
            or checkpoint.validated_poc_ref is not None
            or checkpoint.container_id is not None
            or (
                checkpoint.status is StageStatus.PENDING
                and checkpoint.attempt_id is not None
            )
            or (
                checkpoint.status is not StageStatus.PENDING
                and (
                    not checkpoint.attempt_id or checkpoint.attempt_id == old.attempt_id
                )
            )
            or not isinstance(diagnostic, dict)
            or set(diagnostic) != {"kind", "reason", *numeric}
            or diagnostic.get("kind") != "simple_poc_candidate_rejection_diagnostic"
            or diagnostic.get("reason") != "OTHER_VALIDATOR_REJECTION"
            or any(
                type(diagnostic.get(field)) is not int or diagnostic[field] < 0
                for field in numeric
            )
        ):
            raise ValueError("unbound replay marker")
        return old
    except (
        KeyError,
        OSError,
        TypeError,
        ValueError,
        UnicodeError,
        sqlite3.Error,
    ) as error:
        raise ValueError("POC_VALIDATOR_CORRECTION_REPLAY_UNBOUND") from error


def urlconf_replay_binding(
    checkpoint: StageCheckpoint,
    artifacts: SimpleArtifactRepository,
    *,
    _historical_validator_stop: bool = False,
) -> tuple[tuple[str, str, str, int], tuple[str, ...]] | None:
    """Re-derive this candidate-only replay from its immutable execution evidence."""

    if not checkpoint.recovery_decision_refs:
        return None
    try:
        if checkpoint.attempt_number == MAX_RECOVERY_ATTEMPTS + 7:
            old = validator_correction_replay_previous(checkpoint, artifacts)
            return urlconf_replay_binding(
                old, artifacts, _historical_validator_stop=True
            )
        if len(checkpoint.recovery_decision_refs) > 32:
            raise ValueError("too many recovery decisions")
        markers: list[tuple[StoredDataRef, dict[str, object]]] = []
        for ref in checkpoint.recovery_decision_refs:
            record = json.loads(artifacts.read_bounded(ref, 64 * 1024))
            if not isinstance(record, dict):
                raise ValueError("invalid recovery record")
            if record.get("urlconf_replay") is True:
                markers.append((ref, record))
        if not markers:
            return None
        if len(markers) != 1:
            raise ValueError("ambiguous URLConf replay")
        marker_ref, record = markers[0]
        decision = record.get("decision")
        original_error = record.get("original_error")
        signature = record.get("urlconf_signature")
        roots = record.get("urlconf_project_roots")
        failed_attempt = record.get("attempt")
        failed_attempt_int = failed_attempt if isinstance(failed_attempt, int) else None
        if (
            type(failed_attempt) is int
            and checkpoint.attempt_number == failed_attempt + 4
        ):
            layout = pinned_layout_replay_binding(
                checkpoint,
                artifacts,
                _historical_validator_stop=_historical_validator_stop,
            )
            if layout is None or layout[2].attempt_number != failed_attempt + 3:
                raise ValueError("unbound pinned layout extension")
            return urlconf_replay_binding(layout[2], artifacts)
        extended = type(failed_attempt) is int and checkpoint.attempt_number in {
            failed_attempt + 2,
            failed_attempt + 3,
        }
        if extended:
            if failed_attempt_int is None:
                raise ValueError("invalid URLConf attempt")
            second_extension = checkpoint.attempt_number == failed_attempt_int + 3
            extension_kind = (
                "simple_poc_urlconf_candidate_replay"
                if second_extension
                else "simple_poc_candidate_constraint_replay"
            )
            failure_event_field = (
                "urlconf_failure_event_id"
                if second_extension
                else "app_failure_event_id"
            )
            extension_refs: list[tuple[StoredDataRef, dict[str, object]]] = []
            for ref in checkpoint.recovery_decision_refs:
                extension = json.loads(artifacts.read_bounded(ref, 64 * 1024))
                if (
                    isinstance(extension, dict)
                    and extension.get("kind") == extension_kind
                ):
                    extension_refs.append((ref, extension))
            if len(extension_refs) != 1:
                raise ValueError("missing candidate constraint replay")
            extension_ref, extension = extension_refs[0]
            old_ref = StoredDataRef.model_validate(extension["old_checkpoint_ref"])
            old_bytes = artifacts.read_bounded(old_ref, 256 * 1024)
            old = StageCheckpoint.model_validate_json(old_bytes)
            if (
                extension_ref not in checkpoint.input_refs
                or old_ref not in checkpoint.input_refs
                or extension.get("identity")
                != checkpoint.identity.model_dump(mode="json")
                or extension.get("old_attempt_id") != old.attempt_id
                or extension.get("old_attempt_number")
                != failed_attempt_int + (2 if second_extension else 1)
                or extension.get("old_checkpoint_hash")
                != hashlib.sha256(
                    canonical_bytes(old.model_dump(mode="json"))
                ).hexdigest()
                or extension.get("diagnostic_ref")
                != (
                    old.output_refs[0].model_dump(mode="json")
                    if len(old.output_refs) == 1
                    else None
                )
                or any(
                    not isinstance(extension.get(field), str) or not extension[field]
                    for field in (
                        failure_event_field,
                        "exhaustion_event_id",
                        "root_failure_event_id",
                    )
                )
                or old.identity != checkpoint.identity
                or old.stage is not SimpleStage.POC_CANDIDATE_DONE
                or old.stage_version != checkpoint.stage_version
                or old.status is not StageStatus.BLOCKED
                or old.error_code != "RECOVERY_EXHAUSTED"
                or old.retryable
                or old.attempt_number
                != failed_attempt_int + (2 if second_extension else 1)
                or old.attempt_id == checkpoint.attempt_id
                or old.input_hash != input_reference_hash(old.input_refs)
                or old.recipe_ref != checkpoint.recipe_ref
                or old.image_digest != checkpoint.image_digest
                or old.recovery_lineage_id != checkpoint.recovery_lineage_id
                or old.recovery_origin_stage is not SimpleStage.POC_EXECUTION_DONE
                or tuple(checkpoint.recovery_decision_refs)
                != (*old.recovery_decision_refs, extension_ref)
                or any(
                    ref not in checkpoint.input_refs
                    for ref in (*old.input_refs, *old.output_refs)
                )
                or candidate_app_replay_unsupported_app(old, artifacts) is None
                or urlconf_replay_binding(old, artifacts) is None
            ):
                raise ValueError("unbound candidate constraint replay")
        if (
            marker_ref not in checkpoint.input_refs
            or record.get("kind") != "simple_recovery_decision"
            or record.get("identity") != checkpoint.identity.model_dump(mode="json")
            or record.get("stage") != SimpleStage.POC_EXECUTION_DONE.value
            or record.get("decision_origin") != "RULE"
            or record.get("diagnostic_excerpt")
            != "candidate-only Django URLConf namespace wiring"
            or record.get("explicit_exhaustion_replay") is not True
            or record.get("recovery_revision") != DJANGO_URLCONF_RECOVERY_REVISION
            or checkpoint.stage is not SimpleStage.POC_CANDIDATE_DONE
            or checkpoint.recovery_origin_stage is not SimpleStage.POC_EXECUTION_DONE
            or not checkpoint.recovery_lineage_id
            or type(failed_attempt) is not int
            or checkpoint.attempt_number
            not in {
                failed_attempt,
                failed_attempt + 1,
                failed_attempt + 2,
                failed_attempt + 3,
            }
            or not isinstance(record.get("attempt_id"), str)
            or not record["attempt_id"]
            or (
                checkpoint.attempt_number > failed_attempt
                and (
                    not checkpoint.attempt_id
                    or checkpoint.attempt_id == record["attempt_id"]
                )
            )
            or not isinstance(decision, dict)
            or decision.get("category") != "GENERATED_INPUT"
            or decision.get("action") != "REGENERATE_INPUT"
            or decision.get("environment_patch") != ""
            or not isinstance(original_error, dict)
            or original_error.get("code") != "POC_EXECUTION_FAILED"
            or not isinstance(signature, list)
            or len(signature) != 4
            or not isinstance(roots, list)
            or not roots
            or any(
                not isinstance(root, str)
                or _CANDIDATE_APP_NAME.fullmatch(root.encode("utf-8")) is None
                for root in roots
            )
        ):
            raise ValueError("unbound URLConf replay")
        evidence = tuple(
            StoredDataRef.model_validate(value)
            for value in original_error["evidence_refs"]
        )
        if len(evidence) != 4 or any(
            ref not in checkpoint.input_refs for ref in evidence
        ):
            raise ValueError("unbound URLConf evidence")
        execution = json.loads(artifacts.read_bounded(evidence[0], 64 * 1024))
        cleanup = json.loads(artifacts.read_bounded(evidence[3], 64 * 1024))
        if not isinstance(execution, dict) or not isinstance(cleanup, dict):
            raise ValueError("invalid execution or cleanup receipt")
        candidate_ref = StoredDataRef.model_validate(execution["candidate_ref"])
        content_ref = StoredDataRef.model_validate(execution["content_ref"])
        if (
            execution.get("kind") != "simple_poc_execution"
            or execution.get("attempt_id") != record["attempt_id"]
            or execution.get("exit_code") != 2
            or execution.get("timed_out") is not False
            or execution.get("stdout_ref") != evidence[1].model_dump(mode="json")
            or execution.get("stderr_ref") != evidence[2].model_dump(mode="json")
            or cleanup.get("kind") != "simple_container_cleanup"
            or cleanup.get("attempt_id") != record["attempt_id"]
            or cleanup.get("container_id") != execution.get("container_id")
            or cleanup.get("status") != "REMOVED"
            or candidate_ref not in checkpoint.input_refs
            or content_ref not in checkpoint.input_refs
        ):
            raise ValueError("unbound execution receipt")
        candidate = json.loads(artifacts.read_bounded(candidate_ref, 64 * 1024))
        content = artifacts.read_bounded(content_ref, 1024 * 1024)
        if (
            not isinstance(candidate, dict)
            or candidate.get("kind") != "simple_poc_candidate"
            or candidate.get("attempt_id") != record["attempt_id"]
            or candidate.get("content_ref") != content_ref.model_dump(mode="json")
            or candidate.get("content_digest") != hashlib.sha256(content).hexdigest()
        ):
            raise ValueError("unbound candidate content")
        derived = django_urlconf_reverse_failure(
            artifacts.read_bounded(evidence[2], 1024 * 1024),
            artifacts.read_bounded(evidence[1], 1024 * 1024),
            content,
        )
        if derived is None or list(derived) != signature:
            raise ValueError("URLConf diagnostic changed")
        return derived, tuple(roots)
    except (
        KeyError,
        OSError,
        TypeError,
        ValueError,
        UnicodeError,
        sqlite3.Error,
    ) as error:
        raise ValueError("POC_URLCONF_REPLAY_UNBOUND") from error


def literal_required_python_path(candidate: bytes, stderr: bytes) -> str | None:
    """Return one failed, literal Python source prerequisite, never an arbitrary path.

    This only classifies a direct ``isfile`` guard that raises a harness error
    on the same line recorded by the executed Python traceback. It does not
    infer file absence from the checkout alone.
    """

    match = re.fullmatch(
        rb"HarnessError\r?\nTraceback \(most recent call last\):\r?\n"
        rb"  at unresolved_frame:(?P<line>[0-9]+)\r?\n?",
        stderr,
    )
    tree = _django_candidate_url_tree(candidate)
    if match is None or tree is None or len(candidate) > 1024 * 1024:
        return None
    if candidate.startswith(b"#!/bin/sh"):
        preamble = candidate.split(b"python - <<", 1)[0].splitlines()
        printed_cd = (
            b"cd /workspace || { printf 'HarnessError: workspace_unavailable\\n"
            b"Traceback: at startup\\n' >&2; exit 2; }"
        )
        if preamble not in (
            [b"#!/bin/sh", b"cd /workspace || exit 2"],
            [
                b"#!/bin/sh",
                b"cd /workspace || exit 2",
                b"export PYTHONDONTWRITEBYTECODE=1",
            ],
            [b"#!/bin/sh", printed_cd, b"export PYTHONDONTWRITEBYTECODE=1"],
        ):
            return None
    failed_line = int(match.group("line"))
    prior_nodes = [
        node
        for node in _candidate_top_level_nodes(tree)
        if getattr(node, "lineno", failed_line) < failed_line
    ]
    if not _safe_prior_definitions(tree, failed_line) or not (
        _read_only_before_failed_guard(prior_nodes)
    ):
        return None
    if not any(
        isinstance(node, ast.Import)
        and any(alias.name == "os" and alias.asname is None for alias in node.names)
        for node in tree.body
    ) and not any(
        isinstance(stmt, ast.Try)
        and any(
            isinstance(node, ast.Import)
            and any(alias.name == "os" and alias.asname is None for alias in node.names)
            for node in stmt.body
        )
        for stmt in tree.body
    ):
        return None
    results: list[tuple[str, str]] = []
    for statement in tree.body:
        if not isinstance(statement, ast.Try):
            continue
        roots: dict[str, str] = {}
        for item in statement.body:
            if isinstance(item, ast.Assign) and len(item.targets) == 1:
                target = item.targets[0]
                if isinstance(target, ast.Name):
                    if isinstance(item.value, ast.Constant) and isinstance(
                        item.value.value, str
                    ):
                        roots[target.id] = item.value.value
                    else:
                        roots.pop(target.id, None)
            elif isinstance(item, (ast.AugAssign, ast.AnnAssign)) and isinstance(
                item.target, ast.Name
            ):
                roots.pop(item.target.id, None)
            if not isinstance(item, ast.If) or item.orelse or len(item.body) != 1:
                continue
            raised = item.body[0]
            if (
                not isinstance(raised, ast.Raise)
                or raised.lineno != failed_line
                or not isinstance(raised.exc, ast.Call)
                or not isinstance(raised.exc.func, ast.Name)
                or raised.exc.func.id != "HarnessError"
                or raised.cause is not None
            ):
                continue
            predicate = item.test
            if (
                not isinstance(predicate, ast.UnaryOp)
                or not isinstance(predicate.op, ast.Not)
                or not isinstance(predicate.operand, ast.Call)
                or not isinstance(predicate.operand.func, ast.Attribute)
                or predicate.operand.func.attr != "isfile"
                or not isinstance(predicate.operand.func.value, ast.Attribute)
                or predicate.operand.func.value.attr != "path"
                or not isinstance(predicate.operand.func.value.value, ast.Name)
                or predicate.operand.func.value.value.id != "os"
                or len(predicate.operand.args) != 1
                or predicate.operand.keywords
            ):
                continue
            path_expr = predicate.operand.args[0]
            if (
                not isinstance(path_expr, ast.BinOp)
                or not isinstance(path_expr.op, ast.Add)
                or not isinstance(path_expr.left, ast.Name)
                or not isinstance(path_expr.right, ast.Constant)
                or not isinstance(path_expr.right.value, str)
                or path_expr.left.id not in roots
            ):
                continue
            path = roots[path_expr.left.id] + path_expr.right.value
            if (
                not path.startswith("/workspace/")
                or not path.endswith(".py")
                or len(path) > 4096
                or any(part in {"", ".", ".."} for part in path.split("/")[2:])
                or "\\" in path
                or "\x00" in path
            ):
                continue
            results.append((path_expr.left.id, path))
    if len(results) != 1:
        return None
    root_name, path = results[0]
    if (
        sum(
            isinstance(node, ast.Name)
            and node.id == root_name
            and isinstance(node.ctx, (ast.Store, ast.Del))
            for node in prior_nodes
        )
        != 1
    ):
        return None
    return path


def _safe_prior_definitions(tree: ast.AST, failed_line: int) -> bool:
    for node in ast.walk(tree):
        if getattr(node, "lineno", failed_line) >= failed_line:
            continue
        if isinstance(node, (ast.AsyncFunctionDef, ast.ClassDef)):
            if not (
                isinstance(node, ast.ClassDef)
                and node.name == "HarnessError"
                and not node.decorator_list
                and not node.keywords
                and len(node.bases) == 1
                and isinstance(node.bases[0], ast.Name)
                and node.bases[0].id == "Exception"
                and len(node.body) == 1
                and isinstance(node.body[0], ast.Pass)
            ):
                return False
        if isinstance(node, ast.FunctionDef):
            arguments = node.args
            parameters = (
                *arguments.posonlyargs,
                *arguments.args,
                *arguments.kwonlyargs,
            )
            if (
                node.name in {"open", "print", "os", "hashlib", "HarnessError"}
                or node.decorator_list
                or arguments.defaults
                or any(value is not None for value in arguments.kw_defaults)
                or node.returns is not None
                or any(arg.annotation is not None for arg in parameters)
                or arguments.vararg is not None
                and arguments.vararg.annotation is not None
                or arguments.kwarg is not None
                and arguments.kwarg.annotation is not None
            ):
                return False
    return True


def _read_only_before_failed_guard(nodes: list[ast.AST]) -> bool:
    """Fail closed on calls or bindings that could alter the observed path.

    This is deliberately a small syntax whitelist, not a general Python effect
    analyzer. The executed Docker receipt is still required by the caller.
    """

    safe_modules = {
        "hashlib",
        "importlib.util",
        "os",
        "re",
        "sys",
        "tempfile",
        "traceback",
    }
    protected = {"open", "print", "os", "hashlib", "HarnessError"}
    for node in nodes:
        if isinstance(node, ast.Import) and any(
            alias.name not in safe_modules or alias.asname is not None
            for alias in node.names
        ):
            return False
        if isinstance(node, ast.ImportFrom):
            return False
        if isinstance(node, (ast.Attribute, ast.Subscript)) and isinstance(
            node.ctx, (ast.Store, ast.Del)
        ):
            return False
        if (
            isinstance(node, ast.Name)
            and node.id in protected
            and isinstance(node.ctx, (ast.Store, ast.Del))
        ):
            return False

    read_streams: set[str] = set()
    for node in nodes:
        if not isinstance(node, ast.With):
            continue
        for item in node.items:
            if isinstance(item.optional_vars, ast.Name) and _read_only_open(
                item.context_expr
            ):
                read_streams.add(item.optional_vars.id)
    for name in read_streams:
        if (
            sum(
                isinstance(node, ast.Name)
                and node.id == name
                and isinstance(node.ctx, (ast.Store, ast.Del))
                for node in nodes
            )
            != 1
        ):
            return False

    raised_errors = {
        id(node.exc)
        for node in nodes
        if isinstance(node, ast.Raise) and node.exc is not None
    }
    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            if func.id == "open" and _read_only_open(node):
                continue
            if (
                func.id == "print"
                and not node.keywords
                and all(
                    isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                    for arg in node.args
                )
            ):
                continue
            if (
                func.id == "HarnessError"
                and id(node) in raised_errors
                and (
                    len(node.args) == 1
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)
                    and not node.keywords
                )
            ):
                continue
            return False
        if not isinstance(func, ast.Attribute) or node.keywords:
            return False
        receiver = func.value
        if (
            func.attr == "isfile"
            and isinstance(receiver, ast.Attribute)
            and receiver.attr == "path"
            and isinstance(receiver.value, ast.Name)
            and receiver.value.id == "os"
            and len(node.args) == 1
        ):
            continue
        if (
            func.attr == "sha256"
            and isinstance(receiver, ast.Name)
            and receiver.id == "hashlib"
            and len(node.args) == 1
        ):
            continue
        if (
            func.attr == "read"
            and isinstance(receiver, ast.Name)
            and receiver.id in read_streams
            and not node.args
        ):
            continue
        if (
            func.attr == "hexdigest"
            and isinstance(receiver, ast.Call)
            and isinstance(receiver.func, ast.Attribute)
            and receiver.func.attr == "sha256"
            and isinstance(receiver.func.value, ast.Name)
            and receiver.func.value.id == "hashlib"
            and not node.args
        ):
            continue
        return False
    return True


def _read_only_open(node: ast.AST) -> bool:
    if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
        return False
    if node.func.id != "open" or not node.args or len(node.args) > 2:
        return False
    if any(kw.arg != "mode" for kw in node.keywords):
        return False
    mode = (
        node.args[1]
        if len(node.args) == 2
        else next((kw.value for kw in node.keywords if kw.arg == "mode"), None)
    )
    return (
        isinstance(mode, ast.Constant)
        and mode.value in {"r", "rb", "rt"}
        and len(node.args) + len(node.keywords) == 2
    )


def pinned_layout_replay_binding(
    checkpoint: StageCheckpoint,
    artifacts: SimpleArtifactRepository,
    *,
    _historical_validator_stop: bool = False,
) -> tuple[str, str, StageCheckpoint] | None:
    """Re-bind the one executed layout failure and its previous candidate chain."""

    if not checkpoint.recovery_decision_refs:
        return None
    if checkpoint.attempt_number == MAX_RECOVERY_ATTEMPTS + 7:
        old = validator_correction_replay_previous(checkpoint, artifacts)
        return pinned_layout_replay_binding(
            old, artifacts, _historical_validator_stop=True
        )
    try:
        if len(checkpoint.recovery_decision_refs) > 32:
            raise ValueError("too many decisions")
        records = [
            json.loads(artifacts.read_bounded(ref, 64 * 1024))
            for ref in checkpoint.recovery_decision_refs
        ]
        selected = [
            (ref, record)
            for ref, record in zip(
                checkpoint.recovery_decision_refs, records, strict=True
            )
            if isinstance(record, dict) and record.get("pinned_layout_replay") is True
        ]
        if not selected:
            return None
        if len(selected) != 1:
            raise ValueError("ambiguous layout replay")
        marker_ref, marker = selected[0]
        old_ref = StoredDataRef.model_validate(
            marker["layout_candidate_checkpoint_ref"]
        )
        old = StageCheckpoint.model_validate_json(
            artifacts.read_bounded(old_ref, 256 * 1024)
        )
        failed_ref = StoredDataRef.model_validate(
            marker["layout_execution_checkpoint_ref"]
        )
        failed_execution = StageCheckpoint.model_validate_json(
            artifacts.read_bounded(failed_ref, 256 * 1024)
        )
        old_hash = hashlib.sha256(
            canonical_bytes(old.model_dump(mode="json"))
        ).hexdigest()
        failed_hash = hashlib.sha256(
            canonical_bytes(failed_execution.model_dump(mode="json"))
        ).hexdigest()
        original_error = marker["original_error"]
        evidence = tuple(
            StoredDataRef.model_validate(value)
            for value in original_error["evidence_refs"]
        )
        if (
            marker_ref != checkpoint.recovery_decision_refs[-1]
            or marker_ref not in checkpoint.input_refs
            or old_ref not in checkpoint.input_refs
            or failed_ref not in checkpoint.input_refs
            or marker.get("kind") != "simple_recovery_decision"
            or marker.get("identity") != checkpoint.identity.model_dump(mode="json")
            or marker.get("stage") != SimpleStage.POC_EXECUTION_DONE.value
            or marker.get("attempt") != 8
            or marker.get("explicit_exhaustion_replay") is not True
            or marker.get("decision_origin") != "RULE"
            or marker.get("diagnostic_excerpt")
            != "executed required pinned Python source path mismatch"
            or marker.get("layout_candidate_checkpoint_hash") != old_hash
            or marker.get("layout_execution_checkpoint_hash") != failed_hash
            or marker.get("exhausted_checkpoint_hash") != failed_hash
            or marker.get("failure_event_id") is None
            or marker.get("exhaustion_event_id") is None
            or not isinstance(original_error, dict)
            or original_error.get("code") != "POC_EXECUTION_FAILED"
            or len(evidence) != 4
            or any(ref not in checkpoint.input_refs for ref in evidence)
            or checkpoint.stage is not SimpleStage.POC_CANDIDATE_DONE
            or not (
                checkpoint.status
                in {StageStatus.PENDING, StageStatus.RUNNING, StageStatus.SUCCEEDED}
                or _historical_validator_stop
                and checkpoint.attempt_number == MAX_RECOVERY_ATTEMPTS + 6
                and checkpoint.status is StageStatus.BLOCKED
                and checkpoint.error_code == "RECOVERY_EXHAUSTED"
                and not checkpoint.retryable
            )
            or checkpoint.attempt_number not in {8, 9}
            or checkpoint.input_hash != input_reference_hash(checkpoint.input_refs)
            or checkpoint.identity != old.identity
            or checkpoint.recipe_ref != old.recipe_ref
            or checkpoint.image_digest != old.image_digest
            or checkpoint.recovery_lineage_id != old.recovery_lineage_id
            or checkpoint.recovery_origin_stage is not SimpleStage.POC_EXECUTION_DONE
            or tuple(checkpoint.recovery_decision_refs)
            != (*old.recovery_decision_refs, marker_ref)
            or any(
                ref not in checkpoint.input_refs
                for ref in (*old.input_refs, *old.output_refs)
            )
            or old.stage is not SimpleStage.POC_CANDIDATE_DONE
            or old.status is not StageStatus.SUCCEEDED
            or old.attempt_number != 8
            or old.attempt_id != marker.get("attempt_id")
            or old.input_hash != input_reference_hash(old.input_refs)
            or len(old.output_refs) < 2
            or failed_execution.stage is not SimpleStage.POC_EXECUTION_DONE
            or failed_execution.status is not StageStatus.BLOCKED
            or failed_execution.error_code != "RECOVERY_EXHAUSTED"
            or failed_execution.retryable
            or failed_execution.attempt_number != 8
            or failed_execution.attempt_id != old.attempt_id
            or failed_execution.identity != old.identity
            or failed_execution.recipe_ref != old.recipe_ref
            or failed_execution.image_digest != old.image_digest
            or failed_execution.recovery_lineage_id != old.recovery_lineage_id
            or failed_execution.input_hash
            != input_reference_hash(failed_execution.input_refs)
            or failed_execution.output_refs != evidence
            or any(
                ref not in checkpoint.input_refs for ref in failed_execution.input_refs
            )
            or any(
                ref not in failed_execution.input_refs for ref in old.output_refs[:2]
            )
        ):
            raise ValueError("unbound layout replay")
        execution = json.loads(artifacts.read_bounded(evidence[0], 64 * 1024))
        cleanup = json.loads(artifacts.read_bounded(evidence[3], 64 * 1024))
        candidate = json.loads(artifacts.read_bounded(old.output_refs[0], 64 * 1024))
        content = artifacts.read_bounded(old.output_refs[1], 1024 * 1024)
        if (
            execution.get("kind") != "simple_poc_execution"
            or execution.get("attempt_id") != old.attempt_id
            or execution.get("candidate_ref")
            != old.output_refs[0].model_dump(mode="json")
            or execution.get("content_ref")
            != old.output_refs[1].model_dump(mode="json")
            or execution.get("stdout_ref") != evidence[1].model_dump(mode="json")
            or execution.get("stderr_ref") != evidence[2].model_dump(mode="json")
            or execution.get("exit_code") != 2
            or execution.get("timed_out") is not False
            or execution.get("image_digest") != old.image_digest
            or cleanup.get("kind") != "simple_container_cleanup"
            or cleanup.get("attempt_id") != old.attempt_id
            or cleanup.get("container_id") != execution.get("container_id")
            or cleanup.get("status") != "REMOVED"
            or candidate.get("kind") != "simple_poc_candidate"
            or candidate.get("attempt_id") != old.attempt_id
            or candidate.get("content_ref")
            != old.output_refs[1].model_dump(mode="json")
            or candidate.get("content_digest") != hashlib.sha256(content).hexdigest()
        ):
            raise ValueError("unbound layout receipt")
        stderr = artifacts.read_bounded(evidence[2], 1024 * 1024)
        failed = literal_required_python_path(content, stderr)
        corrected = marker.get("layout_corrected_path")
        if (
            failed is None
            or failed != marker.get("layout_failed_path")
            or not isinstance(corrected, str)
            or not corrected.startswith("/workspace/")
            or corrected == failed
            or not corrected.endswith(".py")
            or not isinstance(marker.get("layout_dockerfile_ref"), dict)
        ):
            raise ValueError("unbound layout paths")
        # The old candidate's URL and absent-app proofs are required.
        if (
            urlconf_replay_binding(old, artifacts) is None
            or candidate_app_replay_unsupported_app(old, artifacts) is None
        ):
            raise ValueError("unbound prior constraints")
        return failed, corrected, old
    except (
        KeyError,
        OSError,
        TypeError,
        ValueError,
        UnicodeError,
        sqlite3.Error,
    ) as error:
        raise ValueError("POC_GENERATED_INPUT_REPLAY_UNBOUND") from error


def sanitized_extract_failure(output: bytes) -> bytes | None:
    """Return only an exact phase/class label, never a traceback or source text."""

    if _SANITIZED_EXTRACT_FAILURE.fullmatch(output) is None:
        return None
    return output.strip().replace(b"\r\n", b"\n")


def sanitized_extract_recovery_decision() -> RecoveryDecision:
    """Guidance contains only fixed policy text, never repository source."""

    return RecoveryDecision(
        category=RecoveryCategory.GENERATED_INPUT,
        action=RecoveryAction.REGENERATE_INPUT,
        diagnosis="The generated PoC failed while extracting source context",
        guidance=(
            "Regenerate only the PoC from the pinned source. Inspect the actual "
            "AST route or handler selection and avoid assertions about a fixed "
            "node count; validate the selected branch before execution. Keep "
            "target and framework behavior intact and do not treat this setup "
            "error as vulnerability counterevidence."
        ),
    )


def django_poc_fixture_failure(stderr: bytes, candidate: bytes) -> str | None:
    """Classify only bounded, redacted Django setup frames in a schema-building PoC.

    The returned label is fixed policy text, not a copy of untrusted stderr.
    It establishes a generated-input repair opportunity, never a finding verdict.
    """

    if (
        not stderr
        or len(stderr) > 8 * 1024
        or len(candidate) > _MAX_POC_CANDIDATE_BYTES
        or b"django.setup(" not in candidate
        or not (
            b"schema_editor(" in candidate
            or (b"call_command(" in candidate and b"migrate" in candidate)
        )
    ):
        return None
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    if not lines or len(lines) > 40:
        return None
    if lines[0] == b"stage=schema":
        lines = lines[1:]
    if len(lines) < 2 or not any(b"Traceback" in line for line in lines[1:]):
        return None
    frames = b"\n".join(lines[1:])
    if (
        lines[0] in {b"NodeNotFoundError", b"NodeNotFoundError during schema"}
        and b"build_graph" in frames
        and b"validate_consistency" in frames
    ):
        return "migration graph"
    if lines == [
        b"ValueError: harness_runtime",
        b"Traceback (function names only):",
        b"in db_parameters",
        b"in target_field",
        b"in __get__",
        b"in foreign_related_fields",
        b"in __get__",
        b"in related_fields",
        b"in resolve_related_fields",
        b"in resolve_related_fields",
    ]:
        return "model relation"
    if (
        lines[0] in {b"ValueError", b"ValueError during schema"}
        and b"foreign_related_fields" in frames
        and b"resolve_related_fields" in frames
    ):
        return "model relation"
    if lines[0] in {b"OperationalError", b"OperationalError: writable_storage"}:
        if b"execute" in frames and (
            b"_insert" in frames or lines[0] == b"OperationalError: writable_storage"
        ):
            return "fixture database"
    return None


def _django_literal_configuration(candidate: bytes) -> dict[str, object] | None:
    """Read one direct settings.configure call without evaluating candidate code."""

    tree = _django_candidate_url_tree(candidate)
    if tree is None:
        return None
    calls = [
        node
        for node in _candidate_top_level_nodes(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "settings"
        and node.func.attr == "configure"
    ]
    if (
        len(calls) != 1
        or calls[0].args
        or any(keyword.arg is None for keyword in calls[0].keywords)
    ):
        return None
    names = [keyword.arg for keyword in calls[0].keywords]
    if len(names) != len(set(names)):
        return None
    values: dict[str, object] = {}
    for keyword in calls[0].keywords:
        assert keyword.arg is not None
        if keyword.arg not in {"ROOT_URLCONF", "INSTALLED_APPS"}:
            if isinstance(keyword.value, ast.Constant):
                values[keyword.arg] = keyword.value.value
            continue
        try:
            values[keyword.arg] = ast.literal_eval(keyword.value)
        except (ValueError, TypeError, MemoryError, RecursionError):
            return None
    root = values.get("ROOT_URLCONF")
    apps = values.get("INSTALLED_APPS")
    if (
        not isinstance(root, str)
        or re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+", root) is None
        or not root.endswith(".urls")
        or not isinstance(apps, (tuple, list))
        or len(apps) > 64
        or not all(isinstance(app, str) for app in apps)
    ):
        return None
    return values


def django_migration_setting_mismatch(
    stderr: bytes,
    stdout: bytes,
    candidate: bytes,
    project_settings: bytes,
    app_settings: bytes,
    migration: bytes,
    *,
    app_name: str,
) -> str | None:
    """Find a pinned default-off switch omitted by a generated migration PoC."""

    if (
        len(stderr) > 1024
        or len(stdout) > 4096
        or re.fullmatch(
            rb"NodeNotFoundError\r?\nTraceback \(most recent call last\):\r?\n"
            rb"(?:  at [A-Za-z_][A-Za-z_0-9]*:[0-9]+\r?\n?){2,20}",
            stderr,
        )
        is None
        or b"  at build_graph:" not in stderr
        or b"  at validate_consistency:" not in stderr
        or re.search(rb"(?i)\b(?:reproduced|confirmed|route resolved)\b", stdout)
        or b"SASTSIMI_POC_INCONCLUSIVE" in stdout
        or b"django.setup(" not in candidate
        or b"call_command(" not in candidate
        or b"migrate" not in candidate
        or b"client.get(" in candidate.split(b"call_command(", 1)[0]
        or not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", app_name)
    ):
        return None
    config = _django_literal_configuration(candidate)
    configured_apps = config.get("INSTALLED_APPS") if config is not None else None
    if (
        not isinstance(configured_apps, (list, tuple))
        or app_name not in configured_apps
    ):
        return None
    try:
        project_tree = ast.parse(project_settings.decode("utf-8"))
        app_tree = ast.parse(app_settings.decode("utf-8"))
        migration_tree = ast.parse(migration.decode("utf-8"))
    except (UnicodeError, SyntaxError, ValueError):
        return None
    project_assignments = {
        target.id: node.value
        for node in project_tree.body
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name)
    }
    imported_settings = {
        alias.asname or alias.name
        for node in migration_tree.body
        if isinstance(node, ast.ImportFrom) and node.module == app_name
        for alias in node.names
        if alias.name == "settings"
    }
    if len(imported_settings) != 1:
        return None
    migration_alias = next(iter(imported_settings))
    migration_dependencies = {
        node.value.right.attr
        for node in ast.walk(migration_tree)
        if isinstance(node, ast.Assign)
        and any(
            isinstance(t, ast.Name) and t.id == "dependencies" for t in node.targets
        )
        and isinstance(node.value, ast.BinOp)
        and isinstance(node.value.op, ast.Add)
        and isinstance(node.value.right, ast.Attribute)
        and isinstance(node.value.right.value, ast.Name)
        and node.value.right.value.id == migration_alias
    }
    for node in app_tree.body:
        if (
            not isinstance(node, ast.Assign)
            or len(node.targets) != 1
            or not isinstance(node.targets[0], ast.Name)
            or not isinstance(node.value, ast.Call)
            or not isinstance(node.value.func, ast.Name)
            or node.value.func.id != "getattr"
            or len(node.value.args) != 3
            or not isinstance(node.value.args[0], ast.Name)
            or node.value.args[0].id != "settings"
            or not isinstance(node.value.args[1], ast.Constant)
            or node.value.args[1].value != node.targets[0].id
            or not isinstance(node.value.args[2], ast.Constant)
            or node.value.args[2].value is not True
        ):
            continue
        flag = node.targets[0].id
        if (
            (config is not None and flag in config)
            or not re.fullmatch(r"[A-Z][A-Z_0-9]*", flag)
            or flag not in project_assignments
            or not _django_project_default_false(project_assignments[flag], flag)
        ):
            continue
        for condition in app_tree.body:
            if (
                not isinstance(condition, ast.If)
                or not isinstance(condition.test, ast.Name)
                or condition.test.id != flag
            ):
                continue
            for statement in condition.body:
                if (
                    not isinstance(statement, ast.Assign)
                    or len(statement.targets) != 1
                    or not isinstance(statement.targets[0], ast.Name)
                    or statement.targets[0].id not in migration_dependencies
                    or not isinstance(statement.value, ast.Call)
                    or not isinstance(statement.value.func, ast.Name)
                    or statement.value.func.id != "getattr"
                    or len(statement.value.args) != 3
                    or not isinstance(statement.value.args[1], ast.Constant)
                    or statement.value.args[1].value != statement.targets[0].id
                ):
                    continue
                try:
                    dependencies = ast.literal_eval(statement.value.args[2])
                except (ValueError, TypeError, MemoryError, RecursionError):
                    continue
                if (
                    isinstance(dependencies, list)
                    and dependencies
                    and all(
                        isinstance(item, tuple)
                        and len(item) == 2
                        and all(isinstance(part, str) for part in item)
                        for item in dependencies
                    )
                    and any(item[0] not in configured_apps for item in dependencies)
                    and any(
                        isinstance(other, ast.Assign)
                        and any(
                            isinstance(t, ast.Name) and t.id == statement.targets[0].id
                            for t in other.targets
                        )
                        and isinstance(other.value, (ast.List, ast.Tuple))
                        and not other.value.elts
                        for other in condition.orelse
                    )
                ):
                    return flag
    return None


def django_settings_replay_forbidden(content: bytes, flag: str) -> bool:
    """Require the next PoC to spell out the pinned default-off override."""

    config = _django_literal_configuration(content)
    tree = _django_candidate_url_tree(content)
    if config is None or tree is None or config.get(flag) is not False:
        return True
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if any(
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "settings"
                and target.attr == flag
                for target in targets
            ):
                return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in {"setattr", "delattr"}
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "settings"
        ):
            return True
    return False


def _candidate_sensitive_content_replay_marker(
    checkpoint: StageCheckpoint, artifacts: SimpleArtifactRepository
) -> bool:
    """Distinguish a bound candidate-content retry from a settings replay."""

    if (
        checkpoint.stage is not SimpleStage.POC_CANDIDATE_DONE
        or checkpoint.recovery_origin_stage is not SimpleStage.POC_CANDIDATE_DONE
        or not checkpoint.recovery_decision_refs
        or len(checkpoint.recovery_decision_refs) > 32
        or checkpoint.input_hash != input_reference_hash(checkpoint.input_refs)
        or checkpoint.container_id is not None
        or checkpoint.validated_poc_ref is not None
    ):
        return False
    decision_ref = checkpoint.recovery_decision_refs[-1]
    if decision_ref not in checkpoint.input_refs:
        return False
    try:
        decision_record = json.loads(artifacts.read_bounded(decision_ref, 64 * 1024))
    except (OSError, TypeError, ValueError, UnicodeError):
        return False
    return bool(
        isinstance(decision_record, dict)
        and decision_record.get("kind") == "simple_recovery_decision"
        and decision_record.get("identity")
        == checkpoint.identity.model_dump(mode="json")
        and decision_record.get("stage") == SimpleStage.POC_CANDIDATE_DONE.value
        and type(decision_record.get("attempt")) is int
        and decision_record["attempt"] in {1, 2}
        and isinstance(decision_record.get("attempt_id"), str)
        and decision_record["attempt_id"]
        and isinstance(decision_record.get("original_error"), dict)
        and decision_record["original_error"].get("code") == "POC_SENSITIVE_CONTENT"
        and isinstance(decision_record.get("decision"), dict)
        and decision_record["decision"].get("category") == "GENERATED_INPUT"
        and decision_record["decision"].get("action") in {"REGENERATE_INPUT", "STOP"}
    )


def _settings_replay_binding(
    checkpoint: StageCheckpoint,
    artifacts: SimpleArtifactRepository,
    *,
    relation: bool,
    migration: bool = False,
    allow_blocked_migration_candidate: bool = False,
) -> tuple[str, StageCheckpoint] | None:
    """Rebind the one settings repair to its saved execution and source blobs."""

    prior_attempt = (
        MAX_RECOVERY_ATTEMPTS if relation or migration else MAX_RECOVERY_ATTEMPTS + 7
    )
    if checkpoint.attempt_number != prior_attempt + 1:
        return None
    # A candidate-stage content retry can reach the same numeric attempt as
    # an execution-stage settings repair. Only its bound recovery record may
    # exempt it from the migration/relation settings proof.
    if _candidate_sensitive_content_replay_marker(checkpoint, artifacts):
        return None
    try:
        if (
            checkpoint.stage is not SimpleStage.POC_CANDIDATE_DONE
            or (
                checkpoint.status
                not in {StageStatus.PENDING, StageStatus.RUNNING, StageStatus.SUCCEEDED}
                and not (
                    allow_blocked_migration_candidate
                    and migration
                    and checkpoint.status is StageStatus.BLOCKED
                    and checkpoint.error_code == "RECOVERY_EXHAUSTED"
                    and checkpoint.retryable is False
                )
            )
            or not checkpoint.recovery_decision_refs
            or len(checkpoint.recovery_decision_refs) > 32
            or checkpoint.input_hash != input_reference_hash(checkpoint.input_refs)
            or checkpoint.recovery_origin_stage is not SimpleStage.POC_EXECUTION_DONE
            or checkpoint.container_id is not None
            or checkpoint.validated_poc_ref is not None
        ):
            raise ValueError("invalid settings replay checkpoint")
        marker_ref = checkpoint.recovery_decision_refs[-1]
        marker = json.loads(artifacts.read_bounded(marker_ref, 64 * 1024))
        if not isinstance(marker, dict):
            raise ValueError("invalid settings replay marker")
        if migration and marker.get("recovery_revision") != (
            DJANGO_MIGRATION_GRAPH_SETTINGS_SOURCE_BOUND_REVISION
        ):
            return None
        if relation and marker.get("recovery_revision") not in {
            DJANGO_RELATION_SETTINGS_RECOVERY_REVISION,
            DJANGO_RELATION_SETTINGS_SOURCE_BOUND_REVISION,
        }:
            return None
        old_candidate_ref = StoredDataRef.model_validate(
            marker["settings_candidate_checkpoint_ref"]
        )
        old_execution_ref = StoredDataRef.model_validate(
            marker["settings_execution_checkpoint_ref"]
        )
        old_candidate = StageCheckpoint.model_validate_json(
            artifacts.read_bounded(old_candidate_ref, 256 * 1024)
        )
        old_execution = StageCheckpoint.model_validate_json(
            artifacts.read_bounded(old_execution_ref, 256 * 1024)
        )
        source_paths = marker["settings_source_paths"]
        source_refs = tuple(
            StoredDataRef.model_validate(value)
            for value in marker["settings_source_refs"]
        )
        if (
            not isinstance(source_paths, list)
            or len(source_paths) != 3
            or not all(
                isinstance(path, str)
                and re.fullmatch(
                    r"(?:src/)?[A-Za-z_][A-Za-z_0-9]*"
                    r"(?:/[A-Za-z_0-9]+)+\.py",
                    path,
                )
                for path in source_paths
            )
            or len(source_refs) != 3
        ):
            raise ValueError("invalid settings source references")
        project_source, app_source, dependency_source = (
            artifacts.read_bounded(ref, 128 * 1024) for ref in source_refs
        )
        candidate_ref, content_ref = old_candidate.output_refs[:2]
        candidate_record = json.loads(artifacts.read_bounded(candidate_ref, 64 * 1024))
        content = artifacts.read_bounded(content_ref, 1024 * 1024)
        execution_ref, stdout_ref, stderr_ref, cleanup_ref = old_execution.output_refs
        execution = json.loads(artifacts.read_bounded(execution_ref, 64 * 1024))
        stdout = artifacts.read_bounded(stdout_ref, 1024 * 1024)
        stderr = artifacts.read_bounded(stderr_ref, 1024 * 1024)
        cleanup = json.loads(artifacts.read_bounded(cleanup_ref, 64 * 1024))
        if relation or migration:
            from .django_migration_graph_omission import (
                django_migration_graph_project_scan_root,
                django_migration_graph_settings_omission,
            )
            from .django_relation_settings_omission import (
                django_relation_project_settings_paths,
                django_relation_setting_mismatch,
            )

            app_name = (
                source_paths[1]
                .removeprefix("src/")
                .removesuffix("/settings.py")
                .replace("/", ".")
            )
            project_suffix = None
            flag = (
                None
                if migration
                else django_relation_setting_mismatch(
                    stderr,
                    stdout,
                    content,
                    project_source,
                    app_source,
                    dependency_source,
                    app_name=app_name,
                )
            )
            revision = marker.get("recovery_revision")
            if revision == DJANGO_RELATION_SETTINGS_RECOVERY_REVISION and not migration:
                if (
                    "settings_project_candidates" in marker
                    or "settings_project_selection" in marker
                    or "settings_tracked_manifest_ref" in marker
                    or "settings_reachable_sources" in marker
                ):
                    raise ValueError("mixed relation settings replay revisions")
            elif revision == (
                DJANGO_MIGRATION_GRAPH_SETTINGS_SOURCE_BOUND_REVISION
                if migration
                else DJANGO_RELATION_SETTINGS_SOURCE_BOUND_REVISION
            ):
                entries = marker.get("settings_project_candidates")
                mode = marker.get("settings_project_selection")
                reachable_entries = marker.get("settings_reachable_sources")
                if (
                    not isinstance(entries, list)
                    or not 1 <= len(entries) <= 16
                    or mode
                    not in ({"DYNAMIC"} if migration else {"LITERAL", "DYNAMIC"})
                    or not isinstance(reachable_entries, list)
                    or not 1 <= len(reachable_entries) <= 128
                ):
                    raise ValueError("invalid relation project binding")
                manifest_ref = StoredDataRef.model_validate(
                    marker["settings_tracked_manifest_ref"]
                )
                manifest = json.loads(
                    artifacts.read_bounded(manifest_ref, 8 * 1024 * 1024)
                )
                tracked_paths = (
                    manifest.get("paths") if isinstance(manifest, dict) else None
                )
                if (
                    manifest_ref not in checkpoint.input_refs
                    or not isinstance(manifest, dict)
                    or manifest.get("kind") != "simple_tracked_sources"
                    or not isinstance(tracked_paths, list)
                    or len(tracked_paths) > 100_000
                    or not all(isinstance(path, str) for path in tracked_paths)
                ):
                    raise ValueError("invalid relation tracked manifest")
                candidate_paths: list[str] = []
                candidate_refs: list[StoredDataRef] = []
                for entry in entries:
                    if not isinstance(entry, dict):
                        raise ValueError("invalid relation project entry")
                    path = entry.get("path")
                    if (
                        not isinstance(path, str)
                        or re.fullmatch(
                            r"(?:src/)?[A-Za-z_][A-Za-z_0-9]*"
                            r"(?:/[A-Za-z_0-9]+)+\.py",
                            path,
                        )
                        is None
                        or not path.endswith("/settings.py")
                    ):
                        raise ValueError("invalid relation project path")
                    candidate_paths.append(path)
                    candidate_refs.append(StoredDataRef.model_validate(entry["ref"]))
                if (
                    len(set(candidate_paths)) != len(candidate_paths)
                    or candidate_paths[0] != source_paths[0]
                    or candidate_refs[0] != source_refs[0]
                    or any(ref not in checkpoint.input_refs for ref in candidate_refs)
                ):
                    raise ValueError("unbound relation project candidates")
                selection: tuple[str, tuple[str, ...], str | None] | None
                if migration:
                    scan_root = django_migration_graph_project_scan_root(content)
                    selection = (
                        (
                            "DYNAMIC",
                            tuple(
                                sorted(
                                    path
                                    for path in tracked_paths
                                    if PurePosixPath(path).name == "settings.py"
                                )
                            ),
                            "",
                        )
                        if scan_root == "/workspace"
                        else None
                    )
                else:
                    selection = django_relation_project_settings_paths(
                        content,
                        set(tracked_paths),
                        app_name=app_name,
                    )
                if (
                    selection is None
                    or selection[0] != mode
                    or (mode == "LITERAL" and len(candidate_paths) != 1)
                ):
                    raise ValueError("unbound relation project selection")
                reachable_paths: list[str] = []
                reachable_refs: list[StoredDataRef] = []
                for entry in reachable_entries:
                    if not isinstance(entry, dict):
                        raise ValueError("invalid reachable relation source")
                    path = entry.get("path")
                    if not isinstance(path, str):
                        raise ValueError("invalid reachable relation path")
                    reachable_paths.append(path)
                    reachable_refs.append(StoredDataRef.model_validate(entry["ref"]))
                if (
                    len(set(reachable_paths)) != len(reachable_paths)
                    or set(reachable_paths) != set(selection[1])
                    or any(ref not in checkpoint.input_refs for ref in reachable_refs)
                ):
                    raise ValueError("unbound reachable relation sources")
                actual_projects: list[tuple[str, StoredDataRef]] = []
                for path, ref in zip(reachable_paths, reachable_refs, strict=True):
                    source = artifacts.read_bounded(ref, 128 * 1024)
                    if path == source_paths[1]:
                        if ref != source_refs[1]:
                            raise ValueError("unbound relation app settings")
                        continue
                    tree = ast.parse(source.decode("utf-8"))
                    installed = [
                        node.value
                        for node in tree.body
                        if isinstance(node, ast.Assign)
                        and any(
                            isinstance(target, ast.Name)
                            and target.id == "INSTALLED_APPS"
                            for target in node.targets
                        )
                    ]
                    if not installed and not migration:
                        continue
                    if len(installed) != 1:
                        raise ValueError("ambiguous relation project apps")
                    apps = ast.literal_eval(installed[0])
                    if not isinstance(apps, (list, tuple)) or app_name not in apps:
                        raise ValueError("conflicting relation project apps")
                    actual_projects.append((path, ref))
                actual_projects.sort(
                    key=lambda item: (len(PurePosixPath(item[0]).parts), item[0])
                )
                if actual_projects != list(
                    zip(candidate_paths, candidate_refs, strict=True)
                ):
                    raise ValueError("omitted relation project candidate")
                project_sources = tuple(
                    artifacts.read_bounded(ref, 128 * 1024) for ref in candidate_refs
                )
                if migration:
                    flag = django_migration_graph_settings_omission(
                        stderr,
                        stdout,
                        content,
                        project_sources,
                        app_source,
                        dependency_source,
                        app_name=app_name,
                    )
                elif any(
                    django_relation_setting_mismatch(
                        stderr,
                        stdout,
                        content,
                        source,
                        app_source,
                        dependency_source,
                        app_name=app_name,
                    )
                    != flag
                    for source in project_sources
                ):
                    raise ValueError("conflicting relation project setting")
            else:
                raise ValueError("unsupported relation settings replay revision")
        else:
            config = _django_literal_configuration(content)
            configured_apps = (
                config.get("INSTALLED_APPS") if config is not None else None
            )
            apps = configured_apps if isinstance(configured_apps, (list, tuple)) else ()
            root_module = config.get("ROOT_URLCONF") if config is not None else None
            project_suffix = (
                root_module.removesuffix(".urls").replace(".", "/") + "/settings.py"
                if isinstance(root_module, str)
                else None
            )
            matched_apps = [
                app
                for app in apps
                if isinstance(app, str)
                and source_paths[1]
                in {
                    app.replace(".", "/") + "/settings.py",
                    "src/" + app.replace(".", "/") + "/settings.py",
                }
            ]
            app_name = matched_apps[0] if len(matched_apps) == 1 else None
            flag = (
                django_migration_setting_mismatch(
                    stderr,
                    stdout,
                    content,
                    project_source,
                    app_source,
                    dependency_source,
                    app_name=app_name,
                )
                if app_name is not None
                else None
            )
        old_candidate_hash = hashlib.sha256(
            canonical_bytes(old_candidate.model_dump(mode="json"))
        ).hexdigest()
        old_execution_hash = hashlib.sha256(
            canonical_bytes(old_execution.model_dump(mode="json"))
        ).hexdigest()
        expected_lineage = (
            old_execution.recovery_lineage_id
            or hashlib.sha256(
                canonical_bytes(
                    {
                        "identity": checkpoint.identity,
                        "attempt_id": old_execution.attempt_id,
                    }
                )
            ).hexdigest()
        )
        original_error = marker["original_error"]
        evidence = tuple(
            StoredDataRef.model_validate(value)
            for value in original_error["evidence_refs"]
        )
        if (
            marker_ref not in checkpoint.input_refs
            or marker.get("kind") != "simple_recovery_decision"
            or marker.get("identity") != checkpoint.identity.model_dump(mode="json")
            or marker.get("stage") != SimpleStage.POC_EXECUTION_DONE.value
            or marker.get("attempt") != prior_attempt
            or marker.get("attempt_id") != old_execution.attempt_id
            or marker.get("decision_origin") != "RULE"
            or marker.get("diagnostic_excerpt")
            != (
                "pinned Django migration graph setting omission"
                if migration
                else (
                    "pinned Django relation settings mismatch"
                    if relation
                    else "pinned Django migration settings mismatch"
                )
            )
            or marker.get("explicit_exhaustion_replay") is not True
            or marker.get(
                "migration_settings_replay"
                if migration
                else "relation_settings_replay"
                if relation
                else "settings_mismatch_replay"
            )
            is not True
            or (
                not relation
                and not migration
                and marker.get("recovery_revision")
                != DJANGO_SETTINGS_MISMATCH_RECOVERY_REVISION
            )
            or marker.get("settings_flag") != flag
            or flag is None
            or (
                source_paths[2]
                != source_paths[1].removesuffix("settings.py") + "models.py"
                if relation
                else (
                    not source_paths[2].startswith(
                        source_paths[1].removesuffix("settings.py") + "migrations/"
                    )
                    if migration
                    else (
                        project_suffix is None
                        or source_paths[0]
                        not in {project_suffix, "src/" + project_suffix}
                        or not source_paths[2].startswith(
                            source_paths[1].removesuffix("settings.py") + "migrations/"
                        )
                    )
                )
            )
            or marker.get("settings_candidate_checkpoint_hash") != old_candidate_hash
            or marker.get("settings_execution_checkpoint_hash") != old_execution_hash
            or marker.get("exhausted_checkpoint_hash") != old_execution_hash
            or not all(
                isinstance(marker.get(field), str) and marker[field]
                for field in ("failure_event_id", "exhaustion_event_id")
            )
            or not isinstance(original_error, dict)
            or original_error.get("code") != "POC_EXECUTION_FAILED"
            or original_error.get("retryable") is not True
            or evidence != old_execution.output_refs
            or any(
                ref not in checkpoint.input_refs
                for ref in (
                    old_candidate_ref,
                    old_execution_ref,
                    *source_refs,
                    *old_candidate.input_refs,
                    *old_candidate.output_refs,
                    *old_execution.input_refs,
                    *old_execution.output_refs,
                )
            )
            or checkpoint.recovery_decision_refs
            != (*old_execution.recovery_decision_refs, marker_ref)
            or old_candidate.identity != checkpoint.identity
            or old_execution.identity != checkpoint.identity
            or old_candidate.stage is not SimpleStage.POC_CANDIDATE_DONE
            or old_candidate.status is not StageStatus.SUCCEEDED
            or old_candidate.attempt_number != prior_attempt
            or old_execution.stage is not SimpleStage.POC_EXECUTION_DONE
            or old_execution.status is not StageStatus.BLOCKED
            or old_execution.error_code != "RECOVERY_EXHAUSTED"
            or old_execution.retryable
            or old_execution.attempt_number != old_candidate.attempt_number
            or old_execution.attempt_id != old_candidate.attempt_id
            or old_candidate.input_hash
            != input_reference_hash(old_candidate.input_refs)
            or old_execution.input_hash
            != input_reference_hash(old_execution.input_refs)
            or any(
                ref not in old_execution.input_refs
                for ref in old_candidate.output_refs[:2]
            )
            or old_candidate.recipe_ref != checkpoint.recipe_ref
            or old_execution.recipe_ref != checkpoint.recipe_ref
            or old_candidate.image_digest != checkpoint.image_digest
            or old_execution.image_digest != checkpoint.image_digest
            or old_candidate.recovery_lineage_id != old_execution.recovery_lineage_id
            or checkpoint.recovery_lineage_id != expected_lineage
            or old_execution.gate_revision_count != checkpoint.gate_revision_count
            or old_candidate.gate_revision_count != checkpoint.gate_revision_count
            or checkpoint.attempt_id == old_execution.attempt_id
            or (
                checkpoint.status is StageStatus.PENDING
                and checkpoint.attempt_id is not None
            )
            or (
                checkpoint.status is not StageStatus.PENDING
                and not checkpoint.attempt_id
            )
            or not isinstance(candidate_record, dict)
            or candidate_record.get("kind") != "simple_poc_candidate"
            or candidate_record.get("attempt_id") != old_candidate.attempt_id
            or candidate_record.get("content_ref")
            != content_ref.model_dump(mode="json")
            or candidate_record.get("content_digest")
            != hashlib.sha256(content).hexdigest()
            or not isinstance(execution, dict)
            or execution.get("kind") != "simple_poc_execution"
            or execution.get("attempt_id") != old_execution.attempt_id
            or execution.get("candidate_ref") != candidate_ref.model_dump(mode="json")
            or execution.get("content_ref") != content_ref.model_dump(mode="json")
            or execution.get("stdout_ref") != stdout_ref.model_dump(mode="json")
            or execution.get("stderr_ref") != stderr_ref.model_dump(mode="json")
            or execution.get("image_digest") != old_execution.image_digest
            or execution.get("exit_code") != 2
            or execution.get("timed_out") is not False
            or not isinstance(cleanup, dict)
            or cleanup.get("kind") != "simple_container_cleanup"
            or cleanup.get("attempt_id") != old_execution.attempt_id
            or cleanup.get("status") != "REMOVED"
            or cleanup.get("container_id") != execution.get("container_id")
        ):
            raise ValueError("unbound settings replay")
        if not relation and not migration:
            validator_correction_replay_previous(old_candidate, artifacts)
            if (
                candidate_app_replay_unsupported_app(old_candidate, artifacts) is None
                or urlconf_replay_binding(old_candidate, artifacts) is None
                or pinned_layout_replay_binding(old_candidate, artifacts) is None
            ):
                raise ValueError("missing historical replay binding")
        return flag, old_candidate
    except (
        KeyError,
        IndexError,
        OSError,
        TypeError,
        ValueError,
        UnicodeError,
        sqlite3.Error,
    ) as error:
        code = (
            "POC_DJANGO_MIGRATION_SETTINGS_REPLAY_UNBOUND"
            if migration
            else "POC_DJANGO_RELATION_SETTINGS_REPLAY_UNBOUND"
            if relation
            else "POC_DJANGO_SETTINGS_REPLAY_UNBOUND"
        )
        raise ValueError(code) from error


def settings_replay_binding(
    checkpoint: StageCheckpoint, artifacts: SimpleArtifactRepository
) -> tuple[str, StageCheckpoint] | None:
    return _settings_replay_binding(checkpoint, artifacts, relation=False)


def relation_settings_replay_binding(
    checkpoint: StageCheckpoint, artifacts: SimpleArtifactRepository
) -> tuple[str, StageCheckpoint] | None:
    return _settings_replay_binding(checkpoint, artifacts, relation=True)


def migration_settings_replay_binding(
    checkpoint: StageCheckpoint, artifacts: SimpleArtifactRepository
) -> tuple[str, StageCheckpoint] | None:
    if checkpoint.attempt_number == MAX_RECOVERY_ATTEMPTS + 2:
        if _candidate_sensitive_content_replay_marker(checkpoint, artifacts):
            return None
        if checkpoint.recovery_decision_refs:
            try:
                final_marker = json.loads(
                    artifacts.read_bounded(
                        checkpoint.recovery_decision_refs[-1], 64 * 1024
                    )
                )
            except (OSError, TypeError, ValueError, UnicodeError):
                final_marker = None
            if not (
                isinstance(final_marker, dict)
                and final_marker.get("kind")
                == "simple_poc_django_migration_settings_candidate_replay"
            ):
                # Attempt numbers overlap with candidate-app replay, and a
                # later decision may follow its marker. Defer that lineage to
                # its own strict validator only when no migration marker is
                # present anywhere in the lineage.
                candidate_app_marker_seen = False
                migration_marker_seen = False
                for ref in checkpoint.recovery_decision_refs:
                    try:
                        marker = json.loads(artifacts.read_bounded(ref, 64 * 1024))
                    except (OSError, TypeError, ValueError, UnicodeError):
                        continue
                    if isinstance(marker, dict):
                        migration_marker_seen |= (
                            marker.get("kind")
                            == "simple_poc_django_migration_settings_candidate_replay"
                        )
                        candidate_app_marker_seen |= (
                            marker.get("candidate_app_replay") is True
                            or marker.get("diagnostic_excerpt")
                            == "candidate-only Django app import during setup"
                        )
                if candidate_app_marker_seen and not migration_marker_seen:
                    return None
            if (
                isinstance(final_marker, dict)
                and final_marker.get("kind") == "simple_recovery_decision"
                and final_marker.get("urlconf_replay") is True
                and urlconf_replay_binding(checkpoint, artifacts) is not None
            ):
                return None
        return _migration_settings_candidate_replay_binding(checkpoint, artifacts)
    return _settings_replay_binding(
        checkpoint, artifacts, relation=False, migration=True
    )


def migration_settings_blocked_replay_binding(
    checkpoint: StageCheckpoint, artifacts: SimpleArtifactRepository
) -> tuple[str, StageCheckpoint] | None:
    """Reverify the original pinned proof after a candidate-only replay fails.

    The ordinary candidate validator must continue rejecting a blocked checkpoint;
    only this source-bound recovery path may inspect it.
    """

    if checkpoint.stage is not SimpleStage.POC_CANDIDATE_DONE or (
        checkpoint.status is not StageStatus.BLOCKED
        or checkpoint.error_code != "RECOVERY_EXHAUSTED"
        or checkpoint.retryable
    ):
        return None
    return _settings_replay_binding(
        checkpoint,
        artifacts,
        relation=False,
        migration=True,
        allow_blocked_migration_candidate=True,
    )


def _migration_settings_candidate_replay_binding(
    checkpoint: StageCheckpoint, artifacts: SimpleArtifactRepository
) -> tuple[str, StageCheckpoint]:
    """Bind attempt five to the failed attempt and original pinned source proof."""

    try:
        if (
            checkpoint.stage is not SimpleStage.POC_CANDIDATE_DONE
            or checkpoint.status
            not in {StageStatus.PENDING, StageStatus.RUNNING, StageStatus.SUCCEEDED}
            or checkpoint.input_hash != input_reference_hash(checkpoint.input_refs)
            or checkpoint.recovery_origin_stage is not SimpleStage.POC_EXECUTION_DONE
            or not checkpoint.recovery_decision_refs
            or checkpoint.container_id is not None
            or checkpoint.validated_poc_ref is not None
        ):
            raise ValueError("invalid migration candidate checkpoint")
        marker_ref = checkpoint.recovery_decision_refs[-1]
        marker = json.loads(artifacts.read_bounded(marker_ref, 64 * 1024))
        if not isinstance(marker, dict) or set(marker) != {
            "kind",
            "identity",
            "old_attempt_id",
            "old_attempt_number",
            "old_checkpoint_ref",
            "old_checkpoint_hash",
            "original_migration_rule_ref",
            "candidate_failure_event_id",
            "exhaustion_event_id",
            "root_failure_event_id",
            "diagnostic_ref",
        }:
            raise ValueError("invalid migration candidate marker")
        old_ref = StoredDataRef.model_validate(marker["old_checkpoint_ref"])
        old = StageCheckpoint.model_validate_json(
            artifacts.read_bounded(old_ref, 256 * 1024)
        )
        old_hash = hashlib.sha256(
            canonical_bytes(old.model_dump(mode="json"))
        ).hexdigest()
        proof = migration_settings_blocked_replay_binding(old, artifacts)
        expected_inputs = tuple(
            dict.fromkeys((*old.input_refs, *old.output_refs, old_ref, marker_ref))
        )
        if (
            proof is None
            or marker["kind"] != "simple_poc_django_migration_settings_candidate_replay"
            or marker["identity"] != checkpoint.identity.model_dump(mode="json")
            or old.identity != checkpoint.identity
            or old.stage_version != checkpoint.stage_version
            or old.attempt_number != MAX_RECOVERY_ATTEMPTS + 1
            or marker["old_attempt_number"] != old.attempt_number
            or marker["old_attempt_id"] != old.attempt_id
            or marker["old_checkpoint_hash"] != old_hash
            or marker["original_migration_rule_ref"]
            != old.recovery_decision_refs[-1].model_dump(mode="json")
            or marker["diagnostic_ref"] != old.output_refs[0].model_dump(mode="json")
            or any(
                not isinstance(marker[key], str)
                or re.fullmatch(r"[0-9a-f]{64}", marker[key]) is None
                for key in (
                    "candidate_failure_event_id",
                    "exhaustion_event_id",
                    "root_failure_event_id",
                )
            )
            or checkpoint.input_refs != expected_inputs
            or checkpoint.recovery_decision_refs
            != (*old.recovery_decision_refs, marker_ref)
            or checkpoint.gate_revision_count != old.gate_revision_count
            or checkpoint.recovery_lineage_id != old.recovery_lineage_id
            or checkpoint.recipe_ref != old.recipe_ref
            or checkpoint.image_digest != old.image_digest
            or (checkpoint.attempt_id == old.attempt_id)
            or (
                checkpoint.status is StageStatus.PENDING
                and checkpoint.attempt_id is not None
            )
            or (
                checkpoint.status is not StageStatus.PENDING
                and not checkpoint.attempt_id
            )
        ):
            raise ValueError("unbound migration candidate marker")
        return proof
    except (
        KeyError,
        IndexError,
        OSError,
        TypeError,
        ValueError,
        UnicodeError,
        sqlite3.Error,
    ) as error:
        raise ValueError("POC_DJANGO_MIGRATION_SETTINGS_REPLAY_UNBOUND") from error


def django_poc_fixture_recovery_decision(diagnostic: str) -> RecoveryDecision:
    """Supply fixed, target-neutral repair guidance for a proven setup class."""

    if diagnostic not in {"migration graph", "model relation", "fixture database"}:
        raise ValueError("DJANGO_POC_FIXTURE_DIAGNOSTIC_INVALID")
    return RecoveryDecision(
        category=RecoveryCategory.GENERATED_INPUT,
        action=RecoveryAction.REGENERATE_INPUT,
        diagnosis=f"The generated PoC failed during Django {diagnostic} setup",
        guidance=(
            "Regenerate only the PoC candidate against the pinned Django source "
            "and settings. Check installed apps, optional model references, and "
            "migration dependencies before choosing migrate or run_syncdb. If "
            "using schema_editor, create a consistent dependency-complete "
            "temporary schema; account for tables written by fixture creation "
            "and post-save signals. Preserve repository-supported settings, "
            "including installed template apps, and project URL mounts and "
            "namespaces before invoking the target route. Keep writable "
            "database state under /tmp, "
            "preserve the target and framework source, and rerun the intended "
            "route after setup succeeds. This execution error is not a "
            "vulnerability verdict or counterevidence."
        ),
    )


def django_poc_fixture_dependency_failure(
    stderr: bytes, stdout: bytes, candidate: bytes
) -> str | None:
    """Recognize bounded fixture failures after manual Django schema setup.

    This does not identify any particular missing table. Only the exact,
    redacted phase and schema-count observation are admitted as replay evidence.
    """

    if (
        len(stderr) > 8 * 1024
        or len(stdout) > 128
        or len(candidate) > _MAX_POC_CANDIDATE_BYTES
        or b"django.setup(" not in candidate
        or b"schema_editor(" not in candidate
        or b"create_model(" not in candidate
    ):
        return None
    observation = stdout.replace(b"\r\n", b"\n").strip()
    diagnostic = stderr.replace(b"\r\n", b"\n").strip()
    if (
        b"skipped_unrelated" in candidate
        and b"phase = 'fixtures'" in candidate
        and b"objects.create(" in candidate
        and re.fullmatch(
            rb"Schema: created=[1-9][0-9]* skipped_unrelated=[1-9][0-9]*",
            observation,
        )
        is not None
        and diagnostic
        == (
            b"OperationalError during fixtures\n"
            b"Traceback: execute > _execute_with_wrappers > _execute > "
            b"__exit__ > _execute > execute"
        )
    ):
        return "fixture dependency after skipped schema model"
    if (
        b"FIXTURE_SCHEMA current_models_created=" in candidate
        and b"objects.bulk_create(" in candidate
        and re.fullmatch(
            rb"FIXTURE_SCHEMA current_models_created=[1-9][0-9]*",
            observation,
        )
        is not None
        and diagnostic
        == (
            b"OperationalError\n"
            b"Traceback (most recent call last):\n"
            b"  frame 1: _insert\n"
            b"  frame 2: execute_sql\n"
            b"  frame 3: execute\n"
            b"  frame 4: _execute_with_wrappers\n"
            b"  frame 5: _execute\n"
            b"  frame 6: __exit__\n"
            b"  frame 7: _execute\n"
            b"  frame 8: execute"
        )
    ):
        return "fixture dependency after targeted schema setup"
    setup_stage = re.search(
        rb"(?m)^\s*stage\s*=\s*(['\"])database_setup\1\s*$", candidate
    )
    if (
        not stdout
        and setup_stage is not None
        and b"django.setup(" in candidate[: setup_stage.start()]
        and (schema_pos := candidate.find(b"schema_editor(", setup_stage.end())) >= 0
        and (model_pos := candidate.find(b"create_model(", schema_pos)) > schema_pos
        and candidate.find(b"objects.create_user(", model_pos) > model_pos
        and diagnostic
        == (
            b"OperationalError: harness_runtime\n"
            b"Traceback (function names only):\n"
            b"  in _insert\n"
            b"  in execute_sql\n"
            b"  in execute\n"
            b"  in _execute_with_wrappers\n"
            b"  in _execute\n"
            b"  in __exit__\n"
            b"  in _execute\n"
            b"  in execute"
        )
    ):
        return "fixture dependency after user creation"
    return None


def django_poc_fixture_dependency_recovery_decision() -> RecoveryDecision:
    """Target-neutral repair guidance; the omitted table is not asserted."""

    return RecoveryDecision(
        category=RecoveryCategory.GENERATED_INPUT,
        action=RecoveryAction.REGENERATE_INPUT,
        diagnosis="The generated Django PoC failed during fixture database setup",
        guidance=(
            "Regenerate only the PoC candidate against the pinned repository. "
            "Inspect whether the manual schema omitted models or related "
            "foreign-key tables needed "
            "by fixtures and signals; use repository-supported settings to "
            "resolve optional app and model dependencies, then build a "
            "dependency-complete temporary schema before exercising the route. "
            "Do not disable foreign-key enforcement or edit target/framework "
            "source. A fixture setup error is not a vulnerability verdict or "
            "counterevidence."
        ),
    )


def django_poc_schema_exhaustion_failure(
    stderr: bytes, stdout: bytes, candidate: bytes
) -> bool:
    """Recognize only a bounded Django fixture failure before an HTTP request."""

    if stdout or len(stderr) > 1024 or len(candidate) > _MAX_POC_CANDIDATE_BYTES:
        return False
    if stderr.replace(b"\r\n", b"\n").strip() != (
        b"OperationalError: fixture_setup\n"
        b"Traceback (function names only):\n"
        b"  in __len__\n"
        b"  in _fetch_all\n"
        b"  in __iter__\n"
        b"  in execute_sql\n"
        b"  in execute\n"
        b"  in _execute_with_wrappers\n"
        b"  in _execute\n"
        b"  in __exit__\n"
        b"  in _execute\n"
        b"  in execute"
    ):
        return False
    setup = candidate.find(b"django.setup(")
    schema = candidate.find(b"schema_editor(", setup)
    model = candidate.find(b"create_model(", schema)
    fixture = candidate.find(b"objects.create(", model)
    route = candidate.find(b"client.get(", fixture)
    return setup >= 0 and setup < schema < model < fixture < route


def django_poc_schema_exhaustion_decision() -> RecoveryDecision:
    return RecoveryDecision(
        category=RecoveryCategory.GENERATED_INPUT,
        action=RecoveryAction.REGENERATE_INPUT,
        diagnosis=(
            "The generated Django PoC failed before route execution "
            "during fixture setup"
        ),
        guidance=(
            "Regenerate only the PoC candidate using commit-pinned repository "
            "settings, installed apps, migrations, and requested source. Prefer "
            "the repository-supported migrate command with run_syncdb when "
            "supported. If migrations cannot be used, create a dependency-"
            "complete temporary schema for all installed models, framework "
            "tables and signal-written dependencies; do not hand-pick a few "
            "models, suppress foreign-key checks, or edit target code. Check "
            "fixture setup before invoking the intended route. If setup still "
            "cannot be verified, preserve an environment error rather than "
            "claiming vulnerability support or counterevidence."
        ),
    )


def django_poc_source_gap_recovery_decision() -> RecoveryDecision:
    """Regenerate a harness only after a pinned model-source budget omission."""

    return RecoveryDecision(
        category=RecoveryCategory.GENERATED_INPUT,
        action=RecoveryAction.REGENERATE_INPUT,
        diagnosis="The generated Django PoC lacked requested pinned model context",
        guidance=(
            "Regenerate only the PoC candidate. Read the commit-pinned Python "
            "model context supplied as bounded source spans, then choose a "
            "dependency-complete temporary Django schema before creating "
            "fixtures and exercising the real route. Do not guess missing "
            "tables from a generic error, alter repository or framework "
            "source, disable foreign-key checks, or treat this setup error "
            "as vulnerability evidence or counterevidence."
        ),
    )


def sqlite_in_memory_storage_failure(
    stderr: bytes, stdout: bytes, candidate: bytes, pinned_source: bytes
) -> bool:
    """Recognize a file-only generated harness for a pinned in-memory target.

    The source is supplied by the caller after validating its pinned checkout.
    Ambiguous, mixed and dynamic SQLite connection modes never qualify.
    """

    if (
        stdout.strip()
        or len(stderr) > 256
        or len(candidate) > _MAX_POC_CANDIDATE_BYTES
        or len(pinned_source) > 128 * 1024
        or stderr.replace(b"\r\n", b"\n")
        != (
            b"RuntimeError: storage_path_unverified\n"
            b"Traceback (function names only): <module> -> main -> "
            b"configure_sqlite_storage\n"
        )
    ):
        return False
    candidate_tree = _sqlite_candidate_tree(candidate)
    if candidate_tree is None:
        return False
    try:
        source_tree = ast.parse(pinned_source.decode("utf-8"))
    except (UnicodeError, SyntaxError, ValueError):
        return False

    storage_functions = [
        node
        for node in candidate_tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "configure_sqlite_storage"
    ]
    if len(storage_functions) != 1:
        return False
    storage_nodes = tuple(ast.walk(storage_functions[0]))
    raises_missing_path = any(
        isinstance(node, ast.Raise)
        and isinstance(node.exc, ast.Call)
        and isinstance(node.exc.func, ast.Name)
        and node.exc.func.id == "RuntimeError"
        and len(node.exc.args) == 1
        and isinstance(node.exc.args[0], ast.Constant)
        and node.exc.args[0].value == "storage_path_unverified"
        for node in storage_nodes
    )
    checks_file_paths = any(
        isinstance(node, ast.Constant)
        and node.value in {"*.db", "*.sqlite", "*.sqlite3"}
        for node in storage_nodes
    )
    attempts_sqlite_remap = any(
        isinstance(node, ast.Attribute)
        and node.attr == "connect"
        and isinstance(node.value, ast.Name)
        and node.value.id == "sqlite3"
        for node in storage_nodes
    )
    if not (raises_missing_path and checks_file_paths and attempts_sqlite_remap):
        return False
    if not any(
        isinstance(node, ast.Import)
        and any(
            alias.name == "sqlite3" and alias.asname is None for alias in node.names
        )
        for node in source_tree.body
    ):
        return False
    connections = [
        node
        for node in ast.walk(source_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "connect"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "sqlite3"
    ]
    return bool(connections) and all(
        node.args
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value == ":memory:"
        for node in connections
    )


def _sqlite_candidate_tree(candidate: bytes) -> ast.Module | None:
    if len(candidate) > _MAX_POC_CANDIDATE_BYTES:
        return None
    python_candidate = candidate
    if candidate.startswith(b"#!/bin/sh\n"):
        marker = b"<<'PY'\n"
        if candidate.count(marker) != 1:
            return None
        shell_prefix, python_remainder = candidate.split(marker, 1)
        marker_line = shell_prefix.rsplit(b"\n", 1)[-1]
        terminator = b"\nPY\n" if python_remainder.endswith(b"\nPY\n") else b"\nPY"
        if (
            b"python3 -" not in marker_line
            or not python_remainder.endswith(terminator)
            or b"\nPY\n" in python_remainder[: -len(terminator)]
        ):
            return None
        python_candidate = python_remainder[: -len(terminator)]
    try:
        return ast.parse(python_candidate.decode("utf-8"))
    except (UnicodeError, SyntaxError, ValueError):
        return None


def sqlite_in_memory_target_paths(candidate: bytes) -> tuple[str, ...]:
    """Extract explicit repository-relative Python sources from a PoC.

    This is only a claimed path. The caller must verify it against the pinned
    tracked-source manifest and Git blob before using it as source evidence.
    """

    tree = _sqlite_candidate_tree(candidate)
    if tree is None:
        return ()
    if not any(
        isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "root"
            for target in node.targets
        )
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "Path"
        and len(node.value.args) == 1
        and isinstance(node.value.args[0], ast.Constant)
        and node.value.args[0].value == "/workspace"
        for node in tree.body
    ):
        return ()
    paths: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        parts: list[str] = []
        value = node.value
        while isinstance(value, ast.BinOp) and isinstance(value.op, ast.Div):
            if not isinstance(value.right, ast.Constant) or not isinstance(
                value.right.value, str
            ):
                break
            parts.append(value.right.value)
            value = value.left
        if not isinstance(value, ast.Name) or value.id != "root" or not parts:
            continue
        normalized = list(reversed(parts))
        if (
            normalized[-1].endswith(".py")
            and all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in normalized)
            and all(part not in {".", ".."} for part in normalized)
        ):
            paths.add("/".join(normalized))
    return tuple(sorted(paths)) if 0 < len(paths) <= 16 else ()


def http_server_constructor_source_path(candidate: bytes) -> str | None:
    """Return one explicitly named repository HTTP server source, not a guess.

    The caller must still bind the returned path to the pinned tracked manifest
    and verify its Git blob before using the source as failure evidence.
    """

    tree = _sqlite_candidate_tree(candidate)
    if tree is None:
        return None
    if not any(
        isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "root"
            for target in node.targets
        )
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "Path"
        and len(node.value.args) == 1
        and isinstance(node.value.args[0], ast.Constant)
        and node.value.args[0].value == "/workspace"
        for node in tree.body
    ):
        return None
    paths: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not any(
            isinstance(target, ast.Name) and target.id == "server_source"
            for target in node.targets
        ):
            continue
        parts: list[str] = []
        value = node.value
        while isinstance(value, ast.BinOp) and isinstance(value.op, ast.Div):
            if not isinstance(value.right, ast.Constant) or not isinstance(
                value.right.value, str
            ):
                break
            parts.append(value.right.value)
            value = value.left
        if not isinstance(value, ast.Name) or value.id != "root":
            return None
        normalized = list(reversed(parts))
        if (
            len(normalized) < 2
            or normalized[-1] != "server.py"
            or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in normalized)
            or any(part in {".", ".."} for part in normalized)
        ):
            return None
        paths.add("/".join(normalized))
    return next(iter(paths)) if len(paths) == 1 else None


def _http_server_constructor_candidate(tree: ast.Module) -> bool:
    helpers = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "server_arguments"
    ]
    if len(helpers) != 1 or len(helpers[0].body) != 3:
        return False
    initialization, loop, result = helpers[0].body
    if (
        not isinstance(loop, ast.For)
        or not isinstance(result, ast.Return)
        or result.value is None
    ):
        return False
    if (
        ast.unparse(initialization) != "args, kwargs = ([], {})"
        or ast.unparse(loop.iter)
        != "inspect.signature(server_class).parameters.items()"
        or not loop.body
        or not isinstance(loop.body[0], ast.If)
        or ast.unparse(loop.body[0].test)
        != (
            "parameter.kind in (inspect.Parameter.VAR_POSITIONAL, "
            "inspect.Parameter.VAR_KEYWORD)"
        )
        or len(loop.body[0].body) != 1
        or not isinstance(loop.body[0].body[0], ast.Continue)
        or ast.unparse(result.value) != "(args, kwargs)"
    ):
        return False
    return any(
        isinstance(node, ast.Call)
        and ast.unparse(node) == "server_class(*arguments[0], **arguments[1])"
        for node in ast.walk(tree)
    )


def _variadic_http_server_source(pinned_source: bytes) -> bool:
    if len(pinned_source) > _MAX_POC_CANDIDATE_BYTES:
        return False
    try:
        tree = ast.parse(pinned_source.decode("utf-8"))
    except (UnicodeError, SyntaxError, ValueError):
        return False
    if not any(
        isinstance(node, ast.ImportFrom)
        and node.module == "http.server"
        and any(
            alias.name in {"HTTPServer", "ThreadingHTTPServer"} for alias in node.names
        )
        for node in tree.body
    ):
        return False
    classes = [
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and any(
            isinstance(base, ast.Name)
            and base.id in {"HTTPServer", "ThreadingHTTPServer"}
            for base in node.bases
        )
    ]
    if len(classes) != 1:
        return False
    constructors = [
        node
        for node in classes[0].body
        if isinstance(node, ast.FunctionDef) and node.name == "__init__"
    ]
    if len(constructors) != 1:
        return False
    constructor = constructors[0]
    args = constructor.args
    if (
        len(args.posonlyargs) != 0
        or len(args.args) != 1
        or args.args[0].arg != "self"
        or args.vararg is None
        or args.vararg.arg != "args"
        or args.kwarg is None
        or args.kwarg.arg != "kwargs"
        or args.kwonlyargs
    ):
        return False
    return any(
        isinstance(node, ast.Call)
        and ast.unparse(node) == "super().__init__(*args, **kwargs)"
        for node in ast.walk(constructor)
    )


def http_server_constructor_failure(
    stderr: bytes,
    stdout: bytes,
    candidate: bytes,
    pinned_source: bytes,
) -> bool:
    """Recognize only the saved pre-HTTP constructor failure shape."""

    if (
        stdout
        or stderr
        != (
            b"TypeError: runtime_failure\n"
            b"Traceback (function names only): <module> -> main -> __init__\n"
        )
        or http_server_constructor_source_path(candidate) is None
        or not _variadic_http_server_source(pinned_source)
    ):
        return False
    tree = _sqlite_candidate_tree(candidate)
    return tree is not None and _http_server_constructor_candidate(tree)


def http_server_constructor_recovery_decision() -> RecoveryDecision:
    """Fixed guidance for a generated PoC constructor mistake, not a verdict."""

    return RecoveryDecision(
        category=RecoveryCategory.GENERATED_INPUT,
        action=RecoveryAction.REGENERATE_INPUT,
        diagnosis=(
            "The generated PoC omitted the HTTP server address and handler "
            "because its signature helper skipped variadic parameters"
        ),
        guidance=(
            "Regenerate only the PoC candidate against pinned source. Inspect "
            "the concrete HTTPServer base in the MRO and its constructor "
            "signature; pass a loopback ephemeral address and the real "
            "repository request-handler class when required. Preserve the "
            "target and its in-memory storage behavior. The observed TypeError "
            "occurred before any HTTP request and is not vulnerability "
            "counterevidence. Do not claim confirmation until the corrected "
            "PoC obtains and interprets a real route response."
        ),
    )


def sqlite_in_memory_storage_recovery_decision() -> RecoveryDecision:
    """Fixed, target-neutral guidance for a proven generated-input mistake."""

    return RecoveryDecision(
        category=RecoveryCategory.GENERATED_INPUT,
        action=RecoveryAction.REGENERATE_INPUT,
        diagnosis=(
            "The generated PoC required a SQLite file path although the "
            "pinned target uses only in-memory connections"
        ),
        guidance=(
            "Regenerate only the PoC candidate using the pinned target source. "
            "Distinguish in-memory SQLite from file-backed storage: when the "
            "target connects to ':memory:' and no file-backed path exists, "
            "do not require a database filename or invent a file remap. "
            "Keep the live in-memory connection and exercise the intended "
            "route. For file-backed or dynamic storage, map only a verified "
            "path and leave unsupported setup unverified. Preserve target and "
            "framework behavior; this setup error is not vulnerability "
            "counterevidence."
        ),
    )


_SAFE_PYTHON_MODULE = re.compile(
    rb"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
)
_SAFE_PYTHON_INTERPRETER = re.compile(
    rb"(?:/[A-Za-z0-9._+-]+)*/?python(?:3(?:\.[0-9]+)?)?"
)


def _python_cli_import_diagnostic(
    output: bytes,
) -> tuple[dict[bytes, bytes], bool]:
    """Accept only a sole, terminal Python interpreter module error."""

    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) != 1 or len(lines[0]) > 1_024:
        return {}, False
    interpreter, marker, module = lines[0].partition(b": No module named ")
    if (
        not marker
        or _SAFE_PYTHON_INTERPRETER.fullmatch(interpreter) is None
        or len(module) > 128
        or _SAFE_PYTHON_MODULE.fullmatch(module) is None
    ):
        return {}, False
    return {b"ModuleNotFoundError:" + module: b"ModuleNotFoundError: " + module}, True


class RecoveryCategory(StrEnum):
    TRANSIENT_TOOL = "TRANSIENT_TOOL"
    GENERATED_INPUT = "GENERATED_INPUT"
    ENVIRONMENT = "ENVIRONMENT"
    TERMINAL = "TERMINAL"


class RecoveryAction(StrEnum):
    RETRY_STAGE = "RETRY_STAGE"
    REBUILD_ENVIRONMENT = "REBUILD_ENVIRONMENT"
    REPLAN_ENVIRONMENT = "REPLAN_ENVIRONMENT"
    REGENERATE_INPUT = "REGENERATE_INPUT"
    STOP = "STOP"


class RecoveryDecision(ContractModel):
    category: RecoveryCategory
    action: RecoveryAction
    diagnosis: str
    guidance: str
    environment_patch: str = ""


class RecoveryResolution(ContractModel):
    decision: RecoveryDecision
    decision_ref: StoredDataRef


class RecoveryCoordinator(Protocol):
    async def decide(
        self,
        checkpoint: StageCheckpoint,
        failure: StageFailure,
    ) -> RecoveryResolution: ...


TERMINAL_ERROR_CODES = frozenset(
    {
        "AUTH_REQUIRED",
        "AUTH_INVALID",
        "POLICY_DENIED",
        "CAPABILITY_DENIED",
        "RECOVERY_EXHAUSTED",
        "SIMPLE_RUNTIME_REFERENCE_SCOPE_MISMATCH",
    }
)

ALLOWED_ACTIONS = {
    RecoveryCategory.TRANSIENT_TOOL: frozenset(
        {RecoveryAction.RETRY_STAGE, RecoveryAction.STOP}
    ),
    RecoveryCategory.GENERATED_INPUT: frozenset(
        {RecoveryAction.REGENERATE_INPUT, RecoveryAction.STOP}
    ),
    RecoveryCategory.ENVIRONMENT: frozenset(
        {
            RecoveryAction.REBUILD_ENVIRONMENT,
            RecoveryAction.REPLAN_ENVIRONMENT,
            RecoveryAction.STOP,
        }
    ),
    RecoveryCategory.TERMINAL: frozenset({RecoveryAction.STOP}),
}

_ALLOWED_PACKAGE_COMMAND_PREFIXES = (
    "python -m pip install ",
    "python3 -m pip install ",
    "pip install ",
    "pip3 install ",
    "apt-get update",
    "apt-get install ",
    "apk add ",
    "dnf install ",
    "yum install ",
    "npm ci",
    "npm install ",
    "pnpm install",
    "yarn install",
    "uv sync",
    "poetry install",
    "bundle install",
    "composer install",
    "cargo fetch",
    "go mod download",
)
_FORBIDDEN_PATCH_FRAGMENT = re.compile(
    r"(?i)(?:[a-z][a-z0-9+.-]*://|[a-z]:[\\/]|\\\\|/var/run/docker\.sock|"
    r"/run/docker\.sock|--mount|\$\(|`|&&|\|\||[;|<>])"
)
_FORBIDDEN_PATCH_ENDPOINT_OPTION = re.compile(
    r"(?i)(?:^|\s)(?:--(?:index-url|extra-index-url|find-links|trusted-host|"
    r"proxy|registry|repository|source|index|config|config-file|"
    r"global-option|install-option|target|prefix|root|src|editable|project)|"
    r"-(?:i|f|t|e))(?:\s|=|$)"
)

_DECISION_SCHEMA: dict[str, object] = {
    "type": "object",
    "additionalProperties": False,
    "properties": {
        "category": {
            "type": "string",
            "enum": [item.value for item in RecoveryCategory],
        },
        "action": {
            "type": "string",
            "enum": [
                item.value
                for item in RecoveryAction
                if item is not RecoveryAction.REPLAN_ENVIRONMENT
            ],
        },
        "diagnosis": {"type": "string"},
        "guidance": {"type": "string"},
        "environment_patch": {"type": "string"},
    },
    "required": [
        "category",
        "action",
        "diagnosis",
        "guidance",
        "environment_patch",
    ],
}

_SAFE_POLICY_VALIDATION_CODES = frozenset(
    {
        "RECOVERY_ACTION_CATEGORY_MISMATCH",
        "RECOVERY_REPLAN_REQUIRES_BOUND_IMPORT_EVIDENCE",
        "RECOVERY_INPUT_REGEN_REQUIRES_BOUND_POC_EVIDENCE",
        "RECOVERY_ENVIRONMENT_PATCH_FORBIDDEN",
        "RECOVERY_ENVIRONMENT_PATCH_UNEXPECTED",
        "RECOVERY_DECISION_TEXT_TOO_LARGE",
        "RECOVERY_DECISION_REDACTION_FAILED",
        "RECOVERY_PROVIDER_INVALID_OUTPUT",
    }
)


def _policy_validation_code(error: ValidationError | ValueError) -> str:
    if isinstance(error, ValidationError):
        return "RECOVERY_DECISION_SCHEMA_INVALID"
    code = str(error)
    return (
        code if code in _SAFE_POLICY_VALIDATION_CODES else "RECOVERY_DECISION_INVALID"
    )


def _policy_feedback(code: str, *, field: str | None = None) -> bytes:
    safe_fields = {
        "$",
        "$.category",
        "$.action",
        "$.diagnosis",
        "$.guidance",
        "$.environment_patch",
    }
    return canonical_bytes(
        {
            "policy_validation_error": code,
            "invalid_field": field if field in safe_fields else None,
            "instruction": (
                "Return one corrected decision only; do not repeat the "
                "rejected response."
            ),
            "required_schema": _DECISION_SCHEMA,
        }
    )


def validate_environment_patch(patch: str) -> str:
    """Accept bounded installer RUN lines or one fixed Playwright browser recipe."""

    normalized = "\n".join(line.strip() for line in patch.strip().splitlines())
    if not normalized or len(normalized.encode("utf-8")) > _MAX_ENVIRONMENT_PATCH_BYTES:
        raise ValueError("RECOVERY_ENVIRONMENT_PATCH_FORBIDDEN")
    if normalized in {
        _PLAYWRIGHT_PATCH_PREFIX + browser for browser in _PLAYWRIGHT_BROWSERS
    }:
        return normalized
    safe_lines: list[str] = []
    for line in normalized.splitlines():
        if (
            not line.startswith("RUN ")
            or _FORBIDDEN_PATCH_FRAGMENT.search(line)
            or _FORBIDDEN_PATCH_ENDPOINT_OPTION.search(line)
        ):
            raise ValueError("RECOVERY_ENVIRONMENT_PATCH_FORBIDDEN")
        command = line[4:].strip().lower()
        try:
            arguments = shlex.split(command)
        except ValueError as error:
            raise ValueError("RECOVERY_ENVIRONMENT_PATCH_FORBIDDEN") from error
        if any(
            argument in {".", "..", "/workspace"}
            or argument.startswith(("./", "../", "/workspace/", ".["))
            or argument.startswith(("-e.", "-e/", "-t/", "-t."))
            for argument in arguments
        ):
            raise ValueError("RECOVERY_ENVIRONMENT_PATCH_FORBIDDEN")
        if not any(
            _allowed_package_command(command, item)
            for item in _ALLOWED_PACKAGE_COMMAND_PREFIXES
        ):
            raise ValueError("RECOVERY_ENVIRONMENT_PATCH_FORBIDDEN")
        if _allowed_package_command(command, "apt-get install ") and (
            not safe_lines or safe_lines[-1].lower() != "run apt-get update"
        ):
            safe_lines.append("RUN apt-get update")
        safe_lines.append(line)
    normalized = "\n".join(safe_lines)
    if len(normalized.encode("utf-8")) > _MAX_ENVIRONMENT_PATCH_BYTES:
        raise ValueError("RECOVERY_ENVIRONMENT_PATCH_FORBIDDEN")
    return normalized


def _allowed_package_command(command: str, allowed: str) -> bool:
    base = allowed.rstrip()
    if command == base:
        return True
    return command.startswith(allowed if allowed.endswith(" ") else base + " ")


class SimpleRecoveryCoordinator:
    def __init__(
        self,
        *,
        client: SimpleLLMClient,
        artifacts: SimpleArtifactRepository,
    ) -> None:
        self._client = client
        self._artifacts = artifacts

    async def decide(
        self,
        checkpoint: StageCheckpoint,
        failure: StageFailure,
    ) -> RecoveryResolution:
        if checkpoint.identity != self._artifacts.identity:
            raise ValueError("RECOVERY_IDENTITY_SCOPE_MISMATCH")
        if not failure.retryable or failure.code in TERMINAL_ERROR_CODES:
            return self._store(
                checkpoint,
                failure,
                self._stop(
                    "failure is not eligible for automatic recovery",
                    "manual review is required",
                ),
            )

        if (
            checkpoint.stage
            in {SimpleStage.POC_CANDIDATE_DONE, SimpleStage.POC_EXECUTION_DONE}
            and failure.code == "POC_SERVER_CONSTRUCTOR_UNBOUND"
        ):
            return self._store(
                checkpoint,
                failure,
                http_server_constructor_recovery_decision(),
            )

        if (
            checkpoint.stage
            in {SimpleStage.POC_CANDIDATE_DONE, SimpleStage.POC_EXECUTION_DONE}
            and failure.code == "POC_DJANGO_SCHEMA_SUBSET_UNVERIFIED"
        ):
            return self._store(
                checkpoint,
                failure,
                RecoveryDecision(
                    category=RecoveryCategory.GENERATED_INPUT,
                    action=RecoveryAction.REGENERATE_INPUT,
                    diagnosis=(
                        "The generated Django PoC uses an unverified explicit "
                        "model subset for its temporary schema"
                    ),
                    guidance=(
                        "Regenerate only the PoC candidate from pinned source. "
                        "Preserve repository settings, installed apps, URL "
                        "namespaces, templates, and STATIC_URL. Prefer migrate "
                        "with run_syncdb when supported; otherwise create a "
                        "dependency-complete schema from all installed models. "
                        "Do not treat this fixture setup error as vulnerability "
                        "support or counterevidence."
                    ),
                ),
            )

        if failure.code == "POC_AUTO_BUNDLE_DOWNLOAD_FAILED":
            stderr = self._auto_bundle_stderr(checkpoint, failure)
            if stderr is not None:
                missing = re.search(
                    rb"No matching distribution found for "
                    rb"([A-Za-z0-9][A-Za-z0-9_.+\-<>=!~\[\]]{0,127})",
                    stderr,
                    re.IGNORECASE,
                )
                if missing is not None:
                    requirement = missing.group(1).decode("ascii")
                    return self._store(
                        checkpoint,
                        failure,
                        self._stop(
                            f"Python distribution unavailable: {requirement}",
                            "Use a compatible pinned Python environment or "
                            "review the repository dependency; unchanged "
                            "downloads will not be retried",
                        ),
                    )
            return self._store(
                checkpoint,
                failure,
                RecoveryDecision(
                    category=RecoveryCategory.TRANSIENT_TOOL,
                    action=RecoveryAction.RETRY_STAGE,
                    diagnosis="Python dependency bundle download did not complete",
                    guidance=(
                        "Retry the bounded dependency download without changing "
                        "the pinned source or PoC inputs"
                    ),
                ),
            )

        missing_browser = (
            self._missing_playwright_browser(checkpoint, failure)
            if failure.code != "POC_RUNTIME_IMPORT_FAILED"
            else None
        )
        if missing_browser is not None:
            return self._store(
                checkpoint,
                failure,
                RecoveryDecision(
                    category=RecoveryCategory.ENVIRONMENT,
                    action=RecoveryAction.REBUILD_ENVIRONMENT,
                    diagnosis="Python Playwright browser binary is absent",
                    guidance="Install the matching browser in the temporary image",
                    environment_patch=validate_environment_patch(
                        _PLAYWRIGHT_PATCH_PREFIX + missing_browser
                    ),
                ),
            )

        import_matches: dict[bytes, bytes] = {}
        isolated_terminal_import = True
        if failure.code == "POC_RUNTIME_IMPORT_FAILED":
            for stream_ref_key in ("stderr_ref", "stdout_ref"):
                matches, terminal, empty = self._poc_execution_import_diagnostic(
                    checkpoint, failure, stream_ref_key
                )
                isolated_terminal_import &= empty or (bool(matches) and terminal)
                for name, span in matches.items():
                    import_matches.setdefault(name, span)
        if len(import_matches) > 1:
            return self._store(
                checkpoint,
                failure,
                RecoveryDecision(
                    category=RecoveryCategory.TERMINAL,
                    action=RecoveryAction.STOP,
                    diagnosis="Multiple distinct Python import failures were observed",
                    guidance=(
                        "Inspect the exact PoC execution evidence; no dependency "
                        "is selected automatically from ambiguous tracebacks"
                    ),
                ),
            )
        if import_matches and isolated_terminal_import:
            import_name, import_output = next(iter(import_matches.items()))
            if self._pinned_local_python_module(checkpoint, import_name):
                return self._store(
                    checkpoint,
                    failure,
                    RecoveryDecision(
                        category=RecoveryCategory.GENERATED_INPUT,
                        action=RecoveryAction.REGENERATE_INPUT,
                        diagnosis=(
                            "Terminal import failure names a module present "
                            "in the pinned repository source"
                        ),
                        guidance=(
                            "Regenerate the PoC import setup using the parent "
                            "import root shown by the pinned source layout. "
                            "Keep that root on sys.path throughout direct and "
                            "transitive absolute imports; for a root package "
                            "this is /workspace, not its child package directory. "
                            "Check importlib.util.find_spec for the intended "
                            "package when a same-named module file exists. "
                            "Do not install a package or change pinned source."
                        ),
                    ),
                    diagnostic_excerpt=import_output,
                )
            return self._store(
                checkpoint,
                failure,
                RecoveryDecision(
                    category=RecoveryCategory.ENVIRONMENT,
                    action=RecoveryAction.REPLAN_ENVIRONMENT,
                    diagnosis=(
                        "Terminal Python import diagnostic suggests an "
                        "environment failure"
                    ),
                    guidance=(
                        "Revisit the pinned source import and dependency evidence; "
                        "if a matching distribution is supported, include an "
                        "explicit `pip:<PEP 508 requirement>` in initial "
                        "environment_requirements. Do not assume the import "
                        "name is the distribution name or run installers inside "
                        "the PoC image."
                    ),
                ),
                diagnostic_excerpt=import_output,
            )
        if failure.code == "POC_RUNTIME_IMPORT_FAILED":
            return self._store(
                checkpoint,
                failure,
                RecoveryDecision(
                    category=RecoveryCategory.TERMINAL,
                    action=RecoveryAction.STOP,
                    diagnosis="Python import failure lacks isolated terminal evidence",
                    guidance=(
                        "Review both exact PoC output streams; automatic dependency "
                        "selection and Dockerfile patching are not justified"
                    ),
                ),
            )
        stderr = self._poc_execution_stderr(checkpoint, failure)
        execution = self._verified_poc_execution(checkpoint, failure)
        if (
            stderr is not None
            and execution is not None
            and execution.get("exit_code") == 2
        ):
            try:
                content_ref = StoredDataRef.model_validate(execution.get("content_ref"))
                candidate_content = self._artifacts.read_bounded(
                    content_ref, _MAX_POC_CANDIDATE_BYTES
                )
            except (OSError, TypeError, ValueError):
                candidate_content = b""
            diagnostic = django_poc_fixture_failure(stderr, candidate_content)
            if diagnostic is not None:
                return self._store(
                    checkpoint,
                    failure,
                    django_poc_fixture_recovery_decision(diagnostic),
                    diagnostic_excerpt=diagnostic.encode("ascii"),
                )
        if stderr is not None and (
            b"PermissionError" in stderr
            or b"Read-only file system" in stderr
            or self._import_time_storage_write_error(stderr)
        ):
            guidance = (
                "Keep /workspace read-only and keep the working directory at "
                "/workspace; configure only verified writable runtime storage "
                "and scratch paths under /tmp before startup"
            )
            if b"exec_module" in stderr and b"set_storage" in stderr:
                guidance += (
                    "; wrap the library setter before importing the target "
                    "so its module-level setter rewrites only the verified "
                    "writable storage argument to /tmp. If a later client "
                    "constructor uses that same relative storage path, "
                    "redirect it too; changing the client only after the "
                    "setter runs does not prevent the initial write"
                )
            if self._import_time_storage_write_error(stderr):
                guidance += (
                    "; if import-time database initialization opens one pinned "
                    "relative SQLite path, redirect only that exact database "
                    "open or constructor to one /tmp path before importing the "
                    "target; copy the existing database there first if present "
                    "and keep the mapping for the entire PoC execution, "
                    "including later requests; if paths are multiple or "
                    "dynamic and cannot be matched exactly, leave setup "
                    "unverified rather than guessing; keep read-only assets "
                    "resolved from /workspace"
                )
            return self._store(
                checkpoint,
                failure,
                RecoveryDecision(
                    category=RecoveryCategory.GENERATED_INPUT,
                    action=RecoveryAction.REGENERATE_INPUT,
                    diagnosis="PoC runtime write was denied inside the container",
                    guidance=guidance,
                ),
            )

        if failure.code == "POC_EXECUTION_FAILED":
            stderr_ref = self._bound_poc_stream_ref(checkpoint, failure, "stderr_ref")
            stdout_ref = self._bound_poc_stream_ref(checkpoint, failure, "stdout_ref")
            if stderr_ref is not None and stdout_ref is not None:
                try:
                    full_stderr = self._artifacts.read_bounded(
                        stderr_ref, _MAX_POC_OUTPUT_BYTES
                    )
                    full_stdout = self._artifacts.read_bounded(
                        stdout_ref, _MAX_POC_OUTPUT_BYTES
                    )
                except (OSError, ValueError):
                    pass
                else:
                    extract_failure = (
                        sanitized_extract_failure(full_stderr)
                        if not full_stdout.strip()
                        else None
                    )
                    if extract_failure is not None:
                        return self._store(
                            checkpoint,
                            failure,
                            sanitized_extract_recovery_decision(),
                            diagnostic_excerpt=extract_failure,
                        )

        if self._verified_exit_two_with_clean_cleanup(checkpoint, failure):
            return self._store(
                checkpoint,
                failure,
                RecoveryDecision(
                    category=RecoveryCategory.GENERATED_INPUT,
                    action=RecoveryAction.REGENERATE_INPUT,
                    diagnosis=(
                        "A bound PoC attempt exited without a usable observation"
                    ),
                    guidance=(
                        "Regenerate only the PoC candidate for the same pinned "
                        "source and supported runtime. Recheck the existing "
                        "route, method, and branch that reach the intended sink; "
                        "do not alter target or framework behavior and do not "
                        "treat this execution error as counterevidence."
                    ),
                ),
            )

        refs = tuple(dict.fromkeys(checkpoint.input_refs + failure.evidence_refs))
        try:
            context = self._artifacts.prompt_context(refs)
        except (OSError, TypeError, ValueError) as error:
            if str(error) == "SIMPLE_RUNTIME_REFERENCE_SCOPE_MISMATCH":
                raise
            return self._store(
                checkpoint,
                failure,
                self._stop(
                    "RECOVERY_EVIDENCE_INVALID",
                    "Preserve the failed stage for manual evidence review",
                ),
                decision_origin="FALLBACK",
            )
        prompt = b"\n".join(
            (
                b"Classify one failed SimpleRuntime stage and choose one "
                b"bounded action.",
                b"Never treat an execution error as a vulnerability FALSE verdict.",
                b"Do not request host changes, source edits, credentials, "
                b"or policy changes.",
                b"Valid category/action pairs: TRANSIENT_TOOL -> RETRY_STAGE or "
                b"STOP; GENERATED_INPUT -> REGENERATE_INPUT or STOP; "
                b"ENVIRONMENT -> REBUILD_ENVIRONMENT or STOP; TERMINAL -> "
                b"STOP. REPLAN_ENVIRONMENT is reserved for a verified import "
                b"rule and must not be returned by this Agent.",
                b"For REBUILD_ENVIRONMENT, environment_patch must contain "
                b"nonempty Dockerfile RUN lines with allowlisted package "
                b"installer commands, never prose, shell chaining, host paths, "
                b"URLs, or an unsupported change to pinned dependency "
                b"constraints. For all other actions environment_patch must "
                b"be empty. If no compliant action is justified, choose STOP.",
                b"For a generated PoC input error, REGENERATE_INPUT may try a "
                b"different existing route, method, or branch to reach the "
                b"intended sink, but must not monkeypatch target or framework "
                b"behavior.",
                canonical_bytes(
                    {
                        "stage": checkpoint.stage.value,
                        "attempt": checkpoint.attempt_number,
                        "error_code": failure.code,
                        "retryable": failure.retryable,
                        "safe_message": failure.safe_message,
                    }
                ),
                context,
            )
        )
        policy_validation_attempts: list[tuple[StoredDataRef | None, str | None]] = []
        decision_origin: Literal["AGENT", "FALLBACK"] = "FALLBACK"
        for validation_attempt in range(2):
            try:
                response = await self._client.call(
                    prompt=prompt,
                    output_schema=_DECISION_SCHEMA,
                    timeout_ms=_RECOVERY_TIMEOUT_MS,
                    agent_name="recovery",
                )
            except Exception:
                response = StageFailure(
                    code="RECOVERY_PROVIDER_FAILED",
                    retryable=False,
                    safe_message="Recovery provider did not return a decision",
                )
            if isinstance(response, StageFailure):
                if response.code == "INVALID_OUTPUT":
                    validation_code = "RECOVERY_PROVIDER_INVALID_OUTPUT"
                    policy_validation_attempts.append((None, validation_code))
                    if validation_attempt == 0:
                        prompt += b"\n" + _policy_feedback(
                            validation_code, field=response.invalid_field
                        )
                        continue
                decision = self._stop(
                    "recovery provider did not return a decision",
                    "preserve the failure for manual review",
                )
                break
            redacted_response_ref = self._redacted_response_ref(response.value)
            try:
                decision = RecoveryDecision.model_validate_json(
                    canonical_bytes(response.value)
                )
                decision = self._validate_decision(decision, checkpoint, failure)
                policy_validation_attempts.append((redacted_response_ref, None))
                decision_origin = "AGENT"
                break
            except (ValidationError, ValueError) as error:
                validation_code = _policy_validation_code(error)
                policy_validation_attempts.append(
                    (redacted_response_ref, validation_code)
                )
                if validation_attempt == 0:
                    prompt += b"\n" + _policy_feedback(validation_code)
                    continue
                decision = self._stop(
                    "recovery output failed policy validation",
                    "preserve the failure for manual review",
                )
        return self._store(
            checkpoint,
            failure,
            decision,
            decision_origin=decision_origin,
            policy_validation_attempts=tuple(policy_validation_attempts),
        )

    def _redacted_response_ref(
        self, value: Mapping[str, object]
    ) -> StoredDataRef | None:
        try:
            serialized = canonical_bytes(value)
            if len(serialized) > _MAX_REDACTED_RECOVERY_RESPONSE_BYTES:
                return None
            redacted = redact_projected_json(serialized).data
            if len(redacted) > _MAX_REDACTED_RECOVERY_RESPONSE_BYTES:
                return None
            return self._artifacts.put_bytes(redacted, "application/json")
        except (OSError, ValueError):
            return None

    def _auto_bundle_stderr(
        self, checkpoint: StageCheckpoint, failure: StageFailure
    ) -> bytes | None:
        """Read only the exact resolver attempt attached to this failed stage."""

        for ref in failure.evidence_refs:
            try:
                attempt = json.loads(self._artifacts.read_bounded(ref, 64 * 1024))
            except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
                continue
            if (
                not isinstance(attempt, dict)
                or attempt.get("kind") != "simple_dependency_bundle_attempt"
                or attempt.get("attempt_id") != checkpoint.attempt_id
                or attempt.get("identity")
                != checkpoint.identity.model_dump(mode="json")
                or attempt.get("error_code") != failure.code
                or attempt.get("timed_out") is True
            ):
                continue
            raw_ref = attempt.get("stderr_ref")
            if raw_ref is None:
                continue
            try:
                stderr_ref = StoredDataRef.model_validate(raw_ref)
                return self._artifacts.read_bounded(stderr_ref, 64 * 1024)
            except (OSError, ValueError):
                continue
        return None

    def _verified_exit_two_with_clean_cleanup(
        self, checkpoint: StageCheckpoint, failure: StageFailure
    ) -> bool:
        """Reconsider only a CAS-bound, fully cleaned failed PoC input."""

        return (
            failure.code == "POC_EXECUTION_FAILED"
            and (execution := self._verified_poc_execution(checkpoint, failure))
            is not None
            and execution.get("exit_code") == 2
        )

    def _verified_poc_execution(
        self, checkpoint: StageCheckpoint, failure: StageFailure
    ) -> dict[str, object] | None:
        """Require one exact, CAS-verified execution, PoC input and cleanup."""

        if (
            checkpoint.stage is not SimpleStage.POC_EXECUTION_DONE
            or failure.code not in {"POC_EXECUTION_FAILED", "POC_RUNTIME_IMPORT_FAILED"}
            or not checkpoint.attempt_id
            or not checkpoint.image_digest
        ):
            return None
        for execution_ref in failure.evidence_refs:
            try:
                execution = json.loads(
                    self._artifacts.read_bounded(execution_ref, 64 * 1024)
                )
                if (
                    not isinstance(execution, dict)
                    or execution.get("kind") != "simple_poc_execution"
                    or execution.get("attempt_id") != checkpoint.attempt_id
                    or type(execution.get("exit_code")) is not int
                    or execution.get("exit_code") == 0
                    or execution.get("timed_out") is not False
                    or execution.get("image_digest") != checkpoint.image_digest
                    or not isinstance(execution.get("container_id"), str)
                    or not execution["container_id"]
                ):
                    continue
                candidate_ref = StoredDataRef.model_validate(
                    execution.get("candidate_ref")
                )
                content_ref = StoredDataRef.model_validate(execution.get("content_ref"))
                if (
                    candidate_ref not in checkpoint.input_refs
                    or content_ref not in checkpoint.input_refs
                ):
                    continue
                candidate = json.loads(
                    self._artifacts.read_bounded(candidate_ref, 64 * 1024)
                )
                if (
                    not isinstance(candidate, dict)
                    or candidate.get("kind") != "simple_poc_candidate"
                    or not isinstance(candidate.get("attempt_id"), str)
                    or not candidate["attempt_id"]
                    or StoredDataRef.model_validate(candidate.get("content_ref"))
                    != content_ref
                ):
                    continue
                content = self._artifacts.read_bounded(
                    content_ref, _MAX_POC_CANDIDATE_BYTES
                )
                if (
                    not isinstance(candidate.get("content_digest"), str)
                    or candidate["content_digest"]
                    != hashlib.sha256(content).hexdigest()
                    or content_ref.content_hash != candidate["content_digest"]
                ):
                    continue
                for key in ("stdout_ref", "stderr_ref"):
                    stream_ref = StoredDataRef.model_validate(execution.get(key))
                    if stream_ref not in failure.evidence_refs:
                        raise ValueError("POC_STREAM_NOT_BOUND")
                    self._artifacts.read_bounded(stream_ref, _MAX_POC_OUTPUT_BYTES)
            except (OSError, ValueError, TypeError, UnicodeDecodeError):
                continue
            for cleanup_ref in failure.evidence_refs:
                try:
                    cleanup = json.loads(
                        self._artifacts.read_bounded(cleanup_ref, 4 * 1024)
                    )
                except (OSError, ValueError, UnicodeDecodeError):
                    continue
                if (
                    isinstance(cleanup, dict)
                    and cleanup.get("kind") == "simple_container_cleanup"
                    and cleanup.get("attempt_id") == checkpoint.attempt_id
                    and cleanup.get("container_id") == execution["container_id"]
                    and cleanup.get("status") == "REMOVED"
                ):
                    return execution
        return None

    def _missing_playwright_browser(
        self, checkpoint: StageCheckpoint, failure: StageFailure
    ) -> str | None:
        stderr = self._poc_execution_stderr(checkpoint, failure)
        if (
            stderr is None
            or b"BrowserType.launch: Executable doesn't exist at " not in stderr
        ):
            return None
        for browser in _PLAYWRIGHT_BROWSERS:
            if b"ms-playwright/" + browser.encode("ascii") in stderr:
                return browser
        return None

    @staticmethod
    def _import_time_storage_write_error(stderr: bytes) -> bool:
        """Recognize a redacted, import-time SQLite write failure conservatively."""

        return b"OperationalError: writable_storage" in stderr or (
            b"OperationalError" in stderr
            and (b"in init_db" in stderr or b"> init_db" in stderr)
        )

    def _poc_execution_stderr(
        self, checkpoint: StageCheckpoint, failure: StageFailure
    ) -> bytes | None:
        return self._poc_execution_stream(checkpoint, failure, "stderr_ref")

    def _poc_execution_import_diagnostic(
        self,
        checkpoint: StageCheckpoint,
        failure: StageFailure,
        stream_ref_key: Literal["stdout_ref", "stderr_ref"],
    ) -> tuple[dict[bytes, bytes], bool, bool]:
        if failure.code != "POC_RUNTIME_IMPORT_FAILED":
            return {}, False, False
        stream_ref = self._bound_poc_stream_ref(checkpoint, failure, stream_ref_key)
        if stream_ref is None:
            return {}, False, False
        try:
            return self._verified_import_diagnostic(stream_ref, checkpoint)
        except (OSError, ValueError):
            return {}, False, False

    def _verified_import_diagnostic(
        self, ref: StoredDataRef, checkpoint: StageCheckpoint
    ) -> tuple[dict[bytes, bytes], bool, bool]:
        """Inspect the verified full stream, capped by the Docker output limit."""

        output = self._artifacts.read_bounded(ref, _MAX_POC_OUTPUT_BYTES)
        matches, terminal = _python_import_traceback_spans(output)
        if not matches and self._verified_pinned_recipe(checkpoint):
            matches, terminal = _python_cli_import_diagnostic(output)
        return matches, terminal, not output.strip()

    def _verified_pinned_recipe(self, checkpoint: StageCheckpoint) -> bool:
        """Verify the built image recipe belongs to this exact pinned run."""

        if checkpoint.recipe_ref is None or checkpoint.image_digest is None:
            return False
        try:
            recipe = json.loads(
                self._artifacts.read_bounded(checkpoint.recipe_ref, 64 * 1024)
            )
        except (OSError, ValueError, UnicodeDecodeError):
            return False
        identity = checkpoint.identity
        return (
            isinstance(recipe, dict)
            and recipe.get("kind") == "simple_environment_recipe"
            and recipe.get("analysis_id") == identity.analysis_id
            and recipe.get("workspace_id") == identity.workspace_id
            and recipe.get("commit_id") == identity.commit_id
            and recipe.get("hypothesis_id") == identity.hypothesis_id
            and isinstance(recipe.get("attempt_id"), str)
            and bool(recipe["attempt_id"])
            and recipe.get("status") == "BUILT"
            and recipe.get("degraded") is False
            and recipe.get("image_digest") == checkpoint.image_digest
            and recipe.get("dockerfile_source")
            in {
                "REPOSITORY_DOCKERFILE",
                "GENERATED",
                "GENERATED_OFFLINE_WHEELS",
            }
        )

    def _pinned_local_python_module(
        self, checkpoint: StageCheckpoint, import_name: bytes
    ) -> bool:
        """Classify only a CAS-backed tracked Python module in the built run."""

        prefix = b"ModuleNotFoundError:"
        if not import_name.startswith(prefix) or not self._verified_pinned_recipe(
            checkpoint
        ):
            return False
        name = import_name.removeprefix(prefix)
        if len(name) > 128 or _SAFE_PYTHON_MODULE.fullmatch(name) is None:
            return False
        try:
            connection = sqlite3.connect(
                f"file:{self._artifacts.paths.database.resolve().as_posix()}?mode=ro",
                uri=True,
            )
            try:
                row = connection.execute(
                    "SELECT run_json FROM simple_analysis_runs WHERE analysis_id = ?",
                    (checkpoint.identity.analysis_id,),
                ).fetchone()
            finally:
                connection.close()
            if row is None:
                return False
            run = SimpleAnalysisRun.model_validate_json(row[0])
            identity = checkpoint.identity
            if (
                run.workspace_id != identity.workspace_id
                or run.commit_id != identity.commit_id
                or run.static_bundle_ref is None
            ):
                return False
            bundle = json.loads(
                self._artifacts.read_bounded(run.static_bundle_ref, 64 * 1024)
            )
            if (
                not isinstance(bundle, dict)
                or bundle.get("kind") != "simple_static_fact_bundle"
                or bundle.get("analysis_id") != identity.analysis_id
                or bundle.get("workspace_id") != identity.workspace_id
                or bundle.get("commit_id") != identity.commit_id
            ):
                return False
            manifest_ref = StoredDataRef.model_validate(
                bundle.get("poc_source_manifest_ref", bundle.get("source_manifest_ref"))
            )
            manifest = json.loads(self._artifacts.read(manifest_ref))
            if (
                not isinstance(manifest, dict)
                or manifest.get("kind") != "simple_tracked_sources"
                or not isinstance(manifest.get("paths"), list)
            ):
                return False
            module_path = name.decode("ascii").replace(".", "/")
            targets = {f"{module_path}.py", f"{module_path}/__init__.py"}
            matched = False
            for path in manifest["paths"]:
                if (
                    not isinstance(path, str)
                    or not path
                    or path.startswith("/")
                    or "\\" in path
                    or ":" in path
                    or any(part in {"", ".", ".."} for part in path.split("/"))
                ):
                    return False
                matched |= any(
                    path == target or path.endswith("/" + target) for target in targets
                )
            return matched
        except (OSError, sqlite3.Error, ValueError, UnicodeError, TypeError):
            return False
        return False

    def _poc_execution_stream(
        self,
        checkpoint: StageCheckpoint,
        failure: StageFailure,
        stream_ref_key: Literal["stdout_ref", "stderr_ref"],
    ) -> bytes | None:
        stream_ref = self._bound_poc_stream_ref(checkpoint, failure, stream_ref_key)
        if stream_ref is None:
            return None
        try:
            return self._artifacts.read(stream_ref)[-16_384:]
        except (OSError, ValueError):
            return None

    def _bound_poc_stream_ref(
        self,
        checkpoint: StageCheckpoint,
        failure: StageFailure,
        stream_ref_key: Literal["stdout_ref", "stderr_ref"],
    ) -> StoredDataRef | None:
        execution = self._verified_poc_execution(checkpoint, failure)
        if execution is None:
            return None
        try:
            return StoredDataRef.model_validate(execution.get(stream_ref_key))
        except ValueError:
            return None

    def _validate_decision(
        self,
        decision: RecoveryDecision,
        checkpoint: StageCheckpoint,
        failure: StageFailure,
    ) -> RecoveryDecision:
        if decision.action not in ALLOWED_ACTIONS[decision.category]:
            raise ValueError("RECOVERY_ACTION_CATEGORY_MISMATCH")
        if decision.action is RecoveryAction.REPLAN_ENVIRONMENT:
            # This action is reserved for the execution-evidence-bound rule.
            raise ValueError("RECOVERY_REPLAN_REQUIRES_BOUND_IMPORT_EVIDENCE")
        if (
            decision.action is RecoveryAction.REGENERATE_INPUT
            and failure.code == "POC_EXECUTION_FAILED"
            and self._verified_poc_execution(checkpoint, failure) is None
        ):
            raise ValueError("RECOVERY_INPUT_REGEN_REQUIRES_BOUND_POC_EVIDENCE")
        if decision.action is RecoveryAction.REBUILD_ENVIRONMENT:
            patch = validate_environment_patch(decision.environment_patch)
            if patch not in {
                _PLAYWRIGHT_PATCH_PREFIX + browser for browser in _PLAYWRIGHT_BROWSERS
            }:
                try:
                    redacted_patch = redact_untrusted_text(patch.encode("utf-8"))
                except ValueError as error:
                    raise ValueError("RECOVERY_ENVIRONMENT_PATCH_FORBIDDEN") from error
                if redacted_patch.data != patch.encode("utf-8"):
                    raise ValueError("RECOVERY_ENVIRONMENT_PATCH_FORBIDDEN")
        elif decision.environment_patch.strip():
            raise ValueError("RECOVERY_ENVIRONMENT_PATCH_UNEXPECTED")
        safe_text: dict[str, str] = {}
        for field in ("diagnosis", "guidance"):
            original = getattr(decision, field).encode("utf-8")
            if len(original) > _MAX_RECOVERY_DECISION_TEXT_BYTES:
                raise ValueError("RECOVERY_DECISION_TEXT_TOO_LARGE")
            try:
                redacted = redact_untrusted_text(original).data
            except ValueError as error:
                raise ValueError("RECOVERY_DECISION_REDACTION_FAILED") from error
            if len(redacted) > _MAX_RECOVERY_DECISION_TEXT_BYTES:
                raise ValueError("RECOVERY_DECISION_TEXT_TOO_LARGE")
            safe_text[field] = redacted.decode("utf-8")
        return decision.model_copy(
            update={
                **safe_text,
                "environment_patch": (
                    patch
                    if decision.action is RecoveryAction.REBUILD_ENVIRONMENT
                    else ""
                ),
            }
        )

    @staticmethod
    def _stop(diagnosis: str, guidance: str) -> RecoveryDecision:
        return RecoveryDecision(
            category=RecoveryCategory.TERMINAL,
            action=RecoveryAction.STOP,
            diagnosis=diagnosis,
            guidance=guidance,
            environment_patch="",
        )

    def _store(
        self,
        checkpoint: StageCheckpoint,
        failure: StageFailure,
        decision: RecoveryDecision,
        *,
        decision_origin: Literal["AGENT", "RULE", "FALLBACK"] = "RULE",
        diagnostic_excerpt: bytes | None = None,
        policy_validation_attempts: tuple[
            tuple[StoredDataRef | None, str | None], ...
        ] = (),
    ) -> RecoveryResolution:
        try:
            bounded_diagnostic = (
                redact_untrusted_text(
                    diagnostic_excerpt[-_MAX_IMPORT_DIAGNOSTIC_BYTES:]
                )
                .data[-_MAX_IMPORT_DIAGNOSTIC_BYTES:]
                .decode("utf-8", errors="replace")
                if diagnostic_excerpt is not None
                else None
            )
        except ValueError:
            bounded_diagnostic = "Python import traceback could not be safely shown"
        decision_ref = self._artifacts.put_json(
            {
                "kind": "simple_recovery_decision",
                "identity": checkpoint.identity.model_dump(mode="json"),
                "stage": checkpoint.stage.value,
                "attempt": checkpoint.attempt_number,
                "attempt_id": checkpoint.attempt_id,
                "original_error": failure.model_dump(mode="json"),
                "decision": decision.model_dump(mode="json"),
                "decision_origin": decision_origin,
                **(
                    {
                        "policy_validation_attempts": [
                            {
                                "redacted_response_ref": (
                                    response_ref.model_dump(mode="json")
                                    if response_ref is not None
                                    else None
                                ),
                                "validation_code": validation_code,
                            }
                            for response_ref, validation_code in (
                                policy_validation_attempts
                            )
                        ]
                    }
                    if policy_validation_attempts
                    else {}
                ),
                **(
                    {"diagnostic_excerpt": bounded_diagnostic}
                    if bounded_diagnostic is not None
                    else {}
                ),
            }
        )
        return RecoveryResolution(decision=decision, decision_ref=decision_ref)


__all__ = [
    "ALLOWED_ACTIONS",
    "MAX_RECOVERY_ATTEMPTS",
    "TERMINAL_ERROR_CODES",
    "RecoveryAction",
    "RecoveryCategory",
    "RecoveryCoordinator",
    "RecoveryDecision",
    "RecoveryResolution",
    "SimpleRecoveryCoordinator",
    "has_python_import_failure",
    "has_python_import_traceback",
    "validate_environment_patch",
]
