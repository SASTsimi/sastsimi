"""Bounded, typed recovery decisions for the sequential SimpleRuntime."""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import sqlite3
from collections.abc import Mapping
from enum import StrEnum
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
from .models import (
    MAX_RECOVERY_ATTEMPTS,
    SimpleAnalysisRun,
    SimpleStage,
    StageCheckpoint,
    StageFailure,
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
