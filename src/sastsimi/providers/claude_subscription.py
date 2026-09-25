"""Official Claude Code CLI adapter for subscription-authenticated calls.

The official ``claude -p`` client is a coding agent, not a chat endpoint.  This
adapter reduces it to a text-in/JSON-out model boundary and refuses to run when
that reduction cannot be observed:

* every built-in tool is removed with ``--tools ""`` so the only tool the model
  can reach is the structured-output transport itself,
* the client reports its own effective isolation in the ``system/init`` event and
  the adapter fails closed unless that report matches exactly,
* the credential must be an official subscription login; an ambient API key or an
  ``apiKeyHelper`` command is rejected before and during the call.

Measured against the official client ``2.1.280``, the first that serves Opus
5.5.  A different client version is rejected by the pinned binding rather than
assumed compatible.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import signal
import subprocess
import tempfile
from collections.abc import AsyncIterator, Callable, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from threading import Lock
from time import monotonic
from typing import Literal, cast

from pydantic import JsonValue

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import (
    ClientExecutionProfile,
    Environment,
    LLMInvocationRequest,
    LLMInvocationResult,
    ProviderProfile,
    ProviderValidationEvidence,
)
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.dto import CancellationResult, CapabilityProbeResult

from .base import (
    CLAUDE_PVD_RUNNER_MARKER,
    Clock,
    CodexProcessRequest,
    CodexProcessResult,
    InvocationResultBuilder,
    NormalizedProviderResult,
    OutputSchemaValidator,
    PromptInputResolver,
    ProviderInputMismatchError,
    ProviderInvalidOutputError,
    ProviderProbeRunner,
    ProviderSessionStore,
    ResolvedPromptInput,
    SubscriptionProcessRunner,
)
from .normalization import (
    NormalizedFailure,
    claude_failure,
    normalize_claude_exception,
)

# The official client transports one structured answer as a tool call.  It is the
# adapter's own output channel, so it is the single tool name ever allowed.
_STRUCTURED_OUTPUT_TOOL = "StructuredOutput"

# A memory guard, not a content limit.  The client caps one turn at 64,000
# output tokens, and the stream carries that answer twice - as the tool call and
# again in the terminal result - JSON-escaped; with no cap on how many
# hypotheses a batch may return, a megabyte was within reach of a real answer.
_MAX_EVENT_STREAM_BYTES = 4 * 1_048_576
_MAX_STDERR_BYTES = 65_536
# The name the client gives a message it built itself rather than received.
_CLIENT_SYNTHETIC_MODEL = "<synthetic>"
_MAX_AUTH_STATUS_BYTES = 65_536
_TREE_KILLER_TIMEOUT_SECONDS = 2.0
# How long a closed conversation may take to exit before it is killed.
_CONVERSATION_EXIT_SECONDS = 10.0
_ARRAY_ENVELOPE_KEY = "items"
_PROCESS_LOCK = Lock()

# The exact official subscription-login identity.  ``api_key`` and ``oauth_token``
# are deliberately absent: an API credential must never satisfy a subscription
# profile, even when one is present in the operator's environment.
_SUBSCRIPTION_AUTH_METHOD = "claude.ai"
_FIRST_PARTY_API_PROVIDER = "firstParty"
# ``apiKeySource`` is always present in the init event.  ``none`` is the only
# value that proves no API key and no apiKeyHelper command produced a credential.
_NO_API_KEY_SOURCE = "none"
_EXPECTED_AGENTS = ("claude", "Explore", "general-purpose", "Plan")
# The only system subtypes allowed after init.  Both are pure progress reports:
# ``thinking_tokens`` carries token counts and ``api_retry`` a retry notice.  A
# subtype outside this set, such as ``permission_denied``, fails the call closed.
_INFORMATIONAL_SYSTEM_SUBTYPES = frozenset({"thinking_tokens", "api_retry"})
# The client's own wording when it declines a tool this boundary never enabled.
_TOOL_UNAVAILABLE_MARKER = "No such tool available"


@asynccontextmanager
async def _claude_process_lock() -> AsyncIterator[None]:
    """Serialize subscription processes across every worker event loop.

    Concurrent children share one credential directory, so they are never run in
    parallel even when separate event loops drive them.
    """

    acquired = False
    try:
        while not acquired:
            acquired = _PROCESS_LOCK.acquire(blocking=False)
            if not acquired:
                await asyncio.sleep(0.01)
        yield
    finally:
        if acquired:
            _PROCESS_LOCK.release()


# A launch, not a whole call, is what collides: two children starting at once
# both find the same credential file's access token expired and race to
# refresh it, and the loser reports "another Claude Code process is
# refreshing it".  Spacing launches by this much clears it without
# serializing the calls themselves, which the process lock above already
# does and which would undo the run's parallelism.  Measured against the
# official client refreshing a subscription token.
_LAUNCH_STAGGER_SECONDS = 0.5
_LAUNCH_LOCK = asyncio.Lock()
_LAST_LAUNCH: list[float] = [0.0]


async def _stagger_launch() -> None:
    async with _LAUNCH_LOCK:
        wait = _LAST_LAUNCH[0] + _LAUNCH_STAGGER_SECONDS - monotonic()
        if wait > 0:
            await asyncio.sleep(wait)
        _LAST_LAUNCH[0] = monotonic()


# The official client resolves its credential directory, and nothing else, from the
# environment.  It was measured to run with neither PATH nor HOME present, so the
# child inherits no search path and no user home to discover configuration from.
_CHILD_ENVIRONMENT_ALLOWLIST = (
    "CLAUDE_CONFIG_DIR",
    "SYSTEMROOT",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
)
# Defence in depth behind the argv flags.  The client honours a large number of
# environment names; the allowlist above already denies them by default, and
# these explicitly disable the behaviours whose absence the contract asserts.
_CHILD_ENVIRONMENT_OVERRIDES: tuple[tuple[str, str], ...] = (
    # instruction_sources=EXPLICIT_SASTSIMI_PAYLOAD_ONLY
    ("CLAUDE_CODE_DISABLE_BUNDLED_SKILLS", "1"),
    ("CLAUDE_CODE_DISABLE_AUTO_MEMORY", "1"),
    ("CLAUDE_CODE_DISABLE_CLAUDE_MDS", "1"),
    ("CLAUDE_CODE_DISABLE_WORKFLOWS", "1"),
    # provider_fallback=DISABLED
    ("CLAUDE_CODE_DISABLE_NONSTREAMING_FALLBACK", "1"),
    ("CLAUDE_CODE_DISABLE_REFUSAL_FALLBACK", "1"),
    # A managed settings file can define apiKeyHelper, which is both an API
    # credential path and arbitrary command execution inside this boundary.
    ("CLAUDE_CODE_MANAGED_SETTINGS_PATH", os.devnull),
    # The pinned executable must not replace itself between digest checks.
    ("DISABLE_AUTOUPDATER", "1"),
    ("CLAUDE_CODE_PACKAGE_MANAGER_AUTO_UPDATE", "0"),
    ("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1"),
    ("DISABLE_TELEMETRY", "1"),
    ("DISABLE_ERROR_REPORTING", "1"),
    ("DISABLE_GROWTHBOOK", "1"),
)


class ProviderExecutableBindingError(RuntimeError):
    """The official client no longer matches its approved executable binding."""


class _ProcessTreeTerminationError(RuntimeError):
    """The child exited but complete process-tree termination was not confirmed."""


@dataclass(frozen=True)
class ApprovedClaudeExecutable:
    """Exact composition-time approval for one official Claude Code CLI binary."""

    path: Path
    sha256: str

    def __post_init__(self) -> None:
        if (
            not self.path.is_absolute()
            or self.path.is_symlink()
            or len(self.sha256) != 64
            or self.sha256 != self.sha256.lower()
            or any(character not in "0123456789abcdef" for character in self.sha256)
        ):
            raise ValueError("INVALID_CLAUDE_EXECUTABLE_BINDING")


@dataclass(frozen=True)
class ApprovedClaudeExecutionBinding:
    """Exact approved profile, client boundary, executable and runtime scope."""

    provider_profile: ProviderProfile
    client_execution_profile: ClientExecutionProfile
    executable: ApprovedClaudeExecutable
    claude_config_dir: Path
    runtime_environment: Environment
    provider_validation_evidence: ProviderValidationEvidence | None = None

    def __post_init__(self) -> None:
        _validate_execution_binding(self)


@dataclass(frozen=True)
class _ChildResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class ClaudeCliProcessRunner:
    """Run a hash-pinned official ``claude -p`` in a disposable boundary."""

    def __init__(
        self,
        *,
        binding: ApprovedClaudeExecutionBinding,
        binding_validator: Callable[[ApprovedClaudeExecutionBinding], None]
        | None = None,
        diagnostics: Callable[[str, int, bytes], None] | None = None,
        usage: Callable[[dict[str, object]], None] | None = None,
    ) -> None:
        self.binding = binding
        # Every call's token counts, so a run's cost is measured, not guessed.
        self._usage = usage
        self.executable = binding.executable
        self.claude_config_dir = binding.claude_config_dir
        self._binding_validator = binding_validator
        # A child that dies leaves the caller with a bare ``FAILED``.  The sink
        # keeps the exit code and a bounded stderr tail where an operator can
        # read them; it never reaches the normalized result.
        self._diagnostics = diagnostics
        self._verify_approval()
        self.verify_executable()

    def _record_child_failure(
        self, invocation_id: str, returncode: int, stderr: bytes
    ) -> None:
        if self._diagnostics is None:
            return
        try:
            self._diagnostics(invocation_id, returncode, stderr[-_MAX_STDERR_BYTES:])
        except Exception:  # noqa: BLE001 - diagnostics must never fail a call
            return

    def _record_usage(
        self,
        invocation_id: str,
        model: str,
        stream: bytes,
        turn: int | None = None,
        cost_before: float = 0.0,
    ) -> float:
        """Record one call or turn; return the session's running cost.

        Token counts are per turn, but the client reports a conversation's
        cost as a running total, so a turn records only what it added.
        """

        try:
            entry = _result_usage(stream)
            if entry is None:
                return cost_before
            running = entry.get("total_cost_usd")
            if isinstance(running, (int, float)):
                entry["total_cost_usd"] = max(0.0, float(running) - cost_before)
                cost_before = float(running)
            if self._usage is None:
                return cost_before
            self._usage(
                {
                    "invocation_id": invocation_id,
                    "model": model,
                    **({"turn": turn} if turn is not None else {}),
                    **entry,
                }
            )
        except Exception:  # noqa: BLE001 - accounting must never fail a call
            pass
        return cost_before

    def _verify_approval(self) -> None:
        _validate_execution_binding(self.binding)
        if self._binding_validator is not None:
            self._binding_validator(self.binding)

    def verify_executable(self) -> None:
        """Recheck the immutable approval immediately before every spawn."""
        try:
            if (
                not self.executable.path.is_file()
                or self.executable.path.is_symlink()
                or self.executable.path.resolve(strict=True) != self.executable.path
                or not self.claude_config_dir.is_dir()
                or self.claude_config_dir.is_symlink()
                or self.claude_config_dir.resolve(strict=True) != self.claude_config_dir
            ):
                raise OSError
            digest = _sha256_file(self.executable.path)
        except OSError:
            raise ProviderExecutableBindingError from None
        if digest != self.executable.sha256:
            raise ProviderExecutableBindingError

    def verify_binding(
        self, request: CodexProcessRequest, *, conversation: bool = False
    ) -> None:
        """Revalidate exact approved records and request identity before a call.

        A conversation is opened before its first turn exists, so its prompt is
        checked per turn instead of here.
        """
        _validate_process_request(request, require_prompt=not conversation)
        self._verify_approval()
        if (
            request.provider_profile_ref != reference(self.binding.provider_profile)
            or request.model != self.binding.provider_profile.model
        ):
            raise ProviderInputMismatchError
        self.verify_executable()

    def child_environment(self, source: Mapping[str, str]) -> dict[str, str]:
        """Build a small allowlisted environment with no ambient credentials.

        Only ``CLAUDE_CONFIG_DIR`` and ``HOME`` are set by the adapter; every other
        name must be both on the allowlist and already present.  An inherited
        ``ANTHROPIC_API_KEY`` cannot reach the child because it is not allowlisted.
        """
        environment = {"CLAUDE_CONFIG_DIR": str(self.claude_config_dir)}
        inherited = ("SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP")
        source_by_upper = {key.upper(): value for key, value in source.items()}
        for name in inherited:
            value = source_by_upper.get(name)
            if value:
                environment[name] = value
        for name, value in _CHILD_ENVIRONMENT_OVERRIDES:
            environment[name] = value
        return environment

    def execution_argv(
        self,
        request: CodexProcessRequest,
        work_directory: Path,
        schema: bytes,
        *,
        conversation: bool = False,
    ) -> tuple[str, ...]:
        """Return the fixed no-tools invocation; prompt bytes are stdin-only.

        ``--settings`` is never passed: a settings document may define an
        ``apiKeyHelper`` command, which is both an API credential path and
        arbitrary command execution inside this boundary.
        """
        _validate_process_request(request, require_prompt=not conversation)
        if not work_directory.is_absolute():
            raise ValueError("CLAUDE_BOUNDARY_PATH_MUST_BE_ABSOLUTE")
        return (
            str(self.executable.path),
            "-p",
            "--model",
            request.model,
            "--safe-mode",
            "--tools",
            "",
            "--strict-mcp-config",
            "--disable-slash-commands",
            "--setting-sources",
            "",
            "--no-session-persistence",
            "--permission-mode",
            "dontAsk",
            "--output-format",
            "stream-json",
            "--verbose",
            "--json-schema",
            schema.decode("utf-8"),
        )

    async def execute(self, request: CodexProcessRequest) -> CodexProcessResult:
        try:
            self.verify_binding(request)
            environment = self.child_environment(os.environ)
            with tempfile.TemporaryDirectory(prefix="sastsimi-claude-") as temporary:
                temporary_root = Path(temporary).resolve()
                work_directory = temporary_root / "work"
                auth_check_directory = temporary_root / "auth-check"
                auth_check_directory.mkdir()
                schema = _strict_json(request.output_schema, ProviderInputMismatchError)
                if not isinstance(schema, dict):
                    raise ProviderInputMismatchError
                schema_bytes = canonical_bytes(_claude_output_schema(schema))
                async with asyncio.timeout(request.timeout_ms / 1_000):
                    version = await self._run_child(
                        (str(self.executable.path), "--version"),
                        stdin=None,
                        cwd=auth_check_directory,
                        environment=environment,
                    )
                    _require_claude_cli_version(
                        version, self.binding.provider_profile.client_version
                    )
                    auth = await self._run_child(
                        (str(self.executable.path), "auth", "status", "--json"),
                        stdin=None,
                        cwd=auth_check_directory,
                        environment=environment,
                    )
                    if auth.returncode != 0:
                        return CodexProcessResult("AUTH_REQUIRED", None, None)
                    if not _is_exact_subscription_login(auth):
                        return CodexProcessResult("AUTH_REQUIRED", None, None)
                    self.verify_executable()
                    work_directory.mkdir()
                    execution = await self._run_child(
                        self.execution_argv(request, work_directory, schema_bytes),
                        stdin=request.prompt,
                        cwd=work_directory,
                        environment=environment,
                    )
                self._record_usage(
                    request.invocation_id, request.model, execution.stdout
                )
                try:
                    (
                        status,
                        final_message,
                        session_id,
                        reopens_at,
                    ) = _validated_event_stream(
                        execution.stdout,
                        model=request.model,
                        client_version=self.binding.provider_profile.client_version,
                    )
                except ProviderInvalidOutputError:
                    # A child that died never produced an answer to judge, so this
                    # is a failed call rather than an unusable model output.
                    if execution.returncode != 0:
                        self._record_child_failure(
                            request.invocation_id,
                            execution.returncode,
                            execution.stderr,
                        )
                        return CodexProcessResult("FAILED", None, None)
                    raise
                if status != "SUCCEEDED":
                    return CodexProcessResult(status, None, None, reopens_at)
                if execution.returncode != 0:
                    self._record_child_failure(
                        request.invocation_id, execution.returncode, execution.stderr
                    )
                    return CodexProcessResult("FAILED", None, None)
                return CodexProcessResult("SUCCEEDED", final_message, session_id)
        except asyncio.CancelledError:
            raise
        except TimeoutError:
            return CodexProcessResult("TIMED_OUT", None, None)
        except ProviderInvalidOutputError:
            return CodexProcessResult("INVALID_OUTPUT", None, None)
        except (
            ProviderExecutableBindingError,
            ProviderInputMismatchError,
            OSError,
        ) as error:
            self._record_child_failure(
                request.invocation_id, -1, f"{type(error).__name__}: {error}".encode()
            )
            return CodexProcessResult("FAILED", None, None)

    @asynccontextmanager
    async def conversation(
        self, request: CodexProcessRequest
    ) -> AsyncIterator[ClaudeConversation]:
        """Open one client process that answers turn after turn.

        The same preflight a single call runs - binding, pinned version and an
        exact subscription login - runs once, before the process starts.
        """

        self.verify_binding(request, conversation=True)
        environment = self.child_environment(os.environ)
        with tempfile.TemporaryDirectory(prefix="sastsimi-claude-") as temporary:
            root = Path(temporary).resolve()
            work_directory = root / "work"
            auth_check_directory = root / "auth-check"
            auth_check_directory.mkdir()
            schema = _strict_json(request.output_schema, ProviderInputMismatchError)
            if not isinstance(schema, dict):
                raise ProviderInputMismatchError
            schema_bytes = canonical_bytes(_claude_output_schema(schema))
            async with asyncio.timeout(request.timeout_ms / 1_000):
                version = await self._run_child(
                    (str(self.executable.path), "--version"),
                    stdin=None,
                    cwd=auth_check_directory,
                    environment=environment,
                )
                _require_claude_cli_version(
                    version, self.binding.provider_profile.client_version
                )
                auth = await self._run_child(
                    (str(self.executable.path), "auth", "status", "--json"),
                    stdin=None,
                    cwd=auth_check_directory,
                    environment=environment,
                )
            if auth.returncode != 0 or not _is_exact_subscription_login(auth):
                yield ClaudeConversation(
                    self,
                    request,
                    None,
                    unavailable=CodexProcessResult("AUTH_REQUIRED", None, None),
                )
                return
            self.verify_executable()
            work_directory.mkdir()
            argv = (
                *self.execution_argv(
                    request, work_directory, schema_bytes, conversation=True
                ),
                "--input-format",
                "stream-json",
            )
            await _stagger_launch()
            process = await asyncio.create_subprocess_exec(
                *argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=work_directory,
                env=dict(environment),
                creationflags=_windows_creation_flags(),
                start_new_session=os.name != "nt",
                # One result line carries a whole structured answer.
                limit=_MAX_EVENT_STREAM_BYTES,
            )
            assert process.stderr is not None
            stderr_task = asyncio.create_task(
                _drain_bounded(process.stderr, _MAX_STDERR_BYTES)
            )
            try:
                yield ClaudeConversation(self, request, process)
            finally:
                if process.stdin is not None and not process.stdin.is_closing():
                    process.stdin.close()
                try:
                    async with asyncio.timeout(_CONVERSATION_EXIT_SECONDS):
                        await process.wait()
                except TimeoutError:
                    pass
                if process.returncode is None:
                    await _terminate_process_tree(process)
                code = process.returncode
                if code is not None and code != 0:
                    self._record_child_failure(
                        request.invocation_id,
                        code,
                        await asyncio.shield(stderr_task),
                    )
                if not stderr_task.done():
                    stderr_task.cancel()
                await asyncio.gather(stderr_task, return_exceptions=True)

    async def _run_child(
        self,
        argv: tuple[str, ...],
        *,
        stdin: bytes | None,
        cwd: Path,
        environment: Mapping[str, str],
    ) -> _ChildResult:
        self.verify_executable()
        await _stagger_launch()
        spawn_task = asyncio.create_task(
            asyncio.create_subprocess_exec(
                *argv,
                stdin=(
                    asyncio.subprocess.DEVNULL
                    if stdin is None
                    else asyncio.subprocess.PIPE
                ),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=dict(environment),
                creationflags=_windows_creation_flags(),
                start_new_session=os.name != "nt",
            )
        )
        try:
            process = await asyncio.shield(spawn_task)
        except asyncio.CancelledError:
            process = await asyncio.shield(spawn_task)
            await _terminate_process_tree(process)
            raise
        assert process.stdout is not None
        assert process.stderr is not None
        stdout_task = asyncio.create_task(
            _drain_bounded(process.stdout, _MAX_EVENT_STREAM_BYTES)
        )
        stderr_task = asyncio.create_task(
            _drain_bounded(process.stderr, _MAX_STDERR_BYTES)
        )
        stdin_task = (
            asyncio.create_task(_write_stdin(process, stdin))
            if stdin is not None
            else None
        )
        try:
            returncode = await process.wait()
            if stdin_task is not None:
                await stdin_task
            return _ChildResult(
                returncode,
                await stdout_task,
                await stderr_task,
            )
        except asyncio.CancelledError:
            await _terminate_process_tree(process)
            raise
        finally:
            if process.returncode is None:
                await _terminate_process_tree(process)
            for task in (stdin_task, stdout_task, stderr_task):
                if task is not None and not task.done():
                    task.cancel()
            await asyncio.gather(
                *(task for task in (stdin_task, stdout_task, stderr_task) if task),
                return_exceptions=True,
            )


class ClaudeConversation:
    """One official client process answering several turns of one conversation.

    Sending a follow-up as a new process re-sends everything before it, and the
    client was measured never reading that repeated prefix from the prompt
    cache: the same 67,000-token prompt sent twice was written to the cache
    both times and read neither time.  In one process the second turn read
    66,952 tokens from the cache and wrote 2,033.

    The client emits a complete ``system/init`` ... ``result`` sequence for
    every turn, so each turn is validated by exactly the checks a single call
    gets, and the session may not change between turns.
    """

    def __init__(
        self,
        runner: ClaudeCliProcessRunner,
        request: CodexProcessRequest,
        process: asyncio.subprocess.Process | None,
        *,
        unavailable: CodexProcessResult | None = None,
    ) -> None:
        self._runner = runner
        self._request = request
        self._process = process
        self._session_id: str | None = None
        self._dead: CodexProcessResult | None = unavailable
        self._turns = 0
        self._cost = 0.0

    async def send(self, prompt: bytes, *, timeout_ms: int) -> CodexProcessResult:
        if self._dead is not None:
            return self._dead
        process = self._process
        assert process is not None and process.stdin is not None
        assert process.stdout is not None
        try:
            text = prompt.decode("utf-8")
        except UnicodeDecodeError:
            return CodexProcessResult("FAILED", None, None)
        if not text.strip():
            return CodexProcessResult("FAILED", None, None)
        line = json.dumps(
            {"type": "user", "message": {"role": "user", "content": text}}
        )
        segment = bytearray()
        try:
            async with asyncio.timeout(timeout_ms / 1_000):
                process.stdin.write(line.encode("utf-8") + b"\n")
                await process.stdin.drain()
                while True:
                    raw = await process.stdout.readline()
                    if not raw:
                        # The client exited mid-turn; nothing more will come.
                        return self._die(CodexProcessResult("FAILED", None, None))
                    segment.extend(raw)
                    if len(segment) >= _MAX_EVENT_STREAM_BYTES:
                        return self._die(
                            CodexProcessResult("INVALID_OUTPUT", None, None)
                        )
                    if b'"result"' in raw and _is_result_event(raw):
                        break
        except TimeoutError:
            return self._die(CodexProcessResult("TIMED_OUT", None, None))
        except (BrokenPipeError, ConnectionResetError, OSError):
            return self._die(CodexProcessResult("FAILED", None, None))
        self._turns += 1
        self._cost = self._runner._record_usage(
            self._request.invocation_id,
            self._request.model,
            bytes(segment),
            turn=self._turns,
            cost_before=self._cost,
        )
        try:
            status, final_message, session_id, reopens_at = _validated_event_stream(
                bytes(segment),
                model=self._request.model,
                client_version=self._runner.binding.provider_profile.client_version,
            )
        except ProviderInvalidOutputError:
            self._runner._record_child_failure(
                self._request.invocation_id, -1, _stream_outline(bytes(segment))
            )
            return self._die(CodexProcessResult("INVALID_OUTPUT", None, None))
        if status != "SUCCEEDED":
            self._runner._record_child_failure(
                self._request.invocation_id, -1, _stream_outline(bytes(segment))
            )
        if self._session_id is None:
            self._session_id = session_id
        elif session_id != self._session_id:
            return self._die(CodexProcessResult("INVALID_OUTPUT", None, None))
        if status != "SUCCEEDED":
            return CodexProcessResult(status, None, None, reopens_at)
        return CodexProcessResult("SUCCEEDED", final_message, session_id)

    def _die(self, result: CodexProcessResult) -> CodexProcessResult:
        self._dead = CodexProcessResult("FAILED", None, None)
        return result


def _stream_outline(stream: bytes) -> bytes:
    """Which events a rejected turn held, and its result event without output.

    Without it a rejected turn is an unexplained ``INVALID_OUTPUT``.  The
    structured output is left out and the result text cut short.
    """

    lines: list[str] = []
    for raw in stream.splitlines():
        try:
            event = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            lines.append(f"unparsed {len(raw)} bytes")
            continue
        if not isinstance(event, dict):
            lines.append(f"non-object {type(event).__name__}")
            continue
        kind = f"{event.get('type')}/{event.get('subtype')}"
        if event.get("type") == "result":
            kept = {
                key: value
                for key, value in event.items()
                if key not in ("structured_output", "usage", "modelUsage")
            }
            if isinstance(kept.get("result"), str):
                kept["result"] = kept["result"][:1000]
            kind += " " + json.dumps(kept, ensure_ascii=False)
        elif event.get("type") == "assistant":
            message = event.get("message")
            blocks = message.get("content") if isinstance(message, dict) else None
            kind += " " + ",".join(
                str(block.get("type"))
                for block in (blocks if isinstance(blocks, list) else [])
                if isinstance(block, dict)
            )
        lines.append(kind)
    return "\n".join(lines).encode("utf-8")


_USAGE_COUNTS = (
    "input_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
    "output_tokens",
)


def _result_usage(stream: bytes) -> dict[str, object] | None:
    """The counts the client reports on its result event; numbers only."""

    for line in reversed(stream.splitlines()):
        if b'"result"' not in line:
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict) or event.get("type") != "result":
            continue
        usage = event.get("usage")
        usage = usage if isinstance(usage, dict) else {}
        entry: dict[str, object] = {
            key: usage[key] for key in _USAGE_COUNTS if isinstance(usage.get(key), int)
        }
        for key in ("total_cost_usd", "duration_ms", "duration_api_ms", "num_turns"):
            value = event.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                entry[key] = value
        entry["is_error"] = event.get("is_error") is True
        subtype = event.get("subtype")
        if isinstance(subtype, str):
            entry["subtype"] = subtype[:64]
        return entry
    return None


def _is_result_event(raw: bytes) -> bool:
    try:
        event = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        return False
    return isinstance(event, dict) and event.get("type") == "result"


class ClaudeSubscriptionAdapter:
    """Translate one exact NEW-session request through an official Claude client."""

    def __init__(
        self,
        *,
        provider_profile_ref: StoredDataRef,
        model: str,
        prompt_resolver: PromptInputResolver,
        process_runner: SubscriptionProcessRunner,
        session_store: ProviderSessionStore,
        output_schema_validator: OutputSchemaValidator,
        result_builder: InvocationResultBuilder,
        clock: Clock,
        probe_runner: ProviderProbeRunner | None = None,
    ) -> None:
        self.provider_profile_ref = provider_profile_ref
        self.model = model
        self.prompt_resolver = prompt_resolver
        self.process_runner = process_runner
        self.session_store = session_store
        self.output_schema_validator = output_schema_validator
        self.result_builder = result_builder
        self.clock = clock
        self.probe_runner = probe_runner
        self._active: dict[str, asyncio.Task[LLMInvocationResult]] = {}
        self._cancel_events: dict[str, asyncio.Event] = {}
        self._active_lock = asyncio.Lock()

    async def probe(
        self, candidate: ProviderValidationEvidence
    ) -> CapabilityProbeResult:
        if self.probe_runner is not None:
            observed = await self.probe_runner.run(candidate, self)
            if (
                getattr(self.probe_runner, "trusted_runner_marker", None)
                is CLAUDE_PVD_RUNNER_MARKER
            ):
                return CapabilityProbeResult(evidence=observed.evidence)
            return CapabilityProbeResult(
                evidence=_fail_untrusted_probe(observed.evidence)
            )
        evidence = candidate.model_copy(
            update={
                "tests": tuple(
                    test.model_copy(
                        update={
                            "result": "FAIL",
                            "safe_summary": (
                                "Claude subscription probe runner is not configured"
                            ),
                        }
                    )
                    for test in candidate.tests
                )
            }
        )
        return CapabilityProbeResult(evidence=evidence)

    async def invoke(self, request: LLMInvocationRequest) -> LLMInvocationResult:
        cancel_event = asyncio.Event()
        async with self._active_lock:
            if request.llm_call_id in self._active:
                return self._failed_before_call(request)
            current = asyncio.create_task(self._invoke_active(request, cancel_event))
            self._active[request.llm_call_id] = current
            self._cancel_events[request.llm_call_id] = cancel_event
        try:
            return await current
        finally:
            async with self._active_lock:
                if self._active.get(request.llm_call_id) is current:
                    del self._active[request.llm_call_id]
                    self._cancel_events.pop(request.llm_call_id, None)

    async def _invoke_active(
        self,
        request: LLMInvocationRequest,
        cancel_event: asyncio.Event,
    ) -> LLMInvocationResult:
        started_at = self.clock.now()
        started_ms = self.clock.monotonic_ms()
        work_task = asyncio.create_task(
            self._invoke_once(
                request,
                started_at=started_at,
                started_ms=started_ms,
                cancel_event=cancel_event,
            )
        )
        try:
            done, _pending = await asyncio.wait(
                (work_task,), timeout=request.timeout_ms / 1_000
            )
            if done:
                try:
                    return await work_task
                except _ProcessTreeTerminationError:
                    normalized = claude_failure("FAILED")
            else:
                cleanup_error = await _cancel_and_wait(work_task)
                normalized = claude_failure(
                    "FAILED" if cleanup_error is not None else "TIMED_OUT"
                )
        except asyncio.CancelledError:
            cleanup_error = await _cancel_and_wait(work_task)
            normalized = claude_failure(
                "FAILED" if cleanup_error is not None else "CANCELLED"
            )
        return self._build_checked(
            request,
            self._failure_outcome(
                request,
                normalized,
                started_at=started_at,
                started_ms=started_ms,
            ),
        )

    async def _invoke_once(
        self,
        request: LLMInvocationRequest,
        *,
        started_at: datetime,
        started_ms: int,
        cancel_event: asyncio.Event,
    ) -> LLMInvocationResult:
        try:
            resolved, schema = await self._prepare(request)
            async with _claude_process_lock():
                process_result = await self.process_runner.execute(
                    CodexProcessRequest(
                        invocation_id=request.llm_call_id,
                        provider_profile_ref=request.provider_profile_ref,
                        model=request.model,
                        prompt=resolved.rendered_prompt_bytes,
                        output_schema=resolved.output_schema_bytes,
                        timeout_ms=request.timeout_ms,
                    )
                )
            if process_result.status != "SUCCEEDED":
                outcome = self._failure_outcome(
                    request,
                    claude_failure(process_result.status),
                    started_at=started_at,
                    started_ms=started_ms,
                )
            else:
                outcome = await self._success_outcome(
                    request,
                    process_result,
                    resolved=resolved,
                    schema=schema,
                    started_at=started_at,
                    started_ms=started_ms,
                    cancel_event=cancel_event,
                )
        except asyncio.CancelledError:
            raise
        except _ProcessTreeTerminationError:
            raise
        except Exception as error:
            current_task = asyncio.current_task()
            if current_task is not None and current_task.cancelling():
                raise _ProcessTreeTerminationError from None
            outcome = self._failure_outcome(
                request,
                normalize_claude_exception(error),
                started_at=started_at,
                started_ms=started_ms,
            )
        return self._build_checked(request, outcome)

    async def _success_outcome(
        self,
        request: LLMInvocationRequest,
        process_result: CodexProcessResult,
        *,
        resolved: ResolvedPromptInput,
        schema: dict[str, JsonValue],
        started_at: datetime,
        started_ms: int,
        cancel_event: asyncio.Event,
    ) -> NormalizedProviderResult:
        final_message = process_result.final_message
        provider_session_id = process_result.provider_session_id
        if (
            not isinstance(final_message, bytes)
            or not isinstance(provider_session_id, str)
            or not provider_session_id.strip()
        ):
            raise ProviderInvalidOutputError
        provider_output = _strict_json(final_message, ProviderInvalidOutputError)
        parsed = _unwrap_claude_output(provider_output, schema)
        if not isinstance(parsed, (dict, list)):
            raise ProviderInvalidOutputError
        raw_output = canonical_bytes(parsed)
        try:
            validated_output = self.output_schema_validator.validate(
                raw_output,
                schema=schema,
                output_schema=resolved.output_schema,
                request=request,
            )
            validated_bytes = canonical_bytes(validated_output)
            poc_content_repair = (
                request.agent_role,
                request.task_kind,
            ) == ("DYNAMIC_REPRODUCTION", "CREATE_POC_CANDIDATE")
            if validated_bytes != raw_output and not poc_content_repair:
                raise ProviderInvalidOutputError
            if poc_content_repair:
                raw_output = validated_bytes
                parsed = validated_output
        except ProviderInvalidOutputError:
            raise
        except Exception as error:
            raise ProviderInvalidOutputError from error
        self._raise_if_cancel_requested(cancel_event)
        session_ref = await self.session_store.register_response(
            provider_session_id, request.llm_call_id
        )
        self._raise_if_cancel_requested(cancel_event)
        if not session_ref.strip():
            raise ProviderInvalidOutputError
        return NormalizedProviderResult(
            status="SUCCEEDED",
            provider="ANTHROPIC",
            model=request.model,
            actual_session_mode="NEW",
            session_ref=session_ref,
            response_text=raw_output.decode("utf-8"),
            parsed_output=parsed,
            validated_output=validated_output,
            usage=None,
            started_at=started_at,
            finished_at=self.clock.now(),
            elapsed_ms=max(0, self.clock.monotonic_ms() - started_ms),
            safe_error=None,
        )

    async def _prepare(
        self, request: LLMInvocationRequest
    ) -> tuple[ResolvedPromptInput, dict[str, JsonValue]]:
        if (
            request.provider_profile_ref != self.provider_profile_ref
            or request.model != self.model
            or request.session_policy != "NEW"
            or request.parent_session_ref is not None
        ):
            raise ProviderInputMismatchError
        resolved = await self.prompt_resolver.resolve(request)
        try:
            payload_ref = reference(resolved.payload)
            output_schema_ref = reference(resolved.output_schema)
        except (TypeError, ValueError) as error:
            raise ProviderInputMismatchError from error
        payload = resolved.payload
        if (
            not isinstance(payload_ref, StoredDataRef)
            or payload_ref != request.prompt_payload_ref
            or not isinstance(output_schema_ref, StoredDataRef)
            or output_schema_ref != request.output_schema_ref
            or payload.registry_entry_ref != request.prompt_registry_entry_ref
            or payload.prompt_key != request.prompt_key
            or payload.agent_role != request.agent_role
            or payload.task_kind != request.task_kind
            or payload.purpose != request.purpose
            or payload.template_ref != request.prompt_template_ref
            or payload.template_version != request.prompt_template_version
            or payload.output_schema_ref != request.output_schema_ref
            or tuple(binding.source_ref for binding in payload.context_bindings)
            != request.context_refs
            or request.output_schema_ref.data_kind != "output_schema_spec"
            or any(
                getattr(payload.meta, field) != getattr(request.meta, field)
                for field in (
                    "analysis_id",
                    "workspace_id",
                    "commit_id",
                    "hypothesis_id",
                    "attempt_id",
                )
            )
        ):
            raise ProviderInputMismatchError
        if (
            _sha256(resolved.template_bytes) != payload.template_ref.content_hash
            or _sha256(resolved.output_schema_bytes)
            != resolved.output_schema.schema_artifact_ref.content_hash
            or _sha256(resolved.rendered_prompt_bytes)
            != payload.rendered_prompt_ref.content_hash
        ):
            raise ProviderInputMismatchError
        if len(resolved.projected_contexts) != len(payload.context_bindings):
            raise ProviderInputMismatchError
        rendered_bindings: list[dict[str, JsonValue]] = []
        for binding, context in zip(
            payload.context_bindings, resolved.projected_contexts, strict=True
        ):
            if (
                binding.trust_class != "UNTRUSTED_DATA"
                or context.slot != binding.slot
                or context.projected_data_ref != binding.projected_data_ref
                or _sha256(context.data) != binding.projected_data_ref.content_hash
            ):
                raise ProviderInputMismatchError
            value = _strict_json(context.data, ProviderInputMismatchError)
            if canonical_bytes(value) != context.data:
                raise ProviderInputMismatchError
            rendered_bindings.append(
                cast(
                    dict[str, JsonValue],
                    {
                        "slot": binding.slot,
                        "trust_class": "UNTRUSTED_DATA",
                        "sha256": _sha256(context.data),
                        "data": value,
                    },
                )
            )
        data_section = canonical_bytes({"bindings": rendered_bindings})
        data_section = data_section.replace(b"<", b"\\u003c").replace(b">", b"\\u003e")
        expected_rendered = (
            resolved.template_bytes
            + b"\n<UNTRUSTED_DATA>\n"
            + data_section
            + b"\n</UNTRUSTED_DATA>\n"
        )
        schema = _strict_json(resolved.output_schema_bytes, ProviderInputMismatchError)
        if (
            expected_rendered != resolved.rendered_prompt_bytes
            or not isinstance(schema, dict)
            or canonical_bytes(schema) != resolved.output_schema_bytes
            or request.output_schema.encode("utf-8") != resolved.output_schema_bytes
            or not resolved.template_bytes.strip()
        ):
            raise ProviderInputMismatchError
        return resolved, schema

    def _failure_outcome(
        self,
        request: LLMInvocationRequest,
        normalized: NormalizedFailure,
        *,
        started_at: datetime,
        started_ms: int,
    ) -> NormalizedProviderResult:
        return NormalizedProviderResult(
            status=normalized.status,
            provider="ANTHROPIC",
            model=request.model,
            actual_session_mode="NEW",
            session_ref=None,
            response_text=None,
            parsed_output=None,
            validated_output=None,
            usage=None,
            started_at=started_at,
            finished_at=self.clock.now(),
            elapsed_ms=max(0, self.clock.monotonic_ms() - started_ms),
            safe_error=normalized.safe_error,
        )

    def _failed_before_call(self, request: LLMInvocationRequest) -> LLMInvocationResult:
        now = self.clock.now()
        return self._build_checked(
            request,
            NormalizedProviderResult(
                status="FAILED",
                provider="ANTHROPIC",
                model=request.model,
                actual_session_mode="NEW",
                session_ref=None,
                response_text=None,
                parsed_output=None,
                validated_output=None,
                usage=None,
                started_at=now,
                finished_at=now,
                elapsed_ms=0,
                safe_error="FAILED: duplicate Claude Code invocation is active",
            ),
        )

    def _build_checked(
        self, request: LLMInvocationRequest, outcome: NormalizedProviderResult
    ) -> LLMInvocationResult:
        expected_success = outcome.status == "SUCCEEDED"
        if expected_success != (
            outcome.response_text is not None
            and outcome.parsed_output is not None
            and outcome.validated_output is not None
            and outcome.session_ref is not None
        ):
            raise ValueError("PROVIDER_RESULT_BUILDER_MISMATCH")
        result = LLMInvocationResult.model_validate(
            self.result_builder.build(request, outcome)
        )
        if (
            result.meta.record_type != "llm_invocation_result"
            or any(
                getattr(result.meta, field) != getattr(request.meta, field)
                for field in (
                    "analysis_id",
                    "workspace_id",
                    "commit_id",
                    "hypothesis_id",
                    "attempt_id",
                )
            )
            or result.llm_call_id != request.llm_call_id
            or result.purpose != request.purpose
            or result.status != outcome.status
            or result.provider != "ANTHROPIC"
            or result.model != request.model
            or result.actual_session_mode != "NEW"
            or result.session_ref != outcome.session_ref
            or result.usage != outcome.usage
            or result.started_at != outcome.started_at
            or result.finished_at != outcome.finished_at
            or result.elapsed_ms != outcome.elapsed_ms
            or result.safe_error != outcome.safe_error
            or (result.response_ref is not None) != expected_success
            or (result.parsed_output_ref is not None) != expected_success
            or (
                expected_success
                and not _is_exact_output_artifact(
                    result.parsed_output_ref,
                    canonical_bytes(outcome.validated_output),
                    request,
                )
            )
        ):
            raise ValueError("PROVIDER_RESULT_BUILDER_MISMATCH")
        return result

    async def cancel(self, invocation_id: str) -> CancellationResult:
        async with self._active_lock:
            task = self._active.get(invocation_id)
            cancel_event = self._cancel_events.get(invocation_id)
        if task is None:
            return CancellationResult(False, "No matching active invocation")
        if task is asyncio.current_task():
            return CancellationResult(False, "Invocation cannot cancel itself")
        if cancel_event is not None:
            cancel_event.set()
        task.cancel()
        result = await asyncio.shield(task)
        cancelled = result.status == "CANCELLED"
        return CancellationResult(
            cancelled,
            None if cancelled else "Invocation cancellation was not confirmed",
        )

    @staticmethod
    def _raise_if_cancel_requested(cancel_event: asyncio.Event) -> None:
        if cancel_event.is_set():
            raise asyncio.CancelledError


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fail_untrusted_probe(
    evidence: ProviderValidationEvidence,
) -> ProviderValidationEvidence:
    return evidence.model_copy(
        update={
            "tests": tuple(
                test.model_copy(
                    update={
                        "result": "FAIL",
                        "safe_summary": (
                            "Claude subscription probe runner is not the trusted runner"
                        ),
                    }
                )
                for test in evidence.tests
            )
        }
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1_048_576):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_execution_binding(binding: ApprovedClaudeExecutionBinding) -> None:
    try:
        profile = ProviderProfile.model_validate(binding.provider_profile)
        client = ClientExecutionProfile.model_validate(binding.client_execution_profile)
        profile_ref = reference(profile)
        client_ref = reference(client)
        validation = (
            None
            if binding.provider_validation_evidence is None
            else ProviderValidationEvidence.model_validate(
                binding.provider_validation_evidence
            )
        )
        canonical_home = binding.claude_config_dir.resolve(strict=True)
    except (OSError, TypeError, ValueError) as error:
        raise ValueError("CLAUDE_EXECUTION_BINDING_MISMATCH") from error
    if (
        not isinstance(profile_ref, StoredDataRef)
        or not isinstance(client_ref, StoredDataRef)
        or profile.provider != "ANTHROPIC"
        or profile.product != "CLAUDE_CODE"
        or profile.transport != "CLAUDE_CODE_CLIENT"
        or profile.auth_mode != "SUBSCRIPTION_LOGIN"
        or profile.credential_source != "OFFICIAL_CLIENT_SESSION"
        or profile.support_status not in {"EXPERIMENTAL", "SUPPORTED"}
        or profile.client_execution_profile_ref != client_ref
        or profile.validation_evidence_ref != client.verification_evidence_ref
        or profile.meta.analysis_id != client.meta.analysis_id
        or profile.meta.workspace_id != client.meta.workspace_id
        or profile.meta.commit_id != client.meta.commit_id
        or tuple(client.environment_variable_allowlist) != _CHILD_ENVIRONMENT_ALLOWLIST
        or binding.runtime_environment != profile.environment
        or not binding.claude_config_dir.is_absolute()
        or binding.claude_config_dir.is_symlink()
        or canonical_home != binding.claude_config_dir
    ):
        raise ValueError("CLAUDE_EXECUTION_BINDING_MISMATCH")
    if profile.support_status == "SUPPORTED":
        required_tests = {f"PVD-{index:02d}" for index in range(1, 16)}
        if validation is None:
            raise ValueError("CLAUDE_EXECUTION_BINDING_MISMATCH")
        validation_ref = reference(validation)
        tests = {str(item.test_id): item for item in validation.tests}
        identity = (
            "profile_key",
            "provider",
            "product",
            "transport",
            "model",
            "environment",
            "auth_mode",
            "client_name",
            "client_version",
        )
        if (
            not isinstance(validation_ref, StoredDataRef)
            or validation_ref != profile.validation_evidence_ref
            or validation_ref != client.verification_evidence_ref
            or any(
                getattr(validation, field) != getattr(profile, field)
                for field in identity
            )
            or set(tests) not in (required_tests, required_tests | {"PVD-16"})
            or len(tests) != len(validation.tests)
            or any(
                item.result != "PASS" or not item.evidence_refs
                for item in tests.values()
            )
        ):
            raise ValueError("CLAUDE_EXECUTION_BINDING_MISMATCH")
    elif binding.provider_validation_evidence is not None:
        raise ValueError("CLAUDE_EXECUTION_BINDING_MISMATCH")


def _require_claude_cli_version(result: _ChildResult, expected: str) -> None:
    try:
        lines = result.stdout.decode("utf-8").splitlines()
    except UnicodeError:
        raise ProviderExecutableBindingError from None
    if result.returncode != 0 or lines != [f"{expected} (Claude Code)"]:
        raise ProviderExecutableBindingError


def _is_exact_subscription_login(result: _ChildResult) -> bool:
    """Accept only an official subscription login, never an API credential.

    ``claude auth status --json`` also reports the operator's email, organization
    and organization name.  Those are read past but never returned, logged or
    stored.
    """
    if len(result.stdout) > _MAX_AUTH_STATUS_BYTES:
        return False
    try:
        payload = _strict_json(result.stdout, ProviderInvalidOutputError)
    except ProviderInvalidOutputError:
        return False
    if not isinstance(payload, dict):
        return False
    subscription = payload.get("subscriptionType")
    return (
        payload.get("loggedIn") is True
        and payload.get("authMethod") == _SUBSCRIPTION_AUTH_METHOD
        and payload.get("apiProvider") == _FIRST_PARTY_API_PROVIDER
        and "apiKeySource" not in payload
        and isinstance(subscription, str)
        and bool(subscription.strip())
    )


def _validate_process_request(
    request: CodexProcessRequest, *, require_prompt: bool = True
) -> None:
    if (
        not request.invocation_id.strip()
        or not isinstance(request.provider_profile_ref, StoredDataRef)
        or not request.model.strip()
        or request.model.startswith("-")
        or any(
            not character.isascii() or not (character.isalnum() or character in "-._:/")
            for character in request.model
        )
        or request.timeout_ms <= 0
        or (require_prompt and not request.prompt)
        or not request.output_schema
    ):
        raise ProviderInputMismatchError


def _windows_creation_flags() -> int:
    if os.name != "nt":
        return 0
    return cast(int, vars(subprocess)["CREATE_NEW_PROCESS_GROUP"]) | cast(
        int, vars(subprocess)["CREATE_NO_WINDOW"]
    )


def _windows_no_window_flag() -> int:
    if os.name != "nt":
        return 0
    return cast(int, vars(subprocess)["CREATE_NO_WINDOW"])


async def _write_stdin(process: asyncio.subprocess.Process, data: bytes) -> None:
    writer = process.stdin
    if writer is None:
        raise RuntimeError("CLAUDE_STDIN_NOT_AVAILABLE")
    try:
        writer.write(data)
        await writer.drain()
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (BrokenPipeError, ConnectionResetError):
            pass


async def _drain_bounded(reader: asyncio.StreamReader, retain_limit: int) -> bytes:
    retained = bytearray()
    while chunk := await reader.read(65_536):
        remaining = retain_limit - len(retained)
        if remaining > 0:
            retained.extend(chunk[:remaining])
    return bytes(retained)


async def _terminate_process_tree(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    if os.name == "nt":
        tree_termination_confirmed = False
        windows_root = os.environ.get("SystemRoot", r"C:\Windows")
        taskkill = Path(windows_root) / "System32" / "taskkill.exe"
        killer: asyncio.subprocess.Process | None = None
        try:
            killer = await asyncio.create_subprocess_exec(
                str(taskkill),
                "/PID",
                str(process.pid),
                "/T",
                "/F",
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                creationflags=_windows_no_window_flag(),
            )
            tree_termination_confirmed = (
                await asyncio.wait_for(
                    asyncio.shield(killer.wait()),
                    timeout=_TREE_KILLER_TIMEOUT_SECONDS,
                )
                == 0
            )
        except (OSError, TimeoutError, asyncio.CancelledError):
            if killer is not None and killer.returncode is None:
                killer.kill()
                await asyncio.shield(killer.wait())
            tree_termination_confirmed = False
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        await asyncio.shield(process.wait())
        if not tree_termination_confirmed:
            raise _ProcessTreeTerminationError
        return
    else:
        kill_group = cast(
            Callable[[int, int], None],
            vars(os)["killpg"],
        )
        terminate_signal = int(signal.SIGTERM)
        kill_signal = int(vars(signal)["SIGKILL"])
        tree_termination_confirmed = True
        try:
            kill_group(process.pid, terminate_signal)
        except ProcessLookupError:
            pass
        except PermissionError:
            tree_termination_confirmed = False
        try:
            await asyncio.wait_for(asyncio.shield(process.wait()), timeout=0.25)
        except TimeoutError:
            try:
                kill_group(process.pid, kill_signal)
            except ProcessLookupError:
                pass
            except PermissionError:
                tree_termination_confirmed = False
    if process.returncode is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
    await asyncio.shield(process.wait())
    if not tree_termination_confirmed:
        raise _ProcessTreeTerminationError


def _require_isolated_init(
    event: dict[str, JsonValue], *, model: str, client_version: str
) -> None:
    """Fail closed unless the client reports the exact contracted isolation.

    The official client reports its own effective configuration before the first
    model request.  That report, not the argv alone, is the enforcement proof.
    """
    tools = event.get("tools")
    if (
        not isinstance(tools, list)
        # Passing an output schema registers the structured-output transport as a
        # tool.  It is this adapter's own answer channel, so it is the only name
        # that may ever appear; anything else is a tool the model could act with.
        or not set(tools) <= {_STRUCTURED_OUTPUT_TOOL}
        or event.get("mcp_servers") != []
        or event.get("plugins") != []
        or event.get("slash_commands") != []
        or event.get("skills") != []
        or event.get("apiKeySource") != _NO_API_KEY_SOURCE
        or event.get("permissionMode") != "dontAsk"
        or event.get("model") != model
        or event.get("claude_code_version") != client_version
        or event.get("agents") != list(_EXPECTED_AGENTS)
        or "memory_paths" in event
    ):
        raise ProviderInvalidOutputError


def _require_isolated_assistant(
    message: dict[str, JsonValue], *, model: str
) -> tuple[str, ...]:
    """Allow only the structured-output transport and report refusable requests.

    A model may still *ask* for a tool this boundary never enabled.  Asking is
    not an escape - the client answers it with a refusal - so the request is
    returned for the caller to match against that refusal instead of failing
    the whole stream here.  A request the client did not refuse is an escape and
    the caller fails closed on it.
    """
    if message.get("model") not in (None, model):
        raise ProviderInvalidOutputError
    content = message.get("content")
    if not isinstance(content, list):
        raise ProviderInvalidOutputError
    requested: list[str] = []
    for block in content:
        if not isinstance(block, dict):
            raise ProviderInvalidOutputError
        kind = block.get("type")
        # Reasoning blocks are observed but never read or stored: only the
        # structured answer crosses this boundary.
        if kind in {"text", "thinking", "redacted_thinking"}:
            continue
        if kind == "tool_use":
            if block.get("name") == _STRUCTURED_OUTPUT_TOOL:
                continue
            identifier = block.get("id")
            if not isinstance(identifier, str) or not identifier.strip():
                raise ProviderInvalidOutputError
            requested.append(identifier)
            continue
        raise ProviderInvalidOutputError
    return tuple(requested)


def _refused_tool_ids(message: dict[str, JsonValue]) -> tuple[str, ...]:
    """Return the tool requests this turn answered with the unavailable error."""
    content = message.get("content")
    if not isinstance(content, list):
        raise ProviderInvalidOutputError
    refused: list[str] = []
    for block in content:
        if not isinstance(block, dict):
            raise ProviderInvalidOutputError
        if block.get("type") != "tool_result":
            continue
        # Only a refusal can clear a request, so only a refusal needs the id
        # that names which request it answers.
        if block.get("is_error") is not True:
            continue
        if _TOOL_UNAVAILABLE_MARKER not in str(block.get("content", "")):
            continue
        identifier = block.get("tool_use_id")
        if not isinstance(identifier, str) or not identifier.strip():
            raise ProviderInvalidOutputError
        refused.append(identifier)
    return tuple(refused)


def _is_client_error_notice(
    event: dict[str, JsonValue], message: dict[str, JsonValue]
) -> bool:
    """Say whether this assistant event is the client's own failure notice.

    Such a notice is built locally, so it names ``<synthetic>`` instead of the
    approved model and carries only the error text.  It is accepted - and
    ignored - so the terminal event can still be read; anything that also
    carries a tool request or a non-text block is not a notice and fails closed
    on the ordinary path.
    """
    error = event.get("error")
    if not isinstance(error, str) or not error.strip():
        return False
    if message.get("model") != _CLIENT_SYNTHETIC_MODEL:
        return False
    content = message.get("content")
    if not isinstance(content, list):
        return False
    return all(
        isinstance(block, dict) and block.get("type") == "text" for block in content
    )


def _window_reopens_at(event: dict[str, JsonValue]) -> int | None:
    """Return when the subscription window reopens, if this is that refusal.

    A momentary burst refusal carries no window; a five-hour one does, and a
    caller that cannot tell them apart spends three short retries on a wait
    that is hours long and then reports the stage blocked.
    """

    info = event.get("rate_limit_info")
    if not isinstance(info, dict) or info.get("status") != "rejected":
        return None
    resets_at = info.get("resetsAt")
    if not isinstance(resets_at, int) or isinstance(resets_at, bool):
        return None
    return resets_at if resets_at > 0 else None


def _validated_event_stream(
    event_stream: bytes, *, model: str, client_version: str
) -> tuple[
    Literal["SUCCEEDED", "AUTH_REQUIRED", "RATE_LIMITED", "FAILED"],
    bytes,
    str,
    int | None,
]:
    """Validate the exact official event lifecycle and extract the one answer.

    Every event is checked against an allowlist; an unknown event type, a second
    session, a forbidden tool or a truncated stream fails closed.
    """
    session_id: str | None = None
    reopens_at: int | None = None
    state: Literal["INIT", "TURN", "DONE"] = "INIT"
    structured: bytes | None = None
    status: Literal["SUCCEEDED", "AUTH_REQUIRED", "RATE_LIMITED", "FAILED"] = "FAILED"
    requested_tools: set[str] = set()
    refused_tools: set[str] = set()
    if not event_stream or len(event_stream) >= _MAX_EVENT_STREAM_BYTES:
        raise ProviderInvalidOutputError
    for line in event_stream.splitlines():
        if not line.strip():
            continue
        event = _strict_json(line, ProviderInvalidOutputError)
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            raise ProviderInvalidOutputError
        event_type = event["type"]
        observed = event.get("session_id")
        if isinstance(observed, str) and observed.strip():
            if session_id is not None and observed != session_id:
                raise ProviderInvalidOutputError
            session_id = observed
        if state == "INIT" and event_type == "system":
            if event.get("subtype") != "init":
                raise ProviderInvalidOutputError
            _require_isolated_init(event, model=model, client_version=client_version)
            state = "TURN"
        elif state == "TURN" and event_type == "system":
            # Progress and retry notices carry no instruction or tool semantics.
            # A second init, or any other system subtype, fails closed.
            if event.get("subtype") not in _INFORMATIONAL_SYSTEM_SUBTYPES:
                raise ProviderInvalidOutputError
        elif state == "TURN" and event_type == "rate_limit_event":
            reopens_at = reopens_at or _window_reopens_at(event)
            continue
        elif state == "TURN" and event_type == "assistant":
            message = event.get("message")
            if not isinstance(message, dict):
                raise ProviderInvalidOutputError
            if event.get("parent_tool_use_id") is not None:
                raise ProviderInvalidOutputError
            if _is_client_error_notice(event, message):
                # The client reports its own transport failures - a 429, for
                # one - as a locally built message rather than a model answer.
                # Rejecting it as a model reroute loses the terminal event that
                # names the real status, so it is observed and carries nothing.
                continue
            requested_tools.update(_require_isolated_assistant(message, model=model))
        elif state == "TURN" and event_type == "user":
            if event.get("parent_tool_use_id") is not None:
                raise ProviderInvalidOutputError
            reply = event.get("message")
            if not isinstance(reply, dict):
                raise ProviderInvalidOutputError
            refused_tools.update(_refused_tool_ids(reply))
        elif state == "TURN" and event_type == "result":
            status, structured = _result_outcome(event)
            state = "DONE"
        else:
            raise ProviderInvalidOutputError
    if state != "DONE" or session_id is None:
        raise ProviderInvalidOutputError
    # Every tool this boundary never enabled must have been declined by the
    # client.  One that ran instead means the isolation failed, so fail closed.
    if requested_tools - refused_tools:
        raise ProviderInvalidOutputError
    if status != "SUCCEEDED":
        return status, b"", session_id, reopens_at
    if structured is None:
        raise ProviderInvalidOutputError
    return status, structured, session_id, None


def _result_outcome(
    event: dict[str, JsonValue],
) -> tuple[
    Literal["SUCCEEDED", "AUTH_REQUIRED", "RATE_LIMITED", "FAILED"], bytes | None
]:
    """Map the terminal event to a common status without copying its text.

    A rate-limited run was measured exiting ``1`` and an ordinary refusal
    exiting ``0``, so the exit code says nothing about which failure happened;
    ``is_error`` and the structured HTTP status are what name it.
    """
    api_status = event.get("api_error_status")
    if event.get("is_error") is not False:
        if api_status == 401 or api_status == 403:
            return "AUTH_REQUIRED", None
        if api_status == 429:
            return "RATE_LIMITED", None
        # A 400 is deterministic (an over-long prompt cannot become acceptable on
        # a retry) but the common status set has no non-retryable request state,
        # so it stays FAILED rather than inventing one outside the contract.
        return "FAILED", None
    if event.get("permission_denials") != []:
        raise ProviderInvalidOutputError
    structured_output = event.get("structured_output")
    if not isinstance(structured_output, (dict, list)):
        raise ProviderInvalidOutputError
    return "SUCCEEDED", canonical_bytes(structured_output)


def _claude_output_schema(
    provider_neutral_schema: dict[str, JsonValue],
) -> dict[str, JsonValue]:
    """Adapt only array roots to the client's structured-output object transport."""
    if provider_neutral_schema.get("type") != "array":
        return provider_neutral_schema
    array_schema = dict(provider_neutral_schema)
    definitions = array_schema.pop("$defs", None)
    adapted: dict[str, JsonValue] = {
        "type": "object",
        "properties": {_ARRAY_ENVELOPE_KEY: cast(JsonValue, array_schema)},
        "required": [_ARRAY_ENVELOPE_KEY],
        "additionalProperties": False,
    }
    if definitions is not None:
        adapted["$defs"] = definitions
    return adapted


def _unwrap_claude_output(
    provider_output: JsonValue,
    provider_neutral_schema: dict[str, JsonValue],
) -> JsonValue:
    if provider_neutral_schema.get("type") != "array":
        return provider_output
    if (
        not isinstance(provider_output, dict)
        or set(provider_output) != {_ARRAY_ENVELOPE_KEY}
        or not isinstance(provider_output[_ARRAY_ENVELOPE_KEY], list)
    ):
        raise ProviderInvalidOutputError
    return provider_output[_ARRAY_ENVELOPE_KEY]


async def _cancel_and_wait(task: asyncio.Task[object]) -> BaseException | None:
    task.cancel()
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            continue
        except BaseException as error:
            return error
    try:
        task.result()
    except asyncio.CancelledError:
        return None
    except BaseException as error:
        return error
    return None


def _strict_json(data: bytes, error_type: type[RuntimeError]) -> JsonValue:
    def reject_duplicates(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
        output: dict[str, JsonValue] = {}
        for key, value in pairs:
            if key in output:
                raise ValueError("duplicate JSON member")
            output[key] = value
        return output

    def reject_constant(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    try:
        return cast(
            JsonValue,
            json.loads(
                data.decode("utf-8"),
                object_pairs_hook=reject_duplicates,
                parse_constant=reject_constant,
            ),
        )
    except (UnicodeError, TypeError, ValueError) as error:
        raise error_type from error


def _is_exact_output_artifact(
    ref: StoredDataRef | None,
    data: bytes,
    request: LLMInvocationRequest,
) -> bool:
    if ref is None:
        return False
    digest = _sha256(data)
    return (
        ref.record_id is None
        and ref.data_kind == "artifact"
        and str(ref.stored_data_id) == digest
        and ref.content_hash == digest
        and ref.workspace_id == request.meta.workspace_id
        and ref.commit_id == request.meta.commit_id
    )


__all__ = [
    "ApprovedClaudeExecutable",
    "ApprovedClaudeExecutionBinding",
    "ClaudeCliProcessRunner",
    "ClaudeSubscriptionAdapter",
    "ProviderExecutableBindingError",
]
