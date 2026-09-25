"""Isolated, subscription-only Claude Code CLI transport for SimpleRuntime."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import signal
import subprocess
import tempfile
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from typing import Any, Protocol, cast
from uuid import uuid4

from sastsimi.config.user_config import SimpleToolBinding
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .models import StageFailure
from .provider import SimpleLLMCallResult, _validate_schema
from .store import SimpleCheckpointStore

_VERIFIED_VERSION = "2.1.280"
_MAX_STREAM_BYTES = 4 * 1024 * 1024
_MAX_STDERR_BYTES = 65_536
_MODEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$")
_AUTH_METHOD = "claude.ai"
_SYSTEM_AGENTS = ["claude", "Explore", "general-purpose", "Plan"]
_LOG = logging.getLogger(__name__)


class ClaudeBoundaryError(RuntimeError):
    """CLI isolation, binding or event proof failed; never retry as a model call."""


class ClaudeTransportError(RuntimeError):
    def __init__(self, code: str, *, retryable: bool = False) -> None:
        super().__init__(code)
        self.code = code
        self.retryable = retryable


@dataclass(frozen=True)
class ClaudeCLIResponse:
    raw_output: bytes
    value: dict[str, Any]
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_minor_units: float | None = None


type ChildRunner = Callable[..., Awaitable[tuple[int, bytes, bytes]]]


class ClaudeTransport(Protocol):
    async def invoke(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        model: str,
        timeout: float,
    ) -> ClaudeCLIResponse: ...


def _strict_json(raw: bytes) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        output: dict[str, Any] = {}
        for key, value in pairs:
            if key in output:
                raise ValueError("duplicate JSON member")
            output[key] = value
        return output

    def non_finite(_value: str) -> None:
        raise ValueError("non-finite JSON number")

    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=unique,
        parse_constant=non_finite,
    )


def _subscription_status(raw: bytes) -> bool:
    if len(raw) > _MAX_STDERR_BYTES:
        return False
    try:
        value = _strict_json(raw)
    except (UnicodeError, ValueError):
        return False
    return (
        isinstance(value, dict)
        and value.get("loggedIn") is True
        and value.get("authMethod") == _AUTH_METHOD
        and value.get("apiProvider") == "firstParty"
        and "apiKeySource" not in value
        and isinstance(value.get("subscriptionType"), str)
        and bool(value["subscriptionType"].strip())
    )


def _child_environment(config_dir: Path, source: Mapping[str, str]) -> dict[str, str]:
    source_upper = {key.upper(): value for key, value in source.items()}
    result = {"CLAUDE_CONFIG_DIR": str(config_dir)}
    for name in ("SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP"):
        value = source_upper.get(name)
        if value:
            result[name] = value
    result.update(
        {
            "CLAUDE_CODE_DISABLE_BUNDLED_SKILLS": "1",
            "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1",
            "CLAUDE_CODE_DISABLE_CLAUDE_MDS": "1",
            "CLAUDE_CODE_DISABLE_WORKFLOWS": "1",
            "CLAUDE_CODE_MANAGED_SETTINGS_PATH": os.devnull,
            "DISABLE_AUTOUPDATER": "1",
            "CLAUDE_CODE_PACKAGE_MANAGER_AUTO_UPDATE": "0",
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "DISABLE_TELEMETRY": "1",
            "DISABLE_ERROR_REPORTING": "1",
        }
    )
    return result


def _parse_stream(raw: bytes, model: str) -> ClaudeCLIResponse:
    if not raw or len(raw) >= _MAX_STREAM_BYTES:
        raise ClaudeBoundaryError("CLAUDE_STREAM_INVALID")
    state = "INIT"
    session: str | None = None
    result: dict[str, Any] | None = None
    usage: dict[str, Any] = {}
    total_cost_usd: int | float | None = None
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            event = _strict_json(line)
        except (UnicodeError, ValueError) as error:
            raise ClaudeBoundaryError("CLAUDE_STREAM_INVALID") from error
        if not isinstance(event, dict):
            raise ClaudeBoundaryError("CLAUDE_STREAM_INVALID")
        event_session = event.get("session_id")
        if isinstance(event_session, str) and event_session:
            if session is None:
                session = event_session
            elif session != event_session:
                raise ClaudeBoundaryError("CLAUDE_STREAM_INVALID")
        kind = event.get("type")
        if state == "INIT" and kind == "system" and event.get("subtype") == "init":
            if (
                event.get("tools") not in ([], ["StructuredOutput"])
                or event.get("mcp_servers") != []
                or event.get("plugins") != []
                or event.get("slash_commands") != []
                or event.get("skills") != []
                or event.get("apiKeySource") != "none"
                or event.get("permissionMode") != "dontAsk"
                or event.get("model") != model
                or event.get("claude_code_version") != _VERIFIED_VERSION
                or event.get("agents") != _SYSTEM_AGENTS
                or "memory_paths" in event
            ):
                raise ClaudeBoundaryError("CLAUDE_ISOLATION_FAILED")
            state = "TURN"
        elif (
            state == "TURN"
            and kind == "system"
            and event.get("subtype") in {"thinking_tokens", "api_retry"}
        ):
            continue
        elif state == "TURN" and kind == "rate_limit_event":
            continue
        elif state == "TURN" and kind == "assistant":
            message = event.get("message")
            if (
                not isinstance(message, dict)
                or event.get("parent_tool_use_id") is not None
            ):
                raise ClaudeBoundaryError("CLAUDE_STREAM_INVALID")
            if message.get("model") not in (None, model, "<synthetic>"):
                raise ClaudeBoundaryError("CLAUDE_MODEL_MISMATCH")
            if message.get("model") == "<synthetic>" and not (
                isinstance(event.get("error"), str) and event["error"].strip()
            ):
                raise ClaudeBoundaryError("CLAUDE_MODEL_MISMATCH")
            content = message.get("content")
            if not isinstance(content, list):
                raise ClaudeBoundaryError("CLAUDE_STREAM_INVALID")
            for block in content:
                if not isinstance(block, dict) or block.get("type") not in {
                    "text",
                    "thinking",
                    "redacted_thinking",
                    "tool_use",
                }:
                    raise ClaudeBoundaryError("CLAUDE_STREAM_INVALID")
                if (
                    block.get("type") == "tool_use"
                    and block.get("name") != "StructuredOutput"
                ):
                    raise ClaudeBoundaryError("CLAUDE_TOOL_FORBIDDEN")
                if (
                    message.get("model") == "<synthetic>"
                    and block.get("type") != "text"
                ):
                    raise ClaudeBoundaryError("CLAUDE_TOOL_FORBIDDEN")
        elif state == "TURN" and kind == "result":
            if event.get("is_error") is not False:
                status = event.get("api_error_status")
                if status in (401, 403):
                    raise ClaudeTransportError("CLAUDE_AUTH_REQUIRED")
                if status == 429:
                    raise ClaudeTransportError("CLAUDE_RATE_LIMITED", retryable=True)
                raise ClaudeTransportError(
                    "CLAUDE_EXECUTION_FAILED", retryable=status in (500, 502, 503, 504)
                )
            if event.get("permission_denials") != []:
                raise ClaudeBoundaryError("CLAUDE_TOOL_FORBIDDEN")
            value = event.get("structured_output")
            if not isinstance(value, dict):
                raise ClaudeBoundaryError("CLAUDE_OUTPUT_INVALID")
            result = value
            usage_value = event.get("usage")
            if isinstance(usage_value, dict):
                usage = usage_value
            reported_cost = event.get("total_cost_usd")
            if (
                isinstance(reported_cost, (int, float))
                and not isinstance(reported_cost, bool)
                and reported_cost >= 0
            ):
                total_cost_usd = reported_cost
            state = "DONE"
        else:
            raise ClaudeBoundaryError("CLAUDE_STREAM_INVALID")
    if state != "DONE" or result is None or session is None:
        raise ClaudeBoundaryError("CLAUDE_STREAM_INVALID")

    def token(name: str) -> int | None:
        value = usage.get(name)
        return (
            value
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0
            else None
        )

    return ClaudeCLIResponse(
        raw_output=raw,
        value=result,
        input_tokens=token("input_tokens"),
        output_tokens=token("output_tokens"),
        cost_minor_units=(
            float(total_cost_usd) * 100 if total_cost_usd is not None else None
        ),
    )


async def _read_limited(reader: asyncio.StreamReader, limit: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while chunk := await reader.read(65_536):
        size += len(chunk)
        if size > limit:
            raise ClaudeBoundaryError("CLAUDE_OUTPUT_TOO_LARGE")
        chunks.append(chunk)
    return b"".join(chunks)


async def _terminate_process_tree(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    if os.name == "nt" and process.pid is not None:
        flags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            killer = await asyncio.create_subprocess_exec(
                "taskkill",
                "/PID",
                str(process.pid),
                "/T",
                "/F",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
                creationflags=flags,
            )
            await asyncio.wait_for(killer.wait(), timeout=5)
        except (OSError, TimeoutError):
            process.kill()
    elif process.pid is not None:
        try:
            vars(os)["killpg"](process.pid, vars(signal)["SIGKILL"])
        except ProcessLookupError:
            pass
    else:
        process.kill()
    try:
        await asyncio.wait_for(process.wait(), timeout=5)
    except TimeoutError as error:
        raise ClaudeBoundaryError("CLAUDE_PROCESS_TERMINATION_FAILED") from error


async def _run_child(
    argv: tuple[str, ...],
    *,
    stdin: bytes | None,
    cwd: Path,
    env: Mapping[str, str],
    timeout: float,
) -> tuple[int, bytes, bytes]:
    flags = (
        int(getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
        | int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if os.name == "nt"
        else 0
    )
    spawn = asyncio.create_task(
        asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE
            if stdin is not None
            else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(cwd),
            env=dict(env),
            creationflags=flags,
            start_new_session=os.name != "nt",
        )
    )
    try:
        process = await asyncio.shield(spawn)
    except asyncio.CancelledError:
        process = await asyncio.shield(spawn)
        await _terminate_process_tree(process)
        raise
    assert process.stdout is not None and process.stderr is not None
    stdout_reader = process.stdout
    stderr_reader = process.stderr

    async def collect() -> tuple[int, bytes, bytes]:
        stdout_task = asyncio.create_task(
            _read_limited(stdout_reader, _MAX_STREAM_BYTES)
        )
        stderr_task = asyncio.create_task(
            _read_limited(stderr_reader, _MAX_STDERR_BYTES)
        )
        try:
            if stdin is not None and process.stdin is not None:
                process.stdin.write(stdin)
                await process.stdin.drain()
                process.stdin.close()
            code = await process.wait()
            return code, await stdout_task, await stderr_task
        finally:
            for task in (stdout_task, stderr_task):
                if not task.done():
                    task.cancel()

    try:
        return await asyncio.wait_for(collect(), timeout=timeout)
    except (TimeoutError, asyncio.CancelledError, ClaudeBoundaryError):
        await _terminate_process_tree(process)
        raise


class OfficialClaudeCLITransport:
    """Pin one native CLI binary and prove no-tools subscription mode per call."""

    def __init__(
        self,
        binding: SimpleToolBinding,
        config_dir: Path,
        *,
        runner: ChildRunner | None = None,
    ) -> None:
        self._binding = binding
        self._config_dir = config_dir
        self._runner = runner or _run_child

    def _verify_binding(self) -> None:
        path = self._binding.executable_path
        if self._binding.version != _VERIFIED_VERSION:
            raise ClaudeBoundaryError("CLAUDE_CLI_UNSUPPORTED_VERSION")
        try:
            if path.is_symlink() or not path.is_file():
                raise ClaudeBoundaryError("CLAUDE_CLI_BINDING_CHANGED")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as error:
            raise ClaudeBoundaryError("CLAUDE_CLI_BINDING_CHANGED") from error
        if digest != self._binding.executable_sha256:
            raise ClaudeBoundaryError("CLAUDE_CLI_BINDING_CHANGED")

    async def invoke(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        model: str,
        timeout: float,
    ) -> ClaudeCLIResponse:
        if not prompt or not _MODEL.fullmatch(model) or timeout <= 0:
            raise ClaudeBoundaryError("CLAUDE_REQUEST_INVALID")
        self._verify_binding()
        env = _child_environment(self._config_dir, os.environ)
        executable = str(self._binding.executable_path)
        with tempfile.TemporaryDirectory(prefix="sastsimi-claude-") as temporary:
            cwd = Path(temporary)
            version_code, version_raw, _ = await self._runner(
                (executable, "--version"),
                stdin=None,
                cwd=cwd,
                env=env,
                timeout=min(timeout, 15),
            )
            if version_code != 0 or version_raw.splitlines() != [
                b"2.1.280 (Claude Code)"
            ]:
                raise ClaudeBoundaryError("CLAUDE_CLI_UNSUPPORTED_VERSION")
            self._verify_binding()
            auth_code, auth_raw, _ = await self._runner(
                (executable, "auth", "status", "--json"),
                stdin=None,
                cwd=cwd,
                env=env,
                timeout=min(timeout, 15),
            )
            if auth_code != 0 or not _subscription_status(auth_raw):
                raise ClaudeTransportError("CLAUDE_AUTH_REQUIRED")
            self._verify_binding()
            argv = (
                executable,
                "-p",
                "--model",
                model,
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
                canonical_bytes(output_schema).decode("utf-8"),
            )
            code, raw, _ = await self._runner(
                argv,
                stdin=prompt,
                cwd=cwd,
                env=env,
                timeout=timeout,
            )
            response = _parse_stream(raw, model)
            if code != 0:
                raise ClaudeTransportError("CLAUDE_EXECUTION_FAILED", retryable=True)
            return response


class ClaudeProvider:
    """The unchanged SimpleLLMClient contract backed by the isolated CLI."""

    def __init__(
        self,
        *,
        artifacts: SimpleArtifactRepository,
        default_model: str,
        agent_models: Mapping[str, str],
        timeout_seconds: int,
        max_retries: int,
        semaphore: asyncio.Semaphore,
        transport: ClaudeTransport,
    ) -> None:
        self._artifacts = artifacts
        self._default_model = default_model
        self._agent_models = dict(agent_models)
        self._timeout_seconds = timeout_seconds
        self._max_retries = max_retries
        self._semaphore = semaphore
        self._transport = transport
        self._attempt_store = SimpleCheckpointStore(artifacts.paths.database)

    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
        agent_name: str = "agent",
    ) -> SimpleLLMCallResult | StageFailure:
        model = self._agent_models.get(agent_name, self._default_model)
        timeout = min(self._timeout_seconds, max(1, timeout_ms) / 1000)
        digest = hashlib.sha256(prompt).hexdigest()
        schema_text = canonical_bytes(output_schema).decode("utf-8")
        correction = b""
        last_failure = StageFailure(
            code="CLAUDE_EXECUTION_FAILED",
            retryable=False,
            safe_message="Claude call did not complete",
        )
        async with self._semaphore:
            for attempt in range(1, self._max_retries + 2):
                started_at = datetime.now(UTC)
                started = monotonic()
                raw_ref: StoredDataRef | None = None
                parsed_ref: StoredDataRef | None = None
                usage: dict[str, int | float | None] = {}
                code = "SUCCEEDED"
                retryable = False
                try:
                    response = await asyncio.wait_for(
                        self._transport.invoke(
                            prompt=prompt + correction,
                            output_schema=output_schema,
                            model=model,
                            timeout=timeout,
                        ),
                        timeout=timeout,
                    )
                    raw_ref = self._artifacts.put_bytes(
                        response.raw_output, "application/x-ndjson"
                    )
                    usage = {
                        "input_tokens": response.input_tokens,
                        "output_tokens": response.output_tokens,
                        "cost_minor_units": response.cost_minor_units,
                    }
                    if not isinstance(response.value, dict):
                        raise ValueError("$: expected object")
                    _validate_schema(response.value, output_schema)
                    canonical = canonical_bytes(response.value)
                    parsed_ref = self._artifacts.put_bytes(
                        canonical, "application/json"
                    )
                    self._record_attempt(
                        agent_name,
                        model,
                        attempt,
                        started,
                        code,
                        raw_ref,
                        parsed_ref,
                        usage,
                    )
                    return SimpleLLMCallResult(
                        value=response.value,
                        prompt_digest=digest,
                        output_digest=hashlib.sha256(canonical).hexdigest(),
                        invocation_id=f"claude-{uuid4().hex}",
                        provider="claude-cli",
                        model=model,
                        started_at=started_at,
                        finished_at=datetime.now(UTC),
                        elapsed_ms=max(0, int((monotonic() - started) * 1000)),
                        raw_output_ref=raw_ref,
                        parsed_output_ref=parsed_ref,
                        input_tokens=response.input_tokens,
                        output_tokens=response.output_tokens,
                        cost_minor_units=response.cost_minor_units,
                        on_demand_possible=True,
                    )
                except asyncio.CancelledError:
                    raise
                except (ValueError, TypeError) as error:
                    code = "CLAUDE_INVALID_OUTPUT"
                    detail = str(error).splitlines()[0][:200]
                    correction = (
                        "\nThe previous JSON failed validation at "
                        + detail
                        + ". Return exactly one corrected JSON object "
                        + "matching this schema:\n"
                        + schema_text
                    ).encode("utf-8")
                    retryable = True
                    last_failure = StageFailure(
                        code=code,
                        retryable=False,
                        safe_message="Claude returned invalid structured output",
                        invalid_field=detail if detail.startswith("$") else None,
                    )
                except ClaudeBoundaryError as error:
                    code = str(error)
                    last_failure = StageFailure(
                        code=code,
                        retryable=False,
                        safe_message="Claude CLI security boundary failed",
                    )
                except ClaudeTransportError as error:
                    code = error.code
                    retryable = error.retryable
                    last_failure = StageFailure(
                        code=code,
                        retryable=retryable,
                        safe_message="Claude CLI call did not complete",
                    )
                except TimeoutError:
                    code = "CLAUDE_TIMED_OUT"
                    retryable = True
                    last_failure = StageFailure(
                        code=code,
                        retryable=True,
                        safe_message="Claude CLI request timed out",
                    )
                self._record_attempt(
                    agent_name,
                    model,
                    attempt,
                    started,
                    code,
                    raw_ref,
                    parsed_ref,
                    usage,
                )
                if not retryable or attempt > self._max_retries:
                    break
                await asyncio.sleep(min(8.0, 0.5 * 2 ** (attempt - 1)))
        return last_failure

    def _record_attempt(
        self,
        agent: str,
        model: str,
        attempt: int,
        started: float,
        status: str,
        raw_ref: StoredDataRef | None,
        parsed_ref: StoredDataRef | None,
        usage: Mapping[str, int | float | None],
    ) -> None:
        elapsed = max(0, int((monotonic() - started) * 1000))
        _LOG.info(
            "claude_call analysis_id=%s agent=%s model=%s "
            "attempt=%d elapsed_ms=%d status=%s",
            self._artifacts.identity.analysis_id,
            agent,
            model,
            attempt,
            elapsed,
            status,
        )
        artifact_ref = self._artifacts.put_json(
            {
                "kind": "claude_agent_attempt",
                "analysis_id": self._artifacts.identity.analysis_id,
                "agent": agent,
                "model": model,
                "attempt": attempt,
                "elapsed_ms": elapsed,
                "status": status,
                "raw_output_ref": raw_ref.model_dump(mode="json") if raw_ref else None,
                "parsed_output_ref": parsed_ref.model_dump(mode="json")
                if parsed_ref
                else None,
                "usage": dict(usage),
                "on_demand_possible": True,
            }
        )
        self._attempt_store.record_llm_attempt(
            attempt_id=uuid4().hex,
            analysis_id=self._artifacts.identity.analysis_id,
            agent=agent,
            model=model,
            attempt_number=attempt,
            status=status,
            elapsed_ms=elapsed,
            input_tokens=cast(int | None, usage.get("input_tokens")),
            output_tokens=cast(int | None, usage.get("output_tokens")),
            cost_cents=cast(float | None, usage.get("cost_minor_units")),
            artifact_ref=artifact_ref,
        )


__all__ = [
    "ClaudeBoundaryError",
    "ClaudeCLIResponse",
    "ClaudeProvider",
    "ClaudeTransportError",
    "OfficialClaudeCLITransport",
]
