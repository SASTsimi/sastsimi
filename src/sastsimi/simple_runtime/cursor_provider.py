"""Cursor Agent SDK boundary for schema-constrained, text-only analysis calls.

The SDK is an agent API, not a JSON completion API.  This module therefore
validates every response locally and never treats malformed output as evidence.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import random
import re
import subprocess
import tempfile
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from time import monotonic
from typing import Any, Protocol
from uuid import uuid4

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef

from .artifacts import SimpleArtifactRepository
from .models import StageFailure
from .provider import (
    SimpleLLMCallResult,
    SimpleLLMClient,
    _validate_schema,
)
from .store import SimpleCheckpointStore

_LOG = logging.getLogger(__name__)
_MAX_RAW_BYTES = 512 * 1024


class CursorTransport(Protocol):
    async def list_models(self, api_key: str) -> set[str]: ...

    async def complete(
        self, *, api_key: str, model: str, prompt: str, timeout: float
    ) -> tuple[str, dict[str, int | float | None]]: ...


class OfficialCursorTransport:
    """One SDK bridge per request so cancellation always tears down the child."""

    def __init__(self, workspace: str) -> None:
        self._workspace = workspace

    async def list_models(self, api_key: str) -> set[str]:
        from cursor_sdk import AsyncClient, AsyncCursor

        async with await AsyncClient.launch_bridge(
            workspace=self._workspace, client_timeout=30, max_retries=0
        ) as client:
            models = await AsyncCursor.models.list(client=client, api_key=api_key)
            return {item.id for item in models}

    async def complete(
        self, *, api_key: str, model: str, prompt: str, timeout: float
    ) -> tuple[str, dict[str, int | float | None]]:
        from cursor_sdk import AgentOptions, AsyncClient, LocalAgentOptions

        agent = None
        run = None
        async with await AsyncClient.launch_bridge(
            workspace=self._workspace,
            client_timeout=timeout,
            max_retries=0,
        ) as client:
            try:
                agent = await client.agents.create(
                    AgentOptions(
                        model=model,
                        api_key=api_key,
                        tools=[],
                        local=LocalAgentOptions(
                            cwd=self._workspace, setting_sources=[]
                        ),
                    )
                )
                run = await agent.send(prompt)
                result = await run.wait()
                if str(result.status).lower() != "finished":
                    raise RuntimeError("CURSOR_RUN_UNSUCCESSFUL")
                usage = result.usage
                metrics: dict[str, int | float | None] = {
                    "input_tokens": getattr(usage, "input_tokens", None),
                    "output_tokens": getattr(usage, "output_tokens", None),
                    "cost_minor_units": None,
                }
                try:
                    settled = await agent.get_usage()
                    cents = getattr(
                        getattr(settled, "cost", None), "charged_cents", None
                    )
                    metrics["cost_minor_units"] = cents
                except Exception:
                    # Usage settlement can lag the response; token counts remain.
                    pass
                return result.result, metrics
            except asyncio.CancelledError:
                if run is not None:
                    try:
                        await asyncio.wait_for(run.cancel(), timeout=5)
                    except Exception:
                        pass
                raise
            finally:
                if agent is not None:
                    try:
                        await asyncio.wait_for(agent.close(), timeout=5)
                    except Exception:
                        pass


class OfficialCursorCLITransport:
    """Official headless CLI using its own browser-login session, never a key."""

    _MODEL_LINE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._:/+-]{0,159}) - .+$")

    def __init__(self, executable: str) -> None:
        self._executable = executable
        self._script = os.path.join(os.path.dirname(executable), "index.js")
        if not os.path.isfile(self._executable) or not os.path.isfile(self._script):
            raise ValueError("CURSOR_CLI_NOT_INSTALLED")

    async def _run(self, *args: str, timeout: float) -> str:
        with tempfile.TemporaryDirectory(prefix="sastsimi-cursor-") as workspace:
            flags = (
                int(getattr(subprocess, "CREATE_NO_WINDOW", 0))
                if os.name == "nt"
                else 0
            )
            allowed_env = {
                "PATH",
                "PATHEXT",
                "SYSTEMROOT",
                "WINDIR",
                "COMSPEC",
                "PROGRAMFILES",
                "PROGRAMDATA",
                "USERPROFILE",
                "HOME",
                "HOMEDRIVE",
                "HOMEPATH",
                "APPDATA",
                "LOCALAPPDATA",
                "TEMP",
                "TMP",
                "TMPDIR",
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "NO_PROXY",
                "SSL_CERT_FILE",
                "CURSOR_API_ENDPOINT",
            }
            child_env = {
                name: value
                for name, value in os.environ.items()
                if name.upper() in allowed_env
            }
            process = await asyncio.create_subprocess_exec(
                self._executable,
                self._script,
                *args,
                cwd=workspace,
                env=child_env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                creationflags=flags,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), timeout=timeout
                )
            except (TimeoutError, asyncio.CancelledError):
                if os.name == "nt" and process.pid is not None:
                    try:
                        terminator = await asyncio.create_subprocess_exec(
                            "taskkill",
                            "/PID",
                            str(process.pid),
                            "/T",
                            "/F",
                            stdout=asyncio.subprocess.DEVNULL,
                            stderr=asyncio.subprocess.DEVNULL,
                            creationflags=flags,
                        )
                        await asyncio.wait_for(terminator.wait(), timeout=5)
                    except Exception:
                        pass
                if process.returncode is None:
                    process.kill()
                await asyncio.wait_for(process.wait(), timeout=5)
                raise
            if process.returncode != 0:
                detail = (stderr + stdout).decode("utf-8", errors="replace").lower()
                if (
                    "rate limit" in detail
                    or "too many requests" in detail
                    or "429" in detail
                ):
                    raise CursorCLIRateLimitError()
                if "login" in detail or "authenticat" in detail:
                    raise CursorCLIAuthenticationError()
                if "model" in detail and (
                    "invalid" in detail or "unavailable" in detail
                ):
                    raise CursorCLIModelError()
                if (
                    "upgrade" in detail
                    or "usage limit" in detail
                    or "plan limit" in detail
                ):
                    raise CursorCLIPlanLimitError()
                if any(
                    marker in detail
                    for marker in (
                        "internal server error",
                        "service unavailable",
                        "502",
                        "503",
                        "504",
                        "network error",
                        "connection failed",
                    )
                ):
                    raise CursorCLITemporaryError()
                raise CursorCLIExecutionError()
            return stdout.decode("utf-8", errors="strict")

    async def list_models(self, api_key: str) -> set[str]:
        del api_key
        output = await self._run("models", timeout=30)
        models = {
            match.group(1)
            for line in output.splitlines()
            if (match := self._MODEL_LINE.fullmatch(line.strip())) is not None
        }
        if not models:
            raise CursorCLIModelCatalogError()
        return models

    async def complete(
        self, *, api_key: str, model: str, prompt: str, timeout: float
    ) -> tuple[str, dict[str, int | float | None]]:
        del api_key
        output = await self._run(
            "--print",
            "--trust",
            "--mode",
            "ask",
            "--output-format",
            "json",
            "--model",
            model,
            prompt,
            timeout=timeout,
        )
        try:
            envelope = json.loads(output)
        except (json.JSONDecodeError, TypeError) as error:
            raise CursorCLIExecutionError() from error
        if (
            not isinstance(envelope, dict)
            or envelope.get("type") != "result"
            or envelope.get("subtype") != "success"
            or envelope.get("is_error") is not False
            or not isinstance(envelope.get("result"), str)
        ):
            raise CursorCLIExecutionError()
        return envelope["result"], {}


class CursorCLIAuthenticationError(Exception):
    pass


class CursorCLIRateLimitError(Exception):
    pass


class CursorCLIModelError(Exception):
    pass


class CursorCLIModelCatalogError(Exception):
    pass


class CursorCLIExecutionError(Exception):
    pass


class CursorCLIPlanLimitError(Exception):
    pass


class CursorCLITemporaryError(Exception):
    pass


class CursorModelCatalog:
    def __init__(self) -> None:
        self.models: set[str] | None = None
        self.credential_digest: str | None = None
        self.refreshed_at: float = 0.0
        self.lock = asyncio.Lock()


def _unwrap_json(raw: str) -> str:
    stripped = raw.strip()
    if stripped.startswith("```") and stripped.endswith("```"):
        first_line, separator, body = stripped.partition("\n")
        if separator and first_line.lower() in {"```", "```json"}:
            return body[:-3].strip()
    return stripped


def _error_code(error: BaseException) -> tuple[str, bool]:
    name = type(error).__name__
    if name in {
        "AuthenticationError",
        "PermissionError",
        "CursorCLIAuthenticationError",
    }:
        return "CURSOR_AUTH_FAILED", False
    if name in {
        "ConfigurationError",
        "InvalidModelError",
        "CursorCLIModelError",
        "CursorCLIModelCatalogError",
    }:
        return "CURSOR_CONFIGURATION_FAILED", False
    if name == "CursorCLIPlanLimitError":
        return "CURSOR_PLAN_LIMIT", False
    if name in {"RateLimitError", "CursorCLIRateLimitError"}:
        return "CURSOR_RATE_LIMITED", True
    if name in {"APITimeoutError", "TimeoutError"}:
        return "CURSOR_TIMED_OUT", True
    if name in {"NetworkError", "InternalServerError", "CursorCLITemporaryError"}:
        return "CURSOR_TEMPORARY_FAILURE", True
    return "CURSOR_REQUEST_FAILED", bool(getattr(error, "is_retryable", False))


def _token_count(value: int | float | None) -> int | None:
    return int(value) if value is not None else None


def _cost_cents(value: int | float | None) -> float | None:
    return float(value) if value is not None else None


class CursorProvider:
    def __init__(
        self,
        *,
        artifacts: SimpleArtifactRepository,
        default_model: str,
        agent_models: Mapping[str, str],
        timeout_seconds: int,
        max_retries: int,
        semaphore: asyncio.Semaphore,
        allow_on_demand: bool,
        fallback: SimpleLLMClient | None = None,
        transport: CursorTransport | None = None,
        use_cli_login: bool = False,
        model_catalog: CursorModelCatalog | None = None,
        budget_check: Callable[[], StageFailure | None] | None = None,
    ) -> None:
        self._artifacts = artifacts
        self._default_model = default_model
        self._agent_models = dict(agent_models)
        self._timeout = timeout_seconds
        self._max_retries = max_retries
        self._semaphore = semaphore
        self._allow_on_demand = allow_on_demand
        self._fallback = fallback
        self._use_cli_login = use_cli_login
        self._transport = transport or OfficialCursorTransport(str(artifacts.data_dir))
        self._attempt_store = SimpleCheckpointStore(artifacts.paths.database)
        self._catalog = model_catalog or CursorModelCatalog()
        self._budget_check = budget_check

    async def _models(self, key: str) -> set[str]:
        async with self._catalog.lock:
            marker = hashlib.sha256(key.encode("utf-8")).hexdigest()
            if (
                self._catalog.credential_digest != marker
                or monotonic() - self._catalog.refreshed_at > 600
            ):
                self._catalog.models = None
                self._catalog.credential_digest = marker
            if self._catalog.models is None:
                for attempt in range(self._max_retries + 1):
                    try:
                        self._catalog.models = await asyncio.wait_for(
                            self._transport.list_models(key), timeout=self._timeout
                        )
                        self._catalog.refreshed_at = monotonic()
                        break
                    except Exception as error:
                        _, retryable = _error_code(error)
                        if not retryable or attempt >= self._max_retries:
                            raise
                        await asyncio.sleep(min(8.0, 0.5 * 2**attempt))
            assert self._catalog.models is not None
            return self._catalog.models

    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
        agent_name: str = "agent",
    ) -> SimpleLLMCallResult | StageFailure:
        key = "" if self._use_cli_login else os.environ.get("CURSOR_API_KEY", "")
        if not self._use_cli_login and (not key or key != key.strip()):
            return StageFailure(
                code="CURSOR_AUTH_REQUIRED",
                retryable=False,
                safe_message="Set CURSOR_API_KEY to your own Cursor API key",
            )
        if not self._allow_on_demand:
            return StageFailure(
                code="CURSOR_ON_DEMAND_CONTROL_UNAVAILABLE",
                retryable=False,
                safe_message=(
                    "Cursor SDK cannot guarantee on-demand usage is disabled; "
                    "set cursor_allow_on_demand=true only after checking Team billing"
                ),
            )
        model = self._agent_models.get(agent_name, self._default_model)
        try:
            models = await self._models(key)
        except Exception as error:
            code, retryable = _error_code(error)
            failure = StageFailure(
                code=code,
                retryable=retryable,
                safe_message="Cursor model catalog could not be read",
            )
            if retryable and self._fallback is not None:
                return await self._fallback.call(
                    prompt=prompt,
                    output_schema=output_schema,
                    timeout_ms=timeout_ms,
                    agent_name=agent_name,
                )
            return failure
        if model not in models:
            return StageFailure(
                code="CURSOR_MODEL_UNAVAILABLE",
                retryable=False,
                safe_message=(
                    f"Cursor model '{model}' is unavailable for this account; "
                    "run sastsimi cursor-models and select a returned ID"
                ),
            )

        timeout = min(self._timeout, max(1, timeout_ms) / 1000)
        schema_text = json.dumps(output_schema, ensure_ascii=False, sort_keys=True)
        base_prompt = (
            prompt.decode("utf-8")
            + "\nReturn exactly one JSON object, without commentary, "
            + "matching this schema:\n"
            + schema_text
        )
        prompt_digest = hashlib.sha256(prompt).hexdigest()
        last_failure: StageFailure | None = None
        correction = ""
        async with self._semaphore:
            for attempt in range(1, self._max_retries + 2):
                if self._budget_check is not None:
                    budget_failure = self._budget_check()
                    if budget_failure is not None:
                        return budget_failure
                started_at = datetime.now(UTC)
                started = monotonic()
                invocation_id = f"cursor-{uuid4().hex}"
                raw_ref = None
                parsed_ref = None
                usage: dict[str, int | float | None] = {}
                code = "SUCCEEDED"
                try:
                    raw, usage = await asyncio.wait_for(
                        self._transport.complete(
                            api_key=key,
                            model=model,
                            prompt=base_prompt + correction,
                            timeout=timeout,
                        ),
                        timeout=timeout,
                    )
                    raw = raw[:_MAX_RAW_BYTES]
                    raw_ref = self._artifacts.put_json(
                        {"kind": "cursor_raw_output", "text": raw}
                    )
                    value = json.loads(_unwrap_json(raw))
                    if not isinstance(value, dict):
                        raise ValueError("$: expected object")
                    _validate_schema(value, output_schema)
                    canonical = canonical_bytes(value)
                    parsed_ref = self._artifacts.put_bytes(
                        canonical, "application/json"
                    )
                    result = SimpleLLMCallResult(
                        value=value,
                        prompt_digest=prompt_digest,
                        output_digest=hashlib.sha256(canonical).hexdigest(),
                        invocation_id=invocation_id,
                        provider="cursor-cli" if self._use_cli_login else "cursor-sdk",
                        model=model,
                        started_at=started_at,
                        finished_at=datetime.now(UTC),
                        elapsed_ms=int((monotonic() - started) * 1000),
                        raw_output_ref=raw_ref,
                        parsed_output_ref=parsed_ref,
                        input_tokens=_token_count(usage.get("input_tokens")),
                        output_tokens=_token_count(usage.get("output_tokens")),
                        cost_minor_units=usage.get("cost_minor_units"),
                        on_demand_possible=True,
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
                    return result
                except asyncio.CancelledError:
                    raise
                except (json.JSONDecodeError, ValueError, TypeError) as error:
                    code = "CURSOR_INVALID_OUTPUT"
                    detail = str(error).splitlines()[0][:200]
                    correction = (
                        "\nYour previous response failed JSON/schema validation at "
                        + detail
                        + ". Return a corrected JSON object matching the same schema:\n"
                        + schema_text
                    )
                    last_failure = StageFailure(
                        code=code,
                        retryable=False,
                        safe_message="Cursor returned invalid structured output",
                    )
                except Exception as error:
                    code, retryable = _error_code(error)
                    last_failure = StageFailure(
                        code=code,
                        retryable=retryable,
                        safe_message="Cursor request did not complete",
                    )
                    if not retryable:
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
                        break
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
                if attempt <= self._max_retries:
                    await asyncio.sleep(
                        min(8.0, 0.5 * 2 ** (attempt - 1)) + random.uniform(0, 0.25)
                    )
        assert last_failure is not None
        if self._fallback is not None and last_failure.retryable:
            return await self._fallback.call(
                prompt=prompt,
                output_schema=output_schema,
                timeout_ms=timeout_ms,
                agent_name=agent_name,
            )
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
        elapsed = int((monotonic() - started) * 1000)
        _LOG.info(
            "cursor_call analysis_id=%s agent=%s model=%s "
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
                "kind": "cursor_agent_attempt",
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
            input_tokens=_token_count(usage.get("input_tokens")),
            output_tokens=_token_count(usage.get("output_tokens")),
            cost_cents=_cost_cents(usage.get("cost_minor_units")),
            artifact_ref=artifact_ref,
        )


__all__ = [
    "CursorModelCatalog",
    "CursorProvider",
    "OfficialCursorTransport",
    "OfficialCursorCLITransport",
]
