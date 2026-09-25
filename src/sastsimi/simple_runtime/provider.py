from __future__ import annotations

import asyncio
import hashlib
import json
import os
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from time import monotonic, time
from typing import Any, Protocol
from uuid import uuid4

from pydantic import JsonValue

from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.providers.base import (
    CodexProcessRequest,
    CodexProcessResult,
    CodexProcessRunner,
    SubscriptionProcessRunner,
)
from sastsimi.simple_runtime.call_queue import CallQueue

from .models import StageFailure

# Measured against the official client: the server turns away a burst of large
# prompts with a 429 that clears on its own, so a refused call is retried a few
# times with a widening wait before the stage gives up.
_RATE_LIMIT_BACKOFF_MS: tuple[int, ...] = (3_000, 12_000, 45_000)
# The subscription window was measured at five hours, so a wait longer than
# that is not a window reopening and is not worth holding the run for.
_MAX_WINDOW_WAIT_SECONDS = 6 * 60 * 60


class SimpleLLMCallResult(ContractModel):
    value: dict[str, JsonValue]
    prompt_digest: str
    output_digest: str
    invocation_id: str | None = None
    provider: str | None = None
    model: str | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    elapsed_ms: int | None = None


class SimpleLLMClient(Protocol):
    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
    ) -> SimpleLLMCallResult | StageFailure: ...


def _matches_type(value: object, expected: str) -> bool:
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, False)


def _validate_schema(value: object, schema: Mapping[str, Any], path: str = "$") -> None:
    expected = schema.get("type")
    if isinstance(expected, str) and not _matches_type(value, expected):
        raise ValueError(path)
    if "const" in schema and value != schema["const"]:
        raise ValueError(path)
    enum = schema.get("enum")
    if isinstance(enum, list) and value not in enum:
        raise ValueError(path)
    if isinstance(value, dict):
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        if not isinstance(properties, dict) or not isinstance(required, list):
            raise ValueError(path)
        missing = [key for key in required if key not in value]
        if missing:
            raise ValueError(f"{path}.{missing[0]}")
        if schema.get("additionalProperties") is False:
            extras = set(value) - set(properties)
            if extras:
                raise ValueError(f"{path}.{sorted(extras)[0]}")
        for key, item in value.items():
            child = properties.get(key)
            if isinstance(child, dict):
                _validate_schema(item, child, f"{path}.{key}")
    if isinstance(value, list) and isinstance(schema.get("items"), dict):
        for index, item in enumerate(value):
            _validate_schema(item, schema["items"], f"{path}[{index}]")


class SimpleCodexClient:
    """One-call-at-a-time Codex boundary for the local sequential runtime."""

    def __init__(
        self,
        *,
        runner: CodexProcessRunner,
        provider_profile_ref: StoredDataRef,
        model: str,
    ) -> None:
        self._runner = runner
        self._provider_profile_ref = provider_profile_ref
        self._model = model
        self._lock = asyncio.Lock()

    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
    ) -> SimpleLLMCallResult | StageFailure:
        prompt_digest = hashlib.sha256(prompt).hexdigest()
        invocation_id = f"simple-{uuid4().hex}"
        request = CodexProcessRequest(
            invocation_id=invocation_id,
            provider_profile_ref=self._provider_profile_ref,
            model=self._model,
            prompt=prompt,
            output_schema=canonical_bytes(output_schema),
            timeout_ms=timeout_ms,
        )
        started_at = datetime.now(UTC)
        started = monotonic()
        async with self._lock:
            result = await self._runner.execute(request)
        finished_at = datetime.now(UTC)
        elapsed_ms = max(0, int((monotonic() - started) * 1000))
        if result.status != "SUCCEEDED" or result.final_message is None:
            return StageFailure(
                code=result.status,
                retryable=result.status
                in {"AUTH_REQUIRED", "RATE_LIMITED", "TIMED_OUT", "FAILED"},
                safe_message=f"Codex call did not succeed: {result.status}",
            )
        try:
            value = json.loads(result.final_message.decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError("$")
            _validate_schema(value, output_schema)
            canonical = canonical_bytes(value)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ) as error:
            field = str(error) if str(error).startswith("$") else None
            return StageFailure(
                code="INVALID_OUTPUT",
                retryable=False,
                safe_message="Codex returned invalid structured output",
                invalid_field=field,
            )
        return SimpleLLMCallResult(
            value=value,
            prompt_digest=prompt_digest,
            output_digest=hashlib.sha256(canonical).hexdigest(),
            invocation_id=invocation_id,
            provider="codex-cli",
            model=self._model,
            started_at=started_at,
            finished_at=finished_at,
            elapsed_ms=elapsed_ms,
        )


class SimpleClaudeClient:
    """Bounded-concurrency Claude Code boundary for the local runtime.

    The official subscription clients share one process boundary shape, so this
    mirrors the Codex client and differs only in which client it names.
    Concurrent children were measured to run correctly against one credential
    directory, so the ceiling is an operator setting rather than a fixed one.
    """

    def __init__(
        self,
        *,
        runner: SubscriptionProcessRunner,
        provider_profile_ref: StoredDataRef,
        model: str,
        queue: CallQueue | None = None,
        rate_limit_backoff_ms: tuple[int, ...] = _RATE_LIMIT_BACKOFF_MS,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
        now: Callable[[], float] = time,
        max_window_wait_seconds: float = _MAX_WINDOW_WAIT_SECONDS,
    ) -> None:
        self._runner = runner
        self._provider_profile_ref = provider_profile_ref
        self._model = model
        # Every agent shares this queue, so the ceiling counts children on the
        # host rather than children per stage.
        self._queue = queue if queue is not None else CallQueue(max_concurrent=1)
        self._rate_limit_backoff_ms = rate_limit_backoff_ms
        self._sleep = sleep
        self._now = now
        self._max_window_wait_seconds = max_window_wait_seconds

    async def _call_through_rate_limits(
        self, request: CodexProcessRequest
    ) -> CodexProcessResult:
        """Retry a call the server turned away for sending too fast.

        The refusal measured here is the server's burst limit, not the
        subscription's usage limit, and it clears on its own.  The wait happens
        outside the queue slot so a call that is waiting does not hold one idle.
        """

        result = await self._queue.submit(lambda: self._runner.execute(request))
        attempts = 0
        while result.status == "RATE_LIMITED":
            wait = self._wait_for(result, attempts)
            if wait is None:
                return result
            await self._sleep(wait)
            attempts += 1
            result = await self._queue.submit(lambda: self._runner.execute(request))
        return result

    def _wait_for(self, result: CodexProcessResult, attempts: int) -> float | None:
        """Return how long to wait, or ``None`` when waiting is pointless.

        A burst refusal clears in seconds, so a short ladder covers it.  A
        subscription window does not: it was measured reopening up to five
        hours later, and spending three short retries on that reports the stage
        blocked for the rest of the night.  When the client says when the
        window reopens, that is what is waited for.
        """

        reopens_at = result.retry_after_epoch
        if reopens_at is not None:
            remaining = reopens_at - self._now()
            if remaining <= 0:
                # Already past; treat it as a burst and retry at once.
                return 0.0
            if remaining > self._max_window_wait_seconds:
                return None
            # A moment past the stated time, so the first retry is not early.
            return remaining + 5
        if attempts >= len(self._rate_limit_backoff_ms):
            return None
        return self._rate_limit_backoff_ms[attempts] / 1000

    @asynccontextmanager
    async def conversation(
        self, *, output_schema: Mapping[str, Any], timeout_ms: int
    ) -> AsyncIterator[SimpleConversation]:
        """Hold one queue slot and one client process for several turns."""

        opener = getattr(self._runner, "conversation", None)
        if opener is None:
            yield _ReplayConversation(self, output_schema, timeout_ms)
            return
        request = CodexProcessRequest(
            invocation_id=f"simple-{uuid4().hex}",
            provider_profile_ref=self._provider_profile_ref,
            model=self._model,
            prompt=b"",
            output_schema=canonical_bytes(output_schema),
            timeout_ms=timeout_ms,
        )
        async with self._queue.hold(), opener(request) as live:
            yield _LiveConversation(self, live, output_schema, timeout_ms)

    async def _ask_live(
        self,
        live: Any,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
    ) -> SimpleLLMCallResult | StageFailure:
        started_at = datetime.now(UTC)
        started = monotonic()
        result = await live.send(prompt, timeout_ms=timeout_ms)
        attempts = 0
        while result.status == "RATE_LIMITED":
            wait = self._wait_for(result, attempts)
            if wait is None:
                break
            await self._sleep(wait)
            attempts += 1
            result = await live.send(prompt, timeout_ms=timeout_ms)
        return self._finish(
            result,
            prompt,
            output_schema,
            invocation_id=f"simple-{uuid4().hex}",
            started_at=started_at,
            started=started,
        )

    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
    ) -> SimpleLLMCallResult | StageFailure:
        invocation_id = f"simple-{uuid4().hex}"
        request = CodexProcessRequest(
            invocation_id=invocation_id,
            provider_profile_ref=self._provider_profile_ref,
            model=self._model,
            prompt=prompt,
            output_schema=canonical_bytes(output_schema),
            timeout_ms=timeout_ms,
        )
        started_at = datetime.now(UTC)
        started = monotonic()
        result = await self._call_through_rate_limits(request)
        return self._finish(
            result,
            prompt,
            output_schema,
            invocation_id=invocation_id,
            started_at=started_at,
            started=started,
        )

    def _finish(
        self,
        result: CodexProcessResult,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        *,
        invocation_id: str,
        started_at: datetime,
        started: float,
    ) -> SimpleLLMCallResult | StageFailure:
        prompt_digest = hashlib.sha256(prompt).hexdigest()
        finished_at = datetime.now(UTC)
        elapsed_ms = max(0, int((monotonic() - started) * 1000))
        if result.status != "SUCCEEDED" or result.final_message is None:
            return StageFailure(
                code=result.status,
                retryable=result.status
                in {"AUTH_REQUIRED", "RATE_LIMITED", "TIMED_OUT", "FAILED"},
                safe_message=f"Claude Code call did not succeed: {result.status}",
            )
        try:
            value = json.loads(result.final_message.decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError("$")
            _validate_schema(value, output_schema)
            canonical = canonical_bytes(value)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ) as error:
            field = str(error) if str(error).startswith("$") else None
            return StageFailure(
                code="INVALID_OUTPUT",
                retryable=False,
                safe_message="Claude Code returned invalid structured output",
                invalid_field=field,
            )
        return SimpleLLMCallResult(
            value=value,
            prompt_digest=prompt_digest,
            output_digest=hashlib.sha256(canonical).hexdigest(),
            invocation_id=invocation_id,
            provider="claude-code",
            model=self._model,
            started_at=started_at,
            finished_at=finished_at,
            elapsed_ms=elapsed_ms,
        )


class SimpleConversation(Protocol):
    async def ask(self, prompt: bytes) -> SimpleLLMCallResult | StageFailure: ...


class _ReplayConversation:
    """Turns replayed as one prompt each time, for a client with no live mode.

    This is what every call used to be; it keeps callers on one shape.
    """

    def __init__(
        self, client: SimpleLLMClient, schema: Mapping[str, Any], timeout_ms: int
    ) -> None:
        self._client = client
        self._schema = schema
        self._timeout_ms = timeout_ms
        self._turns: list[bytes] = []

    async def ask(self, prompt: bytes) -> SimpleLLMCallResult | StageFailure:
        self._turns.append(prompt)
        result = await self._client.call(
            prompt=b"\n\n".join(self._turns),
            output_schema=self._schema,
            timeout_ms=self._timeout_ms,
        )
        if isinstance(result, SimpleLLMCallResult):
            self._turns.append(
                b"Your previous answer:\n" + canonical_bytes(result.value)
            )
        return result


class _LiveConversation:
    """Turns sent to one client process; earlier turns come from the cache."""

    def __init__(
        self,
        client: SimpleClaudeClient,
        live: Any,
        schema: Mapping[str, Any],
        timeout_ms: int,
    ) -> None:
        self._client = client
        self._live = live
        self._schema = schema
        self._timeout_ms = timeout_ms

    async def ask(self, prompt: bytes) -> SimpleLLMCallResult | StageFailure:
        return await self._client._ask_live(
            self._live, prompt, self._schema, self._timeout_ms
        )


@asynccontextmanager
async def conversation_with(
    client: SimpleLLMClient, *, output_schema: Mapping[str, Any], timeout_ms: int
) -> AsyncIterator[SimpleConversation]:
    """Open a conversation with any client: live when it can, replayed if not."""

    opener = getattr(client, "conversation", None)
    if opener is None:
        yield _ReplayConversation(client, output_schema, timeout_ms)
        return
    async with opener(output_schema=output_schema, timeout_ms=timeout_ms) as talk:
        yield talk


class SimpleOpenAIClient:
    """Minimal official Responses API client for the sequential local path."""

    def __init__(self, *, credential_ref: str, model: str) -> None:
        variable = credential_ref.removeprefix("env:")
        if variable == credential_ref:
            raise ValueError("CREDENTIAL_REFERENCE_INVALID")
        self._variable = variable
        self._model = model
        self._lock = asyncio.Lock()

    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
    ) -> SimpleLLMCallResult | StageFailure:
        credential = os.environ.get(self._variable)
        if credential is None or not credential or credential != credential.strip():
            return StageFailure(
                code="AUTH_REQUIRED",
                retryable=True,
                safe_message="Configured API credential is unavailable",
            )
        try:
            from openai import AsyncOpenAI
        except (ImportError, AttributeError):
            return StageFailure(
                code="OPENAI_SDK_UNAVAILABLE",
                retryable=True,
                safe_message="Official OpenAI SDK is unavailable",
            )
        prompt_digest = hashlib.sha256(prompt).hexdigest()
        invocation_id = f"simple-{uuid4().hex}"
        started_at = datetime.now(UTC)
        started = monotonic()
        try:
            async with AsyncOpenAI(api_key=credential, max_retries=0) as client:
                async with self._lock:
                    response = await asyncio.wait_for(
                        client.responses.create(
                            model=self._model,
                            input=prompt.decode("utf-8"),
                            text={
                                "format": {
                                    "type": "json_schema",
                                    "name": "sastsimi_agent_output",
                                    "schema": dict(output_schema),
                                    "strict": True,
                                }
                            },
                            store=False,
                        ),
                        timeout=max(1, timeout_ms) / 1000,
                    )
            raw = str(response.output_text)
        except TimeoutError:
            return StageFailure(
                code="TIMED_OUT",
                retryable=True,
                safe_message="OpenAI request timed out",
            )
        except Exception as error:
            name = type(error).__name__.lower()
            code = (
                "AUTH_REQUIRED"
                if "authentication" in name
                else "RATE_LIMITED"
                if "ratelimit" in name
                else "FAILED"
            )
            return StageFailure(
                code=code,
                retryable=True,
                safe_message="OpenAI request did not complete",
            )
        finished_at = datetime.now(UTC)
        elapsed_ms = max(0, int((monotonic() - started) * 1000))
        try:
            value = json.loads(raw)
            if not isinstance(value, dict):
                raise ValueError("$")
            _validate_schema(value, output_schema)
            canonical = canonical_bytes(value)
        except (json.JSONDecodeError, TypeError, ValueError) as error:
            field = str(error) if str(error).startswith("$") else None
            return StageFailure(
                code="INVALID_OUTPUT",
                retryable=False,
                safe_message="OpenAI returned invalid structured output",
                invalid_field=field,
            )
        return SimpleLLMCallResult(
            value=value,
            prompt_digest=prompt_digest,
            output_digest=hashlib.sha256(canonical).hexdigest(),
            invocation_id=invocation_id,
            provider="openai-api",
            model=self._model,
            started_at=started_at,
            finished_at=finished_at,
            elapsed_ms=elapsed_ms,
        )


__all__ = [
    "SimpleClaudeClient",
    "SimpleCodexClient",
    "SimpleLLMCallResult",
    "SimpleLLMClient",
    "SimpleOpenAIClient",
]
