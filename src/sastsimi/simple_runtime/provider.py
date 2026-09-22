from __future__ import annotations

import asyncio
import hashlib
import json
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from time import monotonic
from typing import Any, Protocol
from uuid import uuid4

from pydantic import JsonValue

from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.providers.base import (
    CodexProcessRequest,
    CodexProcessRunner,
    SubscriptionProcessRunner,
)

from .models import StageFailure


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
        max_concurrent_calls: int = 1,
    ) -> None:
        self._runner = runner
        self._provider_profile_ref = provider_profile_ref
        self._model = model
        self._lock = asyncio.Semaphore(max(1, max_concurrent_calls))

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
