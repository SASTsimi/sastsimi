from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping
from typing import Any
from uuid import uuid4

from pydantic import JsonValue

from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.providers.base import CodexProcessRequest, CodexProcessRunner

from .models import StageFailure


class SimpleLLMCallResult(ContractModel):
    value: dict[str, JsonValue]
    prompt_digest: str
    output_digest: str


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
        request = CodexProcessRequest(
            invocation_id=f"simple-{uuid4().hex}",
            provider_profile_ref=self._provider_profile_ref,
            model=self._model,
            prompt=prompt,
            output_schema=canonical_bytes(output_schema),
            timeout_ms=timeout_ms,
        )
        async with self._lock:
            result = await self._runner.execute(request)
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
        )


__all__ = ["SimpleCodexClient", "SimpleLLMCallResult"]
