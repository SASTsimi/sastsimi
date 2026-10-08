from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from time import monotonic
from typing import Any, Protocol
from uuid import uuid4

from pydantic import JsonValue

from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.prompt_redaction import (
    redact_projected_json,
    redact_untrusted_text,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.providers.base import CodexProcessRequest, CodexProcessRunner

from .attempt_owner import AttemptOwner, PromptByteCounts
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
    request_ref: StoredDataRef | None = None
    response_ref: StoredDataRef | None = None
    raw_output_ref: StoredDataRef | None = None
    parsed_output_ref: StoredDataRef | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost_minor_units: float | None = None
    on_demand_possible: bool = False


class SimpleLLMClient(Protocol):
    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
        agent_name: str = "agent",
        owner: AttemptOwner | None = None,
        prompt_bytes: PromptByteCounts | None = None,
        invocation_id: str | None = None,
    ) -> SimpleLLMCallResult | StageFailure: ...


class InvocationArtifactWriter(Protocol):
    def put_json(self, value: object) -> StoredDataRef: ...


def _request_artifact(
    artifacts: InvocationArtifactWriter | None,
    *,
    invocation_id: str,
    provider: str,
    model: str,
    prompt: bytes,
    output_schema: Mapping[str, Any],
) -> StoredDataRef | None:
    if artifacts is None:
        return None
    try:
        safe_prompt = redact_untrusted_text(prompt).data.decode(
            "utf-8", errors="replace"
        )
    except ValueError:
        safe_prompt = "[CONTENT_REDACTED]"
    return artifacts.put_json(
        {
            "kind": "simple_llm_request",
            "invocation_id": invocation_id,
            "provider": provider,
            "model": model,
            "template_revision": "simple-runtime-inline-v1",
            "prompt": safe_prompt,
            "output_schema": dict(output_schema),
        }
    )


def _response_artifact(
    artifacts: InvocationArtifactWriter | None,
    *,
    invocation_id: str,
    provider: str,
    model: str,
    canonical: bytes,
    input_tokens: int | None,
    output_tokens: int | None,
) -> StoredDataRef | None:
    if artifacts is None:
        return None
    try:
        response = json.loads(redact_projected_json(canonical).data)
    except (ValueError, TypeError, json.JSONDecodeError):
        response = "[CONTENT_REDACTED]"
    return artifacts.put_json(
        {
            "kind": "simple_llm_response",
            "invocation_id": invocation_id,
            "provider": provider,
            "model": model,
            "response": response,
            "usage": {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
            },
        }
    )


_CODEX_INVALID_CATEGORIES = frozenset(
    {
        "event_stream_invalid",
        "final_message_missing",
        "final_message_empty",
        "final_message_oversized",
        "final_message_unreadable",
        "encoding_invalid",
        "json_malformed",
        "schema_mismatch",
        "canonicalization_invalid",
    }
)


def _codex_invalid_output_artifact(
    artifacts: InvocationArtifactWriter | None,
    *,
    invocation_id: str,
    model: str,
    request_ref: StoredDataRef | None,
    category: str,
    source: str | None,
    sha256: str | None,
    raw: bytes | None = None,
    invalid_field: str | None = None,
) -> StoredDataRef | None:
    if artifacts is None:
        return None
    safe_category = (
        category if category in _CODEX_INVALID_CATEGORIES else "process_invalid_output"
    )
    safe_source = source if source in {"event_stream", "final_message"} else None
    digest = hashlib.sha256(raw).hexdigest() if raw is not None else sha256
    if digest is not None and (
        len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        digest = None
    return artifacts.put_json(
        {
            "kind": "simple_llm_invalid_output",
            "invocation_id": invocation_id,
            "provider": "codex-cli",
            "model": model,
            "request_ref": (
                request_ref.model_dump(mode="json") if request_ref is not None else None
            ),
            "category": safe_category,
            "diagnostic_source": safe_source,
            "diagnostic_sha256": digest,
            "invalid_field": invalid_field,
        }
    )


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
    alternatives = schema.get("anyOf")
    if isinstance(alternatives, list):
        valid = False
        for alternative in alternatives:
            if not isinstance(alternative, dict):
                continue
            try:
                _validate_schema(value, alternative, path)
            except ValueError:
                continue
            valid = True
            break
        if not valid:
            raise ValueError(path)
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
                raise ValueError("additional property")
        for key, item in value.items():
            child = properties.get(key)
            if isinstance(child, dict):
                _validate_schema(item, child, f"{path}.{key}")
    if isinstance(value, list):
        max_items = schema.get("maxItems")
        if isinstance(max_items, int) and len(value) > max_items:
            raise ValueError(path)
        min_items = schema.get("minItems")
        if isinstance(min_items, int) and len(value) < min_items:
            raise ValueError(path)
        if isinstance(schema.get("items"), dict):
            for index, item in enumerate(value):
                _validate_schema(item, schema["items"], f"{path}[{index}]")


def _response_tokens(response: object) -> tuple[int | None, int | None]:
    usage = getattr(response, "usage", None)
    input_tokens = getattr(usage, "input_tokens", None)
    output_tokens = getattr(usage, "output_tokens", None)
    total_tokens = getattr(usage, "total_tokens", None)
    if (
        type(input_tokens) is int
        and input_tokens >= 0
        and type(output_tokens) is int
        and output_tokens >= 0
        and type(total_tokens) is int
        and total_tokens == input_tokens + output_tokens
    ):
        return input_tokens, output_tokens
    return None, None


class SimpleCodexClient:
    """One-call-at-a-time Codex boundary for the local sequential runtime."""

    def __init__(
        self,
        *,
        runner: CodexProcessRunner,
        provider_profile_ref: StoredDataRef,
        model: str,
        artifacts: InvocationArtifactWriter | None = None,
    ) -> None:
        self._runner = runner
        self._provider_profile_ref = provider_profile_ref
        self._model = model
        self._lock = asyncio.Lock()
        self._artifacts = artifacts

    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
        agent_name: str = "agent",
        owner: AttemptOwner | None = None,
        prompt_bytes: PromptByteCounts | None = None,
        invocation_id: str | None = None,
    ) -> SimpleLLMCallResult | StageFailure:
        del owner, prompt_bytes
        prompt_digest = hashlib.sha256(prompt).hexdigest()
        invocation_id = invocation_id or f"simple-{uuid4().hex}"
        request_ref = _request_artifact(
            self._artifacts,
            invocation_id=invocation_id,
            provider="codex-cli",
            model=self._model,
            prompt=prompt,
            output_schema=output_schema,
        )
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
        if result.cleanup_unconfirmed:
            return StageFailure(
                code="CODEX_PROCESS_CLEANUP_UNCONFIRMED",
                retryable=False,
                safe_message="Codex child process cleanup could not be confirmed",
                evidence_refs=((request_ref,) if request_ref is not None else ()),
            )
        if result.status == "INVALID_OUTPUT" or (
            result.status == "SUCCEEDED" and result.final_message is None
        ):
            diagnostic_ref = _codex_invalid_output_artifact(
                self._artifacts,
                invocation_id=invocation_id,
                model=self._model,
                request_ref=request_ref,
                category=result.invalid_output_category
                or (
                    "final_message_missing"
                    if result.status == "SUCCEEDED"
                    else "process_invalid_output"
                ),
                source=result.invalid_output_source,
                sha256=result.invalid_output_sha256,
            )
            return StageFailure(
                code="INVALID_OUTPUT",
                retryable=True,
                safe_message="Codex returned invalid structured output",
                evidence_refs=tuple(
                    ref for ref in (request_ref, diagnostic_ref) if ref is not None
                ),
            )
        if result.status == "FAILED" and result.model_unavailable:
            return StageFailure(
                code="MODEL_UNAVAILABLE",
                retryable=False,
                safe_message="Codex model is unavailable",
                evidence_refs=((request_ref,) if request_ref is not None else ()),
            )
        if result.status != "SUCCEEDED" or result.final_message is None:
            return StageFailure(
                code=result.status,
                retryable=result.status in {"RATE_LIMITED", "TIMED_OUT", "FAILED"},
                safe_message=f"Codex call did not succeed: {result.status}",
                evidence_refs=((request_ref,) if request_ref is not None else ()),
            )
        category = "encoding_invalid"
        try:
            decoded = result.final_message.decode("utf-8")
            category = "json_malformed"
            value = json.loads(decoded)
            category = "schema_mismatch"
            if not isinstance(value, dict):
                raise ValueError("$")
            _validate_schema(value, output_schema)
            category = "canonicalization_invalid"
            canonical = canonical_bytes(value)
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ) as error:
            field = (
                str(error)
                if category == "schema_mismatch" and str(error).startswith("$")
                else None
            )
            if field is not None and (
                len(field) > 128
                or re.fullmatch(r"\$(?:\.[A-Za-z_][A-Za-z0-9_]*|\[\d+\])*", field)
                is None
            ):
                field = None
            diagnostic_ref = _codex_invalid_output_artifact(
                self._artifacts,
                invocation_id=invocation_id,
                model=self._model,
                request_ref=request_ref,
                category=category,
                source="final_message",
                sha256=None,
                raw=result.final_message,
                invalid_field=field,
            )
            return StageFailure(
                code="INVALID_OUTPUT",
                retryable=True,
                safe_message="Codex returned invalid structured output",
                invalid_field=field,
                evidence_refs=tuple(
                    ref for ref in (request_ref, diagnostic_ref) if ref is not None
                ),
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
            request_ref=request_ref,
            response_ref=_response_artifact(
                self._artifacts,
                invocation_id=invocation_id,
                provider="codex-cli",
                model=self._model,
                canonical=canonical,
                input_tokens=result.input_tokens,
                output_tokens=result.output_tokens,
            ),
            input_tokens=result.input_tokens,
            output_tokens=result.output_tokens,
        )


class SimpleOpenAIClient:
    """Minimal official Responses API client for the sequential local path."""

    def __init__(
        self,
        *,
        credential_ref: str,
        model: str,
        artifacts: InvocationArtifactWriter | None = None,
    ) -> None:
        variable = credential_ref.removeprefix("env:")
        if variable == credential_ref:
            raise ValueError("CREDENTIAL_REFERENCE_INVALID")
        self._variable = variable
        self._model = model
        self._lock = asyncio.Lock()
        self._artifacts = artifacts

    async def call(
        self,
        *,
        prompt: bytes,
        output_schema: Mapping[str, Any],
        timeout_ms: int,
        agent_name: str = "agent",
        owner: AttemptOwner | None = None,
        prompt_bytes: PromptByteCounts | None = None,
        invocation_id: str | None = None,
    ) -> SimpleLLMCallResult | StageFailure:
        del owner, prompt_bytes, invocation_id
        credential = os.environ.get(self._variable)
        if credential is None or not credential or credential != credential.strip():
            return StageFailure(
                code="AUTH_REQUIRED",
                retryable=False,
                safe_message="Configured API credential is unavailable",
            )
        try:
            from openai import AsyncOpenAI
        except (ImportError, AttributeError):
            return StageFailure(
                code="OPENAI_SDK_UNAVAILABLE",
                retryable=False,
                safe_message="Official OpenAI SDK is unavailable",
            )
        prompt_digest = hashlib.sha256(prompt).hexdigest()
        invocation_id = f"simple-{uuid4().hex}"
        request_ref = _request_artifact(
            self._artifacts,
            invocation_id=invocation_id,
            provider="openai-api",
            model=self._model,
            prompt=prompt,
            output_schema=output_schema,
        )
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
                evidence_refs=((request_ref,) if request_ref is not None else ()),
            )
        except Exception as error:
            name = type(error).__name__.lower()
            status = getattr(error, "status_code", None)
            context_overflow = (
                status == 400
                and getattr(error, "code", None) == "context_length_exceeded"
            )
            code = (
                "AUTH_REQUIRED"
                if status in {401, 403} or "authentication" in name
                else "RATE_LIMITED"
                if status == 429 or "ratelimit" in name
                else "CONTEXT_LIMIT_EXCEEDED"
                if context_overflow
                else "MODEL_OR_REQUEST_UNSUPPORTED"
                if status in {400, 404}
                else "FAILED"
            )
            return StageFailure(
                code=code,
                retryable=code in {"RATE_LIMITED", "FAILED"},
                safe_message=(
                    "OpenAI request exceeds model context window"
                    if context_overflow
                    else "OpenAI request did not complete"
                ),
                evidence_refs=((request_ref,) if request_ref is not None else ()),
            )
        finished_at = datetime.now(UTC)
        elapsed_ms = max(0, int((monotonic() - started) * 1000))
        input_tokens, output_tokens = _response_tokens(response)
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
            request_ref=request_ref,
            response_ref=_response_artifact(
                self._artifacts,
                invocation_id=invocation_id,
                provider="openai-api",
                model=self._model,
                canonical=canonical,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
            ),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )


__all__ = [
    "SimpleCodexClient",
    "SimpleLLMCallResult",
    "SimpleLLMClient",
    "SimpleOpenAIClient",
    "InvocationArtifactWriter",
]
