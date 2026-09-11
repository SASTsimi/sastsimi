"""Provider-neutral dependencies for external LLM adapters.

Production client construction belongs to the application composition boundary.  In
particular, Task 16 must connect the official SDK and configure its client with
provider retries disabled; adapters never import an optional provider SDK or retain a
resolved credential.
"""

from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

from pydantic import JsonValue

from sastsimi.config.secrets import SecretReference
from sastsimi.contracts.evaluation import UsageMeasurement
from sastsimi.contracts.llm import (
    InvocationStatus,
    LLMInvocationRequest,
    LLMInvocationResult,
    OutputSchemaSpec,
    PromptPayload,
    ProviderValidationEvidence,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.ports.clock import Clock
from sastsimi.ports.dto import CapabilityProbeResult, Record


class CredentialUnavailableError(RuntimeError):
    """The approved credential reference cannot currently be resolved."""


class ProviderInputMismatchError(RuntimeError):
    """The resolved transient prompt is not the exact authorized payload."""


class ProviderInvalidOutputError(RuntimeError):
    """A provider response cannot be used as structured agent output."""


@dataclass(frozen=True)
class ResolvedPromptContext:
    """One exact redacted context artifact, in PromptPayload binding order."""

    slot: str
    projected_data_ref: StoredDataRef
    data: bytes


@dataclass(frozen=True)
class ResolvedPromptInput:
    """Exact stored prompt records and bytes resolved only for this invocation.

    The adapter independently verifies every reference, content hash and deterministic
    rendering relationship before any credential or provider client is touched.
    """

    payload: PromptPayload
    template_bytes: bytes
    rendered_prompt_bytes: bytes
    projected_contexts: tuple[ResolvedPromptContext, ...]
    output_schema: OutputSchemaSpec
    output_schema_bytes: bytes


@dataclass(frozen=True)
class NormalizedProviderResult:
    """Provider-neutral result given to the trusted artifact/result builder."""

    status: InvocationStatus
    provider: str
    model: str
    actual_session_mode: Literal["NEW", "RESUMED"]
    session_ref: str | None
    response_text: str | None
    parsed_output: dict[str, JsonValue] | None
    validated_output: Record | None
    usage: UsageMeasurement | None
    started_at: datetime
    finished_at: datetime
    elapsed_ms: int
    safe_error: str | None


class PromptInputResolver(Protocol):
    async def resolve(self, request: LLMInvocationRequest) -> ResolvedPromptInput: ...


class SecretResolver(Protocol):
    async def resolve(self, reference: SecretReference) -> str: ...


class ProviderSessionStore(Protocol):
    """Persists an opaque local response reference without exposing provider IDs."""

    async def register_response(self, response_id: str, llm_call_id: str) -> str: ...


class InvocationResultBuilder(Protocol):
    """Stores redacted artifacts and creates one exact domain result revision."""

    def build(
        self,
        request: LLMInvocationRequest,
        outcome: NormalizedProviderResult,
    ) -> LLMInvocationResult: ...


class ResponsesResource(Protocol):
    async def create(self, **kwargs: object) -> object: ...


class OpenAIResponsesClient(Protocol):
    responses: ResponsesResource


class OpenAIResponsesClientFactory(Protocol):
    """Creates an official async client just in time with ``max_retries=0``."""

    def open(
        self, api_key: str, *, max_retries: Literal[0]
    ) -> AbstractAsyncContextManager[OpenAIResponsesClient]: ...


class OutputSchemaValidator(Protocol):
    """Validates schema, domain model, and the exact semantic-validator revision."""

    def validate(
        self,
        raw: bytes,
        *,
        schema: dict[str, JsonValue],
        output_schema: OutputSchemaSpec,
        request: LLMInvocationRequest,
    ) -> Record: ...


class ProviderProbeRunner(Protocol):
    async def run(
        self, candidate: ProviderValidationEvidence, adapter: object
    ) -> CapabilityProbeResult: ...


__all__ = [
    "Clock",
    "CredentialUnavailableError",
    "InvocationResultBuilder",
    "NormalizedProviderResult",
    "OpenAIResponsesClient",
    "OpenAIResponsesClientFactory",
    "OutputSchemaValidator",
    "PromptInputResolver",
    "ProviderInputMismatchError",
    "ProviderInvalidOutputError",
    "ProviderProbeRunner",
    "ProviderSessionStore",
    "ResolvedPromptContext",
    "ResolvedPromptInput",
    "SecretResolver",
]
