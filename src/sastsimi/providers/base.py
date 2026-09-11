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
    ProviderValidationEvidence,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.ports.clock import Clock
from sastsimi.ports.dto import CapabilityProbeResult


class CredentialUnavailableError(RuntimeError):
    """The approved credential reference cannot currently be resolved."""


class ProviderInputMismatchError(RuntimeError):
    """The resolved transient prompt is not the exact authorized payload."""


class ProviderInvalidOutputError(RuntimeError):
    """A provider response cannot be used as structured agent output."""


@dataclass(frozen=True)
class ResolvedPromptInput:
    """Transient transport input with trusted and untrusted text kept separate."""

    prompt_payload_ref: StoredDataRef
    prompt_registry_entry_ref: StoredDataRef
    prompt_template_ref: StoredDataRef
    output_schema_ref: StoredDataRef
    instructions: str
    untrusted_input: str


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
    """Maps opaque local session refs without exposing provider response IDs."""

    async def resolve_previous_response_id(self, session_ref: str) -> str: ...
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
    """Checks parsed output against the exact requested JSON Schema revision."""

    def validate(
        self, value: dict[str, JsonValue], schema: dict[str, JsonValue]
    ) -> None: ...


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
    "ResolvedPromptInput",
    "SecretResolver",
]
