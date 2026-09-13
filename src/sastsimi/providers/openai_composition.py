"""Production-only composition for the official OpenAI Python SDK."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Mapping
from contextlib import AbstractAsyncContextManager
from importlib import import_module as _stdlib_import_module
from typing import Literal, cast

from sastsimi.config.secrets import SecretReference
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import LLMRole
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.record_store import RecordStore
from sastsimi.prompts.validation import validate_output

from .base import (
    Clock,
    CredentialUnavailableError,
    OpenAIResponsesClient,
    OpenAIResponsesClientFactory,
    ProviderProbeRunner,
    SecretResolver,
)
from .openai_api import OpenAIResponsesApiAdapter
from .storage_io import (
    InvocationMetadataFactory,
    RequestSemanticValidator,
    SemanticValidator,
    StoredInvocationResultBuilder,
    StoredOutputValidator,
    StoredPromptInputResolver,
)

_import_module = _stdlib_import_module


class OpenAISdkUnavailableError(RuntimeError):
    """The required official SDK cannot be loaded in this installation."""


class EnvironmentSecretResolver(SecretResolver):
    """Resolve only explicitly named process environment credentials."""

    async def resolve(self, reference: SecretReference) -> str:
        name = reference.reference.removeprefix("env:")
        if name == reference.reference:
            raise CredentialUnavailableError("CREDENTIAL_UNAVAILABLE")
        value = os.environ.get(name)
        if value is None or not value or value != value.strip():
            raise CredentialUnavailableError("CREDENTIAL_UNAVAILABLE")
        return value


class OfficialOpenAIResponsesClientFactory(OpenAIResponsesClientFactory):
    """Create a short-lived official ``AsyncOpenAI`` client with no SDK retry."""

    def __init__(self) -> None:
        try:
            sdk = _import_module("openai")
            client_type = sdk.AsyncOpenAI
        except (ImportError, AttributeError) as error:
            raise OpenAISdkUnavailableError("OPENAI_SDK_UNAVAILABLE") from error
        if not callable(client_type):
            raise OpenAISdkUnavailableError("OPENAI_SDK_UNAVAILABLE")
        self._client_type = client_type

    def open(
        self, api_key: str, *, max_retries: Literal[0]
    ) -> AbstractAsyncContextManager[OpenAIResponsesClient]:
        if max_retries != 0 or not api_key or api_key != api_key.strip():
            raise ValueError("OPENAI_CLIENT_CONFIGURATION_INVALID")
        client = self._client_type(api_key=api_key, max_retries=0)
        return cast(AbstractAsyncContextManager[OpenAIResponsesClient], client)


class StoredProviderSessionStore:
    """Persist a provider-ID fingerprint and return an opaque local session ref.

    The current OpenAI adapter supports NEW calls only.  The provider response ID is
    therefore never needed again and is deliberately not stored in plaintext.
    """

    def __init__(self, artifacts: ArtifactStore) -> None:
        self._artifacts = artifacts

    async def register_response(self, response_id: str, llm_call_id: str) -> str:
        if (
            not response_id.strip()
            or response_id != response_id.strip()
            or not llm_call_id.strip()
            or llm_call_id != llm_call_id.strip()
        ):
            raise ValueError("PROVIDER_SESSION_ID_INVALID")
        payload = canonical_bytes(
            {
                "llm_call_hash": hashlib.sha256(llm_call_id.encode()).hexdigest(),
                "provider_response_hash": hashlib.sha256(
                    response_id.encode()
                ).hexdigest(),
            }
        )
        ref = self._artifacts.commit(
            self._artifacts.stage_bytes(payload, "application/json")
        )
        return f"local-response:{ref.content_hash}"


def build_openai_responses_api_adapter(
    *,
    provider_profile_ref: StoredDataRef,
    model: str,
    credential_ref: SecretReference,
    records: RecordStore,
    artifacts: ArtifactStore,
    semantic_validators: Mapping[StoredDataRef, SemanticValidator],
    metadata_factory: InvocationMetadataFactory,
    clock: Clock,
    request_semantic_validators: Mapping[tuple[LLMRole, str], RequestSemanticValidator]
    | None = None,
    probe_runner: ProviderProbeRunner | None = None,
) -> OpenAIResponsesApiAdapter:
    """Bind one exact profile/model to real storage and the official SDK only."""

    return OpenAIResponsesApiAdapter(
        provider_profile_ref=provider_profile_ref,
        model=model,
        credential_ref=credential_ref,
        prompt_resolver=StoredPromptInputResolver(records, artifacts),
        secret_resolver=EnvironmentSecretResolver(),
        client_factory=OfficialOpenAIResponsesClientFactory(),
        session_store=StoredProviderSessionStore(artifacts),
        output_schema_validator=StoredOutputValidator(
            records,
            semantic_validators,
            validate_output,
            request_semantic_validators=request_semantic_validators,
        ),
        result_builder=StoredInvocationResultBuilder(
            records, artifacts, metadata_factory
        ),
        clock=clock,
        probe_runner=probe_runner,
    )


__all__ = [
    "EnvironmentSecretResolver",
    "OfficialOpenAIResponsesClientFactory",
    "OpenAISdkUnavailableError",
    "StoredProviderSessionStore",
    "build_openai_responses_api_adapter",
]
