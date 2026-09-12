"""Production OpenAI SDK and storage-backed adapter composition tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.config.secrets import SecretReference
from sastsimi.contracts.ids import CommitId, WorkspaceId
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.record_store import RecordStore
from sastsimi.providers.base import CredentialUnavailableError
from sastsimi.providers.openai_composition import (
    EnvironmentSecretResolver,
    OfficialOpenAIResponsesClientFactory,
    OpenAISdkUnavailableError,
    StoredProviderSessionStore,
    build_openai_responses_api_adapter,
)
from sastsimi.providers.storage_io import (
    StoredInvocationResultBuilder,
    StoredOutputValidator,
    StoredPromptInputResolver,
)
from sastsimi.runtime.system_support import SystemClock
from sastsimi.storage.artifact_store import LocalArtifactStore


def _provider_ref() -> StoredDataRef:
    return StoredDataRef.model_validate(
        {
            "stored_data_id": "provider-profile",
            "data_kind": "provider_profile",
            "content_hash": "a" * 64,
            "workspace_id": "workspace-1",
            "commit_id": "b" * 40,
            "record_id": "provider-profile-record",
        }
    )


@pytest.mark.asyncio
async def test_environment_secret_and_official_sdk_factory_are_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "test-key-must-not-appear-in-errors"
    monkeypatch.setenv("SASTSIMI_TEST_OPENAI_KEY", secret)
    resolver = EnvironmentSecretResolver()

    assert (
        await resolver.resolve(
            SecretReference(reference="env:SASTSIMI_TEST_OPENAI_KEY")
        )
        == secret
    )

    factory = OfficialOpenAIResponsesClientFactory()
    async with factory.open(secret, max_retries=0) as client:
        assert cast(Any, client).max_retries == 0

    monkeypatch.delenv("SASTSIMI_TEST_OPENAI_KEY")
    with pytest.raises(CredentialUnavailableError) as missing:
        await resolver.resolve(
            SecretReference(reference="env:SASTSIMI_TEST_OPENAI_KEY")
        )
    assert secret not in str(missing.value)


def test_missing_openai_sdk_is_an_explicit_unavailable_capability(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sastsimi.providers import openai_composition

    def unavailable(_name: str) -> Any:
        raise ModuleNotFoundError("do not expose this loader detail")

    monkeypatch.setattr(openai_composition, "_import_module", unavailable)

    with pytest.raises(OpenAISdkUnavailableError, match="OPENAI_SDK_UNAVAILABLE"):
        OfficialOpenAIResponsesClientFactory()


@pytest.mark.asyncio
async def test_storage_backed_composition_keeps_provider_id_out_of_session_ref(
    tmp_path: Path,
) -> None:
    artifacts = LocalArtifactStore(
        tmp_path / "artifacts",
        WorkspaceId("workspace-1"),
        CommitId("b" * 40),
    )
    sessions = StoredProviderSessionStore(artifacts)

    first = await sessions.register_response("resp_private_123", "call-1")
    repeated = await sessions.register_response("resp_private_123", "call-1")

    assert first == repeated
    assert first.startswith("local-response:")
    assert "resp_private_123" not in first
    digest = first.removeprefix("local-response:")
    assert artifacts.path_for(digest).is_file()
    assert b"resp_private_123" not in artifacts.path_for(digest).read_bytes()

    adapter = build_openai_responses_api_adapter(
        provider_profile_ref=_provider_ref(),
        model="gpt-test",
        credential_ref=SecretReference(reference="env:OPENAI_API_KEY"),
        records=cast(RecordStore, object()),
        artifacts=cast(ArtifactStore, artifacts),
        semantic_validators={},
        metadata_factory=cast(Any, lambda *_args: None),
        clock=SystemClock(),
    )

    assert isinstance(adapter.prompt_resolver, StoredPromptInputResolver)
    assert isinstance(adapter.output_schema_validator, StoredOutputValidator)
    assert isinstance(adapter.result_builder, StoredInvocationResultBuilder)
    assert isinstance(adapter.session_store, StoredProviderSessionStore)
    assert isinstance(adapter.client_factory, OfficialOpenAIResponsesClientFactory)
    assert isinstance(adapter.secret_resolver, EnvironmentSecretResolver)
