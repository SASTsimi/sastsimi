"""LOCAL_EVALUATION publication is narrow and does not weaken Production."""

from contextlib import nullcontext
from dataclasses import replace
from io import BytesIO
from types import MethodType, SimpleNamespace

import pytest

from sastsimi.composition.local_codex_binding import LocalCodexBindingRecords
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.providers.local_codex_validation import validate_local_codex_binding
from sastsimi.storage.configuration_registry import ConfigurationRegistry
from tests.unit.providers.test_local_codex_validation import (
    _Artifacts,
    _Clock,
    _Ids,
    _ProbeRunner,
    _records,
)


class _ReadableArtifacts(_Artifacts):
    def open_verified(self, ref: StoredDataRef) -> BytesIO:
        try:
            return BytesIO(self.values[ref.content_hash])
        except KeyError:
            raise LookupError(ref.content_hash) from None


class _Records:
    def __init__(self, validation: object, client: object, provider: object) -> None:
        self.database = SimpleNamespace(
            engine=SimpleNamespace(connect=lambda: nullcontext(object()))
        )
        self.evidence = SimpleNamespace(llm_configuration_approved=lambda _record: True)
        self._values = {
            reference(validation): validation,
            reference(client): client,
            reference(provider): provider,
        }

    def resolve(self, _connection: object, ref: StoredDataRef) -> object:
        try:
            return self._values[ref]
        except KeyError:
            raise LookupError(ref) from None


def _publish_exact(
    self: ConfigurationRegistry,
    record: object,
    _approved: object,
    _bind: object | None = None,
) -> StoredDataRef:
    del self
    exact = reference(record)  # type: ignore[arg-type]
    assert isinstance(exact, StoredDataRef)
    return exact


@pytest.mark.asyncio
async def test_local_codex_records_publish_only_through_exact_local_evidence() -> None:
    artifacts = _ReadableArtifacts()
    fixture_records = _records()
    provider = fixture_records.provider.model_copy(
        update={
            "capabilities": fixture_records.provider.capabilities.model_copy(
                update={
                    "resume_session": "UNSUPPORTED",
                    "runtime_tool_loop": "UNSUPPORTED",
                }
            ),
            "limitations": (
                *fixture_records.provider.limitations,
                "RESUME_SESSION_UNSUPPORTED",
            ),
        }
    )
    records = LocalCodexBindingRecords(
        validation=fixture_records.validation,
        client=fixture_records.client,
        provider=provider,
        binding=replace(fixture_records.binding, provider_profile=provider),
    )
    validation = await validate_local_codex_binding(
        records=records,
        artifacts=artifacts,  # type: ignore[arg-type]
        ids=_Ids(),
        clock=_Clock(),
        live_runner=_ProbeRunner(),
        unauthenticated_runner=_ProbeRunner(),
        probe_timeout_ms=500,
    )
    registry = ConfigurationRegistry(
        _Records(records.validation, records.client, records.provider),  # type: ignore[arg-type]
        artifacts,  # type: ignore[arg-type]
    )
    registry._publish = MethodType(_publish_exact, registry)  # type: ignore[method-assign]

    with pytest.raises(ValueError, match="PROVIDER_VALIDATION_INCOMPLETE"):
        registry.register_provider_validation(records.validation)

    evidence_ref = validation.evidence_ref
    assert registry.register_local_provider_validation(
        records.validation,
        local_evidence_ref=evidence_ref,
    ) == reference(records.validation)
    assert registry.register_local_client_execution(
        records.client,
        local_evidence_ref=evidence_ref,
    ) == reference(records.client)
    assert registry.register_local_provider_profile(
        records.provider,
        local_evidence_ref=evidence_ref,
    ) == reference(records.provider)
    assert registry.register_local_provider_profile(
        validation.provider,
        local_evidence_ref=evidence_ref,
    ) == reference(validation.provider)

    wrong_scope = StoredDataRef.model_validate(
        evidence_ref.model_dump()
        | {
            "workspace_id": "another-workspace",
            "commit_id": "another-commit",
        }
    )
    with pytest.raises(ValueError, match="LOCAL_PROVIDER_EVIDENCE_INVALID"):
        registry.register_local_provider_profile(
            validation.provider,
            local_evidence_ref=wrong_scope,
        )
