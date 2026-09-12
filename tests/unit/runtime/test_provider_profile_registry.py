from typing import cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import ProviderProfile, ProviderValidationEvidence
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.configuration_registry import ConfigurationRegistryPort
from sastsimi.ports.dto import CapabilityProbeResult, Record
from sastsimi.ports.record_store import RecordStore
from sastsimi.ports.runtime_query import RuntimeQueryPort
from sastsimi.runtime.provider_profile_registry import ProviderProfileRegistry
from tests.contract.domain.canonical_fixtures import make


def _stored(record: Record) -> StoredDataRef:
    ref = reference(record)
    assert isinstance(ref, StoredDataRef)
    return ref


class _Registry:
    def __init__(self, *, error: str | None = None) -> None:
        self.error = error

    def register_provider_validation(
        self, record: ProviderValidationEvidence
    ) -> StoredDataRef:
        if self.error is not None:
            raise ValueError(self.error)
        return _stored(record)

    def register_provider_profile(
        self, record: ProviderProfile, probe: CapabilityProbeResult
    ) -> StoredDataRef:
        del probe
        if self.error is not None:
            raise ValueError(self.error)
        return _stored(record)


class _Records:
    def __init__(self, *records: Record) -> None:
        self.by_ref = {_stored(record): record for record in records}

    def get_exact(self, ref: StoredDataRef) -> Record:
        return self.by_ref[ref]


class _Queries:
    def __init__(self, *records: Record) -> None:
        self.records = records

    def current_records(self, analysis_id: str, kind: str) -> tuple[Record, ...]:
        return tuple(
            record
            for record in self.records
            if str(getattr(record.meta, "analysis_id", "")) == analysis_id
            and record.meta.record_type == kind
        )

    def published_records(self, analysis_id: str) -> tuple[Record, ...]:
        return tuple(
            record
            for record in self.records
            if str(getattr(record.meta, "analysis_id", "")) == analysis_id
        )


def _validation() -> ProviderValidationEvidence:
    return ProviderValidationEvidence.model_validate_json(
        canonical_bytes(make("ProviderValidationEvidence"))
    )


def _profile(validation: ProviderValidationEvidence) -> ProviderProfile:
    return ProviderProfile.model_validate_json(
        canonical_bytes(
            make("ProviderProfile") | {"validation_evidence_ref": _stored(validation)}
        )
    )


def _registry(
    publisher: _Registry, records: _Records, queries: _Queries
) -> ProviderProfileRegistry:
    return ProviderProfileRegistry(
        cast(ConfigurationRegistryPort, publisher),
        cast(RecordStore, records),
        cast(RuntimeQueryPort, queries),
    )


def test_provider_registry_uses_exact_current_supported_refs() -> None:
    validation = _validation()
    profile = _profile(validation)
    records = _Records(validation, profile)
    queries = _Queries(validation, profile)
    registry = _registry(_Registry(), records, queries)

    assert registry.publish_validation(validation) == _stored(validation)
    assert registry.publish_profile(
        profile, CapabilityProbeResult(validation)
    ) == _stored(profile)
    assert registry.require_supported(_stored(profile)) == profile


def test_provider_registry_rejects_unapproved_stale_or_named_refs() -> None:
    validation = _validation()
    profile = _profile(validation)
    publisher = _Registry(error="CONFIGURATION_APPROVAL_REQUIRED")
    registry = _registry(publisher, _Records(profile), _Queries())

    with pytest.raises(ValueError, match="CONFIGURATION_APPROVAL_REQUIRED"):
        registry.publish_profile(profile, CapabilityProbeResult(validation))
    with pytest.raises(ValueError, match="PROVIDER_PROFILE_NOT_CURRENT"):
        registry.require_supported(_stored(profile))
    with pytest.raises(ValueError, match="PROVIDER_PROFILE_EXACT_REF_REQUIRED"):
        registry.require_supported(profile.profile_key)  # type: ignore[arg-type]
