"""Exact-reference Provider profile publication and selection facade."""

from sastsimi.contracts.llm import ProviderProfile, ProviderValidationEvidence
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.configuration_registry import ConfigurationRegistryPort
from sastsimi.ports.dto import CapabilityProbeResult, Record
from sastsimi.ports.record_store import RecordStore
from sastsimi.ports.runtime_query import RuntimeQueryPort


class ProviderProfileRegistry:
    """Expose only approved publication and exact current profile resolution.

    PVD completeness and human approval remain authoritative in the injected
    ``ConfigurationRegistryPort``.  This facade deliberately has no key/name
    lookup and never substitutes a different current revision.
    """

    def __init__(
        self,
        registry: ConfigurationRegistryPort,
        records: RecordStore,
        queries: RuntimeQueryPort,
    ) -> None:
        self._registry = registry
        self._records = records
        self._queries = queries

    def publish_validation(
        self, validation: ProviderValidationEvidence
    ) -> StoredDataRef:
        """Publish PVD evidence through the approval-enforcing registry."""
        ref = self._registry.register_provider_validation(validation)
        self._require_published_exact(ref, validation)
        self._require_current(ref, validation)
        return ref

    def publish_profile(
        self, profile: ProviderProfile, probe: CapabilityProbeResult
    ) -> StoredDataRef:
        """Publish one profile only through PVD and human approval checks."""
        ref = self._registry.register_provider_profile(profile, probe)
        self._require_published_exact(ref, profile)
        self._require_current(ref, profile)
        return ref

    def require_supported(self, profile_ref: StoredDataRef) -> ProviderProfile:
        """Resolve this exact current SUPPORTED profile or fail closed."""
        if not isinstance(profile_ref, StoredDataRef) or (
            profile_ref.data_kind != ProviderProfile.KIND
            or profile_ref.record_id is None
        ):
            raise ValueError("PROVIDER_PROFILE_EXACT_REF_REQUIRED")
        record = self._records.get_exact(profile_ref)
        if not isinstance(record, ProviderProfile):
            raise ValueError("PROVIDER_PROFILE_CLOSURE_MISMATCH")
        self._require_published_exact(profile_ref, record)
        self._require_current(profile_ref, record)
        if record.support_status != "SUPPORTED":
            raise ValueError("PROVIDER_PROFILE_NOT_SUPPORTED")
        return record

    def _require_published_exact(
        self,
        ref: StoredDataRef,
        record: ProviderProfile | ProviderValidationEvidence,
    ) -> None:
        expected = reference(record)
        if not isinstance(ref, StoredDataRef) or ref != expected:
            raise ValueError("PROVIDER_PROFILE_CLOSURE_MISMATCH")
        resolved = self._records.get_exact(ref)
        if resolved != record:
            raise ValueError("PROVIDER_PROFILE_CLOSURE_MISMATCH")

    def _require_current(
        self,
        ref: StoredDataRef,
        record: ProviderProfile | ProviderValidationEvidence,
    ) -> None:
        current = self._queries.current_records(
            str(record.meta.analysis_id), record.meta.record_type
        )
        same_logical: tuple[Record, ...] = tuple(
            candidate
            for candidate in current
            if candidate.meta.logical_record_id == record.meta.logical_record_id
        )
        if len(same_logical) != 1 or reference(same_logical[0]) != ref:
            raise ValueError("PROVIDER_PROFILE_NOT_CURRENT")
