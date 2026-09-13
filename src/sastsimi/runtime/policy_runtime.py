"""Public runtime service for policy preparation and exact cache selection."""

from sastsimi.contracts.ids import RecordId
from sastsimi.contracts.policy import PolicyCacheRecord, RunPolicyState
from sastsimi.contracts.records import PolicyCacheMeta
from sastsimi.contracts.refs import RecordRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.ports.policy_runtime import (
    PolicyCacheKey,
    PolicyPreparation,
    PolicyRuntimePort,
)


class PolicyRuntimeService:
    def __init__(
        self,
        store: PolicyRuntimePort,
        clock: Clock,
        ids: IdGenerator,
    ) -> None:
        self.store = store
        self.clock = clock
        self.ids = ids

    def begin(
        self,
        work: WorkExecutionState,
        decision_ref: RecordRef,
        reservation_ref: RecordRef,
        state: RunPolicyState,
    ) -> PolicyPreparation:
        return self.store.begin(work, decision_ref, reservation_ref, state)

    def reject_preparing(self, work: WorkExecutionState) -> None:
        self.store.reject_preparing(work)

    def current_state(self, analysis_id: str) -> RunPolicyState | None:
        return self.store.current_state(analysis_id)

    def current_cache(self, key: PolicyCacheKey) -> PolicyCacheRecord | None:
        return self.store.current_cache(key)

    def cache_metadata(
        self,
        key: PolicyCacheKey,
        *,
        schema_version: str,
        previous: PolicyCacheRecord | None = None,
    ) -> PolicyCacheMeta:
        """Issue runtime-owned metadata for one exact cache-key revision chain."""
        if previous is not None and PolicyCacheKey.from_record(previous) != key:
            raise ValueError("POLICY_CACHE_KEY_MISMATCH")
        return PolicyCacheMeta.model_validate(
            dict(
                record_id=self.ids.new(RecordId),
                logical_record_id=key.logical_record_id,
                record_type="policy_cache_record",
                schema_version=schema_version,
                revision_number=1
                if previous is None
                else previous.meta.revision_number + 1,
                previous_record_id=None
                if previous is None
                else previous.meta.record_id,
                created_at=self.clock.now(),
                program_id=key.program_id,
            )
        )
