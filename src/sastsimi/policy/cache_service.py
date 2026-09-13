"""Exact-key, run-neutral policy cache selection."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from sastsimi.contracts.policy import (
    PolicyCacheRecord,
    PolicyCollectionResult,
    PolicyParserResult,
    ProgramPolicyRecord,
    validate_policy_collection,
)
from sastsimi.ports.policy_runtime import PolicyCacheKey
from sastsimi.ports.record_store import RecordStore
from sastsimi.runtime.policy_runtime import PolicyRuntimeService

from .program_catalog import ProgramCatalogEntry


@dataclass(frozen=True, slots=True)
class CachedPolicy:
    cache: PolicyCacheRecord
    collection: PolicyCollectionResult
    policy: ProgramPolicyRecord | None
    parsers: tuple[PolicyParserResult, ...]


class PolicyCacheService:
    """Return only a fresh cache whose entire exact record closure still resolves."""

    def __init__(
        self,
        *,
        runtime: PolicyRuntimeService,
        records: RecordStore,
    ) -> None:
        self._runtime = runtime
        self._records = records

    def current(
        self,
        entry: ProgramCatalogEntry,
        *,
        started_at: datetime,
    ) -> CachedPolicy | None:
        key = PolicyCacheKey(
            program_id=entry.program_id,
            source_config_hash=entry.source_config_ref.content_hash,
            parser_name=entry.parser_name,
            parser_version=entry.parser_version,
            freshness_criterion_hash=entry.freshness_criterion_ref.content_hash,
        )
        cache = self._runtime.current_cache(key)
        if (
            cache is None
            or cache.published_at > started_at
            or cache.freshness_valid_until <= started_at
        ):
            return None
        collection = self._records.get_exact(cache.collection_result_ref)
        if not isinstance(collection, PolicyCollectionResult):
            raise ValueError("POLICY_CACHE_CLOSURE_MISMATCH")
        policy = (
            None
            if cache.policy_record_ref is None
            else self._records.get_exact(cache.policy_record_ref)
        )
        if policy is not None and not isinstance(policy, ProgramPolicyRecord):
            raise ValueError("POLICY_CACHE_CLOSURE_MISMATCH")
        parser_values = tuple(
            self._records.get_exact(ref) for ref in cache.parser_result_refs
        )
        if any(not isinstance(value, PolicyParserResult) for value in parser_values):
            raise ValueError("POLICY_CACHE_CLOSURE_MISMATCH")
        parsers = tuple(
            value for value in parser_values if isinstance(value, PolicyParserResult)
        )
        validate_policy_collection(collection, policy, parsers)
        return CachedPolicy(cache, collection, policy, parsers)


__all__ = ["CachedPolicy", "PolicyCacheService"]
