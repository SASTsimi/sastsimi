"""Trusted construction of the run-local frozen policy record chain."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sastsimi.agents.policy_parser import ParsedPolicyContent, PolicyItemContent
from sastsimi.contracts.ids import ErrorId, GapId, RecordId
from sastsimi.contracts.policy import (
    POLICY_ITEM_FIELDS,
    PolicyCacheRecord,
    PolicyCollectionResult,
    PolicyItem,
    PolicyMissingInfo,
    PolicyParserResult,
    PolicySourceCheck,
    ProgramPolicyRecord,
    RunPolicyState,
    validate_policy_cache_reuse,
    validate_policy_collection,
    validate_run_policy,
)
from sastsimi.contracts.refs import PolicyCacheRef, StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.policy.program_catalog import ProgramCatalogEntry
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.ports.policy_runtime import PolicyCacheKey
from sastsimi.runtime.policy_runtime import PolicyRuntimeService
from sastsimi.runtime.workflow_runner import WorkflowRunner

from .cache_service import CachedPolicy


@dataclass(frozen=True, slots=True)
class CollectedPolicy:
    parser: PolicyParserResult | None
    collection: PolicyCollectionResult
    policy: ProgramPolicyRecord | None
    cache: PolicyCacheRecord | None
    state: RunPolicyState

    def outputs(self) -> tuple[object, ...]:
        values: list[object] = [self.collection]
        if self.policy is not None:
            values.append(self.policy)
        if self.cache is not None:
            values.append(self.cache)
        values.append(self.state)
        return tuple(values)


class PolicyCollector:
    """Own IDs, exact references, freshness and final policy state semantics."""

    def __init__(
        self,
        *,
        runner: WorkflowRunner,
        policy_runtime: PolicyRuntimeService,
        ids: IdGenerator,
        clock: Clock,
    ) -> None:
        self._runner = runner
        self._policy_runtime = policy_runtime
        self._ids = ids
        self._clock = clock

    def collected(
        self,
        *,
        work: WorkExecutionState,
        preparing: RunPolicyState,
        entry: ProgramCatalogEntry,
        source_check: PolicySourceCheck,
        parser: PolicyParserResult,
        parser_ref: StoredDataRef,
        content: ParsedPolicyContent,
        run_started_at: datetime,
    ) -> CollectedPolicy:
        content.require_document_status()
        if (
            parser.status != "SUCCEEDED"
            or reference(parser) != parser_ref
            or parser.source_ref != source_check.source_ref
            or parser.parser_name != entry.parser_name
            or parser.parser_version != entry.parser_version
        ):
            raise ValueError("POLICY_PARSER_CLOSURE_MISMATCH")
        if content.document_status == "ABSENT_CONFIRMED" and any(
            getattr(content, field) for field in POLICY_ITEM_FIELDS
        ):
            raise ValueError("POLICY_ABSENCE_CONTENT_MISMATCH")

        now = self._clock.now()
        current = source_check.status == "VERIFIED" and bool(source_check.evidence_refs)
        valid_until = source_check.checked_at + timedelta(
            seconds=entry.freshness_ttl_seconds
        )
        current = current and valid_until > run_started_at
        policy: ProgramPolicyRecord | None = None
        gap_ids: tuple[GapId, ...] = ()
        item_values: dict[str, tuple[PolicyItem, ...]] = {}
        item_ids: dict[str, str] = {}
        for field in POLICY_ITEM_FIELDS:
            values = tuple(
                self._item(value, source_check.source_ref, item_ids)
                for value in getattr(content, field)
            )
            item_values[field] = values
        missing = tuple(
            PolicyMissingInfo(
                missing_info_id=str(self._ids.new(RecordId)),
                area=value.area,
                blocks_allow=value.blocks_allow,
                description=value.description,
                policy_item_ids=tuple(
                    self._require_item_key(item_ids, key)
                    for key in value.policy_item_keys
                ),
                evidence_refs=(source_check.source_ref,),
            )
            for value in content.missing_information
        )
        if content.document_status == "ABSENT_CONFIRMED":
            gap_ids = (self._ids.new(GapId),)
        else:
            policy = ProgramPolicyRecord.model_validate(
                dict(
                    meta=self._runner.metadata(
                        work.meta,
                        "program_policy_record",
                        attempt_id=work.active_attempt_id,
                    ),
                    policy_record_id=str(self._ids.new(RecordId)),
                    program_id=entry.program_id,
                    preparation_source="COLLECTED",
                    source_cache_ref=None,
                    program_namespace=entry.program_namespace,
                    external_program_id=entry.external_program_id,
                    policy_version=content.policy_version,
                    fetched_at=source_check.checked_at,
                    freshness_status="CURRENT" if current else "UNVERIFIED",
                    freshness_checked_at=now,
                    **item_values,
                    parser_version=entry.parser_version,
                    source_refs=(source_check.source_ref,),
                    source_checks=(source_check,),
                    parser_result_refs=(parser_ref,),
                    freshness_criterion_ref=entry.freshness_criterion_ref,
                    freshness_evidence_refs=source_check.evidence_refs,
                    freshness_valid_until=valid_until,
                    missing_information=missing,
                    freshness_warning=None
                    if current
                    else "Official policy freshness could not be confirmed",
                )
            )
        collection = PolicyCollectionResult.model_validate(
            dict(
                meta=self._runner.metadata(
                    work.meta,
                    "policy_collection_result",
                    attempt_id=work.active_attempt_id,
                ),
                collection_result_id=str(self._ids.new(RecordId)),
                program_id=entry.program_id,
                preparation_source="COLLECTED",
                source_cache_ref=None,
                status=content.document_status,
                official_source_refs=(source_check.source_ref,),
                parser_result_refs=(parser_ref,),
                policy_record_ref=None if policy is None else reference(policy),
                gap_ids=gap_ids,
                error_ids=(),
                completed_at=now,
            )
        )
        validate_policy_collection(collection, policy, (parser,))
        cache: PolicyCacheRecord | None = None
        state_status = "UNVERIFIED"
        if current:
            state_status = "CURRENT" if policy is not None else "ABSENT"
            key = self.cache_key(entry)
            previous = self._policy_runtime.current_cache(key)
            cache = PolicyCacheRecord.model_validate(
                dict(
                    meta=self._policy_runtime.cache_metadata(
                        key,
                        schema_version=preparing.meta.schema_version,
                        previous=previous,
                    ),
                    source_config_ref=entry.source_config_ref,
                    parser_name=entry.parser_name,
                    parser_version=entry.parser_version,
                    collection_status=collection.status,
                    collection_result_ref=reference(collection),
                    parser_result_refs=(parser_ref,),
                    policy_record_ref=None if policy is None else reference(policy),
                    freshness_criterion_ref=entry.freshness_criterion_ref,
                    freshness_checked_at=now,
                    freshness_evidence_refs=source_check.evidence_refs,
                    freshness_valid_until=valid_until,
                    published_at=now,
                )
            )
        state = self._state(
            work=work,
            preparing=preparing,
            status=state_status,
            preparation_source="COLLECTED",
            collection=collection,
            policy=policy,
            cache=cache,
            entry=entry,
            checked_at=now,
            evidence_refs=source_check.evidence_refs,
            valid_until=valid_until,
        )
        validate_run_policy(
            state,
            collection,
            policy,
            started_at=run_started_at,
            cache=cache,
        )
        return CollectedPolicy(parser, collection, policy, cache, state)

    def failed(
        self,
        *,
        work: WorkExecutionState,
        preparing: RunPolicyState,
        entry: ProgramCatalogEntry,
        error_id: ErrorId,
        terminal_status: str,
        run_started_at: datetime,
        source_ref: StoredDataRef | None = None,
        parser: PolicyParserResult | None = None,
        parser_ref: StoredDataRef | None = None,
    ) -> CollectedPolicy:
        if terminal_status not in {"BLOCKED", "FAILED"}:
            raise ValueError("POLICY_FAILURE_STATUS_INVALID")
        official_refs = () if source_ref is None else (source_ref,)
        parser_refs = () if parser_ref is None else (parser_ref,)
        collection = PolicyCollectionResult.model_validate(
            dict(
                meta=self._runner.metadata(
                    work.meta,
                    "policy_collection_result",
                    attempt_id=work.active_attempt_id,
                ),
                collection_result_id=str(self._ids.new(RecordId)),
                program_id=entry.program_id,
                preparation_source="COLLECTED",
                source_cache_ref=None,
                status="COLLECTION_FAILED",
                official_source_refs=official_refs,
                parser_result_refs=parser_refs,
                policy_record_ref=None,
                gap_ids=(),
                error_ids=(error_id,),
                completed_at=self._clock.now(),
            )
        )
        validate_policy_collection(
            collection,
            None,
            () if parser is None else (parser,),
        )
        state = self._state(
            work=work,
            preparing=preparing,
            status=terminal_status,
            preparation_source="COLLECTED",
            collection=collection,
            policy=None,
            cache=None,
            entry=entry,
            checked_at=None,
            evidence_refs=(),
            valid_until=None,
        )
        validate_run_policy(
            state,
            collection,
            None,
            started_at=run_started_at,
        )
        return CollectedPolicy(parser, collection, None, None, state)

    def reused(
        self,
        *,
        work: WorkExecutionState,
        preparing: RunPolicyState,
        entry: ProgramCatalogEntry,
        cached: CachedPolicy,
        run_started_at: datetime,
    ) -> CollectedPolicy:
        cache_ref = reference(cached.cache)
        if not isinstance(cache_ref, PolicyCacheRef):
            raise ValueError("POLICY_CACHE_REFERENCE_MISMATCH")
        policy: ProgramPolicyRecord | None = None
        if cached.policy is not None:
            policy = ProgramPolicyRecord.model_validate(
                cached.policy.model_dump()
                | dict(
                    meta=self._runner.metadata(
                        work.meta,
                        "program_policy_record",
                        attempt_id=work.active_attempt_id,
                    ),
                    policy_record_id=str(self._ids.new(RecordId)),
                    preparation_source="REUSED_CACHE",
                    source_cache_ref=cache_ref,
                )
            )
        collection = PolicyCollectionResult.model_validate(
            cached.collection.model_dump()
            | dict(
                meta=self._runner.metadata(
                    work.meta,
                    "policy_collection_result",
                    attempt_id=work.active_attempt_id,
                ),
                collection_result_id=str(self._ids.new(RecordId)),
                preparation_source="REUSED_CACHE",
                source_cache_ref=cache_ref,
                policy_record_ref=None if policy is None else reference(policy),
                completed_at=self._clock.now(),
            )
        )
        validate_policy_cache_reuse(
            cached.cache,
            cache_ref,
            cached.collection,
            cached.policy,
            cached.parsers,
            collection,
            policy,
            started_at=run_started_at,
        )
        state = self._state(
            work=work,
            preparing=preparing,
            status="CURRENT" if policy is not None else "ABSENT",
            preparation_source="REUSED_CACHE",
            collection=collection,
            policy=policy,
            cache=cached.cache,
            entry=entry,
            checked_at=cached.cache.freshness_checked_at,
            evidence_refs=cached.cache.freshness_evidence_refs,
            valid_until=cached.cache.freshness_valid_until,
        )
        validate_run_policy(
            state,
            collection,
            policy,
            started_at=run_started_at,
            cache=cached.cache,
        )
        return CollectedPolicy(None, collection, policy, None, state)

    def cache_key(self, entry: ProgramCatalogEntry) -> PolicyCacheKey:
        return PolicyCacheKey(
            program_id=entry.program_id,
            source_config_hash=entry.source_config_ref.content_hash,
            parser_name=entry.parser_name,
            parser_version=entry.parser_version,
            freshness_criterion_hash=entry.freshness_criterion_ref.content_hash,
        )

    def _state(
        self,
        *,
        work: WorkExecutionState,
        preparing: RunPolicyState,
        status: str,
        preparation_source: str,
        collection: PolicyCollectionResult,
        policy: ProgramPolicyRecord | None,
        cache: PolicyCacheRecord | None,
        entry: ProgramCatalogEntry,
        checked_at: datetime | None,
        evidence_refs: tuple[StoredDataRef, ...],
        valid_until: datetime | None,
    ) -> RunPolicyState:
        return RunPolicyState.model_validate(
            preparing.model_dump()
            | dict(
                meta=self._runner.revision_metadata(preparing.meta),
                status=status,
                preparation_source=preparation_source,
                policy_work_ref=reference(work),
                policy_cache_ref=None if cache is None else reference(cache),
                collection_result_ref=reference(collection),
                policy_record_ref=None if policy is None else reference(policy),
                freshness_criterion_ref=entry.freshness_criterion_ref
                if checked_at is not None
                else None,
                freshness_checked_at=checked_at,
                freshness_evidence_refs=evidence_refs,
                freshness_valid_until=valid_until,
            )
        )

    def _item(
        self,
        value: PolicyItemContent,
        source_ref: StoredDataRef,
        item_ids: dict[str, str],
    ) -> PolicyItem:
        if value.item_key in item_ids:
            raise ValueError("DUPLICATE_POLICY_ITEM_KEY")
        item_id = str(self._ids.new(RecordId))
        item_ids[value.item_key] = item_id
        return PolicyItem(
            policy_item_id=item_id,
            value=value.value,
            description=value.description,
            conditions=value.conditions,
            source_ref=source_ref,
            source_locator=value.source_locator,
        )

    @staticmethod
    def _require_item_key(item_ids: dict[str, str], key: str) -> str:
        try:
            return item_ids[key]
        except KeyError as error:
            raise ValueError("POLICY_MISSING_INFO_ITEM_UNKNOWN") from error


__all__ = ["CollectedPolicy", "PolicyCollector"]
