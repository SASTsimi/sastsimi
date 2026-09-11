from typing import cast

import pytest

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import PromptRegistryEntry
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.configuration_registry import ConfigurationRegistryPort
from sastsimi.ports.dto import Record
from sastsimi.ports.record_store import RecordStore
from sastsimi.ports.runtime_query import RuntimeQueryPort
from sastsimi.runtime.prompt_registry import PromptRegistry
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import ref


def _stored(record: Record) -> StoredDataRef:
    ref = reference(record)
    assert isinstance(ref, StoredDataRef)
    return ref


class _Registry:
    def __init__(self, *, error: str | None = None) -> None:
        self.error = error

    def register_prompt_entry(self, record: PromptRegistryEntry) -> StoredDataRef:
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


def _entry(**changes: object) -> PromptRegistryEntry:
    data = make("PromptRegistryEntry") | {
        "purpose": "EVALUATION",
        "status": "ACTIVE",
        "quality_evaluation_ref": None,
        "provider_profile_refs": (ref("provider_profile"),),
    }
    return PromptRegistryEntry.model_validate_json(canonical_bytes(data | changes))


def _registry(
    publisher: _Registry, records: _Records, queries: _Queries
) -> PromptRegistry:
    return PromptRegistry(
        cast(ConfigurationRegistryPort, publisher),
        cast(RecordStore, records),
        cast(RuntimeQueryPort, queries),
    )


def test_prompt_registry_publishes_and_resolves_exact_active_evaluation_entry() -> None:
    entry = _entry()
    registry = _registry(_Registry(), _Records(entry), _Queries(entry))

    assert registry.publish(entry) == _stored(entry)
    assert (
        registry.require_active(
            _stored(entry),
            agent_role=entry.agent_role,
            task_kind=entry.task_kind,
            purpose="EVALUATION",
        )
        == entry
    )


def test_prompt_registry_rejects_stale_purpose_mismatch_and_active_conflict() -> None:
    entry = _entry()
    registry = _registry(_Registry(), _Records(entry), _Queries())
    with pytest.raises(ValueError, match="PROMPT_REGISTRY_NOT_CURRENT"):
        registry.require_active(
            _stored(entry),
            agent_role=entry.agent_role,
            task_kind=entry.task_kind,
            purpose="EVALUATION",
        )

    registry = _registry(_Registry(), _Records(entry), _Queries(entry))
    with pytest.raises(ValueError, match="PROMPT_REGISTRY_SELECTION_MISMATCH"):
        registry.require_active(
            _stored(entry),
            agent_role=entry.agent_role,
            task_kind=entry.task_kind,
            purpose="PRODUCTION",
        )

    duplicate = _entry(
        meta=make("PromptRegistryEntry")["meta"]
        | {
            "record_id": "rec-prompt-duplicate",
            "logical_record_id": "logical-prompt-duplicate",
        }
    )
    registry = _registry(
        _Registry(), _Records(entry, duplicate), _Queries(entry, duplicate)
    )
    with pytest.raises(ValueError, match="PROMPT_REGISTRY_ACTIVE_CONFLICT"):
        registry.require_active(
            _stored(entry),
            agent_role=entry.agent_role,
            task_kind=entry.task_kind,
            purpose="EVALUATION",
        )


def test_prompt_registry_does_not_bypass_r8_or_human_approval_checks() -> None:
    entry = _entry()
    registry = _registry(
        _Registry(error="QUALITY_EVIDENCE_MISMATCH"),
        _Records(entry),
        _Queries(entry),
    )

    with pytest.raises(ValueError, match="QUALITY_EVIDENCE_MISMATCH"):
        registry.publish(entry)
    with pytest.raises(ValueError, match="PROMPT_REGISTRY_EXACT_REF_REQUIRED"):
        registry.require_active(
            entry.prompt_key,  # type: ignore[arg-type]
            agent_role=entry.agent_role,
            task_kind=entry.task_kind,
            purpose="EVALUATION",
        )
