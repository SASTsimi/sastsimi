"""Exact-reference Prompt Registry publication and active-entry selection."""

from sastsimi.contracts.llm import LLMRole, PromptRegistryEntry, Purpose
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.configuration_registry import ConfigurationRegistryPort
from sastsimi.ports.dto import Record
from sastsimi.ports.record_store import RecordStore
from sastsimi.ports.runtime_query import RuntimeQueryPort


class PromptRegistry:
    """Publish and resolve prompt entries without name/current fallback.

    The storage registry remains responsible for exact dependency closure,
    human approval and R8 recommendation checks.  Selection is fail-closed if
    the requested revision is stale or more than one ACTIVE entry exists for
    the same role, task and purpose.
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

    def publish(self, entry: PromptRegistryEntry) -> StoredDataRef:
        """Publish through the existing approval and closure validator."""
        ref = self._registry.register_prompt_entry(entry)
        self._require_published_exact(ref, entry)
        self._require_current(ref, entry)
        if entry.status == "ACTIVE":
            self._require_only_active(ref, entry)
        return ref

    def require_active(
        self,
        entry_ref: StoredDataRef,
        *,
        agent_role: LLMRole,
        task_kind: str,
        purpose: Purpose,
    ) -> PromptRegistryEntry:
        """Resolve exactly the active entry authorized for one invocation."""
        if not isinstance(entry_ref, StoredDataRef) or (
            entry_ref.data_kind != PromptRegistryEntry.KIND
            or entry_ref.record_id is None
        ):
            raise ValueError("PROMPT_REGISTRY_EXACT_REF_REQUIRED")
        record = self._records.get_exact(entry_ref)
        if not isinstance(record, PromptRegistryEntry):
            raise ValueError("PROMPT_REGISTRY_CLOSURE_MISMATCH")
        self._require_published_exact(entry_ref, record)
        self._require_current(entry_ref, record)
        if (
            record.status != "ACTIVE"
            or record.agent_role != agent_role
            or record.task_kind != task_kind
            or record.purpose != purpose
        ):
            raise ValueError("PROMPT_REGISTRY_SELECTION_MISMATCH")
        self._require_only_active(entry_ref, record)
        return record

    def _require_published_exact(
        self, ref: StoredDataRef, entry: PromptRegistryEntry
    ) -> None:
        expected = reference(entry)
        if not isinstance(ref, StoredDataRef) or ref != expected:
            raise ValueError("PROMPT_REGISTRY_CLOSURE_MISMATCH")
        resolved = self._records.get_exact(ref)
        if resolved != entry:
            raise ValueError("PROMPT_REGISTRY_CLOSURE_MISMATCH")

    def _current_entries(self, entry: PromptRegistryEntry) -> tuple[Record, ...]:
        return self._queries.current_records(
            str(entry.meta.analysis_id), PromptRegistryEntry.KIND
        )

    def _require_current(self, ref: StoredDataRef, entry: PromptRegistryEntry) -> None:
        same_logical = tuple(
            candidate
            for candidate in self._current_entries(entry)
            if candidate.meta.logical_record_id == entry.meta.logical_record_id
        )
        if len(same_logical) != 1 or reference(same_logical[0]) != ref:
            raise ValueError("PROMPT_REGISTRY_NOT_CURRENT")

    def _require_only_active(
        self, ref: StoredDataRef, entry: PromptRegistryEntry
    ) -> None:
        active = tuple(
            candidate
            for candidate in self._current_entries(entry)
            if isinstance(candidate, PromptRegistryEntry)
            and candidate.status == "ACTIVE"
            and (
                candidate.agent_role,
                candidate.task_kind,
                candidate.purpose,
            )
            == (entry.agent_role, entry.task_kind, entry.purpose)
        )
        if len(active) != 1 or reference(active[0]) != ref:
            raise ValueError("PROMPT_REGISTRY_ACTIVE_CONFLICT")
