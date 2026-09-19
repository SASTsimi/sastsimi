"""Resolve LOCAL_EVALUATION calls from exact analysis-owned prompt routes."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol, cast

from pydantic import BaseModel

from sastsimi.contracts.llm import LLMRole, PromptInputSlot, PromptRegistryEntry
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState, WorkStatus
from sastsimi.ports.authorized_llm_call import AuthorizedLLMCall
from sastsimi.ports.dto import Record
from sastsimi.ports.llm_invocation import PersistedLLMInvocation
from sastsimi.ports.record_store import RecordStore
from sastsimi.ports.runtime_query import RuntimeQueryPort

from .builder import ArtifactPromptSource, PromptSource
from .local_evaluation import (
    ApprovedLocalEvaluationRoute,
    LocalEvaluationRoute,
    PreparedLocalEvaluationCall,
)


@dataclass(frozen=True, slots=True)
class LocalEvaluationRouteBinding:
    """One exact local route owned by one analysis."""

    analysis_id: str
    route: LocalEvaluationRoute
    approval: ApprovedLocalEvaluationRoute


class LocalEvaluationRouteLookup(Protocol):
    def __call__(
        self, analysis_id: str, role: LLMRole, task_kind: str
    ) -> tuple[
        LocalEvaluationRoute,
        ApprovedLocalEvaluationRoute,
        PromptRegistryEntry,
    ]: ...


class LocalEvaluationConfigurationPort(Protocol):
    def prepare_call(
        self,
        *,
        route: LocalEvaluationRoute,
        approved: ApprovedLocalEvaluationRoute,
        work: WorkExecutionState,
        sources: tuple[PromptSource | ArtifactPromptSource, ...],
    ) -> PreparedLocalEvaluationCall: ...

    def bind_artifact_source(
        self, slot: str, ref: StoredDataRef
    ) -> ArtifactPromptSource: ...


class LocalPreparedCallAuthorizer(Protocol):
    def authorize(
        self, *, work: WorkExecutionState, prepared: PreparedLocalEvaluationCall
    ) -> AuthorizedLLMCall: ...

    def settle(
        self, call: AuthorizedLLMCall, invocation: PersistedLLMInvocation
    ) -> None: ...


class ExactAnalysisLocalEvaluationRouteLookup:
    """Return only a current LOCAL_EVALUATION route for the exact analysis."""

    def __init__(
        self,
        *,
        records: RecordStore,
        queries: RuntimeQueryPort,
        bindings: Iterable[LocalEvaluationRouteBinding],
    ) -> None:
        self._records = records
        self._queries = queries
        indexed: dict[tuple[str, str, str], LocalEvaluationRouteBinding] = {}
        for item in bindings:
            key = (item.analysis_id, str(item.route.role), item.route.task_kind)
            if not item.analysis_id.strip() or key in indexed:
                raise ValueError("LOCAL_EVALUATION_LLM_ROUTE_AMBIGUOUS")
            indexed[key] = item
        self._bindings = indexed

    def __call__(
        self, analysis_id: str, role: LLMRole, task_kind: str
    ) -> tuple[
        LocalEvaluationRoute,
        ApprovedLocalEvaluationRoute,
        PromptRegistryEntry,
    ]:
        key = (analysis_id, str(role), task_kind)
        try:
            binding = self._bindings[key]
        except KeyError:
            raise ValueError("LOCAL_EVALUATION_LLM_ROUTE_NOT_CONFIGURED") from None
        route, approval = binding.route, binding.approval
        try:
            entry = self._records.get_exact(approval.active_prompt_ref)
        except (LookupError, ValueError):
            raise ValueError("LOCAL_EVALUATION_LLM_ROUTE_NOT_CURRENT") from None
        if (
            not isinstance(entry, PromptRegistryEntry)
            or reference(entry) != approval.active_prompt_ref
            or not isinstance(entry.meta, RecordMeta)
            or str(entry.meta.analysis_id) != analysis_id
            or entry.status != "ACTIVE"
            or entry.purpose != "LOCAL_EVALUATION"
            or entry.agent_role != role
            or entry.task_kind != task_kind
            or entry.prompt_key != route.prompt_key
            or entry.session_policy != "NEW"
            or entry.quality_evaluation_ref is not None
            or entry.provider_profile_refs != (approval.provider_profile_ref,)
        ):
            raise ValueError("LOCAL_EVALUATION_LLM_ROUTE_MISMATCH")
        current = tuple(
            candidate
            for candidate in self._queries.current_records(
                analysis_id, PromptRegistryEntry.KIND
            )
            if isinstance(candidate, PromptRegistryEntry)
            and candidate.meta.logical_record_id == entry.meta.logical_record_id
        )
        if len(current) != 1 or reference(current[0]) != approval.active_prompt_ref:
            raise ValueError("LOCAL_EVALUATION_LLM_ROUTE_NOT_CURRENT")
        return route, approval, entry


@dataclass(frozen=True, slots=True)
class ConfiguredLocalEvaluationCallResolver:
    """Prepare and authorize one fresh-session call without Production approval."""

    configuration: LocalEvaluationConfigurationPort
    records: RecordStore
    route_lookup: LocalEvaluationRouteLookup
    authorizer: LocalPreparedCallAuthorizer

    def resolve(
        self,
        *,
        work: WorkExecutionState,
        role: LLMRole,
        task_kind: str,
        source_refs: tuple[StoredDataRef, ...],
    ) -> AuthorizedLLMCall:
        if (
            not isinstance(work.meta, RecordMeta)
            or work.status != WorkStatus.RUNNING
            or work.active_attempt_id is None
            or not source_refs
            or len(source_refs) != len(set(source_refs))
        ):
            raise ValueError("LOCAL_EVALUATION_LLM_CALL_SCOPE_MISMATCH")
        route, approved, entry = self.route_lookup(
            str(work.meta.analysis_id), role, task_kind
        )
        if route.role != role or route.task_kind != task_kind:
            raise ValueError("LOCAL_EVALUATION_LLM_ROUTE_MISMATCH")
        sources = self._sources(work.meta, entry.input_slots, source_refs)
        prepared = self.configuration.prepare_call(
            route=route,
            approved=approved,
            work=work,
            sources=sources,
        )
        spec = prepared.call_spec
        if (
            spec.agent_role != role
            or spec.task_kind != task_kind
            or spec.purpose != "LOCAL_EVALUATION"
            or spec.session_policy != "NEW"
            or spec.parent_session_ref is not None
            or spec.model != route.model
            or spec.provider_profile_ref != approved.provider_profile_ref
            or spec.context_refs != source_refs
        ):
            raise ValueError("LOCAL_EVALUATION_LLM_CALL_SCOPE_MISMATCH")
        call = self.authorizer.authorize(work=work, prepared=prepared)
        if call.work != work or call.call_spec_ref != prepared.call_spec_ref:
            raise ValueError("LOCAL_EVALUATION_LLM_AUTHORIZATION_MISMATCH")
        return call

    def settle(
        self, call: AuthorizedLLMCall, invocation: PersistedLLMInvocation
    ) -> None:
        self.authorizer.settle(call, invocation)

    def _sources(
        self,
        work_meta: RecordMeta,
        slots: tuple[PromptInputSlot, ...],
        refs: tuple[StoredDataRef, ...],
    ) -> tuple[PromptSource | ArtifactPromptSource, ...]:
        slot_by_kind: dict[str, PromptInputSlot] = {}
        for slot in slots:
            kind = str(slot.data_kind)
            if not kind or kind in slot_by_kind:
                raise ValueError("LOCAL_EVALUATION_PROMPT_SOURCE_AMBIGUOUS")
            slot_by_kind[kind] = slot
        sources: list[PromptSource | ArtifactPromptSource] = []
        counts: dict[str, int] = {}
        for ref in refs:
            candidate_slot = slot_by_kind.get(ref.data_kind)
            if ref.data_kind == "artifact" and ref.record_id is None:
                if candidate_slot is None:
                    raise ValueError("LOCAL_EVALUATION_PROMPT_SOURCE_NOT_EXACT")
                name = str(candidate_slot.slot)
                try:
                    source = self.configuration.bind_artifact_source(name, ref)
                except (OSError, ValueError):
                    raise ValueError(
                        "LOCAL_EVALUATION_PROMPT_SOURCE_NOT_EXACT"
                    ) from None
                sources.append(source)
                counts[name] = counts.get(name, 0) + 1
                continue
            try:
                value = self.records.get_exact(ref)
            except (LookupError, ValueError):
                raise ValueError("LOCAL_EVALUATION_PROMPT_SOURCE_NOT_EXACT") from None
            meta = getattr(value, "meta", None)
            if (
                candidate_slot is None
                or not isinstance(value, BaseModel)
                or not isinstance(meta, RecordMeta)
                or reference(cast(Record, value)) != ref
            ):
                raise ValueError("LOCAL_EVALUATION_PROMPT_SOURCE_NOT_EXACT")
            if (
                meta.analysis_id != work_meta.analysis_id
                or meta.workspace_id != work_meta.workspace_id
                or meta.commit_id != work_meta.commit_id
                or (
                    meta.hypothesis_id is not None
                    and meta.hypothesis_id != work_meta.hypothesis_id
                )
            ):
                raise ValueError("LOCAL_EVALUATION_PROMPT_SOURCE_SCOPE_MISMATCH")
            name = str(candidate_slot.slot)
            sources.append(PromptSource(name, ref, value))
            counts[name] = counts.get(name, 0) + 1
        for slot in slots:
            name = str(slot.slot)
            cardinality = str(slot.cardinality)
            count = counts.get(name, 0)
            if (
                cardinality == "REQUIRED_ONE"
                and count != 1
                or cardinality == "OPTIONAL_ONE"
                and count > 1
                or cardinality == "REQUIRED_MANY"
                and count < 1
            ):
                raise ValueError("PROMPT_CARDINALITY_MISMATCH")
        return tuple(sources)


__all__ = [
    "ConfiguredLocalEvaluationCallResolver",
    "ExactAnalysisLocalEvaluationRouteLookup",
    "LocalEvaluationConfigurationPort",
    "LocalEvaluationRouteBinding",
    "LocalEvaluationRouteLookup",
    "LocalPreparedCallAuthorizer",
]
