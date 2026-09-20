"""Prepare exact prompt calls through an injected authority boundary."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, cast

from pydantic import BaseModel

from sastsimi.contracts.llm import LLMRole, PromptInputSlot
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import StaticFactBundle
from sastsimi.contracts.work import WorkExecutionState, WorkStatus
from sastsimi.ports.authorized_llm_call import AuthorizedLLMCall
from sastsimi.ports.dto import Record
from sastsimi.ports.llm_invocation import PersistedLLMInvocation
from sastsimi.ports.production_prompt import (
    ApprovedProductionRoute,
    PreparedProductionCall,
    ProductionRoute,
)
from sastsimi.ports.record_store import RecordStore
from sastsimi.prompts.builder import (
    ArtifactPromptSource,
    ProjectedPromptSource,
    PromptSource,
)
from sastsimi.prompts.production import ProductionLLMConfigurationService
from sastsimi.prompts.static_projection import project_hypothesis_static_bundle


class ProductionRouteLookup(Protocol):
    """Resolve an analysis-owned route and its exact approval graph."""

    def __call__(
        self, analysis_id: str, role: LLMRole, task_kind: str
    ) -> tuple[ProductionRoute, ApprovedProductionRoute]: ...


class PreparedCallAuthorizer(Protocol):
    """Attach budget and action authority after prompt preparation."""

    def authorize(
        self, *, work: WorkExecutionState, prepared: PreparedProductionCall
    ) -> AuthorizedLLMCall: ...

    def settle(
        self, call: AuthorizedLLMCall, invocation: PersistedLLMInvocation
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class ConfiguredProductionCallResolver:
    """Build a call from the exact route selected for this analysis.

    The route lookup is keyed by ``analysis_id``.  Consequently a handler
    cannot silently reuse another analysis's prompt approval, Provider, or
    model.  The configuration service additionally verifies their exact refs.
    """

    configuration: ProductionLLMConfigurationService
    records: RecordStore
    route_lookup: ProductionRouteLookup
    authorizer: PreparedCallAuthorizer

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
            raise ValueError("PRODUCTION_LLM_CALL_SCOPE_MISMATCH")
        route, approval = self.route_lookup(str(work.meta.analysis_id), role, task_kind)
        if route.role != role or route.task_kind != task_kind:
            raise ValueError("PRODUCTION_LLM_ROUTE_MISMATCH")
        resolved = self.configuration.resolve_route(route=route, approval=approval)
        sources = self._sources(
            work.meta,
            resolved.entry.input_slots,
            source_refs,
            role=role,
            task_kind=task_kind,
        )
        prepared = self.configuration.prepare_call(
            route=route,
            approval=approval,
            work=work,
            sources=sources,
        )
        if (
            prepared.call_spec.agent_role != role
            or prepared.call_spec.task_kind != task_kind
            or prepared.call_spec.model != route.model
            or prepared.call_spec.provider_profile_ref != resolved.provider_ref
            or prepared.call_spec.context_refs != source_refs
        ):
            raise ValueError("PRODUCTION_LLM_CALL_SCOPE_MISMATCH")
        call = self.authorizer.authorize(work=work, prepared=prepared)
        if call.work != work or call.call_spec_ref != prepared.call_spec_ref:
            raise ValueError("PRODUCTION_LLM_AUTHORIZATION_MISMATCH")
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
        *,
        role: LLMRole,
        task_kind: str,
    ) -> tuple[
        PromptSource | ProjectedPromptSource | ArtifactPromptSource, ...
    ]:
        # PromptInputSlot is deliberately consumed structurally so this adapter
        # does not introduce another prompt-contract model.
        slot_by_kind: dict[str, PromptInputSlot] = {}
        for slot in slots:
            kind = str(slot.data_kind)
            if not kind or kind in slot_by_kind:
                raise ValueError("PRODUCTION_PROMPT_SOURCE_AMBIGUOUS")
            slot_by_kind[kind] = slot
        sources: list[
            PromptSource | ProjectedPromptSource | ArtifactPromptSource
        ] = []
        counts: dict[str, int] = {}
        for ref in refs:
            candidate_slot = slot_by_kind.get(ref.data_kind)
            if ref.data_kind == "artifact" and ref.record_id is None:
                if candidate_slot is None:
                    raise ValueError("PRODUCTION_PROMPT_SOURCE_NOT_EXACT")
                name = str(candidate_slot.slot)
                try:
                    source = self.configuration.bind_artifact_source(name, ref)
                except (OSError, ValueError) as error:
                    raise ValueError("PRODUCTION_PROMPT_SOURCE_NOT_EXACT") from error
                sources.append(source)
                counts[name] = counts.get(name, 0) + 1
                continue
            try:
                value = self.records.get_exact(ref)
            except (LookupError, ValueError) as error:
                raise ValueError("PRODUCTION_PROMPT_SOURCE_NOT_EXACT") from error
            meta = getattr(value, "meta", None)
            if (
                candidate_slot is None
                or not isinstance(value, BaseModel)
                or not isinstance(meta, RecordMeta)
                or reference(cast(Record, value)) != ref
            ):
                raise ValueError("PRODUCTION_PROMPT_SOURCE_NOT_EXACT")
            if (
                meta.analysis_id != work_meta.analysis_id
                or meta.workspace_id != work_meta.workspace_id
                or meta.commit_id != work_meta.commit_id
                or (
                    meta.hypothesis_id is not None
                    and meta.hypothesis_id != work_meta.hypothesis_id
                )
            ):
                raise ValueError("PRODUCTION_PROMPT_SOURCE_SCOPE_MISMATCH")
            name = str(candidate_slot.slot)
            if isinstance(value, StaticFactBundle):
                sources.append(
                    ProjectedPromptSource(
                        name,
                        ref,
                        value,
                        project_hypothesis_static_bundle(value),
                    )
                )
            else:
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
