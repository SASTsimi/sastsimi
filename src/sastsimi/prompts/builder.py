"""Exact-reference prompt payload and LLM call-spec construction."""

import hashlib
import json
from dataclasses import dataclass
from typing import cast

from pydantic import BaseModel

from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import (
    ExecutionLimits,
    LLMCallSpec,
    OutputSchemaSpec,
    PromptContextBinding,
    PromptPayload,
    PromptRegistryEntry,
    ProviderProfile,
)
from sastsimi.contracts.prompt_projection import project_prompt_value
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.dto import Record

from .redaction import redact_projected_json, render_provider_prompt
from .registry import LoadedPromptDefinition


@dataclass(frozen=True)
class PromptSource:
    slot: str
    source_ref: StoredDataRef
    value: BaseModel


def _stored_ref(value: BaseModel) -> StoredDataRef:
    exact = reference(cast(Record, value))
    if not isinstance(exact, StoredDataRef):
        raise ValueError("PROMPT_SCOPE_MISMATCH")
    return exact


class PromptBuilder:
    def __init__(self, artifacts: ArtifactStore) -> None:
        self.artifacts = artifacts

    def read_artifact(self, ref: StoredDataRef) -> bytes:
        with self.artifacts.open_verified(ref) as stream:
            return stream.read()

    def _commit(self, data: bytes, media_type: str) -> StoredDataRef:
        return self.artifacts.commit(self.artifacts.stage_bytes(data, media_type))

    def build_payload(
        self,
        *,
        definition: LoadedPromptDefinition,
        registry_entry_ref: StoredDataRef,
        metadata: RecordMeta,
        sources: tuple[PromptSource, ...],
    ) -> PromptPayload:
        entry = definition.entry
        if _stored_ref(entry) != registry_entry_ref:
            raise ValueError("PROMPT_REGISTRY_HASH_MISMATCH")
        if entry.status != "ACTIVE":
            raise ValueError("PROMPT_REGISTRY_NOT_ACTIVE")
        if (
            hashlib.sha256(definition.template).hexdigest()
            != entry.template_ref.content_hash
        ):
            raise ValueError("PROMPT_TEMPLATE_HASH_MISMATCH")
        slots = {str(slot.slot): slot for slot in entry.input_slots}
        seen: dict[str, int] = {}
        bindings: list[PromptContextBinding] = []
        rendered_bindings: list[tuple[str, bytes]] = []
        source_refs: set[bytes] = set()
        for source in sources:
            slot = slots.get(source.slot)
            if slot is None or source.source_ref.data_kind != slot.data_kind:
                raise ValueError("PROMPT_CONTEXT_DENIED")
            if slot.data_kind in entry.forbidden_context_kinds:
                raise ValueError("PROMPT_CONTEXT_DENIED")
            if slot.trust_class != "UNTRUSTED_DATA":
                raise ValueError("PROMPT_TRUST_ESCALATION_DENIED")
            if _stored_ref(source.value) != source.source_ref:
                raise ValueError("PROMPT_SOURCE_REFERENCE_MISMATCH")
            source_key = canonical_bytes(source.source_ref)
            if source_key in source_refs:
                raise ValueError("PROMPT_CONTEXT_DUPLICATE")
            source_refs.add(source_key)
            projected = project_prompt_value(source.value, slot.field_paths)
            redacted = redact_projected_json(projected).data
            projected_ref = self._commit(redacted, "application/json")
            rendered_bindings.append((source.slot, redacted))
            bindings.append(
                PromptContextBinding(
                    slot=source.slot,
                    data_kind=slot.data_kind,
                    source_ref=source.source_ref,
                    projected_data_ref=projected_ref,
                    field_paths=slot.field_paths,
                    trust_class=slot.trust_class,
                )
            )
            seen[source.slot] = seen.get(source.slot, 0) + 1
        for slot in entry.input_slots:
            count = seen.get(str(slot.slot), 0)
            lower, upper = {
                "REQUIRED_ONE": (1, 1),
                "OPTIONAL_ONE": (0, 1),
                "REQUIRED_MANY": (1, None),
                "OPTIONAL_MANY": (0, None),
            }[slot.cardinality]
            if count < lower or (upper is not None and count > upper):
                raise ValueError("PROMPT_CARDINALITY_MISMATCH")
        rendered = render_provider_prompt(definition.template, tuple(rendered_bindings))
        rendered_ref = self._commit(rendered, "text/markdown")
        return PromptPayload(
            meta=metadata,
            registry_entry_ref=registry_entry_ref,
            prompt_key=entry.prompt_key,
            agent_role=entry.agent_role,
            task_kind=entry.task_kind,
            purpose=entry.purpose,
            template_ref=entry.template_ref,
            template_version=entry.template_version,
            context_bindings=tuple(bindings),
            rendered_prompt_ref=rendered_ref,
            output_schema_ref=entry.output_schema_ref,
        )

    def build_call_spec(
        self,
        *,
        entry: PromptRegistryEntry,
        registry_entry_ref: StoredDataRef,
        payload: PromptPayload,
        prompt_payload_ref: StoredDataRef,
        provider: ProviderProfile,
        provider_profile_ref: StoredDataRef,
        limits: ExecutionLimits,
        output_schema: OutputSchemaSpec,
        metadata: RecordMeta,
        llm_call_id: str,
        model: str,
        parent_session_ref: str | None = None,
    ) -> LLMCallSpec:
        if _stored_ref(entry) != registry_entry_ref:
            raise ValueError("PROMPT_REGISTRY_HASH_MISMATCH")
        if entry.status != "ACTIVE":
            raise ValueError("PROMPT_REGISTRY_NOT_ACTIVE")
        if _stored_ref(payload) != prompt_payload_ref:
            raise ValueError("PROMPT_PAYLOAD_HASH_MISMATCH")
        if _stored_ref(provider) != provider_profile_ref:
            raise ValueError("PROVIDER_PROFILE_HASH_MISMATCH")
        if (entry.session_policy == "NEW" and parent_session_ref is not None) or (
            entry.session_policy == "RESUME" and parent_session_ref is None
        ):
            raise ValueError("PROMPT_SESSION_MISMATCH")
        if provider_profile_ref not in entry.provider_profile_refs:
            raise ValueError("PROVIDER_PROFILE_DENIED")
        if provider.support_status != "SUPPORTED" or provider.model != model:
            raise ValueError("PROVIDER_MODEL_MISMATCH")
        capabilities = provider.capabilities
        session_supported = {
            "NEW": capabilities.new_session == "SUPPORTED",
            "RESUME": capabilities.resume_session == "SUPPORTED",
            "AUTO": capabilities.new_session == "SUPPORTED"
            and capabilities.resume_session == "SUPPORTED",
        }[entry.session_policy]
        if (
            capabilities.non_interactive != "SUPPORTED"
            or capabilities.structured_output != "SUPPORTED"
            or not session_supported
        ):
            raise ValueError("PROVIDER_CAPABILITY_MISMATCH")
        if _stored_ref(limits) != entry.execution_limits_ref:
            raise ValueError("PROMPT_LIMITS_MISMATCH")
        if (
            _stored_ref(output_schema) != entry.output_schema_ref
            or output_schema.result_kind != entry.result_kind
        ):
            raise ValueError("PROMPT_OUTPUT_SCHEMA_MISMATCH")
        expected_payload = (
            payload.registry_entry_ref == registry_entry_ref
            and payload.prompt_key == entry.prompt_key
            and payload.agent_role == entry.agent_role
            and payload.task_kind == entry.task_kind
            and payload.purpose == entry.purpose
            and payload.template_ref == entry.template_ref
            and payload.template_version == entry.template_version
            and payload.output_schema_ref == entry.output_schema_ref
        )
        if not expected_payload:
            raise ValueError("PROMPT_PAYLOAD_MISMATCH")
        schema_bytes = self.read_artifact(output_schema.schema_artifact_ref)
        try:
            schema_value = json.loads(schema_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("PROMPT_OUTPUT_SCHEMA_INVALID") from error
        if not isinstance(schema_value, dict):
            raise ValueError("PROMPT_OUTPUT_SCHEMA_INVALID")
        return LLMCallSpec(
            meta=metadata,
            llm_call_id=llm_call_id,
            agent_role=entry.agent_role,
            task_kind=entry.task_kind,
            purpose=entry.purpose,
            provider_profile_ref=provider_profile_ref,
            model=model,
            session_policy=entry.session_policy,
            parent_session_ref=parent_session_ref,
            context_refs=tuple(
                binding.source_ref for binding in payload.context_bindings
            ),
            prompt_registry_entry_ref=registry_entry_ref,
            prompt_key=entry.prompt_key,
            prompt_template_ref=entry.template_ref,
            prompt_template_version=entry.template_version,
            prompt_payload_ref=prompt_payload_ref,
            execution_limits_ref=entry.execution_limits_ref,
            retry_policy_ref=entry.retry_policy_ref,
            tool_policy_ref=entry.tool_policy_ref,
            redaction_policy_ref=entry.redaction_policy_ref,
            semantic_validator_ref=entry.semantic_validator_ref,
            output_schema_ref=entry.output_schema_ref,
            output_schema=canonical_bytes(schema_value).decode("utf-8"),
            token_budget=limits.token_budget,
            timeout_ms=limits.timeout_ms,
        )
