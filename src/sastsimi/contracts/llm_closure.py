"""Canonical exact-reference closure for one authorized LLM call."""

from .llm import LLMCallSpec, PromptPayload
from .refs import StoredDataRef


def llm_action_input_refs(
    spec_ref: StoredDataRef,
    spec: LLMCallSpec,
    payload: PromptPayload,
) -> tuple[StoredDataRef, ...]:
    """Return every immutable input in one deterministic authorization order."""
    if tuple(binding.source_ref for binding in payload.context_bindings) != tuple(
        spec.context_refs
    ):
        raise ValueError("LLM_ACTION_INPUT_MISMATCH")
    refs = (
        spec_ref,
        spec.prompt_registry_entry_ref,
        spec.prompt_template_ref,
        spec.prompt_payload_ref,
        spec.provider_profile_ref,
        spec.execution_limits_ref,
        spec.retry_policy_ref,
        spec.tool_policy_ref,
        spec.redaction_policy_ref,
        spec.output_schema_ref,
        spec.semantic_validator_ref,
        payload.rendered_prompt_ref,
        *(binding.source_ref for binding in payload.context_bindings),
        *(binding.projected_data_ref for binding in payload.context_bindings),
    )
    if len(refs) != len(set(refs)):
        raise ValueError("LLM_ACTION_INPUT_MISMATCH")
    return refs


__all__ = ["llm_action_input_refs"]
