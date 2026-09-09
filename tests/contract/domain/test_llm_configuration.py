"""The fake adapter consumes the same exact configuration as later providers."""

import importlib
import json
from typing import Any

import pytest

from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import ref
from tests.contract.domain.test_inventory import canonical_fields


@pytest.mark.parametrize(
    "name",
    [
        "ProviderCapabilities",
        "ProviderValidationTest",
        "ProviderValidationEvidence",
        "ClientExecutionProfile",
        "ProviderProfile",
        "ExecutionLimits",
        "LLMRetryPolicy",
        "LLMToolPolicy",
        "PromptRedactionPolicy",
        "OutputSchemaSpec",
        "SemanticValidatorSpec",
        "PromptInputSlot",
        "PromptRegistryEntry",
        "PromptContextBinding",
        "PromptPayload",
        "LLMCallSpec",
    ],
)
def test_llm_configuration_exact_canonical_fields(name: str) -> None:
    module = importlib.import_module("sastsimi.contracts.llm")
    model = getattr(module, name)
    assert set(model.model_fields) == set(canonical_fields()[name])
    assert all(field.is_required() for field in model.model_fields.values())


@pytest.mark.parametrize(
    "name,kind",
    [
        ("ProviderValidationEvidence", "provider_validation_evidence"),
        ("ClientExecutionProfile", "client_execution_profile"),
        ("ProviderProfile", "provider_profile"),
        ("ExecutionLimits", "execution_limits"),
        ("LLMRetryPolicy", "llm_retry_policy"),
        ("LLMToolPolicy", "llm_tool_policy"),
        ("PromptRedactionPolicy", "prompt_redaction_policy"),
        ("OutputSchemaSpec", "output_schema_spec"),
        ("SemanticValidatorSpec", "semantic_validator_spec"),
        ("PromptRegistryEntry", "prompt_registry_entry"),
        ("PromptPayload", "prompt_payload"),
        ("LLMCallSpec", "llm_call_spec"),
    ],
)
def test_config_and_call_records_survive_codec(name: str, kind: str) -> None:
    from sastsimi.storage.codec import decode, encode

    module = importlib.import_module("sastsimi.contracts.llm")
    data = make(name, kind)
    if name == "ProviderProfile":
        data["validation_evidence_ref"] = ref("provider_validation_evidence")
    if name == "PromptRegistryEntry":
        data["provider_profile_refs"] = [ref("provider_profile")]
    if name == "PromptRedactionPolicy":
        data["fail_closed"] = True
    record = getattr(module, name).model_validate_json(json.dumps(data))
    assert decode(kind, encode(record)) == record


@pytest.mark.parametrize(
    "changes",
    [
        {"product": "CLAUDE_CODE"},
        {"transport": "MESSAGES_API"},
        {"auth_mode": "SUBSCRIPTION_LOGIN"},
        {"client_execution_profile_ref": ref("client_execution_profile")},
        {"validation_evidence_ref": ref("provider_validation_evidence", record=False)},
    ],
)
def test_provider_profile_rejects_invalid_transport_identity(
    changes: dict[str, Any],
) -> None:
    from sastsimi.contracts.llm import ProviderProfile

    data = make("ProviderProfile") | dict(
        validation_evidence_ref=ref("provider_validation_evidence"),
    )
    ProviderProfile.model_validate_json(json.dumps(data))
    with pytest.raises(ValueError, match="PROVIDER_PROFILE"):
        ProviderProfile.model_validate_json(json.dumps(data | changes))


@pytest.mark.parametrize("role", ["PRO", "CON"])
def test_evidence_call_spec_requires_new_independent_session(role: str) -> None:
    from sastsimi.contracts.llm import LLMCallSpec

    data = make("LLMCallSpec", "llm_call_spec") | dict(agent_role=role)
    LLMCallSpec.model_validate_json(json.dumps(data))
    with pytest.raises(ValueError, match="EVIDENCE_NEW_SESSION_REQUIRED"):
        LLMCallSpec.model_validate_json(
            json.dumps(
                data
                | dict(
                    session_policy="RESUME",
                    parent_session_ref="other-session",
                )
            )
        )


def test_production_prompt_requires_quality_evidence_and_allowed_slots() -> None:
    from sastsimi.contracts.llm import PromptRegistryEntry

    data = make("PromptRegistryEntry") | dict(
        provider_profile_refs=[ref("provider_profile")],
    )
    PromptRegistryEntry.model_validate_json(json.dumps(data))
    with pytest.raises(ValueError, match="QUALITY_EVIDENCE_REQUIRED"):
        PromptRegistryEntry.model_validate_json(
            json.dumps(
                data
                | dict(
                    purpose="PRODUCTION",
                    status="ACTIVE",
                )
            )
        )
    with pytest.raises(ValueError, match="PROMPT_CONTEXT_DENIED"):
        PromptRegistryEntry.model_validate_json(
            json.dumps(
                data
                | dict(
                    input_slots=[
                        dict(
                            slot="facts",
                            data_kind="static_fact_bundle",
                            field_paths=["$"],
                            cardinality="REQUIRED_ONE",
                            trust_class="UNTRUSTED_DATA",
                        )
                    ],
                    forbidden_context_kinds=["static_fact_bundle"],
                )
            )
        )
