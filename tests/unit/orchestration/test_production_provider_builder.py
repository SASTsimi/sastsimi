from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, cast

import pytest

from sastsimi.composition.production_provider_builder import (
    CodexHostBindingEvidence,
    ProductionProviderBuildUnavailable,
    ProductionProviderPromptFeature,
    _codex_host_binding,
    build_production_adapter_feature,
    build_production_call_feature,
    build_production_provider_prompt_feature,
)
from sastsimi.config.production_profile import ProductionProfile
from sastsimi.config.secrets import SecretReference
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import (
    ProviderProfile,
    ProviderValidationEvidence,
    SemanticValidatorSpec,
)
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.orchestration.production_call_authority import (
    ExactAnalysisProductionRouteLookup,
    ProductionPreparedCallAuthorizer,
)
from sastsimi.orchestration.production_capabilities import production_profile_hash
from sastsimi.orchestration.production_provisioning import (
    PromptRoutesProvisioning,
    ProviderConfigurationProvisioning,
)
from sastsimi.prompts.production_calls import ConfiguredProductionCallResolver
from sastsimi.providers.codex_subscription import ApprovedCodexExecutionBinding
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import meta, ref
from tests.security_negative.test_codex_subscription_boundary import (
    _supported_records,
)
from tests.unit.orchestration.test_production_onboarding import _production_profile


def _record(record_model: type[Any], name: str, **changes: object) -> Any:
    payload = make(name)
    payload["meta"] = meta(record_model.KIND, hypothesis=None, attempt=None)
    return record_model.model_validate_json(
        json.dumps(
            payload | changes, default=lambda value: value.model_dump(mode="json")
        )
    )


def _provider_records(
    profile: ProductionProfile,
) -> tuple[ProviderValidationEvidence, ProviderProfile, SemanticValidatorSpec]:
    route = profile.llm_routes[0]
    connection = profile.providers[0]
    tests = tuple(
        {
            "test_id": f"PVD-{index:02d}",
            "result": "NOT_APPLICABLE" if index == 13 else "PASS",
            "evidence_refs": (ref("observation", record=False),),
            "safe_summary": "approved observation",
        }
        for index in range(1, 16)
    )
    validation = _record(
        ProviderValidationEvidence,
        "ProviderValidationEvidence",
        profile_key=connection.provider_profile_key,
        provider="OPENAI",
        product="OPENAI_API",
        transport="RESPONSES_API",
        model=route.model,
        environment=connection.environment,
        auth_mode="API_KEY",
        client_name=connection.client_name,
        client_version=connection.client_version,
        tests=tests,
    )
    validation_ref = reference(validation)
    assert isinstance(validation_ref, StoredDataRef)
    provider = _record(
        ProviderProfile,
        "ProviderProfile",
        profile_key=connection.provider_profile_key,
        provider="OPENAI",
        product="OPENAI_API",
        transport="RESPONSES_API",
        model=route.model,
        environment=connection.environment,
        auth_mode="API_KEY",
        client_name=connection.client_name,
        client_version=connection.client_version,
        credential_source="ENVIRONMENT",
        support_status="SUPPORTED",
        validation_evidence_ref=validation_ref,
        client_execution_profile_ref=None,
    )
    semantic = _record(
        SemanticValidatorSpec,
        "SemanticValidatorSpec",
        validator_key="production-v1",
    )
    return validation, provider, semantic


def _documents(
    profile: ProductionProfile,
    validation: ProviderValidationEvidence,
    provider: ProviderProfile,
    semantic: SemanticValidatorSpec,
    *,
    implementation_key: str = "OPENAI_RESPONSES_API_V1",
    evidence: tuple[str, ...] = (),
    provider_extra_records: tuple[Any, ...] = (),
) -> tuple[ProviderConfigurationProvisioning, PromptRoutesProvisioning]:
    provider_refs = tuple(
        cast(StoredDataRef, reference(item))
        for item in (validation, provider, *provider_extra_records)
    )
    semantic_ref = cast(StoredDataRef, reference(semantic))
    common = {
        "schema_version": 1,
        "profile_hash": production_profile_hash(profile),
        "analysis_id": "a1",
        "workspace_id": "ws1",
        "commit_id": "c1",
    }
    provider_document = ProviderConfigurationProvisioning.model_validate(
        common
        | {
            "slot": "PROVIDER_CONFIGURATION",
            "record_refs": provider_refs,
            "evidence_sha256": evidence,
            "provider_implementation_bindings": (
                {
                    "provider_profile_key": profile.providers[0].provider_profile_key,
                    "implementation_key": implementation_key,
                },
            ),
        }
    )
    kinds = (
        "execution_limits",
        "llm_retry_policy",
        "llm_tool_policy",
        "prompt_redaction_policy",
        "output_schema_spec",
        "prompt_registry_entry",
        "evaluation_recommendation",
    )
    prompt_refs = (semantic_ref,) + tuple(
        StoredDataRef.model_validate(
            {
                "stored_data_id": f"{kind}-s1",
                "data_kind": kind,
                "content_hash": hashlib.sha256(kind.encode()).hexdigest(),
                "workspace_id": "ws1",
                "commit_id": "c1",
                "record_id": f"{kind}-r1",
            }
        )
        for kind in kinds
    )
    prompt_document = PromptRoutesProvisioning.model_validate(
        common
        | {
            "slot": "PROMPT_ROUTES",
            "record_refs": prompt_refs,
            "semantic_validator_keys": ("production-v1",),
            "semantic_validator_bindings": (
                {
                    "validator_key": "production-v1",
                    "implementation_key": "JSON_SCHEMA_AND_AUTHORITY_V1",
                },
            ),
        }
    )
    return provider_document, prompt_document


class _CurrentQueries:
    def __init__(self, values: tuple[object, ...]) -> None:
        self.values = values

    def current_records(self, analysis_id: str, kind: str) -> tuple[Any, ...]:
        return tuple(
            item
            for item in self.values
            if str(getattr(getattr(item, "meta", None), "analysis_id", ""))
            == analysis_id
            and str(getattr(getattr(item, "meta", None), "record_type", "")) == kind
        )


class _Adapter:
    async def probe(self, candidate: object) -> object:
        raise AssertionError(candidate)

    async def invoke(self, request: object) -> object:
        raise AssertionError(request)

    async def cancel(self, invocation_id: str) -> object:
        raise AssertionError(invocation_id)


def test_openai_adapter_uses_exact_profile_and_reporter_validator() -> None:
    profile = _production_profile()
    validation, provider, semantic = _provider_records(profile)
    provider_document, prompt_document = _documents(
        profile, validation, provider, semantic
    )
    captured: dict[str, object] = {}

    def openai_factory(**kwargs: object) -> object:
        captured.update(kwargs)
        return _Adapter()

    feature = build_production_adapter_feature(
        profile=profile,
        provider_provisioning=provider_document,
        prompt_provisioning=prompt_document,
        provisioned_records={
            cast(StoredDataRef, reference(validation)): validation,
            cast(StoredDataRef, reference(provider)): provider,
            cast(StoredDataRef, reference(semantic)): semantic,
        },
        provisioned_evidence={},
        queries=cast(Any, _CurrentQueries((validation, provider, semantic))),
        records=cast(Any, object()),
        artifacts=cast(Any, object()),
        metadata_factory=cast(Any, lambda *_args: None),
        clock=cast(Any, object()),
        openai_factory=openai_factory,
    )

    provider_ref = cast(StoredDataRef, reference(provider))
    semantic_ref = cast(StoredDataRef, reference(semantic))
    assert feature.adapters == {
        (provider_ref, profile.llm_routes[0].model): feature.adapters[
            (provider_ref, profile.llm_routes[0].model)
        ]
    }
    assert captured["provider_profile_ref"] == provider_ref
    assert captured["credential_ref"] == profile.providers[0].credential_ref
    assert captured["semantic_validators"] == feature.semantic_validators
    assert semantic_ref in feature.semantic_validators
    assert ("REPORTER", "CREATE_DRAFT") in cast(
        dict[object, object], captured["request_semantic_validators"]
    )


def test_mismatched_provider_implementation_is_rejected_without_fallback() -> None:
    profile = _production_profile()
    validation, provider, semantic = _provider_records(profile)
    provider_document, prompt_document = _documents(
        profile,
        validation,
        provider,
        semantic,
        implementation_key="ANTHROPIC_MESSAGES_API_V1",
    )

    with pytest.raises(
        ProductionProviderBuildUnavailable,
        match="PRODUCTION_PROVIDER_IMPLEMENTATION_MISMATCH",
    ):
        build_production_adapter_feature(
            profile=profile,
            provider_provisioning=provider_document,
            prompt_provisioning=prompt_document,
            provisioned_records={
                cast(StoredDataRef, reference(validation)): validation,
                cast(StoredDataRef, reference(provider)): provider,
                cast(StoredDataRef, reference(semantic)): semantic,
            },
            provisioned_evidence={},
            queries=cast(Any, _CurrentQueries((validation, provider, semantic))),
            records=cast(Any, object()),
            artifacts=cast(Any, object()),
            metadata_factory=cast(Any, lambda *_args: None),
            clock=cast(Any, object()),
            openai_factory=lambda **_kwargs: _Adapter(),
        )


def test_anthropic_provider_is_explicitly_unsupported_without_fallback() -> None:
    base = _production_profile()
    connection = base.providers[0].model_copy(
        update={
            "product": "ANTHROPIC_API",
            "client_name": "anthropic-python",
        }
    )
    profile = base.model_copy(update={"providers": (connection,)})
    validation, provider, semantic = _provider_records(base)
    validation = validation.model_copy(
        update={
            "provider": "ANTHROPIC",
            "product": "ANTHROPIC_API",
            "transport": "MESSAGES_API",
            "client_name": "anthropic-python",
        }
    )
    validation_ref = cast(StoredDataRef, reference(validation))
    provider = provider.model_copy(
        update={
            "provider": "ANTHROPIC",
            "product": "ANTHROPIC_API",
            "transport": "MESSAGES_API",
            "client_name": "anthropic-python",
            "validation_evidence_ref": validation_ref,
        }
    )
    provider_document, prompt_document = _documents(
        profile,
        validation,
        provider,
        semantic,
        implementation_key="ANTHROPIC_MESSAGES_API_V1",
    )

    with pytest.raises(
        ProductionProviderBuildUnavailable,
        match="PRODUCTION_PROVIDER_IMPLEMENTATION_UNSUPPORTED",
    ):
        build_production_adapter_feature(
            profile=profile,
            provider_provisioning=provider_document,
            prompt_provisioning=prompt_document,
            provisioned_records={
                validation_ref: validation,
                cast(StoredDataRef, reference(provider)): provider,
                cast(StoredDataRef, reference(semantic)): semantic,
            },
            provisioned_evidence={},
            queries=cast(Any, _CurrentQueries((validation, provider, semantic))),
            records=cast(Any, object()),
            artifacts=cast(Any, object()),
            metadata_factory=cast(Any, lambda *_args: None),
            clock=cast(Any, object()),
            openai_factory=lambda **_kwargs: _Adapter(),
        )


def test_stale_provider_record_is_rejected_before_adapter_construction() -> None:
    profile = _production_profile()
    validation, provider, semantic = _provider_records(profile)
    provider_document, prompt_document = _documents(
        profile, validation, provider, semantic
    )

    with pytest.raises(
        ProductionProviderBuildUnavailable,
        match="PRODUCTION_PROVIDER_CONFIGURATION_STALE",
    ):
        build_production_adapter_feature(
            profile=profile,
            provider_provisioning=provider_document,
            prompt_provisioning=prompt_document,
            provisioned_records={
                cast(StoredDataRef, reference(validation)): validation,
                cast(StoredDataRef, reference(provider)): provider,
                cast(StoredDataRef, reference(semantic)): semantic,
            },
            provisioned_evidence={},
            queries=cast(Any, _CurrentQueries((validation, semantic))),
            records=cast(Any, object()),
            artifacts=cast(Any, object()),
            metadata_factory=cast(Any, lambda *_args: None),
            clock=cast(Any, object()),
            openai_factory=lambda **_kwargs: _Adapter(),
        )


def test_differently_scoped_provisioning_documents_are_rejected() -> None:
    profile = _production_profile()
    validation, provider, semantic = _provider_records(profile)
    provider_document, prompt_document = _documents(
        profile, validation, provider, semantic
    )
    prompt_document = prompt_document.model_copy(update={"analysis_id": "other-run"})

    with pytest.raises(
        ProductionProviderBuildUnavailable,
        match="PRODUCTION_PROVISIONING_SCOPE_MISMATCH",
    ):
        build_production_adapter_feature(
            profile=profile,
            provider_provisioning=provider_document,
            prompt_provisioning=prompt_document,
            provisioned_records={
                cast(StoredDataRef, reference(validation)): validation,
                cast(StoredDataRef, reference(provider)): provider,
                cast(StoredDataRef, reference(semantic)): semantic,
            },
            provisioned_evidence={},
            queries=cast(Any, _CurrentQueries((validation, provider, semantic))),
            records=cast(Any, object()),
            artifacts=cast(Any, object()),
            metadata_factory=cast(Any, lambda *_args: None),
            clock=cast(Any, object()),
            openai_factory=lambda **_kwargs: _Adapter(),
        )


def test_provisioning_for_a_different_profile_is_rejected() -> None:
    profile = _production_profile()
    validation, provider, semantic = _provider_records(profile)
    provider_document, prompt_document = _documents(
        profile, validation, provider, semantic
    )
    changed = profile.model_copy(update={"host_id": "other-approved-host-profile"})

    with pytest.raises(
        ProductionProviderBuildUnavailable,
        match="PRODUCTION_PROVISIONING_SCOPE_MISMATCH",
    ):
        build_production_adapter_feature(
            profile=changed,
            provider_provisioning=provider_document,
            prompt_provisioning=prompt_document,
            provisioned_records={
                cast(StoredDataRef, reference(validation)): validation,
                cast(StoredDataRef, reference(provider)): provider,
                cast(StoredDataRef, reference(semantic)): semantic,
            },
            provisioned_evidence={},
            queries=cast(Any, _CurrentQueries((validation, provider, semantic))),
            records=cast(Any, object()),
            artifacts=cast(Any, object()),
            metadata_factory=cast(Any, lambda *_args: None),
            clock=cast(Any, object()),
            openai_factory=lambda **_kwargs: _Adapter(),
        )


def test_provider_record_from_a_different_analysis_is_rejected() -> None:
    profile = _production_profile()
    validation, provider, semantic = _provider_records(profile)
    provider = provider.model_copy(
        update={"meta": provider.meta.model_copy(update={"analysis_id": "other-run"})}
    )
    provider_document, prompt_document = _documents(
        profile, validation, provider, semantic
    )

    with pytest.raises(
        ProductionProviderBuildUnavailable,
        match="PRODUCTION_PROVISIONED_RECORD_SCOPE_MISMATCH",
    ):
        build_production_adapter_feature(
            profile=profile,
            provider_provisioning=provider_document,
            prompt_provisioning=prompt_document,
            provisioned_records={
                cast(StoredDataRef, reference(validation)): validation,
                cast(StoredDataRef, reference(provider)): provider,
                cast(StoredDataRef, reference(semantic)): semantic,
            },
            provisioned_evidence={},
            queries=cast(Any, _CurrentQueries((validation, provider, semantic))),
            records=cast(Any, object()),
            artifacts=cast(Any, object()),
            metadata_factory=cast(Any, lambda *_args: None),
            clock=cast(Any, object()),
            openai_factory=lambda **_kwargs: _Adapter(),
        )


def test_codex_host_binding_contains_only_env_names_and_builds_exact_binding() -> None:
    executable = Path(__file__).resolve()
    evidence = CodexHostBindingEvidence(
        schema_version=1,
        kind="CODEX_OFFICIAL_CLIENT_HOST_BINDING",
        provider_profile_key="openai-main",
        executable_path_env="SASTSIMI_CODEX_EXECUTABLE",
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        codex_home_env="SASTSIMI_CODEX_HOME",
    )
    payload = canonical_bytes(evidence)
    digest = hashlib.sha256(payload).hexdigest()
    profile = _production_profile()
    validation, provider, semantic = _provider_records(profile)
    provider_document, _prompt_document = _documents(
        profile, validation, provider, semantic, evidence=(digest,)
    )

    assert "C:\\" not in evidence.model_dump_json()
    assert "/home/" not in evidence.model_dump_json()
    assert set(type(evidence).model_fields) == {
        "schema_version",
        "kind",
        "provider_profile_key",
        "executable_path_env",
        "executable_sha256",
        "codex_home_env",
    }
    assert _codex_host_binding(
        "openai-main",
        provider_document,
        {digest: payload},
        {
            "SASTSIMI_CODEX_EXECUTABLE": str(executable),
            "SASTSIMI_CODEX_HOME": str(executable.parent),
        },
    ) == (executable, evidence.executable_sha256, executable.parent)


def test_codex_host_binding_rejects_a_changed_executable_before_factory() -> None:
    executable = Path(__file__).resolve()
    evidence = CodexHostBindingEvidence(
        schema_version=1,
        kind="CODEX_OFFICIAL_CLIENT_HOST_BINDING",
        provider_profile_key="openai-main",
        executable_path_env="SASTSIMI_CODEX_EXECUTABLE",
        executable_sha256="0" * 64,
        codex_home_env="SASTSIMI_CODEX_HOME",
    )
    payload = canonical_bytes(evidence)
    digest = hashlib.sha256(payload).hexdigest()
    profile = _production_profile()
    validation, provider, semantic = _provider_records(profile)
    provider_document, _prompt_document = _documents(
        profile, validation, provider, semantic, evidence=(digest,)
    )

    with pytest.raises(
        ProductionProviderBuildUnavailable,
        match="PRODUCTION_CODEX_EXECUTABLE_DIGEST_MISMATCH",
    ):
        _codex_host_binding(
            "openai-main",
            provider_document,
            {digest: payload},
            {
                "SASTSIMI_CODEX_EXECUTABLE": str(executable),
                "SASTSIMI_CODEX_HOME": str(executable.parent),
            },
        )


def test_supported_codex_factory_requires_exact_validation_evidence() -> None:
    assert (
        "provider_validation_evidence"
        in ApprovedCodexExecutionBinding.__dataclass_fields__
    )


def test_codex_factory_receives_exact_supported_binding() -> None:
    base = _production_profile()
    provider, client, validation = _supported_records()
    connection = base.providers[0].model_copy(
        update={
            "provider_profile_key": provider.profile_key,
            "product": "CODEX",
            "environment": provider.environment,
            "client_name": provider.client_name,
            "client_version": provider.client_version,
            "credential_ref": SecretReference(reference="env:SASTSIMI_CODEX_SESSION"),
        }
    )
    profile = base.model_copy(
        update={
            "providers": (connection,),
            "llm_routes": tuple(
                route.model_copy(
                    update={
                        "provider_profile_key": provider.profile_key,
                        "model": provider.model,
                    }
                )
                for route in base.llm_routes
            ),
        }
    )
    semantic = _record(
        SemanticValidatorSpec,
        "SemanticValidatorSpec",
        validator_key="production-v1",
    )
    executable = Path(__file__).resolve()
    host = CodexHostBindingEvidence(
        schema_version=1,
        kind="CODEX_OFFICIAL_CLIENT_HOST_BINDING",
        provider_profile_key=provider.profile_key,
        executable_path_env="SASTSIMI_CODEX_EXECUTABLE",
        executable_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        codex_home_env="SASTSIMI_CODEX_HOME",
    )
    host_payload = canonical_bytes(host)
    host_digest = hashlib.sha256(host_payload).hexdigest()
    provider_document, prompt_document = _documents(
        profile,
        validation,
        provider,
        semantic,
        implementation_key="CODEX_OFFICIAL_CLIENT_V1",
        evidence=(host_digest,),
        provider_extra_records=(client,),
    )
    captured: dict[str, object] = {}

    def codex_factory(**kwargs: object) -> object:
        captured.update(kwargs)
        return _Adapter()

    feature = build_production_adapter_feature(
        profile=profile,
        provider_provisioning=provider_document,
        prompt_provisioning=prompt_document,
        provisioned_records={
            cast(StoredDataRef, reference(validation)): validation,
            cast(StoredDataRef, reference(client)): client,
            cast(StoredDataRef, reference(provider)): provider,
            cast(StoredDataRef, reference(semantic)): semantic,
        },
        provisioned_evidence={host_digest: host_payload},
        queries=cast(Any, _CurrentQueries((validation, client, provider, semantic))),
        records=cast(Any, object()),
        artifacts=cast(Any, object()),
        metadata_factory=cast(Any, lambda *_args: None),
        clock=cast(Any, object()),
        environment={
            "SASTSIMI_CODEX_EXECUTABLE": str(executable),
            "SASTSIMI_CODEX_HOME": str(executable.parent),
        },
        codex_factory=codex_factory,
    )

    binding = cast(ApprovedCodexExecutionBinding, captured["binding"])
    assert binding.provider_profile is provider
    assert binding.client_execution_profile is client
    assert binding.provider_validation_evidence is validation
    assert binding.executable.path == executable
    assert binding.codex_home == executable.parent
    assert len(feature.adapters) == 1


def test_prompt_feature_rejects_an_incomplete_exact_route_graph() -> None:
    profile = _production_profile()
    validation, provider, semantic = _provider_records(profile)
    provider_document, prompt_document = _documents(
        profile, validation, provider, semantic
    )

    with pytest.raises(
        ProductionProviderBuildUnavailable,
        match="PRODUCTION_PROMPT_ROUTE_GRAPH_INCOMPLETE",
    ):
        build_production_provider_prompt_feature(
            repository_root=Path.cwd(),
            profile=profile,
            provider_provisioning=provider_document,
            prompt_provisioning=prompt_document,
            provisioned_records={
                cast(StoredDataRef, reference(validation)): validation,
                cast(StoredDataRef, reference(provider)): provider,
                cast(StoredDataRef, reference(semantic)): semantic,
            },
            provisioned_evidence={},
            queries=cast(Any, _CurrentQueries((validation, provider, semantic))),
            records=cast(Any, object()),
            configuration=cast(Any, object()),
            artifacts=cast(Any, object()),
            ids=cast(Any, object()),
            metadata_factory=cast(Any, lambda *_args: None),
            clock=cast(Any, object()),
            openai_factory=lambda **_kwargs: _Adapter(),
        )


def test_post_runtime_call_feature_uses_exact_lookup_and_budget_authorizer() -> None:
    lookup = cast(ExactAnalysisProductionRouteLookup, object())
    configured = cast(Any, object())
    prompt_feature = ProductionProviderPromptFeature(
        adapters={},
        approved_routes=(),
        configuration=configured,
        route_lookup=lookup,
    )

    feature = build_production_call_feature(
        provider_prompt=prompt_feature,
        runner=cast(Any, object()),
        records=cast(Any, object()),
        requester_identities={},
        reserved_cost_minor_units=1,
    )

    assert isinstance(feature.authorizer, ProductionPreparedCallAuthorizer)
    assert isinstance(feature.calls, ConfiguredProductionCallResolver)
    assert feature.calls.route_lookup is lookup
    assert feature.calls.configuration is configured
