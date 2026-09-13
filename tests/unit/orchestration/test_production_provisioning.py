from __future__ import annotations

import hashlib
import json
from typing import Any, cast

import pytest

from sastsimi.contracts.capabilities import (
    CapabilityArchitecture,
    CapabilityKind,
    CapabilityLanguage,
    CapabilityOperatingSystem,
    CapabilityOperation,
    RuntimeCapabilityProfile,
    RuntimeCapabilitySelection,
    StaticToolCapabilitySelection,
)
from sastsimi.contracts.ids import CommitId, RecordId, StoredDataId, WorkspaceId
from sastsimi.contracts.refs import HostConfigurationRef, StoredDataRef, reference
from sastsimi.contracts.static import StaticToolProfile
from sastsimi.orchestration.production_onboarding import ProductionProvisioningManifest
from sastsimi.orchestration.production_provisioning import (
    ExactProductionProvisioningResolver,
    ExactProvisioningArtifactMaterializer,
    ProvisioningTemplateMaterializer,
)
from tests.integration.storage.test_production_capability_registry import (
    _runtime_profile,
)
from tests.unit.orchestration.test_production_onboarding import (
    _production_profile,
    _provisioning_payload,
)
from tests.unit.static_analysis.test_repository_profile import (
    _git_capability,
    _static_selection,
)


class _Configuration:
    def __init__(
        self,
        records: dict[
            HostConfigurationRef, RuntimeCapabilityProfile | StaticToolProfile
        ],
    ) -> None:
        self.records = records

    def resolve_pinned_active_profile(
        self, ref: HostConfigurationRef
    ) -> RuntimeCapabilityProfile | StaticToolProfile:
        return self.records[ref]

    def resolve_active_capability(
        self,
        *,
        capability_kind: CapabilityKind,
        language: CapabilityLanguage,
        operation: CapabilityOperation,
        operating_system: CapabilityOperatingSystem,
        architecture: CapabilityArchitecture,
    ) -> RuntimeCapabilitySelection:
        raise AssertionError("pinned provisioning must not perform discovery")

    def resolve_active_static_tool(
        self,
        *,
        adapter_key: str,
        language: CapabilityLanguage,
        operating_system: CapabilityOperatingSystem,
        architecture: CapabilityArchitecture,
    ) -> StaticToolCapabilitySelection:
        raise AssertionError("pinned provisioning must not perform discovery")


def _run_ref(kind: str, index: int) -> StoredDataRef:
    marker = format(index, "x")[-1]
    return StoredDataRef(
        stored_data_id=StoredDataId(f"{kind}-{index}"),
        data_kind=kind,
        content_hash=marker * 64,
        workspace_id=WorkspaceId("workspace"),
        commit_id=CommitId("c" * 40),
        record_id=RecordId(f"{kind}-{index}"),
    )


def _artifact_documents() -> tuple[dict[str, bytes], str]:
    profile_hash = "f" * 64
    source = hashlib.sha256(b"source").hexdigest()
    freshness = hashlib.sha256(b"freshness").hexdigest()
    common: dict[str, object] = {
        "schema_version": 1,
        "profile_hash": profile_hash,
        "analysis_id": "analysis",
        "workspace_id": "workspace",
        "commit_id": "c" * 40,
        "record_refs": [],
        "evidence_sha256": [],
    }

    def document(slot: str, **values: object) -> bytes:
        return json.dumps(common | {"slot": slot} | values).encode()

    verification = [
        _run_ref("verification_playbook", 1),
        _run_ref("playbook_policy", 2),
    ]
    sandbox = [_run_ref("sandbox_profile", 3)]
    providers = [
        _run_ref("provider_validation_evidence", 4),
        _run_ref("provider_profile", 5),
    ]
    prompt_kinds = (
        "execution_limits",
        "llm_retry_policy",
        "llm_tool_policy",
        "prompt_redaction_policy",
        "output_schema_spec",
        "semantic_validator_spec",
        "prompt_registry_entry",
        "evaluation_recommendation",
    )
    prompts = [_run_ref(kind, index + 6) for index, kind in enumerate(prompt_kinds)]
    return (
        {
            "WORKSPACE_STORAGE": document(
                "WORKSPACE_STORAGE",
                backend="SQLITE_RECORDS_AND_CAS",
                root_relative="workspace-storage",
                capacity_bytes=80_000_000,
                backend_key="local-quota-v1",
                enforcement_evidence_sha256=source,
                evidence_sha256=[source],
            ),
            "STATIC_ANALYSIS": document(
                "STATIC_ANALYSIS",
                enabled_tools=["AST"],
                routes=[
                    {
                        "tool": "AST",
                        "adapter_key": "PYTHON_AST",
                        "executable_slot": "PYTHON_RUNTIME",
                        "decoder_key": "PYTHON_AST_JSON_V1",
                        "analysis_config_sha256": source,
                    }
                ],
                evidence_sha256=[source],
            ),
            "VERIFICATION_PLAYBOOKS": document(
                "VERIFICATION_PLAYBOOKS",
                record_refs=[item.model_dump(mode="json") for item in verification],
            ),
            "SANDBOX_PROFILE": document(
                "SANDBOX_PROFILE",
                record_refs=[item.model_dump(mode="json") for item in sandbox],
                container_user="65532:65532",
                max_execute_turns=8,
                resource_journal_relative="sandbox/resource-journal.sqlite3",
                authorization_policy_sha256=source,
                authorization_implementation_key="RUNTIME_DYNAMIC_AUTHORIZATION_V1",
                setup_implementation_key="DOCKER_REPRODUCTION_SETUP_V1",
                evidence_sha256=[source],
            ),
            "POLICY_CATALOG": document(
                "POLICY_CATALOG",
                source_configuration_sha256=source,
                freshness_criterion_sha256=freshness,
                parser_implementation_key="OFFICIAL_HTTP_POLICY_V1",
                evidence_sha256=[source, freshness],
            ),
            "PROVIDER_CONFIGURATION": document(
                "PROVIDER_CONFIGURATION",
                record_refs=[item.model_dump(mode="json") for item in providers],
                provider_implementation_bindings=[
                    {
                        "provider_profile_key": "provider-a",
                        "implementation_key": "OPENAI_RESPONSES_API_V1",
                    }
                ],
            ),
            "PROMPT_ROUTES": document(
                "PROMPT_ROUTES",
                record_refs=[item.model_dump(mode="json") for item in prompts],
                semantic_validator_keys=["production-v1"],
                semantic_validator_bindings=[
                    {
                        "validator_key": "production-v1",
                        "implementation_key": "JSON_SCHEMA_AND_AUTHORITY_V1",
                    }
                ],
            ),
        },
        profile_hash,
    )


def _artifact_templates() -> tuple[dict[str, bytes], str]:
    profile_hash = "f" * 64
    storage_evidence = hashlib.sha256(b"storage-enforcement").hexdigest()
    static_config = hashlib.sha256(b"python-ast-config").hexdigest()
    policy_source = hashlib.sha256(b"policy-source").hexdigest()
    policy_freshness = hashlib.sha256(b"policy-freshness").hexdigest()
    sandbox_policy = hashlib.sha256(b"sandbox-policy").hexdigest()
    common: dict[str, object] = {
        "schema_version": 1,
        "template_scope": "HOST_PROFILE",
        "profile_hash": profile_hash,
        "host_id": "host-a",
        "record_templates": [],
        "evidence_sha256": [],
    }

    def template(slot: str, **values: object) -> bytes:
        return json.dumps(common | {"slot": slot} | values).encode()

    def record_template(key: str, kind: str) -> dict[str, str]:
        return {
            "template_key": key,
            "data_kind": kind,
            "content_sha256": hashlib.sha256(key.encode()).hexdigest(),
        }

    verification = [
        record_template("common-playbook", "verification_playbook"),
        record_template("playbook-policy", "playbook_policy"),
    ]
    sandbox = [record_template("sandbox-profile", "sandbox_profile")]
    provider = [
        record_template("provider-evidence", "provider_validation_evidence"),
        record_template("provider-profile", "provider_profile"),
    ]
    prompt_kinds = (
        "execution_limits",
        "llm_retry_policy",
        "llm_tool_policy",
        "prompt_redaction_policy",
        "output_schema_spec",
        "semantic_validator_spec",
        "prompt_registry_entry",
        "evaluation_recommendation",
    )
    prompts = [record_template(f"prompt-{kind}", kind) for kind in prompt_kinds]

    def record_digests(values: list[dict[str, str]]) -> list[str]:
        return [item["content_sha256"] for item in values]

    return (
        {
            "WORKSPACE_STORAGE": template(
                "WORKSPACE_STORAGE",
                backend="SQLITE_RECORDS_AND_CAS",
                root_relative="workspace-storage",
                capacity_bytes=80_000_000,
                backend_key="local-quota-v1",
                enforcement_evidence_sha256=storage_evidence,
                evidence_sha256=[storage_evidence],
            ),
            "STATIC_ANALYSIS": template(
                "STATIC_ANALYSIS",
                enabled_tools=["AST"],
                routes=[
                    {
                        "tool": "AST",
                        "adapter_key": "PYTHON_AST",
                        "executable_slot": "PYTHON_RUNTIME",
                        "decoder_key": "PYTHON_AST_JSON_V1",
                        "analysis_config_sha256": static_config,
                    }
                ],
                evidence_sha256=[static_config],
            ),
            "VERIFICATION_PLAYBOOKS": template(
                "VERIFICATION_PLAYBOOKS",
                record_templates=verification,
                evidence_sha256=record_digests(verification),
            ),
            "SANDBOX_PROFILE": template(
                "SANDBOX_PROFILE",
                record_templates=sandbox,
                container_user="65532:65532",
                max_execute_turns=8,
                resource_journal_relative="sandbox/resource-journal.sqlite3",
                authorization_policy_sha256=sandbox_policy,
                authorization_implementation_key="RUNTIME_DYNAMIC_AUTHORIZATION_V1",
                setup_implementation_key="DOCKER_REPRODUCTION_SETUP_V1",
                evidence_sha256=[sandbox_policy, *record_digests(sandbox)],
            ),
            "POLICY_CATALOG": template(
                "POLICY_CATALOG",
                source_configuration_sha256=policy_source,
                freshness_criterion_sha256=policy_freshness,
                parser_implementation_key="OFFICIAL_HTTP_POLICY_V1",
                evidence_sha256=[policy_source, policy_freshness],
            ),
            "PROVIDER_CONFIGURATION": template(
                "PROVIDER_CONFIGURATION",
                record_templates=provider,
                provider_implementation_bindings=[
                    {
                        "provider_profile_key": "provider-a",
                        "implementation_key": "OPENAI_RESPONSES_API_V1",
                    }
                ],
                evidence_sha256=record_digests(provider),
            ),
            "PROMPT_ROUTES": template(
                "PROMPT_ROUTES",
                record_templates=prompts,
                semantic_validator_bindings=[
                    {
                        "validator_key": "production-v1",
                        "implementation_key": "JSON_SCHEMA_AND_AUTHORITY_V1",
                    }
                ],
                evidence_sha256=record_digests(prompts),
            ),
        },
        profile_hash,
    )


def _manifest() -> tuple[
    ProductionProvisioningManifest,
    dict[HostConfigurationRef, RuntimeCapabilityProfile | StaticToolProfile],
    dict[str, bytes],
]:
    profile = _production_profile()
    git, _ = _git_capability()
    python = _runtime_profile(
        key="python-runtime",
        kind="PYTHON_RUNTIME",
        languages=("PYTHON",),
        operations=("START",),
        subject_key="python",
    )
    ast = _static_selection("PYTHON_AST", "PYTHON").profile
    refs = {
        "GIT_CLONE": cast(HostConfigurationRef, reference(git)),
        "GIT_CHECKOUT": cast(HostConfigurationRef, reference(git)),
        "PYTHON_RUNTIME": cast(HostConfigurationRef, reference(python)),
        "AST": cast(HostConfigurationRef, reference(ast)),
    }
    payload = _provisioning_payload(profile)
    payload["host_id"] = "host-a"
    for item in cast(list[dict[str, object]], payload["capabilities"]):
        item["profile_ref"] = refs[cast(str, item["slot"])].model_dump(mode="json")
    manifest = ProductionProvisioningManifest.model_validate_json(json.dumps(payload))
    records: dict[
        HostConfigurationRef, RuntimeCapabilityProfile | StaticToolProfile
    ] = {
        refs["GIT_CLONE"]: git,
        refs["PYTHON_RUNTIME"]: python,
        refs["AST"]: ast,
    }
    artifacts = {
        item.content_sha256: f"{item.slot}-data".encode() for item in manifest.artifacts
    }
    assert all(
        hashlib.sha256(data).hexdigest() == digest for digest, data in artifacts.items()
    )
    return (
        manifest,
        records,
        artifacts,
    )


def test_exact_provisioning_resolves_only_current_approved_inputs() -> None:
    manifest, records, artifacts = _manifest()
    resolver = ExactProductionProvisioningResolver(
        configuration=_Configuration(records),
        evidence=artifacts.__getitem__,
    )

    resolved = resolver.resolve(manifest)

    assert set(resolved.capabilities) == {
        "GIT_CLONE",
        "GIT_CHECKOUT",
        "PYTHON_RUNTIME",
        "AST",
    }
    assert set(resolved.artifacts) == {
        "WORKSPACE_STORAGE",
        "STATIC_ANALYSIS",
        "VERIFICATION_PLAYBOOKS",
        "SANDBOX_PROFILE",
        "POLICY_CATALOG",
        "PROVIDER_CONFIGURATION",
        "PROMPT_ROUTES",
    }


def test_exact_provisioning_rejects_stale_capability_substitution() -> None:
    manifest, records, artifacts = _manifest()
    clone_ref = next(
        item.profile_ref for item in manifest.capabilities if item.slot == "GIT_CLONE"
    )
    records[clone_ref] = next(
        record
        for record in records.values()
        if isinstance(record, RuntimeCapabilityProfile)
        and record.capability_kind == "PYTHON_RUNTIME"
    )
    resolver = ExactProductionProvisioningResolver(
        configuration=_Configuration(records),
        evidence=artifacts.__getitem__,
    )

    with pytest.raises(ValueError, match="PRODUCTION_CAPABILITY_REFERENCE_MISMATCH"):
        resolver.resolve(manifest)


def test_exact_provisioning_parser_accepts_complete_typed_seven_slot_set() -> None:
    artifacts, profile_hash = _artifact_documents()

    parsed = ExactProvisioningArtifactMaterializer.parse(
        artifacts,
        profile_hash=profile_hash,
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="c" * 40,
    )

    assert set(parsed) == set(artifacts)
    assert parsed["STATIC_ANALYSIS"].slot == "STATIC_ANALYSIS"


def test_exact_provisioning_parser_rejects_stale_run_scope() -> None:
    artifacts, profile_hash = _artifact_documents()

    with pytest.raises(
        ValueError, match="PRODUCTION_PROVISIONING_ARTIFACT_SCOPE_MISMATCH"
    ):
        ExactProvisioningArtifactMaterializer.parse(
            artifacts,
            profile_hash=profile_hash,
            analysis_id="different-analysis",
            workspace_id="workspace",
            commit_id="c" * 40,
        )


def test_profile_template_binds_exact_run_scope_after_ids_are_allocated() -> None:
    artifacts, profile_hash = _artifact_templates()
    templates = ProvisioningTemplateMaterializer.parse(
        artifacts,
        profile_hash=profile_hash,
        host_id="host-a",
    )
    refs = {
        item.template_key: _run_ref(item.data_kind, index)
        for index, document in enumerate(templates.values(), start=1)
        for item in document.record_templates
    }

    bound = ProvisioningTemplateMaterializer.bind_run(
        templates,
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="c" * 40,
        record_refs=refs,
    )
    parsed = ExactProvisioningArtifactMaterializer.parse(
        bound,
        profile_hash=profile_hash,
        analysis_id="analysis",
        workspace_id="workspace",
        commit_id="c" * 40,
    )

    assert parsed["WORKSPACE_STORAGE"].record_refs == ()
    assert {ref.data_kind for ref in parsed["VERIFICATION_PLAYBOOKS"].record_refs} == {
        "verification_playbook",
        "playbook_policy",
    }


def test_profile_template_rejects_untrusted_implementation_key() -> None:
    artifacts, profile_hash = _artifact_templates()
    payload = json.loads(artifacts["PROMPT_ROUTES"])
    payload["semantic_validator_bindings"][0]["implementation_key"] = (
        "IMPORT_ARBITRARY_MODULE"
    )
    artifacts["PROMPT_ROUTES"] = json.dumps(payload).encode()

    with pytest.raises(ValueError, match="PRODUCTION_PROVISIONING_TEMPLATE_INVALID"):
        ProvisioningTemplateMaterializer.parse(
            artifacts,
            profile_hash=profile_hash,
            host_id="host-a",
        )


def test_profile_template_rejects_workspace_escape() -> None:
    artifacts, profile_hash = _artifact_templates()
    payload = json.loads(artifacts["WORKSPACE_STORAGE"])
    payload["root_relative"] = "../outside"
    artifacts["WORKSPACE_STORAGE"] = json.dumps(payload).encode()

    with pytest.raises(ValueError, match="PRODUCTION_PROVISIONING_TEMPLATE_INVALID"):
        ProvisioningTemplateMaterializer.parse(
            artifacts,
            profile_hash=profile_hash,
            host_id="host-a",
        )


def test_exact_provisioning_materializer_rejects_wrong_record_type() -> None:
    artifacts, profile_hash = _artifact_documents()

    class _WrongRecordStore:
        @staticmethod
        def get_exact(_ref: StoredDataRef) -> object:
            return object()

    class _UnusedQueries:
        @staticmethod
        def current_records(_analysis_id: str, _kind: str) -> tuple[object, ...]:
            raise AssertionError("wrong record types must fail before current lookup")

    materializer = ExactProvisioningArtifactMaterializer(
        records=cast(Any, _WrongRecordStore()),
        queries=cast(Any, _UnusedQueries()),
        evidence=lambda digest: (
            b"source"
            if digest == hashlib.sha256(b"source").hexdigest()
            else b"freshness"
        ),
    )

    with pytest.raises(
        ValueError, match="PRODUCTION_PROVISIONING_RECORD_SCOPE_MISMATCH"
    ):
        materializer.materialize(
            artifacts,
            profile_hash=profile_hash,
            analysis_id="analysis",
            workspace_id="workspace",
            commit_id="c" * 40,
        )
