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
                "WORKSPACE_STORAGE", backend="SQLITE_RECORDS_AND_CAS"
            ),
            "STATIC_ANALYSIS": document(
                "STATIC_ANALYSIS", enabled_tools=["AST"]
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
            ),
            "POLICY_CATALOG": document(
                "POLICY_CATALOG",
                source_configuration_sha256=source,
                freshness_criterion_sha256=freshness,
                evidence_sha256=[source, freshness],
            ),
            "PROVIDER_CONFIGURATION": document(
                "PROVIDER_CONFIGURATION",
                record_refs=[item.model_dump(mode="json") for item in providers],
            ),
            "PROMPT_ROUTES": document(
                "PROMPT_ROUTES",
                record_refs=[item.model_dump(mode="json") for item in prompts],
                semantic_validator_keys=["production-v1"],
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
        item.content_sha256: f"{item.slot}-data".encode()
        for item in manifest.artifacts
    }
    assert all(
        hashlib.sha256(data).hexdigest() == digest
        for digest, data in artifacts.items()
    )
    return manifest, records, artifacts


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
        evidence=lambda _digest: b"unused",
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
