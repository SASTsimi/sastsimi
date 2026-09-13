from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.composition.production_composition import (
    ProductionCapabilityUnavailable,
)
from sastsimi.composition.production_default_assembler import (
    BuiltProductionDynamicFeature,
    ProductionStaticRuntimePorts,
    build_default_production_bundle_assembler,
    build_default_production_bundle_registry,
)
from sastsimi.composition.production_feature_installer import (
    DynamicProductionFeature,
    PolicyProductionFeature,
    T08ProductionFeature,
)
from sastsimi.composition.production_filesystem_provisioner import (
    ProductionBundleAssemblyContext,
    ProductionImplementationSet,
)
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.ids import (
    AnalysisId,
    CommitId,
    LogicalRecordId,
    RecordId,
    StoredDataId,
    WorkspaceId,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import HostConfigurationRef, StoredDataRef, reference
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.orchestration.production_provisioning import (
    PolicyCatalogProvisioning,
    PromptRoutesProvisioning,
    ProviderConfigurationProvisioning,
    ProviderImplementationBinding,
    SandboxProfileProvisioning,
    SemanticValidatorBinding,
    StaticAnalysisProvisioning,
    StaticRouteProvisioning,
    VerificationPlaybooksProvisioning,
    WorkspaceStorageProvisioning,
)
from sastsimi.ports.production_analysis import ProductionAnalyzeUnavailable


def _meta(kind: str, name: str) -> RecordMeta:
    return RecordMeta(
        record_id=RecordId(name),
        logical_record_id=LogicalRecordId(name),
        record_type=kind,
        schema_version="1.0.0",
        revision_number=1,
        previous_record_id=None,
        created_at=datetime(2026, 9, 13, tzinfo=UTC),
        analysis_id=AnalysisId("analysis"),
        workspace_id=WorkspaceId("workspace"),
        commit_id=CommitId("c" * 40),
        hypothesis_id=None,
        attempt_id=None,
    )


def _playbooks() -> tuple[
    VerificationPlaybook,
    StoredDataRef,
    PlaybookPolicy,
    StoredDataRef,
]:
    common = VerificationPlaybook(
        meta=_meta(VerificationPlaybook.KIND, "common-playbook"),
        scope="COMMON",
        vulnerability_type=None,
        prerequisites=(),
        source_checks=("source",),
        sink_checks=("sink",),
        path_checks=("path",),
        defense_checks=("defense",),
        falsification_question_templates=(),
        static_evidence_requirements=("location",),
        dynamic_evidence_requirements=(),
        restriction_checks=("restriction",),
        hold_conditions=("missing evidence",),
    )
    common_ref = cast(StoredDataRef, reference(common))
    policy = PlaybookPolicy(
        meta=_meta(PlaybookPolicy.KIND, "playbook-policy"),
        common_playbook_ref=common_ref,
        type_playbooks=(),
        approved_by="operator",
        approved_at=datetime(2026, 9, 13, tzinfo=UTC),
    )
    return common, common_ref, policy, cast(StoredDataRef, reference(policy))


def _host_ref(kind: str, name: str) -> HostConfigurationRef:
    return HostConfigurationRef(
        stored_data_id=StoredDataId(name),
        data_kind=kind,
        content_hash="a" * 64,
        host_id="host-a",
        publication_analysis_id=AnalysisId("capability-analysis"),
        publication_workspace_id=WorkspaceId("capability-workspace"),
        publication_commit_id=CommitId("capability-commit"),
        record_id=RecordId(name),
    )


class _Queries:
    def __init__(self, values: tuple[Any, ...]) -> None:
        self._values = values

    def current_records(self, analysis_id: str, kind: str) -> tuple[object, ...]:
        return tuple(
            value
            for value in self._values
            if str(value.meta.analysis_id) == analysis_id
            and value.meta.record_type == kind
        )


def _assembly_context(tmp_path: Path) -> ProductionBundleAssemblyContext:
    common, common_ref, policy, policy_ref = _playbooks()
    git_ref = _host_ref("runtime_capability_profile", "git-profile")
    python_ref = _host_ref("runtime_capability_profile", "python-profile")
    ast_ref = _host_ref("static_tool_profile", "ast-profile")
    config_digest = "b" * 64
    workspace = WorkspaceStorageProvisioning.model_construct(
        root_relative="workspaces",
        capacity_bytes=10_000_000,
    )
    route = StaticRouteProvisioning.model_construct(
        tool="AST",
        adapter_key="PYTHON_AST",
        executable_slot="PYTHON_RUNTIME",
        decoder_key="PYTHON_AST_JSON_V1",
        analysis_config_sha256=config_digest,
        rule_catalog_sha256=None,
        rule_selection_sha256=None,
        rule_mapping_sha256=None,
    )
    static = StaticAnalysisProvisioning.model_construct(
        enabled_tools=("AST",),
        routes=(route,),
    )
    verification = VerificationPlaybooksProvisioning.model_construct(
        record_refs=(common_ref, policy_ref)
    )
    provider = ProviderConfigurationProvisioning.model_construct(
        provider_implementation_bindings=(
            ProviderImplementationBinding(
                provider_profile_key="openai",
                implementation_key="OPENAI_RESPONSES_API_V1",
            ),
        )
    )
    prompts = PromptRoutesProvisioning.model_construct(
        semantic_validator_bindings=(
            SemanticValidatorBinding(
                validator_key="schemas",
                implementation_key="JSON_SCHEMA_AND_AUTHORITY_V1",
            ),
        )
    )
    policy_document = PolicyCatalogProvisioning.model_construct(
        parser_implementation_key="OFFICIAL_HTTP_POLICY_V1"
    )
    sandbox_document = SandboxProfileProvisioning.model_construct(
        authorization_implementation_key="RUNTIME_DYNAMIC_AUTHORIZATION_V1",
        setup_implementation_key="DOCKER_REPRODUCTION_SETUP_V1",
    )
    materialized = SimpleNamespace(
        documents={
            "WORKSPACE_STORAGE": workspace,
            "STATIC_ANALYSIS": static,
            "VERIFICATION_PLAYBOOKS": verification,
            "PROVIDER_CONFIGURATION": provider,
            "PROMPT_ROUTES": prompts,
            "POLICY_CATALOG": policy_document,
            "SANDBOX_PROFILE": sandbox_document,
        },
        records={common_ref: common, policy_ref: policy},
        evidence={config_digest: b"config"},
    )
    capabilities = {
        "GIT_CLONE": SimpleNamespace(),
        "GIT_CHECKOUT": SimpleNamespace(),
        "PYTHON_RUNTIME": SimpleNamespace(),
        "AST": SimpleNamespace(),
    }
    capability_bindings = tuple(
        SimpleNamespace(slot=slot, profile_ref=ref)
        for slot, ref in (
            ("GIT_CLONE", git_ref),
            ("GIT_CHECKOUT", git_ref),
            ("PYTHON_RUNTIME", python_ref),
            ("AST", ast_ref),
        )
    )
    return cast(
        ProductionBundleAssemblyContext,
        SimpleNamespace(
            data_dir=tmp_path.resolve(),
            request=SimpleNamespace(),
            profile=SimpleNamespace(
                taxonomy_version="cwe-4.17",
                allow_local_repository=False,
                timeouts=SimpleNamespace(workspace_ms=10, static_tool_ms=20),
                budget=SimpleNamespace(
                    max_total_cost_minor_units=100,
                    max_total_llm_calls=10,
                ),
                tools=SimpleNamespace(
                    git="git",
                    python="python",
                    codeql="codeql",
                    opengrep="opengrep",
                ),
                llm_routes=(),
            ),
            scope=SimpleNamespace(
                analysis_id=AnalysisId("analysis"),
                workspace_id=WorkspaceId("workspace"),
                commit_id=CommitId("c" * 40),
            ),
            implementation_set=ProductionImplementationSet(
                static_routes=("AST:PYTHON_AST:PYTHON_AST_JSON_V1",),
                provider_adapters=("OPENAI_RESPONSES_API_V1",),
                policy_parser="OFFICIAL_HTTP_POLICY_V1",
                sandbox_authorization="RUNTIME_DYNAMIC_AUTHORIZATION_V1",
                sandbox_setup="DOCKER_REPRODUCTION_SETUP_V1",
                semantic_validators=("JSON_SCHEMA_AND_AUTHORITY_V1",),
            ),
            resolved=SimpleNamespace(capabilities=capabilities),
            materialized=materialized,
            provisioning=SimpleNamespace(capabilities=capability_bindings),
            records=SimpleNamespace(),
            queries=_Queries((common, policy)),
            artifacts=SimpleNamespace(),
            configuration=SimpleNamespace(),
        ),
    )


def _static_ports() -> ProductionStaticRuntimePorts:
    return ProductionStaticRuntimePorts(
        process_receipts=lambda _action, _attempt: None,
        cancellation_observation=lambda _request, _profile: None,
        dispatch_state=lambda _action: None,
        attempt_dispatch=lambda _attempt: None,
    )


@pytest.mark.parametrize("codeql_unavailable", [False, True])
def test_default_assembler_composes_non_r7_features_and_exact_refs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, codeql_unavailable: bool
) -> None:
    from sastsimi.composition import production_default_assembler as module

    context = _assembly_context(tmp_path)
    provider_prompt = SimpleNamespace(
        adapters={cast(Any, object()): cast(Any, object())},
        approved_routes=(cast(Any, object()),),
    )
    t08 = cast(T08ProductionFeature, SimpleNamespace(workspace_locator=object()))
    policy = cast(PolicyProductionFeature, SimpleNamespace())
    calls = cast(Any, SimpleNamespace(calls=object()))
    dynamic = cast(DynamicProductionFeature, SimpleNamespace())
    cancellation = cast(Any, SimpleNamespace(cancel=lambda _target: None))
    installed = cast(Any, object())
    captured: dict[str, object] = {}

    def static_runtime_factory(context: object) -> ProductionStaticRuntimePorts:
        if codeql_unavailable:
            module._require_static_runtime_ports(
                _static_ports(),
                StaticAnalysisProvisioning.model_construct(
                    enabled_tools=("AST", "CODEQL")
                ),
            )
        return _static_ports()

    monkeypatch.setattr(
        module,
        "build_production_provider_prompt_feature",
        lambda **kwargs: captured.setdefault("provider", kwargs) and provider_prompt,
    )
    monkeypatch.setattr(
        module,
        "build_production_policy_feature_factory",
        lambda found: (
            captured.setdefault("policy_context", found)
            and (lambda install_context, production_calls: policy)
        ),
    )
    monkeypatch.setattr(
        module,
        "build_production_call_feature",
        lambda **kwargs: captured.setdefault("calls", kwargs) and calls,
    )
    monkeypatch.setattr(
        module,
        "build_production_t08_feature",
        lambda install_context, inputs: (
            captured.setdefault("t08", (install_context, inputs)) and t08
        ),
    )
    monkeypatch.setattr(
        module,
        "ProductionFeatureInstaller",
        lambda inputs: (
            captured.setdefault("feature_inputs", inputs)
            and (lambda install_context: installed)
        ),
    )

    registry = build_default_production_bundle_registry(
        implementation_set=context.implementation_set,
        repository_root=Path.cwd(),
        static_runtime_factory=static_runtime_factory,
        dynamic_feature_factory=lambda assembly, install_context, static: (
            BuiltProductionDynamicFeature(dynamic, (lambda: None,))
        ),
        cancellation_factory=lambda install_context, static, adapters, feature: (
            cancellation
        ),
        executable_resolver=lambda _name: Path(__file__).resolve(),
    )
    assembly = registry(context)
    install_context = SimpleNamespace(
        data_dir=context.data_dir,
        request=context.request,
        profile=context.profile,
        scope=context.scope,
        runner=object(),
        runtime=SimpleNamespace(unit_of_work=SimpleNamespace(records=context.records)),
        approved_llm_routes=provider_prompt.approved_routes,
        role_identity_refs={role: cast(Any, object()) for role in RequesterRole},
    )

    assert assembly.llm_adapters is provider_prompt.adapters
    assert assembly.approved_llm_routes is provider_prompt.approved_routes
    if codeql_unavailable:
        with pytest.raises(
            ProductionAnalyzeUnavailable,
            match="PRODUCTION_CODEQL_SAFE_PREREQUISITES_UNAVAILABLE",
        ):
            assembly.install(cast(Any, install_context))
        assert "t08" not in captured
        assert "feature_inputs" not in captured
        return
    assert assembly.install(cast(Any, install_context)) is installed
    feature_inputs = cast(Any, captured["feature_inputs"])
    assert feature_inputs.t08 is t08
    assert feature_inputs.policy is policy
    assert feature_inputs.calls is calls.calls
    assert feature_inputs.dynamic is dynamic
    assert feature_inputs.verification_policy_ref == reference(_playbooks()[2])
    assert feature_inputs.verification_playbook_ref == reference(_playbooks()[0])
    assert feature_inputs.taxonomy_version == "cwe-4.17"
    assert feature_inputs.external_cancellation is cancellation
    assert len(feature_inputs.readiness_checks) == 1


def test_default_assembler_rejects_unsupported_implementation_before_building(
    tmp_path: Path,
) -> None:
    context = _assembly_context(tmp_path)
    context = cast(
        ProductionBundleAssemblyContext,
        SimpleNamespace(
            **{
                **vars(cast(Any, context)),
                "implementation_set": ProductionImplementationSet(
                    static_routes=("AST:IMPORT_ARBITRARY:PYTHON_AST_JSON_V1",),
                    provider_adapters=("OPENAI_RESPONSES_API_V1",),
                    policy_parser="OFFICIAL_HTTP_POLICY_V1",
                    sandbox_authorization="RUNTIME_DYNAMIC_AUTHORIZATION_V1",
                    sandbox_setup="DOCKER_REPRODUCTION_SETUP_V1",
                    semantic_validators=("JSON_SCHEMA_AND_AUTHORITY_V1",),
                ),
            }
        ),
    )
    assembler = build_default_production_bundle_assembler(
        repository_root=Path.cwd(),
        static_runtime_factory=lambda _context: _static_ports(),
        dynamic_feature_factory=lambda _assembly, _context, _static: cast(
            Any, object()
        ),
        cancellation_factory=lambda *_args: cast(Any, object()),
    )

    with pytest.raises(
        ProductionCapabilityUnavailable,
        match="PRODUCTION_FEATURE_SET_UNSUPPORTED",
    ):
        assembler(context)


def test_default_assembler_rejects_non_current_playbook_reference(
    tmp_path: Path,
) -> None:
    context = _assembly_context(tmp_path)
    context = cast(
        ProductionBundleAssemblyContext,
        SimpleNamespace(
            **{
                **vars(cast(Any, context)),
                "queries": _Queries(()),
            }
        ),
    )
    assembler = build_default_production_bundle_assembler(
        repository_root=Path.cwd(),
        static_runtime_factory=lambda _context: _static_ports(),
        dynamic_feature_factory=lambda _assembly, _context, _static: cast(
            Any, object()
        ),
        cancellation_factory=lambda *_args: cast(Any, object()),
    )

    with pytest.raises(
        ProductionCapabilityUnavailable,
        match="PRODUCTION_PLAYBOOK_RECORD_STALE",
    ):
        assembler(context)
