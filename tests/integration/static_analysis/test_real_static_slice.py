"""Exact private wiring tests; component behavior is tested in focused suites."""

import hashlib
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.bootstrap import _build_real_static_slice, build_runtime
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.static import StaticToolProfile
from sastsimi.orchestration.static_external_runner import (
    RepositoryRecoveryValidatorPort,
    StaticDispatchState,
    StaticExternalRunner,
)
from sastsimi.orchestration.static_publication import StaticNormalizationPublisher
from sastsimi.ports.context import ContextLineageReaderPort
from sastsimi.ports.dto import (
    CancellationResult,
    CanonicalRepositorySource,
    MonotonicActionDeadline,
    ProcessReceipt,
    StaticCapabilityObservation,
    StaticRuleMapping,
    StaticToolObservation,
    StaticToolRequest,
    WorkspaceStoragePolicy,
)
from sastsimi.ports.workspace import WorkspaceLocatorPort
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.static_analysis.coordinator import StaticToolCoordinator
from sastsimi.static_analysis.normalizer import decoder_key
from sastsimi.verification.context_service import (
    ContextRetrievalService,
    TrackedFilesResolver,
)
from tests.contract.domain.fixtures import meta, ref
from tests.integration.runtime_support import Harness
from tests.integration.static_analysis.conftest import RealStaticSlicePaths


def _unreachable_source(_value: str) -> CanonicalRepositorySource:
    raise AssertionError("repository preparation is outside this composition test")


def _unreachable_policy(
    _ref: Any, _raw: bytes, _media_type: str
) -> WorkspaceStoragePolicy:
    raise AssertionError("repository preparation is outside this composition test")


def _profile(
    *,
    adapter_key: str,
    tool_name: str,
    tool_kind: str,
    executable_key: str,
    executable: Path,
    version: str,
) -> StaticToolProfile:
    metadata = meta("static_tool_profile", attempt=None)
    metadata.update(
        record_id=f"{adapter_key.lower()}-profile-r1",
        logical_record_id=f"{adapter_key.lower()}-profile-l1",
    )
    return StaticToolProfile.model_validate_json(
        canonical_bytes(
            {
                "meta": metadata,
                "profile_key": f"{adapter_key.lower()}-fixture",
                "purpose": "FIXTURE",
                "status": "APPROVED",
                "adapter_key": adapter_key,
                "tool_name": tool_name,
                "tool_kind": tool_kind,
                "executable_key": executable_key,
                "executable_sha256": hashlib.sha256(
                    executable.read_bytes()
                ).hexdigest(),
                "expected_version": version,
                "capability_evidence_ref": None,
                "probe_timeout_ms": 100,
                "run_timeout_ms": 200,
                "stdout_limit_bytes": 1024,
                "stderr_limit_bytes": 1024,
                "max_attempt_output_bytes": 4096,
                "max_output_file_bytes": 2048,
                "max_artifact_read_bytes": 2048,
            }
        )
    )


@dataclass
class _ProbeAdapter:
    executable: Path
    tool_name: str
    tool_kind: str
    executable_key: str
    version: str
    probes: int = 0

    async def probe(
        self, profile: StaticToolProfile, deadline: MonotonicActionDeadline
    ) -> StaticCapabilityObservation:
        assert deadline.action_id.startswith("probe-")
        self.probes += 1
        return StaticCapabilityObservation(
            available=True,
            tool_name=self.tool_name,
            tool_kind=cast(Any, self.tool_kind),
            executable_key=self.executable_key,
            observed_executable_sha256=hashlib.sha256(
                self.executable.read_bytes()
            ).hexdigest(),
            observed_version=self.version,
            expected_version=profile.expected_version,
            reason_code=None,
        )

    async def execute(
        self,
        request: StaticToolRequest,
        workspace_root: Path,
        profile: StaticToolProfile,
        deadline: MonotonicActionDeadline,
    ) -> StaticToolObservation:
        del request, workspace_root, profile, deadline
        raise AssertionError("execution behavior is covered by focused adapter suites")

    async def cancel(self, attempt_id: str) -> CancellationResult:
        return CancellationResult(False, attempt_id)


@pytest.mark.asyncio
async def test_private_factory_wires_exact_existing_components(
    real_static_slice_paths: RealStaticSlicePaths,
) -> None:
    runtime_root = real_static_slice_paths.workspace_root / "runtime"
    runtime_root.mkdir()
    h = Harness(runtime_root)
    approved_profiles: set[str] = set()
    trusted = cast(Any, h.evidence)
    trusted.static_tool_configuration_approved = lambda candidate: (
        content_hash(candidate) in approved_profiles
    )
    runtime = build_runtime(
        runtime_root,
        None,
        None,
        h.clock,
        h.ids,
        evidence=h.evidence,
    )
    runner = WorkflowRunner(runtime, h.clock, h.ids)
    profile_inputs = (
        ("PYTHON_AST", "AST", "STRUCTURE", "fixture-python", "3.12"),
        ("CODEQL", "CODEQL", "RULE_BASED", "fixture-codeql", "1.0"),
        ("OPENGREP", "OPENGREP", "RULE_BASED", "fixture-opengrep", "1.0"),
    )
    profiles = tuple(
        _profile(
            adapter_key=adapter_key,
            tool_name=tool_name,
            tool_kind=tool_kind,
            executable_key=executable_key,
            executable=real_static_slice_paths.executable,
            version=version,
        )
        for adapter_key, tool_name, tool_kind, executable_key, version in profile_inputs
    )
    approved_profiles.update(content_hash(profile) for profile in profiles)
    profile_refs = tuple(
        runtime.configuration.register_static_tool_profile(profile)
        for profile in profiles
    )
    assert (
        tuple(
            runtime.configuration.resolve_static_tool_profile(profile_ref)
            for profile_ref in profile_refs
        )
        == profiles
    )

    workspace_locator = cast(WorkspaceLocatorPort, SimpleNamespace())
    adapters = {
        adapter_key: _ProbeAdapter(
            real_static_slice_paths.executable,
            tool_name,
            tool_kind,
            executable_key,
            version,
        )
        for adapter_key, tool_name, tool_kind, executable_key, version in profile_inputs
    }
    executables = {
        "fixture-python": real_static_slice_paths.executable,
        "fixture-codeql": real_static_slice_paths.executable,
        "fixture-opengrep": real_static_slice_paths.executable,
    }
    tracked_files_for = cast(TrackedFilesResolver, lambda _workspace: ())
    lineage_reader = cast(ContextLineageReaderPort, SimpleNamespace())
    catalog_ref = StoredDataRef.model_validate(ref("rule_catalog"))
    decoder = cast(Any, lambda _raw, _input: None)
    decoders = {decoder_key(profile_refs[0], "AST", "3.12"): decoder}
    rule_catalogs = {catalog_ref: ("R1",)}
    rule_selections = {catalog_ref: ("R1",)}
    rule_mappings = {catalog_ref: (StaticRuleMapping("R1", "SOURCE", None, False),)}

    def process_receipts(
        _action_id: str, _attempt_id: str
    ) -> tuple[ProcessReceipt, ...]:
        return ()

    def dispatch_state(_action_id: str) -> StaticDispatchState | None:
        return None

    def cancellation_observation(
        _request: StaticToolRequest, _profile: StaticToolProfile
    ) -> StaticToolObservation | None:
        return None

    def lease_root_resolver(lease_id: str) -> Path:
        return real_static_slice_paths.workspace_root / lease_id

    recovery_validator = cast(RepositoryRecoveryValidatorPort, SimpleNamespace())

    slice_ = _build_real_static_slice(
        runner=runner,
        workspace_locator=workspace_locator,
        adapters=adapters,
        executables=executables,
        receipt_root=real_static_slice_paths.receipt_root,
        context_receipt_root=real_static_slice_paths.context_receipt_root,
        canonicalize_source=_unreachable_source,
        decode_policy=_unreachable_policy,
        static_process_receipts=process_receipts,
        static_cancellation_observation=cancellation_observation,
        static_dispatch_state=dispatch_state,
        lease_root_resolver=lease_root_resolver,
        recovery_validator=recovery_validator,
        decoders=decoders,
        rule_catalogs=rule_catalogs,
        rule_selections=rule_selections,
        rule_mappings=rule_mappings,
        tracked_files_for=tracked_files_for,
        prohibited_workspace_roots=(real_static_slice_paths.workspace_root,),
        lineage_reader=lineage_reader,
    )

    assert isinstance(slice_.external, StaticExternalRunner)
    assert isinstance(slice_.tools, StaticToolCoordinator)
    assert isinstance(slice_.normalization, StaticNormalizationPublisher)
    assert isinstance(slice_.context, ContextRetrievalService)
    capabilities = tuple(
        [await slice_.tools.probe(profile_ref) for profile_ref in profile_refs]
    )
    assert all(item.available for item in capabilities)
    assert all(adapter.probes == 1 for adapter in adapters.values())
    assert (
        tuple(
            slice_.tools._profiles.resolve(profile_ref) for profile_ref in profile_refs
        )
        == profiles
    )
    assert dict(slice_.tools._adapters) == adapters
    assert dict(slice_.tools._executables) == executables
    assert slice_.tools._external is slice_.external
    assert slice_.tools._prohibited_roots == (
        real_static_slice_paths.workspace_root.resolve(),
    )
    assert slice_.external.receipt_root == real_static_slice_paths.receipt_root
    assert slice_.external.static_process_receipts is process_receipts
    assert slice_.external.static_cancellation_observation is cancellation_observation
    assert slice_.external.static_dispatch_state is dispatch_state
    assert slice_.external.lease_root_resolver is lease_root_resolver
    assert slice_.external.recovery_validator is recovery_validator
    assert slice_.external.static_publisher.rule_catalogs == rule_catalogs
    assert slice_.external.static_publisher.rule_selections == rule_selections
    assert dict(slice_.normalization.normalizer._decoders) == decoders
    assert dict(slice_.normalization._rule_mappings) == rule_mappings
    assert slice_.context.runtime is runtime
    assert slice_.context.runner is runner
    assert slice_.context.workspace_locator is workspace_locator
    assert slice_.context.tracked_files_for is tracked_files_for
    assert slice_.context.lineage_reader is lineage_reader
    assert slice_.context.receipt_root == real_static_slice_paths.context_receipt_root


def test_private_factory_requires_explicit_paths_and_registries() -> None:
    import inspect

    signature = inspect.signature(_build_real_static_slice)
    assert "runtime" not in signature.parameters
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY
        for parameter in signature.parameters.values()
    )
    assert {
        "workspace_locator",
        "adapters",
        "executables",
        "receipt_root",
        "context_receipt_root",
        "static_process_receipts",
        "static_cancellation_observation",
        "static_dispatch_state",
        "lease_root_resolver",
        "recovery_validator",
        "decoders",
        "rule_catalogs",
        "rule_selections",
        "rule_mappings",
        "tracked_files_for",
        "prohibited_workspace_roots",
    }.issubset(signature.parameters)
    assert all(
        signature.parameters[name].default is inspect.Parameter.empty
        for name in signature.parameters
        if name != "lineage_reader"
    )
