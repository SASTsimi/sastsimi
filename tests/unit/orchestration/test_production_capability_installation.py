from __future__ import annotations

import shutil
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import pytest

from sastsimi.config.production_profile import ProductionProfile
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.budget import Purpose
from sastsimi.contracts.capabilities import RuntimeCapabilityProfile
from sastsimi.contracts.ids import (
    AnalysisId,
    CommitId,
    ProgramId,
    RecordId,
    StoredDataId,
    WorkspaceId,
)
from sastsimi.contracts.refs import (
    HostConfigurationRef,
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.work import WorkType
from sastsimi.orchestration.production_call_authority import AnalysisApprovedRoute
from sastsimi.orchestration.production_capabilities import (
    DurableHandlerFailureRecorder,
    ProfileBackedProductionCapabilityBundle,
    ProfileBackedProductionCapabilityResolver,
    production_profile_hash,
)
from sastsimi.orchestration.production_composition import (
    InstalledProductionServices,
    ProductionCapabilityUnavailable,
    ProductionInstallationContext,
)
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.ports.llm_provider import LLMProviderAdapter
from sastsimi.ports.trusted_evidence import UnprovenEvidence
from sastsimi.storage.artifact_store import LocalArtifactStore
from tests.contract.domain.fixtures import meta
from tests.integration.orchestration.test_production_composition import _profile
from tests.unit.orchestration.test_production_llm_work_handlers import _context
from tests.unit.prompts.test_production_configuration import (
    _approved_hypothesis_route,
    _service,
)


class _Provider:
    async def invoke(self, request: object) -> object:
        raise AssertionError(request)

    async def cancel(self, invocation_id: str) -> object:
        raise AssertionError(invocation_id)

    async def probe(self, profile: object) -> object:
        raise AssertionError(profile)


class _Capabilities:
    def __init__(self, profile: RuntimeCapabilityProfile) -> None:
        self.profile = profile
        self.calls: list[HostConfigurationRef] = []

    def resolve_pinned_active_profile(
        self, profile_ref: HostConfigurationRef
    ) -> RuntimeCapabilityProfile:
        self.calls.append(profile_ref)
        return self.profile


class _BlockRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[object, object, str, str]] = []

    def block(
        self,
        work: object,
        identity: object,
        cause: str,
        *,
        role: str,
    ) -> object:
        self.calls.append((work, identity, cause, role))
        return cast(Any, work).model_copy(
            update={"status": "BLOCKED", "active_attempt_id": None}
        )


@pytest.fixture
def data_dir() -> Iterator[Path]:
    path = Path.cwd() / f".production-capability-test-{uuid4()}"
    try:
        yield path
    finally:
        if path.exists():
            shutil.rmtree(path)


def _single_route_profile(route: object) -> ProductionProfile:
    values = _profile().model_dump(mode="python")
    values["providers"] = (
        {
            "provider_profile_key": "approved-provider",
            "product": "OPENAI_API",
            "environment": "PERSONAL_LOCAL",
            "client_name": "client_name",
            "client_version": "client_version",
            "credential_ref": {"reference": "env:OPENAI_API_KEY"},
        },
    )
    values["llm_routes"] = (
        {
            "role": cast(Any, route).role,
            "task_kind": cast(Any, route).task_kind,
            "provider_profile_key": cast(Any, route).provider_profile_key,
            "model": cast(Any, route).model,
            "prompt_key": cast(Any, route).prompt_key,
        },
    )
    return ProductionProfile.model_validate(values)


def _scope() -> PlannedRunScope:
    return PlannedRunScope(
        analysis_id=AnalysisId("a1"),
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
        repository_ref="https://example.invalid/repository.git",
    )


def _request() -> AnalysisStartRequest:
    return AnalysisStartRequest(
        repository_ref=_scope().repository_ref,
        requested_git_ref=str(_scope().commit_id),
        program_id=ProgramId("program-one"),
        purpose=Purpose.PRODUCTION,
    )


def _git_profile() -> RuntimeCapabilityProfile:
    approval_ref = HostConfigurationRef(
        stored_data_id=StoredDataId("git-approval"),
        data_kind="tool_capability_evidence",
        content_hash="a" * 64,
        host_id="host-one",
        publication_analysis_id=_scope().analysis_id,
        publication_workspace_id=_scope().workspace_id,
        publication_commit_id=_scope().commit_id,
        record_id=RecordId("git-approval"),
    )
    profile_meta = meta(
        "runtime_capability_profile", hypothesis=None, attempt=None
    )
    profile_meta["created_at"] = datetime(2026, 9, 13, tzinfo=UTC)
    return RuntimeCapabilityProfile.model_validate(
        {
            "meta": profile_meta,
            "host_id": "host-one",
            "profile_key": "git-production",
            "purpose": "PRODUCTION",
            "status": "ACTIVE",
            "capability_kind": "GIT",
            "subject_key": "git",
            "expected_version": "2.0",
            "subject_sha256": "b" * 64,
            "operating_system": "windows",
            "architecture": "x86_64",
            "languages": ("ANY",),
            "operations": ("CLONE", "CHECKOUT"),
            "capability_evidence_ref": approval_ref,
        }
    )


def _policy_ref(artifacts: LocalArtifactStore) -> RunStoredDataRef:
    stored = artifacts.commit(
        artifacts.stage_bytes(b'{"policy":"approved"}', "application/json")
    )
    return RunStoredDataRef(
        stored_data_id=stored.stored_data_id,
        data_kind="artifact",
        content_hash=stored.content_hash,
        analysis_id=_scope().analysis_id,
        record_id=None,
    )


def _bundle(
    tmp_path: Path,
) -> tuple[
    ProfileBackedProductionCapabilityBundle,
    ProductionProfile,
    Any,
    _Capabilities,
]:
    service, records, artifacts = _service(tmp_path)
    route, approval = _approved_hypothesis_route(service, records, artifacts)
    profile = _single_route_profile(route)
    git_profile = _git_profile()
    git_ref = reference(git_profile)
    assert isinstance(git_ref, HostConfigurationRef)
    capabilities = _Capabilities(git_profile)

    def install(context: ProductionInstallationContext) -> InstalledProductionServices:
        del context
        return cast(InstalledProductionServices, SimpleNamespace())

    bundle = ProfileBackedProductionCapabilityBundle(
        profile_hash=production_profile_hash(profile),
        data_dir=tmp_path,
        analysis_id=_scope().analysis_id,
        workspace_id=_scope().workspace_id,
        commit_id=_scope().commit_id,
        repository_ref=_scope().repository_ref,
        host_id=profile.host_id,
        llm_adapters=cast(
            dict[tuple[StoredDataRef, str], LLMProviderAdapter],
            {(approval.provider_profile_ref, route.model): _Provider()},
        ),
        approved_llm_routes=(
            AnalysisApprovedRoute(
                analysis_id="a1",
                route=route,
                approval=approval,
            ),
        ),
        workspace_dependency_refs=cast(
            tuple[RecordRef, ...], (_policy_ref(artifacts), git_ref)
        ),
        records=records,
        queries=service._queries,  # noqa: SLF001 - exact shared test registry
        artifacts=artifacts,
        configuration=capabilities,
        configuration_evidence=UnprovenEvidence(),
        install=install,
    )
    return bundle, profile, records, capabilities


def test_profile_backed_resolver_revalidates_exact_current_bundle_and_binds_failure(
    data_dir: Path,
) -> None:
    bundle, profile, _records, capabilities = _bundle(data_dir)
    resolver = ProfileBackedProductionCapabilityResolver(lambda **_values: bundle)

    resolved = resolver.resolve(
        data_dir=data_dir,
        request=_request(),
        profile=profile,
        scope=_scope(),
    )

    assert capabilities.calls == [bundle.workspace_dependency_refs[1]]
    runner = _BlockRunner()
    identity = next(iter(bundle.llm_adapters))[0]
    context = cast(
        ProductionInstallationContext,
        SimpleNamespace(
            data_dir=data_dir,
            request=_request(),
            profile=profile,
            scope=_scope(),
            approved_llm_routes=bundle.approved_llm_routes,
            runner=runner,
            role_identity_refs={RequesterRole.RECOVERY: identity},
        ),
    )
    resolved.install(context)
    work_context = _context(WorkType.HYPOTHESIS_PROPOSAL, ())
    blocked = resolved.handler_failure_recorder.record_handler_failure(
        work_context, "WORK_HANDLER_FAILED"
    )

    assert blocked.status == "BLOCKED"
    assert runner.calls == [
        (
            work_context.work,
            identity,
            "WORK_HANDLER_FAILED",
            "RECOVERY",
        )
    ]


def test_profile_backed_resolver_rejects_stale_prompt_before_install(
    data_dir: Path,
) -> None:
    bundle, profile, records, _capabilities = _bundle(data_dir)
    active_ref = bundle.approved_llm_routes[0].approval.active_prompt_ref
    active = records.get_exact(active_ref)
    records.add(
        active.model_copy(
            update={
                "meta": active.meta.model_copy(
                    update={
                        "record_id": "replacement-record",
                        "previous_record_id": active.meta.record_id,
                        "revision_number": active.meta.revision_number + 1,
                    }
                )
            }
        )
    )
    resolver = ProfileBackedProductionCapabilityResolver(lambda **_values: bundle)

    with pytest.raises(
        ProductionCapabilityUnavailable,
        match="PRODUCTION_CAPABILITY_BUNDLE_NOT_CURRENT",
    ):
        resolver.resolve(
            data_dir=data_dir,
            request=_request(),
            profile=profile,
            scope=_scope(),
        )


def test_profile_backed_resolver_rejects_profile_mismatch_before_current_checks(
    data_dir: Path,
) -> None:
    bundle, profile, _records, capabilities = _bundle(data_dir)
    mismatched = replace(bundle, profile_hash="f" * 64)
    resolver = ProfileBackedProductionCapabilityResolver(lambda **_values: mismatched)

    with pytest.raises(
        ProductionCapabilityUnavailable,
        match="PRODUCTION_PROFILE_CAPABILITY_MISMATCH",
    ):
        resolver.resolve(
            data_dir=data_dir,
            request=_request(),
            profile=profile,
            scope=_scope(),
        )

    assert capabilities.calls == []


def test_durable_failure_recorder_rejects_unsafe_reason_without_touching_runtime(
    data_dir: Path,
) -> None:
    bundle, _profile_value, _records, _capabilities = _bundle(data_dir)
    runner = _BlockRunner()
    recorder = DurableHandlerFailureRecorder(
        cast(Any, runner), next(iter(bundle.llm_adapters))[0]
    )

    with pytest.raises(ValueError, match="HANDLER_FAILURE_REASON_INVALID"):
        recorder.record_handler_failure(
            _context(WorkType.HYPOTHESIS_PROPOSAL, ()),
            "raw C:\\Users\\operator secret",
        )

    assert runner.calls == []
