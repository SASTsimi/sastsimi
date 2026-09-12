"""Profile-backed production capability resolution and failure persistence."""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from threading import Lock
from typing import Protocol

from sastsimi.config.production_profile import ProductionProfile
from sastsimi.contracts.actions import ActionRequest, CheckType, RequesterRole
from sastsimi.contracts.analysis import AnalysisStartRequest
from sastsimi.contracts.budget import (
    BudgetProfileBinding,
    DynamicReproductionLifecycleProfile,
    ExecutionBudgetProfile,
    Purpose,
    VerificationBudgetProfile,
    WorkBudgetProfile,
)
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.capabilities import (
    CapabilityApprovalEvidence,
    RuntimeCapabilityProfile,
)
from sastsimi.contracts.dynamic import SandboxProfile
from sastsimi.contracts.ids import AnalysisId, CommitId, WorkspaceId
from sastsimi.contracts.llm import LLMRecord, ProviderProfile
from sastsimi.contracts.refs import (
    BudgetScopeRef,
    HostConfigurationRef,
    RecordRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.static import StaticToolProfile
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.capability_registry import ProductionCapabilityResolverPort
from sastsimi.ports.dto import WorkContext
from sastsimi.ports.llm_provider import LLMProviderAdapter
from sastsimi.ports.record_store import RecordStore
from sastsimi.ports.runtime_query import RuntimeQueryPort
from sastsimi.ports.trusted_evidence import TrustedEvidencePort
from sastsimi.runtime.work_service import HandlerFailureRecorder
from sastsimi.runtime.workflow_runner import WorkflowRunner

from .production_call_authority import (
    AnalysisApprovedRoute,
    ExactAnalysisProductionRouteLookup,
)
from .production_composition import (
    InstalledProductionServices,
    ProductionCapabilityUnavailable,
    ProductionFeatureInstaller,
    ProductionInstallationContext,
    ResolvedProductionCapabilities,
)
from .production_operator_profiles import ProductionTrustedEvidence
from .run_scope_plan import PlannedRunScope

_SAFE_REASON = re.compile(r"[A-Z0-9_]{1,96}\Z")


def production_profile_hash(profile: ProductionProfile) -> str:
    """Hash the credential-free JSON view, including normalized path strings."""

    return content_hash(profile.model_dump(mode="json"))


class ProductionCapabilityBundleLoader(Protocol):
    """Load one explicitly selected capability bundle for an allocated scope."""

    def __call__(
        self,
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: ProductionProfile,
        scope: PlannedRunScope,
    ) -> ProfileBackedProductionCapabilityBundle: ...


@dataclass(frozen=True, slots=True)
class ProfileBackedProductionCapabilityBundle:
    """Trusted exact records and adapters selected for one production run."""

    profile_hash: str
    data_dir: Path
    analysis_id: AnalysisId
    workspace_id: WorkspaceId
    commit_id: CommitId
    repository_ref: str
    host_id: str
    llm_adapters: Mapping[tuple[StoredDataRef, str], LLMProviderAdapter]
    approved_llm_routes: tuple[AnalysisApprovedRoute, ...]
    workspace_dependency_refs: tuple[RecordRef, ...]
    records: RecordStore
    queries: RuntimeQueryPort
    artifacts: ArtifactStore
    configuration: ProductionCapabilityResolverPort
    configuration_evidence: TrustedEvidencePort
    install: ProductionFeatureInstaller


class DurableHandlerFailureRecorder(HandlerFailureRecorder):
    """End one exact failed handler attempt through the normal durable CAS path."""

    def __init__(
        self, runner: WorkflowRunner, recovery_identity_ref: StoredDataRef
    ) -> None:
        self._runner = runner
        self._identity = recovery_identity_ref

    def record_handler_failure(
        self, context: WorkContext, reason_code: str
    ) -> WorkExecutionState:
        if _SAFE_REASON.fullmatch(reason_code) is None:
            raise ValueError("HANDLER_FAILURE_REASON_INVALID")
        work = context.work
        if (
            work.status != "RUNNING"
            or work.active_attempt_id != context.attempt.attempt_id
            or work.work_id != context.attempt.work_id
            or work.input_hash != context.attempt.input_hash
        ):
            raise ValueError("HANDLER_FAILURE_CONTEXT_NOT_CURRENT")
        return self._runner.block(
            work,
            self._identity,
            reason_code,
            role=RequesterRole.RECOVERY.value,
        )


class _DeferredHandlerFailureRecorder(HandlerFailureRecorder):
    """Bind the durable recorder only after the factory creates its runtime."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._delegate: DurableHandlerFailureRecorder | None = None

    def bind(self, delegate: DurableHandlerFailureRecorder) -> None:
        with self._lock:
            if self._delegate is not None:
                raise ValueError("HANDLER_FAILURE_RECORDER_ALREADY_BOUND")
            self._delegate = delegate

    def record_handler_failure(
        self, context: WorkContext, reason_code: str
    ) -> WorkExecutionState:
        with self._lock:
            delegate = self._delegate
        if delegate is None:
            raise ValueError("HANDLER_FAILURE_RECORDER_NOT_BOUND")
        return delegate.record_handler_failure(context, reason_code)


class CompositeProductionTrustedEvidence(TrustedEvidencePort):
    """Keep operator authority separate from pre-approved configuration evidence."""

    def __init__(
        self,
        operator: ProductionTrustedEvidence,
        configuration: TrustedEvidencePort,
    ) -> None:
        self._operator = operator
        self._configuration = configuration

    @contextmanager
    def output_approval(
        self,
        action: ActionRequest,
        work: WorkExecutionState,
        output_refs: tuple[RecordRef, ...],
    ) -> Iterator[None]:
        """Delegate attempt-local output authority to the operator boundary."""

        with self._operator.output_approval(action, work, output_refs):
            yield

    def capability_approval_authorized(
        self, evidence: CapabilityApprovalEvidence
    ) -> bool:
        return self._configuration.capability_approval_authorized(evidence)

    def static_tool_configuration_approved(self, profile: StaticToolProfile) -> bool:
        return self._configuration.static_tool_configuration_approved(profile)

    def generation_restart_evidence(
        self, action: ActionRequest
    ) -> tuple[BudgetScopeRef, ...] | None:
        operator = self._operator.generation_restart_evidence(action)
        return (
            operator
            if operator is not None
            else self._configuration.generation_restart_evidence(action)
        )

    def authorized_outputs(
        self, action: ActionRequest
    ) -> tuple[RecordRef, ...] | None:
        return self._operator.authorized_outputs(action)

    def identity_role(self, ref: BudgetScopeRef) -> RequesterRole | None:
        return self._operator.identity_role(ref)

    def approved(
        self, profile: ExecutionBudgetProfile | BudgetProfileBinding
    ) -> bool:
        return self._operator.approved(profile)

    def pricing(self, profile: ExecutionBudgetProfile) -> bool:
        return self._operator.pricing(profile)

    def budget_configuration_approved(
        self,
        profile: WorkBudgetProfile
        | VerificationBudgetProfile
        | DynamicReproductionLifecycleProfile,
    ) -> bool:
        return self._operator.budget_configuration_approved(profile)

    def playbook_configuration_approved(
        self, record: VerificationPlaybook | PlaybookPolicy
    ) -> bool:
        return self._configuration.playbook_configuration_approved(record)

    def llm_configuration_approved(self, record: LLMRecord) -> bool:
        return self._configuration.llm_configuration_approved(record)

    def sandbox_configuration_approved(self, profile: SandboxProfile) -> bool:
        return self._configuration.sandbox_configuration_approved(profile)

    def action_evidence(
        self, action: ActionRequest, check: CheckType
    ) -> tuple[BudgetScopeRef, ...] | None:
        return self._operator.action_evidence(action, check)

    def item_count(
        self, action: ActionRequest, work: WorkExecutionState
    ) -> int | None:
        return self._operator.item_count(action, work)


class ProfileBackedProductionCapabilityResolver:
    """Resolve one exact bundle and revalidate every mutable current pointer."""

    def __init__(self, load_bundle: ProductionCapabilityBundleLoader) -> None:
        self._load_bundle = load_bundle

    def resolve(
        self,
        *,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: ProductionProfile,
        scope: PlannedRunScope,
    ) -> ResolvedProductionCapabilities:
        try:
            bundle = self._load_bundle(
                data_dir=data_dir,
                request=request,
                profile=profile,
                scope=scope,
            )
        except ProductionCapabilityUnavailable:
            raise
        except Exception:
            raise ProductionCapabilityUnavailable(
                "PRODUCTION_CAPABILITY_BUNDLE_UNAVAILABLE"
            ) from None
        self._require_identity(bundle, data_dir, request, profile, scope)
        try:
            self._require_current(bundle, profile, scope)
        except (LookupError, OSError, TypeError, ValueError):
            raise ProductionCapabilityUnavailable(
                "PRODUCTION_CAPABILITY_BUNDLE_NOT_CURRENT"
            ) from None

        recorder = _DeferredHandlerFailureRecorder()

        def install(
            context: ProductionInstallationContext,
        ) -> InstalledProductionServices:
            if (
                context.data_dir.resolve() != data_dir.resolve()
                or context.request != request
                or context.profile != profile
                or context.scope != scope
                or context.approved_llm_routes != bundle.approved_llm_routes
            ):
                raise ProductionCapabilityUnavailable(
                    "PRODUCTION_CAPABILITY_INSTALL_SCOPE_MISMATCH"
                )
            identity = context.role_identity_refs.get(RequesterRole.RECOVERY)
            if not isinstance(identity, StoredDataRef):
                raise ProductionCapabilityUnavailable(
                    "PRODUCTION_RECOVERY_IDENTITY_REQUIRED"
                )
            recorder.bind(DurableHandlerFailureRecorder(context.runner, identity))
            return bundle.install(context)

        return ResolvedProductionCapabilities(
            llm_adapters=bundle.llm_adapters,
            approved_llm_routes=bundle.approved_llm_routes,
            workspace_dependency_refs=bundle.workspace_dependency_refs,
            handler_failure_recorder=recorder,
            install=install,
            configuration_evidence=bundle.configuration_evidence,
        )

    @staticmethod
    def _require_identity(
        bundle: ProfileBackedProductionCapabilityBundle,
        data_dir: Path,
        request: AnalysisStartRequest,
        profile: ProductionProfile,
        scope: PlannedRunScope,
    ) -> None:
        if (
            bundle.profile_hash != production_profile_hash(profile)
            or bundle.data_dir.resolve() != data_dir.resolve()
        ):
            raise ProductionCapabilityUnavailable(
                "PRODUCTION_PROFILE_CAPABILITY_MISMATCH"
            )
        if (
            (
                bundle.analysis_id,
                bundle.workspace_id,
                bundle.commit_id,
                bundle.repository_ref,
                bundle.host_id,
            )
            != (
                scope.analysis_id,
                scope.workspace_id,
                scope.commit_id,
                scope.repository_ref,
                profile.host_id,
            )
            or request.repository_ref != scope.repository_ref
            or request.requested_git_ref.lower() != str(scope.commit_id)
            or str(request.program_id) != profile.program_id
            or request.purpose != Purpose.PRODUCTION
        ):
            raise ProductionCapabilityUnavailable(
                "PRODUCTION_CAPABILITY_SCOPE_MISMATCH"
            )

    @staticmethod
    def _require_current(
        bundle: ProfileBackedProductionCapabilityBundle,
        profile: ProductionProfile,
        scope: PlannedRunScope,
    ) -> None:
        lookup = ExactAnalysisProductionRouteLookup(
            records=bundle.records,
            queries=bundle.queries,
            approvals=bundle.approved_llm_routes,
        )
        connections = {
            item.provider_profile_key: item for item in profile.providers
        }
        for configured in profile.llm_routes:
            route, approval = lookup(
                str(scope.analysis_id), configured.role, configured.task_kind
            )
            if any(
                getattr(route, name) != getattr(configured, name)
                for name in (
                    "role",
                    "task_kind",
                    "provider_profile_key",
                    "model",
                    "prompt_key",
                )
            ):
                raise ValueError("PRODUCTION_LLM_ROUTE_MISMATCH")
            provider = bundle.records.get_exact(approval.provider_profile_ref)
            connection = connections[configured.provider_profile_key]
            credential_source = (
                "OFFICIAL_CLIENT_SESSION"
                if connection.product in {"CODEX", "CLAUDE_CODE"}
                else (
                    "ENVIRONMENT"
                    if connection.credential_ref.reference.startswith("env:")
                    else "SECRET_STORE"
                )
            )
            if (
                not isinstance(provider, ProviderProfile)
                or reference(provider) != approval.provider_profile_ref
                or provider.support_status != "SUPPORTED"
                or (
                    provider.profile_key,
                    provider.product,
                    provider.environment,
                    provider.client_name,
                    provider.client_version,
                    provider.model,
                    provider.credential_source,
                )
                != (
                    connection.provider_profile_key,
                    connection.product,
                    connection.environment,
                    connection.client_name,
                    connection.client_version,
                    configured.model,
                    credential_source,
                )
            ):
                raise ValueError("PRODUCTION_PROVIDER_PROFILE_MISMATCH")

        policies = tuple(
            ref
            for ref in bundle.workspace_dependency_refs
            if isinstance(ref, RunStoredDataRef)
        )
        git_refs = tuple(
            ref
            for ref in bundle.workspace_dependency_refs
            if isinstance(ref, HostConfigurationRef)
        )
        if len(policies) != 1 or len(git_refs) not in {1, 2}:
            raise ValueError("PRODUCTION_WORKSPACE_CAPABILITY_INVALID")
        policy = policies[0]
        if (
            policy.data_kind != "artifact"
            or policy.record_id is not None
            or policy.analysis_id != scope.analysis_id
        ):
            raise ValueError("PRODUCTION_WORKSPACE_CAPABILITY_INVALID")
        with bundle.artifacts.open_verified(policy) as stream:
            stream.read()

        operations: set[str] = set()
        for ref in git_refs:
            resolved = bundle.configuration.resolve_pinned_active_profile(ref)
            if (
                not isinstance(resolved, RuntimeCapabilityProfile)
                or reference(resolved) != ref
                or resolved.host_id != profile.host_id
                or resolved.capability_kind != "GIT"
                or resolved.status != "ACTIVE"
            ):
                raise ValueError("PRODUCTION_GIT_CAPABILITY_INVALID")
            operations.update(resolved.operations)
        if not {"CLONE", "CHECKOUT"} <= operations:
            raise ValueError("PRODUCTION_GIT_CAPABILITY_INVALID")


__all__ = [
    "CompositeProductionTrustedEvidence",
    "DurableHandlerFailureRecorder",
    "ProductionCapabilityBundleLoader",
    "ProfileBackedProductionCapabilityBundle",
    "ProfileBackedProductionCapabilityResolver",
    "production_profile_hash",
]
