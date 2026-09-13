"""Concrete fail-closed T08 repository and static-analysis composition."""

from __future__ import annotations

import hashlib
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import cast

from sastsimi.composition.production_feature_installer import T08ProductionFeature
from sastsimi.composition.production_static_adapters import (
    StaticAdapterCancellationRouter,
    StaticAttemptDispatchReader,
)
from sastsimi.composition.runtime import build_real_static_slice
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.capabilities import RuntimeCapabilityProfile
from sastsimi.contracts.refs import (
    HostConfigurationRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.static import CodeWorkspace, StaticToolProfile
from sastsimi.orchestration.production_capabilities import production_profile_hash
from sastsimi.orchestration.production_context import ProductionInstallationContext
from sastsimi.orchestration.production_provisioning import (
    StaticAnalysisProvisioning,
    WorkspaceStorageProvisioning,
)
from sastsimi.orchestration.repository_profile_handler import (
    RepositoryProfileHandler,
    RepositoryProfileWorkHandler,
)
from sastsimi.orchestration.static_adapter_context import (
    ApprovedStaticRuleClosure,
    StaticAdapterBuildContext,
    StaticAdapterFactory,
)
from sastsimi.orchestration.static_external_runner import (
    StaticCancellationObservationReader,
    StaticDispatchStateReader,
    StaticProcessReceiptReader,
)
from sastsimi.orchestration.static_work_handlers import (
    ContextRetrievalWorkHandler,
    ExactContextRetrievalCallResolver,
    ExactRepositoryProfileCallResolver,
    ExactStaticNormalizationCallResolver,
    ExactStaticToolCallResolver,
    RepositoryProfileFanoutWorkHandler,
    StaticNormalizationWorkHandler,
    StaticPostWorkspaceSeeder,
    StaticProductionGraph,
    StaticToolRoute,
    StaticToolWorkHandler,
)
from sastsimi.orchestration.workspace_prep_handler import (
    ExactWorkspacePrepCallResolver,
    WorkspacePrepWorkHandler,
)
from sastsimi.ports.capability_registry import ProductionCapabilityResolverPort
from sastsimi.ports.context import ContextLineageReaderPort
from sastsimi.ports.dto import (
    MonotonicActionDeadline,
    ProcessReceipt,
    RepositoryPreparation,
    StaticRuleMapping,
    TrackedFile,
    WorkspaceStorageLease,
    WorkspaceStoragePolicy,
)
from sastsimi.ports.workspace import WorkspaceStoragePort
from sastsimi.static_analysis.ast_adapter import replay_python_ast_raw
from sastsimi.static_analysis.codeql_adapter import replay_codeql_raw
from sastsimi.static_analysis.normalizer import DecoderKey, RawDecoder, decoder_key
from sastsimi.static_analysis.open_grep_adapter import replay_opengrep_raw
from sastsimi.static_analysis.process import (
    AttemptOutputBudget,
    SafeProcessRunner,
    process_command_fingerprint,
)
from sastsimi.static_analysis.repository_loader import (
    RepositoryLoader,
    RepositoryProcessRunner,
    WorkspaceGuard,
    canonicalize_repository_source,
)
from sastsimi.static_analysis.repository_profile import (
    RepositoryExecutionSelector,
    RepositoryProfiler,
)
from sastsimi.static_analysis.workspace_storage import (
    ProductionWorkspaceStorage,
    decode_workspace_storage_policy,
)

_PROCESS_OUTPUT_LIMIT = 4 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class ProductionT08Inputs:
    """Operator-approved inputs that contain no inferred tool or language."""

    workspace: WorkspaceStorageProvisioning
    static: StaticAnalysisProvisioning
    git_clone_profile_ref: HostConfigurationRef
    git_checkout_profile_ref: HostConfigurationRef
    static_profile_refs: Mapping[str, HostConfigurationRef]
    evidence: Mapping[str, bytes]
    rule_closures: Mapping[str, ApprovedStaticRuleClosure]
    git_executable: Path
    build_static_adapters: StaticAdapterFactory
    static_process_receipts: StaticProcessReceiptReader
    static_cancellation_observation: StaticCancellationObservationReader
    static_dispatch_state: StaticDispatchStateReader
    static_attempt_dispatch: StaticAttemptDispatchReader
    workspace_timeout_ms: int
    repository_profile_timeout_ms: int
    allow_local_repository: bool = False
    lineage_reader: ContextLineageReaderPort | None = None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_directory(root: Path, relative: str) -> Path:
    base = root.resolve(strict=True)
    target = base.joinpath(*relative.split("/"))
    try:
        target.relative_to(base)
    except ValueError as error:
        raise ValueError("PRODUCTION_T08_PATH_INVALID") from error
    target.mkdir(parents=True, exist_ok=True)
    resolved = target.resolve(strict=True)
    if target.is_symlink() or not resolved.is_dir() or resolved != target.absolute():
        raise ValueError("PRODUCTION_T08_PATH_INVALID")
    return resolved


class _ProductionWorkspaceLocator:
    """Register only successful loader output, then guard that exact manifest."""

    def __init__(
        self,
        *,
        storage: WorkspaceStoragePort,
        git_executable: Path,
        output_dir: Path,
        recovery_timeout_ms: int,
    ) -> None:
        self._storage = storage
        self._git_executable = git_executable
        self._output_dir = output_dir
        self._recovery_timeout_ms = recovery_timeout_ms
        self._roots: dict[str, Path] = {}
        self._commits: dict[str, str] = {}
        self._manifests: dict[str, tuple[TrackedFile, ...]] = {}

    def register(self, outcome: RepositoryPreparation) -> None:
        if (
            outcome.status != "READY"
            or outcome.root is None
            or outcome.lease_id is None
            or outcome.resolved_commit_id is None
        ):
            raise ValueError("WORKSPACE_PREPARATION_NOT_READY")
        lease = self._storage.resolve(outcome.lease_id)
        if lease.workspace_id != outcome.workspace_id or lease.root.resolve(
            strict=True
        ) != outcome.root.resolve(strict=True):
            raise ValueError("WORKSPACE_PREPARATION_SCOPE_MISMATCH")
        self._storage.enforce(lease)
        self._roots[outcome.workspace_id] = outcome.root.resolve(strict=True)
        self._commits[outcome.workspace_id] = outcome.resolved_commit_id
        self._manifests[outcome.workspace_id] = outcome.tracked_files

    def _guard(self, attempt_id: str) -> WorkspaceGuard:
        output = _safe_directory(
            self._output_dir, hashlib.sha256(attempt_id.encode()).hexdigest()[:24]
        )

        def factory(
            root: Path, deadline: MonotonicActionDeadline, current_attempt: str
        ) -> RepositoryProcessRunner:
            return SafeProcessRunner(
                action_id=deadline.action_id,
                attempt_id=current_attempt,
                workspace_root=root,
                output_root=output,
                executable=self._git_executable,
                output_budget=AttemptOutputBudget(
                    attempt_id=current_attempt, limit_bytes=_PROCESS_OUTPUT_LIMIT
                ),
            )

        return WorkspaceGuard(
            roots=self._roots,
            manifests=self._manifests,
            process_runner_factory=factory,
            git_executable=self._git_executable,
            output_dir=output,
        )

    def root_for(self, workspace: CodeWorkspace) -> Path:
        try:
            root = self._roots[str(workspace.workspace_id)]
        except KeyError as error:
            raise ValueError("WORKSPACE_ROOT_NOT_REGISTERED") from error
        if (
            workspace.status != "READY"
            or workspace.commit_id is None
            or self._commits.get(str(workspace.workspace_id))
            != str(workspace.commit_id)
        ):
            raise ValueError("WORKSPACE_NOT_READY")
        return root

    async def assert_unchanged(
        self,
        workspace: CodeWorkspace,
        deadline: MonotonicActionDeadline,
        *,
        attempt_id: str,
        check_id: str,
    ) -> tuple[ProcessReceipt, ...]:
        return await self._guard(attempt_id).assert_unchanged(
            workspace, deadline, attempt_id=attempt_id, check_id=check_id
        )

    async def assert_preparation_unchanged(
        self,
        outcome: RepositoryPreparation,
        deadline: MonotonicActionDeadline,
        *,
        attempt_id: str,
        check_id: str,
    ) -> tuple[ProcessReceipt, ...]:
        return await self._guard(attempt_id).assert_preparation_unchanged(
            outcome, deadline, attempt_id=attempt_id, check_id=check_id
        )

    def validate_integrity_receipts(
        self,
        workspace: CodeWorkspace,
        deadline: MonotonicActionDeadline,
        *,
        attempt_id: str,
        check_ids: tuple[str, ...],
        receipts: tuple[ProcessReceipt, ...],
    ) -> None:
        self._guard(attempt_id).validate_integrity_receipts(
            workspace,
            deadline,
            attempt_id=attempt_id,
            check_ids=check_ids,
            receipts=receipts,
        )

    def verify_git_capability(self, subject_key: str, expected_sha256: str) -> None:
        self._guard("git-capability").verify_git_capability(
            subject_key, expected_sha256
        )

    async def validate(
        self,
        outcome: RepositoryPreparation,
        *,
        action_id: str,
        attempt_id: str,
        process_receipts: tuple[ProcessReceipt, ...],
    ) -> None:
        self.register(outcome)
        lease = self._storage.resolve(cast(str, outcome.lease_id))
        self._storage.enforce(lease)
        now = time.monotonic_ns()
        deadline = MonotonicActionDeadline(
            action_id,
            now,
            now + self._recovery_timeout_ms * 1_000_000,
        )
        guard = self._guard(attempt_id)
        expected = guard.preparation_process_specs(
            outcome,
            action_id=action_id,
            attempt_id=attempt_id,
            deadline=deadline,
        )
        if len(expected) != len(process_receipts) or any(
            receipt.action_id != action_id
            or receipt.attempt_id != attempt_id
            or receipt.invocation_id != spec.invocation_id
            or receipt.command_kind != spec.command_kind
            or receipt.command_fingerprint != process_command_fingerprint(spec)
            or receipt.outcome != "SUCCEEDED"
            or receipt.return_code != 0
            for receipt, spec in zip(process_receipts, expected, strict=True)
        ):
            raise ValueError("WORKSPACE_PROCESS_RECEIPTS_INVALID")
        await guard.assert_preparation_unchanged(
            outcome,
            deadline,
            attempt_id=attempt_id,
            check_id="recovery-verify",
        )
        self._storage.enforce(lease)

    def tracked_files_for(self, workspace: CodeWorkspace) -> tuple[TrackedFile, ...]:
        self.root_for(workspace)
        try:
            return self._manifests[str(workspace.workspace_id)]
        except KeyError as error:
            raise ValueError("WORKSPACE_MANIFEST_UNAVAILABLE") from error


class _RegisteringRepositoryLoader:
    def __init__(
        self, loader: RepositoryLoader, locator: _ProductionWorkspaceLocator
    ) -> None:
        self._loader = loader
        self._locator = locator
        self.process_receipts: tuple[ProcessReceipt, ...] = ()

    def verify_git_capability(self, subject_key: str, expected_sha256: str) -> None:
        self._loader.verify_git_capability(subject_key, expected_sha256)

    async def prepare(
        self,
        *,
        submitted_source: str,
        requested_ref: str,
        analysis_id: str,
        workspace_id: str,
        attempt_id: str,
        policy_ref: RunStoredDataRef,
        policy: WorkspaceStoragePolicy,
        deadline: MonotonicActionDeadline,
    ) -> RepositoryPreparation:
        try:
            outcome = await self._loader.prepare(
                submitted_source=submitted_source,
                requested_ref=requested_ref,
                analysis_id=analysis_id,
                workspace_id=workspace_id,
                attempt_id=attempt_id,
                policy_ref=policy_ref,
                policy=policy,
                deadline=deadline,
            )
        finally:
            self.process_receipts = self._loader.process_receipts
        if outcome.status == "READY":
            self._locator.register(outcome)
        return outcome


def _require_evidence(
    evidence: Mapping[str, bytes], digests: Sequence[str]
) -> Mapping[str, bytes]:
    resolved: dict[str, bytes] = {}
    for digest in digests:
        try:
            payload = evidence[digest]
        except KeyError:
            raise ValueError("PRODUCTION_T08_EVIDENCE_MISSING") from None
        if hashlib.sha256(payload).hexdigest() != digest:
            raise ValueError("PRODUCTION_T08_EVIDENCE_STALE")
        resolved[digest] = payload
    return MappingProxyType(resolved)


def _resolve_profiles(
    resolver: ProductionCapabilityResolverPort,
    inputs: ProductionT08Inputs,
) -> tuple[RuntimeCapabilityProfile, Mapping[str, StaticToolProfile]]:
    clone = resolver.resolve_pinned_active_profile(inputs.git_clone_profile_ref)
    checkout = resolver.resolve_pinned_active_profile(inputs.git_checkout_profile_ref)
    if (
        not isinstance(clone, RuntimeCapabilityProfile)
        or not isinstance(checkout, RuntimeCapabilityProfile)
        or reference(clone) != inputs.git_clone_profile_ref
        or reference(checkout) != inputs.git_checkout_profile_ref
        or clone.status != "ACTIVE"
        or checkout.status != "ACTIVE"
        or clone.capability_kind != "GIT"
        or checkout.capability_kind != "GIT"
        or "CLONE" not in clone.operations
        or "CHECKOUT" not in checkout.operations
        or (clone.subject_key, clone.subject_sha256)
        != (
            checkout.subject_key,
            checkout.subject_sha256,
        )
        or (clone.operating_system, clone.architecture)
        != (checkout.operating_system, checkout.architecture)
    ):
        raise ValueError("PRODUCTION_GIT_CAPABILITY_INVALID")
    static_profiles: dict[str, StaticToolProfile] = {}
    if set(inputs.static_profile_refs) != set(inputs.static.enabled_tools):
        raise ValueError("PRODUCTION_STATIC_PROFILE_SET_INVALID")
    for tool, profile_ref in inputs.static_profile_refs.items():
        profile = resolver.resolve_pinned_active_profile(profile_ref)
        route = next(item for item in inputs.static.routes if item.tool == tool)
        if (
            not isinstance(profile, StaticToolProfile)
            or reference(profile) != profile_ref
            or profile.status != "ACTIVE"
            or profile.purpose != "PRODUCTION"
            or profile.adapter_key != route.adapter_key
        ):
            raise ValueError("PRODUCTION_STATIC_CAPABILITY_INVALID")
        static_profiles[tool] = profile
    return clone, MappingProxyType(static_profiles)


def build_production_t08_feature(
    context: ProductionInstallationContext,
    inputs: ProductionT08Inputs,
) -> T08ProductionFeature:
    """Build all five T08 handlers from exact approved configuration only."""

    if (
        inputs.workspace_timeout_ms <= 0
        or inputs.repository_profile_timeout_ms <= 0
        or inputs.workspace.analysis_id != str(context.scope.analysis_id)
        or inputs.workspace.workspace_id != str(context.scope.workspace_id)
        or inputs.workspace.commit_id != str(context.scope.commit_id)
        or inputs.static.analysis_id != str(context.scope.analysis_id)
        or inputs.static.workspace_id != str(context.scope.workspace_id)
        or inputs.static.commit_id != str(context.scope.commit_id)
        or inputs.workspace.profile_hash != production_profile_hash(context.profile)
        or inputs.static.profile_hash != production_profile_hash(context.profile)
    ):
        raise ValueError("PRODUCTION_T08_SCOPE_MISMATCH")
    declared_digests = tuple(
        dict.fromkeys(
            (*inputs.workspace.evidence_sha256, *inputs.static.evidence_sha256)
        )
    )
    evidence = _require_evidence(inputs.evidence, declared_digests)
    resolver = cast(ProductionCapabilityResolverPort, context.runtime.configuration)
    git_profile, profiles = _resolve_profiles(resolver, inputs)
    git = inputs.git_executable.resolve(strict=True)
    if (
        not git.is_file()
        or git.stem.lower() != str(git_profile.subject_key).lower()
        or _sha256(git) != git_profile.subject_sha256
    ):
        raise ValueError("PRODUCTION_GIT_EXECUTABLE_INVALID")

    workspace_root = _safe_directory(context.data_dir, inputs.workspace.root_relative)
    output_root = _safe_directory(context.data_dir, "process-output/t08")
    receipt_root = _safe_directory(context.data_dir, "receipts/static")
    context_receipts = _safe_directory(context.data_dir, "receipts/context")
    storage = ProductionWorkspaceStorage(
        workspace_root,
        capacity_bytes=inputs.workspace.capacity_bytes,
        backend_key=str(inputs.workspace.backend_key),
        enforcement_evidence=str(inputs.workspace.enforcement_evidence_sha256),
    )
    locator = _ProductionWorkspaceLocator(
        storage=storage,
        git_executable=git,
        output_dir=output_root,
        recovery_timeout_ms=inputs.repository_profile_timeout_ms,
    )

    def repository_process_factory(
        lease: WorkspaceStorageLease,
        deadline: MonotonicActionDeadline,
        attempt_output: Path,
    ) -> RepositoryProcessRunner:
        return SafeProcessRunner(
            action_id=deadline.action_id,
            attempt_id=lease.attempt_id,
            workspace_root=lease.root,
            output_root=attempt_output,
            executable=git,
            output_budget=AttemptOutputBudget(
                attempt_id=lease.attempt_id, limit_bytes=_PROCESS_OUTPUT_LIMIT
            ),
        )

    loader = _RegisteringRepositoryLoader(
        RepositoryLoader(
            storage=storage,
            process_runner_factory=repository_process_factory,
            git_executable=git,
            output_dir=output_root,
            allow_local_file=inputs.allow_local_repository,
        ),
        locator,
    )

    committed_artifacts: dict[str, StoredDataRef] = {}
    for digest in declared_digests:
        ref = context.runtime.unit_of_work.artifacts.commit(
            context.runtime.unit_of_work.artifacts.stage_bytes(
                evidence[digest], "application/octet-stream"
            )
        )
        if ref.content_hash != digest or (
            str(ref.workspace_id),
            str(ref.commit_id),
        ) != (str(context.scope.workspace_id), str(context.scope.commit_id)):
            raise ValueError("PRODUCTION_T08_ARTIFACT_REFERENCE_MISMATCH")
        committed_artifacts[digest] = ref

    routes: dict[str, StaticToolRoute] = {}
    rule_catalogs: dict[StoredDataRef, tuple[str, ...]] = {}
    rule_selections: dict[StoredDataRef, tuple[str, ...]] = {}
    rule_mappings: dict[StoredDataRef, tuple[StaticRuleMapping, ...]] = {}
    for route in inputs.static.routes:
        profile_ref = inputs.static_profile_refs[route.tool]
        config_ref = committed_artifacts[route.analysis_config_sha256]
        catalog_ref: StoredDataRef | None = None
        catalog_ids: tuple[str, ...] = ()
        if route.tool != "AST":
            try:
                closure = inputs.rule_closures[route.tool]
            except KeyError:
                raise ValueError("PRODUCTION_STATIC_RULE_CLOSURE_MISSING") from None
            closure.validate_for(route)
            assert route.rule_catalog_sha256 is not None
            assert route.rule_selection_sha256 is not None
            assert route.rule_mapping_sha256 is not None
            catalog_ref = committed_artifacts[route.rule_catalog_sha256]
            catalog_ids = closure.catalog_rule_ids
            rule_catalogs[catalog_ref] = catalog_ids
            rule_selections[catalog_ref] = closure.selected_rule_ids
            rule_mappings[catalog_ref] = closure.mappings
        routes[route.tool] = StaticToolRoute(
            profile_ref, config_ref, catalog_ref, catalog_ids
        )
    if set(inputs.rule_closures) != set(inputs.static.enabled_tools) - {"AST"}:
        raise ValueError("PRODUCTION_STATIC_RULE_CLOSURE_SET_INVALID")
    if len({item.analysis_config_ref for item in routes.values()}) != 1:
        raise ValueError("PRODUCTION_STATIC_ANALYSIS_CONFIG_MISMATCH")

    adapter_context = StaticAdapterBuildContext(
        context.data_dir,
        locator,
        locator.tracked_files_for,
        MappingProxyType(routes),
        profiles,
        evidence,
        MappingProxyType(dict(inputs.rule_closures)),
    )
    adapters = dict(inputs.build_static_adapters(adapter_context))
    expected_adapters = {item.adapter_key for item in inputs.static.routes}
    if set(adapters) != expected_adapters:
        raise ValueError("PRODUCTION_STATIC_ADAPTER_SET_INVALID")
    executables: dict[str, Path] = {}
    decoders: dict[DecoderKey, RawDecoder] = {}
    decoder_for = {
        "PYTHON_AST_JSON_V1": replay_python_ast_raw,
        "CODEQL_SARIF_V1": replay_codeql_raw,
        "OPENGREP_JSON_V1": replay_opengrep_raw,
    }
    for route in inputs.static.routes:
        profile = profiles[route.tool]
        adapter = adapters[route.adapter_key]
        if (
            "fake" in type(adapter).__module__.lower()
            or not callable(getattr(adapter, "probe", None))
            or not callable(getattr(adapter, "execute", None))
            or not callable(getattr(adapter, "cancel", None))
            or not isinstance(getattr(adapter, "executable", None), Path)
        ):
            raise ValueError("PRODUCTION_STATIC_ADAPTER_INVALID")
        try:
            executable = adapter.executable.resolve(strict=True)
            executable_sha256 = _sha256(executable)
        except OSError as error:
            raise ValueError("PRODUCTION_STATIC_EXECUTABLE_INVALID") from error
        if not executable.is_file() or executable_sha256 != profile.executable_sha256:
            raise ValueError("PRODUCTION_STATIC_EXECUTABLE_INVALID")
        configured = executables.get(str(profile.executable_key))
        if configured is not None and configured != executable:
            raise ValueError("PRODUCTION_STATIC_EXECUTABLE_KEY_COLLISION")
        executables[profile.executable_key] = executable
        profile_ref = inputs.static_profile_refs[route.tool]
        decoders[
            decoder_key(profile_ref, profile.tool_name, profile.expected_version)
        ] = decoder_for[route.decoder_key]

    static_slice = build_real_static_slice(
        runner=context.runner,
        workspace_locator=locator,
        adapters=adapters,
        executables=executables,
        receipt_root=receipt_root,
        context_receipt_root=context_receipts,
        canonicalize_source=lambda source: canonicalize_repository_source(
            source, allow_local_file=inputs.allow_local_repository
        ),
        decode_policy=decode_workspace_storage_policy,
        static_process_receipts=inputs.static_process_receipts,
        static_cancellation_observation=inputs.static_cancellation_observation,
        static_dispatch_state=inputs.static_dispatch_state,
        lease_root_resolver=lambda lease_id: storage.resolve(lease_id).root,
        recovery_validator=locator,
        decoders=decoders,
        rule_catalogs=rule_catalogs,
        rule_selections=rule_selections,
        rule_mappings=rule_mappings,
        tracked_files_for=locator.tracked_files_for,
        prohibited_workspace_roots=(workspace_root,),
        lineage_reader=inputs.lineage_reader,
    )
    static_identity = context.role_identity_refs[RequesterRole.STATIC_ANALYSIS]
    repository_identity = context.role_identity_refs[RequesterRole.REPOSITORY_LOADER]
    context_identity = context.role_identity_refs[
        RequesterRole.CONTEXT_RETRIEVAL_SERVICE
    ]
    graph = StaticProductionGraph(
        runner=context.runner,
        work_query=context.scheduler_store,
        requester_identity_ref=static_identity,
        routes=tuple(routes[item] for item in inputs.static.enabled_tools),
    )
    profile_handler = RepositoryProfileWorkHandler(
        RepositoryProfileHandler(
            context.runner,
            RepositoryProfiler(),
            RepositoryExecutionSelector(
                resolver,
                operating_system=git_profile.operating_system,
                architecture=git_profile.architecture,
            ),
            locator,
        ),
        ExactRepositoryProfileCallResolver(
            runner=context.runner,
            work_query=context.scheduler_store,
            external=static_slice.external,
            timeout_ms=inputs.repository_profile_timeout_ms,
        ),
        context.budget_binding_ref,
        static_identity,
        static_identity,
    )
    return T08ProductionFeature(
        workspace_prep=WorkspacePrepWorkHandler(
            static_slice.external,
            loader,
            ExactWorkspacePrepCallResolver(context.runner),
            repository_identity,
            context.scope.workspace_id,
            inputs.workspace_timeout_ms,
        ),
        repository_profile=RepositoryProfileFanoutWorkHandler(profile_handler, graph),
        static_tool=StaticToolWorkHandler(
            static_slice.tools,
            ExactStaticToolCallResolver(
                runner=context.runner,
                graph=graph,
                requester_identity_ref=static_identity,
            ),
            graph,
        ),
        static_normalize=StaticNormalizationWorkHandler(
            static_slice.normalization,
            ExactStaticNormalizationCallResolver(
                runner=context.runner,
                graph=graph,
            ),
            graph,
            static_identity,
        ),
        context_retrieval=ContextRetrievalWorkHandler(
            static_slice.context,
            ExactContextRetrievalCallResolver(runner=context.runner),
            context.role_identity_refs[RequesterRole.VERIFICATION],
            context_identity,
        ),
        seeder=StaticPostWorkspaceSeeder(
            context.runner,
            context.scheduler_store,
            graph,
        ),
        workspace_locator=locator,
        static_cancellation=StaticAdapterCancellationRouter(
            adapters=adapters,
            profiles={profile.adapter_key: profile for profile in profiles.values()},
            dispatch_for_attempt=inputs.static_attempt_dispatch,
        ),
    )


__all__ = [
    "ApprovedStaticRuleClosure",
    "ProductionT08Inputs",
    "StaticAdapterBuildContext",
    "StaticAdapterFactory",
    "build_production_t08_feature",
]
