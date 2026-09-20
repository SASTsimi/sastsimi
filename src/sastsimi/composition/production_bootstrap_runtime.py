"""Concrete production-only factories used by the shipped ``analyze`` command.

The filesystem provisioner supplies approved, exact configuration records.  This
module supplies the remaining host-runtime bindings without selecting a fake or
guessing a missing capability.  Docker target resolution is intentionally a
narrow seam: T16B owns the evidence-backed resolver and this module only loads
that public service when it is installed.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import stat
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import Lock
from typing import Literal, Protocol, cast

from pydantic import TypeAdapter
from sqlalchemy import select

from sastsimi.composition.production_cancellation import (
    build_production_cancellation_router,
)
from sastsimi.composition.production_default_assembler import (
    BuiltProductionDynamicFeature,
    ProductionStaticRuntimePorts,
    build_default_production_bundle_assembler,
)
from sastsimi.composition.production_dynamic_feature_builder import (
    build_production_dynamic_feature,
)
from sastsimi.composition.production_feature_installer import (
    DynamicProductionFeature,
    T08ProductionFeature,
)
from sastsimi.composition.production_filesystem_provisioner import (
    ProductionBundleAssemblyContext,
    ProductionBundleAssemblyPort,
)
from sastsimi.composition.production_static_adapters import (
    StaticAttemptAdapterDispatch,
)
from sastsimi.contracts.actions import ActionDecision, ActionRequest, ActionType
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import (
    HostConfigurationRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.static import CodeWorkspace, StaticToolProfile
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.orchestration.production_context import (
    ProductionCapabilityUnavailable,
    ProductionInstallationContext,
)
from sastsimi.orchestration.static_external_runner import StaticDispatchState
from sastsimi.ports.dto import ProcessReceipt, StaticToolObservation, StaticToolRequest
from sastsimi.ports.dynamic_sandbox import (
    TrustedDockerTarget,
    TrustedDockerTargetResolverPort,
)
from sastsimi.ports.llm_provider import LLMProviderAdapter
from sastsimi.ports.scheduler import ExternalCancellationPort
from sastsimi.ports.static_tool import (
    PrebuiltCodeQLDatabasePort,
    ProductionStaticOutputQuotaPort,
)
from sastsimi.storage import models
from sastsimi.storage.codec import REF_ADAPTER
from sastsimi.storage.repositories import SQLiteRecordStore

_PROCESS_RECEIPT = TypeAdapter(ProcessReceipt)
_MAX_RECEIPT_BYTES = 64 * 1024
_MAX_PROCESS_STREAM_BYTES = 64 * 1024 * 1024
_MAX_STATIC_RECEIPT_DIRECTORIES = 256
_MAX_STATIC_RECEIPT_FILES = 4096
_REPARSE_POINT = 0x400
type StaticDispatchPhase = Literal["PREPARED", "DISPATCHED", "RETURNED"]


class DockerTargetResolverFactory(Protocol):
    """Build the exact resolver for one approved run and host."""

    def __call__(
        self, context: ProductionBundleAssemblyContext
    ) -> TrustedDockerTargetResolverPort: ...


class _CapabilityServiceBuilder(Protocol):
    def __call__(
        self,
        data_dir: Path,
        *,
        host_id: str,
        executable_paths: Mapping[str, Path],
        docker_host: str | None,
    ) -> TrustedDockerTargetResolverPort: ...


class _LazyDockerTargetResolver:
    """Create the host resolver only when dynamic reproduction claims Docker."""

    def __init__(
        self,
        factory: DockerTargetResolverFactory,
        context: ProductionBundleAssemblyContext,
    ) -> None:
        self._factory = factory
        self._context = context
        self._lock = Lock()
        self._resolver: TrustedDockerTargetResolverPort | None = None

    def resolve_current(self, profile_ref: HostConfigurationRef) -> TrustedDockerTarget:
        return self._delegate().resolve_current(profile_ref)

    def require_current(self, target: TrustedDockerTarget) -> None:
        self._delegate().require_current(target)

    def _delegate(self) -> TrustedDockerTargetResolverPort:
        resolver = self._resolver
        if resolver is not None:
            return resolver
        with self._lock:
            resolver = self._resolver
            if resolver is None:
                resolver = self._factory(self._context)
                if any(
                    not callable(getattr(resolver, method, None))
                    for method in ("resolve_current", "require_current")
                ):
                    raise ProductionCapabilityUnavailable(
                        "PRODUCTION_DOCKER_RESOLVER_INVALID"
                    )
                self._resolver = resolver
            return resolver


@dataclass(frozen=True, slots=True)
class ProductionStaticRuntimeFactory:
    """Bind durable SQLite dispatch state and process receipt evidence."""

    output_quota: ProductionStaticOutputQuotaPort | None = None
    codeql_database_provider: PrebuiltCodeQLDatabasePort | None = None
    codeql_database_limit_bytes: int | None = None

    def __call__(
        self, context: ProductionInstallationContext
    ) -> ProductionStaticRuntimePorts:
        runtime = _SQLiteStaticRuntime(context)
        return ProductionStaticRuntimePorts(
            process_receipts=runtime.process_receipts,
            cancellation_observation=runtime.cancellation_observation,
            dispatch_state=runtime.dispatch_state,
            attempt_dispatch=runtime.attempt_dispatch,
            output_quota=self.output_quota,
            codeql_database_provider=self.codeql_database_provider,
            codeql_database_limit_bytes=self.codeql_database_limit_bytes,
        )


@dataclass(frozen=True, slots=True)
class ProductionDynamicRuntimeFactory:
    """Bind R7 to the current workspace and an evidence-backed Docker target."""

    docker_resolver_factory: DockerTargetResolverFactory

    def __call__(
        self,
        assembly: ProductionBundleAssemblyContext,
        context: ProductionInstallationContext,
        static: T08ProductionFeature,
    ) -> BuiltProductionDynamicFeature:
        resolver = _LazyDockerTargetResolver(self.docker_resolver_factory, assembly)

        def workspace_root_for(work: WorkExecutionState) -> Path:
            meta = work.meta
            if not isinstance(meta, RecordMeta):
                raise ValueError("CURRENT_WORKSPACE_REQUIRED")
            state = context.runtime.budget_registry.current_state(str(meta.analysis_id))
            workspace_ref = state.workspace_ref
            if not isinstance(workspace_ref, RunStoredDataRef):
                raise ValueError("CURRENT_WORKSPACE_REQUIRED")
            workspace = context.runtime.unit_of_work.records.get_exact(workspace_ref)
            if (
                not isinstance(workspace, CodeWorkspace)
                or reference(workspace) != workspace_ref
                or workspace.status != "READY"
                or workspace.workspace_id != meta.workspace_id
                or workspace.commit_id != meta.commit_id
            ):
                raise ValueError("CURRENT_WORKSPACE_REQUIRED")
            return static.workspace_locator.root_for(workspace)

        built = build_production_dynamic_feature(
            context=context,
            resolved=assembly.resolved,
            materialized=assembly.materialized,
            workspace_root_for=workspace_root_for,
            docker_target_resolver=resolver,
        )
        return BuiltProductionDynamicFeature(
            feature=built.feature,
            readiness_checks=built.readiness_checks,
        )


@dataclass(frozen=True, slots=True)
class ProductionCancellationFactory:
    """Route cancellation only to the exact real static, LLM, or Docker target."""

    def __call__(
        self,
        context: ProductionInstallationContext,
        static: T08ProductionFeature,
        provider_adapters: Mapping[tuple[StoredDataRef, str], LLMProviderAdapter],
        dynamic: DynamicProductionFeature,
    ) -> ExternalCancellationPort:
        from sastsimi.sandbox.cleanup import OwnedResourceRegistry

        del provider_adapters
        return build_production_cancellation_router(
            records=context.runtime.unit_of_work.records,
            static=static.static_cancellation,
            provider_calls=context.runtime.llm_calls,
            docker=dynamic.docker,
            # A new owner reloads the durable journal before taking the exact
            # attempt snapshot; no prior process memory is trusted.
            resources=OwnedResourceRegistry(journal_path=dynamic.resource_journal_path),
        )


def build_production_bootstrap_assembler(
    *,
    repository_root: Path,
    docker_resolver_factory: DockerTargetResolverFactory | None = None,
    static_output_quota: ProductionStaticOutputQuotaPort | None = None,
    codeql_database_provider: PrebuiltCodeQLDatabasePort | None = None,
    codeql_database_limit_bytes: int | None = None,
) -> ProductionBundleAssemblyPort:
    """Build the real default T08-T13 assembler used by ``sastsimi analyze``."""

    return build_default_production_bundle_assembler(
        repository_root=repository_root,
        static_runtime_factory=ProductionStaticRuntimeFactory(
            output_quota=static_output_quota,
            codeql_database_provider=codeql_database_provider,
            codeql_database_limit_bytes=codeql_database_limit_bytes,
        ),
        dynamic_feature_factory=ProductionDynamicRuntimeFactory(
            docker_resolver_factory or _default_docker_resolver
        ),
        cancellation_factory=ProductionCancellationFactory(),
    )


@dataclass(frozen=True, slots=True)
class _SQLiteStaticRuntime:
    context: ProductionInstallationContext

    def process_receipts(
        self, action_id: str, attempt_id: str
    ) -> Sequence[ProcessReceipt] | None:
        """Read only receipts from the exact action/attempt-bound output root."""

        root = self.context.data_dir / "static-execution"
        _require_safe_directory(root, "STATIC_PROCESS_RECEIPT_ROOT_INVALID")
        matches: list[Path] = []
        for tool_root in _children(root):
            if not tool_root.is_dir():
                continue
            _require_safe_directory(tool_root, "STATIC_PROCESS_RECEIPT_ROOT_INVALID")
            for attempt_root in _children(tool_root):
                if not attempt_root.is_dir():
                    continue
                _require_safe_directory(
                    attempt_root, "STATIC_PROCESS_RECEIPT_ROOT_INVALID"
                )
                marker = attempt_root / "sastsimi-attempt.json"
                if not marker.exists():
                    continue
                value = _json_object(marker, _MAX_RECEIPT_BYTES)
                if (
                    set(value)
                    != {
                        "schema_version",
                        "tool",
                        "workspace_id",
                        "commit_id",
                        "action_id",
                        "attempt_id",
                    }
                    or value["schema_version"] != 1
                ):
                    raise ValueError("STATIC_PROCESS_RECEIPT_BINDING_INVALID")
                if (
                    value["action_id"] == action_id
                    and value["attempt_id"] == attempt_id
                ):
                    matches.append(attempt_root)
        if not matches:
            return None
        if len(matches) != 1:
            raise ValueError("STATIC_PROCESS_RECEIPT_BINDING_INVALID")
        receipts = tuple(
            self._read_process_receipt(path, action_id, attempt_id)
            for path in _nested_process_receipts(matches[0])
        )
        return tuple(sorted(receipts, key=lambda item: item.invocation_id)) or None

    @staticmethod
    def cancellation_observation(
        _request: StaticToolRequest, _profile: StaticToolProfile
    ) -> StaticToolObservation | None:
        # A missing partial observation is explicit.  Cancellation closure still
        # requires exact process receipts and therefore cannot fabricate output.
        return None

    def dispatch_state(self, action_id: str) -> StaticDispatchState | None:
        rows = self._dispatch_rows(action_id=action_id)
        if not rows:
            return None
        if len(rows) != 1:
            raise ValueError("STATIC_DISPATCH_STATE_AMBIGUOUS")
        row = rows[0]
        state = _dispatch_phase(row)
        if state is None:
            return None
        return StaticDispatchState(
            action_id=action_id,
            work_id=_required_string(row, "work_id"),
            attempt_id=_required_string(row, "attempt_id"),
            decision_ref=REF_ADAPTER.validate_json(
                _required_string(row, "decision_ref")
            ),
            reservation_ref=REF_ADAPTER.validate_json(
                _required_string(row, "reservation_ref")
            ),
            state=state,
            idempotency_key=cast(str | None, row["idempotency_key"]),
        )

    def attempt_dispatch(self, attempt_id: str) -> StaticAttemptAdapterDispatch | None:
        rows = self._dispatch_rows(attempt_id=attempt_id)
        matches: list[StaticAttemptAdapterDispatch] = []
        records = self.context.runtime.unit_of_work.records
        configuration = self.context.runtime.configuration
        for row in rows:
            state = _dispatch_phase(row)
            if state is None:
                continue
            decision_ref = REF_ADAPTER.validate_json(
                _required_string(row, "decision_ref")
            )
            decision = records.get_exact(decision_ref)
            action = (
                records.get_exact(decision.action_ref)
                if isinstance(decision, ActionDecision)
                else None
            )
            if (
                not isinstance(action, ActionRequest)
                or action.action_type != ActionType.RUN_TOOL
            ):
                continue
            profiles: list[tuple[HostConfigurationRef, StaticToolProfile]] = []
            for ref in action.input_refs:
                if not isinstance(ref, HostConfigurationRef):
                    continue
                try:
                    profile = configuration.resolve_static_tool_profile_ref(ref)
                except (LookupError, TypeError, ValueError):
                    continue
                if (
                    isinstance(profile, StaticToolProfile)
                    and reference(profile) == ref
                    and profile.tool_name == action.tool_name
                ):
                    profiles.append((ref, profile))
            if len(profiles) != 1:
                raise ValueError("STATIC_ATTEMPT_DISPATCH_AMBIGUOUS")
            profile_ref, profile = profiles[0]
            matches.append(
                StaticAttemptAdapterDispatch(
                    action_id=str(action.action_id),
                    attempt_id=attempt_id,
                    adapter_key=profile.adapter_key,
                    tool_profile_ref=profile_ref,
                    state=state,
                )
            )
        if not matches:
            return None
        if len(matches) != 1:
            raise ValueError("STATIC_ATTEMPT_DISPATCH_AMBIGUOUS")
        return matches[0]

    def _dispatch_rows(
        self, *, action_id: str | None = None, attempt_id: str | None = None
    ) -> tuple[Mapping[str, object], ...]:
        if (action_id is None) == (attempt_id is None):
            raise ValueError("STATIC_DISPATCH_LOOKUP_INVALID")
        table = models.external_dispatches
        condition = (
            table.c.action_id == action_id
            if action_id is not None
            else table.c.attempt_id == attempt_id
        )
        records = self.context.runtime.unit_of_work.records
        if not isinstance(records, SQLiteRecordStore):
            raise ValueError("STATIC_DISPATCH_STORE_INVALID")
        with records.database.engine.connect() as db:
            return tuple(
                cast(Mapping[str, object], row)
                for row in db.execute(select(table).where(condition)).mappings()
            )

    @staticmethod
    def _read_process_receipt(
        path: Path, action_id: str, attempt_id: str
    ) -> ProcessReceipt:
        raw = _guarded_read(path, _MAX_RECEIPT_BYTES)
        try:
            receipt = _PROCESS_RECEIPT.validate_json(raw)
        except ValueError:
            raise ValueError("STATIC_PROCESS_RECEIPT_INVALID") from None
        if (
            receipt.action_id != action_id
            or receipt.attempt_id != attempt_id
            or raw != _canonical_receipt(receipt)
            or Path(receipt.stdout_name).name != receipt.stdout_name
            or Path(receipt.stderr_name).name != receipt.stderr_name
        ):
            raise ValueError("STATIC_PROCESS_RECEIPT_INVALID")
        _require_stream(
            path.parent / receipt.stdout_name,
            receipt.stdout_size,
            receipt.stdout_sha256,
        )
        _require_stream(
            path.parent / receipt.stderr_name,
            receipt.stderr_size,
            receipt.stderr_sha256,
        )
        return receipt


def _default_docker_resolver(
    context: ProductionBundleAssemblyContext,
) -> TrustedDockerTargetResolverPort:
    """Load T16B's public service; absence is an explicit blocked capability."""

    try:
        from sastsimi.capabilities import build_production_capability_probe_service

        builder = cast(
            _CapabilityServiceBuilder,
            build_production_capability_probe_service,
        )
    except (AttributeError, ImportError, ModuleNotFoundError):
        raise ProductionCapabilityUnavailable(
            "PRODUCTION_DOCKER_RESOLVER_REQUIRED"
        ) from None
    docker = _resolve_executable(context.profile.tools.docker)
    try:
        return builder(
            context.data_dir,
            host_id=context.profile.host_id,
            executable_paths={"docker": docker},
            docker_host=_default_docker_host(),
        )
    except (LookupError, OSError, TypeError, ValueError):
        raise ProductionCapabilityUnavailable(
            "PRODUCTION_DOCKER_RESOLVER_UNAVAILABLE"
        ) from None


def _default_docker_host() -> str:
    if platform.system().lower() == "windows":
        return "npipe:////./pipe/docker_engine"
    return "unix:///var/run/docker.sock"


def _resolve_executable(value: str) -> Path:
    candidate = Path(value)
    found = (
        str(candidate)
        if candidate.is_absolute() or candidate.parent != Path(".")
        else shutil.which(value)
    )
    if found is None:
        raise ProductionCapabilityUnavailable(
            "PRODUCTION_DOCKER_EXECUTABLE_UNAVAILABLE"
        )
    try:
        result = Path(found).resolve(strict=True)
    except OSError:
        raise ProductionCapabilityUnavailable(
            "PRODUCTION_DOCKER_EXECUTABLE_UNAVAILABLE"
        ) from None
    if not result.is_file():
        raise ProductionCapabilityUnavailable(
            "PRODUCTION_DOCKER_EXECUTABLE_UNAVAILABLE"
        )
    return result


def _children(path: Path) -> tuple[Path, ...]:
    try:
        return tuple(sorted(path.iterdir(), key=lambda item: item.name))
    except OSError:
        raise ValueError("STATIC_PROCESS_RECEIPT_ROOT_INVALID") from None


def _nested_process_receipts(attempt_root: Path) -> tuple[Path, ...]:
    """Find adapter receipts below one exact attempt without following links."""

    pending = [attempt_root]
    directories = 0
    files = 0
    receipts: list[Path] = []
    while pending:
        current = pending.pop()
        _require_safe_directory(current, "STATIC_PROCESS_RECEIPT_ROOT_INVALID")
        directories += 1
        if directories > _MAX_STATIC_RECEIPT_DIRECTORIES:
            raise ValueError("STATIC_PROCESS_RECEIPT_ROOT_INVALID")
        for child in _children(current):
            try:
                info = child.lstat()
            except OSError:
                raise ValueError("STATIC_PROCESS_RECEIPT_ROOT_INVALID") from None
            if child.is_symlink() or bool(
                getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
            ):
                raise ValueError("STATIC_PROCESS_RECEIPT_ROOT_INVALID")
            if stat.S_ISDIR(info.st_mode):
                pending.append(child)
                continue
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("STATIC_PROCESS_RECEIPT_ROOT_INVALID")
            files += 1
            if files > _MAX_STATIC_RECEIPT_FILES:
                raise ValueError("STATIC_PROCESS_RECEIPT_ROOT_INVALID")
            if child.name.endswith(".receipt.json"):
                receipts.append(child)
    return tuple(sorted(receipts, key=lambda item: item.as_posix()))


def _require_safe_directory(path: Path, code: str) -> None:
    try:
        info = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError:
        raise ValueError(code) from None
    if (
        not stat.S_ISDIR(info.st_mode)
        or path.is_symlink()
        or bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)
        or resolved != path.absolute()
    ):
        raise ValueError(code)


def _guarded_read(path: Path, limit: int) -> bytes:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or path.is_symlink()
            or before.st_nlink != 1
            or bool(getattr(before, "st_file_attributes", 0) & _REPARSE_POINT)
            or before.st_size > limit
        ):
            raise ValueError
        data = path.read_bytes()
        after = path.lstat()
    except (OSError, ValueError):
        raise ValueError("STATIC_PROCESS_RECEIPT_INVALID") from None
    if _file_identity(before) != _file_identity(after) or len(data) != before.st_size:
        raise ValueError("STATIC_PROCESS_RECEIPT_INVALID")
    return data


def _file_identity(details: os.stat_result) -> tuple[object, ...]:
    """Compare mutation-relevant identity while ignoring read-time metadata."""

    return (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_size,
        details.st_mtime_ns,
        details.st_nlink,
        getattr(details, "st_file_attributes", 0),
    )


def _json_object(path: Path, limit: int) -> dict[str, object]:
    try:
        value = json.loads(_guarded_read(path, limit))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("STATIC_PROCESS_RECEIPT_BINDING_INVALID") from None
    if not isinstance(value, dict):
        raise ValueError("STATIC_PROCESS_RECEIPT_BINDING_INVALID")
    return cast(dict[str, object], value)


def _canonical_receipt(receipt: ProcessReceipt) -> bytes:
    from sastsimi.contracts.canonical_json import canonical_bytes

    return canonical_bytes(asdict(receipt))


def _require_stream(path: Path, expected_size: int, expected_sha256: str) -> None:
    if (
        expected_size < 0
        or expected_size > _MAX_PROCESS_STREAM_BYTES
        or len(expected_sha256) != 64
    ):
        raise ValueError("STATIC_PROCESS_RECEIPT_INVALID")
    raw = _guarded_read(path, _MAX_PROCESS_STREAM_BYTES)
    if len(raw) != expected_size or hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise ValueError("STATIC_PROCESS_RECEIPT_INVALID")


def _dispatch_phase(
    row: Mapping[str, object],
) -> StaticDispatchPhase | None:
    if row["reconciled_at"] is not None and row["returned_at"] is None:
        return None
    if row["returned_at"] is not None:
        return "RETURNED"
    if row["dispatched_at"] is not None:
        return "DISPATCHED"
    return "PREPARED"


def _required_string(row: Mapping[str, object], key: str) -> str:
    value = row[key]
    if not isinstance(value, str) or not value:
        raise ValueError("STATIC_DISPATCH_STATE_INVALID")
    return value


__all__ = [
    "DockerTargetResolverFactory",
    "ProductionCancellationFactory",
    "ProductionDynamicRuntimeFactory",
    "ProductionStaticRuntimeFactory",
    "build_production_bootstrap_assembler",
]
