"""Trusted production composition for the host capability probe API."""

from __future__ import annotations

import os
import platform
import sys
import tempfile
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast
from uuid import uuid4

from sastsimi.bootstrap import build_runtime
from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.config.secrets import SecretReference
from sastsimi.contracts.capabilities import (
    CapabilityArchitecture,
    CapabilityOperatingSystem,
)
from sastsimi.contracts.ids import CommitId, OpaqueId, WorkspaceId
from sastsimi.contracts.refs import HostConfigurationRef
from sastsimi.storage.database import Database
from sastsimi.storage.migrations import upgrade

from .models import CapabilityProbeReceipt, ProbeKind
from .probes import (
    OpenAIResponsesProbe,
    ProductionExecutableRegistry,
    SubprocessCommandProbeRunner,
)
from .service import _CapabilityProbeEngine
from .store import _CapabilityProbeEvidenceAuthority, _SQLiteCapabilityProbeStore


class EnvironmentSecretLookup:
    """Resolve only an approved environment reference without persisting its value."""

    def resolve(self, reference: SecretReference) -> str:
        if not reference.reference.startswith("env:"):
            raise ValueError("SECRET_REFERENCE_UNSUPPORTED")
        value = os.environ.get(reference.reference.removeprefix("env:"))
        if value is None or not value.strip():
            raise ValueError("SECRET_UNAVAILABLE")
        return value


class _SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic_ms(self) -> int:
        return time.monotonic_ns() // 1_000_000


class _UuidIds:
    def new[T: OpaqueId](self, kind: type[T]) -> T:
        return kind(str(uuid4()))


class _NativeApprovalIdentity:
    """Read the interactive OS account without trusting caller or environment text."""

    def __call__(self) -> str:
        if os.name == "nt":
            import ctypes

            size = ctypes.c_ulong(257)
            buffer = ctypes.create_unicode_buffer(size.value)
            if not ctypes.windll.advapi32.GetUserNameW(buffer, ctypes.byref(size)):
                raise ValueError("APPROVER_UNAVAILABLE")
            identity = buffer.value
        else:
            import pwd

            class _PasswdRecord(Protocol):
                pw_name: str

            get_effective_user_id = cast(
                Callable[[], int],
                os.geteuid,  # type: ignore[attr-defined]
            )
            get_user = cast(
                Callable[[int], _PasswdRecord],
                pwd.getpwuid,  # type: ignore[attr-defined]
            )
            identity = get_user(get_effective_user_id()).pw_name
        if not identity:
            raise ValueError("APPROVER_UNAVAILABLE")
        return identity


class ProductionCapabilityProbeService:
    """Narrow public facade; dependency injection exists only in the internal engine."""

    def __init__(
        self,
        data_dir: Path,
        *,
        host_id: str,
        executable_paths: Mapping[str, Path],
        docker_host: str | None,
    ) -> None:
        self.__engine = _build_production_engine(
            data_dir,
            host_id=host_id,
            executable_paths=executable_paths,
            docker_host=docker_host,
        )

    def probe(
        self,
        kind: ProbeKind,
        *,
        model: str | None = None,
        credential_ref: SecretReference | None = None,
    ) -> CapabilityProbeReceipt:
        return self.__engine.probe(kind, model=model, credential_ref=credential_ref)

    def list(self) -> tuple[CapabilityProbeReceipt, ...]:
        return self.__engine.list()

    def approve(
        self, probe_id: str, *, expected_target_hash: str
    ) -> HostConfigurationRef:
        return self.__engine.approve(
            probe_id, expected_target_hash=expected_target_hash
        )

    def resolve_executable(self, profile_ref: HostConfigurationRef) -> Path:
        return self.__engine.resolve_executable(profile_ref)


def _host_platform() -> tuple[CapabilityOperatingSystem, CapabilityArchitecture]:
    operating_system = {
        "windows": "windows",
        "linux": "linux",
        "darwin": "macos",
    }.get(platform.system().lower())
    architecture = {
        "amd64": "x86_64",
        "x86_64": "x86_64",
        "arm64": "aarch64",
        "aarch64": "aarch64",
    }.get(platform.machine().lower())
    if operating_system is None or architecture is None:
        raise ValueError("CAPABILITY_HOST_PLATFORM_UNSUPPORTED")
    return cast(CapabilityOperatingSystem, operating_system), cast(
        CapabilityArchitecture, architecture
    )


def _build_production_engine(
    data_dir: Path,
    *,
    host_id: str,
    executable_paths: Mapping[str, Path],
    docker_host: str | None,
) -> _CapabilityProbeEngine:
    if not host_id.strip():
        raise ValueError("CAPABILITY_HOST_REQUIRED")
    paths = RuntimePaths(data_dir)
    store = _SQLiteCapabilityProbeStore(
        data_dir / "db" / "capability-probes.sqlite3", host_id=host_id
    )
    authority = _CapabilityProbeEvidenceAuthority(store)
    upgrade(Database(paths.database))
    clock = _SystemClock()
    runtime = build_runtime(
        data_dir,
        WorkspaceId("host-configuration"),
        CommitId("host-configuration-v1"),
        clock,
        _UuidIds(),
        evidence=authority,
        capability_host_id=host_id,
    )
    operating_system, architecture = _host_platform()
    allowed_executables = frozenset({"git", "opengrep", "docker", "codeql"})
    if not set(executable_paths) <= allowed_executables:
        raise ValueError("CAPABILITY_EXECUTABLE_KEY_UNSUPPORTED")
    if ("docker" in executable_paths) != (docker_host is not None):
        raise ValueError("DOCKER_HOST_CONFIGURATION_MISMATCH")
    executable_registry = ProductionExecutableRegistry(
        {"python": Path(sys.executable), **dict(executable_paths)},
        forbidden_roots=(
            data_dir,
            data_dir / "workspaces",
            data_dir / "probe-scratch",
            Path(tempfile.gettempdir()),
            Path.cwd(),
        ),
    )
    return _CapabilityProbeEngine(
        registry=runtime.configuration,
        artifacts=runtime.unit_of_work.artifacts,
        store=store,
        host_id=host_id,
        operating_system=operating_system,
        architecture=architecture,
        clock=clock.now,
        executable_locator=executable_registry.resolve,
        command_runner=SubprocessCommandProbeRunner(),
        docker_host=docker_host,
        approval_identity=_NativeApprovalIdentity(),
        secret_resolver=EnvironmentSecretLookup(),
        openai_probe=OpenAIResponsesProbe(),
        scratch_root=data_dir / "probe-scratch",
    )


def build_production_capability_probe_service(
    data_dir: Path,
    *,
    host_id: str,
    executable_paths: Mapping[str, Path],
    docker_host: str | None,
) -> ProductionCapabilityProbeService:
    """Build the non-injectable production probe/list/approve application API."""

    return ProductionCapabilityProbeService(
        data_dir,
        host_id=host_id,
        executable_paths=executable_paths,
        docker_host=docker_host,
    )


__all__ = [
    "ProductionCapabilityProbeService",
    "build_production_capability_probe_service",
]
