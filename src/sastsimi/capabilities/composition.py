"""Trusted production composition for the host capability probe API."""

from __future__ import annotations

import os
import platform
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import uuid4

from sastsimi.bootstrap import build_runtime
from sastsimi.config.runtime_paths import RuntimePaths
from sastsimi.config.secrets import SecretReference
from sastsimi.contracts.capabilities import (
    CapabilityArchitecture,
    CapabilityOperatingSystem,
)
from sastsimi.contracts.ids import CommitId, OpaqueId, WorkspaceId
from sastsimi.storage.database import Database
from sastsimi.storage.migrations import upgrade

from .probes import OpenAIResponsesProbe
from .service import CapabilityProbeService
from .store import CapabilityProbeEvidenceAuthority, SQLiteCapabilityProbeStore


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


def build_production_capability_probe_service(
    data_dir: Path, *, host_id: str
) -> CapabilityProbeService:
    """Build the non-injectable production probe/list/approve application API."""

    if not host_id.strip():
        raise ValueError("CAPABILITY_HOST_REQUIRED")
    paths = RuntimePaths(data_dir)
    store = SQLiteCapabilityProbeStore(
        data_dir / "db" / "capability-probes.sqlite3", host_id=host_id
    )
    authority = CapabilityProbeEvidenceAuthority(store)
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
    return CapabilityProbeService(
        registry=runtime.configuration,
        artifacts=runtime.unit_of_work.artifacts,
        store=store,
        host_id=host_id,
        operating_system=operating_system,
        architecture=architecture,
        clock=clock.now,
        secret_resolver=EnvironmentSecretLookup(),
        openai_probe=OpenAIResponsesProbe(),
        scratch_root=data_dir / "probe-scratch",
    )


__all__ = ["build_production_capability_probe_service"]
