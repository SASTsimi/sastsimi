"""Narrow production capability resolvers consumed by T08/T11/T14."""

from pathlib import Path
from typing import Protocol, runtime_checkable

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
from sastsimi.contracts.refs import HostConfigurationRef
from sastsimi.contracts.static import StaticToolProfile


@runtime_checkable
class ProductionCapabilityResolverPort(Protocol):
    """Return only current, evidence-backed selections with exact profile refs."""

    def resolve_active_capability(
        self,
        *,
        capability_kind: CapabilityKind,
        language: CapabilityLanguage,
        operation: CapabilityOperation,
        operating_system: CapabilityOperatingSystem,
        architecture: CapabilityArchitecture,
    ) -> RuntimeCapabilitySelection: ...

    def resolve_active_static_tool(
        self,
        *,
        adapter_key: str,
        language: CapabilityLanguage,
        operating_system: CapabilityOperatingSystem,
        architecture: CapabilityArchitecture,
    ) -> StaticToolCapabilitySelection: ...

    def resolve_pinned_active_profile(
        self, profile_ref: HostConfigurationRef
    ) -> RuntimeCapabilityProfile | StaticToolProfile: ...


@runtime_checkable
class DockerCommandCapabilityResolverPort(Protocol):
    """Revalidate one exact ACTIVE Docker profile immediately before execution."""

    def resolve_docker_command(
        self, profile_ref: HostConfigurationRef
    ) -> tuple[Path, str]: ...
