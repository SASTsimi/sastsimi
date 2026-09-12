"""Narrow production capability resolver consumed by T08/T11/T14."""

from typing import Protocol, runtime_checkable

from sastsimi.contracts.capabilities import (
    CapabilityArchitecture,
    CapabilityKind,
    CapabilityLanguage,
    CapabilityOperatingSystem,
    CapabilityOperation,
    RuntimeCapabilitySelection,
    StaticToolCapabilitySelection,
)


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
