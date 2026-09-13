"""Resolve an exact operator-approved provisioning manifest without defaults."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass

from sastsimi.contracts.capabilities import RuntimeCapabilityProfile
from sastsimi.contracts.refs import HostConfigurationRef, reference
from sastsimi.contracts.static import StaticToolProfile
from sastsimi.ports.capability_registry import ProductionCapabilityResolverPort

from .production_onboarding import ProductionProvisioningManifest


@dataclass(frozen=True, slots=True)
class ResolvedProductionProvisioning:
    """Exact current host records plus verified immutable configuration bytes."""

    capabilities: Mapping[str, RuntimeCapabilityProfile | StaticToolProfile]
    artifacts: Mapping[str, bytes]


class ExactProductionProvisioningResolver:
    """Revalidate every exact ref and its declared provisioning purpose."""

    def __init__(
        self,
        *,
        configuration: ProductionCapabilityResolverPort,
        evidence: Callable[[str], bytes],
    ) -> None:
        self._configuration = configuration
        self._evidence = evidence

    def resolve(
        self, manifest: ProductionProvisioningManifest
    ) -> ResolvedProductionProvisioning:
        capabilities: dict[str, RuntimeCapabilityProfile | StaticToolProfile] = {}
        for item in manifest.capabilities:
            profile = self._configuration.resolve_pinned_active_profile(
                item.profile_ref
            )
            if reference(profile) != item.profile_ref:
                raise ValueError("PRODUCTION_CAPABILITY_REFERENCE_MISMATCH")
            self._require_slot(item.slot, item.profile_ref, profile)
            capabilities[item.slot] = profile
        artifacts: dict[str, bytes] = {
            item.slot: self._evidence(item.content_sha256)
            for item in manifest.artifacts
        }
        if any(not value for value in artifacts.values()):
            raise ValueError("PRODUCTION_PROVISIONING_ARTIFACT_EMPTY")
        return ResolvedProductionProvisioning(capabilities, artifacts)

    @staticmethod
    def _require_slot(
        slot: str,
        expected_ref: HostConfigurationRef,
        profile: RuntimeCapabilityProfile | StaticToolProfile,
    ) -> None:
        runtime = {
            "GIT_CLONE": ("GIT", "CLONE"),
            "GIT_CHECKOUT": ("GIT", "CHECKOUT"),
            "PYTHON_RUNTIME": ("PYTHON_RUNTIME", "START"),
            "DOCKER": ("DOCKER", "CONTAINER_RUN"),
        }
        static = {
            "AST": "PYTHON_AST",
            "CODEQL": "CODEQL",
            "OPENGREP": "OPENGREP",
        }
        if slot in runtime:
            kind, required_operation = runtime[slot]
            if (
                not isinstance(profile, RuntimeCapabilityProfile)
                or expected_ref.data_kind != RuntimeCapabilityProfile.KIND
                or profile.status != "ACTIVE"
                or profile.purpose != "PRODUCTION"
                or profile.capability_kind != kind
                or required_operation not in profile.operations
            ):
                raise ValueError("PRODUCTION_CAPABILITY_SLOT_MISMATCH")
            if slot == "DOCKER" and not {
                "IMAGE_BUILD",
                "CONTAINER_RUN",
                "HEALTH_CHECK",
                "CLEANUP",
            } <= set(profile.operations):
                raise ValueError("PRODUCTION_CAPABILITY_SLOT_MISMATCH")
            return
        adapter = static.get(slot)
        if (
            adapter is None
            or not isinstance(profile, StaticToolProfile)
            or expected_ref.data_kind != StaticToolProfile.KIND
            or profile.status != "ACTIVE"
            or profile.purpose != "PRODUCTION"
            or profile.adapter_key != adapter
        ):
            raise ValueError("PRODUCTION_CAPABILITY_SLOT_MISMATCH")


__all__ = [
    "ExactProductionProvisioningResolver",
    "ResolvedProductionProvisioning",
]
