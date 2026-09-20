"""Compose exact, credential-free production onboarding bundles.

This module does not run a probe, evaluate a Provider, approve a prompt, or
invent a provisioning default.  It only closes already-approved inputs over
their exact content hashes and current host capability references.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Literal, Self, cast

from pydantic import AwareDatetime, model_validator

from sastsimi.contracts.base import ContractModel, NonEmptyStr, Sha256
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.prompt_redaction import assert_safe_provider_text
from sastsimi.contracts.refs import HostConfigurationRef

from .production_onboarding import (
    ProductionOnboardingManifest,
    ProductionProvisioningManifest,
    ProviderOnboardingApproval,
    ProvisioningArtifact,
    ProvisioningCapability,
    RouteOnboardingApproval,
)
from .production_provisioning import ProvisioningTemplateMaterializer

type CapabilitySlot = Literal[
    "GIT_CLONE",
    "GIT_CHECKOUT",
    "PYTHON_RUNTIME",
    "AST",
    "CODEQL",
    "OPENGREP",
    "DOCKER",
]
type ProbeKind = Literal[
    "GIT",
    "PYTHON_RUNTIME",
    "PYTHON_AST",
    "CODEQL",
    "OPENGREP",
    "DOCKER",
]
type ArtifactSlot = Literal[
    "WORKSPACE_STORAGE",
    "STATIC_ANALYSIS",
    "VERIFICATION_PLAYBOOKS",
    "SANDBOX_PROFILE",
    "POLICY_CATALOG",
    "PROVIDER_CONFIGURATION",
    "PROMPT_ROUTES",
]

_ARTIFACT_SLOTS = frozenset(
    {
        "WORKSPACE_STORAGE",
        "STATIC_ANALYSIS",
        "VERIFICATION_PLAYBOOKS",
        "SANDBOX_PROFILE",
        "POLICY_CATALOG",
        "PROVIDER_CONFIGURATION",
        "PROMPT_ROUTES",
    }
)

_EXPECTED_PROBE_KIND: Mapping[CapabilitySlot, ProbeKind] = {
    "GIT_CLONE": "GIT",
    "GIT_CHECKOUT": "GIT",
    "PYTHON_RUNTIME": "PYTHON_RUNTIME",
    "AST": "PYTHON_AST",
    "CODEQL": "CODEQL",
    "OPENGREP": "OPENGREP",
    "DOCKER": "DOCKER",
}


class ApprovedCapabilityProbe(ContractModel):
    """Operator-selected probe whose already-approved ref must still be current."""

    slot: CapabilitySlot
    probe_id: NonEmptyStr


class ProductionOnboardingBuildInput(ContractModel):
    """Human decisions needed to compose, but not grant, production approval."""

    schema_version: Literal[1]
    created_at: AwareDatetime
    expires_at: AwareDatetime
    approved_by: NonEmptyStr
    policy_artifact_sha256: Sha256
    capability_probes: tuple[ApprovedCapabilityProbe, ...]
    provider_approvals: tuple[ProviderOnboardingApproval, ...]
    route_approvals: tuple[RouteOnboardingApproval, ...]

    @model_validator(mode="after")
    def exact_selection(self) -> Self:
        slots = tuple(item.slot for item in self.capability_probes)
        required = {"GIT_CLONE", "GIT_CHECKOUT", "PYTHON_RUNTIME", "AST"}
        if (
            self.created_at >= self.expires_at
            or len(slots) != len(set(slots))
            or not required <= set(slots)
        ):
            raise ValueError("PRODUCTION_ONBOARDING_BUILD_INPUT_INVALID")
        return self


class ProductionOnboardingBundleIndex(ContractModel):
    """Portable index containing hashes only, never source paths or secrets."""

    schema_version: Literal[1]
    onboarding_manifest_sha256: Sha256
    provisioning_manifest_sha256: Sha256
    evidence_sha256: tuple[Sha256, ...]

    @model_validator(mode="after")
    def unique_evidence(self) -> Self:
        if len(self.evidence_sha256) != len(set(self.evidence_sha256)):
            raise ValueError("PRODUCTION_ONBOARDING_BUNDLE_INDEX_INVALID")
        return self


@dataclass(frozen=True, slots=True)
class ComposedProductionOnboarding:
    onboarding: ProductionOnboardingManifest
    provisioning: ProductionProvisioningManifest
    onboarding_bytes: bytes
    provisioning_bytes: bytes
    evidence: Mapping[str, bytes]
    index: ProductionOnboardingBundleIndex
    index_bytes: bytes


ApprovedProbeResolver = Callable[[str], tuple[str, HostConfigurationRef]]


def compose_production_onboarding(
    *,
    approval_input: bytes,
    slot_templates: tuple[bytes, ...],
    evidence: Mapping[str, bytes],
    profile_hash: str,
    host_id: str,
    resolve_probe: ApprovedProbeResolver,
) -> ComposedProductionOnboarding:
    """Close exact approved inputs into manifests without creating approval."""

    _require_safe(approval_input, *slot_templates, *evidence.values())
    approval = ProductionOnboardingBuildInput.model_validate_json(approval_input)
    template_bytes = _templates_by_slot(slot_templates)
    parsed = ProvisioningTemplateMaterializer.parse(
        template_bytes,
        profile_hash=profile_hash,
        host_id=host_id,
    )

    capabilities: list[ProvisioningCapability] = []
    for selected in approval.capability_probes:
        kind, profile_ref = resolve_probe(str(selected.probe_id))
        if (
            kind != _EXPECTED_PROBE_KIND[selected.slot]
            or profile_ref.host_id != host_id
        ):
            raise ValueError("PRODUCTION_CAPABILITY_PROBE_MISMATCH")
        capabilities.append(
            ProvisioningCapability(slot=selected.slot, profile_ref=profile_ref)
        )

    artifacts = tuple(
        ProvisioningArtifact(
            slot=cast(ArtifactSlot, slot),
            content_sha256=hashlib.sha256(data).hexdigest(),
        )
        for slot, data in sorted(template_bytes.items())
    )
    provisioning = ProductionProvisioningManifest(
        schema_version=2,
        artifact_scope="HOST_PROFILE_TEMPLATE",
        profile_hash=profile_hash,
        host_id=host_id,
        created_at=approval.created_at,
        expires_at=approval.expires_at,
        approved_by=approval.approved_by,
        capabilities=tuple(capabilities),
        artifacts=artifacts,
    )
    provisioning_bytes = canonical_bytes(provisioning)
    provisioning_digest = hashlib.sha256(provisioning_bytes).hexdigest()
    onboarding = ProductionOnboardingManifest(
        schema_version=2,
        profile_hash=profile_hash,
        created_at=approval.created_at,
        expires_at=approval.expires_at,
        approved_by=approval.approved_by,
        policy_artifact_sha256=approval.policy_artifact_sha256,
        provisioning_manifest_sha256=provisioning_digest,
        provider_approvals=approval.provider_approvals,
        route_approvals=approval.route_approvals,
    )
    onboarding_bytes = canonical_bytes(onboarding)

    supplied = dict(evidence)
    supplied.update(
        {hashlib.sha256(data).hexdigest(): data for data in template_bytes.values()}
    )
    required = {
        approval.policy_artifact_sha256,
        *(
            item.evidence_sha256
            for provider in approval.provider_approvals
            for item in provider.tests
        ),
        *(
            digest
            for route in approval.route_approvals
            for digest in (
                route.evaluation_result_sha256,
                route.recommendation_sha256,
            )
        ),
        *(
            digest
            for document in parsed.values()
            for digest in document.evidence_sha256
        ),
    }
    if set(supplied) != required | {
        item.content_sha256 for item in provisioning.artifacts
    }:
        raise ValueError("PRODUCTION_ONBOARDING_EVIDENCE_SET_MISMATCH")
    supplied[provisioning_digest] = provisioning_bytes
    index = ProductionOnboardingBundleIndex(
        schema_version=1,
        onboarding_manifest_sha256=hashlib.sha256(onboarding_bytes).hexdigest(),
        provisioning_manifest_sha256=provisioning_digest,
        evidence_sha256=tuple(sorted(supplied)),
    )
    return ComposedProductionOnboarding(
        onboarding=onboarding,
        provisioning=provisioning,
        onboarding_bytes=onboarding_bytes,
        provisioning_bytes=provisioning_bytes,
        evidence=supplied,
        index=index,
        index_bytes=canonical_bytes(index),
    )


def _templates_by_slot(values: tuple[bytes, ...]) -> dict[str, bytes]:
    by_slot: dict[str, bytes] = {}
    for data in values:
        try:
            payload = json.loads(data)
            slot = payload["slot"]
        except (KeyError, TypeError, json.JSONDecodeError):
            raise ValueError("PRODUCTION_PROVISIONING_TEMPLATE_INVALID") from None
        if not isinstance(slot, str) or slot not in _ARTIFACT_SLOTS or slot in by_slot:
            raise ValueError("PRODUCTION_PROVISIONING_TEMPLATE_SET_INCOMPLETE")
        by_slot[slot] = data
    return by_slot


def _require_safe(*values: bytes) -> None:
    for data in values:
        assert_safe_provider_text(data)
        digest = hashlib.sha256(data).hexdigest()
        if not digest:
            raise ValueError("PRODUCTION_ONBOARDING_EVIDENCE_INVALID")


def safe_evidence_digest(data: bytes) -> str:
    """Return a digest only after the persisted bytes pass the secret/path guard."""

    assert_safe_provider_text(data)
    return hashlib.sha256(data).hexdigest()


__all__ = [
    "ApprovedCapabilityProbe",
    "ApprovedProbeResolver",
    "ComposedProductionOnboarding",
    "ProductionOnboardingBuildInput",
    "ProductionOnboardingBundleIndex",
    "compose_production_onboarding",
    "safe_evidence_digest",
]
