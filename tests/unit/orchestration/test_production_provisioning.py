from __future__ import annotations

import hashlib
import json
from typing import cast

import pytest

from sastsimi.contracts.capabilities import RuntimeCapabilityProfile
from sastsimi.contracts.refs import HostConfigurationRef, reference
from sastsimi.contracts.static import StaticToolProfile
from sastsimi.orchestration.production_onboarding import ProductionProvisioningManifest
from sastsimi.orchestration.production_provisioning import (
    ExactProductionProvisioningResolver,
)
from tests.integration.storage.test_production_capability_registry import (
    _runtime_profile,
)
from tests.unit.orchestration.test_production_onboarding import (
    _production_profile,
    _provisioning_payload,
)
from tests.unit.static_analysis.test_repository_profile import (
    _git_capability,
    _static_selection,
)


class _Configuration:
    def __init__(
        self,
        records: dict[
            HostConfigurationRef, RuntimeCapabilityProfile | StaticToolProfile
        ],
    ) -> None:
        self.records = records

    def resolve_pinned_active_profile(
        self, ref: HostConfigurationRef
    ) -> RuntimeCapabilityProfile | StaticToolProfile:
        return self.records[ref]


def _manifest() -> tuple[
    ProductionProvisioningManifest,
    dict[HostConfigurationRef, RuntimeCapabilityProfile | StaticToolProfile],
    dict[str, bytes],
]:
    profile = _production_profile()
    git, _ = _git_capability()
    python = _runtime_profile(
        key="python-runtime",
        kind="PYTHON_RUNTIME",
        languages=("PYTHON",),
        operations=("START",),
        subject_key="python",
    )
    ast = _static_selection("PYTHON_AST", "PYTHON").profile
    refs = {
        "GIT_CLONE": cast(HostConfigurationRef, reference(git)),
        "GIT_CHECKOUT": cast(HostConfigurationRef, reference(git)),
        "PYTHON_RUNTIME": cast(HostConfigurationRef, reference(python)),
        "AST": cast(HostConfigurationRef, reference(ast)),
    }
    payload = _provisioning_payload(profile)
    payload["host_id"] = "host-a"
    for item in cast(list[dict[str, object]], payload["capabilities"]):
        item["profile_ref"] = refs[cast(str, item["slot"])].model_dump(mode="json")
    manifest = ProductionProvisioningManifest.model_validate_json(json.dumps(payload))
    records = {refs["GIT_CLONE"]: git, refs["PYTHON_RUNTIME"]: python, refs["AST"]: ast}
    artifacts = {
        item.content_sha256: f"{item.slot}-data".encode()
        for item in manifest.artifacts
    }
    assert all(
        hashlib.sha256(data).hexdigest() == digest
        for digest, data in artifacts.items()
    )
    return manifest, records, artifacts


def test_exact_provisioning_resolves_only_current_approved_inputs() -> None:
    manifest, records, artifacts = _manifest()
    resolver = ExactProductionProvisioningResolver(
        configuration=cast(object, _Configuration(records)),  # type: ignore[arg-type]
        evidence=artifacts.__getitem__,
    )

    resolved = resolver.resolve(manifest)

    assert set(resolved.capabilities) == {
        "GIT_CLONE",
        "GIT_CHECKOUT",
        "PYTHON_RUNTIME",
        "AST",
    }
    assert set(resolved.artifacts) == {
        "WORKSPACE_STORAGE",
        "STATIC_ANALYSIS",
        "VERIFICATION_PLAYBOOKS",
        "SANDBOX_PROFILE",
        "POLICY_CATALOG",
        "PROVIDER_CONFIGURATION",
        "PROMPT_ROUTES",
    }


def test_exact_provisioning_rejects_stale_capability_substitution() -> None:
    manifest, records, artifacts = _manifest()
    clone_ref = next(
        item.profile_ref for item in manifest.capabilities if item.slot == "GIT_CLONE"
    )
    records[clone_ref] = next(
        record
        for record in records.values()
        if isinstance(record, RuntimeCapabilityProfile)
        and record.capability_kind == "PYTHON_RUNTIME"
    )
    resolver = ExactProductionProvisioningResolver(
        configuration=cast(object, _Configuration(records)),  # type: ignore[arg-type]
        evidence=artifacts.__getitem__,
    )

    with pytest.raises(ValueError, match="PRODUCTION_CAPABILITY_REFERENCE_MISMATCH"):
        resolver.resolve(manifest)
