from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

import pytest

from sastsimi.config.production_profile import ProductionProfile
from sastsimi.orchestration.production_capabilities import (
    ProfileBackedProductionCapabilityBundle,
    production_profile_hash,
)
from sastsimi.orchestration.production_onboarding import (
    FilesystemProductionOnboardingStore,
    OnboardedProductionCapabilityBundleLoader,
    ProductionOnboardingManifest,
    ProductionOnboardingUnavailable,
    ProductionProvisioningManifest,
)
from sastsimi.prompts.production import REQUIRED_PRODUCTION_PROMPT_ROUTES
from tests.integration.orchestration.test_production_composition import _profile


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _production_profile() -> ProductionProfile:
    values = _profile().model_dump(mode="python")
    values["providers"] = (
        {
            "provider_profile_key": "openai-main",
            "product": "OPENAI_API",
            "environment": "PERSONAL_LOCAL",
            "client_name": "openai-python",
            "client_version": "2.x",
            "credential_ref": {"reference": "env:OPENAI_API_KEY"},
        },
    )
    values["llm_routes"] = tuple(
        {
            "role": route.role,
            "task_kind": route.task_kind,
            "provider_profile_key": "openai-main",
            "model": "gpt-test",
            "prompt_key": f"{route.role.lower()}.{route.task_kind.lower()}.v1",
        }
        for route in REQUIRED_PRODUCTION_PROMPT_ROUTES
    )
    return ProductionProfile.model_validate(values)


def _manifest_payload(root: Path) -> dict[str, object]:
    profile = _production_profile()
    now = datetime(2026, 9, 13, tzinfo=UTC)
    evidence = _sha(b"safe evidence")
    template_hashes = {
        str(route.template_path): _sha((root / route.template_path).read_bytes())
        for route in REQUIRED_PRODUCTION_PROMPT_ROUTES
    }
    return {
        "schema_version": 1,
        "profile_hash": _sha(
            json.dumps(
                profile.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ),
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(days=30)).isoformat(),
        "approved_by": "operator@example.invalid",
        "policy_artifact_sha256": evidence,
        "provider_approvals": [
            {
                "provider_profile_key": "openai-main",
                "product": "OPENAI_API",
                "environment": "PERSONAL_LOCAL",
                "model": "gpt-test",
                "client_name": "openai-python",
                "client_version": "2.x",
                "credential_ref": "env:OPENAI_API_KEY",
                "checked_at": now.isoformat(),
                "checked_by": "pvd-runner",
                "approved_by": "operator@example.invalid",
                "approved_at": now.isoformat(),
                "expires_at": (now + timedelta(days=30)).isoformat(),
                "terms_approved_by": "operator@example.invalid",
                "terms_approved_at": now.isoformat(),
                "terms_valid_until": (now + timedelta(days=30)).isoformat(),
                "tests": [
                    {
                        "test_id": f"PVD-{index:02d}",
                        "result": ("NOT_APPLICABLE" if index == 13 else "PASS"),
                        "evidence_sha256": evidence,
                        "safe_summary": f"PVD-{index:02d} observed",
                    }
                    for index in range(1, 16)
                ],
            }
        ],
        "route_approvals": [
            {
                "role": route.role,
                "task_kind": route.task_kind,
                "provider_profile_key": "openai-main",
                "model": "gpt-test",
                "prompt_key": f"{route.role.lower()}.{route.task_kind.lower()}.v1",
                "template_path": str(route.template_path),
                "template_sha256": template_hashes[str(route.template_path)],
                "evaluation_result_sha256": evidence,
                "recommendation_sha256": evidence,
                "decision": "ACCEPT_FOR_PRODUCTION",
                "approved_by": "operator@example.invalid",
                "approved_at": now.isoformat(),
            }
            for route in REQUIRED_PRODUCTION_PROMPT_ROUTES
        ],
    }


@pytest.fixture
def data_dir() -> Iterator[Path]:
    path = Path.cwd() / f".production-onboarding-test-{uuid4()}"
    try:
        yield path
    finally:
        if path.exists():
            shutil.rmtree(path)


def _save(
    store: FilesystemProductionOnboardingStore, payload: dict[str, object]
) -> ProductionOnboardingManifest:
    store.put_evidence(b"safe evidence")
    manifest = _parse(payload)
    store.save(manifest)
    return manifest


def _parse(payload: dict[str, object]) -> ProductionOnboardingManifest:
    return ProductionOnboardingManifest.model_validate_json(json.dumps(payload))


def _provisioning_payload(profile: ProductionProfile) -> dict[str, object]:
    now = datetime(2026, 9, 13, tzinfo=UTC)

    def capability(slot: str, index: int, kind: str) -> dict[str, object]:
        return {
            "slot": slot,
            "profile_ref": {
                "stored_data_id": f"capability-{index}",
                "data_kind": kind,
                "content_hash": f"{index:x}" * 64,
                "configuration_scope": "HOST",
                "host_id": profile.host_id,
                "publication_analysis_id": "capability-publication",
                "publication_workspace_id": "capability-workspace",
                "publication_commit_id": "capability-commit",
                "record_id": f"capability-record-{index}",
            },
        }

    artifacts = [
        "WORKSPACE_STORAGE",
        "STATIC_ANALYSIS",
        "VERIFICATION_PLAYBOOKS",
        "SANDBOX_PROFILE",
        "POLICY_CATALOG",
        "PROVIDER_CONFIGURATION",
        "PROMPT_ROUTES",
    ]
    return {
        "schema_version": 2,
        "artifact_scope": "HOST_PROFILE_TEMPLATE",
        "profile_hash": production_profile_hash(profile),
        "host_id": profile.host_id,
        "created_at": now.isoformat(),
        "expires_at": (now + timedelta(days=30)).isoformat(),
        "approved_by": "operator@example.invalid",
        "capabilities": [
            capability("GIT_CLONE", 1, "runtime_capability_profile"),
            capability("GIT_CHECKOUT", 2, "runtime_capability_profile"),
            capability("PYTHON_RUNTIME", 3, "runtime_capability_profile"),
            capability("AST", 4, "static_tool_profile"),
        ],
        "artifacts": [
            {"slot": slot, "content_sha256": _sha(f"{slot}-data".encode())}
            for slot in artifacts
        ],
    }


def _save_provisioning(
    store: FilesystemProductionOnboardingStore, profile: ProductionProfile
) -> str:
    payload = _provisioning_payload(profile)
    for item in cast(list[dict[str, str]], payload["artifacts"]):
        data = f"{item['slot']}-data".encode()
        assert store.put_evidence(data) == item["content_sha256"]
    provisioning = ProductionProvisioningManifest.model_validate_json(
        json.dumps(payload)
    )
    return store.put_evidence(provisioning.model_dump_json().encode())


def test_onboarding_manifest_requires_full_pvd_and_current_terms_approval(
    data_dir: Path,
) -> None:
    payload = _manifest_payload(Path.cwd())
    provider = cast(list[dict[str, Any]], payload["provider_approvals"])[0]
    provider["tests"] = cast(list[dict[str, object]], provider["tests"])[1:]

    with pytest.raises(ValueError, match="PVD_OBSERVATIONS_INCOMPLETE"):
        _parse(payload)

    payload = _manifest_payload(Path.cwd())
    provider = cast(list[dict[str, Any]], payload["provider_approvals"])[0]
    tests = cast(list[dict[str, object]], provider["tests"])
    tests[0]["result"] = "FAIL"

    with pytest.raises(ValueError, match="PVD_OBSERVATIONS_INCOMPLETE"):
        _parse(payload)

    payload = _manifest_payload(Path.cwd())
    provider = cast(list[dict[str, Any]], payload["provider_approvals"])[0]
    provider["terms_valid_until"] = "2026-09-13T12:00:00Z"
    manifest = _parse(payload)
    store = FilesystemProductionOnboardingStore(data_dir)
    store.put_evidence(b"safe evidence")
    store.save(manifest)

    loader = OnboardedProductionCapabilityBundleLoader(
        store=store,
        repository_root=Path.cwd(),
        clock=lambda: datetime(2026, 9, 14, tzinfo=UTC),
        provision=lambda **_kwargs: cast(
            ProfileBackedProductionCapabilityBundle, SimpleNamespace()
        ),
    )
    with pytest.raises(
        ProductionOnboardingUnavailable, match="PROVIDER_TERMS_APPROVAL_STALE"
    ):
        loader.load_for_profile(_production_profile())


def test_onboarding_store_rejects_secret_material(data_dir: Path) -> None:
    payload = _manifest_payload(Path.cwd())
    provider = cast(list[dict[str, Any]], payload["provider_approvals"])[0]
    provider["credential_ref"] = "sk-secret-value"

    with pytest.raises(ValueError, match="CREDENTIAL_REFERENCE_INVALID"):
        FilesystemProductionOnboardingStore(data_dir).save(_parse(payload))


def test_onboarding_store_never_overwrites_a_different_approval(
    data_dir: Path,
) -> None:
    store = FilesystemProductionOnboardingStore(data_dir)
    first = _save(store, _manifest_payload(Path.cwd()))
    changed = first.model_copy(update={"approved_by": "another-operator"})

    with pytest.raises(ValueError, match="ONBOARDING_MANIFEST_CONFLICT"):
        store.save(changed)


def test_loader_verifies_profile_prompts_and_injects_exact_provisioning(
    data_dir: Path,
) -> None:
    root = Path.cwd()
    profile = _production_profile()
    store = FilesystemProductionOnboardingStore(data_dir)
    provisioning_digest = _save_provisioning(store, profile)
    payload = _manifest_payload(root)
    payload["schema_version"] = 2
    payload["provisioning_manifest_sha256"] = provisioning_digest
    manifest = _save(store, payload)
    calls: list[dict[str, object]] = []
    expected = cast(ProfileBackedProductionCapabilityBundle, SimpleNamespace())

    def provision(**values: object) -> ProfileBackedProductionCapabilityBundle:
        calls.append(values)
        return expected

    loader = OnboardedProductionCapabilityBundleLoader(
        store=store,
        repository_root=root,
        clock=lambda: datetime(2026, 9, 14, tzinfo=UTC),
        provision=provision,
    )

    loaded = loader.load_for_profile(profile)

    assert loaded == manifest
    assert calls == []
    assert (
        loader.provision(
            data_dir=data_dir,
            request=cast(Any, object()),
            profile=profile,
            scope=cast(Any, object()),
        )
        is expected
    )
    assert calls[0]["manifest"] == manifest
    assert isinstance(calls[0]["provisioning"], ProductionProvisioningManifest)
    assert "installer" not in calls[0]


def test_provisioning_fails_closed_without_exact_manifest(data_dir: Path) -> None:
    profile = _production_profile()
    store = FilesystemProductionOnboardingStore(data_dir)
    _save(store, _manifest_payload(Path.cwd()))
    loader = OnboardedProductionCapabilityBundleLoader(
        store=store,
        repository_root=Path.cwd(),
        clock=lambda: datetime(2026, 9, 14, tzinfo=UTC),
        provision=lambda **_kwargs: cast(
            ProfileBackedProductionCapabilityBundle, SimpleNamespace()
        ),
    )

    with pytest.raises(
        ProductionOnboardingUnavailable,
        match="PRODUCTION_PROVISIONING_APPROVAL_REQUIRED",
    ):
        loader.provision(
            data_dir=data_dir,
            request=object(),
            profile=profile,
            scope=object(),
        )


def test_loader_blocks_modified_builtin_prompt(data_dir: Path) -> None:
    source_root = Path.cwd()
    profile = _production_profile()
    store = FilesystemProductionOnboardingStore(data_dir)
    _save(store, _manifest_payload(source_root))
    copied_root = data_dir / "repository"
    route = REQUIRED_PRODUCTION_PROMPT_ROUTES[0]
    target = copied_root / route.template_path
    target.parent.mkdir(parents=True)
    target.write_text("modified", encoding="utf-8")

    loader = OnboardedProductionCapabilityBundleLoader(
        store=store,
        repository_root=copied_root,
        clock=lambda: datetime(2026, 9, 14, tzinfo=UTC),
        provision=lambda **_kwargs: cast(
            ProfileBackedProductionCapabilityBundle, SimpleNamespace()
        ),
    )

    with pytest.raises(
        ProductionOnboardingUnavailable, match="PRODUCTION_PROMPT_APPROVAL_STALE"
    ):
        loader.load_for_profile(profile)


def test_loader_blocks_provider_identity_changed_after_pvd(data_dir: Path) -> None:
    profile = _production_profile()
    payload = _manifest_payload(Path.cwd())
    provider = cast(list[dict[str, Any]], payload["provider_approvals"])[0]
    provider["client_version"] = "different-client"
    store = FilesystemProductionOnboardingStore(data_dir)
    _save(store, payload)
    loader = OnboardedProductionCapabilityBundleLoader(
        store=store,
        repository_root=Path.cwd(),
        clock=lambda: datetime(2026, 9, 14, tzinfo=UTC),
        provision=lambda **_kwargs: cast(
            ProfileBackedProductionCapabilityBundle, SimpleNamespace()
        ),
    )

    with pytest.raises(
        ProductionOnboardingUnavailable, match="PRODUCTION_PROVIDER_APPROVAL_STALE"
    ):
        loader.load_for_profile(profile)
