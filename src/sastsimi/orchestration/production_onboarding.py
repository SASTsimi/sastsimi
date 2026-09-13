"""Credential-free operator onboarding and production bundle loading.

The onboarding file is only an approval receipt.  It never contains a secret and
cannot turn a smoke test into Provider support.  Exact PVD and R8 evidence must be
imported first; a run-scoped provisioner then publishes the corresponding domain
records and returns the capability bundle consumed by production composition.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Literal, Protocol, Self

from pydantic import AwareDatetime, model_validator

from sastsimi.config.production_profile import ProductionProfile
from sastsimi.contracts.base import ContractModel, NonEmptyStr, Sha256
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import Environment, LLMRole, Product
from sastsimi.contracts.prompt_redaction import assert_safe_provider_text
from sastsimi.contracts.refs import HostConfigurationRef
from sastsimi.orchestration.production_capabilities import (
    ProfileBackedProductionCapabilityBundle,
    production_profile_hash,
)
from sastsimi.orchestration.production_composition import ProductionFeatureInstaller
from sastsimi.prompts.production import REQUIRED_PRODUCTION_PROMPT_ROUTES

_PVD_IDS = frozenset(f"PVD-{index:02d}" for index in range(1, 16))
_OPTIONAL_PVD_IDS = frozenset({"PVD-16"})
_ENV_REFERENCE = re.compile(r"env:[A-Z][A-Z0-9_]{1,127}\Z")
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class ProductionOnboardingUnavailable(RuntimeError):
    """Safe reason why a profile cannot be used for production yet."""


class PVDObservation(ContractModel):
    test_id: Literal[
        "PVD-01",
        "PVD-02",
        "PVD-03",
        "PVD-04",
        "PVD-05",
        "PVD-06",
        "PVD-07",
        "PVD-08",
        "PVD-09",
        "PVD-10",
        "PVD-11",
        "PVD-12",
        "PVD-13",
        "PVD-14",
        "PVD-15",
        "PVD-16",
    ]
    result: Literal["PASS", "FAIL", "NOT_APPLICABLE"]
    evidence_sha256: Sha256
    safe_summary: NonEmptyStr


class ProviderOnboardingApproval(ContractModel):
    provider_profile_key: NonEmptyStr
    product: Product
    environment: Environment
    model: NonEmptyStr
    client_name: NonEmptyStr
    client_version: NonEmptyStr
    credential_ref: NonEmptyStr
    checked_at: AwareDatetime
    checked_by: NonEmptyStr
    approved_by: NonEmptyStr
    approved_at: AwareDatetime
    expires_at: AwareDatetime
    terms_approved_by: NonEmptyStr
    terms_approved_at: AwareDatetime
    terms_valid_until: AwareDatetime
    tests: tuple[PVDObservation, ...]

    @model_validator(mode="after")
    def complete_observations(self) -> Self:
        by_id = {str(item.test_id): item for item in self.tests}
        if len(by_id) != len(self.tests) or set(by_id) not in {
            _PVD_IDS,
            _PVD_IDS | _OPTIONAL_PVD_IDS,
        }:
            raise ValueError("PVD_OBSERVATIONS_INCOMPLETE")
        allowed_na = (
            {"PVD-13"} if self.product in {"OPENAI_API", "ANTHROPIC_API"} else set()
        )
        if any(
            item.result == "FAIL"
            or (item.result == "NOT_APPLICABLE" and item.test_id not in allowed_na)
            for item in self.tests
        ):
            raise ValueError("PVD_OBSERVATIONS_INCOMPLETE")
        if by_id["PVD-15"].result != "PASS":
            raise ValueError("PVD_TERMS_APPROVAL_REQUIRED")
        if not (
            self.checked_at <= self.approved_at < self.expires_at
            and self.terms_approved_at < self.terms_valid_until
        ):
            raise ValueError("PVD_APPROVAL_TIME_INVALID")
        return self


class RouteOnboardingApproval(ContractModel):
    role: LLMRole
    task_kind: NonEmptyStr
    provider_profile_key: NonEmptyStr
    model: NonEmptyStr
    prompt_key: NonEmptyStr
    template_path: NonEmptyStr
    template_sha256: Sha256
    evaluation_result_sha256: Sha256
    recommendation_sha256: Sha256
    decision: Literal["ACCEPT_FOR_PRODUCTION", "REJECT", "NEEDS_MORE_EVIDENCE"]
    approved_by: NonEmptyStr
    approved_at: AwareDatetime


class ProvisioningCapability(ContractModel):
    """One exact host capability revision selected for a production slot."""

    slot: Literal[
        "GIT_CLONE",
        "GIT_CHECKOUT",
        "PYTHON_RUNTIME",
        "AST",
        "CODEQL",
        "OPENGREP",
        "DOCKER",
    ]
    profile_ref: HostConfigurationRef


class ProvisioningArtifact(ContractModel):
    """Content-addressed operator input; its bytes are never inferred."""

    slot: Literal[
        "WORKSPACE_STORAGE",
        "STATIC_ANALYSIS",
        "VERIFICATION_PLAYBOOKS",
        "SANDBOX_PROFILE",
        "POLICY_CATALOG",
        "PROVIDER_CONFIGURATION",
        "PROMPT_ROUTES",
    ]
    content_sha256: Sha256


class ProductionProvisioningManifest(ContractModel):
    """Exact, credential-free inputs required to construct one run bundle.

    The approval receipt deliberately names immutable host revisions and
    content-addressed configuration artifacts.  A provisioner must resolve and
    revalidate every item; absence is not permission to select a default.
    """

    schema_version: Literal[1]
    profile_hash: Sha256
    host_id: NonEmptyStr
    created_at: AwareDatetime
    expires_at: AwareDatetime
    approved_by: NonEmptyStr
    capabilities: tuple[ProvisioningCapability, ...]
    artifacts: tuple[ProvisioningArtifact, ...]

    @model_validator(mode="after")
    def exact_closure(self) -> Self:
        capability_slots = tuple(item.slot for item in self.capabilities)
        artifact_slots = tuple(item.slot for item in self.artifacts)
        required_capabilities = {
            "GIT_CLONE",
            "GIT_CHECKOUT",
            "PYTHON_RUNTIME",
            "AST",
        }
        required_artifacts = {
            "WORKSPACE_STORAGE",
            "STATIC_ANALYSIS",
            "VERIFICATION_PLAYBOOKS",
            "SANDBOX_PROFILE",
            "POLICY_CATALOG",
            "PROVIDER_CONFIGURATION",
            "PROMPT_ROUTES",
        }
        static_slots = {
            "AST",
            "CODEQL",
            "OPENGREP",
        }
        if (
            self.created_at >= self.expires_at
            or len(capability_slots) != len(set(capability_slots))
            or len(artifact_slots) != len(set(artifact_slots))
            or not required_capabilities <= set(capability_slots)
            or set(artifact_slots) != required_artifacts
            or any(
                item.profile_ref.host_id != self.host_id
                for item in self.capabilities
            )
            or any(
                item.profile_ref.data_kind
                != (
                    "static_tool_profile"
                    if item.slot in static_slots
                    else "runtime_capability_profile"
                )
                for item in self.capabilities
            )
        ):
            raise ValueError("PRODUCTION_PROVISIONING_APPROVAL_INVALID")
        return self


class ProductionOnboardingManifest(ContractModel):
    """Credential-free, immutable operator approval input for one profile."""

    schema_version: Literal[1, 2]
    profile_hash: Sha256
    created_at: AwareDatetime
    expires_at: AwareDatetime
    approved_by: NonEmptyStr
    policy_artifact_sha256: Sha256
    provisioning_manifest_sha256: Sha256 | None = None
    provider_approvals: tuple[ProviderOnboardingApproval, ...]
    route_approvals: tuple[RouteOnboardingApproval, ...]

    @model_validator(mode="after")
    def unique_and_accepted(self) -> Self:
        providers = tuple(
            (item.provider_profile_key, item.model) for item in self.provider_approvals
        )
        routes = tuple((item.role, item.task_kind) for item in self.route_approvals)
        if (
            not providers
            or len(providers) != len(set(providers))
            or not routes
            or len(routes) != len(set(routes))
            or any(
                item.decision != "ACCEPT_FOR_PRODUCTION"
                for item in self.route_approvals
            )
            or self.created_at >= self.expires_at
            or (self.schema_version == 2)
            != (self.provisioning_manifest_sha256 is not None)
        ):
            raise ValueError("PRODUCTION_ONBOARDING_APPROVAL_INVALID")
        return self


class FilesystemProductionOnboardingStore:
    """Atomic content-addressed evidence and approval receipt persistence."""

    def __init__(self, data_dir: Path) -> None:
        self.root = data_dir.resolve() / "onboarding"

    def put_evidence(self, data: bytes) -> str:
        assert_safe_provider_text(data)
        digest = hashlib.sha256(data).hexdigest()
        target = self._evidence_path(digest)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if target.read_bytes() != data:
                raise ValueError("ONBOARDING_EVIDENCE_HASH_MISMATCH")
            return digest
        temporary = target.with_name(target.name + ".tmp")
        try:
            with temporary.open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
        return digest

    def save(self, manifest: ProductionOnboardingManifest) -> Path:
        manifest = ProductionOnboardingManifest.model_validate(manifest)
        for provider in manifest.provider_approvals:
            if _ENV_REFERENCE.fullmatch(provider.credential_ref) is None:
                raise ValueError("CREDENTIAL_REFERENCE_INVALID")
        data = canonical_bytes(manifest)
        assert_safe_provider_text(data)
        target = self._manifest_path(manifest.profile_hash)
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            if target.read_bytes() != data:
                raise ValueError("ONBOARDING_MANIFEST_CONFLICT")
            return target
        temporary = target.with_name(target.name + ".tmp")
        try:
            with temporary.open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
        return target

    def load(self, profile_hash: str) -> ProductionOnboardingManifest:
        try:
            data = self._manifest_path(profile_hash).read_bytes()
            assert_safe_provider_text(data)
            return ProductionOnboardingManifest.model_validate_json(data)
        except (OSError, ValueError):
            raise ProductionOnboardingUnavailable(
                "PRODUCTION_ONBOARDING_REQUIRED"
            ) from None

    def require_evidence(self, digest: str) -> bytes:
        try:
            data = self._evidence_path(digest).read_bytes()
        except OSError:
            raise ProductionOnboardingUnavailable(
                "PRODUCTION_ONBOARDING_EVIDENCE_MISSING"
            ) from None
        if hashlib.sha256(data).hexdigest() != digest:
            raise ProductionOnboardingUnavailable(
                "PRODUCTION_ONBOARDING_EVIDENCE_STALE"
            )
        assert_safe_provider_text(data)
        return data

    def _manifest_path(self, profile_hash: str) -> Path:
        if re.fullmatch(r"[0-9a-f]{64}", profile_hash) is None:
            raise ValueError("PROFILE_HASH_INVALID")
        return self.root / "profiles" / f"{profile_hash}.json"

    def _evidence_path(self, digest: str) -> Path:
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("EVIDENCE_HASH_INVALID")
        return self.root / "evidence" / "sha256" / digest[:2] / digest[2:]


class AnalysisCapabilityProvisioner(Protocol):
    """Publish run-scoped exact records and bind concrete adapters."""

    def __call__(
        self,
        *,
        data_dir: Path,
        request: object,
        profile: ProductionProfile,
        scope: object,
        manifest: ProductionOnboardingManifest,
        provisioning: ProductionProvisioningManifest,
        evidence: Callable[[str], bytes],
        installer: ProductionFeatureInstaller,
    ) -> ProfileBackedProductionCapabilityBundle: ...


class OnboardedProductionCapabilityBundleLoader:
    """Fail closed on stale onboarding before provisioning an analysis bundle."""

    def __init__(
        self,
        *,
        store: FilesystemProductionOnboardingStore | None = None,
        repository_root: Path,
        clock: Callable[[], datetime],
        provision: AnalysisCapabilityProvisioner,
        installer: ProductionFeatureInstaller,
    ) -> None:
        self._store = store
        self._repository_root = repository_root.resolve()
        self._clock = clock
        self._provision = provision
        self._installer = installer

    def load_for_profile(
        self, profile: ProductionProfile, *, data_dir: Path | None = None
    ) -> ProductionOnboardingManifest:
        store = self._store_for(data_dir)
        digest = production_profile_hash(profile)
        manifest = store.load(digest)
        if manifest.profile_hash != digest:
            raise ProductionOnboardingUnavailable("PRODUCTION_ONBOARDING_STALE")
        now = self._clock()
        if now >= manifest.expires_at:
            raise ProductionOnboardingUnavailable("PRODUCTION_ONBOARDING_STALE")
        configured_providers = {
            (item.provider_profile_key, route.model): item
            for item in profile.providers
            for route in profile.llm_routes
            if route.provider_profile_key == item.provider_profile_key
        }
        approvals = {
            (item.provider_profile_key, item.model): item
            for item in manifest.provider_approvals
        }
        if set(configured_providers) != set(approvals):
            raise ProductionOnboardingUnavailable(
                "PRODUCTION_PROVIDER_APPROVAL_INCOMPLETE"
            )
        for key, provider_approval in approvals.items():
            connection = configured_providers[key]
            if (
                provider_approval.product != connection.product
                or provider_approval.environment != connection.environment
                or provider_approval.client_name != connection.client_name
                or provider_approval.client_version != connection.client_version
                or provider_approval.credential_ref
                != connection.credential_ref.reference
                or now >= provider_approval.expires_at
            ):
                raise ProductionOnboardingUnavailable(
                    "PRODUCTION_PROVIDER_APPROVAL_STALE"
                )
            if now >= provider_approval.terms_valid_until:
                raise ProductionOnboardingUnavailable("PROVIDER_TERMS_APPROVAL_STALE")
        expected_routes = {
            (item.role, item.task_kind): item for item in profile.llm_routes
        }
        approved_routes = {
            (item.role, item.task_kind): item for item in manifest.route_approvals
        }
        if set(expected_routes) != set(approved_routes):
            raise ProductionOnboardingUnavailable(
                "PRODUCTION_PROMPT_APPROVAL_INCOMPLETE"
            )
        required = {
            (item.role, item.task_kind): item
            for item in REQUIRED_PRODUCTION_PROMPT_ROUTES
        }
        for key, route in expected_routes.items():
            route_approval = approved_routes[key]
            definition = required.get(key)
            if (
                definition is None
                or (
                    route_approval.provider_profile_key,
                    route_approval.model,
                    route_approval.prompt_key,
                )
                != (route.provider_profile_key, route.model, route.prompt_key)
                or Path(route_approval.template_path) != definition.template_path
            ):
                raise ProductionOnboardingUnavailable(
                    "PRODUCTION_PROMPT_APPROVAL_STALE"
                )
            try:
                template = read_builtin_prompt(
                    self._repository_root, definition.template_path
                )
            except (OSError, ValueError):
                raise ProductionOnboardingUnavailable(
                    "PRODUCTION_PROMPT_APPROVAL_STALE"
                ) from None
            if hashlib.sha256(template).hexdigest() != route_approval.template_sha256:
                raise ProductionOnboardingUnavailable(
                    "PRODUCTION_PROMPT_APPROVAL_STALE"
                )
        for digest_value in self._evidence_digests(manifest):
            store.require_evidence(digest_value)
        return manifest

    def provision(
        self,
        *,
        data_dir: Path,
        request: object,
        profile: ProductionProfile,
        scope: object,
    ) -> ProfileBackedProductionCapabilityBundle:
        store = self._store_for(data_dir)
        manifest = self.load_for_profile(profile, data_dir=data_dir)
        provisioning = self._load_provisioning(store, manifest, profile)
        return self._provision(
            data_dir=data_dir,
            request=request,
            profile=profile,
            scope=scope,
            manifest=manifest,
            provisioning=provisioning,
            evidence=store.require_evidence,
            installer=self._installer,
        )

    __call__ = provision

    def _store_for(self, data_dir: Path | None) -> FilesystemProductionOnboardingStore:
        if self._store is None:
            if data_dir is None:
                raise ProductionOnboardingUnavailable(
                    "PRODUCTION_ONBOARDING_DATA_DIR_REQUIRED"
                )
            return FilesystemProductionOnboardingStore(data_dir)
        if (
            data_dir is not None
            and self._store.root != data_dir.resolve() / "onboarding"
        ):
            raise ProductionOnboardingUnavailable(
                "PRODUCTION_ONBOARDING_DATA_DIR_MISMATCH"
            )
        return self._store

    @staticmethod
    def _evidence_digests(
        manifest: ProductionOnboardingManifest,
    ) -> frozenset[str]:
        return frozenset(
            {
                manifest.policy_artifact_sha256,
                *(
                    item.evidence_sha256
                    for provider in manifest.provider_approvals
                    for item in provider.tests
                ),
                *(item.evaluation_result_sha256 for item in manifest.route_approvals),
                *(item.recommendation_sha256 for item in manifest.route_approvals),
            }
        )

    def _load_provisioning(
        self,
        store: FilesystemProductionOnboardingStore,
        manifest: ProductionOnboardingManifest,
        profile: ProductionProfile,
    ) -> ProductionProvisioningManifest:
        digest = manifest.provisioning_manifest_sha256
        if digest is None:
            raise ProductionOnboardingUnavailable(
                "PRODUCTION_PROVISIONING_APPROVAL_REQUIRED"
            )
        try:
            payload = store.require_evidence(digest)
            provisioning = ProductionProvisioningManifest.model_validate_json(payload)
        except (ValueError, ProductionOnboardingUnavailable):
            raise ProductionOnboardingUnavailable(
                "PRODUCTION_PROVISIONING_APPROVAL_STALE"
            ) from None
        now = self._clock()
        if (
            provisioning.profile_hash != manifest.profile_hash
            or provisioning.host_id != profile.host_id
            or now >= provisioning.expires_at
            or provisioning.approved_by != manifest.approved_by
        ):
            raise ProductionOnboardingUnavailable(
                "PRODUCTION_PROVISIONING_APPROVAL_STALE"
            )
        for item in provisioning.artifacts:
            store.require_evidence(item.content_sha256)
        return provisioning


def read_builtin_prompt(repository_root: Path, relative: Path) -> bytes:
    """Read one canonical prompt without following links outside the source tree."""

    root = repository_root.resolve(strict=True)
    if relative.is_absolute() or any(
        part in {"", ".", ".."} for part in relative.parts
    ):
        raise ValueError("PROMPT_PATH_DENIED")
    candidate = root.joinpath(*relative.parts)
    current = root
    for part in relative.parts:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or bool(
            getattr(info, "st_file_attributes", 0) & _REPARSE_POINT
        ):
            raise ValueError("PROMPT_PATH_DENIED")
    resolved = candidate.resolve(strict=True)
    resolved.relative_to(root)
    if not resolved.is_file():
        raise ValueError("PROMPT_PATH_DENIED")
    data = resolved.read_bytes()
    if not data or len(data) > 4 * 1024 * 1024:
        raise ValueError("PROMPT_FILE_SIZE_INVALID")
    return data


__all__ = [
    "AnalysisCapabilityProvisioner",
    "FilesystemProductionOnboardingStore",
    "OnboardedProductionCapabilityBundleLoader",
    "PVDObservation",
    "ProductionOnboardingManifest",
    "ProductionOnboardingUnavailable",
    "ProductionProvisioningManifest",
    "ProvisioningArtifact",
    "ProvisioningCapability",
    "ProviderOnboardingApproval",
    "RouteOnboardingApproval",
    "read_builtin_prompt",
]
