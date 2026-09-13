"""Immutable production configuration snapshots and read-only restart inspection."""

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from sastsimi.config.production_profile import ProductionProfile
from sastsimi.contracts.analysis import (
    AnalysisRunInput,
    AnalysisRunState,
    AnalysisStartRequest,
)
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.ids import AnalysisId, StoredDataId
from sastsimi.contracts.prompt_redaction import (
    assert_safe_provider_text,
    redact_untrusted_text,
)
from sastsimi.contracts.refs import RunStoredDataRef, reference
from sastsimi.orchestration.production_capabilities import (
    ProfileBackedProductionCapabilityBundle,
)
from sastsimi.orchestration.production_onboarding import (
    FilesystemProductionOnboardingStore,
    OnboardedProductionCapabilityBundleLoader,
    ProductionOnboardingManifest,
    ProductionProvisioningManifest,
)
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.record_store import RecordStore


@dataclass(frozen=True, slots=True)
class ProductionDescriptor:
    """Validated pinned input; contains no runtime or executable adapter."""

    run_input: AnalysisRunInput
    scope: PlannedRunScope
    request: AnalysisStartRequest
    profile: ProductionProfile
    onboarding: ProductionOnboardingManifest


def _artifact_ref(analysis_id: AnalysisId, digest: str) -> RunStoredDataRef:
    return RunStoredDataRef(
        stored_data_id=StoredDataId(digest),
        data_kind="artifact",
        content_hash=digest,
        analysis_id=analysis_id,
        record_id=None,
    )


def _require_credential_free_profile(data: bytes) -> None:
    # Exact approved host paths are configuration, never command output.
    if set(redact_untrusted_text(data).categories) - {"HOST_ABSOLUTE_PATH"}:
        raise ValueError("PRODUCTION_DESCRIPTOR_CREDENTIAL_REJECTED")


def persist_production_descriptor(
    *,
    artifacts: ArtifactStore,
    analysis_id: AnalysisId,
    profile: ProductionProfile,
    manifest: ProductionOnboardingManifest,
    evidence: Callable[[str], bytes],
) -> tuple[RunStoredDataRef, RunStoredDataRef]:
    """Snapshot canonical profile, approval receipt and its exact evidence bytes."""
    profile_data = canonical_bytes(profile.model_dump(mode="json"))
    manifest_data = canonical_bytes(manifest)
    _require_credential_free_profile(profile_data)
    assert_safe_provider_text(manifest_data)
    profile = ProductionProfile.model_validate(json.loads(profile_data))
    manifest = ProductionOnboardingManifest.model_validate_json(manifest_data)
    if manifest.profile_hash != content_hash(profile.model_dump(mode="json")):
        raise ValueError("PRODUCTION_DESCRIPTOR_PROFILE_MISMATCH")
    digest = manifest.provisioning_manifest_sha256
    if digest is None:
        raise ValueError("PRODUCTION_DESCRIPTOR_PROVISIONING_REQUIRED")
    provisioning_data = evidence(digest)
    provisioning = ProductionProvisioningManifest.model_validate_json(provisioning_data)
    digests = {
        digest,
        manifest.policy_artifact_sha256,
        *(item.content_sha256 for item in provisioning.artifacts),
        *(
            item.evidence_sha256
            for provider in manifest.provider_approvals
            for item in provider.tests
        ),
        *(item.evaluation_result_sha256 for item in manifest.route_approvals),
        *(item.recommendation_sha256 for item in manifest.route_approvals),
    }
    for required in sorted(digests):
        data = provisioning_data if required == digest else evidence(required)
        assert_safe_provider_text(data)
        ref = artifacts.commit_run(
            artifacts.stage_bytes(data, "application/json"), analysis_id
        )
        if ref != _artifact_ref(analysis_id, required):
            raise ValueError("PRODUCTION_DESCRIPTOR_EVIDENCE_MISMATCH")
    return (
        artifacts.commit_run(
            artifacts.stage_bytes(profile_data, "application/json"), analysis_id
        ),
        artifacts.commit_run(
            artifacts.stage_bytes(manifest_data, "application/json"), analysis_id
        ),
    )


class _PinnedOnboardingStore(FilesystemProductionOnboardingStore):
    """Use the existing approval validator over exact run artifacts only."""

    def __init__(
        self,
        manifest: ProductionOnboardingManifest,
        analysis_id: AnalysisId,
        artifacts: ArtifactStore,
    ) -> None:
        self._manifest = manifest
        self._analysis_id = analysis_id
        self._artifacts = artifacts

    def load(self, profile_hash: str) -> ProductionOnboardingManifest:
        if self._manifest.profile_hash != profile_hash:
            raise ValueError("PRODUCTION_DESCRIPTOR_PROFILE_MISMATCH")
        return self._manifest

    def require_evidence(self, digest: str) -> bytes:
        with self._artifacts.open_verified(
            _artifact_ref(self._analysis_id, digest)
        ) as stream:
            data = stream.read()
        assert_safe_provider_text(data)
        return data


def _no_provision(**_: object) -> ProfileBackedProductionCapabilityBundle:
    raise ValueError("PRODUCTION_RESUME_DISPATCH_NOT_AVAILABLE")


def load_production_descriptor(
    *,
    state: AnalysisRunState,
    records: RecordStore,
    artifacts: ArtifactStore,
    repository_root: Path,
    now: datetime,
) -> ProductionDescriptor:
    """Verify exact immutable bytes without creating IDs, profiles or workers."""
    if state.analysis_input_ref.analysis_id != state.meta.analysis_id:
        raise ValueError("PRODUCTION_DESCRIPTOR_SCOPE_MISMATCH")
    if records.get_exact(reference(state)) != state:
        raise ValueError("PRODUCTION_DESCRIPTOR_STATE_MISMATCH")
    run_input = records.get_exact(state.analysis_input_ref)
    if (
        not isinstance(run_input, AnalysisRunInput)
        or reference(run_input) != state.analysis_input_ref
    ):
        raise ValueError("PRODUCTION_DESCRIPTOR_INPUT_MISMATCH")
    profile_ref, onboarding_ref = (
        run_input.production_profile_ref,
        run_input.production_onboarding_ref,
    )
    if (
        run_input.workspace_id is None
        or run_input.commit_id is None
        or profile_ref is None
        or onboarding_ref is None
    ):
        raise ValueError("PRODUCTION_DESCRIPTOR_REQUIRED")
    if (
        run_input.meta.analysis_id != state.meta.analysis_id
        or profile_ref.analysis_id != state.meta.analysis_id
        or onboarding_ref.analysis_id != state.meta.analysis_id
        or run_input.purpose != "PRODUCTION"
        or state.purpose != "PRODUCTION"
        or run_input.program_id != state.program_id
        or run_input.requested_git_ref != str(run_input.commit_id)
        or (
            state.workspace_id is not None
            and state.workspace_id != run_input.workspace_id
        )
        or (state.commit_id is not None and state.commit_id != run_input.commit_id)
    ):
        raise ValueError("PRODUCTION_DESCRIPTOR_SCOPE_MISMATCH")
    import re

    if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", str(run_input.commit_id)) is None:
        raise ValueError("PRODUCTION_DESCRIPTOR_COMMIT_INVALID")
    with artifacts.open_verified(profile_ref) as stream:
        profile_data = stream.read()
    with artifacts.open_verified(onboarding_ref) as stream:
        manifest_data = stream.read()
    _require_credential_free_profile(profile_data)
    assert_safe_provider_text(manifest_data)
    profile = ProductionProfile.model_validate(json.loads(profile_data))
    manifest = ProductionOnboardingManifest.model_validate_json(manifest_data)
    if profile.program_id != str(
        run_input.program_id
    ) or profile_ref.content_hash != content_hash(profile.model_dump(mode="json")):
        raise ValueError("PRODUCTION_DESCRIPTOR_PROFILE_MISMATCH")
    if (
        now < manifest.created_at
        or any(
            now < item.approved_at or now < item.terms_approved_at
            for item in manifest.provider_approvals
        )
        or any(now < item.approved_at for item in manifest.route_approvals)
    ):
        raise ValueError("PRODUCTION_DESCRIPTOR_APPROVAL_NOT_CURRENT")
    store = _PinnedOnboardingStore(manifest, state.meta.analysis_id, artifacts)
    validator = OnboardedProductionCapabilityBundleLoader(
        store=store,
        repository_root=repository_root,
        clock=lambda: now,
        provision=_no_provision,
    )
    validator.load_for_profile(profile)
    digest = manifest.provisioning_manifest_sha256
    if digest is None:
        raise ValueError("PRODUCTION_DESCRIPTOR_PROVISIONING_REQUIRED")
    provisioning = ProductionProvisioningManifest.model_validate_json(
        store.require_evidence(digest)
    )
    if (
        provisioning.profile_hash != manifest.profile_hash
        or provisioning.host_id != profile.host_id
        or provisioning.approved_by != manifest.approved_by
        or now < provisioning.created_at
        or now >= provisioning.expires_at
    ):
        raise ValueError("PRODUCTION_DESCRIPTOR_PROVISIONING_MISMATCH")
    for item in provisioning.artifacts:
        store.require_evidence(item.content_sha256)
    return ProductionDescriptor(
        run_input=run_input,
        scope=PlannedRunScope(
            state.meta.analysis_id,
            run_input.workspace_id,
            run_input.commit_id,
            str(run_input.repository_ref),
        ),
        request=AnalysisStartRequest(
            repository_ref=run_input.repository_ref,
            requested_git_ref=run_input.requested_git_ref,
            program_id=run_input.program_id,
            purpose=run_input.purpose,
        ),
        profile=profile,
        onboarding=manifest,
    )
