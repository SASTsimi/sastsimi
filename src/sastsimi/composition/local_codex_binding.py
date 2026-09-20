"""Exact official Codex binding for explicitly non-production local evaluation."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from sastsimi.config.local_evaluation_profile import LocalCodexSubscriptionSettings
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import LogicalRecordId, RecordId
from sastsimi.contracts.llm import (
    ClientExecutionProfile,
    ProviderCapabilities,
    ProviderProfile,
    ProviderValidationEvidence,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.orchestration.run_scope_plan import PlannedRunScope
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.providers.codex_subscription import (
    ApprovedCodexExecutable,
    ApprovedCodexExecutionBinding,
)


@dataclass(frozen=True, slots=True)
class LocalCodexBindingRecords:
    """Run-scoped experimental records plus their executable binding."""

    validation: ProviderValidationEvidence
    client: ClientExecutionProfile
    provider: ProviderProfile
    binding: ApprovedCodexExecutionBinding


def _meta(
    scope: PlannedRunScope,
    kind: str,
    *,
    ids: IdGenerator,
    clock: Clock,
) -> RecordMeta:
    record_id = ids.new(RecordId)
    return RecordMeta(
        record_id=record_id,
        logical_record_id=LogicalRecordId(str(record_id)),
        record_type=kind,
        schema_version="1.0.0",
        revision_number=1,
        previous_record_id=None,
        created_at=clock.now(),
        analysis_id=scope.analysis_id,
        workspace_id=scope.workspace_id,
        commit_id=scope.commit_id,
        hypothesis_id=None,
        attempt_id=None,
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1_048_576):
                digest.update(chunk)
    except (AttributeError, OSError):
        raise ValueError("LOCAL_CODEX_EXECUTABLE_MISMATCH") from None
    return digest.hexdigest()


def build_local_codex_binding(
    *,
    settings: LocalCodexSubscriptionSettings,
    scope: PlannedRunScope,
    artifacts: ArtifactStore,
    ids: IdGenerator,
    clock: Clock,
) -> LocalCodexBindingRecords:
    """Build a hash-pinned experimental binding without a Production claim."""

    try:
        executable = settings.executable_path.resolve(strict=True)
        codex_home = settings.codex_home.resolve(strict=True)
    except OSError:
        raise ValueError("LOCAL_CODEX_EXECUTABLE_MISMATCH") from None
    if (
        not executable.is_file()
        or executable.is_symlink()
        or _sha256_file(executable) != settings.executable_sha256
        or not codex_home.is_dir()
        or codex_home.is_symlink()
    ):
        raise ValueError("LOCAL_CODEX_EXECUTABLE_MISMATCH")

    network_policy_ref = artifacts.commit(
        artifacts.stage_bytes(
            canonical_bytes(
                {
                    "schema_version": 1,
                    "purpose": "LOCAL_EVALUATION",
                    "network": "OFFICIAL_CODEX_SERVICE_ONLY",
                    "provider_fallback": "DISABLED",
                }
            ),
            "application/json",
        )
    )
    validation = ProviderValidationEvidence(
        meta=_meta(
            scope,
            ProviderValidationEvidence.KIND,
            ids=ids,
            clock=clock,
        ),
        profile_key=settings.provider_profile_key,
        provider="OPENAI",
        product="CODEX",
        transport="CODEX_CLIENT",
        model=settings.model,
        environment="PERSONAL_LOCAL",
        auth_mode="SUBSCRIPTION_LOGIN",
        client_name="codex-cli",
        client_version=settings.client_version,
        tests=(),
        checked_at=clock.now(),
        checked_by="LOCAL_EVALUATION_OPERATOR",
    )
    validation_ref = reference(validation)
    if not isinstance(validation_ref, StoredDataRef):
        raise ValueError("LOCAL_CODEX_BINDING_SCOPE_MISMATCH")
    client = ClientExecutionProfile(
        meta=_meta(scope, ClientExecutionProfile.KIND, ids=ids, clock=clock),
        execution_key=f"{settings.provider_profile_key}:isolated-new-session",
        working_directory_mode="ISOLATED_EMPTY",
        filesystem_mode="NO_REPOSITORY_ACCESS",
        tool_mode="DISABLED",
        mcp_mode="DISABLED",
        hooks_mode="DISABLED",
        plugin_mode="DISABLED",
        instruction_sources="EXPLICIT_SASTSIMI_PAYLOAD_ONLY",
        environment_variable_allowlist=(
            "CODEX_HOME",
            "SYSTEMROOT",
            "WINDIR",
            "COMSPEC",
            "TEMP",
            "TMP",
        ),
        network_policy_ref=network_policy_ref,
        provider_fallback="DISABLED",
        verification_evidence_ref=validation_ref,
    )
    client_ref = reference(client)
    if not isinstance(client_ref, StoredDataRef):
        raise ValueError("LOCAL_CODEX_BINDING_SCOPE_MISMATCH")
    provider = ProviderProfile(
        meta=_meta(scope, ProviderProfile.KIND, ids=ids, clock=clock),
        profile_key=settings.provider_profile_key,
        provider="OPENAI",
        product="CODEX",
        transport="CODEX_CLIENT",
        model=settings.model,
        environment="PERSONAL_LOCAL",
        auth_mode="SUBSCRIPTION_LOGIN",
        client_name="codex-cli",
        client_version=settings.client_version,
        credential_source="OFFICIAL_CLIENT_SESSION",
        capabilities=ProviderCapabilities(
            non_interactive="UNVERIFIED",
            structured_output="UNVERIFIED",
            new_session="UNVERIFIED",
            resume_session="UNSUPPORTED",
            parallel_calls="UNVERIFIED",
            cancellation="UNVERIFIED",
            timeout_detection="UNVERIFIED",
            auth_expiry_detection="UNVERIFIED",
            rate_limit_detection="UNVERIFIED",
            request_id="UNSUPPORTED",
            token_usage="UNVERIFIED",
            session_metadata="UNVERIFIED",
            runtime_tool_loop="UNSUPPORTED",
        ),
        support_status="EXPERIMENTAL",
        validation_evidence_ref=validation_ref,
        client_execution_profile_ref=client_ref,
        limitations=(
            "LOCAL_EVALUATION_ONLY",
            "PRODUCTION_APPROVAL_NOT_GRANTED",
            "RESUME_SESSION_UNSUPPORTED",
        ),
        checked_at=clock.now(),
        evidence_urls=(),
    )
    binding = ApprovedCodexExecutionBinding(
        provider_profile=provider,
        client_execution_profile=client,
        executable=ApprovedCodexExecutable(
            path=executable,
            sha256=settings.executable_sha256,
        ),
        codex_home=codex_home,
        runtime_environment="PERSONAL_LOCAL",
        provider_validation_evidence=None,
    )
    return LocalCodexBindingRecords(validation, client, provider, binding)


__all__ = ["LocalCodexBindingRecords", "build_local_codex_binding"]
