"""Application service for probing and explicitly approving host capabilities."""

from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Protocol, cast
from uuid import uuid4

from sastsimi.config.secrets import SecretReference
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.capabilities import (
    CapabilityApprovalEvidence,
    CapabilityArchitecture,
    CapabilityControlEvidence,
    CapabilityLanguage,
    CapabilityOperatingSystem,
    CapabilityOperation,
    RuntimeCapabilityProfile,
    capability_target_hash,
)
from sastsimi.contracts.ids import (
    AnalysisId,
    CommitId,
    LogicalRecordId,
    RecordId,
    StoredDataId,
    WorkspaceId,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import HostConfigurationRef, StoredDataRef
from sastsimi.contracts.static import StaticToolProfile
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.runtime.configuration_registry import ConfigurationRegistry

from .models import CapabilityProbeReceipt, ProbeKind
from .probes import (
    CommandProbeRunner,
    OpenAIProbeTransport,
    SubprocessCommandProbeRunner,
    locate_executable,
    python_ast_observation,
    safe_repository_loader_control,
    sha256_file,
    verify_outer_boundary_controls,
)
from .store import SQLiteCapabilityProbeStore

type ExecutableLocator = Callable[[str], Path | None]
type Clock = Callable[[], datetime]
type CapabilityProfile = RuntimeCapabilityProfile | StaticToolProfile

_PUBLICATION_ANALYSIS = AnalysisId("capability-publication")
_PUBLICATION_WORKSPACE = WorkspaceId("host-configuration")
_PUBLICATION_COMMIT = CommitId("host-configuration-v1")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+| -]{0,127}$")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class SecretLookup(Protocol):
    def resolve(self, reference: SecretReference) -> str: ...


class CapabilityProbeService:
    """Only this service converts actual observations into trusted profiles."""

    def __init__(
        self,
        *,
        registry: ConfigurationRegistry,
        artifacts: ArtifactStore,
        store: SQLiteCapabilityProbeStore,
        host_id: str,
        operating_system: CapabilityOperatingSystem,
        architecture: CapabilityArchitecture,
        clock: Clock,
        executable_locator: ExecutableLocator = locate_executable,
        command_runner: CommandProbeRunner | None = None,
        secret_resolver: SecretLookup | None = None,
        openai_probe: OpenAIProbeTransport | None = None,
        scratch_root: Path | None = None,
    ) -> None:
        if store.host_id != host_id or _SAFE_IDENTIFIER.fullmatch(host_id) is None:
            raise ValueError("PROBE_HOST_MISMATCH")
        self._registry = registry
        self._artifacts = artifacts
        self._store = store
        self._host_id = host_id
        self._operating_system = operating_system
        self._architecture = architecture
        self._clock = clock
        self._locate = executable_locator
        self._commands = command_runner or SubprocessCommandProbeRunner()
        self._secret_resolver = secret_resolver
        self._openai = openai_probe
        self._scratch_root = scratch_root or Path(tempfile.gettempdir())

    def probe(
        self,
        kind: ProbeKind,
        *,
        model: str | None = None,
        credential_ref: SecretReference | None = None,
    ) -> CapabilityProbeReceipt:
        """Run one actual probe; callers cannot supply its outcome or evidence."""

        probe_id = "probe-" + str(uuid4())
        checked_at = self._clock()
        profile_key: str | None = None
        subject_key: str | None = None
        version: str | None = None
        digest: str | None = None
        status: str = "BLOCKED"
        activation_supported = False
        controls: tuple[str, ...] = ()
        summary = "Capability probe could not be completed"

        if kind == "PYTHON_AST":
            observed = python_ast_observation()
            if observed is not None:
                version, digest = observed
                profile_key, subject_key = "python-ast", "python"
                status, activation_supported = "PASSED", True
                summary = "Python AST parse probe passed"
        elif kind in {"GIT", "OPENGREP", "DOCKER", "CODEQL"}:
            name = {
                "GIT": "git",
                "OPENGREP": "opengrep",
                "DOCKER": "docker",
                "CODEQL": "codeql",
            }[kind]
            executable = self._locate(name)
            if executable is None:
                summary = f"{kind} executable is unavailable"
            else:
                arguments = {
                    "GIT": ("--version",),
                    "OPENGREP": ("--version",),
                    "DOCKER": (
                        "version",
                        "--format",
                        "{{.Client.Version}}|{{.Server.Version}}",
                    ),
                    "CODEQL": ("version", "--format=terse"),
                }[kind]
                try:
                    command_observation = self._commands.run(
                        executable, arguments, timeout_ms=15_000
                    )
                    normalized = self._safe_version(command_observation.safe_stdout)
                    observed_digest = (
                        sha256_file(executable)
                        if command_observation.succeeded and normalized is not None
                        else None
                    )
                except (OSError, subprocess.SubprocessError, TimeoutError, ValueError):
                    command_observation = None
                    normalized = None
                    observed_digest = None
                if (
                    command_observation is not None
                    and command_observation.succeeded
                    and normalized is not None
                    and observed_digest is not None
                ):
                    version = normalized.removeprefix("git version ")
                    digest = observed_digest
                    profile_key = {
                        "GIT": "git",
                        "OPENGREP": "opengrep",
                        "DOCKER": "docker",
                        "CODEQL": "codeql",
                    }[kind]
                    subject_key = profile_key
                    try:
                        control_passed = (
                            safe_repository_loader_control(self._scratch_root)
                            if kind == "GIT"
                            else kind == "DOCKER"
                            and verify_outer_boundary_controls(self._scratch_root)
                        )
                    except (OSError, ValueError):
                        control_passed = False
                    if kind == "GIT" and control_passed:
                        status, activation_supported = "PASSED", True
                        controls = ("SAFE_REPOSITORY_LOADER",)
                        summary = "Git binary and safe loader control probe passed"
                    elif kind == "DOCKER" and control_passed:
                        status, activation_supported = "PASSED", True
                        controls = ("SANDBOX_OUTER_BOUNDARY",)
                        summary = "Docker CLI, daemon, and outer boundary probe passed"
                    elif kind == "OPENGREP":
                        status, activation_supported = "PASSED", True
                        summary = "OpenGrep binary probe passed"
                    elif kind == "CODEQL":
                        summary = "CodeQL quota control probe is unavailable"
                    else:
                        summary = f"{kind} required control probe failed"
                elif kind == "DOCKER":
                    summary = "Docker CLI or daemon probe failed"
                else:
                    summary = f"{kind} version probe failed"
        elif kind == "OPENAI_API":
            if (
                model is None
                or not model.strip()
                or credential_ref is None
                or self._secret_resolver is None
                or self._openai is None
            ):
                summary = "OpenAI probe configuration is incomplete"
            else:
                try:
                    secret = self._secret_resolver.resolve(credential_ref)
                    passed = bool(secret) and self._openai.probe(
                        model=model, secret=secret
                    )
                except Exception:
                    passed = False
                finally:
                    if "secret" in locals():
                        del secret
                if passed:
                    status = "PASSED"
                    summary = "OpenAI authentication and structured output probe passed"
                else:
                    summary = "OpenAI authentication or structured output probe failed"

        evidence = {
            "schema_version": "1.0.0",
            "probe_id": probe_id,
            "host_id": self._host_id,
            "kind": kind,
            "status": status,
            "observed_version": version,
            "observed_sha256": digest,
            "operating_system": self._operating_system,
            "architecture": self._architecture,
            "checks": tuple(controls),
            "safe_summary": summary,
        }
        staged = self._artifacts.stage_bytes(
            canonical_bytes(evidence), "application/json"
        )
        evidence_ref = self._artifacts.commit(staged)
        target_hash: str | None = None
        if activation_supported:
            target_hash = capability_target_hash(
                self._profile(
                    kind,
                    profile_key=cast(str, profile_key),
                    subject_key=cast(str, subject_key),
                    version=cast(str, version),
                    digest=cast(str, digest),
                    evidence_ref=self._placeholder_evidence_ref(),
                )
            )
        receipt = CapabilityProbeReceipt.model_validate(
            {
                "probe_id": probe_id,
                "host_id": self._host_id,
                "kind": kind,
                "status": status,
                "profile_key": profile_key,
                "subject_key": subject_key,
                "observed_version": version,
                "observed_sha256": digest,
                "operating_system": self._operating_system,
                "architecture": self._architecture,
                "checked_at": checked_at,
                "evidence_ref": evidence_ref,
                "approval_target_hash": target_hash,
                "activation_supported": activation_supported,
                "safe_summary": summary,
            }
        )
        self._store.add(receipt)
        return receipt

    def list(self) -> tuple[CapabilityProbeReceipt, ...]:
        """List sanitized receipts for this exact host only."""

        return self._store.list()

    def resolve_executable(self, profile_ref: HostConfigurationRef) -> Path:
        """Resolve a pinned ACTIVE ref to the same current executable digest."""

        profile = self._registry.resolve_pinned_active_profile(profile_ref)
        if isinstance(profile, StaticToolProfile):
            key = profile.executable_key
            expected_digest = profile.executable_sha256
            executable = (
                Path(sys.executable)
                if profile.adapter_key == "PYTHON_AST"
                else self._locate(key)
            )
        elif profile.capability_kind in {"GIT", "DOCKER"}:
            key = profile.subject_key
            expected_digest = profile.subject_sha256
            executable = self._locate(key)
        else:
            raise ValueError("CAPABILITY_EXECUTABLE_ROUTE_UNSUPPORTED")
        if executable is None:
            raise ValueError("CAPABILITY_EXECUTABLE_UNAVAILABLE")
        try:
            if executable.is_symlink():
                raise ValueError
            resolved = executable.resolve(strict=True)
            if not resolved.is_file() or sha256_file(resolved) != expected_digest:
                raise ValueError
        except (OSError, ValueError) as error:
            raise ValueError("CAPABILITY_EXECUTABLE_CHANGED") from error
        return resolved

    def approve(
        self,
        probe_id: str,
        *,
        expected_target_hash: str,
        approved_by: str,
    ) -> HostConfigurationRef:
        """Publish ACTIVE only after a human confirms the exact probed target."""

        receipt = self._store.get(probe_id)
        if receipt.approved_profile_ref is not None:
            self._registry.resolve_pinned_active_profile(receipt.approved_profile_ref)
            return receipt.approved_profile_ref
        if receipt.status != "PASSED" or not receipt.activation_supported:
            raise ValueError("PROBE_NOT_ACTIVATABLE")
        if (
            receipt.approval_target_hash is None
            or expected_target_hash != receipt.approval_target_hash
        ):
            raise ValueError("APPROVAL_TARGET_MISMATCH")
        if _SAFE_IDENTIFIER.fullmatch(approved_by) is None:
            raise ValueError("APPROVER_REQUIRED")
        assert receipt.profile_key is not None
        assert receipt.subject_key is not None
        assert receipt.observed_version is not None
        assert receipt.observed_sha256 is not None
        profile_draft = self._profile(
            receipt.kind,
            profile_key=receipt.profile_key,
            subject_key=receipt.subject_key,
            version=receipt.observed_version,
            digest=receipt.observed_sha256,
            evidence_ref=self._placeholder_evidence_ref(),
        )
        languages, operations = self._route(receipt.kind)
        controls = self._controls(receipt.kind, receipt.evidence_ref)
        approval = self._store.pending_approval(probe_id)
        if approval is None:
            approval = CapabilityApprovalEvidence.model_validate(
                {
                    "meta": self._meta(
                        "tool_capability_evidence",
                        logical="approval-" + receipt.probe_id,
                    ),
                    "host_id": self._host_id,
                    "profile_key": receipt.profile_key,
                    "capability_kind": self._contract_kind(receipt.kind),
                    "subject_key": receipt.subject_key,
                    "observed_version": receipt.observed_version,
                    "observed_sha256": receipt.observed_sha256,
                    "operating_system": self._operating_system,
                    "architecture": self._architecture,
                    "languages": languages,
                    "operations": operations,
                    "probe_status": "PASSED",
                    "probe_evidence_refs": (receipt.evidence_ref,),
                    "security_control_evidence": controls,
                    "checked_at": receipt.checked_at,
                    "checked_by": "production-capability-probe",
                    "checked_by_role": "R8",
                    "decision": "ACTIVATE",
                    "approved_at": self._clock(),
                    "approved_by": approved_by,
                    "approved_by_role": "HUMAN",
                    "approval_target_hash": capability_target_hash(profile_draft),
                    "safe_summary": (
                        "Exact local capability probe approved by a human"
                    ),
                }
            )
            self._store.authorize(approval, probe_id)
        elif approval.approved_by != approved_by:
            raise ValueError("APPROVER_MISMATCH")
        approval_hash = content_hash(approval)
        approval_published = False
        try:
            approval_ref = self._registry.register_capability_approval(approval)
            approval_published = True
            profile = self._profile(
                receipt.kind,
                profile_key=receipt.profile_key,
                subject_key=receipt.subject_key,
                version=receipt.observed_version,
                digest=receipt.observed_sha256,
                evidence_ref=approval_ref,
            )
            profile_ref = self._profile_ref(profile)
            self._store.publish(probe_id, profile_ref)
            if isinstance(profile, StaticToolProfile):
                actual_ref = self._registry.register_production_static_tool_profile(
                    profile
                )
            else:
                actual_ref = self._registry.register_runtime_capability(profile)
            if actual_ref != profile_ref:
                raise ValueError("CAPABILITY_PUBLICATION_REF_MISMATCH")
        except Exception:
            self._store.unpublish(probe_id)
            if not approval_published:
                self._store.revoke(approval_hash)
            raise
        return profile_ref

    @staticmethod
    def _safe_version(value: str | None) -> str | None:
        if value is None or _VERSION.fullmatch(value) is None:
            return None
        return value

    @staticmethod
    def _contract_kind(kind: ProbeKind) -> str:
        return "AST" if kind == "PYTHON_AST" else kind

    @staticmethod
    def _route(
        kind: ProbeKind,
    ) -> tuple[tuple[CapabilityLanguage, ...], tuple[CapabilityOperation, ...]]:
        route = {
            "GIT": (("ANY",), ("CLONE", "CHECKOUT")),
            "PYTHON_AST": (("PYTHON",), ("PARSE",)),
            "OPENGREP": (("PYTHON", "JAVASCRIPT"), ("ANALYZE",)),
            "DOCKER": (
                ("ANY",),
                ("IMAGE_BUILD", "CONTAINER_RUN", "HEALTH_CHECK", "CLEANUP"),
            ),
            "CODEQL": (("PYTHON", "JAVASCRIPT"), ("ANALYZE",)),
            "OPENAI_API": (("ANY",), ("START",)),
        }[kind]
        return cast(
            tuple[tuple[CapabilityLanguage, ...], tuple[CapabilityOperation, ...]],
            route,
        )

    @staticmethod
    def _controls(
        kind: ProbeKind, evidence_ref: StoredDataRef
    ) -> tuple[CapabilityControlEvidence, ...]:
        control = {
            "GIT": "SAFE_REPOSITORY_LOADER",
            "DOCKER": "SANDBOX_OUTER_BOUNDARY",
        }.get(kind)
        if control is None:
            return ()
        return (
            CapabilityControlEvidence.model_validate(
                {"control": control, "evidence_ref": evidence_ref}
            ),
        )

    def _meta(self, kind: str, *, logical: str) -> RecordMeta:
        return RecordMeta(
            record_id=RecordId(str(uuid4())),
            logical_record_id=LogicalRecordId(logical),
            record_type=kind,
            schema_version="1.0.0",
            revision_number=1,
            previous_record_id=None,
            created_at=self._clock(),
            analysis_id=_PUBLICATION_ANALYSIS,
            workspace_id=_PUBLICATION_WORKSPACE,
            commit_id=_PUBLICATION_COMMIT,
            hypothesis_id=None,
            attempt_id=None,
        )

    def _placeholder_evidence_ref(self) -> HostConfigurationRef:
        return HostConfigurationRef(
            stored_data_id=StoredDataId("pending-capability-approval"),
            data_kind="tool_capability_evidence",
            content_hash="0" * 64,
            host_id=self._host_id,
            publication_analysis_id=_PUBLICATION_ANALYSIS,
            publication_workspace_id=_PUBLICATION_WORKSPACE,
            publication_commit_id=_PUBLICATION_COMMIT,
            record_id=RecordId("pending-capability-approval"),
        )

    @staticmethod
    def _profile_ref(profile: CapabilityProfile) -> HostConfigurationRef:
        from sastsimi.contracts.refs import reference

        ref = reference(profile)
        if not isinstance(ref, HostConfigurationRef):
            raise ValueError("CAPABILITY_SCOPE_MISMATCH")
        return ref

    def _profile(
        self,
        kind: ProbeKind,
        *,
        profile_key: str,
        subject_key: str,
        version: str,
        digest: str,
        evidence_ref: HostConfigurationRef,
    ) -> CapabilityProfile:
        logical = "profile-" + hashlib_key(
            self._host_id + "|" + kind + "|" + profile_key
        )
        if kind in {"PYTHON_AST", "OPENGREP", "CODEQL"}:
            adapter = {
                "PYTHON_AST": ("PYTHON_AST", "AST", "STRUCTURE"),
                "OPENGREP": ("OPENGREP", "OPENGREP", "RULE_BASED"),
                "CODEQL": ("CODEQL", "CODEQL", "RULE_BASED"),
            }[kind]
            return StaticToolProfile.model_validate(
                {
                    "meta": self._meta("static_tool_profile", logical=logical),
                    "host_id": self._host_id,
                    "profile_key": profile_key,
                    "purpose": "PRODUCTION",
                    "status": "ACTIVE",
                    "adapter_key": adapter[0],
                    "tool_name": adapter[1],
                    "tool_kind": adapter[2],
                    "executable_key": subject_key,
                    "executable_sha256": digest,
                    "expected_version": version,
                    "capability_evidence_ref": evidence_ref,
                    "probe_timeout_ms": 15_000,
                    "run_timeout_ms": 300_000,
                    "stdout_limit_bytes": 1_048_576,
                    "stderr_limit_bytes": 1_048_576,
                    "max_attempt_output_bytes": 8_388_608,
                    "max_output_file_bytes": 4_194_304,
                    "max_artifact_read_bytes": 8_388_608,
                }
            )
        languages, operations = self._route(kind)
        return RuntimeCapabilityProfile.model_validate(
            {
                "meta": self._meta("runtime_capability_profile", logical=logical),
                "host_id": self._host_id,
                "profile_key": profile_key,
                "purpose": "PRODUCTION",
                "status": "ACTIVE",
                "capability_kind": kind,
                "subject_key": subject_key,
                "expected_version": version,
                "subject_sha256": digest,
                "operating_system": self._operating_system,
                "architecture": self._architecture,
                "languages": languages,
                "operations": operations,
                "capability_evidence_ref": evidence_ref,
            }
        )


def hashlib_key(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode()).hexdigest()[:24]


__all__ = ["CapabilityProbeService"]
