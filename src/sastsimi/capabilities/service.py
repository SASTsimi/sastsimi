"""Application service for probing and explicitly approving host capabilities."""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
import time
from collections.abc import Callable, Mapping
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
    DockerBuildCapability,
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
from sastsimi.ports.dynamic_sandbox import TrustedDockerTarget
from sastsimi.runtime.configuration_registry import ConfigurationRegistry

from .docker_build_boundary import DockerBuildBoundaryProbeResult
from .models import CapabilityProbeReceipt, ProbeKind
from .probes import (
    CommandObservation,
    CommandProbeRunner,
    OpenAIProbeTransport,
    python_ast_observation,
    safe_repository_loader_control,
    sha256_file,
    verify_outer_boundary_controls,
)
from .store import _SQLiteCapabilityProbeStore

type ExecutableLocator = Callable[[str], Path | None]
type Clock = Callable[[], datetime]
type ApprovalIdentity = Callable[[], str]
type DockerBuildCapabilityProbe = Callable[
    [], DockerBuildBoundaryProbeResult | DockerBuildCapability | None
]
type CapabilityProfile = RuntimeCapabilityProfile | StaticToolProfile

_PUBLICATION_ANALYSIS = AnalysisId("capability-publication")
_PUBLICATION_WORKSPACE = WorkspaceId("host-configuration")
_PUBLICATION_COMMIT = CommitId("host-configuration-v1")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+| -]{0,127}$")
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_WINDOWS_DOCKER_HOST = "npipe:////./pipe/docker_engine"
_SYSTEM_DOCKER_HOSTS = frozenset(
    {"unix:///var/run/docker.sock", "unix:///run/docker.sock"}
)
_ROOTLESS_DOCKER_HOST = re.compile(r"^unix:///run/user/[1-9][0-9]*/docker\.sock$")


class SecretLookup(Protocol):
    def resolve(self, reference: SecretReference) -> str: ...


class _CapabilityProbeEngine:
    """Internal injectable engine used by production composition and tests."""

    def __init__(
        self,
        *,
        registry: ConfigurationRegistry,
        artifacts: ArtifactStore,
        store: _SQLiteCapabilityProbeStore,
        host_id: str,
        operating_system: CapabilityOperatingSystem,
        architecture: CapabilityArchitecture,
        clock: Clock,
        executable_locator: ExecutableLocator,
        command_runner: CommandProbeRunner,
        docker_host: str | None,
        approval_identity: ApprovalIdentity,
        secret_resolver: SecretLookup | None = None,
        openai_probe: OpenAIProbeTransport | None = None,
        scratch_root: Path,
        docker_build_capability_probe: DockerBuildCapabilityProbe,
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
        self._commands = command_runner
        self._docker_host = self._validated_docker_host(docker_host)
        self._approval_identity = approval_identity
        self._secret_resolver = secret_resolver
        self._openai = openai_probe
        self._scratch_root = scratch_root
        self._docker_build_capability_probe = docker_build_capability_probe

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
        execution_target_hash: str | None = None
        docker_build_capability: DockerBuildCapability | None = None
        boundary_result: DockerBuildBoundaryProbeResult | None = None
        docker_build_boundary_code: str | None = None
        docker_build_storage_identity_hash: str | None = None
        summary = "Capability probe could not be completed"

        if kind == "PYTHON_AST":
            python_executable = self._locate("python")
            observed = (
                python_ast_observation(python_executable)
                if python_executable is not None
                else None
            )
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
                try:
                    before_digest = sha256_file(executable)
                except (OSError, ValueError):
                    before_digest = None
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
                    command_observation = (
                        self._run_docker(executable, arguments, timeout_ms=15_000)
                        if kind == "DOCKER"
                        else self._commands.run(
                            executable, arguments, timeout_ms=15_000
                        )
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
                    and before_digest == observed_digest
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
                        if kind == "GIT":
                            control_passed = safe_repository_loader_control(
                                self._scratch_root
                            ) and self._probe_git_operations(executable)
                        elif kind == "OPENGREP":
                            control_passed = self._probe_opengrep_analyze(executable)
                        elif kind == "DOCKER":
                            self._scratch_root.mkdir(parents=True, exist_ok=True)
                            execution_target_hash = self._docker_target_hash(executable)
                            boundary_result = self._docker_build_boundary_result()
                            docker_build_boundary_code = boundary_result.code
                            docker_build_storage_identity_hash = (
                                boundary_result.storage_identity_hash
                            )
                            docker_build_capability = boundary_result.capability
                            control_passed = (
                                execution_target_hash is not None
                                and docker_build_capability is not None
                                and verify_outer_boundary_controls(self._scratch_root)
                                and self._probe_docker_operations(
                                    executable,
                                    probe_id,
                                    docker_build_capability,
                                )
                                and self._docker_target_hash(executable)
                                == execution_target_hash
                            )
                        else:
                            control_passed = False
                        digest_unchanged = sha256_file(executable) == observed_digest
                    except (OSError, ValueError, subprocess.SubprocessError):
                        control_passed = False
                        digest_unchanged = False
                    if kind == "GIT" and control_passed and digest_unchanged:
                        status, activation_supported = "PASSED", True
                        controls = ("SAFE_REPOSITORY_LOADER",)
                        summary = "Git binary and safe loader control probe passed"
                    elif kind == "DOCKER" and control_passed and digest_unchanged:
                        status, activation_supported = "PASSED", True
                        controls = ("SANDBOX_OUTER_BOUNDARY",)
                        summary = "Docker CLI, daemon, and outer boundary probe passed"
                    elif kind == "OPENGREP" and control_passed and digest_unchanged:
                        status, activation_supported = "PASSED", True
                        summary = "OpenGrep binary probe passed"
                    elif kind == "CODEQL":
                        summary = "CodeQL quota control probe is unavailable"
                    elif kind == "DOCKER" and docker_build_capability is None:
                        summary = (
                            boundary_result.safe_summary
                            if boundary_result is not None
                            else "Docker build resource boundary probe is unavailable"
                        )
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

        if not activation_supported:
            execution_target_hash = None
            docker_build_capability = None

        evidence = {
            "schema_version": "1.0.0",
            "probe_id": probe_id,
            "host_id": self._host_id,
            "kind": kind,
            "status": status,
            "observed_version": version,
            "observed_sha256": digest,
            "execution_target_hash": execution_target_hash,
            "docker_build_capability": docker_build_capability,
            "docker_build_boundary_code": docker_build_boundary_code,
            "docker_build_storage_identity_hash": (docker_build_storage_identity_hash),
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
                    execution_target_hash=execution_target_hash,
                    docker_build_capability=docker_build_capability,
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
                "execution_target_hash": execution_target_hash,
                "docker_build_capability": docker_build_capability,
                "docker_build_boundary_code": docker_build_boundary_code,
                "docker_build_storage_identity_hash": (
                    docker_build_storage_identity_hash
                ),
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
                self._locate("python")
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
        if (
            isinstance(profile, RuntimeCapabilityProfile)
            and profile.capability_kind == "DOCKER"
            and self._docker_target_hash(resolved) != profile.execution_target_hash
        ):
            raise ValueError("CAPABILITY_EXECUTION_TARGET_CHANGED")
        return resolved

    def resolve_docker_command(
        self, profile_ref: HostConfigurationRef
    ) -> tuple[Path, str]:
        """Return an exact executable and daemon only after current-state checks."""

        profile = self._registry.resolve_pinned_active_profile(profile_ref)
        if (
            not isinstance(profile, RuntimeCapabilityProfile)
            or profile.capability_kind != "DOCKER"
        ):
            raise ValueError("CAPABILITY_DOCKER_PROFILE_REQUIRED")
        if self._docker_host is None:
            raise ValueError("DOCKER_HOST_REQUIRED")
        return self.resolve_executable(profile_ref), self._docker_host

    def resolve_current(self, profile_ref: HostConfigurationRef) -> TrustedDockerTarget:
        """Convert one exact ACTIVE Docker profile into T11's trusted target."""

        profile = self._registry.resolve_pinned_active_profile(profile_ref)
        if (
            not isinstance(profile, RuntimeCapabilityProfile)
            or profile.capability_kind != "DOCKER"
            or profile.docker_build_capability is None
        ):
            raise ValueError("CAPABILITY_DOCKER_PROFILE_REQUIRED")
        executable, daemon_target = self.resolve_docker_command(profile_ref)
        boundary = profile.docker_build_capability
        current_boundary = self._docker_build_boundary_result()
        if current_boundary.capability != boundary:
            raise ValueError("CAPABILITY_DOCKER_BOUNDARY_CHANGED")
        return TrustedDockerTarget(
            profile_ref=profile_ref,
            executable=executable,
            subject_key=profile.subject_key,
            subject_sha256=profile.subject_sha256,
            daemon_target=daemon_target,
            build_backend=boundary.build_backend,
            enforced_build_limits=frozenset(boundary.enforced_build_limits),
            external_build_disk_limit_bytes=boundary.external_build_disk_limit_bytes,
            external_build_storage_identity_hash=(
                boundary.external_build_storage_identity_hash
            ),
        )

    def require_current(self, target: TrustedDockerTarget) -> None:
        """Revalidate every pinned field immediately before a Docker command."""

        if self.resolve_current(target.profile_ref) != target:
            raise ValueError("CAPABILITY_DOCKER_TARGET_CHANGED")

    def approve(
        self,
        probe_id: str,
        *,
        expected_target_hash: str,
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
        approved_by = self._approval_identity()
        if _SAFE_IDENTIFIER.fullmatch(approved_by) is None:
            raise ValueError("APPROVER_REQUIRED")
        assert receipt.profile_key is not None
        assert receipt.subject_key is not None
        assert receipt.observed_version is not None
        assert receipt.observed_sha256 is not None
        executable = self._locate(receipt.subject_key)
        if executable is None:
            raise ValueError("CAPABILITY_EXECUTABLE_UNAVAILABLE")
        try:
            if executable.is_symlink():
                raise ValueError
            resolved = executable.resolve(strict=True)
            if sha256_file(resolved) != receipt.observed_sha256:
                raise ValueError
        except (OSError, ValueError) as error:
            raise ValueError("CAPABILITY_EXECUTABLE_CHANGED") from error
        if receipt.kind == "DOCKER" and (
            receipt.execution_target_hash is None
            or self._docker_target_hash(resolved) != receipt.execution_target_hash
        ):
            raise ValueError("CAPABILITY_EXECUTION_TARGET_CHANGED")
        profile_draft = self._profile(
            receipt.kind,
            profile_key=receipt.profile_key,
            subject_key=receipt.subject_key,
            version=receipt.observed_version,
            digest=receipt.observed_sha256,
            execution_target_hash=receipt.execution_target_hash,
            docker_build_capability=receipt.docker_build_capability,
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
                    "execution_target_hash": receipt.execution_target_hash,
                    "docker_build_capability": receipt.docker_build_capability,
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
        approval_ref = self._registry.register_capability_approval(approval)
        profile = self._profile(
            receipt.kind,
            profile_key=receipt.profile_key,
            subject_key=receipt.subject_key,
            version=receipt.observed_version,
            digest=receipt.observed_sha256,
            execution_target_hash=receipt.execution_target_hash,
            docker_build_capability=receipt.docker_build_capability,
            evidence_ref=approval_ref,
            record_id=RecordId("profile-" + receipt.probe_id),
            created_at=approval.approved_at,
        )
        profile_ref = self._profile_ref(profile)
        if isinstance(profile, StaticToolProfile):
            actual_ref = self._registry.register_production_static_tool_profile(profile)
        else:
            actual_ref = self._registry.register_runtime_capability(profile)
        if actual_ref != profile_ref:
            raise ValueError("CAPABILITY_PUBLICATION_REF_MISMATCH")
        self._store.publish(probe_id, profile_ref)
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

    def _meta(
        self,
        kind: str,
        *,
        logical: str,
        record_id: RecordId | None = None,
        created_at: datetime | None = None,
    ) -> RecordMeta:
        return RecordMeta(
            record_id=record_id or RecordId(str(uuid4())),
            logical_record_id=LogicalRecordId(logical),
            record_type=kind,
            schema_version="1.0.0",
            revision_number=1,
            previous_record_id=None,
            created_at=created_at or self._clock(),
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
        execution_target_hash: str | None = None,
        docker_build_capability: DockerBuildCapability | None = None,
        record_id: RecordId | None = None,
        created_at: datetime | None = None,
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
                    "meta": self._meta(
                        "static_tool_profile",
                        logical=logical,
                        record_id=record_id,
                        created_at=created_at,
                    ),
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
                "meta": self._meta(
                    "runtime_capability_profile",
                    logical=logical,
                    record_id=record_id,
                    created_at=created_at,
                ),
                "host_id": self._host_id,
                "profile_key": profile_key,
                "purpose": "PRODUCTION",
                "status": "ACTIVE",
                "capability_kind": kind,
                "subject_key": subject_key,
                "expected_version": version,
                "subject_sha256": digest,
                "execution_target_hash": execution_target_hash,
                "docker_build_capability": docker_build_capability,
                "operating_system": self._operating_system,
                "architecture": self._architecture,
                "languages": languages,
                "operations": operations,
                "capability_evidence_ref": evidence_ref,
            }
        )

    def _probe_git_operations(self, executable: Path) -> bool:
        self._scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=self._scratch_root) as temporary:
            root = Path(temporary)
            source = root / "source"
            clone = root / "clone"
            source.mkdir()
            (source / "checked.txt").write_text("capability-probe\n", encoding="utf-8")
            commands = (
                ("-C", str(source), "init"),
                ("-C", str(source), "add", "checked.txt"),
                (
                    "-C",
                    str(source),
                    "-c",
                    "commit.gpgsign=false",
                    "-c",
                    "user.name=SASTSIMI Probe",
                    "-c",
                    "user.email=probe@localhost.invalid",
                    "commit",
                    "--quiet",
                    "-m",
                    "probe",
                ),
                ("clone", "--no-hardlinks", "--", str(source), str(clone)),
                ("-C", str(clone), "checkout", "--detach", "HEAD"),
                ("-C", str(clone), "rev-parse", "HEAD"),
            )
            observations = tuple(
                self._commands.run(executable, command, timeout_ms=15_000)
                for command in commands
            )
            head = observations[-1].safe_stdout
            return all(item.succeeded for item in observations) and bool(
                head and re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", head)
            )

    def _probe_opengrep_analyze(self, executable: Path) -> bool:
        self._scratch_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=self._scratch_root) as temporary:
            root = Path(temporary)
            python_source = root / "probe.py"
            javascript_source = root / "probe.js"
            rule = root / "probe.yml"
            python_source.write_text("print('sastsimi-probe')\n", encoding="utf-8")
            javascript_source.write_text(
                "console.log('sastsimi-probe');\n", encoding="utf-8"
            )
            rule.write_text(
                "rules:\n"
                "  - id: sastsimi.probe.python\n"
                "    languages: [python]\n"
                "    severity: INFO\n"
                "    message: capability probe\n"
                "    pattern: print(...)\n"
                "  - id: sastsimi.probe.javascript\n"
                "    languages: [javascript]\n"
                "    severity: INFO\n"
                "    message: capability probe\n"
                "    pattern: console.log(...)\n",
                encoding="utf-8",
            )
            observed = self._commands.run(
                executable,
                (
                    "scan",
                    "--config",
                    str(rule),
                    "--json",
                    "--disable-version-check",
                    str(python_source),
                    str(javascript_source),
                ),
                timeout_ms=30_000,
            )
            if not observed.succeeded or observed.safe_stdout is None:
                return False
            try:
                parsed = json.loads(observed.safe_stdout)
                observed_check_ids = {
                    item.get("check_id")
                    for item in parsed.get("results", [])
                    if isinstance(item, dict)
                }
                return {
                    "sastsimi.probe.python",
                    "sastsimi.probe.javascript",
                } <= observed_check_ids
            except (AttributeError, TypeError, ValueError):
                return False

    @staticmethod
    def _validated_docker_host(docker_host: str | None) -> str | None:
        if docker_host is None:
            return None
        if docker_host == _WINDOWS_DOCKER_HOST:
            return docker_host
        if docker_host in _SYSTEM_DOCKER_HOSTS:
            return docker_host
        if _ROOTLESS_DOCKER_HOST.fullmatch(docker_host) is not None:
            return docker_host
        raise ValueError("DOCKER_HOST_UNTRUSTED")

    def _run_docker(
        self,
        executable: Path,
        arguments: tuple[str, ...],
        *,
        timeout_ms: int,
        environment_overrides: Mapping[str, str] | None = None,
    ) -> CommandObservation:
        if self._docker_host is None:
            raise ValueError("DOCKER_HOST_REQUIRED")
        return self._commands.run(
            executable,
            ("--host", self._docker_host, *arguments),
            timeout_ms=timeout_ms,
            environment_overrides=environment_overrides,
        )

    def _docker_build_boundary_result(self) -> DockerBuildBoundaryProbeResult:
        result = self._docker_build_capability_probe()
        if isinstance(result, DockerBuildBoundaryProbeResult):
            return result
        if isinstance(result, DockerBuildCapability):
            return DockerBuildBoundaryProbeResult(
                code="DOCKER_BUILD_BOUNDARY_PRECHECK_PASSED",
                capability=result,
                storage_identity_hash=(result.external_build_storage_identity_hash),
            )
        return DockerBuildBoundaryProbeResult(
            code="DOCKER_BUILD_DISK_BOUNDARY_UNPROVEN"
        )

    def _docker_target_hash(self, executable: Path) -> str | None:
        version = self._run_docker(
            executable,
            ("version", "--format", "{{.Client.Version}}|{{.Server.Version}}"),
            timeout_ms=15_000,
        )
        daemon = self._run_docker(
            executable,
            ("info", "--format", "{{.ID}}|{{.OSType}}|{{.Architecture}}"),
            timeout_ms=15_000,
        )
        if not version.succeeded or not daemon.succeeded or not daemon.safe_stdout:
            return None
        target = (
            (self._docker_host or "")
            + "|"
            + daemon.safe_stdout
            + "|"
            + (version.safe_stdout or "")
        )
        if any(ord(character) < 32 for character in target) or len(target) > 768:
            return None
        return content_hash({"docker_execution_target": target})

    def _probe_docker_operations(
        self,
        executable: Path,
        probe_id: str,
        boundary: DockerBuildCapability,
    ) -> bool:
        if (
            boundary.build_backend != "LEGACY_LIMITED"
            or boundary.enforced_build_limits != ("CPU", "MEMORY", "PID", "DISK")
        ):
            return False
        self._scratch_root.mkdir(parents=True, exist_ok=True)
        tag = "sastsimi-capability-" + probe_id.removeprefix("probe-")
        container = tag + "-run"
        built = False
        started = False
        operation_passed = False
        cleanup_passed = True
        with tempfile.TemporaryDirectory(dir=self._scratch_root) as temporary:
            root = Path(temporary)
            base = self._run_docker(
                executable,
                ("image", "inspect", "--format", "{{.Id}}", "busybox:latest"),
                timeout_ms=15_000,
            )
            if (
                not base.succeeded
                or base.safe_stdout is None
                or re.fullmatch(r"sha256:[0-9a-f]{64}", base.safe_stdout) is None
            ):
                return False
            base_image_id = base.safe_stdout
            (root / "Dockerfile").write_text(
                f"FROM {base_image_id}\n"
                "USER 65532:65532\n"
                "RUN set -eu; "
                "if [ -f /sys/fs/cgroup/memory.max ]; then "
                '[ "$(cat /sys/fs/cgroup/memory.max)" = "67108864" ]; '
                "else "
                '[ "$(cat /sys/fs/cgroup/memory/memory.limit_in_bytes)" '
                '= "67108864" ]; fi; '
                "if [ -f /sys/fs/cgroup/cpu.max ]; then "
                '[ "$(cat /sys/fs/cgroup/cpu.max)" = "50000 100000" ]; '
                "else "
                '[ "$(cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us)" = "50000" ]; '
                '[ "$(cat /sys/fs/cgroup/cpu/cpu.cfs_period_us)" = "100000" ]; '
                "fi; "
                '[ "$(ulimit -u)" = "64" ]\n'
                'HEALTHCHECK --interval=1s --timeout=1s --retries=3 CMD ["true"]\n'
                'CMD ["sleep", "30"]\n',
                encoding="utf-8",
            )
            try:
                build = self._run_docker(
                    executable,
                    (
                        "image",
                        "build",
                        "--quiet",
                        "--pull=false",
                        "--no-cache",
                        "--network",
                        "none",
                        "--cpu-period",
                        "100000",
                        "--cpu-quota",
                        "50000",
                        "--memory",
                        "67108864",
                        "--ulimit",
                        "nproc=64:64",
                        "--tag",
                        tag,
                        str(root),
                    ),
                    timeout_ms=60_000,
                    environment_overrides={"DOCKER_BUILDKIT": "0"},
                )
                built = build.succeeded
                if built:
                    run = self._run_docker(
                        executable,
                        (
                            "run",
                            "--detach",
                            "--name",
                            container,
                            "--user",
                            "65532:65532",
                            "--network",
                            "none",
                            "--read-only",
                            "--cap-drop",
                            "ALL",
                            "--security-opt",
                            "no-new-privileges",
                            "--pids-limit",
                            "64",
                            "--cpus",
                            "0.5",
                            "--memory",
                            "67108864",
                            "--tmpfs",
                            "/tmp:rw,noexec,nosuid,nodev,size=16m",
                            tag,
                        ),
                        timeout_ms=30_000,
                    )
                    started = run.succeeded
                if started:
                    for _ in range(6):
                        inspected = self._run_docker(
                            executable,
                            ("inspect", container),
                            timeout_ms=15_000,
                        )
                        if not inspected.succeeded or inspected.safe_stdout is None:
                            break
                        state = self._docker_inspect(inspected.safe_stdout)
                        if state is not None and self._docker_boundary_passed(state):
                            operation_passed = True
                            break
                        if state is None or not self._docker_health_starting(state):
                            break
                        time.sleep(0.5)
            finally:
                if started:
                    removed = self._run_docker(
                        executable,
                        ("rm", "--force", "--volumes", container),
                        timeout_ms=15_000,
                    )
                    cleanup_passed = cleanup_passed and removed.succeeded
                if built:
                    removed_image = self._run_docker(
                        executable,
                        ("image", "rm", "--force", tag),
                        timeout_ms=15_000,
                    )
                    cleanup_passed = cleanup_passed and removed_image.succeeded
        return operation_passed and cleanup_passed

    @staticmethod
    def _docker_inspect(payload: str) -> dict[str, object] | None:
        try:
            parsed = json.loads(payload)
        except (TypeError, ValueError):
            return None
        if not isinstance(parsed, list) or len(parsed) != 1:
            return None
        state = parsed[0]
        return state if isinstance(state, dict) else None

    @staticmethod
    def _docker_health_starting(state: dict[str, object]) -> bool:
        runtime_state = state.get("State")
        if not isinstance(runtime_state, dict):
            return False
        health = runtime_state.get("Health")
        return isinstance(health, dict) and health.get("Status") == "starting"

    @staticmethod
    def _docker_boundary_passed(state: dict[str, object]) -> bool:
        configuration = state.get("Config")
        host = state.get("HostConfig")
        runtime_state = state.get("State")
        mounts = state.get("Mounts")
        if not all(
            isinstance(item, dict) for item in (configuration, host, runtime_state)
        ):
            return False
        assert isinstance(configuration, dict)
        assert isinstance(host, dict)
        assert isinstance(runtime_state, dict)
        health = runtime_state.get("Health")
        cap_drop = host.get("CapDrop")
        security_options = host.get("SecurityOpt")
        tmpfs = host.get("Tmpfs")
        tmp_options = (
            frozenset(str(tmpfs["/tmp"]).split(","))
            if isinstance(tmpfs, dict) and set(tmpfs) == {"/tmp"}
            else frozenset()
        )
        safe_mounts = (
            isinstance(mounts, list)
            and len(mounts) == 1
            and isinstance(mounts[0], dict)
            and mounts[0].get("Type") == "tmpfs"
            and mounts[0].get("Destination") == "/tmp"
        )
        return bool(
            configuration.get("User") == "65532:65532"
            and host.get("NetworkMode") == "none"
            and host.get("ReadonlyRootfs") is True
            and host.get("Privileged") is False
            and isinstance(cap_drop, list)
            and "ALL" in cap_drop
            and isinstance(security_options, list)
            and any(
                str(option).startswith("no-new-privileges")
                for option in security_options
            )
            and host.get("PidsLimit") == 64
            and host.get("Memory") == 67_108_864
            and host.get("NanoCpus") == 500_000_000
            and host.get("Binds") in (None, [])
            and host.get("PidMode") in (None, "")
            and host.get("IpcMode") in (None, "", "private")
            and tmp_options
            == frozenset({"rw", "noexec", "nosuid", "nodev", "size=16m"})
            and safe_mounts
            and isinstance(health, dict)
            and health.get("Status") == "healthy"
        )


def hashlib_key(value: str) -> str:
    import hashlib

    return hashlib.sha256(value.encode()).hexdigest()[:24]


__all__: list[str] = []
