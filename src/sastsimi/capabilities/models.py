"""Safe internal receipts for production host capability probes."""

from typing import Literal, Self

from pydantic import AwareDatetime, model_validator

from sastsimi.contracts.base import ContractModel, NonEmptyStr, Sha256
from sastsimi.contracts.capabilities import DockerBuildCapability
from sastsimi.contracts.domain import SafeDiagnostic
from sastsimi.contracts.refs import HostConfigurationRef, StoredDataRef

type ProbeKind = Literal[
    "GIT", "PYTHON_AST", "OPENGREP", "DOCKER", "OPENAI_API", "CODEQL"
]


class CapabilityProbeReceipt(ContractModel):
    """Sanitized, immutable result created only by the probe service."""

    probe_id: NonEmptyStr
    host_id: NonEmptyStr
    kind: ProbeKind
    status: Literal["PASSED", "BLOCKED", "FAILED"]
    profile_key: NonEmptyStr | None
    subject_key: NonEmptyStr | None
    observed_version: NonEmptyStr | None
    observed_sha256: Sha256 | None
    execution_target_hash: Sha256 | None = None
    docker_build_capability: DockerBuildCapability | None = None
    operating_system: Literal["windows", "linux", "macos"]
    architecture: Literal["x86_64", "aarch64"]
    checked_at: AwareDatetime
    evidence_ref: StoredDataRef
    approval_target_hash: Sha256 | None
    activation_supported: bool
    safe_summary: SafeDiagnostic
    approved_profile_ref: HostConfigurationRef | None = None

    @model_validator(mode="after")
    def closed_state(self) -> Self:
        complete = all(
            value is not None
            for value in (
                self.profile_key,
                self.subject_key,
                self.observed_version,
                self.observed_sha256,
            )
        )
        if self.activation_supported and (
            self.status != "PASSED" or not complete or self.approval_target_hash is None
        ):
            raise ValueError("PROBE_ACTIVATION_TARGET_INCOMPLETE")
        if self.approved_profile_ref is not None and not self.activation_supported:
            raise ValueError("PROBE_APPROVAL_INVALID")
        if self.kind == "DOCKER" and self.activation_supported:
            if (
                self.execution_target_hash is None
                or self.docker_build_capability is None
            ):
                raise ValueError("PROBE_DOCKER_BOUNDARY_REQUIRED")
        elif (
            self.execution_target_hash is not None
            or self.docker_build_capability is not None
        ):
            raise ValueError("PROBE_DOCKER_BOUNDARY_FORBIDDEN")
        return self


__all__ = ["CapabilityProbeReceipt", "ProbeKind"]
