"""Evidence-backed production capability selection contracts."""

from typing import Literal, Self

from pydantic import AwareDatetime, model_validator

from ._domain import DomainRecord, SafeDiagnostic, unique
from .base import ContractModel, NonEmptyStr, Sha256
from .canonical_json import content_hash
from .refs import StoredDataRef, require_record_ref
from .static import StaticToolProfile

type CapabilityKind = Literal[
    "GIT",
    "AST",
    "CODEQL",
    "OPENGREP",
    "DOCKER",
    "PYTHON_RUNTIME",
    "JAVASCRIPT_RUNTIME",
    "PACKAGE_MANAGER",
    "BUILD",
    "START",
]
type CapabilityLanguage = Literal["ANY", "PYTHON", "JAVASCRIPT"]
type CapabilityOperatingSystem = Literal["windows", "linux", "macos"]
type CapabilityArchitecture = Literal["x86_64", "aarch64"]
type CapabilityOperation = Literal[
    "CLONE",
    "CHECKOUT",
    "PARSE",
    "ANALYZE",
    "IMAGE_BUILD",
    "CONTAINER_RUN",
    "HEALTH_CHECK",
    "CLEANUP",
    "PACKAGE_INSTALL",
    "BUILD",
    "START",
]
type CapabilitySecurityControl = Literal[
    "SAFE_REPOSITORY_LOADER",
    "STATIC_WRITE_DENYING_QUOTA",
    "SANDBOX_OUTER_BOUNDARY",
]


class CapabilityControlEvidence(ContractModel):
    """Exact evidence that one required production boundary was exercised."""

    control: CapabilitySecurityControl
    evidence_ref: StoredDataRef

RUNTIME_CAPABILITY_ROUTES: dict[
    CapabilityKind, tuple[frozenset[CapabilityLanguage], frozenset[CapabilityOperation]]
] = {
    "GIT": (frozenset({"ANY"}), frozenset({"CLONE", "CHECKOUT"})),
    "DOCKER": (
        frozenset({"ANY"}),
        frozenset({"IMAGE_BUILD", "CONTAINER_RUN", "HEALTH_CHECK", "CLEANUP"}),
    ),
    "PYTHON_RUNTIME": (frozenset({"PYTHON"}), frozenset({"START"})),
    "JAVASCRIPT_RUNTIME": (frozenset({"JAVASCRIPT"}), frozenset({"START"})),
    "PACKAGE_MANAGER": (
        frozenset({"PYTHON", "JAVASCRIPT"}),
        frozenset({"PACKAGE_INSTALL"}),
    ),
    "BUILD": (frozenset({"PYTHON", "JAVASCRIPT"}), frozenset({"BUILD"})),
    "START": (frozenset({"PYTHON", "JAVASCRIPT"}), frozenset({"START"})),
}
STATIC_CAPABILITY_ROUTES: dict[
    CapabilityKind, tuple[frozenset[CapabilityLanguage], frozenset[CapabilityOperation]]
] = {
    "AST": (frozenset({"PYTHON"}), frozenset({"PARSE"})),
    "CODEQL": (
        frozenset({"PYTHON", "JAVASCRIPT"}),
        frozenset({"ANALYZE"}),
    ),
    "OPENGREP": (
        frozenset({"PYTHON", "JAVASCRIPT"}),
        frozenset({"ANALYZE"}),
    ),
}
REQUIRED_SECURITY_CONTROLS: dict[
    CapabilityKind, frozenset[CapabilitySecurityControl]
] = {
    "GIT": frozenset({"SAFE_REPOSITORY_LOADER"}),
    "CODEQL": frozenset({"STATIC_WRITE_DENYING_QUOTA"}),
    "DOCKER": frozenset({"SANDBOX_OUTER_BOUNDARY"}),
}


class CapabilityApprovalEvidence(DomainRecord):
    """Exact R8 probe plus human decision for one profile revision."""

    KIND = "tool_capability_evidence"
    HYPOTHESIS = False
    ATTEMPT = False
    profile_key: NonEmptyStr
    capability_kind: CapabilityKind
    subject_key: NonEmptyStr
    observed_version: NonEmptyStr
    observed_sha256: Sha256
    operating_system: CapabilityOperatingSystem
    architecture: CapabilityArchitecture
    languages: tuple[CapabilityLanguage, ...]
    operations: tuple[CapabilityOperation, ...]
    probe_status: Literal["PASSED", "BLOCKED", "FAILED"]
    probe_evidence_refs: tuple[StoredDataRef, ...]
    security_control_evidence: tuple[CapabilityControlEvidence, ...] = ()
    checked_at: AwareDatetime
    checked_by: NonEmptyStr
    checked_by_role: Literal["R8"]
    decision: Literal["ACTIVATE", "RETIRE", "REJECT"]
    approved_at: AwareDatetime
    approved_by: NonEmptyStr
    approved_by_role: Literal["HUMAN"]
    approval_target_hash: Sha256
    safe_summary: SafeDiagnostic

    @model_validator(mode="after")
    def complete_evidence(self) -> Self:
        if not self.languages or not self.operations or not self.probe_evidence_refs:
            raise ValueError("CAPABILITY_EVIDENCE_INCOMPLETE")
        unique(self.languages)
        unique(self.operations)
        unique(self.probe_evidence_refs)
        unique(item.control for item in self.security_control_evidence)
        unique(item.evidence_ref for item in self.security_control_evidence)
        route = RUNTIME_CAPABILITY_ROUTES.get(
            self.capability_kind
        ) or STATIC_CAPABILITY_ROUTES.get(self.capability_kind)
        if route is None or not set(self.operations) <= route[1]:
            raise ValueError("CAPABILITY_OPERATION_MISMATCH")
        if not set(self.languages) <= route[0]:
            raise ValueError("CAPABILITY_LANGUAGE_MISMATCH")
        if self.decision == "ACTIVATE" and self.probe_status != "PASSED":
            raise ValueError("CAPABILITY_ACTIVATION_PROBE_NOT_PASSED")
        controls = {item.control for item in self.security_control_evidence}
        if self.decision == "ACTIVATE" and not REQUIRED_SECURITY_CONTROLS.get(
            self.capability_kind, frozenset()
        ) <= controls:
            raise ValueError("CAPABILITY_SECURITY_CONTROL_EVIDENCE_REQUIRED")
        if self.approved_at < self.checked_at:
            raise ValueError("CAPABILITY_APPROVAL_PRECEDES_PROBE")
        return self


class RuntimeCapabilityProfile(DomainRecord):
    """One immutable executable host capability revision."""

    KIND = "runtime_capability_profile"
    HYPOTHESIS = False
    ATTEMPT = False
    profile_key: NonEmptyStr
    purpose: Literal["PRODUCTION"]
    status: Literal["ACTIVE", "RETIRED"]
    capability_kind: CapabilityKind
    subject_key: NonEmptyStr
    expected_version: NonEmptyStr
    subject_sha256: Sha256
    operating_system: CapabilityOperatingSystem
    architecture: CapabilityArchitecture
    languages: tuple[CapabilityLanguage, ...]
    operations: tuple[CapabilityOperation, ...]
    capability_evidence_ref: StoredDataRef

    @model_validator(mode="after")
    def closed_profile(self) -> Self:
        require_record_ref(self.capability_evidence_ref, "tool_capability_evidence")
        if not self.languages or not self.operations:
            raise ValueError("CAPABILITY_ROUTE_INCOMPLETE")
        unique(self.languages)
        unique(self.operations)
        route = RUNTIME_CAPABILITY_ROUTES.get(self.capability_kind)
        if route is None or not set(self.operations) <= route[1]:
            raise ValueError("CAPABILITY_OPERATION_MISMATCH")
        if not set(self.languages) <= route[0]:
            raise ValueError("CAPABILITY_LANGUAGE_MISMATCH")
        if self.status == "RETIRED" and self.meta.revision_number == 1:
            raise ValueError("CAPABILITY_RETIREMENT_REVISION_INVALID")
        return self


class RuntimeCapabilitySelection(ContractModel):
    """Trusted route result that pins the exact executable revision."""

    profile_ref: StoredDataRef
    profile: RuntimeCapabilityProfile


class StaticToolCapabilitySelection(ContractModel):
    """Trusted static-tool route result with its exact profile revision."""

    profile_ref: StoredDataRef
    profile: StaticToolProfile
    evidence: CapabilityApprovalEvidence


def capability_target_hash(
    profile: RuntimeCapabilityProfile | StaticToolProfile,
) -> str:
    """Hash semantic target fields without metadata or the approval reference."""

    value = profile.model_dump(mode="python")
    value.pop("meta")
    value.pop("capability_evidence_ref")
    return content_hash(value)
