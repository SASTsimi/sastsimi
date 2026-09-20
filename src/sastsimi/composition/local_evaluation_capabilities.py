"""Resolve the exact approved host capabilities for one local evaluation.

The local profile names routes; it does not contain mutable executable paths or
copy capability records into the analysis.  This module joins those names to
the durable capability-probe registry and revalidates every exact revision.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Protocol

from sastsimi.contracts.refs import HostConfigurationRef, StoredDataRef
from sastsimi.ports.trusted_evidence import TrustedEvidencePort

_KINDS = ("GIT", "PYTHON_RUNTIME", "PYTHON_AST", "OPENGREP", "CODEQL")


class _CapabilityKeys(Protocol):
    git_profile_key: str
    python_runtime_profile_key: str
    python_ast_profile_key: str
    opengrep_profile_key: str
    codeql_profile_key: str


class _LocalProfile(Protocol):
    host_id: str
    capabilities: _CapabilityKeys


class _Receipt(Protocol):
    probe_id: str
    host_id: str
    kind: str
    profile_key: str | None
    status: str
    approved_profile_ref: HostConfigurationRef | None


class LocalCapabilityService(Protocol):
    def list(self) -> tuple[_Receipt, ...]: ...

    def require_approved_current(
        self, probe_id: str, expected_ref: HostConfigurationRef
    ) -> HostConfigurationRef: ...

    def resolve_executable(self, profile_ref: HostConfigurationRef) -> Path: ...

    def trusted_evidence(self) -> TrustedEvidencePort: ...

    def evidence_refs(self) -> tuple[StoredDataRef, ...]: ...


type LocalCapabilityServiceFactory = Callable[[str | None], LocalCapabilityService]


@dataclass(frozen=True, slots=True)
class LocalEvaluationApprovedCapabilities:
    """Current exact refs and executables, with no inferred fallback route."""

    git_profile_ref: HostConfigurationRef
    python_runtime_profile_ref: HostConfigurationRef
    static_profile_refs: Mapping[str, HostConfigurationRef]
    executables: Mapping[str, Path]
    trusted_evidence: TrustedEvidencePort
    protected_artifact_refs: tuple[StoredDataRef, ...]

    @property
    def workspace_dependency_refs(
        self,
    ) -> tuple[HostConfigurationRef]:
        """Return only the Git capability consumed by repository preparation."""

        return (self.git_profile_ref,)


def resolve_local_approved_capabilities(
    profile: _LocalProfile,
    service_factory: LocalCapabilityServiceFactory,
) -> LocalEvaluationApprovedCapabilities:
    """Resolve all required routes or fail before any repository work starts."""

    expected = {
        "GIT": profile.capabilities.git_profile_key,
        "PYTHON_RUNTIME": profile.capabilities.python_runtime_profile_key,
        "PYTHON_AST": profile.capabilities.python_ast_profile_key,
        "OPENGREP": profile.capabilities.opengrep_profile_key,
        "CODEQL": profile.capabilities.codeql_profile_key,
    }
    lookup = service_factory(None)
    receipts = lookup.list()
    resolved: dict[str, HostConfigurationRef] = {}
    executables: dict[str, Path] = {}
    for kind in _KINDS:
        matching = tuple(
            item
            for item in receipts
            if item.host_id == profile.host_id
            and item.kind == kind
            and item.profile_key == expected[kind]
            and item.status == "PASSED"
        )
        approved = tuple(
            item for item in matching if item.approved_profile_ref is not None
        )
        if not approved:
            raise ValueError("LOCAL_EVALUATION_CAPABILITY_NOT_APPROVED")
        service = service_factory(kind)
        current: dict[HostConfigurationRef, Path] = {}
        for item in approved:
            assert item.approved_profile_ref is not None
            try:
                exact_ref = service.require_approved_current(
                    item.probe_id, item.approved_profile_ref
                )
                executable = service.resolve_executable(exact_ref).resolve()
            except (LookupError, OSError, ValueError):
                continue
            if exact_ref.host_id != profile.host_id:
                continue
            existing = current.get(exact_ref)
            if existing is not None and existing != executable:
                raise ValueError("LOCAL_EVALUATION_CAPABILITY_AMBIGUOUS")
            current[exact_ref] = executable
        if len(current) != 1:
            reason = (
                "LOCAL_EVALUATION_CAPABILITY_NOT_CURRENT"
                if not current
                else "LOCAL_EVALUATION_CAPABILITY_AMBIGUOUS"
            )
            raise ValueError(reason)
        exact_ref, executable = next(iter(current.items()))
        resolved[kind] = exact_ref
        executables[kind] = executable

    return LocalEvaluationApprovedCapabilities(
        git_profile_ref=resolved["GIT"],
        python_runtime_profile_ref=resolved["PYTHON_RUNTIME"],
        static_profile_refs=MappingProxyType(
            {
                "AST": resolved["PYTHON_AST"],
                "OPENGREP": resolved["OPENGREP"],
                "CODEQL": resolved["CODEQL"],
            }
        ),
        executables=MappingProxyType(executables),
        trusted_evidence=lookup.trusted_evidence(),
        protected_artifact_refs=lookup.evidence_refs(),
    )


__all__ = [
    "LocalCapabilityServiceFactory",
    "LocalEvaluationApprovedCapabilities",
    "resolve_local_approved_capabilities",
]
