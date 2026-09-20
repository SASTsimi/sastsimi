from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from sastsimi.composition.local_evaluation_capabilities import (
    LocalCapabilityServiceFactory,
    resolve_local_approved_capabilities,
)
from sastsimi.contracts.ids import (
    AnalysisId,
    CommitId,
    RecordId,
    StoredDataId,
    WorkspaceId,
)
from sastsimi.contracts.refs import HostConfigurationRef, StoredDataRef


def _ref(kind: str, name: str) -> HostConfigurationRef:
    return HostConfigurationRef(
        stored_data_id=StoredDataId(name),
        data_kind=kind,
        content_hash="a" * 64,
        host_id="host-a",
        publication_analysis_id=AnalysisId("capability-analysis"),
        publication_workspace_id=WorkspaceId("capability-workspace"),
        publication_commit_id=CommitId("capability-commit"),
        record_id=RecordId(name),
    )


@dataclass(frozen=True)
class _Receipt:
    probe_id: str
    host_id: str
    kind: str
    profile_key: str
    status: str
    approved_profile_ref: HostConfigurationRef | None


class _Evidence:
    pass


class _Service:
    def __init__(self, receipts: tuple[_Receipt, ...], kind: str | None) -> None:
        self.receipts = receipts
        self.kind = kind
        self.checked: list[tuple[str, HostConfigurationRef]] = []

    def list(self) -> tuple[_Receipt, ...]:
        return self.receipts

    def require_approved_current(
        self, probe_id: str, expected_ref: HostConfigurationRef
    ) -> HostConfigurationRef:
        self.checked.append((probe_id, expected_ref))
        if self.kind is None:
            raise AssertionError("lookup service cannot validate a capability")
        return expected_ref

    def resolve_executable(self, profile_ref: HostConfigurationRef) -> Path:
        assert self.kind is not None
        return Path(f"/tools/{self.kind.lower()}")

    def trusted_evidence(self) -> _Evidence:
        return _Evidence()

    def evidence_refs(self) -> tuple[StoredDataRef, ...]:
        return (
            StoredDataRef(
                stored_data_id=StoredDataId("b" * 64),
                data_kind="artifact",
                content_hash="b" * 64,
                workspace_id=WorkspaceId("host-configuration"),
                commit_id=CommitId("host-configuration-v1"),
                record_id=None,
            ),
        )


def _profile() -> SimpleNamespace:
    return SimpleNamespace(
        host_id="host-a",
        capabilities=SimpleNamespace(
            git_profile_key="git-live",
            python_runtime_profile_key="python-runtime-live",
            python_ast_profile_key="python-ast-live",
            opengrep_profile_key="opengrep-live",
            codeql_profile_key="codeql-live",
        ),
    )


def _receipts() -> tuple[_Receipt, ...]:
    return tuple(
        _Receipt(
            probe_id=f"probe-{kind.lower()}",
            host_id="host-a",
            kind=kind,
            profile_key=key,
            status="PASSED",
            approved_profile_ref=_ref("static_tool_profile", key),
        )
        for kind, key in (
            ("GIT", "git-live"),
            ("PYTHON_RUNTIME", "python-runtime-live"),
            ("PYTHON_AST", "python-ast-live"),
            ("OPENGREP", "opengrep-live"),
            ("CODEQL", "codeql-live"),
        )
    )


def test_resolves_each_exact_approved_current_profile_and_executable() -> None:
    receipts = _receipts()
    services: dict[str | None, _Service] = {}

    def factory(kind: str | None) -> _Service:
        return services.setdefault(kind, _Service(receipts, kind))

    resolved = resolve_local_approved_capabilities(
        _profile(), cast(LocalCapabilityServiceFactory, factory)
    )

    assert resolved.git_profile_ref == receipts[0].approved_profile_ref
    assert resolved.python_runtime_profile_ref == receipts[1].approved_profile_ref
    assert resolved.workspace_dependency_refs == (receipts[0].approved_profile_ref,)
    assert resolved.static_profile_refs == {
        "AST": receipts[2].approved_profile_ref,
        "OPENGREP": receipts[3].approved_profile_ref,
        "CODEQL": receipts[4].approved_profile_ref,
    }
    assert resolved.executables["GIT"] == Path("/tools/git").resolve()
    assert resolved.executables["CODEQL"] == Path("/tools/codeql").resolve()
    assert resolved.protected_artifact_refs == services[None].evidence_refs()
    assert all(
        services[kind].checked
        for kind in ("GIT", "PYTHON_RUNTIME", "PYTHON_AST", "OPENGREP", "CODEQL")
    )


def test_rejects_missing_or_ambiguous_profile_instead_of_falling_back() -> None:
    receipts = _receipts()
    duplicate = _Receipt(
        probe_id="probe-opengrep-new",
        host_id="host-a",
        kind="OPENGREP",
        profile_key="opengrep-live",
        status="PASSED",
        approved_profile_ref=_ref("static_tool_profile", "opengrep-new"),
    )

    def factory(kind: str | None) -> _Service:
        return _Service((*receipts, duplicate), kind)

    with pytest.raises(ValueError, match="LOCAL_EVALUATION_CAPABILITY_AMBIGUOUS"):
        resolve_local_approved_capabilities(
            _profile(), cast(LocalCapabilityServiceFactory, factory)
        )


def test_rejects_unapproved_receipt() -> None:
    receipts = list(_receipts())
    receipts[-1] = _Receipt(
        probe_id="probe-codeql",
        host_id="host-a",
        kind="CODEQL",
        profile_key="codeql-live",
        status="PASSED",
        approved_profile_ref=None,
    )

    def factory(kind: str | None) -> _Service:
        return _Service(tuple(receipts), kind)

    with pytest.raises(ValueError, match="LOCAL_EVALUATION_CAPABILITY_NOT_APPROVED"):
        resolve_local_approved_capabilities(
            _profile(), cast(LocalCapabilityServiceFactory, factory)
        )
