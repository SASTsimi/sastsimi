"""Production capability publication is evidence-backed and exact."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.capabilities import (
    CapabilityApprovalEvidence,
    CapabilityControlEvidence,
    RuntimeCapabilityProfile,
    RuntimeCapabilitySelection,
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
from sastsimi.contracts.work import (
    SubjectType,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.ports.capability_registry import ProductionCapabilityResolverPort
from sastsimi.runtime.services import RuntimeServices
from sastsimi.storage.database import Database
from sastsimi.storage.migrations import upgrade
from tests.integration.runtime_support import TestClock, TestIds
from tests.integration.trusted_fixture import FixtureEvidence

NOW = datetime(2026, 9, 12, tzinfo=UTC)


def _placeholder_ref(host_id: str = "host-a") -> HostConfigurationRef:
    return HostConfigurationRef(
        stored_data_id=StoredDataId("approval-placeholder"),
        data_kind="tool_capability_evidence",
        content_hash="a" * 64,
        host_id=host_id,
        publication_analysis_id=AnalysisId("capability-run"),
        publication_workspace_id=WorkspaceId("ws1"),
        publication_commit_id=CommitId("c1"),
        record_id=RecordId("approval-placeholder"),
    )


class CapabilityEvidence(FixtureEvidence):
    def __init__(self) -> None:
        super().__init__()
        self.capability_approvals: set[str] = set()

    def capability_approval_authorized(
        self, evidence: CapabilityApprovalEvidence
    ) -> bool:
        return content_hash(evidence) in self.capability_approvals


def _meta(
    kind: str,
    record_id: str,
    *,
    logical_id: str | None = None,
    revision: int = 1,
    previous: str | None = None,
) -> RecordMeta:
    return RecordMeta(
        record_id=RecordId(record_id),
        logical_record_id=LogicalRecordId(logical_id or record_id),
        record_type=kind,
        schema_version="1.0.0",
        revision_number=revision,
        previous_record_id=RecordId(previous) if previous is not None else None,
        created_at=NOW,
        analysis_id=AnalysisId("capability-run"),
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
        hypothesis_id=None,
        attempt_id=None,
    )


def _runtime_profile(
    *,
    key: str = "python-package",
    kind: str = "PACKAGE_MANAGER",
    languages: tuple[str, ...] = ("PYTHON",),
    operations: tuple[str, ...] = ("PACKAGE_INSTALL",),
    status: str = "ACTIVE",
    record_id: str = "python-package-v1",
    logical_id: str = "python-package",
    revision: int = 1,
    previous: str | None = None,
    evidence_ref: HostConfigurationRef | None = None,
    subject_key: str = "python",
    expected_version: str = "3.12.6",
    host_id: str = "host-a",
) -> RuntimeCapabilityProfile:
    return RuntimeCapabilityProfile.model_validate(
        {
            "meta": _meta(
                "runtime_capability_profile",
                record_id,
                logical_id=logical_id,
                revision=revision,
                previous=previous,
            ),
            "profile_key": key,
            "host_id": host_id,
            "purpose": "PRODUCTION",
            "status": status,
            "capability_kind": kind,
            "subject_key": subject_key,
            "expected_version": expected_version,
            "subject_sha256": "b" * 64,
            "operating_system": "windows",
            "architecture": "x86_64",
            "languages": languages,
            "operations": operations,
            "capability_evidence_ref": evidence_ref or _placeholder_ref(host_id),
        }
    )


def _security_controls(
    capability_kind: str, evidence_ref: StoredDataRef
) -> tuple[CapabilityControlEvidence, ...]:
    required = {
        "GIT": "SAFE_REPOSITORY_LOADER",
        "CODEQL": "STATIC_WRITE_DENYING_QUOTA",
        "DOCKER": "SANDBOX_OUTER_BOUNDARY",
    }
    control = required.get(capability_kind)
    if control is None:
        return ()
    return (
        CapabilityControlEvidence.model_validate(
            {"control": control, "evidence_ref": evidence_ref}
        ),
    )


def _approval(
    profile: RuntimeCapabilityProfile | StaticToolProfile,
    raw_ref: StoredDataRef,
    *,
    record_id: str = "approval-v1",
    decision: str = "ACTIVATE",
    capability_kind: str = "PACKAGE_MANAGER",
    languages: tuple[str, ...] = ("PYTHON",),
    operations: tuple[str, ...] = ("PACKAGE_INSTALL",),
    security_control_evidence: tuple[CapabilityControlEvidence, ...] = (),
    host_id: str = "host-a",
) -> CapabilityApprovalEvidence:
    return CapabilityApprovalEvidence.model_validate(
        {
            "meta": _meta("tool_capability_evidence", record_id),
            "profile_key": profile.profile_key,
            "host_id": host_id,
            "capability_kind": capability_kind,
            "subject_key": (
                profile.executable_key
                if isinstance(profile, StaticToolProfile)
                else profile.subject_key
            ),
            "observed_version": (
                profile.expected_version
                if isinstance(profile, StaticToolProfile)
                else profile.expected_version
            ),
            "observed_sha256": (
                profile.executable_sha256
                if isinstance(profile, StaticToolProfile)
                else profile.subject_sha256
            ),
            "operating_system": "windows",
            "architecture": "x86_64",
            "languages": languages,
            "operations": operations,
            "probe_status": "PASSED",
            "probe_evidence_refs": (raw_ref,),
            "security_control_evidence": security_control_evidence,
            "checked_at": NOW,
            "checked_by": "gitterable",
            "checked_by_role": "R8",
            "decision": decision,
            "approved_at": NOW,
            "approved_by": "taehyeon-git",
            "approved_by_role": "HUMAN",
            "approval_target_hash": capability_target_hash(profile),
            "safe_summary": "Exact local capability probe passed and was approved.",
        }
    )


def _runtime(
    tmp_path: Path,
    *,
    host_id: str = "host-a",
    evidence: CapabilityEvidence | None = None,
) -> tuple[RuntimeServices, CapabilityEvidence, StoredDataRef]:
    evidence = evidence or CapabilityEvidence()
    upgrade(Database(tmp_path / "db" / "sastsimi.sqlite3"))
    runtime = build_runtime(
        tmp_path,
        WorkspaceId("ws1"),
        CommitId("c1"),
        TestClock(),
        TestIds(),
        evidence=evidence,
        capability_host_id=host_id,
    )
    artifacts = runtime.unit_of_work.artifacts
    raw_ref = artifacts.commit(
        artifacts.stage_bytes(b"version=3.12.6\nos=windows\n", "text/plain")
    )
    return runtime, evidence, raw_ref


def test_active_runtime_capability_is_resolved_by_exact_trusted_route(
    tmp_path: Path,
) -> None:
    runtime, evidence, raw_ref = _runtime(tmp_path)
    draft = _runtime_profile()
    approval = _approval(draft, raw_ref)
    evidence.capability_approvals.add(content_hash(approval))
    approval_ref = runtime.configuration.register_capability_approval(approval)
    profile = draft.model_copy(update={"capability_evidence_ref": approval_ref})
    profile_ref = runtime.configuration.register_runtime_capability(profile)

    selection = runtime.configuration.resolve_active_capability(
        capability_kind="PACKAGE_MANAGER",
        language="PYTHON",
        operation="PACKAGE_INSTALL",
        operating_system="windows",
        architecture="x86_64",
    )

    assert selection.profile_ref == profile_ref
    assert selection.profile == profile
    assert runtime.configuration.get_runtime_capability(profile_ref) == profile
    assert isinstance(runtime.configuration, ProductionCapabilityResolverPort)


def test_retired_profile_keeps_history_but_cannot_be_selected(tmp_path: Path) -> None:
    runtime, evidence, raw_ref = _runtime(tmp_path)
    draft = _runtime_profile()
    activation = _approval(draft, raw_ref)
    evidence.capability_approvals.add(content_hash(activation))
    activation_ref = runtime.configuration.register_capability_approval(activation)
    active = draft.model_copy(update={"capability_evidence_ref": activation_ref})
    active_ref = runtime.configuration.register_runtime_capability(active)

    retirement_target = _runtime_profile(
        status="RETIRED",
        record_id="python-package-v2",
        logical_id="python-package",
        revision=2,
        previous="python-package-v1",
    )
    changed_retirement = retirement_target.model_copy(
        update={"languages": ("JAVASCRIPT",)}
    )
    changed_approval = _approval(
        changed_retirement,
        raw_ref,
        record_id="changed-retirement-v1",
        decision="RETIRE",
        languages=("JAVASCRIPT",),
    )
    evidence.capability_approvals.add(content_hash(changed_approval))
    changed_approval_ref = runtime.configuration.register_capability_approval(
        changed_approval
    )
    with pytest.raises(ValueError, match="CAPABILITY_RETIREMENT_IDENTITY_MISMATCH"):
        runtime.configuration.register_runtime_capability(
            changed_retirement.model_copy(
                update={"capability_evidence_ref": changed_approval_ref}
            )
        )
    retirement = _approval(
        retirement_target,
        raw_ref,
        record_id="retirement-v1",
        decision="RETIRE",
    )
    evidence.capability_approvals.add(content_hash(retirement))
    retirement_ref = runtime.configuration.register_capability_approval(retirement)
    retired = retirement_target.model_copy(
        update={"capability_evidence_ref": retirement_ref}
    )
    runtime.configuration.register_runtime_capability(retired)

    assert runtime.configuration.get_runtime_capability(active_ref) == active
    with pytest.raises(LookupError, match="CAPABILITY_ROUTE_NOT_ACTIVE"):
        runtime.configuration.resolve_active_capability(
            capability_kind="PACKAGE_MANAGER",
            language="PYTHON",
            operation="PACKAGE_INSTALL",
            operating_system="windows",
            architecture="x86_64",
        )


@pytest.mark.parametrize(
    ("adapter_key", "tool_name", "tool_kind", "capability_kind", "operation"),
    [
        ("PYTHON_AST", "AST", "STRUCTURE", "AST", "PARSE"),
        ("CODEQL", "CODEQL", "RULE_BASED", "CODEQL", "ANALYZE"),
        ("OPENGREP", "OPENGREP", "RULE_BASED", "OPENGREP", "ANALYZE"),
    ],
)
def test_minimum_static_routes_are_representable(
    adapter_key: str,
    tool_name: str,
    tool_kind: str,
    capability_kind: str,
    operation: str,
) -> None:
    profile = StaticToolProfile.model_validate(
        {
            "meta": _meta("static_tool_profile", f"{adapter_key}-v1"),
            "profile_key": f"{adapter_key}-production",
            "host_id": "host-a",
            "purpose": "PRODUCTION",
            "status": "ACTIVE",
            "adapter_key": adapter_key,
            "tool_name": tool_name,
            "tool_kind": tool_kind,
            "executable_key": adapter_key.lower(),
            "executable_sha256": "d" * 64,
            "expected_version": "1.0.0",
            "capability_evidence_ref": _placeholder_ref(),
            "probe_timeout_ms": 1_000,
            "run_timeout_ms": 30_000,
            "stdout_limit_bytes": 1_024,
            "stderr_limit_bytes": 1_024,
            "max_attempt_output_bytes": 4_096,
            "max_output_file_bytes": 2_048,
            "max_artifact_read_bytes": 2_048,
        }
    )
    assert profile.adapter_key == adapter_key
    assert capability_kind in {"AST", "CODEQL", "OPENGREP"}
    assert operation in {"PARSE", "ANALYZE"}


@pytest.mark.parametrize(
    ("adapter_key", "tool_name", "tool_kind", "capability_kind", "operation"),
    [
        ("PYTHON_AST", "AST", "STRUCTURE", "AST", "PARSE"),
        ("CODEQL", "CODEQL", "RULE_BASED", "CODEQL", "ANALYZE"),
        ("OPENGREP", "OPENGREP", "RULE_BASED", "OPENGREP", "ANALYZE"),
    ],
)
def test_minimum_static_capability_can_be_activated_and_resolved(
    tmp_path: Path,
    adapter_key: str,
    tool_name: str,
    tool_kind: str,
    capability_kind: str,
    operation: str,
) -> None:
    runtime, evidence, raw_ref = _runtime(tmp_path)
    draft = StaticToolProfile.model_validate(
        {
            "meta": _meta("static_tool_profile", f"{adapter_key}-active-v1"),
            "profile_key": f"{adapter_key}-active",
            "host_id": "host-a",
            "purpose": "PRODUCTION",
            "status": "ACTIVE",
            "adapter_key": adapter_key,
            "tool_name": tool_name,
            "tool_kind": tool_kind,
            "executable_key": adapter_key.lower(),
            "executable_sha256": "d" * 64,
            "expected_version": "1.0.0",
            "capability_evidence_ref": _placeholder_ref(),
            "probe_timeout_ms": 1_000,
            "run_timeout_ms": 30_000,
            "stdout_limit_bytes": 1_024,
            "stderr_limit_bytes": 1_024,
            "max_attempt_output_bytes": 4_096,
            "max_output_file_bytes": 2_048,
            "max_artifact_read_bytes": 2_048,
        }
    )
    approval = _approval(
        draft,
        raw_ref,
        capability_kind=capability_kind,
        languages=("PYTHON",),
        operations=(operation,),
        security_control_evidence=_security_controls(capability_kind, raw_ref),
    )
    evidence.capability_approvals.add(content_hash(approval))
    approval_ref = runtime.configuration.register_capability_approval(approval)
    profile = draft.model_copy(update={"capability_evidence_ref": approval_ref})
    profile_ref = runtime.configuration.register_production_static_tool_profile(profile)

    selection = runtime.configuration.resolve_active_static_tool(
        adapter_key=adapter_key,
        language="PYTHON",
        operating_system="windows",
        architecture="x86_64",
    )
    work_a = _ready_static_work(
        analysis_id=f"{adapter_key}-analysis-a",
        workspace_id=f"{adapter_key}-workspace-a",
        commit_id=f"{adapter_key}-commit-a",
        profile_ref=selection.profile_ref,
    )
    work_b = _ready_static_work(
        analysis_id=f"{adapter_key}-analysis-b",
        workspace_id=f"{adapter_key}-workspace-b",
        commit_id=f"{adapter_key}-commit-b",
        profile_ref=selection.profile_ref,
    )

    assert selection.profile_ref == profile_ref
    assert selection.evidence == approval
    assert isinstance(profile_ref, HostConfigurationRef)
    assert work_a.input_refs == work_b.input_refs == (profile_ref,)
    assert runtime.unit_of_work.records.get_exact(profile_ref) == profile


def test_forged_or_ambiguous_active_capability_fails_closed(tmp_path: Path) -> None:
    runtime, evidence, raw_ref = _runtime(tmp_path)
    forged = _runtime_profile()
    forged_approval = _approval(forged, raw_ref)

    with pytest.raises(ValueError, match="CAPABILITY_APPROVAL_REQUIRED"):
        runtime.configuration.register_capability_approval(forged_approval)
    with pytest.raises(ValueError, match="CAPABILITY_EVIDENCE_REQUIRED"):
        runtime.configuration.register_runtime_capability(forged)

    evidence.capability_approvals.add(content_hash(forged_approval))
    approval_ref = runtime.configuration.register_capability_approval(forged_approval)
    with pytest.raises(ValueError, match="CAPABILITY_APPROVAL_TARGET_MISMATCH"):
        runtime.configuration.register_runtime_capability(
            forged.model_copy(
                update={
                    "expected_version": "3.13.0",
                    "capability_evidence_ref": approval_ref,
                }
            )
        )
    trusted = forged.model_copy(update={"capability_evidence_ref": approval_ref})
    runtime.configuration.register_runtime_capability(trusted)

    second_draft = _runtime_profile(
        key="python-package-second",
        record_id="python-package-second-v1",
        logical_id="python-package-second",
    )
    second_approval = _approval(second_draft, raw_ref, record_id="approval-v2")
    evidence.capability_approvals.add(content_hash(second_approval))
    second_ref = runtime.configuration.register_capability_approval(second_approval)
    with pytest.raises(ValueError, match="CAPABILITY_ACTIVE_ROUTE_CONFLICT"):
        runtime.configuration.register_runtime_capability(
            second_draft.model_copy(update={"capability_evidence_ref": second_ref})
        )

    with pytest.raises(LookupError, match="CAPABILITY_ROUTE_NOT_ACTIVE"):
        runtime.configuration.resolve_active_capability(
            capability_kind="PACKAGE_MANAGER",
            language="JAVASCRIPT",
            operation="PACKAGE_INSTALL",
            operating_system="windows",
            architecture="x86_64",
        )


def test_production_static_profile_requires_current_matching_evidence(
    tmp_path: Path,
) -> None:
    runtime, evidence, raw_ref = _runtime(tmp_path)
    draft = StaticToolProfile.model_validate(
        {
            "meta": _meta("static_tool_profile", "ast-production-v1"),
            "profile_key": "ast-production",
            "host_id": "host-a",
            "purpose": "PRODUCTION",
            "status": "ACTIVE",
            "adapter_key": "PYTHON_AST",
            "tool_name": "AST",
            "tool_kind": "STRUCTURE",
            "executable_key": "python",
            "executable_sha256": "c" * 64,
            "expected_version": "3.12.6",
            "capability_evidence_ref": _placeholder_ref(),
            "probe_timeout_ms": 1_000,
            "run_timeout_ms": 30_000,
            "stdout_limit_bytes": 1_024,
            "stderr_limit_bytes": 1_024,
            "max_attempt_output_bytes": 4_096,
            "max_output_file_bytes": 2_048,
            "max_artifact_read_bytes": 2_048,
        }
    )
    approval = _approval(
        draft,
        raw_ref,
        capability_kind="AST",
        languages=("PYTHON",),
        operations=("PARSE",),
    )
    evidence.capability_approvals.add(content_hash(approval))
    approval_ref = runtime.configuration.register_capability_approval(approval)
    profile = draft.model_copy(update={"capability_evidence_ref": approval_ref})
    profile_ref = runtime.configuration.register_production_static_tool_profile(profile)

    selection = runtime.configuration.resolve_active_static_tool(
        adapter_key="PYTHON_AST",
        language="PYTHON",
        operating_system="windows",
        architecture="x86_64",
    )

    assert selection.profile_ref == profile_ref
    assert selection.profile == profile
    assert (
        runtime.configuration.resolve_production_static_tool_profile(profile_ref)
        == profile
    )


def test_static_retirement_is_exact_and_preserves_historical_revision(
    tmp_path: Path,
) -> None:
    runtime, evidence, raw_ref = _runtime(tmp_path)
    draft = StaticToolProfile.model_validate(
        {
            "meta": _meta("static_tool_profile", "ast-production-v1"),
            "profile_key": "ast-production",
            "host_id": "host-a",
            "purpose": "PRODUCTION",
            "status": "ACTIVE",
            "adapter_key": "PYTHON_AST",
            "tool_name": "AST",
            "tool_kind": "STRUCTURE",
            "executable_key": "python",
            "executable_sha256": "c" * 64,
            "expected_version": "3.12.6",
            "capability_evidence_ref": _placeholder_ref(),
            "probe_timeout_ms": 1_000,
            "run_timeout_ms": 30_000,
            "stdout_limit_bytes": 1_024,
            "stderr_limit_bytes": 1_024,
            "max_attempt_output_bytes": 4_096,
            "max_output_file_bytes": 2_048,
            "max_artifact_read_bytes": 2_048,
        }
    )
    activation = _approval(
        draft,
        raw_ref,
        capability_kind="AST",
        languages=("PYTHON",),
        operations=("PARSE",),
    )
    evidence.capability_approvals.add(content_hash(activation))
    activation_ref = runtime.configuration.register_capability_approval(activation)
    active = draft.model_copy(update={"capability_evidence_ref": activation_ref})
    active_ref = runtime.configuration.register_production_static_tool_profile(active)

    retirement_target = active.model_copy(
        update={
            "meta": _meta(
                "static_tool_profile",
                "ast-production-v2",
                logical_id="ast-production-v1",
                revision=2,
                previous="ast-production-v1",
            ),
            "status": "RETIRED",
            "capability_evidence_ref": _placeholder_ref(),
        }
    )
    retirement = _approval(
        retirement_target,
        raw_ref,
        record_id="ast-retirement-v1",
        decision="RETIRE",
        capability_kind="AST",
        languages=("PYTHON",),
        operations=("PARSE",),
    )
    evidence.capability_approvals.add(content_hash(retirement))
    retirement_ref = runtime.configuration.register_capability_approval(retirement)
    retired = retirement_target.model_copy(
        update={"capability_evidence_ref": retirement_ref}
    )
    runtime.configuration.register_production_static_tool_profile(retired)

    assert (
        runtime.configuration.get_production_static_tool_profile(active_ref) == active
    )
    with pytest.raises(ValueError, match="STALE_CONFIGURATION_REVISION"):
        runtime.configuration.resolve_production_static_tool_profile(active_ref)
    with pytest.raises(LookupError, match="STATIC_TOOL_ROUTE_NOT_ACTIVE"):
        runtime.configuration.resolve_active_static_tool(
            adapter_key="PYTHON_AST",
            language="PYTHON",
            operating_system="windows",
            architecture="x86_64",
        )


@pytest.mark.parametrize(
    ("kind", "language", "operation"),
    [
        ("GIT", "ANY", "CLONE"),
        ("DOCKER", "ANY", "IMAGE_BUILD"),
        ("PYTHON_RUNTIME", "PYTHON", "START"),
        ("JAVASCRIPT_RUNTIME", "JAVASCRIPT", "START"),
        ("PACKAGE_MANAGER", "PYTHON", "PACKAGE_INSTALL"),
        ("PACKAGE_MANAGER", "JAVASCRIPT", "PACKAGE_INSTALL"),
        ("BUILD", "PYTHON", "BUILD"),
        ("BUILD", "JAVASCRIPT", "BUILD"),
        ("START", "PYTHON", "START"),
        ("START", "JAVASCRIPT", "START"),
    ],
)
def test_minimum_runtime_capability_routes_are_representable(
    kind: str, language: str, operation: str
) -> None:
    profile = _runtime_profile(
        key=f"{kind}-{language}-{operation}",
        kind=kind,
        languages=(language,),
        operations=(operation,),
    )
    assert profile.capability_kind == kind


@pytest.mark.parametrize(
    ("kind", "language", "operation", "subject_key"),
    [
        ("GIT", "ANY", "CLONE", "git"),
        ("GIT", "ANY", "CHECKOUT", "git"),
        ("DOCKER", "ANY", "IMAGE_BUILD", "docker"),
        ("DOCKER", "ANY", "CONTAINER_RUN", "docker"),
        ("DOCKER", "ANY", "HEALTH_CHECK", "docker"),
        ("DOCKER", "ANY", "CLEANUP", "docker"),
        ("PYTHON_RUNTIME", "PYTHON", "START", "python"),
        ("JAVASCRIPT_RUNTIME", "JAVASCRIPT", "START", "node"),
        ("PACKAGE_MANAGER", "PYTHON", "PACKAGE_INSTALL", "pip"),
        ("PACKAGE_MANAGER", "JAVASCRIPT", "PACKAGE_INSTALL", "npm"),
        ("BUILD", "PYTHON", "BUILD", "python-build"),
        ("BUILD", "JAVASCRIPT", "BUILD", "npm-build"),
        ("START", "PYTHON", "START", "python-start"),
        ("START", "JAVASCRIPT", "START", "npm-start"),
    ],
)
def test_minimum_runtime_capability_can_be_activated_and_resolved(
    tmp_path: Path,
    kind: str,
    language: str,
    operation: str,
    subject_key: str,
) -> None:
    runtime, evidence, raw_ref = _runtime(tmp_path)
    draft = _runtime_profile(
        key=f"{kind}-{language}-{operation}",
        kind=kind,
        languages=(language,),
        operations=(operation,),
        record_id=f"{kind}-{language}-{operation}-v1",
        logical_id=f"{kind}-{language}-{operation}",
        subject_key=subject_key,
        expected_version="1.0.0",
    )
    approval = _approval(
        draft,
        raw_ref,
        record_id=f"{kind}-{language}-{operation}-approval-v1",
        capability_kind=kind,
        languages=(language,),
        operations=(operation,),
        security_control_evidence=_security_controls(kind, raw_ref),
    )
    evidence.capability_approvals.add(content_hash(approval))
    approval_ref = runtime.configuration.register_capability_approval(approval)
    profile = draft.model_copy(update={"capability_evidence_ref": approval_ref})
    profile_ref = runtime.configuration.register_runtime_capability(profile)

    selection = runtime.configuration.resolve_active_capability(
        capability_kind=kind,
        language=language,
        operation=operation,
        operating_system="windows",
        architecture="x86_64",
    )

    assert selection.profile_ref == profile_ref


def test_runtime_profile_rejects_invalid_route_and_first_retirement() -> None:
    with pytest.raises(ValidationError, match="CAPABILITY_OPERATION_MISMATCH"):
        _runtime_profile(kind="GIT", operations=("IMAGE_BUILD",))
    with pytest.raises(ValidationError, match="CAPABILITY_RETIREMENT_REVISION_INVALID"):
        _runtime_profile(status="RETIRED")


def test_high_risk_capability_requires_exact_security_control_evidence() -> None:
    git_profile = _runtime_profile(
        key="git-production",
        kind="GIT",
        languages=("ANY",),
        operations=("CLONE",),
    )
    raw_ref = StoredDataRef(
        stored_data_id=StoredDataId("probe-output"),
        data_kind="capability_probe_output",
        content_hash="e" * 64,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
        record_id=None,
    )
    with pytest.raises(
        ValidationError, match="CAPABILITY_SECURITY_CONTROL_EVIDENCE_REQUIRED"
    ):
        _approval(
            git_profile,
            raw_ref,
            capability_kind="GIT",
            languages=("ANY",),
            operations=("CLONE",),
        )

    approval = _approval(
        git_profile,
        raw_ref,
        capability_kind="GIT",
        languages=("ANY",),
        operations=("CLONE",),
        security_control_evidence=(
            CapabilityControlEvidence(
                control="SAFE_REPOSITORY_LOADER", evidence_ref=raw_ref
            ),
        ),
    )
    assert approval.security_control_evidence[0].control == "SAFE_REPOSITORY_LOADER"


def _ready_static_work(
    *,
    analysis_id: str,
    workspace_id: str,
    commit_id: str,
    profile_ref: HostConfigurationRef,
) -> WorkExecutionState:
    transition_ref = StoredDataRef(
        stored_data_id=StoredDataId(f"transition-{analysis_id}"),
        data_kind="state_transition",
        content_hash="3" * 64,
        workspace_id=WorkspaceId(workspace_id),
        commit_id=CommitId(commit_id),
        record_id=RecordId(f"transition-{analysis_id}"),
    )
    return WorkExecutionState.model_validate(
        {
            "meta": {
                "record_id": f"work-{analysis_id}",
                "logical_record_id": f"work-{analysis_id}",
                "record_type": "work_execution_state",
                "schema_version": "1.0.0",
                "revision_number": 1,
                "previous_record_id": None,
                "created_at": NOW,
                "analysis_id": analysis_id,
                "workspace_id": workspace_id,
                "commit_id": commit_id,
                "hypothesis_id": None,
                "attempt_id": None,
            },
            "work_id": f"work-{analysis_id}",
            "parent_work_ref": None,
            "work_type": WorkType.STATIC_TOOL,
            "subject_type": SubjectType.ANALYSIS,
            "subject_id": analysis_id,
            "work_generation": 1,
            "status": WorkStatus.READY,
            "state_version": 2,
            "last_transition_ref": transition_ref,
            "last_transition_commit_ref": None,
            "active_attempt_id": None,
            "input_hash": "1" * 64,
            "dedupe_key": "2" * 64,
            "trigger_primitive_ref": None,
            "input_refs": (profile_ref,),
            "output_refs": (),
            "gap_ids": (),
            "error_ids": (),
            "waiting_for": (),
            "stop_reason": None,
            "started_at": None,
            "finished_at": None,
            "elapsed_ms": 0,
        }
    )


def test_two_repository_works_pin_same_current_host_capability(tmp_path: Path) -> None:
    runtime, evidence, raw_ref = _runtime(tmp_path)
    draft = _runtime_profile()
    approval = _approval(draft, raw_ref)
    evidence.capability_approvals.add(content_hash(approval))
    approval_ref = runtime.configuration.register_capability_approval(approval)
    profile = draft.model_copy(update={"capability_evidence_ref": approval_ref})
    expected_ref = runtime.configuration.register_runtime_capability(profile)

    first = runtime.configuration.resolve_active_capability(
        capability_kind="PACKAGE_MANAGER",
        language="PYTHON",
        operation="PACKAGE_INSTALL",
        operating_system="windows",
        architecture="x86_64",
    )
    second = runtime.configuration.resolve_active_capability(
        capability_kind="PACKAGE_MANAGER",
        language="PYTHON",
        operation="PACKAGE_INSTALL",
        operating_system="windows",
        architecture="x86_64",
    )
    work_a = _ready_static_work(
        analysis_id="analysis-a",
        workspace_id="workspace-a",
        commit_id="commit-a",
        profile_ref=first.profile_ref,
    )
    work_b = _ready_static_work(
        analysis_id="analysis-b",
        workspace_id="workspace-b",
        commit_id="commit-b",
        profile_ref=second.profile_ref,
    )

    assert isinstance(expected_ref, HostConfigurationRef)
    assert first.profile_ref == second.profile_ref == expected_ref
    assert work_a.input_refs == work_b.input_refs == (expected_ref,)
    assert WorkExecutionState.model_validate_json(
        work_a.model_dump_json()
    ).input_refs == (expected_ref,)
    assert runtime.configuration.get_runtime_capability(expected_ref) == profile
    assert runtime.unit_of_work.records.get_exact(expected_ref) == profile


def test_cross_profile_forged_host_reference_is_rejected(tmp_path: Path) -> None:
    runtime, evidence, raw_ref = _runtime(tmp_path)
    package_draft = _runtime_profile()
    package_approval = _approval(package_draft, raw_ref)
    evidence.capability_approvals.add(content_hash(package_approval))
    approval_ref = runtime.configuration.register_capability_approval(package_approval)
    package_profile = package_draft.model_copy(
        update={"capability_evidence_ref": approval_ref}
    )
    package_ref = runtime.configuration.register_runtime_capability(package_profile)

    build_draft = _runtime_profile(
        key="python-build",
        kind="BUILD",
        operations=("BUILD",),
        record_id="python-build-v1",
        logical_id="python-build",
        subject_key="python-build",
    )
    build_approval = _approval(
        build_draft,
        raw_ref,
        record_id="python-build-approval-v1",
        capability_kind="BUILD",
        operations=("BUILD",),
    )
    evidence.capability_approvals.add(content_hash(build_approval))
    build_approval_ref = runtime.configuration.register_capability_approval(
        build_approval
    )
    build_ref = runtime.configuration.register_runtime_capability(
        build_draft.model_copy(update={"capability_evidence_ref": build_approval_ref})
    )
    forged = package_ref.model_copy(
        update={
            "record_id": build_ref.record_id,
            "stored_data_id": build_ref.stored_data_id,
        }
    )

    with pytest.raises(ValueError, match="RECORD_REVISION_MISMATCH"):
        runtime.configuration.get_runtime_capability(forged)
    with pytest.raises(ValidationError, match="CAPABILITY_SELECTION_REF_MISMATCH"):
        RuntimeCapabilitySelection(profile_ref=build_ref, profile=package_profile)


def test_host_b_resolver_cannot_select_host_a_profile(tmp_path: Path) -> None:
    runtime_a, evidence, raw_ref = _runtime(tmp_path)
    draft = _runtime_profile()
    approval = _approval(draft, raw_ref)
    evidence.capability_approvals.add(content_hash(approval))
    approval_ref = runtime_a.configuration.register_capability_approval(approval)
    profile_ref = runtime_a.configuration.register_runtime_capability(
        draft.model_copy(update={"capability_evidence_ref": approval_ref})
    )
    runtime_b = build_runtime(
        tmp_path,
        WorkspaceId("ws1"),
        CommitId("c1"),
        TestClock(),
        TestIds(),
        evidence=evidence,
        capability_host_id="host-b",
    )

    with pytest.raises(LookupError, match="CAPABILITY_ROUTE_NOT_ACTIVE"):
        runtime_b.configuration.resolve_active_capability(
            capability_kind="PACKAGE_MANAGER",
            language="PYTHON",
            operation="PACKAGE_INSTALL",
            operating_system="windows",
            architecture="x86_64",
        )
    with pytest.raises(ValueError, match="CAPABILITY_HOST_MISMATCH"):
        runtime_b.configuration.get_runtime_capability(profile_ref)


def test_same_route_isolated_by_trusted_host_binding(tmp_path: Path) -> None:
    runtime_a, evidence, raw_ref = _runtime(tmp_path)
    draft_a = _runtime_profile()
    approval_a = _approval(draft_a, raw_ref)
    evidence.capability_approvals.add(content_hash(approval_a))
    approval_ref_a = runtime_a.configuration.register_capability_approval(approval_a)
    profile_ref_a = runtime_a.configuration.register_runtime_capability(
        draft_a.model_copy(update={"capability_evidence_ref": approval_ref_a})
    )

    runtime_b, _, raw_ref_b = _runtime(tmp_path, host_id="host-b", evidence=evidence)
    draft_b = _runtime_profile(
        host_id="host-b",
        record_id="python-package-host-b-v1",
        logical_id="python-package-host-b",
    )
    approval_b = _approval(
        draft_b,
        raw_ref_b,
        record_id="approval-host-b-v1",
        host_id="host-b",
    )
    evidence.capability_approvals.add(content_hash(approval_b))
    approval_ref_b = runtime_b.configuration.register_capability_approval(approval_b)
    profile_ref_b = runtime_b.configuration.register_runtime_capability(
        draft_b.model_copy(update={"capability_evidence_ref": approval_ref_b})
    )

    selection_a = runtime_a.configuration.resolve_active_capability(
        capability_kind="PACKAGE_MANAGER",
        language="PYTHON",
        operation="PACKAGE_INSTALL",
        operating_system="windows",
        architecture="x86_64",
    )
    selection_b = runtime_b.configuration.resolve_active_capability(
        capability_kind="PACKAGE_MANAGER",
        language="PYTHON",
        operation="PACKAGE_INSTALL",
        operating_system="windows",
        architecture="x86_64",
    )

    assert selection_a.profile_ref == profile_ref_a
    assert selection_b.profile_ref == profile_ref_b
    assert selection_a.profile_ref.host_id == "host-a"
    assert selection_b.profile_ref.host_id == "host-b"
