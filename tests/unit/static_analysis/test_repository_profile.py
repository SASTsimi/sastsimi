"""Repository profiling is closed over the exact safe Git manifest."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from sastsimi.contracts.capabilities import (
    CapabilityApprovalEvidence,
    CapabilityControlEvidence,
    RuntimeCapabilityProfile,
    RuntimeCapabilitySelection,
    StaticToolCapabilitySelection,
    capability_target_hash,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import (
    HostConfigurationRef,
    RunStoredDataRef,
    StoredDataRef,
    reference,
)
from sastsimi.contracts.static import RepositoryProfile, StaticToolProfile
from sastsimi.ports.capability_registry import ProductionCapabilityResolverPort
from sastsimi.ports.dto import CandidateGap, RepositoryPreparation, TrackedFile
from sastsimi.static_analysis.repository_profile import (
    RepositoryExecutionSelector,
    RepositoryProfiler,
    resolve_git_capability_refs,
    static_tool_work_inputs,
)
from tests.integration.runtime_support import metadata


def _blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


def _write(root: Path, path: str, raw: bytes) -> TrackedFile:
    target = root.joinpath(*path.split("/"))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(raw)
    return TrackedFile(path, "100644", _blob(raw), len(raw))


def _preparation(root: Path, tracked: tuple[TrackedFile, ...]) -> RepositoryPreparation:
    return RepositoryPreparation(
        analysis_id="analysis",
        workspace_id="workspace",
        repository_url="file:///fixture",
        requested_ref="main",
        status="READY",
        resolved_commit_id="a" * 40,
        root=root,
        tracked_files=tracked,
        gaps=(),
        errors=(),
        lease_id="lease",
    )


def _meta() -> RecordMeta:
    return RecordMeta.model_validate_json(
        json.dumps(
            metadata("repository_profile", "repository-profile", code=True)
            | {
                "analysis_id": "analysis",
                "workspace_id": "workspace",
                "commit_id": "a" * 40,
                "attempt_id": "attempt",
            }
        )
    )


def _selection_meta() -> RecordMeta:
    return RecordMeta.model_validate_json(
        json.dumps(
            metadata("repository_execution_selection", "selection", code=True)
            | {
                "analysis_id": "analysis",
                "workspace_id": "workspace",
                "commit_id": "a" * 40,
                "attempt_id": "attempt",
            }
        )
    )


def _workspace_ref() -> RunStoredDataRef:
    return RunStoredDataRef.model_validate_json(
        json.dumps(
            {
                "stored_data_id": "workspace-record",
                "data_kind": "code_workspace",
                "content_hash": "d" * 64,
                "analysis_id": "analysis",
                "record_id": "workspace-record",
            }
        )
    )


def _decision_ref() -> StoredDataRef:
    return StoredDataRef.model_validate(
        {
            "stored_data_id": "decision-record",
            "data_kind": "action_decision",
            "content_hash": "e" * 64,
            "workspace_id": "workspace",
            "commit_id": "a" * 40,
            "record_id": "decision-record",
        }
    )


def _build(root: Path, tracked: tuple[TrackedFile, ...]) -> RepositoryProfile:
    return RepositoryProfiler().build(
        _preparation(root, tracked),
        meta=_meta(),
        workspace_ref=_workspace_ref(),
        action_decision_ref=_decision_ref(),
    )


def _host_ref(kind: str, name: str) -> HostConfigurationRef:
    return HostConfigurationRef.model_validate(
        {
            "stored_data_id": name,
            "data_kind": kind,
            "content_hash": "a" * 64,
            "host_id": "host-a",
            "publication_analysis_id": "capability-run",
            "publication_workspace_id": "capability-workspace",
            "publication_commit_id": "capability-commit",
            "record_id": name,
        }
    )


def _raw_probe_ref(name: str) -> StoredDataRef:
    return StoredDataRef.model_validate(
        {
            "stored_data_id": name,
            "data_kind": "capability_probe_output",
            "content_hash": "b" * 64,
            "workspace_id": "w1",
            "commit_id": "c1",
            "record_id": None,
        }
    )


def _capability_meta(kind: str, name: str) -> dict[str, object]:
    value = metadata(kind, name, code=True)
    value["created_at"] = datetime(2026, 9, 13, tzinfo=UTC)
    return value


def _static_selection(adapter: str, language: str) -> StaticToolCapabilitySelection:
    name = f"{adapter.lower()}-{language.lower()}"
    placeholder = _host_ref("tool_capability_evidence", f"{name}-approval")
    profile = StaticToolProfile.model_validate(
        {
            "meta": _capability_meta("static_tool_profile", f"{name}-profile"),
            "host_id": "host-a",
            "profile_key": name,
            "purpose": "PRODUCTION",
            "status": "ACTIVE",
            "adapter_key": adapter,
            "tool_name": "AST" if adapter == "PYTHON_AST" else adapter,
            "tool_kind": "STRUCTURE" if adapter == "PYTHON_AST" else "RULE_BASED",
            "executable_key": name,
            "executable_sha256": "c" * 64,
            "expected_version": "1",
            "capability_evidence_ref": placeholder,
            "probe_timeout_ms": 1,
            "run_timeout_ms": 1,
            "stdout_limit_bytes": 1,
            "stderr_limit_bytes": 1,
            "max_attempt_output_bytes": 1,
            "max_output_file_bytes": 1,
            "max_artifact_read_bytes": 1,
        }
    )
    raw_ref = _raw_probe_ref(f"{name}-probe")
    control = (
        (
            CapabilityControlEvidence(
                control="STATIC_WRITE_DENYING_QUOTA", evidence_ref=raw_ref
            ),
        )
        if adapter == "CODEQL"
        else ()
    )
    evidence = CapabilityApprovalEvidence.model_validate(
        {
            "meta": _capability_meta("tool_capability_evidence", f"{name}-approval"),
            "host_id": "host-a",
            "profile_key": name,
            "capability_kind": "AST" if adapter == "PYTHON_AST" else adapter,
            "subject_key": name,
            "observed_version": "1",
            "observed_sha256": "c" * 64,
            "operating_system": "windows",
            "architecture": "x86_64",
            "languages": (language,),
            "operations": ("PARSE" if adapter == "PYTHON_AST" else "ANALYZE",),
            "probe_status": "PASSED",
            "probe_evidence_refs": (raw_ref,),
            "security_control_evidence": control,
            "checked_at": datetime(2026, 9, 13, tzinfo=UTC),
            "checked_by": "gitterable",
            "checked_by_role": "R8",
            "decision": "ACTIVATE",
            "approved_at": datetime(2026, 9, 13, tzinfo=UTC),
            "approved_by": "taehyeon-git",
            "approved_by_role": "HUMAN",
            "approval_target_hash": capability_target_hash(profile),
            "safe_summary": "Capability approved.",
        }
    )
    profile = profile.model_copy(
        update={"capability_evidence_ref": reference(evidence)}
    )
    profile_ref = reference(profile)
    assert isinstance(profile_ref, HostConfigurationRef)
    return StaticToolCapabilitySelection(
        profile_ref=profile_ref,
        profile=profile,
        evidence=evidence,
    )


def _git_capability() -> tuple[RuntimeCapabilityProfile, CapabilityApprovalEvidence]:
    placeholder = _host_ref("tool_capability_evidence", "git-approval")
    profile = RuntimeCapabilityProfile.model_validate(
        {
            "meta": _capability_meta("runtime_capability_profile", "git-profile"),
            "host_id": "host-a",
            "profile_key": "git-production",
            "purpose": "PRODUCTION",
            "status": "ACTIVE",
            "capability_kind": "GIT",
            "subject_key": "git",
            "expected_version": "2.51.0",
            "subject_sha256": "d" * 64,
            "operating_system": "windows",
            "architecture": "x86_64",
            "languages": ("ANY",),
            "operations": ("CLONE", "CHECKOUT"),
            "capability_evidence_ref": placeholder,
        }
    )
    raw_ref = _raw_probe_ref("git-probe")
    evidence = CapabilityApprovalEvidence.model_validate(
        {
            "meta": _capability_meta("tool_capability_evidence", "git-approval"),
            "host_id": "host-a",
            "profile_key": "git-production",
            "capability_kind": "GIT",
            "subject_key": "git",
            "observed_version": "2.51.0",
            "observed_sha256": "d" * 64,
            "operating_system": "windows",
            "architecture": "x86_64",
            "languages": ("ANY",),
            "operations": ("CLONE", "CHECKOUT"),
            "probe_status": "PASSED",
            "probe_evidence_refs": (raw_ref,),
            "security_control_evidence": (
                CapabilityControlEvidence(
                    control="SAFE_REPOSITORY_LOADER", evidence_ref=raw_ref
                ),
            ),
            "checked_at": datetime(2026, 9, 13, tzinfo=UTC),
            "checked_by": "gitterable",
            "checked_by_role": "R8",
            "decision": "ACTIVATE",
            "approved_at": datetime(2026, 9, 13, tzinfo=UTC),
            "approved_by": "taehyeon-git",
            "approved_by_role": "HUMAN",
            "approval_target_hash": capability_target_hash(profile),
            "safe_summary": "Git capability approved.",
        }
    )
    return (
        profile.model_copy(update={"capability_evidence_ref": reference(evidence)}),
        evidence,
    )


def _git_profile() -> RuntimeCapabilityProfile:
    return _git_capability()[0]


class _Resolver:
    def __init__(self, *, missing: tuple[str, str] | None = None) -> None:
        self.missing = missing
        self.selections = {
            (adapter, language): _static_selection(adapter, language)
            for language, adapters in {
                "PYTHON": ("PYTHON_AST", "CODEQL", "OPENGREP"),
                "JAVASCRIPT": ("CODEQL", "OPENGREP"),
            }.items()
            for adapter in adapters
        }
        self.pinned = {
            item.profile_ref: item.profile for item in self.selections.values()
        }
        self.git_profile, self.git_evidence = _git_capability()
        git_ref = reference(self.git_profile)
        assert isinstance(git_ref, HostConfigurationRef)
        self.git_ref = git_ref
        self.pinned[git_ref] = self.git_profile

    def resolve_active_static_tool(
        self, **values: str
    ) -> StaticToolCapabilitySelection:
        route = (values["adapter_key"], values["language"])
        if route == self.missing:
            raise LookupError("CAPABILITY_ROUTE_NOT_ACTIVE")
        return self.selections[route]

    def resolve_pinned_active_profile(
        self, profile_ref: HostConfigurationRef
    ) -> RuntimeCapabilityProfile | StaticToolProfile:
        return self.pinned[profile_ref]

    def resolve_active_capability(self, **values: str) -> RuntimeCapabilitySelection:
        assert values["capability_kind"] == "GIT"
        assert values["language"] == "ANY"
        assert values["operation"] in {"CLONE", "CHECKOUT"}
        return RuntimeCapabilitySelection(
            profile_ref=self.git_ref,
            profile=self.git_profile,
        )


def test_profile_uses_only_exact_tracked_files_and_detects_known_inputs(
    tmp_path: Path,
) -> None:
    tracked = (
        _write(tmp_path, "src/app.py", b"from fastapi import FastAPI\n"),
        _write(
            tmp_path,
            "pyproject.toml",
            b'[project]\nname="demo"\ndependencies=["fastapi>=0.100"]\n',
        ),
        _write(tmp_path, "Dockerfile", b"FROM python:3.12-slim\n"),
    )
    # An untracked package file must never influence detection.
    (tmp_path / "package.json").write_text('{"dependencies":{"express":"*"}}')

    result = _build(tmp_path, tracked)

    assert result.status == "READY"
    assert [item.name for item in result.languages] == ["PYTHON"]
    assert [item.name for item in result.frameworks] == ["FASTAPI"]
    assert [item.kind for item in result.config_files] == ["DOCKERFILE", "PYPROJECT"]
    assert tuple(item.git_path for item in result.tracked_files) == tuple(
        sorted(item.git_path for item in tracked)
    )
    assert all(len(item.content_sha256) == 64 for item in result.tracked_files)


def test_profile_fails_closed_when_a_tracked_blob_changed(tmp_path: Path) -> None:
    tracked = (_write(tmp_path, "app.py", b"print('safe')\n"),)
    (tmp_path / "app.py").write_text("print('changed')\n")

    with pytest.raises(ValueError, match="REPOSITORY_MANIFEST_MISMATCH"):
        RepositoryProfiler().build(
            _preparation(tmp_path, tracked),
            meta=_meta(),
            workspace_ref=_workspace_ref(),
            action_decision_ref=_decision_ref(),
        )


def test_unknown_or_ambiguous_build_is_not_guessed(tmp_path: Path) -> None:
    tracked = (_write(tmp_path, "README.md", b"custom build instructions"),)

    result = _build(tmp_path, tracked)

    assert result.status == "NEEDS_CONFIRMATION"
    assert result.languages == ()
    assert "LANGUAGE_UNCONFIRMED" in result.confirmation_reasons
    assert "BUILD_OR_START_UNCONFIRMED" in result.confirmation_reasons


def test_javascript_framework_uses_source_and_tracked_package_evidence(
    tmp_path: Path,
) -> None:
    tracked = (
        _write(tmp_path, "src/server.js", b"export const server = true;\n"),
        _write(
            tmp_path,
            "package.json",
            b'{"dependencies":{"express":"^5.0.0"},'
            b'"scripts":{"start":"node src/server.js"}}',
        ),
    )

    result = _build(tmp_path, tracked)

    assert result.status == "READY"
    assert [item.name for item in result.languages] == ["JAVASCRIPT"]
    assert [item.name for item in result.frameworks] == ["EXPRESS"]


def test_package_declaration_alone_does_not_guess_a_language(tmp_path: Path) -> None:
    tracked = (_write(tmp_path, "package.json", b'{"dependencies":{}}'),)

    result = _build(tmp_path, tracked)

    assert result.status == "NEEDS_CONFIRMATION"
    assert result.languages == ()
    assert result.confirmation_reasons == (
        "BUILD_OR_START_UNCONFIRMED",
        "LANGUAGE_UNCONFIRMED",
    )


def test_large_unrelated_tracked_file_is_hashed_without_becoming_config(
    tmp_path: Path,
) -> None:
    tracked = (
        _write(tmp_path, "app.py", b"print('ok')\n"),
        _write(tmp_path, "Dockerfile", b"FROM python:3.12-slim\n"),
        _write(tmp_path, "assets/video.bin", b"x" * (2 * 1024 * 1024 + 1)),
    )

    result = _build(tmp_path, tracked)

    assert result.status == "READY"
    large = next(
        item for item in result.tracked_files if item.git_path.endswith(".bin")
    )
    assert large.size_bytes > 2 * 1024 * 1024
    assert len(large.content_sha256) == 64


def test_profile_contract_rejects_manifest_or_evidence_tampering(
    tmp_path: Path,
) -> None:
    tracked = (
        _write(tmp_path, "app.py", b"print('ok')\n"),
        _write(tmp_path, "Dockerfile", b"FROM python:3.12-slim\n"),
    )
    result = _build(tmp_path, tracked)

    with pytest.raises(ValueError, match="REPOSITORY_PROFILE_MANIFEST_MISMATCH"):
        type(result).model_validate(result.model_dump() | {"manifest_hash": "f" * 64})
    language = result.languages[0].model_copy(update={"evidence_paths": ("other.py",)})
    with pytest.raises(ValueError, match="REPOSITORY_PROFILE_MANIFEST_MISMATCH"):
        type(result).model_validate(result.model_dump() | {"languages": (language,)})


def test_repository_preparation_gaps_are_preserved_and_require_confirmation(
    tmp_path: Path,
) -> None:
    tracked = (
        _write(tmp_path, "app.py", b"print('ok')\n"),
        _write(tmp_path, "Dockerfile", b"FROM python:3.12-slim\n"),
    )
    preparation = _preparation(tmp_path, tracked)
    preparation = replace(
        preparation,
        gaps=(
            CandidateGap(
                "REPOSITORY",
                "SUBMODULE_UNAVAILABLE",
                "UNSUPPORTED",
                "A tracked submodule was excluded.",
                ("vendor/module",),
                (),
                (),
                False,
            ),
        ),
    )

    result = RepositoryProfiler().build(
        preparation,
        meta=_meta(),
        workspace_ref=_workspace_ref(),
        action_decision_ref=_decision_ref(),
    )

    assert result.status == "NEEDS_CONFIRMATION"
    assert result.gaps[0].code == "SUBMODULE_UNAVAILABLE"
    assert "REPOSITORY_GAP:SUBMODULE_UNAVAILABLE" in result.confirmation_reasons


def test_python_selection_uses_exact_active_registry_refs(tmp_path: Path) -> None:
    tracked = (
        _write(tmp_path, "app.py", b"print('ok')\n"),
        _write(tmp_path, "requirements.txt", b""),
        _write(tmp_path, "Dockerfile", b"FROM python:3.12-slim\n"),
    )
    repository = _build(tmp_path, tracked)
    fake_resolver = _Resolver()
    resolver = cast(ProductionCapabilityResolverPort, fake_resolver)
    assert resolve_git_capability_refs(
        resolver,
        operating_system="windows",
        architecture="x86_64",
    ) == (fake_resolver.git_ref, fake_resolver.git_ref)
    selection = RepositoryExecutionSelector(
        resolver,
        operating_system="windows",
        architecture="x86_64",
    ).select(
        repository,
        meta=_selection_meta(),
        repository_profile_ref=cast(StoredDataRef, reference(repository)),
        git_clone_profile_ref=fake_resolver.git_ref,
        git_checkout_profile_ref=fake_resolver.git_ref,
    )

    assert selection.status == "READY"
    assert [item.adapter_key for item in selection.selected_tools] == [
        "CODEQL",
        "OPENGREP",
        "PYTHON_AST",
    ]
    selection_ref = cast(StoredDataRef, reference(selection))
    for tool in selection.selected_tools:
        assert static_tool_work_inputs(selection, selection_ref, tool) == (
            selection.repository_profile_ref,
            selection_ref,
            tool.tool_profile_ref,
        )


def test_tool_selection_blocks_when_required_capability_is_missing(
    tmp_path: Path,
) -> None:
    tracked = (
        _write(tmp_path, "app.py", b"print('ok')\n"),
        _write(tmp_path, "requirements.txt", b""),
        _write(tmp_path, "Dockerfile", b"FROM python:3.12-slim\n"),
    )
    repository = _build(tmp_path, tracked)

    fake_resolver = _Resolver(missing=("CODEQL", "PYTHON"))
    resolver = cast(ProductionCapabilityResolverPort, fake_resolver)
    selection = RepositoryExecutionSelector(
        resolver,
        operating_system="windows",
        architecture="x86_64",
    ).select(
        repository,
        meta=_selection_meta(),
        repository_profile_ref=cast(StoredDataRef, reference(repository)),
        git_clone_profile_ref=fake_resolver.git_ref,
        git_checkout_profile_ref=fake_resolver.git_ref,
    )

    assert selection.status == "BLOCKED"
    assert selection.selected_tools == ()
    assert [gap.code for gap in selection.gaps] == [
        "NO_ACTIVE_STATIC_CAPABILITY:CODEQL:PYTHON"
    ]
    assert selection.errors == ()


def test_registry_mismatch_fails_without_selecting_any_tool(tmp_path: Path) -> None:
    tracked = (
        _write(tmp_path, "app.js", b"console.log('ok')\n"),
        _write(
            tmp_path,
            "package.json",
            b'{"scripts":{"start":"node app.js"}}',
        ),
    )
    repository = _build(tmp_path, tracked)
    fake_resolver = _Resolver()
    stale = fake_resolver.selections[("CODEQL", "JAVASCRIPT")]
    del fake_resolver.pinned[stale.profile_ref]

    selection = RepositoryExecutionSelector(
        cast(ProductionCapabilityResolverPort, fake_resolver),
        operating_system="windows",
        architecture="x86_64",
    ).select(
        repository,
        meta=_selection_meta(),
        repository_profile_ref=cast(StoredDataRef, reference(repository)),
        git_clone_profile_ref=fake_resolver.git_ref,
        git_checkout_profile_ref=fake_resolver.git_ref,
    )

    assert selection.status == "FAILED"
    assert selection.selected_tools == ()
    assert selection.gaps == ()
    assert [error.code for error in selection.errors] == [
        "CAPABILITY_REGISTRY_MISMATCH"
    ]


def test_uncertain_profile_blocks_for_input_without_resolver_calls(
    tmp_path: Path,
) -> None:
    tracked = (_write(tmp_path, "README.md", b"Use a private build system.\n"),)
    repository = _build(tmp_path, tracked)
    fake_resolver = _Resolver()
    resolver = cast(ProductionCapabilityResolverPort, fake_resolver)
    selection = RepositoryExecutionSelector(
        resolver,
        operating_system="windows",
        architecture="x86_64",
    ).select(
        repository,
        meta=_selection_meta(),
        repository_profile_ref=cast(StoredDataRef, reference(repository)),
        git_clone_profile_ref=fake_resolver.git_ref,
        git_checkout_profile_ref=fake_resolver.git_ref,
    )

    assert selection.status == "BLOCKED"
    assert selection.selected_tools == ()
    assert {gap.code for gap in selection.gaps} == {
        "BUILD_OR_START_UNCONFIRMED",
        "LANGUAGE_UNCONFIRMED",
    }


@pytest.mark.parametrize(
    ("language_path", "config_path", "config", "dockerfile"),
    [
        ("app.py", "pyproject.toml", b'[project.scripts]\nserve="app:main"\n', False),
        ("app.py", "requirements.txt", b"fastapi\n", True),
        (
            "app.js",
            "package.json",
            b'{"scripts":{"start":"node app.js"}}',
            False,
        ),
        (
            "app.js",
            "package.json",
            b'{"scripts":{"start":"node app.js"}}',
            True,
        ),
    ],
)
def test_python_and_javascript_profiles_support_dockerfile_yes_or_no(
    tmp_path: Path,
    language_path: str,
    config_path: str,
    config: bytes,
    dockerfile: bool,
) -> None:
    tracked = [
        _write(tmp_path, language_path, b"print('ok')\n"),
        _write(tmp_path, config_path, config),
    ]
    if dockerfile:
        tracked.append(_write(tmp_path, "Dockerfile", b"FROM scratch\n"))

    profile = _build(tmp_path, tuple(tracked))

    assert profile.status == "READY"
    assert ("DOCKERFILE" in {item.kind for item in profile.config_files}) is dockerfile
