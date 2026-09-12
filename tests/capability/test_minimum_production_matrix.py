from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import cast

import pytest

from sastsimi.capabilities import build_production_capability_probe_service
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.static import RepositoryProfile
from sastsimi.ports.capability_registry import ProductionCapabilityResolverPort
from sastsimi.static_analysis.repository_profile import RepositoryExecutionSelector

from ..unit.static_analysis.test_repository_profile import (
    _build,
    _Resolver,
    _selection_meta,
    _write,
)

FIXTURES = Path(__file__).parents[1] / "fixtures" / "capabilities"


def _profile_fixture(tmp_path: Path, name: str) -> RepositoryProfile:
    source = FIXTURES / name
    tracked = tuple(
        _write(
            tmp_path,
            path.relative_to(source).as_posix(),
            path.read_bytes(),
        )
        for path in sorted(source.rglob("*"))
        if path.is_file()
    )
    return _build(tmp_path, tracked)


@pytest.mark.parametrize(
    ("fixture", "language", "configs", "selected"),
    (
        (
            "python-existing-dockerfile",
            "PYTHON",
            {"DOCKERFILE", "REQUIREMENTS"},
            ["OPENGREP", "PYTHON_AST"],
        ),
        (
            "javascript-generated-dockerfile",
            "JAVASCRIPT",
            {"PACKAGE_JSON"},
            ["OPENGREP"],
        ),
    ),
)
def test_repository_fixtures_select_only_verified_active_tool_intersection(
    tmp_path: Path,
    fixture: str,
    language: str,
    configs: set[str],
    selected: list[str],
) -> None:
    """Catches untracked inference and inactive CodeQL becoming executable."""

    repository = _profile_fixture(tmp_path, fixture)
    resolver = _Resolver(missing=("CODEQL", language))
    selection = RepositoryExecutionSelector(
        cast(ProductionCapabilityResolverPort, resolver),
        operating_system="windows",
        architecture="x86_64",
    ).select(
        repository,
        meta=_selection_meta(),
        repository_profile_ref=cast(StoredDataRef, reference(repository)),
        git_clone_profile_ref=resolver.git_ref,
        git_checkout_profile_ref=resolver.git_ref,
    )

    assert repository.status == "READY"
    assert [item.name for item in repository.languages] == [language]
    assert {item.kind for item in repository.config_files} == configs
    assert selection.status == "READY"
    assert [item.adapter_key for item in selection.selected_tools] == selected
    assert [item.reason for item in selection.gaps] == ["MISSING"]
    assert [item.code for item in selection.gaps] == [
        f"NO_ACTIVE_STATIC_CAPABILITY:CODEQL:{language}"
    ]


def test_public_python_probe_approves_exact_active_profile(tmp_path: Path) -> None:
    """Exercise the public service with the actual running AST parser."""

    service = build_production_capability_probe_service(
        tmp_path,
        host_id="t16-python-acceptance-host",
        executable_paths={},
        docker_host=None,
    )
    receipt = service.probe("PYTHON_AST")

    assert receipt.status == "PASSED"
    assert receipt.activation_supported is True
    assert receipt.approval_target_hash is not None
    profile_ref = service.approve(
        receipt.probe_id,
        expected_target_hash=receipt.approval_target_hash,
    )
    assert service.resolve_executable(profile_ref) == Path(sys.executable).resolve(
        strict=True
    )


def test_public_git_probe_approves_exact_active_profile(tmp_path: Path) -> None:
    """Exercise the public service with an explicitly configured trusted Git."""

    configured = os.environ.get("SASTSIMI_T16_GIT")
    if configured is None:
        pytest.skip("set SASTSIMI_T16_GIT to run the host capability acceptance")
    git = Path(configured)
    service = build_production_capability_probe_service(
        tmp_path,
        host_id="t16-acceptance-host",
        executable_paths={"git": git},
        docker_host=None,
    )

    receipt = service.probe("GIT")

    assert receipt.status == "PASSED"
    assert receipt.activation_supported is True
    assert receipt.approval_target_hash is not None
    profile_ref = service.approve(
        receipt.probe_id,
        expected_target_hash=receipt.approval_target_hash,
    )
    assert service.resolve_executable(profile_ref) == git.resolve(strict=True)
