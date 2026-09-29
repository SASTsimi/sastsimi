"""The static bootstrap reads only a tracked, bounded repository policy."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from sastsimi.composition.simple_process import LocalProcessExecutor
from sastsimi.config.user_config import SimpleExecutionProfile, SimpleToolBinding
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime import bootstrap_stages
from sastsimi.simple_runtime.application import SimpleAnalysisRequest
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.github_policy import DiscoveredPolicy
from sastsimi.simple_runtime.models import CheckpointIdentity
from sastsimi.simple_runtime.static_coverage import CoverageSlice
from sastsimi.simple_runtime.store import SimpleCheckpointStore
from tests.integration.runtime_support import TestClock


def test_tracked_github_security_policy_wins_over_other_locations(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    (root / ".github").mkdir(parents=True)
    (root / "docs").mkdir()
    (root / "SECURITY.md").write_text("Root reporting rule", encoding="utf-8")
    (root / ".github" / "SECURITY.md").write_text(
        "GitHub reporting rule", encoding="utf-8"
    )
    (root / "docs" / "SECURITY.md").write_text("Docs reporting rule", encoding="utf-8")

    result = bootstrap_stages._security_policy(
        root,
        ("docs/SECURITY.md", ".github/SECURITY.md", "SECURITY.md"),
    )

    assert result is not None
    assert result["path"] == ".github/SECURITY.md"
    assert result["content"] == "GitHub reporting rule"


def test_untracked_or_empty_security_policy_is_not_collected(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "SECURITY.md").write_text("untracked rule", encoding="utf-8")
    assert bootstrap_stages._security_policy(root, ("app.py",)) is None

    (root / "SECURITY.md").write_text(" \n", encoding="utf-8")
    assert bootstrap_stages._security_policy(root, ("SECURITY.md",)) is None


def test_security_policy_rejects_oversized_file_and_external_symlink(
    tmp_path: Path,
) -> None:
    root = tmp_path / "repo"
    root.mkdir()
    (root / "SECURITY.md").write_bytes(b"x" * (256 * 1024 + 1))
    assert bootstrap_stages._security_policy(root, ("SECURITY.md",)) is None

    outside = tmp_path / "outside.md"
    outside.write_text("external policy", encoding="utf-8")
    (root / "SECURITY.md").unlink()
    try:
        os.symlink(outside, root / "SECURITY.md")
    except OSError:
        pytest.skip("Windows symlink privilege is unavailable")
    assert bootstrap_stages._security_policy(root, ("SECURITY.md",)) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["FOUND", "ABSENT", "FETCH_FAILED"])
async def test_static_bootstrap_persists_exact_policy_snapshot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, status: str
) -> None:
    body = b"# Reporting rules\n" if status == "FOUND" else None
    clock = TestClock()
    scanner = tmp_path / "mock-opengrep"
    scanner.write_bytes(b"mock scanner")
    rules = tmp_path / "opengrep" / "rules.yml"
    rules.parent.mkdir(parents=True)
    rules.write_text(
        "rules:\n  - id: python.test\n    languages: [python]\n", encoding="utf-8"
    )

    class Discovery:
        calls = 0

        async def discover(self, _repository_url: str) -> DiscoveredPolicy:
            self.calls += 1
            return DiscoveredPolicy(
                status=status,  # type: ignore[arg-type]
                reason_code=f"POLICY_{status}",
                owner="acme",
                repo="app",
                publisher="acme/app" if body else None,
                source_url="https://api.github.com/repos/acme/app/contents/SECURITY.md?ref=main"
                if body
                else None,
                source_path="SECURITY.md" if body else None,
                blob_sha="a" * 40 if body else None,
                etag='"v1"' if body else None,
                content_type="text/markdown" if body else None,
                checked_at=clock.now(),
                sha256=hashlib.sha256(body).hexdigest() if body else None,
                body=body,
            )

    profile = SimpleExecutionProfile(
        provider_profile_ref="test",
        provider="openai",
        model="test-model",
        auth_mode="API_KEY",
        credential_ref="env:OPENAI_API_KEY",
        data_dir=tmp_path,
        workspace_root=tmp_path / "workspaces",
        max_cost_minor_units=100,
        max_tokens=1000,
        max_elapsed_seconds=3600,
        docker_network="NONE",
        tools={
            "opengrep": SimpleToolBinding(
                executable_path=scanner,
                version="test",
                executable_sha256=hashlib.sha256(b"mock scanner").hexdigest(),
            )
        },
    )
    discovery = Discovery()
    bootstrap = bootstrap_stages.DirectStaticBootstrap(
        profile=profile,
        process=LocalProcessExecutor(),
        store=SimpleCheckpointStore(tmp_path / "db" / "sastsimi.sqlite3"),
        policy_discovery=discovery,
        static_material_root=tmp_path,
    )

    async def no_repository(_request: object, _workspace: object) -> None:
        return None

    async def no_workspace_verification(_workspace: object, _request: object) -> None:
        return None

    async def no_files(_workspace: object) -> tuple[str, ...]:
        return ()

    async def no_scan(
        *_args: object,
    ) -> tuple[list[CoverageSlice], list[StoredDataRef], list[str]]:
        return [], [], []

    monkeypatch.setattr(bootstrap, "_prepare_repository", no_repository)
    monkeypatch.setattr(
        bootstrap, "_verify_opengrep_workspace", no_workspace_verification
    )
    monkeypatch.setattr(bootstrap, "_tracked_files", no_files)
    monkeypatch.setattr(
        bootstrap, "_repository_profile", lambda _tracked, **_kwargs: {}
    )
    monkeypatch.setattr(
        bootstrap, "_python_ast", lambda _workspace, _tracked, _artifacts: {}
    )
    monkeypatch.setattr(bootstrap, "_collect_opengrep", no_scan)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )

    with pytest.raises(
        bootstrap_stages.StaticCoverageBlocked, match="NO_PYTHON_SOURCE"
    ) as caught:
        await bootstrap.run(
            SimpleAnalysisRequest(
                data_dir=tmp_path,
                repository="https://github.com/acme/app",
                commit="a" * 40,
            ),
            identity,
        )

    assert discovery.calls == 1
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    bundle = json.loads(artifacts.read(caught.value.bundle_ref))
    snapshot_ref = StoredDataRef.model_validate(bundle["policy_snapshot_ref"])
    snapshot = json.loads(artifacts.read(snapshot_ref))
    assert snapshot["kind"] == "simple_policy_snapshot"
    assert snapshot["analysis_id"] == "analysis-1"
    assert snapshot["status"] == status
    if body is not None:
        assert (
            artifacts.read(StoredDataRef.model_validate(snapshot["body_ref"])) == body
        )
    else:
        assert snapshot["body_ref"] is None
