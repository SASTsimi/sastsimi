"""The static bootstrap reads only a tracked, bounded repository policy."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from sastsimi.config.user_config import SimpleExecutionProfile
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.simple_runtime import bootstrap_stages
from sastsimi.simple_runtime.application import SimpleAnalysisRequest
from sastsimi.simple_runtime.artifacts import SimpleArtifactRepository
from sastsimi.simple_runtime.github_policy import DiscoveredPolicy
from sastsimi.simple_runtime.models import CheckpointIdentity
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
        tools={},
    )
    discovery = Discovery()
    bootstrap = bootstrap_stages.DirectStaticBootstrap(
        profile=profile, policy_discovery=discovery, static_material_root=tmp_path
    )

    async def no_repository(_request: object, _workspace: object) -> None:
        return None

    async def no_files(_workspace: object) -> tuple[str, ...]:
        return ()

    async def opengrep(_workspace: object, _data_dir: object, _id: object) -> bytes:
        return b'{"results": []}'

    monkeypatch.setattr(bootstrap, "_prepare_repository", no_repository)
    monkeypatch.setattr(bootstrap, "_tracked_files", no_files)
    monkeypatch.setattr(bootstrap, "_repository_profile", lambda _tracked: {})
    monkeypatch.setattr(bootstrap, "_python_ast", lambda _workspace, _tracked: {})
    monkeypatch.setattr(bootstrap, "_run_opengrep", opengrep)
    identity = CheckpointIdentity(
        analysis_id="analysis-1",
        workspace_id="workspace-1",
        commit_id="a" * 40,
        hypothesis_id=None,
    )

    result = await bootstrap.run(
        SimpleAnalysisRequest(
            data_dir=tmp_path,
            repository="https://github.com/acme/app",
            commit="a" * 40,
        ),
        identity,
    )

    assert discovery.calls == 1
    assert result.policy_snapshot_ref is not None
    artifacts = SimpleArtifactRepository(tmp_path, identity)
    snapshot = json.loads(artifacts.read(result.policy_snapshot_ref))
    assert snapshot["kind"] == "simple_policy_snapshot"
    assert snapshot["analysis_id"] == "analysis-1"
    assert snapshot["status"] == status
    if body is not None:
        assert (
            artifacts.read(StoredDataRef.model_validate(snapshot["body_ref"])) == body
        )
    else:
        assert snapshot["body_ref"] is None
