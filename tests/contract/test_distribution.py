"""The installed wheel must carry the operator-facing runtime resources."""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path


def test_wheel_contains_runtime_resources(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[2]
    output = tmp_path / "dist"
    subprocess.run(
        [
            sys.executable,
            "-m",
            "hatchling",
            "build",
            "-t",
            "wheel",
            "-d",
            str(output),
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    (wheel,) = output.glob("sastsimi-*.whl")

    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
        metadata_name = next(
            name for name in names if name.endswith(".dist-info/METADATA")
        )
        metadata = archive.read(metadata_name).decode("utf-8")

    required = {
        "sastsimi/prompts/registry.py",
        "sastsimi/prompts/templates/verification/final-verdict/1.0.0.md",
        "sastsimi/storage/alembic/versions/0008_cancellation_observations.py",
        "sastsimi/_static/candidate-v1/opengrep/rules.yml",
        "sastsimi/_static/candidate-v1/codeql/python-security.qls",
        "sastsimi/dashboard/static/index.html",
    }
    assert required <= names
    assert "Description-Content-Type: text/markdown" in metadata
    assert "SASTSIMI" in metadata
    assert str(root) not in metadata


def test_operator_examples_do_not_embed_secrets_or_local_absolute_paths() -> None:
    root = Path(__file__).resolve().parents[2]
    paths = (
        root / "README.md",
        root / "config" / "profiles" / "production.example.toml",
        root / "docs" / "installation.md",
        root / "docs" / "provider-setup.md",
        root / "docs" / "usage.md",
        root / "docs" / "onboarding-evidence.md",
        root / "docs" / "troubleshooting.md",
        root / "docs" / "architecture-to-code.md",
        root / "scripts" / "wheel-smoke.ps1",
    )
    forbidden = (
        "C:/Users/",
        "C:\\Users\\",
        "/Users/",
        "/home/",
        "-----BEGIN PRIVATE KEY-----",
        "sk-proj-",
        "ghp_",
        "https://user:password@",
    )
    violations = [
        f"{path.relative_to(root)}: {marker}"
        for path in paths
        for marker in forbidden
        if marker in path.read_text(encoding="utf-8")
    ]
    assert not violations, "\n".join(violations)


def test_readme_first_screen_contains_the_real_operator_path() -> None:
    root = Path(__file__).resolve().parents[2]
    readme = (root / "README.md").read_text(encoding="utf-8")
    first_screen = readme.split("## 전체 분석 흐름", maxsplit=1)[0]

    for required in (
        "Python 3.12",
        "uv sync --frozen",
        "OPENAI_API_KEY",
        "codex login",
        "CodeQL",
        "OpenGrep",
        "Docker",
        "sastsimi setup",
        "sastsimi analyze",
        "sastsimi status A-001",
        "sastsimi resume A-001",
        "sastsimi dashboard",
        "sastsimi report F-001 --export markdown",
        "docs/troubleshooting.md",
    ):
        assert required in first_screen


def test_operator_docs_link_official_openai_authentication() -> None:
    root = Path(__file__).resolve().parents[2]
    provider = (root / "docs" / "provider-setup.md").read_text(encoding="utf-8")

    assert "https://developers.openai.com/api/docs/quickstart" in provider
    assert "https://developers.openai.com/codex/auth" in provider
