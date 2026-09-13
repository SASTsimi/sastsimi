"""The installed wheel must carry the operator-facing runtime resources."""

from __future__ import annotations

import subprocess
import sys
import zipfile
from pathlib import Path


def test_wheel_contains_readme_and_operator_resources(tmp_path: Path) -> None:
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
        "sastsimi/resources/sastsimi.example.toml",
        "sastsimi/resources/docs/installation.md",
        "sastsimi/resources/docs/configuration.md",
        "sastsimi/resources/docs/usage.md",
        "sastsimi/resources/docs/external-tools.md",
        "sastsimi/resources/docs/troubleshooting.md",
        "sastsimi/resources/docs/architecture-to-code.md",
        "sastsimi/prompts/registry.py",
        "sastsimi/prompts/templates/verification/final-verdict/1.0.0.md",
        "sastsimi/storage/alembic/versions/0005_chaining_matches.py",
    }
    assert required <= names
    assert "Description-Content-Type: text/markdown" in metadata
    assert "SASTSIMI" in metadata
    assert str(root) not in metadata


def test_operator_examples_do_not_embed_secrets_or_local_absolute_paths() -> None:
    root = Path(__file__).resolve().parents[2]
    paths = (
        root / "README.md",
        root / "config" / "sastsimi.example.toml",
        root / "docs" / "installation.md",
        root / "docs" / "configuration.md",
        root / "docs" / "usage.md",
        root / "docs" / "external-tools.md",
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
