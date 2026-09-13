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
