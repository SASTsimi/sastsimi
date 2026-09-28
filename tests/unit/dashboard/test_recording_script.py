"""PowerShell recording script contracts; no screen capture is started in tests."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "record-dashboard.ps1"


def _run(
    tmp_path: Path,
    *extra: str,
    url: str = "http://127.0.0.1:8765/",
    output_path: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    shell = shutil.which("pwsh") or shutil.which("powershell.exe")
    if shell is None:
        pytest.skip("PowerShell is unavailable")
    return subprocess.run(
        [
            shell,
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(_SCRIPT),
            "-Url",
            url,
            "-OutputPath",
            str(output_path or tmp_path / "demo.mp4"),
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )


def test_record_dry_run_is_bounded_and_does_not_create_video(tmp_path: Path) -> None:
    fake_ffmpeg = tmp_path / "ffmpeg.exe"
    fake_ffmpeg.write_bytes(b"test fixture")
    result = _run(
        tmp_path, "-FfmpegPath", str(fake_ffmpeg), "-DurationSeconds", "12", "-DryRun"
    )
    assert result.returncode == 0, result.stderr
    assert "gdigrab" in result.stdout
    assert "12" in result.stdout
    assert not (tmp_path / "demo.mp4").exists()


def test_record_rejects_non_loopback_and_non_mp4(tmp_path: Path) -> None:
    bad_url = _run(
        tmp_path,
        "-FfmpegPath",
        str(tmp_path / "ffmpeg.exe"),
        "-DryRun",
        url="https://example.com/",
    )
    assert bad_url.returncode != 0
    assert "loopback" in (bad_url.stderr + bad_url.stdout).lower()
    bad_extension = _run(
        tmp_path,
        "-DryRun",
        output_path=tmp_path / "demo.avi",
    )
    assert bad_extension.returncode != 0
    assert "mp4" in (bad_extension.stderr + bad_extension.stdout).lower()


def test_record_rejects_missing_ffmpeg(tmp_path: Path) -> None:
    result = _run(
        tmp_path, "-FfmpegPath", str(tmp_path / "missing-ffmpeg.exe"), "-DryRun"
    )
    assert result.returncode != 0
    assert "ffmpeg" in (result.stderr + result.stdout).lower()
