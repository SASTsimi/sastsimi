"""Keep the R7 prompt and validation handoff executable in CI."""

import subprocess
import sys
from pathlib import Path


def test_r7_handoff_validation_script() -> None:
    root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, "scripts/validate-r7-handoff.py"],
        cwd=root,
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "5 templates, 25 prompt cases, 4 lifecycle pairs" in result.stdout
