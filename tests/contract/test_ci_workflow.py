"""Static regression for shell contexts rejected by GitHub before job creation."""

import re
from pathlib import Path

import yaml  # type: ignore[import-untyped]


def test_ci_shell_positions_use_fixed_values() -> None:
    workflow = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
    shells = re.findall(
        r"^\s*shell:\s*(.+)$", workflow.read_text(encoding="utf-8"), re.MULTILINE
    )
    assert shells, "The workflow must select an explicit execution shell"
    for shell in shells:
        assert "${{" not in shell, (
            f"Use a fixed shell: GitHub rejects matrix context here: {shell}"
        )


def test_ci_requires_installed_wheel_smoke_on_both_supported_os_families() -> None:
    workflow = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
    document = yaml.load(workflow.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    jobs = document["jobs"]

    smoke = jobs["installed-wheel-smoke"]
    assert smoke["strategy"]["matrix"]["os"] == ["ubuntu-24.04", "windows-2022"]
    smoke_commands = "\n".join(
        step.get("run", "") for step in smoke["steps"] if isinstance(step, dict)
    )
    assert "scripts/wheel-smoke.ps1" in smoke_commands

    core = jobs["core"]
    assert "installed-wheel-smoke" in core["needs"]
    required = "\n".join(
        step.get("run", "") for step in core["steps"] if isinstance(step, dict)
    )
    assert "WHEEL_SMOKE_RESULT" in required
