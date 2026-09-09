"""Static regression for shell contexts rejected by GitHub before job creation."""

import re
from pathlib import Path


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
