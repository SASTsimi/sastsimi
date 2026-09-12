"""Keep the R7 prompt and validation handoff executable in CI."""

import runpy
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize(
    "mutation", ["target", "value", "value_from", "scope", "producer", "wildcard"]
)
def test_lifecycle_assertion_rejects_mutation(mutation: str) -> None:
    root = Path(__file__).resolve().parents[2]
    validator = runpy.run_path(str(root / "scripts/validate-r7-handoff.py"))
    fixtures = root / "docs/handoff/R7/validation"
    case = validator["load_json"](fixtures / "environment-ready.input.json")
    expected = validator["load_json"](fixtures / "environment-ready.expected.json")
    validator["validate_lifecycle_assertions"](case, expected)
    if mutation == "target":
        expected["assertions"][1]["target"] = "UNKNOWN_RECORD"
    elif mutation == "value":
        expected["assertions"][1]["value"] = "WRONG_PRODUCER"
    elif mutation == "value_from":
        expected["assertions"][1]["value_from"] = "DQ1.missing_field"
    elif mutation == "scope":
        expected["expected_record_projections"]["ENV1"]["fields"]["scope"] = {
            "attempt_id": "OLD"
        }
    elif mutation == "producer":
        expected["expected_record_projections"]["ENV1"]["producer"] = "WRONG_PRODUCER"
    else:
        expected["expected_record_projections"]["ENV1"]["fields"]["checks"] = []
    with pytest.raises(validator["ValidationFailure"]):
        validator["validate_lifecycle_assertions"](case, expected)


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
