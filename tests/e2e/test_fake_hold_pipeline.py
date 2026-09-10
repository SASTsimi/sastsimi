"""The fake slice retains unresolved conditions for HOLD."""

from pathlib import Path

import pytest

from sastsimi.bootstrap import build_fake_pipeline
from sastsimi.contracts.verification import VerificationResult


def test_hold_pipeline_requires_an_unresolved_condition(tmp_path: Path) -> None:
    pipeline = build_fake_pipeline(tmp_path)
    result = pipeline.analyze(scenario="HOLD")
    assert result.status == "COMPLETE"
    assert result.verdict_counts == {"HOLD": 1}
    assert pipeline.runtime is not None
    (verification,) = pipeline.runtime.queries.current_records(
        "fake-analysis", "verification_result"
    )
    assert isinstance(verification, VerificationResult)
    assert verification.unresolved_conditions == ("Reachability",)
    with pytest.raises(ValueError, match="HOLD_CONDITIONS_REQUIRED"):
        VerificationResult.model_validate(
            verification.model_dump() | {"unresolved_conditions": ()}
        )
