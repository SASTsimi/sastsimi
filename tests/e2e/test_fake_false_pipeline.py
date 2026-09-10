"""The fake slice retains falsification evidence for FALSE."""

from pathlib import Path

import pytest

from sastsimi.bootstrap import build_fake_pipeline
from sastsimi.contracts.verification import VerificationResult


def test_false_pipeline_closes_with_disproved_falsification(tmp_path: Path) -> None:
    pipeline = build_fake_pipeline(tmp_path)
    result = pipeline.analyze(scenario="FALSE")
    assert result.status == "COMPLETE"
    assert result.verdict_counts == {"FALSE": 1}
    assert len(result.verification_refs) == 1
    assert pipeline.reports() == ()
    assert pipeline.runtime is not None
    (verification,) = pipeline.runtime.queries.current_records(
        "fake-analysis", "verification_result"
    )
    assert isinstance(verification, VerificationResult)
    malformed = verification.model_dump()
    malformed["falsification_results"][0]["evidence_refs"] = ()
    with pytest.raises(ValueError, match="EVIDENCE_REQUIRED"):
        VerificationResult.model_validate(malformed)
