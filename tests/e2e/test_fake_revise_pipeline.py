"""Technical REVISE starts a same-owner fresh canonical generation."""

from pathlib import Path

from sastsimi.bootstrap import build_fake_pipeline
from sastsimi.contracts.dynamic import DynamicReproductionResult
from sastsimi.contracts.gates import CWELabel, TechnicalEvidenceReview
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    VerificationAssignment,
)
from sastsimi.storage.codec import reference


def test_revise_requires_new_generation_dynamic_poc_and_cwe(tmp_path: Path) -> None:
    pipeline = build_fake_pipeline(tmp_path)
    result = pipeline.analyze(scenario="REVISE")
    assert result.status == "COMPLETE"
    assert result.verdict_counts == {"TRUE": 1}
    assert result.gate_counts == {"ACCEPT": 1, "REVISE": 1}
    assert pipeline.runtime is not None
    (process,) = pipeline.runtime.queries.current_records(
        "fake-analysis", "hypothesis_process_state"
    )
    (assignment,) = pipeline.runtime.queries.current_records(
        "fake-analysis", "verification_assignment"
    )
    (label,) = pipeline.runtime.queries.current_records("fake-analysis", "cwe_label")
    dynamics = tuple(
        item
        for item in pipeline.runtime.queries.current_records(
            "fake-analysis", "dynamic_reproduction_result"
        )
        if isinstance(item, DynamicReproductionResult)
    )
    reviews = tuple(
        item
        for item in pipeline.runtime.queries.published_records("fake-analysis")
        if isinstance(item, TechnicalEvidenceReview)
    )
    assert isinstance(process, HypothesisProcessState)
    assert isinstance(assignment, VerificationAssignment)
    assert isinstance(label, CWELabel)
    assert process.verification_generation == 2
    assert process.verification_assignment_ref == reference(assignment)
    assert len(dynamics) == 2
    assert {item.meta.attempt_id for item in dynamics}.__len__() == 2
    assert label.verification_generation == 2
    assert {item.status for item in reviews} == {"REVISE", "ACCEPT"}
