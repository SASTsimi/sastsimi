"""Technical REVISE starts a same-owner fresh canonical generation."""

from pathlib import Path

from sastsimi.bootstrap import build_fake_pipeline
from sastsimi.contracts.dynamic import DynamicReproductionResult
from sastsimi.contracts.gates import CWELabel, TechnicalEvidenceReview
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    VerificationAssignment,
)
from sastsimi.contracts.llm import LLMInvocationLog
from sastsimi.contracts.verification import (
    ConEvidenceResult,
    ProEvidenceResult,
    VerificationResult,
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
    logs = tuple(
        item
        for item in pipeline.runtime.queries.published_records("fake-analysis")
        if isinstance(item, LLMInvocationLog)
    )
    assert len({item.llm_call_id for item in logs}) == len(logs)
    assert len({item.session_ref for item in logs}) == len(logs)
    assert process.verification_result_ref is not None
    current_verification = pipeline.runtime.unit_of_work.records.get_exact(
        process.verification_result_ref
    )
    assert isinstance(current_verification, VerificationResult)
    assert current_verification.pro_evidence_ref is not None
    assert current_verification.con_evidence_ref is not None
    current_pro = pipeline.runtime.unit_of_work.records.get_exact(
        current_verification.pro_evidence_ref
    )
    current_con = pipeline.runtime.unit_of_work.records.get_exact(
        current_verification.con_evidence_ref
    )
    assert isinstance(current_pro, ProEvidenceResult)
    assert isinstance(current_con, ConEvidenceResult)
    synthesis = next(
        item
        for item in logs
        if item.agent_role == "VERIFICATION"
        and item.context_refs.count(reference(current_pro)) == 1
        and item.context_refs.count(reference(current_con)) == 1
    )
    assert synthesis.context_refs.count(reference(current_pro)) == 1
    assert synthesis.context_refs.count(reference(current_con)) == 1
