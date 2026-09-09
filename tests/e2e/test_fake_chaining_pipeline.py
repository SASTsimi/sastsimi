"""The optional child flow closes deterministically at a no-match result."""

from pathlib import Path

from sastsimi.bootstrap import build_fake_pipeline
from sastsimi.contracts.chaining import ChainingResult, PrimitiveIndexState


def test_chaining_no_match_uses_the_current_primitive_snapshot(tmp_path: Path) -> None:
    pipeline = build_fake_pipeline(tmp_path)
    result = pipeline.analyze(scenario="CHAINING")
    assert result.status == "COMPLETE"
    assert pipeline.runtime is not None
    (chaining,) = pipeline.runtime.queries.current_records(
        "fake-analysis", "chaining_result"
    )
    (index,) = pipeline.runtime.queries.current_records(
        "fake-analysis", "primitive_index_state"
    )
    assert isinstance(chaining, ChainingResult)
    assert isinstance(index, PrimitiveIndexState)
    assert chaining.considered_primitive_refs == index.primitive_refs
    assert chaining.primitive_match_candidates == ()
    assert chaining.chained_hypothesis_proposals == ()
    assert chaining.no_match_reasons[0].reason_code == "ENTITY_UNRELATED"
