"""The fake slice must prove current validated PoC before publishing TRUE."""

from pathlib import Path

import pytest

from sastsimi.bootstrap import build_fake_pipeline
from sastsimi.contracts.actions import ActionRequest
from sastsimi.contracts.reporting import ReportDraft


def test_final_true_without_current_validated_poc_is_rejected(tmp_path: Path) -> None:
    pipeline = build_fake_pipeline(tmp_path)
    with pytest.raises(ValueError, match="POC"):
        pipeline.analyze(scenario="TRUE_WITHOUT_POC")
    assert pipeline.results().verdict_counts.get("TRUE", 0) == 0
    assert pipeline.reports() == ()


def test_true_pipeline_closes_exact_report_without_submission(tmp_path: Path) -> None:
    pipeline = build_fake_pipeline(tmp_path)
    result = pipeline.analyze(scenario="TRUE")
    assert result.status == "COMPLETE"
    assert result.verdict_counts == {"TRUE": 1}
    assert len(result.finding_refs) == 1
    assert len(result.report_draft_refs) == 1
    assert len(result.poc_refs) == 1
    assert pipeline.runtime is not None
    (report,) = pipeline.reports()
    assert isinstance(report, ReportDraft)
    actions = (
        item
        for item in pipeline.runtime.queries.published_records("fake-analysis")
        if isinstance(item, ActionRequest)
    )
    assert all("SUBMIT" not in action.action_type.value for action in actions)


def test_result_and_report_queries_reload_persisted_run(tmp_path: Path) -> None:
    pipeline = build_fake_pipeline(tmp_path)
    expected = pipeline.analyze(scenario="TRUE")
    reloaded = build_fake_pipeline(tmp_path)
    assert reloaded.results() == expected
    assert len(reloaded.reports()) == 1
