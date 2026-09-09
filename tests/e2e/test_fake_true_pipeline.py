"""The fake slice must prove current validated PoC before publishing TRUE."""

import json
from collections import Counter
from pathlib import Path

import pytest

from sastsimi.bootstrap import build_fake_pipeline, load_fake_progress
from sastsimi.contracts.actions import ActionDecision, ActionRequest, RequesterRole
from sastsimi.contracts.dynamic import (
    DynamicReproductionRequest,
    PoCBundle,
    PoCCandidate,
    SandboxEnvironment,
)
from sastsimi.contracts.llm import LLMInvocationLog
from sastsimi.contracts.refs import reference
from sastsimi.contracts.reporting import ReportDraft
from sastsimi.contracts.static import RuleExecutionRecord, ToolRunResult
from sastsimi.contracts.verification import VerificationInitialAssessment
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.interfaces.cli.main import main
from sastsimi.ports.dto import Record


def test_final_true_without_current_validated_poc_is_rejected(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pipeline = build_fake_pipeline(tmp_path)
    with pytest.raises(LookupError):
        pipeline.analyze(scenario="TRUE_WITHOUT_POC")
    assert pipeline.runtime is not None
    assert pipeline.runtime.queries.current_records(
        "fake-analysis", "dynamic_reproduction_result"
    )
    assert (
        pipeline.runtime.queries.current_records("fake-analysis", "verification_result")
        == ()
    )
    with pytest.raises(LookupError, match="ANALYSIS_RESULT_NOT_FOUND"):
        pipeline.results()
    assert load_fake_progress(tmp_path)["status"] == "RUNNING"
    assert main(["--data-dir", str(tmp_path), "results", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)["data"]["status"] == "RUNNING"
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
    published = pipeline.runtime.queries.published_records("fake-analysis")
    actions = tuple(item for item in published if isinstance(item, ActionRequest))
    action_counts = Counter(action.action_type.value for action in actions)
    assert action_counts["RUN_TOOL"] == 2
    assert action_counts["FETCH_POLICY"] == 1
    assert action_counts["READ_CODE"] == 1
    assert action_counts["CALL_LLM"] >= 5
    assert action_counts["REQUEST_DYNAMIC_REPRO"] == 1
    assert action_counts["RUN_SANDBOX"] == 1
    assert action_counts["CALL_TECHNICAL_GATE"] == 1
    assert action_counts["CALL_RULE_SCOPE_GATE"] == 1
    assert action_counts["CREATE_REPORT_DRAFT"] == 1
    assert all("SUBMIT" not in action.action_type.value for action in actions)
    (final_action,) = tuple(
        action for action in actions if action.result_kind == "analysis_run_result"
    )
    final_decision = max(
        (
            item
            for item in published
            if isinstance(item, ActionDecision)
            and item.action_ref == reference(final_action)
        ),
        key=lambda item: item.meta.revision_number,
    )
    assert final_decision.use_status == "USED"
    assert final_decision.outcome_refs == (reference(result),)

    tool_runs = tuple(item for item in published if isinstance(item, ToolRunResult))
    assert {item.tool_kind for item in tool_runs} == {"STRUCTURE", "RULE_BASED"}
    assert sum(isinstance(item, RuleExecutionRecord) for item in published) == 1
    branch_works = {
        str(item.work_id): item
        for item in published
        if isinstance(item, WorkExecutionState)
        and item.work_type.value in {"STATIC_TOOL", "POLICY_FETCH"}
    }
    assert len(branch_works) == 3

    def record_sequence(item: Record) -> int:
        record_id = str(item.meta.record_id)
        return int(record_id.rsplit("-", 1)[1])

    first_branch_revision: dict[str, int] = {}
    for item in published:
        if isinstance(item, WorkExecutionState) and str(item.work_id) in branch_works:
            work_id = str(item.work_id)
            first_branch_revision[work_id] = min(
                record_sequence(item),
                first_branch_revision.get(work_id, record_sequence(item)),
            )
    first_external = min(
        record_sequence(action)
        for action in actions
        if action.action_type.value in {"RUN_TOOL", "FETCH_POLICY"}
    )
    assert all(sequence < first_external for sequence in first_branch_revision.values())
    (assessment,) = tuple(
        item for item in published if isinstance(item, VerificationInitialAssessment)
    )
    (dynamic_request,) = tuple(
        item for item in published if isinstance(item, DynamicReproductionRequest)
    )
    assert record_sequence(assessment) < record_sequence(dynamic_request)

    logs = tuple(item for item in published if isinstance(item, LLMInvocationLog))
    pro = next(item for item in logs if item.agent_role == "PRO")
    con = next(item for item in logs if item.agent_role == "CON")
    assert pro.context_refs == con.context_refs
    assert pro.session_policy == con.session_policy == "NEW"
    assert pro.session_ref != con.session_ref
    for log in logs:
        assert log.parsed_output_ref is not None
        assert log.exposed_response_ref is not None
        assert pipeline.runtime.unit_of_work.records.get_exact(log.parsed_output_ref)
        with pipeline.runtime.unit_of_work.artifacts.open_verified(
            log.exposed_response_ref
        ) as stream:
            assert stream.read()
    (poc,) = tuple(item for item in published if isinstance(item, PoCBundle))
    candidate = pipeline.runtime.unit_of_work.records.get_exact(poc.candidate_ref)
    assert isinstance(candidate, PoCCandidate)
    with pipeline.runtime.unit_of_work.artifacts.open_verified(
        candidate.content_ref
    ) as stream:
        assert stream.read()
    assert any(isinstance(item, SandboxEnvironment) for item in published)
    assert result.resources.work_count == len(result.work_state_refs)
    assert result.resources.attempt_count == len(result.work_attempt_refs)
    assert result.resources.llm_call_count == len(logs)
    assert result.resources.usage_complete is True
    assert result.resources.unavailable_reasons == ()
    assert result.hypothesis_counts == {
        "TOTAL": 1,
        "TERMINAL": 1,
        "PROPOSAL_TOTAL": 1,
        "REGISTERED": 1,
        "DUPLICATE": 0,
        "INVALID_OUTPUT": 0,
        "CANCELLED": 0,
        "DUPLICATE_UNIQUE": 0,
        "DUPLICATE_UNCERTAIN": 0,
        "CHECK_FAILED": 0,
        "INVALID_DUPLICATE_TARGET": 0,
    }
    assert result.gate_counts == {"ACCEPT": 1}
    assert result.errors == ()
    assert result.gaps == ()
    for field in type(result).model_fields:
        if field.endswith("_refs"):
            for item_ref in getattr(result, field):
                pipeline.runtime.unit_of_work.records.get_exact(item_ref)
    assert result.elapsed_ms == 0


def test_result_and_report_queries_reload_persisted_run(tmp_path: Path) -> None:
    pipeline = build_fake_pipeline(tmp_path)
    expected = pipeline.analyze(scenario="TRUE")
    reloaded = build_fake_pipeline(tmp_path)
    assert reloaded.results() == expected
    assert len(reloaded.reports()) == 1


def test_finalization_rejects_inventory_omission_then_retries_exactly(
    tmp_path: Path,
) -> None:
    scenario = build_fake_pipeline(tmp_path)._scenario
    verification = scenario._verification("TRUE")
    scenario._post_true(verification)
    candidate = scenario._result_candidate("TRUE")
    assert candidate.resources.pricing_revision_refs
    assert scenario.runtime is not None
    owner = next(
        ref
        for ref, role in scenario.evidence.identities.items()
        if ref.data_kind == "work_budget_profile"
    )
    scenario.evidence.identities[owner] = RequesterRole.ORCHESTRATION

    invalid_candidates = (
        (
            candidate.model_copy(update={"finding_refs": ()}),
            "RECORD_REVISION_MISMATCH",
        ),
        (
            candidate.model_copy(
                update={
                    "resources": candidate.resources.model_copy(
                        update={"pricing_revision_refs": ()}
                    )
                }
            ),
            "ANALYSIS_RESOURCE_SUMMARY_MISMATCH",
        ),
    )
    for invalid, expected_error in invalid_candidates:
        with pytest.raises(ValueError, match=expected_error):
            scenario.runtime.finalization.finalize(invalid)

        assert not any(
            isinstance(item, type(candidate))
            for item in scenario.runtime.queries.published_records("fake-analysis")
        )
    result_ref = scenario.runtime.finalization.finalize(candidate)
    assert scenario.runtime.finalization.finalize(candidate) == result_ref
