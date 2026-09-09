from typing import Any

import pytest
from pydantic import ValidationError

from .fixtures import meta, mutations, ref, wire


def test_usage_absent_tokens_do_not_invent_cost() -> None:
    from sastsimi.contracts.evaluation import UsageMeasurement

    value: dict[str, Any] = dict(
        token_source="UNAVAILABLE",
        input_tokens=None,
        output_tokens=None,
        total_tokens=None,
        token_unavailable_reason="Provider did not report",
        provider_units={},
        cost_source="UNAVAILABLE",
        cost_minor_units=None,
        currency=None,
        pricing_revision_ref=None,
        cost_unavailable_reason="Price unknown",
    )
    wire(UsageMeasurement, value)
    for patch in mutations(
        dict(total_tokens=0),
        dict(cost_minor_units=0),
        dict(token_unavailable_reason=None),
    ):
        with pytest.raises(ValidationError):
            wire(UsageMeasurement, value | patch)
    known = value | dict(
        token_source="PROVIDER_REPORTED",
        input_tokens=2,
        output_tokens=3,
        total_tokens=5,
        token_unavailable_reason=None,
    )
    wire(UsageMeasurement, known)
    with pytest.raises(ValidationError):
        wire(UsageMeasurement, known | {"total_tokens": 6})


def test_evaluation_comparison_pins_config_revisions() -> None:
    from sastsimi.contracts.evaluation import (
        EvaluationRunConfig,
        validate_evaluation_comparison,
    )

    budget = dict(
        stored_data_id="b1",
        data_kind="execution_budget_profile",
        record_id="b1",
        content_hash="b" * 64,
        analysis_id="a1",
    )
    value: dict[str, Any] = dict(
        meta=meta("evaluation_run_config", attempt=None),
        evaluation_config_id="eval1",
        comparison_group_id="g1",
        corpus_refs=[ref("corpus")],
        ground_truth_refs=[ref("truth")],
        grader_refs=[ref("grader")],
        provider_profile_ref=ref("provider_profile"),
        model="model-a",
        session_policy="NEW",
        prompt_registry_entry_ref=ref("prompt_registry_entry"),
        execution_budget_profile_ref=budget,
        output_schema_ref=ref("schema"),
    )
    first = wire(EvaluationRunConfig, value)
    second = wire(EvaluationRunConfig, value | {"model": "model-b"})
    validate_evaluation_comparison(first, second, varying_axes=frozenset({"model"}))
    with pytest.raises(ValueError, match="EVALUATION_CONFIG_MISMATCH"):
        validate_evaluation_comparison(
            first,
            wire(
                EvaluationRunConfig,
                value | {"corpus_refs": [ref("corpus") | {"content_hash": "c" * 64}]},
            ),
            varying_axes=frozenset({"model"}),
        )


def test_failed_hypotheses_cannot_be_complete_run() -> None:
    from sastsimi.contracts.evaluation import AnalysisRunResult

    value: dict[str, Any] = dict(
        meta=meta("analysis_run_result", run=True),
        purpose="PRODUCTION",
        repository_url="https://example.org/repo",
        program_id="program1",
        workspace_id=None,
        commit_id=None,
        workspace_ref=None,
        status="FAILED",
        hypothesis_counts={},
        failed_hypothesis_count=0,
        verdict_counts={},
        gate_counts={},
        run_policy_state_ref=None,
        stop_reasons=["CHECKOUT_FAILED"],
        errors=[],
        gaps=[],
        resources=dict(
            elapsed_ms=1,
            work_count=1,
            attempt_count=1,
            retry_count=0,
            llm_call_count=0,
            dynamic_attempt_count=0,
            cost_minor_units=0,
            currency="USD",
            pricing_revision_refs=[],
            usage_measurement_refs=[],
            usage_complete=True,
            unavailable_reasons=[],
        ),
        started_at="2026-09-08T00:00:00Z",
        finished_at="2026-09-08T00:00:01Z",
        elapsed_ms=1000,
        debug_trace_ref=dict(
            stored_data_id="trace",
            data_kind="debug_trace",
            record_id=None,
            content_hash="a" * 64,
            analysis_id="a1",
        ),
    )
    for name in (
        "hypothesis_duplicate_review_refs finding_refs "
        "verification_refs cwe_label_refs "
        "technical_review_refs rule_scope_review_refs policy_cache_refs "
        "policy_collection_result_refs policy_parser_result_refs policy_record_refs "
        "dynamic_request_refs dynamic_result_refs environment_recipe_refs "
        "sandbox_environment_refs agent_log_refs dynamic_reproduction_conclusion_refs "
        "sandbox_policy_decision_refs cleanup_result_refs primitive_and_chaining_refs "
        "poc_candidate_refs poc_refs report_draft_refs llm_invocation_log_refs "
        "action_decision_refs work_state_refs work_attempt_refs transition_commit_refs "
        "eval_config_refs"
    ).split():
        value[name] = []
    wire(AnalysisRunResult, value)
    for field in value:
        with pytest.raises(ValidationError):
            wire(AnalysisRunResult, {k: v for k, v in value.items() if k != field})
    for patch in mutations(
        dict(status="COMPLETE", failed_hypothesis_count=1),
        dict(purpose="EVALUATION"),
        dict(policy_record_refs=[ref("program_policy_record")]),
    ):
        with pytest.raises(ValidationError):
            wire(AnalysisRunResult, value | patch)
