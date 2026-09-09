"""The fake slice must prove current validated PoC before publishing TRUE."""

import json
from collections import Counter
from pathlib import Path

import pytest

from sastsimi.bootstrap import build_fake_pipeline, load_fake_progress
from sastsimi.contracts.actions import ActionDecision, ActionRequest, RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.dynamic import (
    AgentLog,
    CleanupResult,
    DynamicReproductionRequest,
    PoCBundle,
    PoCCandidate,
    SandboxCommandRecord,
    SandboxEnvironment,
    SandboxPolicyDecision,
)
from sastsimi.contracts.evaluation import (
    EvaluationRecommendation,
    EvaluationRunConfig,
    EvaluationRunResult,
)
from sastsimi.contracts.hypothesis import ProposalProcessState
from sastsimi.contracts.llm import (
    LLMCallSpec,
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
    PromptPayload,
    PromptRegistryEntry,
    ProviderProfile,
    ProviderValidationEvidence,
)
from sastsimi.contracts.refs import StoredDataRef, reference
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
    published_by_ref = {reference(item): item for item in published}
    actions = tuple(item for item in published if isinstance(item, ActionRequest))
    action_counts = Counter(action.action_type.value for action in actions)
    assert action_counts["RUN_TOOL"] == 2
    assert action_counts["FETCH_POLICY"] == 1
    assert action_counts["READ_CODE"] == 1
    assert action_counts["CALL_LLM"] >= 5
    assert action_counts["REQUEST_DYNAMIC_REPRO"] == 1
    assert action_counts["RUN_SANDBOX"] == 3
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
    assert {log.task_kind for log in logs if log.agent_role == "VERIFICATION"} >= {
        "CREATE_DYNAMIC_REQUEST",
        "FINAL_VERDICT",
    }
    final_call = next(log for log in logs if log.task_kind == "FINAL_VERDICT")
    assert final_call.parsed_output_ref in result.verification_refs
    assert reference(assessment) in final_call.context_refs
    assert reference(dynamic_request) in final_call.context_refs
    assert {log.agent_role for log in logs} >= {
        "POLICY_PARSER",
        "PRO",
        "CON",
        "VERIFICATION",
        "DYNAMIC_REPRODUCTION",
        "CHAINING",
    }
    assert len({log.llm_call_id for log in logs}) == len(logs)
    assert len({log.session_ref for log in logs}) == len(logs)
    pro = next(item for item in logs if item.agent_role == "PRO")
    con = next(item for item in logs if item.agent_role == "CON")
    assert pro.context_refs == con.context_refs
    assert pro.session_policy == con.session_policy == "NEW"
    assert pro.session_ref != con.session_ref
    for log in logs:
        assert log.parsed_output_ref is not None
        assert log.exposed_response_ref is not None
        output = published_by_ref[log.parsed_output_ref]
        spec = published_by_ref[log.call_spec_ref]
        assert isinstance(spec, LLMCallSpec)
        request = next(
            item
            for item in published
            if isinstance(item, LLMInvocationRequest)
            and item.llm_call_id == log.llm_call_id
        )
        decision = published_by_ref[log.action_decision_ref]
        assert isinstance(decision, ActionDecision)
        action = published_by_ref[decision.action_ref]
        assert isinstance(action, ActionRequest)
        assert action.input_refs == spec.context_refs == request.context_refs
        assert action.llm_call_spec_ref == log.call_spec_ref
        payload = published_by_ref[log.prompt_payload_ref]
        assert isinstance(payload, PromptPayload)
        entry = published_by_ref[spec.prompt_registry_entry_ref]
        assert isinstance(entry, PromptRegistryEntry)
        assert entry.status == "ACTIVE" and entry.purpose == "PRODUCTION"
        assert entry.quality_evaluation_ref is not None
        recommendation = published_by_ref[entry.quality_evaluation_ref]
        assert isinstance(recommendation, EvaluationRecommendation)
        evaluation = published_by_ref[recommendation.evaluation_result_ref]
        assert isinstance(evaluation, EvaluationRunResult)
        config = published_by_ref[evaluation.config_ref]
        assert isinstance(config, EvaluationRunConfig)
        assert config.provider_profile_ref == spec.provider_profile_ref
        assert config.model == spec.model
        assert config.session_policy == spec.session_policy
        assert recommendation.target_provider_profile_ref == spec.provider_profile_ref
        assert recommendation.target_model == spec.model
        assert recommendation.target_session_policy == spec.session_policy
        assert (
            tuple(binding.source_ref for binding in payload.context_bindings)
            == spec.context_refs
        )
        for artifact_ref in (
            payload.template_ref,
            payload.rendered_prompt_ref,
            *(binding.projected_data_ref for binding in payload.context_bindings),
        ):
            with pipeline.runtime.unit_of_work.artifacts.open_verified(
                artifact_ref
            ) as stream:
                assert stream.read()
        with pipeline.runtime.unit_of_work.artifacts.open_verified(
            log.exposed_request_ref
        ) as stream:
            assert stream.read() == canonical_bytes(request)
        with pipeline.runtime.unit_of_work.artifacts.open_verified(
            log.exposed_response_ref
        ) as stream:
            assert stream.read() == canonical_bytes(output)
    synthesis = next(
        log
        for log in logs
        if log.agent_role == "VERIFICATION"
        and log.task_kind == "verification_initial_assessment"
    )
    assert synthesis.context_refs.count(pro.parsed_output_ref) == 1
    assert synthesis.context_refs.count(con.parsed_output_ref) == 1

    validations = tuple(
        item for item in published if isinstance(item, ProviderValidationEvidence)
    )
    profiles = tuple(item for item in published if isinstance(item, ProviderProfile))
    assert validations and profiles
    probe_evidence_refs: set[StoredDataRef] = set()
    for validation in validations:
        by_id = {test.test_id: test.result for test in validation.tests}
        assert set(by_id) == {f"PVD-{index:02d}" for index in range(1, 17)}
        assert by_id["PVD-13"] == "NOT_APPLICABLE"
        assert all(
            result == "PASS" for test_id, result in by_id.items() if test_id != "PVD-13"
        )
        for test in validation.tests:
            probe_evidence_refs.update(test.evidence_refs)
    for evidence_ref in probe_evidence_refs:
        with pipeline.runtime.unit_of_work.artifacts.open_verified(
            evidence_ref
        ) as stream:
            assert stream.read()
    assert all(
        profile.capabilities.cancellation == "UNSUPPORTED" for profile in profiles
    )
    assert all(
        profile.capabilities.resume_session == "UNSUPPORTED" for profile in profiles
    )

    (proposal_state,) = tuple(
        item for item in published if isinstance(item, ProposalProcessState)
    )
    assert proposal_state.status == "SCHEMA_VALID"
    assert proposal_state.registration_reason == "NO_CANDIDATES"
    (poc,) = tuple(item for item in published if isinstance(item, PoCBundle))
    candidate = pipeline.runtime.unit_of_work.records.get_exact(poc.candidate_ref)
    assert isinstance(candidate, PoCCandidate)
    with pipeline.runtime.unit_of_work.artifacts.open_verified(
        candidate.content_ref
    ) as stream:
        assert stream.read()
    assert any(isinstance(item, SandboxEnvironment) for item in published)
    (command,) = tuple(
        item for item in published if isinstance(item, SandboxCommandRecord)
    )
    (cleanup,) = tuple(item for item in published if isinstance(item, CleanupResult))
    (agent_log,) = tuple(item for item in published if isinstance(item, AgentLog))
    policies = tuple(
        item for item in published if isinstance(item, SandboxPolicyDecision)
    )
    assert len(policies) == 2
    command_events = tuple(
        event for event in agent_log.events if event.event_type.startswith("COMMAND_")
    )
    assert {event.event_type for event in command_events} == {
        "COMMAND_STARTED",
        "COMMAND_FINISHED",
    }
    assert all(event.command_ref == reference(command) for event in command_events)
    assert all(
        event.command_digest == command.command_digest for event in command_events
    )
    cleanup_event = next(
        event for event in agent_log.events if event.event_type == "CLEANUP_FINISHED"
    )
    assert cleanup_event.output_refs == (reference(cleanup),)
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
                resolved = pipeline.runtime.unit_of_work.records.get_exact(item_ref)
                assert reference(resolved) == item_ref
    with pipeline.runtime.unit_of_work.artifacts.open_verified(
        result.debug_trace_ref
    ) as stream:
        assert stream.read()
    assert result.elapsed_ms == 0


def test_provider_mismatch_cannot_publish_domain_output(tmp_path: Path) -> None:
    scenario = build_fake_pipeline(tmp_path)._scenario
    rejected_output_refs: list[StoredDataRef] = []

    async def mismatched_provider(
        _request: LLMInvocationRequest,
        expected: LLMInvocationResult,
    ) -> LLMInvocationResult:
        assert expected.parsed_output_ref is not None
        rejected_output_refs.append(expected.parsed_output_ref)
        return expected.model_copy(update={"status": "FAILED"})

    scenario.provider_invoke = mismatched_provider
    with pytest.raises(ValueError, match="FAKE_PROVIDER_OUTPUT_MISMATCH"):
        scenario.analyze(scenario="FALSE")

    assert scenario.runtime is not None
    assert (
        scenario.runtime.queries.current_records(
            "fake-analysis", "policy_parser_result"
        )
        == ()
    )
    assert (
        scenario.runtime.queries.current_records("fake-analysis", "llm_invocation_log")
        == ()
    )
    with pytest.raises(LookupError, match="Exact record is not published"):
        scenario.runtime.unit_of_work.records.get_exact(rejected_output_refs[0])


def test_sandbox_mismatch_cannot_publish_command_or_dynamic_result(
    tmp_path: Path,
) -> None:
    scenario = build_fake_pipeline(tmp_path)._scenario

    async def mismatched_sandbox(
        _request: object,
        expected: SandboxCommandRecord,
    ) -> SandboxCommandRecord:
        return expected.model_copy(update={"redaction_status": "REDACTED"})

    scenario.sandbox_execute = mismatched_sandbox
    with pytest.raises(ValueError, match="FAKE_SANDBOX_COMMAND_MISMATCH"):
        scenario.analyze(scenario="TRUE")

    assert scenario.runtime is not None
    for kind in (
        "sandbox_command_record",
        "cleanup_result",
        "agent_log",
        "dynamic_reproduction_result",
    ):
        assert scenario.runtime.queries.current_records("fake-analysis", kind) == ()


@pytest.mark.parametrize("mismatch", ["content", "source_check"])
def test_policy_fetch_mismatch_publishes_nothing(tmp_path: Path, mismatch: str) -> None:
    from dataclasses import replace

    from sastsimi.ports.dto import OfficialPolicyFetchRequest, OfficialPolicySource

    scenario = build_fake_pipeline(tmp_path)._scenario

    async def wrong_source(
        _request: OfficialPolicyFetchRequest, expected: OfficialPolicySource
    ) -> OfficialPolicySource:
        if mismatch == "content":
            return replace(expected, content=b"substituted policy source")
        return replace(
            expected,
            source_check=expected.source_check.model_copy(
                update={"source_url": "https://wrong.invalid/policy"}
            ),
        )

    scenario.policy_fetch = wrong_source
    with pytest.raises(ValueError, match="FAKE_POLICY_SOURCE_MISMATCH"):
        scenario.analyze(scenario="FALSE")
    assert scenario.runtime is not None
    for kind in ("policy_parser_result", "program_policy_record", "run_policy_state"):
        assert scenario.runtime.queries.current_records("fake-analysis", kind) == ()


def test_invocation_recording_crash_prevents_domain_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    scenario = build_fake_pipeline(tmp_path)._scenario
    invoke = scenario.provider_invoke

    def crash(*_args: object) -> StoredDataRef:
        raise RuntimeError("invocation recording crash")

    async def inject_crash(
        request: LLMInvocationRequest, expected: LLMInvocationResult
    ) -> LLMInvocationResult:
        assert scenario.runtime is not None
        monkeypatch.setattr(scenario.runtime.validator, "record_invocation", crash)
        return await invoke(request, expected)

    scenario.provider_invoke = inject_crash
    with pytest.raises(RuntimeError, match="invocation recording crash"):
        scenario.analyze(scenario="FALSE")
    assert scenario.runtime is not None
    for kind in ("policy_parser_result", "program_policy_record", "llm_invocation_log"):
        assert scenario.runtime.queries.current_records("fake-analysis", kind) == ()


def test_crash_after_invocation_can_publish_exact_domain_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from sastsimi.contracts.policy import PolicyParserResult

    scenario = build_fake_pipeline(tmp_path)._scenario
    invoke = scenario.provider_invoke

    def crash(*_args: object) -> tuple[StoredDataRef, ...]:
        raise RuntimeError("domain publication crash")

    async def inject_crash(
        request: LLMInvocationRequest, expected: LLMInvocationResult
    ) -> LLMInvocationResult:
        assert scenario.runtime is not None
        monkeypatch.setattr(scenario.runtime.intermediate, "publish", crash)
        return await invoke(request, expected)

    scenario.provider_invoke = inject_crash
    with pytest.raises(RuntimeError, match="domain publication crash"):
        scenario.analyze(scenario="FALSE")
    assert scenario.runtime is not None
    runtime = scenario.runtime
    assert (
        runtime.queries.current_records("fake-analysis", "policy_parser_result") == ()
    )
    published = runtime.queries.published_records("fake-analysis")
    (log,) = tuple(item for item in published if isinstance(item, LLMInvocationLog))
    (request,) = tuple(
        item for item in published if isinstance(item, LLMInvocationRequest)
    )
    (result,) = tuple(
        item for item in published if isinstance(item, LLMInvocationResult)
    )
    assert runtime.validator.record_invocation(request, result, log) == reference(log)
    assert log.parsed_output_ref is not None and log.exposed_response_ref is not None
    with pytest.raises(LookupError):
        runtime.unit_of_work.records.get_exact(log.parsed_output_ref)
    with runtime.unit_of_work.artifacts.open_verified(
        log.exposed_response_ref
    ) as response:
        candidate = PolicyParserResult.model_validate_json(response.read())
    assert candidate.llm_invocation_ref == reference(request)
    save = next(
        item
        for item in published
        if isinstance(item, ActionRequest)
        and item.result_kind == "policy_parser_result"
    )
    decision = next(
        item
        for item in published
        if isinstance(item, ActionDecision) and item.action_ref == reference(save)
    )
    assert save.work_ref is not None
    work = runtime.unit_of_work.records.get_exact(save.work_ref)
    assert isinstance(work, WorkExecutionState)
    monkeypatch.undo()
    (published_ref,) = runtime.intermediate.publish(
        str(work.work_id), reference(decision), (candidate,)
    )
    assert published_ref == log.parsed_output_ref


@pytest.mark.parametrize("boundary", ["cleanup", "chaining"])
def test_late_external_mismatch_prevents_publication(
    tmp_path: Path, boundary: str
) -> None:
    from sastsimi.contracts.dynamic import CleanupResult
    from sastsimi.ports.dto import SandboxCleanupRequest

    scenario = build_fake_pipeline(tmp_path)._scenario
    invoke = scenario.provider_invoke

    async def wrong_cleanup(
        _request: SandboxCleanupRequest, expected: CleanupResult
    ) -> CleanupResult:
        return expected.model_copy(update={"status": "FAILED"})

    async def wrong_chaining(
        request: LLMInvocationRequest, expected: LLMInvocationResult
    ) -> LLMInvocationResult:
        if request.agent_role == "CHAINING":
            return expected.model_copy(update={"status": "FAILED"})
        return await invoke(request, expected)

    absent: tuple[str, ...]
    if boundary == "cleanup":
        scenario.sandbox_cleanup = wrong_cleanup
        error = "FAKE_SANDBOX_CLEANUP_MISMATCH"
        absent = ("cleanup_result", "agent_log", "dynamic_reproduction_result")
    else:
        scenario.provider_invoke = wrong_chaining
        error = "FAKE_PROVIDER_OUTPUT_MISMATCH"
        absent = ("chaining_result", "report_draft")
    with pytest.raises(ValueError, match=error):
        scenario.analyze(scenario="TRUE")
    assert scenario.runtime is not None
    for kind in absent:
        assert scenario.runtime.queries.current_records("fake-analysis", kind) == ()


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
