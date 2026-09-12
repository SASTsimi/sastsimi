import json
from typing import Any

from sastsimi.contracts.base import ContractModel


def mutations(*changes: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    return changes


def meta(
    kind: str,
    *,
    hypothesis: str | None = None,
    attempt: str | None = "at1",
    run: bool = False,
) -> dict[str, Any]:
    value: dict[str, Any] = dict(
        record_id=f"{kind}-r1",
        logical_record_id=f"{kind}-l1",
        record_type=kind,
        schema_version="1.0.0",
        analysis_id="a1",
        revision_number=1,
        previous_record_id=None,
        created_at="2026-09-08T00:00:00Z",
    )
    if not run:
        value.update(
            workspace_id="ws1",
            commit_id="c1",
            hypothesis_id=hypothesis,
            attempt_id=attempt,
        )
    return value


def ref(kind: str, *, record: bool = True) -> dict[str, Any]:
    return dict(
        stored_data_id=f"{kind}-s1",
        data_kind=kind,
        record_id=f"{kind}-r1" if record else None,
        content_hash="a" * 64,
        workspace_id="ws1",
        commit_id="c1",
    )


def wire[T: ContractModel](model: type[T], value: dict[str, Any]) -> T:
    return model.model_validate_json(json.dumps(value))


def location() -> dict[str, Any]:
    return dict(
        workspace_id="ws1",
        commit_id="c1",
        file_path="src/app.py",
        start_line=1,
        end_line=2,
        start_column=None,
        end_column=None,
    )


def tool() -> dict[str, Any]:
    return dict(
        meta=meta("tool_run_result"),
        tool_name="ast",
        tool_version="1",
        tool_kind="STRUCTURE",
        status="SUCCEEDED",
        coverage=dict(
            analyzed_paths=["src/app.py"],
            skipped_paths=[],
            analyzed_languages=["python"],
            skipped_languages=[],
            notes=[],
        ),
        rule_execution_ref=None,
        raw_result_ref=ref("raw", record=False),
        gaps=[],
        errors=[],
        started_at="2026-09-08T00:00:00Z",
        finished_at="2026-09-08T00:00:01Z",
        elapsed_ms=1000,
    )


def bundle() -> dict[str, Any]:
    return dict(
        meta=meta("static_fact_bundle", attempt=None),
        entities=[],
        locations=[location()],
        source_candidates=[],
        sink_candidates=[],
        sanitizer_candidates=[],
        validator_candidates=[],
        auth_and_permission_checks=[],
        other_facts=[],
        call_edges=[],
        data_flow_candidates=[],
        route_bindings=[],
        tool_runs=[tool()],
        gaps=[],
        errors=[],
    )


def proposal() -> dict[str, Any]:
    return dict(
        proposal_id="p1",
        meta=meta("hypothesis_proposal", attempt=None),
        proposal_state="HYPOTHESIS_ONLY",
        assertion_mode="NON_FINAL",
        statement="Untrusted input may reach the sink",
        origin="INITIAL",
        vulnerability_type_candidates=[],
        target_entities=[],
        target_locations=[location()],
        suspected_path=[location()],
        observed_facts=[],
        assumptions=["reachable"],
        restrictions=[],
        falsification_questions=[
            dict(question_id="q1", question="Can the input reach the sink?")
        ],
        validation_checks=[dict(validation_id="v1", instruction="Check reachability")],
        parent_hypothesis_ids=[],
        source_primitive_match_id=None,
    )


def evidence(role: str = "PRO") -> dict[str, Any]:
    return dict(
        meta=meta(f"{role.lower()}_evidence_result", hypothesis="h1", attempt=role),
        role=role,
        parent_work_id="verification-work",
        evidence_work_id=f"{role}-work",
        verification_generation=1,
        llm_call_id=f"{role}-call",
        debate_input_hash="b" * 64,
        evidence=[
            dict(
                claim_id=role,
                statement="Observed code",
                source_role=role,
                evidence_refs=[ref("code_fragment", record=False)],
                code_locations=[location()],
                limitations=[],
            )
        ],
        summary="Checked source",
        limitations=[],
    )


def verification() -> dict[str, Any]:
    return dict(
        meta=meta("verification_result", hypothesis="h1"),
        playbook_ref=ref("verification_playbook"),
        playbook_application_ref=ref("playbook_application"),
        verification_mode="ALWAYS_DEBATE",
        debate_triggers=[],
        debate_skip_reason=None,
        debate_input_hash="b" * 64,
        pro_evidence_ref=ref("pro_evidence_result"),
        con_evidence_ref=ref("con_evidence_result"),
        supporting_evidence=evidence()["evidence"],
        counter_evidence=evidence("CON")["evidence"],
        falsification_results=[
            dict(
                question_id="q1",
                outcome="INCONCLUSIVE",
                evidence_refs=[ref("code_fragment", record=False)],
                rationale="Condition unresolved",
            )
        ],
        validation_results=[
            dict(
                validation_id="v1",
                completion="COMPLETE",
                evidence_refs=[ref("code_fragment", record=False)],
                summary="Checked",
            )
        ],
        initial_verdict="HOLD",
        dynamic_request_ref=None,
        dynamic_result_ref=None,
        poc_ref=None,
        verdict="HOLD",
        verdict_rationale="Reachability unresolved",
        restrictions=[],
        bypass_candidates=[],
        required_primitive_candidates=[],
        provided_primitive_candidates=[],
        impact_escalation_candidates=[],
        material_child_proposals=[],
        unresolved_conditions=["Reachability"],
        metrics=dict(
            pro_tokens=None,
            con_tokens=None,
            synthesis_tokens=None,
            elapsed_ms=1,
            verdict_changed_after_debate=False,
            hold_resolved=False,
            false_positive_reduction_candidate=False,
            new_bypass_count=0,
            new_restriction_count=0,
            new_falsification_count=0,
        ),
        errors=[],
    )


def dynamic_request() -> dict[str, Any]:
    return dict(
        meta=meta(
            "dynamic_reproduction_request", hypothesis="h1", attempt="r6-attempt"
        ),
        verification_assignment_ref=ref("verification_assignment"),
        verification_generation=1,
        hypothesis_ref=ref("vulnerability_hypothesis"),
        purpose="POC_CONFIRMATION",
        initial_verdict="TRUE",
        goal="Reproduce path",
        environment_needs=[],
        sandbox_profile_ref=ref("sandbox_profile"),
        code_refs=[ref("code_fragment", record=False)],
        static_evidence_refs=[],
        pro_evidence_ref=ref("pro_evidence_result"),
        con_evidence_ref=ref("con_evidence_result"),
        created_at="2026-09-08T00:00:00Z",
    )


def dynamic_failure() -> dict[str, Any]:
    return dict(
        meta=meta("dynamic_reproduction_result", hypothesis="h1"),
        action_decision_ref=None,
        request_ref=ref("dynamic_reproduction_request"),
        reproduction_plan_ref=None,
        purpose="POC_CONFIRMATION",
        policy_decision_ref=None,
        agent_invoked=False,
        agent_log_ref=ref("agent_log"),
        agent_conclusion_ref=None,
        environment_recipe_ref=None,
        environment_ref=None,
        poc_candidate_ref=None,
        poc_ref=None,
        observation_refs=[],
        status="FAILED",
        failure_category="PLAN",
        failure_reason="Missing required setup",
        plan_issues=[
            dict(
                issue_code="MISSING_INPUT",
                status="OPEN",
                message="Missing setup",
                related_refs=[],
            )
        ],
        hypothesis_outcome="INCONCLUSIVE",
        hypothesis_evidence_refs=[],
        hypothesis_disproved=False,
        disproof_evidence_refs=[],
        hypothesis_linkage="No execution",
        plan_execution_status="NEEDS_REVISION",
        plan_issue_evidence_refs=[],
        limitations=["Setup missing"],
        cleanup_required=False,
        cleanup_status="NOT_REQUIRED",
        cleanup_ref=None,
        started_at="2026-09-08T00:00:00Z",
        finished_at="2026-09-08T00:00:01Z",
        elapsed_ms=1000,
    )


def event() -> dict[str, Any]:
    return dict(
        event_id="event1",
        sequence=1,
        action_id="action1",
        event_type="ERROR",
        actor="REPRODUCTION_SESSION_MANAGER",
        environment_ref=None,
        environment_recipe_ref=None,
        poc_candidate_ref=None,
        tool_request_ref=None,
        command_ref=None,
        command_digest=None,
        redaction_status=None,
        input_refs=[],
        output_refs=[],
        exit_code=None,
        safe_message="Setup unavailable",
        occurred_at="2026-09-08T00:00:00Z",
    )
