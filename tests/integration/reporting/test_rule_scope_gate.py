from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
from io import BytesIO
from typing import cast

import pytest

from sastsimi.agents.rule_scope_gate import (
    RuleScopeAgentOutcome,
    RuleScopeCallRefs,
    RuleScopeEvidenceSelection,
    RuleScopeProposal,
)
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.gates import CWELabel, TechnicalEvidenceReview
from sastsimi.contracts.llm import (
    LLMCallSpec,
    LLMInvocationLog,
    LLMInvocationRequest,
    LLMInvocationResult,
    LLMToolPolicy,
    PromptContextBinding,
    PromptPayload,
)
from sastsimi.contracts.policy import (
    PolicyCollectionResult,
    ProgramPolicyRecord,
    RunPolicyState,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.reporting.rule_scope_gate_handler import WorkflowRuleScopePublisher
from sastsimi.reporting.rule_scope_gate_workflow import (
    ExactRuleScopePromptGuard,
    OfficialSourceBinding,
    RuleScopeExecution,
    RuleScopeGateInputs,
    RuleScopeGateService,
)
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation
from sastsimi.runtime.workflow_runner import WorkflowRunner
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import meta, ref, wire

NOW = "2026-09-08T00:00:00Z"


class _Agent:
    def __init__(self, proposal: RuleScopeProposal) -> None:
        self.proposal = proposal
        self.calls = 0
        self.invocation = _stub_invocation()

    async def review(self, **_kwargs: object) -> RuleScopeAgentOutcome:
        self.calls += 1
        return RuleScopeAgentOutcome(
            proposal=self.proposal,
            invocation=self.invocation,
        )


@dataclass
class _Fixture:
    inputs: RuleScopeGateInputs
    service: RuleScopeGateService
    agent: _Agent
    starts: list[RuleScopeGateInputs]
    published: list[object]
    current_policy_states: list[StoredDataRef]
    prompt_checks: list[object]
    executions: list[RuleScopeExecution]


def wire_ref(kind: str, *, artifact: bool = False) -> StoredDataRef:
    return StoredDataRef.model_validate(
        ref(kind, record=not artifact)
        | ({"stored_data_id": "a" * 64} if artifact else {})
    )


def _record_meta(kind: str, *, attempt: str | None = "at-gate") -> RecordMeta:
    return wire(
        RecordMeta,
        meta(kind, hypothesis="h1", attempt=attempt)
        | {
            "record_id": f"{kind}-{attempt or 'none'}-r1",
            "logical_record_id": f"{kind}-{attempt or 'none'}-l1",
        },
    )


def _stub_invocation() -> PersistedLLMInvocation:
    output_ref = wire_ref("artifact", artifact=True)
    decision_ref = wire_ref("action_decision")
    spec_ref = wire_ref("llm_call_spec")
    request = wire(
        LLMInvocationRequest,
        make("LLMInvocationRequest", "llm_invocation_request")
        | {
            "meta": meta("llm_invocation_request", hypothesis="h1", attempt="at-gate"),
            "llm_call_id": "rule-scope-call",
            "action_decision_ref": decision_ref.model_dump(mode="json"),
            "call_spec_ref": spec_ref.model_dump(mode="json"),
            "agent_role": "RULE_SCOPE_GATE",
            "task_kind": "REVIEW",
            "purpose": "PRODUCTION",
            "session_policy": "NEW",
            "parent_session_ref": None,
        },
    )
    result = wire(
        LLMInvocationResult,
        make("LLMInvocationResult", "llm_invocation_result")
        | {
            "meta": meta("llm_invocation_result", hypothesis="h1", attempt="at-gate"),
            "llm_call_id": request.llm_call_id,
            "purpose": request.purpose,
            "status": "SUCCEEDED",
            "model": request.model,
            "actual_session_mode": "NEW",
            "response_ref": output_ref.model_dump(mode="json"),
            "parsed_output_ref": output_ref.model_dump(mode="json"),
            "safe_error": None,
        },
    )
    log = wire(
        LLMInvocationLog,
        make("LLMInvocationLog", "llm_invocation_log")
        | {
            "meta": meta("llm_invocation_log", hypothesis="h1", attempt="at-gate"),
            "llm_call_id": request.llm_call_id,
            "action_decision_ref": decision_ref.model_dump(mode="json"),
            "call_spec_ref": spec_ref.model_dump(mode="json"),
            "agent_role": request.agent_role,
            "task_kind": request.task_kind,
            "purpose": request.purpose,
            "model": request.model,
            "session_policy": "NEW",
            "parent_session_ref": None,
            "exposed_response_ref": output_ref.model_dump(mode="json"),
            "parsed_output_ref": output_ref.model_dump(mode="json"),
            "status": "SUCCEEDED",
            "safe_error": None,
        },
    )
    log_ref = cast(StoredDataRef, reference(log))
    return PersistedLLMInvocation(request, result, log_ref, "RETURNED")


def _fixture() -> _Fixture:
    verification = wire(
        VerificationResult,
        make("VerificationResult")
        | {
            "initial_verdict": "TRUE",
            "verdict": "TRUE",
            "verdict_rationale": "Confirmed by the validated reproduction",
            "dynamic_request_ref": ref("dynamic_reproduction_request"),
            "dynamic_result_ref": ref("dynamic_reproduction_result"),
            "poc_ref": ref("poc_bundle"),
            "unresolved_conditions": [],
        },
    )
    verification_ref = cast(StoredDataRef, reference(verification))
    label = wire(
        CWELabel,
        make("CWELabel", "cwe_label")
        | {
            "verification_result_ref": verification_ref.model_dump(mode="json"),
            "verification_generation": 1,
        },
    )
    label_ref = cast(StoredDataRef, reference(label))
    technical = wire(
        TechnicalEvidenceReview,
        make("TechnicalEvidenceReview")
        | {
            "verification_result_ref": verification_ref.model_dump(mode="json"),
            "cwe_label_ref": label_ref.model_dump(mode="json"),
        },
    )
    technical_ref = cast(StoredDataRef, reference(technical))

    body = "Official program policy: testing is allowed on listed assets."
    source_ref = StoredDataRef.model_validate(
        ref("official_policy_source", record=False)
        | {
            "stored_data_id": sha256(body.encode()).hexdigest(),
            "content_hash": sha256(body.encode()).hexdigest(),
        }
    )
    source_check = {
        "source_id": "official-source-1",
        "source_ref": source_ref.model_dump(mode="json"),
        "source_url": "https://program.example/policy",
        "publisher": "program.example",
        "status": "VERIFIED",
        "evidence_refs": [source_ref.model_dump(mode="json")],
        "checked_at": NOW,
    }

    def item(item_id: str) -> dict[str, object]:
        return {
            "policy_item_id": item_id,
            "value": "allowed",
            "description": "Official program rule",
            "conditions": [],
            "source_ref": source_ref.model_dump(mode="json"),
            "source_locator": "policy#rules",
        }

    policy = wire(
        ProgramPolicyRecord,
        make("ProgramPolicyRecord")
        | {
            "freshness_status": "CURRENT",
            "freshness_checked_at": NOW,
            "freshness_valid_until": "2026-09-09T00:00:00Z",
            "source_refs": [source_ref.model_dump(mode="json")],
            "source_checks": [source_check],
            "freshness_criterion_ref": ref("freshness_criterion"),
            "freshness_evidence_refs": [ref("freshness_evidence", record=False)],
            "in_scope_assets": [item("scope-1")],
            "accepted_vulnerability_classes": [item("rule-1")],
            "testing_restrictions": [item("testing-1")],
            "impact_criteria": [item("impact-1")],
        },
    )
    policy_ref = cast(StoredDataRef, reference(policy))
    collection = wire(
        PolicyCollectionResult,
        make("PolicyCollectionResult")
        | {
            "official_source_refs": [source_ref.model_dump(mode="json")],
            "policy_record_ref": policy_ref.model_dump(mode="json"),
        },
    )
    collection_ref = cast(StoredDataRef, reference(collection))
    state_data = make("RunPolicyState")
    state_data.update(
        status="CURRENT",
        preparation_source="COLLECTED",
        policy_cache_ref={
            "stored_data_id": "cache-s1",
            "data_kind": "policy_cache_record",
            "record_id": "cache-r1",
            "content_hash": "b" * 64,
            "program_id": "program1",
            "schema_version": "1.0.0",
        },
        collection_result_ref=collection_ref.model_dump(mode="json"),
        policy_record_ref=policy_ref.model_dump(mode="json"),
        freshness_criterion_ref=ref("freshness_criterion"),
        freshness_checked_at=NOW,
        freshness_evidence_refs=[ref("freshness_evidence", record=False)],
        freshness_valid_until="2026-09-09T00:00:00Z",
    )
    state = wire(RunPolicyState, state_data)
    state_ref = cast(StoredDataRef, reference(state))
    owner_ref = wire_ref("agent_identity")
    required = (
        verification_ref,
        label_ref,
        technical_ref,
        state_ref,
        collection_ref,
        policy_ref,
        source_ref,
    )
    work_data = make("WorkExecutionState")
    work_data.update(
        meta=meta("work_execution_state", hypothesis="h1", attempt=None),
        work_type="RULE_SCOPE_GATE",
        subject_type="HYPOTHESIS",
        subject_id="h1",
        status="RUNNING",
        state_version=3,
        last_transition_ref=ref("state_transition"),
        last_transition_commit_ref=ref("transition_commit"),
        active_attempt_id="at-gate",
        input_refs=[item.model_dump(mode="json") for item in required],
        dedupe_key="c" * 64,
        started_at=NOW,
    )
    work = wire(WorkExecutionState, work_data)
    inputs = RuleScopeGateInputs(
        verification=verification,
        verification_ref=verification_ref,
        cwe_label=label,
        cwe_label_ref=label_ref,
        technical_review=technical,
        technical_review_ref=technical_ref,
        run_policy_state=state,
        run_policy_state_ref=state_ref,
        collection=collection,
        collection_ref=collection_ref,
        policy=policy,
        policy_ref=policy_ref,
        official_sources=(
            OfficialSourceBinding(
                source_ref=source_ref,
                source_locator="https://program.example/policy",
                content_hash=source_ref.content_hash,
                redacted_body=body,
            ),
        ),
        available_evidence_refs=tuple(
            dict.fromkeys(
                (
                    source_ref,
                    *(
                        evidence_ref
                        for claim in (
                            *verification.supporting_evidence,
                            *verification.counter_evidence,
                        )
                        for evidence_ref in claim.evidence_refs
                    ),
                    *(
                        evidence_ref
                        for result in (
                            *verification.falsification_results,
                            *verification.validation_results,
                        )
                        for evidence_ref in result.evidence_refs
                    ),
                    *label.evidence_refs,
                    verification.dynamic_result_ref,
                    verification.poc_ref,
                    *state.freshness_evidence_refs,
                    *(
                        evidence_ref
                        for check in policy.source_checks
                        for evidence_ref in check.evidence_refs
                    ),
                    *policy.freshness_evidence_refs,
                )
            )
        ),
        verification_owner_ref=owner_ref,
        current_generation=1,
    )
    proposal = RuleScopeProposal(
        rule_compliance="PASS",
        scope_compliance="PASS",
        testing_restriction_compliance="PASS",
        security_impact="SUFFICIENT",
        report_permission="ALLOW",
        evidence_links=tuple(
            RuleScopeEvidenceSelection(
                area=area,
                policy_item_ids=(item_id,),
                evidence_indexes=(0,),
            )
            for area, item_id in (
                ("RULE", "rule-1"),
                ("SCOPE", "scope-1"),
                ("TESTING_RESTRICTION", "testing-1"),
                ("IMPACT", "impact-1"),
            )
        ),
        reasons=("Official rules and actual testing evidence are aligned.",),
        missing_information=(),
    )
    agent = _Agent(proposal)
    starts: list[RuleScopeGateInputs] = []
    published: list[object] = []
    executions: list[RuleScopeExecution] = []
    gate_identity_ref = wire_ref("agent_identity")

    def start(value: RuleScopeGateInputs) -> RuleScopeExecution:
        starts.append(value)
        context = tuple(
            dict.fromkeys(
                (
                    value.verification_ref,
                    value.cwe_label_ref,
                    value.technical_review_ref,
                    value.run_policy_state_ref,
                    value.collection_ref,
                    *((value.policy_ref,) if value.policy_ref is not None else ()),
                    *(source.source_ref for source in value.official_sources),
                    *value.available_evidence_refs,
                )
            )
        )
        current_work = WorkExecutionState.model_validate(
            work.model_dump() | {"input_refs": context}
        )
        execution = RuleScopeExecution(
            work=current_work,
            call=object(),
            owner_ref=owner_ref,
            gate_identity_ref=gate_identity_ref,
        )
        executions.append(execution)
        return execution

    def publish(
        _execution: RuleScopeExecution,
        review: object,
        _invocation: PersistedLLMInvocation,
    ) -> StoredDataRef:
        published.append(review)
        return cast(StoredDataRef, reference(cast(object, review)))

    counter = iter(range(1, 100))

    def metadata_factory(
        source: RecordMeta, kind: str, attempt_id: object
    ) -> RecordMeta:
        number = next(counter)
        return RecordMeta.model_validate(
            source.model_dump()
            | {
                "record_id": f"{kind}-r{number}",
                "logical_record_id": f"{kind}-l{number}",
                "record_type": kind,
                "revision_number": 1,
                "previous_record_id": None,
                "attempt_id": str(attempt_id),
            }
        )

    current_policy_states = [state_ref]
    prompt_checks: list[object] = []

    def prompt_guard(*args: object) -> None:
        prompt_checks.append(args)

    service = RuleScopeGateService(
        agent=agent,
        execution_factory=start,
        publisher=publish,
        metadata_factory=metadata_factory,
        id_factory=lambda prefix: f"{prefix}-{next(counter)}",
        current_owner=lambda _verification: owner_ref,
        current_policy_state=lambda _analysis: current_policy_states[0],
        prompt_guard=prompt_guard,
    )
    return _Fixture(
        inputs,
        service,
        agent,
        starts,
        published,
        current_policy_states,
        prompt_checks,
        executions,
    )


@pytest.mark.asyncio
async def test_found_current_accept_keeps_report_and_testing_axes_separate() -> None:
    fixture = _fixture()

    outcome = await fixture.service.review(fixture.inputs)

    assert outcome.stop_reason is None
    assert outcome.review is not None
    assert outcome.review_ref == reference(outcome.review)
    assert outcome.review.report_permission == "ALLOW"
    assert outcome.review.testing_restriction_compliance == "PASS"
    assert {link.area for link in outcome.review.evidence_links} == {
        "RULE",
        "SCOPE",
        "IMPACT",
        "TESTING_RESTRICTION",
    }
    assert fixture.agent.calls == 1
    assert len(fixture.starts) == len(fixture.published) == 1
    assert len(fixture.prompt_checks) == 1


@pytest.mark.asyncio
async def test_workflow_publisher_uses_rule_scope_gate_identity() -> None:
    fixture = _fixture()
    outcome = await fixture.service.review(fixture.inputs)
    assert outcome.review is not None
    review = outcome.review
    execution = replace(
        fixture.executions[0],
        call=RuleScopeCallRefs(
            decision_ref=wire_ref("action_decision"),
            reservation_ref=wire_ref("budget_reservation"),
            call_spec_ref=fixture.agent.invocation.request.call_spec_ref,
        ),
    )

    class _Completed:
        output_refs = (reference(review),)

    class _Runner:
        def __init__(self) -> None:
            self.args: tuple[object, ...] | None = None

        def complete(self, *args: object, **_kwargs: object) -> _Completed:
            self.args = args
            return _Completed()

    runner = _Runner()
    publisher = WorkflowRuleScopePublisher(cast(WorkflowRunner, runner))

    assert publisher(execution, review, fixture.agent.invocation) == reference(review)
    assert runner.args is not None
    assert runner.args[1] == execution.gate_identity_ref
    assert runner.args[2] == "RULE_SCOPE_GATE"


@pytest.mark.asyncio
async def test_exact_prompt_guard_pins_official_source_and_disables_tools() -> None:
    fixture = _fixture()
    await fixture.service.review(fixture.inputs)
    base_execution = fixture.executions[0]
    context = tuple(cast(StoredDataRef, ref) for ref in base_execution.work.input_refs)
    projected: dict[StoredDataRef, bytes] = {}
    bindings = []
    official = fixture.inputs.official_sources[0]
    for index, source_ref in enumerate(context):
        data = canonical_bytes(official) if source_ref == official.source_ref else b"{}"
        digest = sha256(data).hexdigest()
        projected_ref = StoredDataRef.model_validate(
            {
                "stored_data_id": digest,
                "data_kind": "artifact",
                "record_id": None,
                "content_hash": digest,
                "workspace_id": "ws1",
                "commit_id": "c1",
            }
        )
        projected[projected_ref] = data
        bindings.append(
            PromptContextBinding(
                slot=f"input-{index}",
                data_kind=source_ref.data_kind,
                source_ref=source_ref,
                projected_data_ref=projected_ref,
                field_paths=("/",),
                trust_class="UNTRUSTED_DATA",
            )
        )
    tool = LLMToolPolicy(
        meta=_record_meta("llm_tool_policy"),
        policy_key="tools.none.v1",
        allowed_tools=(),
        forbidden_actions=("ALL",),
        sandbox_only=False,
    )
    tool_ref = cast(StoredDataRef, reference(tool))
    payload = PromptPayload(
        meta=_record_meta("prompt_payload"),
        registry_entry_ref=wire_ref("prompt_registry_entry"),
        prompt_key="rule-scope-gate.review",
        agent_role="RULE_SCOPE_GATE",
        task_kind="REVIEW",
        purpose="EVALUATION",
        template_ref=wire_ref("prompt_template"),
        template_version="1.0.0",
        context_bindings=tuple(bindings),
        rendered_prompt_ref=wire_ref("artifact", artifact=True),
        output_schema_ref=wire_ref("output_schema_spec"),
    )
    payload_ref = cast(StoredDataRef, reference(payload))
    spec = wire(
        LLMCallSpec,
        make("LLMCallSpec", "llm_call_spec")
        | {
            "meta": meta("llm_call_spec", hypothesis="h1", attempt="at-gate"),
            "agent_role": "RULE_SCOPE_GATE",
            "task_kind": "REVIEW",
            "context_refs": [item.model_dump(mode="json") for item in context],
            "prompt_payload_ref": payload_ref.model_dump(mode="json"),
            "prompt_key": payload.prompt_key,
            "prompt_template_ref": payload.template_ref.model_dump(mode="json"),
            "prompt_template_version": payload.template_version,
            "tool_policy_ref": tool_ref.model_dump(mode="json"),
            "output_schema_ref": payload.output_schema_ref.model_dump(mode="json"),
        },
    )
    spec_ref = cast(StoredDataRef, reference(spec))
    records = {spec_ref: spec, payload_ref: payload, tool_ref: tool}

    class _Records:
        def get_exact(self, record_ref: StoredDataRef) -> object:
            return records[record_ref]

    class _Artifacts:
        def open_verified(self, artifact_ref: StoredDataRef) -> BytesIO:
            return BytesIO(projected[artifact_ref])

    execution = replace(
        base_execution,
        call=RuleScopeCallRefs(
            decision_ref=wire_ref("action_decision"),
            reservation_ref=wire_ref("budget_reservation"),
            call_spec_ref=spec_ref,
        ),
    )

    guard = ExactRuleScopePromptGuard(records=_Records(), artifacts=_Artifacts())
    guard(execution, fixture.inputs, context)

    records[tool_ref] = LLMToolPolicy(
        meta=tool.meta.model_copy(
            update={
                "record_id": "unsafe-tool-policy-r1",
                "logical_record_id": "unsafe-tool-policy-l1",
            }
        ),
        policy_key="tools.enabled.v1",
        allowed_tools=("web-search",),
        forbidden_actions=(),
        sandbox_only=False,
    )
    with pytest.raises(ValueError, match="RULE_SCOPE_TOOLS_FORBIDDEN"):
        guard(execution, fixture.inputs, context)
