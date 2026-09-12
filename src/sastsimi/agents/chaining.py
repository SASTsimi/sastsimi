"""Content-only Chaining Agent boundary with trusted invocation provenance."""

from __future__ import annotations

from dataclasses import dataclass
from typing import BinaryIO, Literal, Protocol

from pydantic import ValidationError

from sastsimi.contracts.actions import (
    ActionDecision,
    ActionRequest,
    ActionType,
    RequesterRole,
)
from sastsimi.contracts.base import ContractModel, NonEmptyStr
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import BudgetScopeRef, RecordRef, StoredDataRef, reference
from sastsimi.contracts.work import AttemptStatus, WorkStatus, WorkType
from sastsimi.ports.chaining import (
    ChainedHypothesisContent,
    ChainingAgentInput,
    ChainingAgentOutcome,
    ChainingAgentOutput,
    ChainingDecision,
)
from sastsimi.ports.dto import WorkContext
from sastsimi.ports.llm_invocation import (
    LLMInvocationExpectation,
    LLMInvocationProvenanceValidator,
    PersistedLLMInvocation,
)


class LLMCallInvoker(Protocol):
    async def invoke(
        self,
        *,
        work: object,
        decision_ref: StoredDataRef,
        reservation_ref: RecordRef,
        call_spec_ref: StoredDataRef,
    ) -> PersistedLLMInvocation: ...


class ExactRecordReader(Protocol):
    def get_exact(self, ref: RecordRef) -> object: ...


class ArtifactReader(Protocol):
    def open_verified(self, ref: StoredDataRef) -> BinaryIO: ...


class _ChildContent(ContractModel):
    statement: NonEmptyStr
    vulnerability_type_candidates: tuple[NonEmptyStr, ...]
    falsification_questions: tuple[NonEmptyStr, ...]
    validation_checks: tuple[NonEmptyStr, ...]


class _DecisionContent(ContractModel):
    comparison_key: NonEmptyStr
    outcome: Literal["MATCH", "NO_MATCH"]
    reason_code: (
        Literal[
            "ENTITY_UNRELATED",
            "PRIVILEGE_UNSATISFIED",
            "ORDER_INVALID",
            "RESTRICTION_CONFLICT",
            "NO_CODE_EVIDENCE",
        ]
        | None
    )
    detail: NonEmptyStr
    evidence_keys: tuple[NonEmptyStr, ...]
    child: _ChildContent | None


class _OutputContent(ContractModel):
    decisions: tuple[_DecisionContent, ...]


@dataclass(frozen=True, slots=True)
class ChainingCallRefs:
    decision_ref: StoredDataRef
    reservation_ref: RecordRef
    call_spec_ref: StoredDataRef


class ChainingAgent:
    """Invoke one authorized match call and return no domain-owned authority."""

    def __init__(
        self,
        *,
        llm_calls: LLMCallInvoker,
        records: ExactRecordReader,
        artifacts: ArtifactReader,
        provenance_validator: LLMInvocationProvenanceValidator,
    ) -> None:
        self._llm_calls = llm_calls
        self._records = records
        self._artifacts = artifacts
        self._validate_provenance = provenance_validator

    async def match(
        self,
        *,
        context: WorkContext,
        decision_ref: StoredDataRef,
        reservation_ref: RecordRef,
        call_spec_ref: StoredDataRef,
        content: ChainingAgentInput,
    ) -> ChainingAgentOutcome:
        self._require_context(context)
        requester = self._requester(decision_ref, context)
        invocation = await self._llm_calls.invoke(
            work=context.work,
            decision_ref=decision_ref,
            reservation_ref=reservation_ref,
            call_spec_ref=call_spec_ref,
        )
        required_context = tuple(
            ref for ref in context.work.input_refs if isinstance(ref, StoredDataRef)
        )
        self._validate_provenance(
            records=self._records,
            work=context.work,
            issued_decision_ref=decision_ref,
            reservation_ref=reservation_ref,
            call_spec_ref=call_spec_ref,
            invocation=invocation,
            expectation=LLMInvocationExpectation(
                work_type=WorkType.CHAINING,
                action_type=ActionType.CALL_LLM,
                requested_by=RequesterRole.CHAINING,
                requester_identity_ref=requester,
                agent_role="CHAINING",
                task_kind="MATCH_PRIMITIVES",
                required_context=required_context,
                require_new_session=True,
                forbid_tools=True,
            ),
        )
        result = invocation.result
        if result.status != "SUCCEEDED":
            return ChainingAgentOutcome(invocation=invocation, content=None)
        output_ref = result.parsed_output_ref
        if output_ref is None or result.response_ref != output_ref:
            raise ValueError("CHAINING_OUTPUT_REFERENCE_MISMATCH")
        try:
            with self._artifacts.open_verified(output_ref) as stream:
                raw = stream.read()
            parsed = parse_chaining_output(raw, content)
        except ValueError:
            raise
        except Exception as error:
            raise ValueError("CHAINING_OUTPUT_ARTIFACT_INVALID") from error
        return ChainingAgentOutcome(invocation=invocation, content=parsed)

    def _requester(
        self, decision_ref: StoredDataRef, context: WorkContext
    ) -> BudgetScopeRef:
        decision = self._records.get_exact(decision_ref)
        if (
            not isinstance(decision, ActionDecision)
            or reference(decision) != decision_ref
        ):
            raise ValueError("CHAINING_ACTION_CLOSURE_MISMATCH")
        action = self._records.get_exact(decision.action_ref)
        work_ref = reference(context.work)
        if (
            not isinstance(action, ActionRequest)
            or reference(action) != decision.action_ref
            or action.requested_by != RequesterRole.CHAINING
            or action.action_type != ActionType.CALL_LLM
            or action.work_ref != work_ref
        ):
            raise ValueError("CHAINING_ACTION_CLOSURE_MISMATCH")
        return action.requester_identity_ref

    @staticmethod
    def _require_context(context: WorkContext) -> None:
        work, attempt = context.work, context.attempt
        if (
            work.work_type != WorkType.CHAINING
            or work.status != WorkStatus.RUNNING
            or work.active_attempt_id is None
            or attempt.status != AttemptStatus.RUNNING
            or attempt.work_id != work.work_id
            or attempt.attempt_id != work.active_attempt_id
            or attempt.input_hash != work.input_hash
        ):
            raise ValueError("CHAINING_WORK_CONTEXT_MISMATCH")


def parse_chaining_output(
    raw: bytes,
    agent_input: ChainingAgentInput,
) -> ChainingAgentOutput:
    """Validate canonical content and exact comparison/evidence coverage."""

    try:
        parsed = _OutputContent.model_validate_json(raw)
    except ValidationError as error:
        raise ValueError("CHAINING_OUTPUT_INVALID") from error
    if canonical_bytes(parsed) != raw:
        raise ValueError("CHAINING_OUTPUT_ARTIFACT_INVALID")
    expected = {item.comparison_key for item in agent_input.comparisons}
    actual = {str(item.comparison_key) for item in parsed.decisions}
    if len(actual) != len(parsed.decisions) or actual != expected:
        raise ValueError("CHAINING_DECISION_COVERAGE_MISMATCH")
    evidence = {item.evidence_key for item in agent_input.evidence}
    decisions: list[ChainingDecision] = []
    for item in parsed.decisions:
        selected = tuple(str(key) for key in item.evidence_keys)
        if len(set(selected)) != len(selected) or not set(selected) <= evidence:
            raise ValueError("CHAINING_EVIDENCE_SELECTION_MISMATCH")
        child = (
            ChainedHypothesisContent(
                statement=str(item.child.statement),
                vulnerability_type_candidates=tuple(
                    str(value) for value in item.child.vulnerability_type_candidates
                ),
                falsification_questions=tuple(
                    str(value) for value in item.child.falsification_questions
                ),
                validation_checks=tuple(
                    str(value) for value in item.child.validation_checks
                ),
            )
            if item.child is not None
            else None
        )
        decisions.append(
            ChainingDecision(
                comparison_key=str(item.comparison_key),
                outcome=item.outcome,
                reason_code=item.reason_code,
                detail=str(item.detail),
                evidence_keys=selected,
                child=child,
            )
        )
    return ChainingAgentOutput(decisions=tuple(decisions))


__all__ = [
    "ChainingAgent",
    "ChainingCallRefs",
    "parse_chaining_output",
]
