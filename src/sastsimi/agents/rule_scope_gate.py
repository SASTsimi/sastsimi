"""Rule Scope Gate LLM boundary and content-only output validation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import BinaryIO, Literal, Protocol

from pydantic import NonNegativeInt, model_validator

from sastsimi.contracts.actions import (
    ActionDecision,
    ActionRequest,
    ActionType,
    Decision,
    RequesterRole,
    UseStatus,
    validate_decision_revision,
)
from sastsimi.contracts.base import ContractModel, NonEmptyStr
from sastsimi.contracts.budget import BudgetReservation
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.llm import LLMCallSpec, LLMInvocationLog, LLMToolPolicy
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState, WorkStatus, WorkType
from sastsimi.ports.llm_invocation import (
    LLMInvocationExpectation,
    LLMInvocationProvenanceValidator,
    PersistedLLMInvocation,
)

PolicyArea = Literal["RULE", "SCOPE", "IMPACT", "TESTING_RESTRICTION"]


class RuleScopeEvidenceSelection(ContractModel):
    """Untrusted indexes into the runtime-bound evidence list; never raw refs."""

    area: PolicyArea
    policy_item_ids: tuple[NonEmptyStr, ...]
    evidence_indexes: tuple[NonNegativeInt, ...]

    @model_validator(mode="after")
    def unique_selection(self) -> RuleScopeEvidenceSelection:
        if len(self.policy_item_ids) != len(set(self.policy_item_ids)):
            raise ValueError("DUPLICATE_POLICY_ITEM")
        if len(self.evidence_indexes) != len(set(self.evidence_indexes)):
            raise ValueError("DUPLICATE_EVIDENCE_SELECTION")
        return self


class RuleScopeMissingInfoProposal(ContractModel):
    """Content-only gap; the runtime allocates its identifier and exact refs."""

    area: PolicyArea
    description: NonEmptyStr
    policy_item_ids: tuple[NonEmptyStr, ...]
    evidence_indexes: tuple[NonNegativeInt, ...]


class RuleScopeProposal(ContractModel):
    """The only Rule Scope content the provider may propose."""

    rule_compliance: Literal["PASS", "FAIL", "UNCERTAIN"]
    scope_compliance: Literal["PASS", "FAIL", "UNCERTAIN"]
    testing_restriction_compliance: Literal["PASS", "FAIL", "UNCERTAIN"]
    security_impact: Literal["SUFFICIENT", "INSUFFICIENT", "UNCERTAIN"]
    report_permission: Literal["ALLOW", "DENY"]
    evidence_links: tuple[RuleScopeEvidenceSelection, ...]
    reasons: tuple[NonEmptyStr, ...]
    missing_information: tuple[RuleScopeMissingInfoProposal, ...]

    @model_validator(mode="after")
    def unique_areas(self) -> RuleScopeProposal:
        evidence_areas = [item.area for item in self.evidence_links]
        missing_areas = [item.area for item in self.missing_information]
        if len(evidence_areas) != len(set(evidence_areas)):
            raise ValueError("DUPLICATE_EVIDENCE_AREA")
        if len(missing_areas) != len(set(missing_areas)):
            raise ValueError("DUPLICATE_MISSING_AREA")
        if not self.reasons:
            raise ValueError("GATE_REASON_REQUIRED")
        return self


@dataclass(frozen=True)
class RuleScopeCallRefs:
    decision_ref: StoredDataRef
    reservation_ref: RecordRef
    call_spec_ref: StoredDataRef


@dataclass(frozen=True)
class RuleScopeAgentOutcome:
    proposal: RuleScopeProposal
    invocation: PersistedLLMInvocation

    @property
    def action_decision_ref(self) -> StoredDataRef:
        return self.invocation.request.action_decision_ref


class LLMCallInvoker(Protocol):
    async def invoke(
        self,
        *,
        work: WorkExecutionState,
        decision_ref: StoredDataRef,
        reservation_ref: RecordRef,
        call_spec_ref: StoredDataRef,
    ) -> PersistedLLMInvocation: ...


class RecordReader(Protocol):
    def get_exact(self, ref: RecordRef) -> object: ...


class ArtifactReader(Protocol):
    def open_verified(self, ref: StoredDataRef) -> BinaryIO: ...


class RuleScopeGateAgent:
    """Invoke the isolated Gate role and reject all provider-owned authority."""

    def __init__(
        self,
        *,
        llm_calls: LLMCallInvoker,
        records: RecordReader,
        artifacts: ArtifactReader,
        provenance_validator: LLMInvocationProvenanceValidator,
    ) -> None:
        self._llm_calls = llm_calls
        self._records = records
        self._artifacts = artifacts
        self._validate_provenance = provenance_validator

    async def review(
        self,
        *,
        work: WorkExecutionState,
        call: RuleScopeCallRefs,
        owner_ref: StoredDataRef,
        required_context: tuple[StoredDataRef, ...],
    ) -> RuleScopeAgentOutcome:
        invocation = await self._llm_calls.invoke(
            work=work,
            decision_ref=call.decision_ref,
            reservation_ref=call.reservation_ref,
            call_spec_ref=call.call_spec_ref,
        )
        self._require_invocation(
            invocation,
            work=work,
            call=call,
            owner_ref=owner_ref,
            required_context=required_context,
        )
        output_ref = invocation.result.parsed_output_ref
        assert output_ref is not None
        try:
            with self._artifacts.open_verified(output_ref) as stream:
                raw = stream.read()
            proposal = RuleScopeProposal.model_validate_json(raw)
        except ValueError:
            raise
        except Exception as error:
            raise ValueError("RULE_SCOPE_OUTPUT_ARTIFACT_INVALID") from error
        if canonical_bytes(proposal) != raw:
            raise ValueError("RULE_SCOPE_OUTPUT_ARTIFACT_INVALID")
        return RuleScopeAgentOutcome(
            proposal=proposal,
            invocation=invocation,
        )

    def _require_invocation(
        self,
        invocation: PersistedLLMInvocation,
        *,
        work: WorkExecutionState,
        call: RuleScopeCallRefs,
        owner_ref: StoredDataRef,
        required_context: tuple[StoredDataRef, ...],
    ) -> None:
        try:
            self._validate_provenance(
                records=self._records,
                work=work,
                issued_decision_ref=call.decision_ref,
                reservation_ref=call.reservation_ref,
                call_spec_ref=call.call_spec_ref,
                invocation=invocation,
                expectation=LLMInvocationExpectation(
                    work_type=WorkType.RULE_SCOPE_GATE,
                    action_type=ActionType.CALL_RULE_SCOPE_GATE,
                    requested_by=RequesterRole.VERIFICATION,
                    requester_identity_ref=owner_ref,
                    agent_role="RULE_SCOPE_GATE",
                    task_kind="REVIEW",
                    required_context=required_context,
                    forbid_tools=True,
                ),
            )
        except ValueError as error:
            raise ValueError("RULE_SCOPE_INVOCATION_CLOSURE_MISMATCH") from error
        request, result = invocation.request, invocation.result
        request_ref = reference(request)
        result_ref = reference(result)
        log_value = self._records.get_exact(invocation.log_ref)
        if (
            not isinstance(work.meta, RecordMeta)
            or not isinstance(request_ref, StoredDataRef)
            or not isinstance(result_ref, StoredDataRef)
            or work.work_type != WorkType.RULE_SCOPE_GATE
            or work.status != WorkStatus.RUNNING
            or work.active_attempt_id is None
            or invocation.dispatch_state != "RETURNED"
            or request.agent_role != "RULE_SCOPE_GATE"
            or request.task_kind != "REVIEW"
            or request.session_policy != "NEW"
            or request.parent_session_ref is not None
            or request.call_spec_ref != call.call_spec_ref
            or tuple(request.context_refs) != required_context
            or len(required_context) != len(set(required_context))
            or result.status != "SUCCEEDED"
            or result.llm_call_id != request.llm_call_id
            or result.actual_session_mode != "NEW"
            or result.parsed_output_ref is None
            or result.response_ref != result.parsed_output_ref
            or result.parsed_output_ref.record_id is not None
            or result.parsed_output_ref.data_kind != "artifact"
            or str(result.parsed_output_ref.stored_data_id)
            != result.parsed_output_ref.content_hash
            or self._records.get_exact(request_ref) != request
            or self._records.get_exact(result_ref) != result
            or not isinstance(log_value, LLMInvocationLog)
            or reference(log_value) != invocation.log_ref
        ):
            raise ValueError("RULE_SCOPE_INVOCATION_CLOSURE_MISMATCH")
        expected_scope = (
            work.meta.analysis_id,
            work.meta.workspace_id,
            work.meta.commit_id,
            work.meta.hypothesis_id,
            work.active_attempt_id,
        )
        if (
            (
                request.meta.analysis_id,
                request.meta.workspace_id,
                request.meta.commit_id,
                request.meta.hypothesis_id,
                request.meta.attempt_id,
            )
            != expected_scope
            or (
                result.meta.analysis_id,
                result.meta.workspace_id,
                result.meta.commit_id,
                result.meta.hypothesis_id,
                result.meta.attempt_id,
            )
            != expected_scope
            or (
                log_value.meta.analysis_id,
                log_value.meta.workspace_id,
                log_value.meta.commit_id,
                log_value.meta.hypothesis_id,
                log_value.meta.attempt_id,
            )
            != expected_scope
        ):
            raise ValueError("RULE_SCOPE_INVOCATION_CLOSURE_MISMATCH")
        issued = self._records.get_exact(call.decision_ref)
        decision = self._records.get_exact(request.action_decision_ref)
        if (
            not isinstance(issued, ActionDecision)
            or not isinstance(decision, ActionDecision)
            or reference(issued) != call.decision_ref
            or reference(decision) != request.action_decision_ref
            or issued.decision != Decision.ALLOW
            or issued.use_status != UseStatus.UNUSED
            or decision.decision != Decision.ALLOW
            or decision.use_status != UseStatus.USED
        ):
            raise ValueError("RULE_SCOPE_ACTION_AUTHORITY_MISMATCH")
        for item in (issued, decision):
            if (
                not isinstance(item.meta, RecordMeta)
                or (
                    item.meta.analysis_id,
                    item.meta.workspace_id,
                    item.meta.commit_id,
                    item.meta.hypothesis_id,
                    item.meta.attempt_id,
                )
                != expected_scope
            ):
                raise ValueError("RULE_SCOPE_ACTION_AUTHORITY_MISMATCH")
        try:
            validate_decision_revision(issued, decision)
        except ValueError as error:
            raise ValueError("RULE_SCOPE_ACTION_AUTHORITY_MISMATCH") from error
        action = self._records.get_exact(decision.action_ref)
        if (
            not isinstance(action, ActionRequest)
            or reference(action) != decision.action_ref
            or action.action_type != ActionType.CALL_RULE_SCOPE_GATE
            or action.requested_by != RequesterRole.VERIFICATION
            or action.requester_identity_ref != owner_ref
            or action.work_ref != reference(work)
            or action.llm_call_spec_ref != call.call_spec_ref
            or not isinstance(action.meta, RecordMeta)
            or (
                action.meta.analysis_id,
                action.meta.workspace_id,
                action.meta.commit_id,
                action.meta.hypothesis_id,
                action.meta.attempt_id,
            )
            != expected_scope
        ):
            raise ValueError("RULE_SCOPE_ACTION_AUTHORITY_MISMATCH")
        reservation = self._records.get_exact(call.reservation_ref)
        if (
            not isinstance(reservation, BudgetReservation)
            or reference(reservation) != call.reservation_ref
            or reservation.action_ref != decision.action_ref
            or reservation.work_ref != reference(work)
            or not isinstance(reservation.meta, RecordMeta)
            or (
                reservation.meta.analysis_id,
                reservation.meta.workspace_id,
                reservation.meta.commit_id,
                reservation.meta.hypothesis_id,
                reservation.meta.attempt_id,
            )
            != expected_scope
        ):
            raise ValueError("RULE_SCOPE_RESERVATION_MISMATCH")
        spec = self._records.get_exact(call.call_spec_ref)
        if (
            not isinstance(spec, LLMCallSpec)
            or reference(spec) != call.call_spec_ref
            or spec.agent_role != "RULE_SCOPE_GATE"
            or spec.task_kind != "REVIEW"
            or spec.session_policy != "NEW"
            or spec.parent_session_ref is not None
            or tuple(spec.context_refs) != required_context
            or not isinstance(spec.meta, RecordMeta)
            or (
                spec.meta.analysis_id,
                spec.meta.workspace_id,
                spec.meta.commit_id,
                spec.meta.hypothesis_id,
                spec.meta.attempt_id,
            )
            != expected_scope
        ):
            raise ValueError("RULE_SCOPE_CALL_SPEC_MISMATCH")
        request_fields = (
            "llm_call_id",
            "agent_role",
            "task_kind",
            "purpose",
            "provider_profile_ref",
            "model",
            "session_policy",
            "parent_session_ref",
            "context_refs",
            "prompt_registry_entry_ref",
            "prompt_key",
            "prompt_template_ref",
            "prompt_template_version",
            "prompt_payload_ref",
            "execution_limits_ref",
            "retry_policy_ref",
            "tool_policy_ref",
            "redaction_policy_ref",
            "semantic_validator_ref",
            "output_schema_ref",
            "output_schema",
            "token_budget",
            "timeout_ms",
        )
        log_fields = tuple(
            name
            for name in request_fields
            if name not in {"output_schema", "token_budget", "timeout_ms"}
        )
        if any(
            getattr(request, name) != getattr(spec, name) for name in request_fields
        ):
            raise ValueError("RULE_SCOPE_INVOCATION_CLOSURE_MISMATCH")
        if any(getattr(log_value, name) != getattr(spec, name) for name in log_fields):
            raise ValueError("RULE_SCOPE_INVOCATION_CLOSURE_MISMATCH")
        if (
            log_value.action_decision_ref != request.action_decision_ref
            or log_value.call_spec_ref != request.call_spec_ref
            or log_value.status != result.status
            or log_value.provider != result.provider
            or log_value.model != result.model
            or log_value.session_ref != result.session_ref
            or log_value.exposed_response_ref != result.response_ref
            or log_value.parsed_output_ref != result.parsed_output_ref
            or log_value.usage != result.usage
            or log_value.safe_error != result.safe_error
        ):
            raise ValueError("RULE_SCOPE_INVOCATION_CLOSURE_MISMATCH")
        tool_policy = self._records.get_exact(spec.tool_policy_ref)
        if (
            not isinstance(tool_policy, LLMToolPolicy)
            or reference(tool_policy) != spec.tool_policy_ref
            or tool_policy.policy_key != "tools.none.v1"
            or tool_policy.allowed_tools
        ):
            raise ValueError("RULE_SCOPE_TOOLS_FORBIDDEN")


__all__ = [
    "RuleScopeAgentOutcome",
    "RuleScopeCallRefs",
    "RuleScopeEvidenceSelection",
    "RuleScopeGateAgent",
    "RuleScopeMissingInfoProposal",
    "RuleScopeProposal",
]
