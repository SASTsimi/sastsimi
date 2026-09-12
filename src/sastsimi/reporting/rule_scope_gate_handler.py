"""Production-facing Rule Scope work resolution and result adapter."""

from __future__ import annotations

from hashlib import sha256
from typing import Protocol

from sastsimi.agents.rule_scope_gate import RuleScopeCallRefs
from sastsimi.contracts.domain import DomainRecord
from sastsimi.contracts.gates import (
    CWELabel,
    RuleScopeImpactReview,
    TechnicalEvidenceReview,
)
from sastsimi.contracts.policy import (
    PolicyCollectionResult,
    ProgramPolicyRecord,
    RunPolicyState,
)
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import WorkType
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.dto import WorkContext, WorkHandlerResult
from sastsimi.ports.record_store import RecordStore
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation
from sastsimi.runtime.workflow_runner import WorkflowRunner

from .cwe_work_handler import _require_claimed
from .rule_scope_gate_workflow import (
    CurrentOwner,
    OfficialSourceBinding,
    RuleScopeExecution,
    RuleScopeGateInputs,
    RuleScopeGateService,
    _expected_rule_scope_evidence,
)


class CompletingRunner(Protocol):
    def complete(self, *args: object, **kwargs: object) -> object: ...


class RuleScopeCallResolver(Protocol):
    def __call__(self, context: WorkContext) -> RuleScopeCallRefs: ...


class RuleScopeInputResolver(Protocol):
    def __call__(
        self, context: WorkContext
    ) -> tuple[RuleScopeGateInputs, RuleScopeExecution]: ...


class StoredRuleScopeInputResolver:
    """Resolve one claimed work's immutable inputs and its post-claim LLM call."""

    def __init__(
        self,
        *,
        records: RecordStore,
        artifacts: ArtifactStore,
        resolve_call: RuleScopeCallResolver,
        current_owner: CurrentOwner,
        gate_identity_ref: StoredDataRef,
    ) -> None:
        self._records = records
        self._artifacts = artifacts
        self.resolve_call = resolve_call
        self._current_owner = current_owner
        self._gate_identity_ref = gate_identity_ref

    def __call__(
        self, context: WorkContext
    ) -> tuple[RuleScopeGateInputs, RuleScopeExecution]:
        _require_claimed(context, WorkType.RULE_SCOPE_GATE)
        work = context.work
        verification_ref = _one(work.input_refs, "verification_result")
        label_ref = _one(work.input_refs, "cwe_label")
        technical_ref = _one(work.input_refs, "technical_evidence_review")
        state_ref = _one(work.input_refs, "run_policy_state")
        collection_ref = _one(work.input_refs, "policy_collection_result")
        verification = self._exact(verification_ref, VerificationResult)
        label = self._exact(label_ref, CWELabel)
        technical = self._exact(technical_ref, TechnicalEvidenceReview)
        state = self._exact(state_ref, RunPolicyState)
        collection = self._exact(collection_ref, PolicyCollectionResult)
        policy_refs = tuple(
            ref
            for ref in work.input_refs
            if isinstance(ref, StoredDataRef)
            and ref.data_kind == "program_policy_record"
        )
        if len(policy_refs) > 1:
            raise ValueError("RULE_SCOPE_INPUT_CARDINALITY_MISMATCH")
        policy_ref = policy_refs[0] if policy_refs else None
        policy = (
            self._exact(policy_ref, ProgramPolicyRecord)
            if policy_ref is not None
            else None
        )
        source_refs = (
            tuple(collection.official_source_refs)
            if collection.status == "FOUND"
            else ()
        )
        source_urls = (
            {check.source_ref: check.source_url for check in policy.source_checks}
            if policy is not None
            else {}
        )
        sources = tuple(
            self._official_source(ref, source_urls.get(ref)) for ref in source_refs
        )
        evidence = _expected_rule_scope_evidence(
            verification=verification,
            label=label,
            state=state,
            policy=policy,
            source_refs=source_refs,
        )
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
            official_sources=sources,
            available_evidence_refs=evidence,
            verification_owner_ref=self._current_owner(verification),
            current_generation=work.work_generation,
        )
        execution = RuleScopeExecution(
            work=work,
            call=self.resolve_call(context),
            owner_ref=inputs.verification_owner_ref,
            gate_identity_ref=self._gate_identity_ref,
        )
        return inputs, execution

    def _official_source(
        self, ref: StoredDataRef, source_locator: str | None
    ) -> OfficialSourceBinding:
        if source_locator is None:
            raise ValueError("OFFICIAL_POLICY_SOURCE_LOCATOR_MISMATCH")
        try:
            with self._artifacts.open_verified(ref) as stream:
                raw = stream.read()
            body = raw.decode("utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise ValueError("OFFICIAL_POLICY_SOURCE_INVALID") from error
        if sha256(raw).hexdigest() != ref.content_hash:
            raise ValueError("OFFICIAL_POLICY_SOURCE_DIGEST_MISMATCH")
        return OfficialSourceBinding(
            source_ref=ref,
            source_locator=source_locator,
            content_hash=ref.content_hash,
            redacted_body=body,
        )

    def _exact[T: DomainRecord](self, ref: StoredDataRef, model: type[T]) -> T:
        value = self._records.get_exact(ref)
        if not isinstance(value, model) or reference(value) != ref:
            raise ValueError("RECORD_REVISION_MISMATCH")
        return value


class WorkflowRuleScopePublisher:
    """Save with RULE_SCOPE_GATE identity; never with Verification identity."""

    def __init__(self, runner: WorkflowRunner) -> None:
        self._runner = runner

    def __call__(
        self,
        execution: RuleScopeExecution,
        review: RuleScopeImpactReview,
        invocation: PersistedLLMInvocation,
    ) -> StoredDataRef:
        if execution.gate_identity_ref is None:
            raise ValueError("RULE_SCOPE_GATE_IDENTITY_REQUIRED")
        completed = self._runner.complete(
            execution.work,
            execution.gate_identity_ref,
            "RULE_SCOPE_GATE",
            (review,),
            action_input_refs=self._save_inputs(execution, invocation),
        )
        output_ref = completed.output_refs[0]
        if not isinstance(output_ref, StoredDataRef):
            raise ValueError("RULE_SCOPE_REVIEW_COMMIT_MISMATCH")
        return output_ref

    @staticmethod
    def _save_inputs(
        execution: RuleScopeExecution,
        invocation: PersistedLLMInvocation,
    ) -> tuple[RecordRef, ...]:
        refs: tuple[RecordRef, ...] = (
            *execution.work.input_refs,
            execution.call.decision_ref,
            execution.call.reservation_ref,
            execution.call.call_spec_ref,
            invocation.request.action_decision_ref,
            reference(invocation.request),
            reference(invocation.result),
            invocation.log_ref,
        )
        if invocation.result.parsed_output_ref is not None:
            refs = (*refs, invocation.result.parsed_output_ref)
        return tuple(dict.fromkeys(refs))


class RuleScopeGateHandler:
    """Scheduler handler; the service itself preserves the no-work stop branch."""

    def __init__(
        self,
        service: RuleScopeGateService,
        *,
        resolve_inputs: RuleScopeInputResolver,
    ) -> None:
        self._service = service
        self.resolve_inputs = resolve_inputs

    async def execute(self, context: WorkContext) -> WorkHandlerResult:
        _require_claimed(context, WorkType.RULE_SCOPE_GATE)
        inputs, execution = self.resolve_inputs(context)
        if execution.work != context.work:
            raise ValueError("RULE_SCOPE_WORK_CONTEXT_MISMATCH")
        outcome = await self._service.review(inputs, execution=execution)
        if outcome.review_ref is None:
            raise ValueError("RULE_SCOPE_WORK_NOT_REQUIRED")
        return WorkHandlerResult((outcome.review_ref,))


def _one(refs: tuple[RecordRef, ...], kind: str) -> StoredDataRef:
    values = tuple(
        ref for ref in refs if isinstance(ref, StoredDataRef) and ref.data_kind == kind
    )
    if len(values) != 1:
        raise ValueError("RULE_SCOPE_INPUT_CARDINALITY_MISMATCH")
    return values[0]


__all__ = [
    "RuleScopeCallResolver",
    "RuleScopeGateHandler",
    "RuleScopeInputResolver",
    "StoredRuleScopeInputResolver",
    "WorkflowRuleScopePublisher",
]
