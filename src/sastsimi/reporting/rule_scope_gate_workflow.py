"""Trusted Rule Scope Gate preflight, finalization, and fail-closed stopping."""

from __future__ import annotations

from dataclasses import dataclass
from typing import BinaryIO, Literal, Protocol

from pydantic import model_validator

from sastsimi.agents.rule_scope_gate import (
    RuleScopeAgentOutcome,
    RuleScopeCallRefs,
    RuleScopeGateAgent,
    RuleScopeProposal,
)
from sastsimi.contracts.base import ContractModel, NonEmptyStr, Sha256
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.domain import DomainRecord, exact_set, same_scope
from sastsimi.contracts.gates import (
    CWELabel,
    RuleScopeEvidenceLink,
    RuleScopeImpactReview,
    TechnicalEvidenceReview,
    validate_rule_scope_gate,
)
from sastsimi.contracts.ids import AttemptId
from sastsimi.contracts.llm import LLMCallSpec, LLMToolPolicy, PromptPayload
from sastsimi.contracts.policy import (
    PolicyCollectionResult,
    PolicyMissingInfo,
    ProgramPolicyRecord,
    RunPolicyState,
    validate_policy_freshness,
)
from sastsimi.contracts.prompt_redaction import assert_safe_provider_text
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import WorkExecutionState, WorkStatus, WorkType
from sastsimi.runtime.llm_call_service import PersistedLLMInvocation


class OfficialSourceBinding(ContractModel):
    """Redacted official source body and its immutable artifact provenance."""

    source_ref: StoredDataRef
    source_locator: NonEmptyStr
    content_hash: Sha256
    redacted_body: NonEmptyStr

    @model_validator(mode="after")
    def exact_digest(self) -> OfficialSourceBinding:
        if (
            self.source_ref.record_id is not None
            or self.source_ref.content_hash != self.content_hash
            or str(self.source_ref.stored_data_id) != self.content_hash
        ):
            raise ValueError("OFFICIAL_POLICY_SOURCE_DIGEST_MISMATCH")
        assert_safe_provider_text(self.redacted_body.encode("utf-8"))
        return self


@dataclass(frozen=True)
class RuleScopeGateInputs:
    verification: VerificationResult
    verification_ref: StoredDataRef
    cwe_label: CWELabel
    cwe_label_ref: StoredDataRef
    technical_review: TechnicalEvidenceReview
    technical_review_ref: StoredDataRef
    run_policy_state: RunPolicyState
    run_policy_state_ref: StoredDataRef
    collection: PolicyCollectionResult
    collection_ref: StoredDataRef
    policy: ProgramPolicyRecord | None
    policy_ref: StoredDataRef | None
    official_sources: tuple[OfficialSourceBinding, ...]
    available_evidence_refs: tuple[StoredDataRef, ...]
    verification_owner_ref: StoredDataRef
    current_generation: int


@dataclass(frozen=True)
class RuleScopeExecution:
    work: WorkExecutionState
    call: RuleScopeCallRefs
    owner_ref: StoredDataRef
    gate_identity_ref: StoredDataRef | None = None


@dataclass(frozen=True)
class RuleScopeGateOutcome:
    review: RuleScopeImpactReview | None
    review_ref: StoredDataRef | None
    stop_reason: Literal["POLICY_COLLECTION_FAILED"] | None


def _expected_rule_scope_evidence(
    *,
    verification: VerificationResult,
    label: CWELabel,
    state: RunPolicyState,
    policy: ProgramPolicyRecord | None,
    source_refs: tuple[StoredDataRef, ...],
) -> tuple[StoredDataRef, ...]:
    """Build the one canonical evidence closure used by resolution and preflight."""
    if verification.dynamic_result_ref is None or verification.poc_ref is None:
        raise ValueError("VALIDATED_POC_REQUIRED")
    values = (
        *source_refs,
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
            for result in verification.falsification_results
            for evidence_ref in result.evidence_refs
        ),
        *(
            evidence_ref
            for result in verification.validation_results
            for evidence_ref in result.evidence_refs
        ),
        *(
            evidence_ref
            for restriction in verification.restrictions
            for evidence_ref in restriction.evidence_refs
        ),
        *(
            fact.bundle_ref
            for restriction in verification.restrictions
            for fact in restriction.fact_refs
        ),
        *label.evidence_refs,
        verification.dynamic_result_ref,
        verification.poc_ref,
        *state.freshness_evidence_refs,
        *(
            evidence_ref
            for check in (policy.source_checks if policy is not None else ())
            for evidence_ref in check.evidence_refs
        ),
        *(policy.freshness_evidence_refs if policy is not None else ()),
        *(
            evidence_ref
            for gap in (policy.missing_information if policy is not None else ())
            for evidence_ref in gap.evidence_refs
        ),
    )
    return tuple(dict.fromkeys(values))


class AgentPort(Protocol):
    async def review(self, **kwargs: object) -> RuleScopeAgentOutcome: ...


class ExecutionFactory(Protocol):
    def __call__(self, inputs: RuleScopeGateInputs) -> RuleScopeExecution: ...


class ReviewPublisher(Protocol):
    def __call__(
        self,
        execution: RuleScopeExecution,
        review: RuleScopeImpactReview,
        invocation: PersistedLLMInvocation,
    ) -> StoredDataRef: ...


class MetadataFactory(Protocol):
    def __call__(
        self, source: RecordMeta, record_type: str, attempt_id: AttemptId | None
    ) -> RecordMeta: ...


class IdFactory(Protocol):
    def __call__(self, prefix: str) -> str: ...


class CurrentOwner(Protocol):
    def __call__(self, verification: VerificationResult) -> StoredDataRef: ...


class CurrentPolicyState(Protocol):
    def __call__(self, analysis_id: str) -> StoredDataRef: ...


class PromptBindingGuard(Protocol):
    def __call__(
        self,
        execution: RuleScopeExecution,
        inputs: RuleScopeGateInputs,
        required_context: tuple[StoredDataRef, ...],
    ) -> None: ...


class PromptRecordReader(Protocol):
    def get_exact(self, ref: StoredDataRef) -> object: ...


class PromptArtifactReader(Protocol):
    def open_verified(self, ref: StoredDataRef) -> BinaryIO: ...


class ExactRuleScopePromptGuard:
    """Fail before dispatch unless the prompt pins exact redacted official bytes."""

    def __init__(
        self, *, records: PromptRecordReader, artifacts: PromptArtifactReader
    ) -> None:
        self._records = records
        self._artifacts = artifacts

    def __call__(
        self,
        execution: RuleScopeExecution,
        inputs: RuleScopeGateInputs,
        required_context: tuple[StoredDataRef, ...],
    ) -> None:
        spec_value = self._records.get_exact(execution.call.call_spec_ref)
        if (
            not isinstance(spec_value, LLMCallSpec)
            or reference(spec_value) != execution.call.call_spec_ref
            or spec_value.agent_role != "RULE_SCOPE_GATE"
            or spec_value.task_kind != "REVIEW"
            or spec_value.session_policy != "NEW"
            or spec_value.parent_session_ref is not None
            or tuple(spec_value.context_refs) != required_context
        ):
            raise ValueError("RULE_SCOPE_CALL_SPEC_MISMATCH")
        payload_value = self._records.get_exact(spec_value.prompt_payload_ref)
        if (
            not isinstance(payload_value, PromptPayload)
            or reference(payload_value) != spec_value.prompt_payload_ref
            or payload_value.agent_role != "RULE_SCOPE_GATE"
            or payload_value.task_kind != "REVIEW"
            or payload_value.prompt_key != spec_value.prompt_key
            or payload_value.template_ref != spec_value.prompt_template_ref
            or payload_value.output_schema_ref != spec_value.output_schema_ref
        ):
            raise ValueError("RULE_SCOPE_PROMPT_BINDING_MISMATCH")
        try:
            exact_set(
                (binding.source_ref for binding in payload_value.context_bindings),
                required_context,
            )
        except ValueError as error:
            raise ValueError("RULE_SCOPE_PROMPT_BINDING_MISMATCH") from error
        bindings = {
            binding.source_ref: binding for binding in payload_value.context_bindings
        }
        for source in inputs.official_sources:
            binding = bindings.get(source.source_ref)
            if binding is None:
                raise ValueError("RULE_SCOPE_PROMPT_BINDING_MISMATCH")
            with self._artifacts.open_verified(binding.projected_data_ref) as stream:
                if stream.read() != canonical_bytes(source):
                    raise ValueError("RULE_SCOPE_PROMPT_SOURCE_MISMATCH")
        tool_value = self._records.get_exact(spec_value.tool_policy_ref)
        if (
            not isinstance(tool_value, LLMToolPolicy)
            or reference(tool_value) != spec_value.tool_policy_ref
            or tool_value.policy_key != "tools.none.v1"
            or tool_value.allowed_tools
        ):
            raise ValueError("RULE_SCOPE_TOOLS_FORBIDDEN")


class RuleScopeGateService:
    """Run only after exact TRUE/CWE/Technical/policy preflight succeeds."""

    def __init__(
        self,
        *,
        agent: AgentPort | RuleScopeGateAgent,
        execution_factory: ExecutionFactory | None,
        publisher: ReviewPublisher,
        metadata_factory: MetadataFactory,
        id_factory: IdFactory,
        current_owner: CurrentOwner,
        current_policy_state: CurrentPolicyState,
        prompt_guard: PromptBindingGuard,
    ) -> None:
        self._agent = agent
        self._execution_factory = execution_factory
        self._publisher = publisher
        self._metadata = metadata_factory
        self._ids = id_factory
        self._current_owner = current_owner
        self._current_policy_state = current_policy_state
        self._prompt_guard = prompt_guard

    async def review(
        self,
        inputs: RuleScopeGateInputs,
        *,
        execution: RuleScopeExecution | None = None,
    ) -> RuleScopeGateOutcome:
        # Validate the current failure pointer, but never create work or call an LLM.
        if inputs.collection.status == "COLLECTION_FAILED":
            self._preflight_collection_failure(inputs)
            return RuleScopeGateOutcome(None, None, "POLICY_COLLECTION_FAILED")

        required_context = self._preflight(inputs)
        if execution is None:
            if self._execution_factory is None:
                raise ValueError("RULE_SCOPE_EXECUTION_REQUIRED")
            execution = self._execution_factory(inputs)
        self._require_execution(execution, inputs, required_context)
        self._prompt_guard(execution, inputs, required_context)
        outcome = await self._agent.review(
            work=execution.work,
            call=execution.call,
            owner_ref=execution.owner_ref,
            required_context=required_context,
        )
        review = self._finalize(inputs, execution, outcome)
        review_ref = self._publisher(execution, review, outcome.invocation)
        if review_ref != reference(review):
            raise ValueError("RULE_SCOPE_REVIEW_COMMIT_MISMATCH")
        return RuleScopeGateOutcome(review, review_ref, None)

    def _preflight_collection_failure(self, inputs: RuleScopeGateInputs) -> None:
        self._require_exact_ref(inputs.collection_ref, inputs.collection)
        self._require_exact_ref(inputs.run_policy_state_ref, inputs.run_policy_state)
        if (
            self._current_policy_state(str(inputs.verification.meta.analysis_id))
            != inputs.run_policy_state_ref
        ):
            raise ValueError("STALE_RUN_POLICY_STATE")
        if (
            inputs.run_policy_state.status not in {"BLOCKED", "FAILED"}
            or inputs.run_policy_state.collection_result_ref != inputs.collection_ref
            or inputs.run_policy_state.program_id != inputs.collection.program_id
            or inputs.run_policy_state.policy_record_ref is not None
            or inputs.policy is not None
            or inputs.policy_ref is not None
        ):
            raise ValueError("GATE_POLICY_CLOSURE_MISMATCH")

    def _preflight(self, inputs: RuleScopeGateInputs) -> tuple[StoredDataRef, ...]:
        for ref, record in (
            (inputs.verification_ref, inputs.verification),
            (inputs.cwe_label_ref, inputs.cwe_label),
            (inputs.technical_review_ref, inputs.technical_review),
            (inputs.run_policy_state_ref, inputs.run_policy_state),
            (inputs.collection_ref, inputs.collection),
        ):
            self._require_exact_ref(ref, record)
        if (inputs.policy is None) != (inputs.policy_ref is None):
            raise ValueError("POLICY_RECORD_REQUIRED")
        if inputs.policy is not None and inputs.policy_ref is not None:
            self._require_exact_ref(inputs.policy_ref, inputs.policy)

        verification = inputs.verification
        label = inputs.cwe_label
        technical = inputs.technical_review
        if (
            verification.verdict != "TRUE"
            or label.verification_result_ref != inputs.verification_ref
            or label.verification_generation != inputs.current_generation
            or technical.status != "ACCEPT"
            or technical.handoff_readiness != "READY"
            or technical.verification_result_ref != inputs.verification_ref
            or technical.cwe_label_ref != inputs.cwe_label_ref
        ):
            raise ValueError("GATE_ORDER_BYPASS")
        same_scope(verification.meta, label.meta)
        same_scope(verification.meta, technical.meta)
        if self._current_owner(verification) != inputs.verification_owner_ref:
            raise ValueError("STALE_VERIFICATION_OWNER")
        if (
            self._current_policy_state(str(verification.meta.analysis_id))
            != inputs.run_policy_state_ref
        ):
            raise ValueError("STALE_RUN_POLICY_STATE")

        state, collection, policy = (
            inputs.run_policy_state,
            inputs.collection,
            inputs.policy,
        )
        if (
            state.status not in {"CURRENT", "ABSENT", "UNVERIFIED"}
            or state.collection_result_ref != inputs.collection_ref
            or state.policy_record_ref != inputs.policy_ref
            or collection.policy_record_ref != inputs.policy_ref
            or state.program_id != collection.program_id
        ):
            raise ValueError("GATE_POLICY_CLOSURE_MISMATCH")
        if state.status == "CURRENT":
            if collection.status != "FOUND" or policy is None:
                raise ValueError("POLICY_STATE_STATUS_MISMATCH")
            validate_policy_freshness(state, policy)
        elif state.status == "ABSENT" and collection.status != "ABSENT_CONFIRMED":
            raise ValueError("POLICY_STATE_STATUS_MISMATCH")

        source_refs = tuple(item.source_ref for item in inputs.official_sources)
        if len(source_refs) != len(set(source_refs)):
            raise ValueError("DUPLICATE_OFFICIAL_POLICY_SOURCE")
        if collection.status == "FOUND":
            assert policy is not None
            try:
                exact_set(source_refs, collection.official_source_refs)
                exact_set(source_refs, policy.source_refs)
            except ValueError as error:
                raise ValueError("OFFICIAL_POLICY_SOURCE_SET_MISMATCH") from error
            source_urls = {
                check.source_ref: check.source_url for check in policy.source_checks
            }
            if any(
                source_urls.get(binding.source_ref) != binding.source_locator
                for binding in inputs.official_sources
            ):
                raise ValueError("OFFICIAL_POLICY_SOURCE_LOCATOR_MISMATCH")
        expected_evidence = self._expected_evidence(inputs, source_refs)
        try:
            exact_set(inputs.available_evidence_refs, expected_evidence)
        except ValueError as error:
            raise ValueError("RULE_SCOPE_EVIDENCE_CLOSURE_MISMATCH") from error
        if any(ref not in inputs.available_evidence_refs for ref in source_refs):
            raise ValueError("RULE_SCOPE_EVIDENCE_CLOSURE_MISMATCH")

        return tuple(
            dict.fromkeys(
                (
                    inputs.verification_ref,
                    inputs.cwe_label_ref,
                    inputs.technical_review_ref,
                    inputs.run_policy_state_ref,
                    inputs.collection_ref,
                    *((inputs.policy_ref,) if inputs.policy_ref is not None else ()),
                    *source_refs,
                    *inputs.available_evidence_refs,
                )
            )
        )

    @staticmethod
    def _expected_evidence(
        inputs: RuleScopeGateInputs,
        source_refs: tuple[StoredDataRef, ...],
    ) -> tuple[StoredDataRef, ...]:
        return _expected_rule_scope_evidence(
            verification=inputs.verification,
            label=inputs.cwe_label,
            state=inputs.run_policy_state,
            policy=inputs.policy,
            source_refs=source_refs,
        )

    @staticmethod
    def _require_exact_ref(ref: StoredDataRef, record: DomainRecord) -> None:
        if reference(record) != ref:
            raise ValueError("RECORD_REVISION_MISMATCH")

    @staticmethod
    def _require_execution(
        execution: RuleScopeExecution,
        inputs: RuleScopeGateInputs,
        required_context: tuple[StoredDataRef, ...],
    ) -> None:
        work = execution.work
        if (
            not isinstance(work.meta, RecordMeta)
            or work.work_type != WorkType.RULE_SCOPE_GATE
            or work.status != WorkStatus.RUNNING
            or work.active_attempt_id is None
            or work.work_generation != inputs.current_generation
            or work.meta.hypothesis_id != inputs.verification.meta.hypothesis_id
            or execution.owner_ref != inputs.verification_owner_ref
            or tuple(work.input_refs) != required_context
        ):
            raise ValueError("RULE_SCOPE_WORK_CLOSURE_MISMATCH")

    def _finalize(
        self,
        inputs: RuleScopeGateInputs,
        execution: RuleScopeExecution,
        outcome: RuleScopeAgentOutcome,
    ) -> RuleScopeImpactReview:
        if not isinstance(execution.work.meta, RecordMeta):
            raise ValueError("RULE_SCOPE_WORK_CLOSURE_MISMATCH")
        proposal = outcome.proposal
        self._require_canonical_uncertain(inputs, proposal)
        policy_item_ids = (
            {item.policy_item_id for item in inputs.policy.items()}
            if inputs.policy is not None
            else set()
        )
        links = tuple(
            RuleScopeEvidenceLink(
                link_id=self._ids("rule-scope-link"),
                area=item.area,
                policy_item_ids=item.policy_item_ids,
                evidence_refs=self._selected_evidence(
                    item.evidence_indexes, inputs.available_evidence_refs
                ),
            )
            for item in proposal.evidence_links
        )
        missing = tuple(
            PolicyMissingInfo(
                missing_info_id=self._ids("rule-scope-missing"),
                area=item.area,
                blocks_allow=True,
                description=item.description,
                policy_item_ids=item.policy_item_ids,
                evidence_refs=self._selected_evidence(
                    item.evidence_indexes,
                    inputs.available_evidence_refs,
                    allow_empty=True,
                ),
            )
            for item in proposal.missing_information
        )
        if inputs.policy is not None and any(
            not link.policy_item_ids for link in links
        ):
            raise ValueError("POLICY_ITEM_EVIDENCE_REQUIRED")
        selected_item_ids = (
            *(item_id for link in links for item_id in link.policy_item_ids),
            *(item_id for gap in missing for item_id in gap.policy_item_ids),
        )
        if any(item_id not in policy_item_ids for item_id in selected_item_ids):
            raise ValueError("POLICY_ITEM_CLOSURE_MISMATCH")
        review_status = self._review_status(proposal)
        meta = self._metadata(
            execution.work.meta,
            "rule_scope_impact_review",
            execution.work.active_attempt_id,
        )
        if (
            meta.record_type != "rule_scope_impact_review"
            or meta.analysis_id != execution.work.meta.analysis_id
            or meta.workspace_id != execution.work.meta.workspace_id
            or meta.commit_id != execution.work.meta.commit_id
            or meta.hypothesis_id != execution.work.meta.hypothesis_id
            or meta.attempt_id != execution.work.active_attempt_id
        ):
            raise ValueError("RULE_SCOPE_RUNTIME_METADATA_MISMATCH")
        review = RuleScopeImpactReview(
            meta=meta,
            action_decision_ref=outcome.action_decision_ref,
            verification_result_ref=inputs.verification_ref,
            technical_review_ref=inputs.technical_review_ref,
            cwe_label_ref=inputs.cwe_label_ref,
            run_policy_state_ref=inputs.run_policy_state_ref,
            policy_collection_result_ref=inputs.collection_ref,
            policy_record_ref=inputs.policy_ref,
            review_status=review_status,
            rule_compliance=proposal.rule_compliance,
            scope_compliance=proposal.scope_compliance,
            testing_restriction_compliance=proposal.testing_restriction_compliance,
            security_impact=proposal.security_impact,
            report_permission=proposal.report_permission,
            evidence_links=links,
            reasons=proposal.reasons,
            missing_information=missing,
        )
        validate_rule_scope_gate(
            review,
            inputs.technical_review,
            inputs.run_policy_state,
            inputs.collection,
            inputs.policy,
        )
        return review

    @staticmethod
    def _selected_evidence(
        indexes: tuple[int, ...],
        available: tuple[StoredDataRef, ...],
        *,
        allow_empty: bool = False,
    ) -> tuple[StoredDataRef, ...]:
        if (not indexes and not allow_empty) or any(
            index >= len(available) for index in indexes
        ):
            raise ValueError("RULE_SCOPE_EVIDENCE_SELECTION_INVALID")
        return tuple(available[index] for index in indexes)

    @staticmethod
    def _review_status(
        proposal: RuleScopeProposal,
    ) -> Literal["PASS", "FAIL", "UNCERTAIN"]:
        axes = (
            proposal.rule_compliance,
            proposal.scope_compliance,
            proposal.testing_restriction_compliance,
        )
        if "FAIL" in axes or proposal.security_impact == "INSUFFICIENT":
            return "FAIL"
        if "UNCERTAIN" in axes or proposal.security_impact == "UNCERTAIN":
            return "UNCERTAIN"
        return "PASS"

    @staticmethod
    def _require_canonical_uncertain(
        inputs: RuleScopeGateInputs, proposal: RuleScopeProposal
    ) -> None:
        if (
            inputs.collection.status == "ABSENT_CONFIRMED"
            or inputs.run_policy_state.status == "UNVERIFIED"
        ) and (
            proposal.rule_compliance,
            proposal.scope_compliance,
            proposal.testing_restriction_compliance,
            proposal.security_impact,
            proposal.report_permission,
        ) != ("UNCERTAIN", "UNCERTAIN", "UNCERTAIN", "UNCERTAIN", "DENY"):
            raise ValueError("UNVERIFIED_POLICY_GATE_MISMATCH")


__all__ = [
    "ExactRuleScopePromptGuard",
    "OfficialSourceBinding",
    "RuleScopeExecution",
    "RuleScopeGateInputs",
    "RuleScopeGateOutcome",
    "RuleScopeGateService",
]
