"""Hypothesis LLM boundary and trusted proposal finalization."""

from __future__ import annotations

import json
from typing import Protocol, cast

from pydantic import JsonValue, ValidationError

from sastsimi.contracts.base import ContractModel, NonEmptyStr
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.hypothesis import (
    FalsificationQuestion,
    HypothesisProposal,
    ValidationCheck,
    validate_proposal_facts,
)
from sastsimi.contracts.ids import (
    LogicalRecordId,
    ProposalId,
    RecordId,
)
from sastsimi.contracts.llm import PromptPayload
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RecordRef, StoredDataRef, reference
from sastsimi.contracts.scopes import same_scope
from sastsimi.contracts.static import (
    CodeFact,
    CodeLocation,
    CodeRelation,
    CodeSymbol,
    Restriction,
    StaticFactBundle,
)
from sastsimi.contracts.work import WorkExecutionState, WorkStatus, WorkType
from sastsimi.ports.artifact_store import ArtifactStore
from sastsimi.ports.clock import Clock
from sastsimi.ports.id_generator import IdGenerator
from sastsimi.ports.llm_invocation import (
    HypothesisAgentOutcome as HypothesisAgentOutcome,
)
from sastsimi.ports.llm_invocation import PersistedLLMInvocation
from sastsimi.prompts.builder import PromptBuilder, PromptSource
from sastsimi.prompts.registry import LoadedPromptDefinition


class HypothesisLLMCall(Protocol):
    """The narrow T09 LLMCallService surface used by this Agent."""

    async def invoke(
        self,
        *,
        work: WorkExecutionState,
        decision_ref: StoredDataRef,
        reservation_ref: RecordRef,
        call_spec_ref: StoredDataRef,
    ) -> PersistedLLMInvocation: ...


class _QuestionContent(ContractModel):
    question: NonEmptyStr


class _CheckContent(ContractModel):
    instruction: NonEmptyStr


class _ProposalContent(ContractModel):
    """Content an untrusted Provider may propose; no runtime-owned fields."""

    statement: NonEmptyStr
    vulnerability_type_candidates: tuple[NonEmptyStr, ...]
    target_entities: tuple[CodeSymbol, ...]
    target_locations: tuple[CodeLocation, ...]
    suspected_path: tuple[CodeRelation | CodeLocation, ...]
    observed_facts: tuple[CodeFact, ...]
    assumptions: tuple[NonEmptyStr, ...]
    restrictions: tuple[Restriction, ...]
    falsification_questions: tuple[_QuestionContent, ...]
    validation_checks: tuple[_CheckContent, ...]


class HypothesisAgent:
    """Build the exact prompt, call T09, then cross the trusted ID boundary."""

    def __init__(
        self,
        *,
        prompt_builder: PromptBuilder,
        llm_calls: HypothesisLLMCall,
        artifacts: ArtifactStore,
        ids: IdGenerator,
        clock: Clock,
    ) -> None:
        self._prompt_builder = prompt_builder
        self._llm_calls = llm_calls
        self._artifacts = artifacts
        self._ids = ids
        self._clock = clock

    def prepare_prompt(
        self,
        *,
        definition: LoadedPromptDefinition,
        registry_entry_ref: StoredDataRef,
        work: WorkExecutionState,
        static_bundle: StaticFactBundle,
        static_bundle_ref: StoredDataRef,
    ) -> PromptPayload:
        """Create an exact redacted payload; persistence stays runtime-owned."""

        self._require_work_bundle(work, static_bundle, static_bundle_ref)
        entry = definition.entry
        if (
            entry.agent_role != "HYPOTHESIS"
            or entry.task_kind != "GENERATE_INITIAL"
            or entry.session_policy != "NEW"
            or entry.result_kind != "hypothesis_proposal"
        ):
            raise ValueError("HYPOTHESIS_PROMPT_BINDING_MISMATCH")
        return self._prompt_builder.build_payload(
            definition=definition,
            registry_entry_ref=registry_entry_ref,
            metadata=self._fresh_meta(work, "prompt_payload"),
            sources=(PromptSource("facts", static_bundle_ref, static_bundle),),
        )

    async def propose(
        self,
        *,
        work: WorkExecutionState,
        decision_ref: StoredDataRef,
        reservation_ref: RecordRef,
        call_spec_ref: StoredDataRef,
        static_bundle: StaticFactBundle,
        static_bundle_ref: StoredDataRef,
    ) -> HypothesisAgentOutcome:
        """Run one already-authorized call and finalize only a safe success."""

        self._require_work_bundle(work, static_bundle, static_bundle_ref)
        invocation = await self._llm_calls.invoke(
            work=work,
            decision_ref=decision_ref,
            reservation_ref=reservation_ref,
            call_spec_ref=call_spec_ref,
        )
        self._require_invocation_binding(
            invocation,
            work=work,
            call_spec_ref=call_spec_ref,
            static_bundle_ref=static_bundle_ref,
        )
        if invocation.result.status != "SUCCEEDED":
            return HypothesisAgentOutcome(invocation, ())
        contents = self._read_contents(invocation)
        proposals = tuple(
            self._finalize(content, work, static_bundle, static_bundle_ref)
            for content in contents
        )
        return HypothesisAgentOutcome(invocation, proposals)

    def _fresh_meta(self, work: WorkExecutionState, kind: str) -> RecordMeta:
        if not isinstance(work.meta, RecordMeta) or work.active_attempt_id is None:
            raise ValueError("HYPOTHESIS_WORK_NOT_ACTIVE")
        record_id = self._ids.new(RecordId)
        return RecordMeta(
            record_id=record_id,
            logical_record_id=LogicalRecordId(str(record_id)),
            record_type=kind,
            schema_version=work.meta.schema_version,
            revision_number=1,
            previous_record_id=None,
            created_at=self._clock.now(),
            analysis_id=work.meta.analysis_id,
            workspace_id=work.meta.workspace_id,
            commit_id=work.meta.commit_id,
            hypothesis_id=None,
            attempt_id=work.active_attempt_id,
        )

    @staticmethod
    def _require_work_bundle(
        work: WorkExecutionState,
        bundle: StaticFactBundle,
        bundle_ref: StoredDataRef,
    ) -> None:
        if (
            not isinstance(work.meta, RecordMeta)
            or work.meta.hypothesis_id is not None
            or work.meta.attempt_id is not None
            or work.work_type != WorkType.HYPOTHESIS_PROPOSAL
            or work.status != WorkStatus.RUNNING
            or work.active_attempt_id is None
            or reference(bundle) != bundle_ref
            or bundle.meta.hypothesis_id is not None
            or bundle.meta.attempt_id is not None
        ):
            raise ValueError("HYPOTHESIS_STATIC_CLOSURE_MISMATCH")
        same_scope(work.meta, bundle.meta, hypothesis=False)
        static_inputs = tuple(
            ref
            for ref in work.input_refs
            if isinstance(ref, StoredDataRef) and ref.data_kind == "static_fact_bundle"
        )
        if static_inputs != (bundle_ref,):
            raise ValueError("HYPOTHESIS_STATIC_CLOSURE_MISMATCH")

    @staticmethod
    def _require_invocation_binding(
        invocation: PersistedLLMInvocation,
        *,
        work: WorkExecutionState,
        call_spec_ref: StoredDataRef,
        static_bundle_ref: StoredDataRef,
    ) -> None:
        request, result = invocation.request, invocation.result
        if not isinstance(work.meta, RecordMeta):
            raise ValueError("HYPOTHESIS_INVOCATION_MISMATCH")
        scope = (
            "analysis_id",
            "workspace_id",
            "commit_id",
            "hypothesis_id",
            "attempt_id",
        )
        if (
            request.agent_role != "HYPOTHESIS"
            or request.task_kind != "GENERATE_INITIAL"
            or request.session_policy != "NEW"
            or request.parent_session_ref is not None
            or request.call_spec_ref != call_spec_ref
            or request.action_decision_ref.data_kind != "action_decision"
            or request.action_decision_ref.workspace_id != work.meta.workspace_id
            or request.action_decision_ref.commit_id != work.meta.commit_id
            or request.context_refs != (static_bundle_ref,)
            or request.meta.attempt_id != work.active_attempt_id
            or request.meta.hypothesis_id is not None
            or any(
                getattr(request.meta, field) != getattr(work.meta, field)
                for field in ("analysis_id", "workspace_id", "commit_id")
            )
            or result.llm_call_id != request.llm_call_id
            or result.purpose != request.purpose
            or result.model != request.model
            or any(
                getattr(result.meta, field) != getattr(request.meta, field)
                for field in scope
            )
            or invocation.log_ref.data_kind != "llm_invocation_log"
            or invocation.log_ref.workspace_id != work.meta.workspace_id
            or invocation.log_ref.commit_id != work.meta.commit_id
        ):
            raise ValueError("HYPOTHESIS_INVOCATION_MISMATCH")
        if result.status == "SUCCEEDED":
            output_ref = result.parsed_output_ref
            if (
                output_ref is None
                or result.response_ref != output_ref
                or output_ref.record_id is not None
                or output_ref.data_kind != "artifact"
                or output_ref.workspace_id != work.meta.workspace_id
                or output_ref.commit_id != work.meta.commit_id
            ):
                raise ValueError("HYPOTHESIS_OUTPUT_REFERENCE_MISMATCH")
        elif result.parsed_output_ref is not None or result.response_ref is not None:
            raise ValueError("HYPOTHESIS_OUTPUT_REFERENCE_MISMATCH")

    def _read_contents(
        self, invocation: PersistedLLMInvocation
    ) -> tuple[_ProposalContent, ...]:
        output_ref = invocation.result.parsed_output_ref
        if output_ref is None:
            raise ValueError("HYPOTHESIS_OUTPUT_REFERENCE_MISMATCH")
        try:
            with self._artifacts.open_verified(output_ref) as stream:
                raw = stream.read()
            value = json.loads(raw)
            if canonical_bytes(value) != raw or not isinstance(value, list):
                raise ValueError("HYPOTHESIS_OUTPUT_INVALID")
            _reject_runtime_authority(cast(JsonValue, value))
            contents = tuple(
                _ProposalContent.model_validate_json(canonical_bytes(item))
                for item in value
            )
        except ValueError:
            raise
        except (OSError, TypeError, ValidationError, json.JSONDecodeError) as error:
            raise ValueError("HYPOTHESIS_OUTPUT_INVALID") from error
        return contents

    def _finalize(
        self,
        content: _ProposalContent,
        work: WorkExecutionState,
        bundle: StaticFactBundle,
        bundle_ref: StoredDataRef,
    ) -> HypothesisProposal:
        proposal = HypothesisProposal(
            meta=self._fresh_meta(work, "hypothesis_proposal"),
            proposal_id=self._ids.new(ProposalId),
            proposal_state="HYPOTHESIS_ONLY",
            assertion_mode="NON_FINAL",
            origin="INITIAL",
            parent_hypothesis_ids=(),
            source_primitive_match_id=None,
            statement=content.statement,
            vulnerability_type_candidates=content.vulnerability_type_candidates,
            target_entities=content.target_entities,
            target_locations=content.target_locations,
            suspected_path=content.suspected_path,
            observed_facts=content.observed_facts,
            assumptions=content.assumptions,
            restrictions=content.restrictions,
            falsification_questions=tuple(
                FalsificationQuestion(
                    question_id=str(self._ids.new(RecordId)), question=item.question
                )
                for item in content.falsification_questions
            ),
            validation_checks=tuple(
                ValidationCheck(
                    validation_id=str(self._ids.new(RecordId)),
                    instruction=item.instruction,
                )
                for item in content.validation_checks
            ),
        )
        validate_proposal_facts(proposal, bundle, bundle_ref)
        _require_static_content(proposal, bundle)
        return proposal


def _reject_runtime_authority(value: JsonValue) -> None:
    if not isinstance(value, list):
        raise ValueError("HYPOTHESIS_OUTPUT_INVALID")
    top_level_denied = {
        "meta",
        "record_id",
        "logical_record_id",
        "hypothesis_id",
        "attempt_id",
        "proposal_id",
        "proposal_state",
        "assertion_mode",
        "origin",
        "parent_hypothesis_ids",
        "source_primitive_match_id",
    }
    for item in value:
        if not isinstance(item, dict) or top_level_denied.intersection(item):
            raise ValueError("OUTPUT_RUNTIME_AUTHORITY_DENIED")
        questions = item.get("falsification_questions", [])
        checks = item.get("validation_checks", [])
        if (
            isinstance(questions, list)
            and any(
                isinstance(question, dict) and "question_id" in question
                for question in questions
            )
        ) or (
            isinstance(checks, list)
            and any(
                isinstance(check, dict) and "validation_id" in check for check in checks
            )
        ):
            raise ValueError("OUTPUT_RUNTIME_AUTHORITY_DENIED")


def _require_static_content(
    proposal: HypothesisProposal, bundle: StaticFactBundle
) -> None:
    """Reject provider-created code facts, locations, relations, and evidence refs."""

    entities = {canonical_bytes(item) for item in bundle.entities}
    facts = bundle.facts()
    relations = (
        *bundle.call_edges,
        *bundle.data_flow_candidates,
        *bundle.route_bindings,
    )
    locations = {
        canonical_bytes(item)
        for item in (
            *bundle.locations,
            *(entity.location for entity in bundle.entities),
            *(fact.location for fact in facts),
            *(relation.from_location for relation in relations),
            *(relation.to_location for relation in relations),
        )
    }
    relation_values = {canonical_bytes(item) for item in relations}
    allowed_evidence_refs = {
        canonical_bytes(ref)
        for run in bundle.tool_runs
        for ref in (run.raw_result_ref, run.rule_execution_ref)
        if ref is not None
    }
    if any(canonical_bytes(item) not in entities for item in proposal.target_entities):
        raise ValueError("HYPOTHESIS_STATIC_CONTENT_DRIFT")
    if any(
        canonical_bytes(item) not in locations for item in proposal.target_locations
    ):
        raise ValueError("HYPOTHESIS_STATIC_CONTENT_DRIFT")
    for item in proposal.suspected_path:
        allowed = relation_values if isinstance(item, CodeRelation) else locations
        if canonical_bytes(item) not in allowed:
            raise ValueError("HYPOTHESIS_STATIC_CONTENT_DRIFT")
    if any(
        canonical_bytes(ref) not in allowed_evidence_refs
        for restriction in proposal.restrictions
        for ref in restriction.evidence_refs
    ):
        raise ValueError("HYPOTHESIS_STATIC_CONTENT_DRIFT")


__all__ = [
    "HypothesisAgent",
    "HypothesisAgentOutcome",
    "HypothesisLLMCall",
]
