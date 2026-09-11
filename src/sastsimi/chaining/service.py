"""Primitive admission and exact-snapshot chaining workflow."""

from dataclasses import dataclass
from typing import Literal

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.chaining import (
    ChainingResult,
    Primitive,
    PrimitiveAdmissionDecision,
    PrimitiveIndexState,
)
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.verification import VerificationResult
from sastsimi.ports.fake_workflow import NoMatchBuilder, ProviderInvoker, ProviderProber
from sastsimi.runtime.fake_llm_configuration import register_fake_llm_call
from sastsimi.runtime.fake_llm_invocation import (
    invoke_fake_provider,
    persist_fake_invocation,
)
from sastsimi.runtime.fake_support import (
    ANALYSIS_ID,
    COMMIT_ID,
    WORKSPACE_ID,
    FakeClock,
    FakeEvidence,
    FakeRecordFactory,
)
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner


@dataclass(frozen=True)
class ChainingDependencies:
    runtime: RuntimeServices
    runner: WorkflowRunner
    clock: FakeClock
    evidence: FakeEvidence
    records: FakeRecordFactory
    provider_invoke: ProviderInvoker
    provider_probe: ProviderProber
    no_match_builder: NoMatchBuilder


@dataclass(frozen=True)
class ChainingOutcome:
    primitive_ref: StoredDataRef | None
    stopped: bool


class ChainingService:
    """Own admission, Primitive publication and pinned-index Chaining."""

    def __init__(self, dependencies: ChainingDependencies) -> None:
        self.runtime = dependencies.runtime
        self.runner = dependencies.runner
        self.clock = dependencies.clock
        self.evidence = dependencies.evidence
        self.provider_invoke = dependencies.provider_invoke
        self.provider_probe = dependencies.provider_probe
        self.no_match_builder = dependencies.no_match_builder
        self._record_meta = dependencies.records.record_meta
        self._artifact = dependencies.records.artifact
        self._stored_artifact = dependencies.records.stored_artifact

    def run(
        self,
        *,
        verification: VerificationResult,
        scope: StoredDataRef,
        orchestrator_ref: StoredDataRef,
        generation: int,
        verification_ref: StoredDataRef,
        technical_ref: StoredDataRef,
        collection_ref: StoredDataRef,
        review_ref: StoredDataRef,
        label_ref: StoredDataRef,
        observation: StoredDataRef,
        admission_decision: Literal["ALLOW", "DENY"],
        publish_denied_primitive: bool,
        stop_after_chaining: bool,
    ) -> ChainingOutcome:
        hypothesis_id = str(verification.meta.hypothesis_id)
        primitive_work = self.runner.start(
            scope,
            verification.meta,
            "PRIMITIVE_UPDATE",
            "HYPOTHESIS",
            hypothesis_id,
            orchestrator_ref,
            inputs=(verification_ref, technical_ref, collection_ref, review_ref),
            generation=generation,
        )
        primitive_identity = self.evidence.identity(
            RequesterRole.PRIMITIVE_ADMISSION_RUNTIME
        )
        admission = PrimitiveAdmissionDecision.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(
                        primitive_work.meta,
                        "primitive_admission_decision",
                        attempt_id=primitive_work.active_attempt_id,
                    ),
                    verification_result_ref=verification_ref,
                    technical_review_ref=technical_ref,
                    policy_collection_result_ref=collection_ref,
                    rule_scope_review_ref=review_ref,
                    testing_restriction_compliance=(
                        "PASS" if admission_decision == "ALLOW" else "FAIL"
                    ),
                    decision=admission_decision,
                    reason_code=(
                        "TESTING_RESTRICTION_PASSED"
                        if admission_decision == "ALLOW"
                        else "TESTING_RESTRICTION_VIOLATION"
                    ),
                    decided_at=self.clock.now(),
                )
            )
        )
        admission_ref = reference(admission)
        assert isinstance(admission_ref, StoredDataRef)
        primitive = Primitive.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(
                        primitive_work.meta,
                        "primitive",
                        attempt_id=primitive_work.active_attempt_id,
                    ),
                    primitive_id="fake-primitive",
                    workspace_id=WORKSPACE_ID,
                    commit_id=COMMIT_ID,
                    inputs=verification.required_primitive_candidates,
                    result=verification.provided_primitive_candidates[0],
                    restrictions=verification.restrictions,
                    source_hypothesis_id=verification.meta.hypothesis_id,
                    source_verification_ref=verification_ref,
                    technical_review_ref=technical_ref,
                    admission_decision_ref=admission_ref,
                    evidence_refs=(observation,),
                    description="Deterministic validated primitive",
                )
            )
        )
        primitive_ref = reference(primitive)
        assert isinstance(primitive_ref, StoredDataRef)
        outputs = (
            (admission, primitive)
            if admission_decision == "ALLOW" or publish_denied_primitive
            else (admission,)
        )
        self.runner.complete(
            primitive_work,
            primitive_identity,
            "PRIMITIVE_ADMISSION_RUNTIME",
            outputs,
        )
        if admission_decision == "DENY":
            return ChainingOutcome(None, True)

        indexes = tuple(
            item
            for item in self.runtime.queries.current_records(
                str(ANALYSIS_ID), "primitive_index_state"
            )
            if isinstance(item, PrimitiveIndexState)
            and item.meta.hypothesis_id == verification.meta.hypothesis_id
        )
        if len(indexes) != 1:
            raise LookupError("EXACT_PRIMITIVE_INDEX_NOT_FOUND")
        primitive_index = indexes[0]
        primitive_index_ref = reference(primitive_index)
        assert isinstance(primitive_index_ref, StoredDataRef)
        chaining_work = self.runner.start(
            scope,
            verification.meta,
            "CHAINING",
            "ANALYSIS",
            str(ANALYSIS_ID),
            orchestrator_ref,
            inputs=(primitive_index_ref, *primitive_index.primitive_refs),
            trigger_primitive_ref=primitive_ref,
            generation=generation,
        )
        chaining_identity = self.evidence.identity(RequesterRole.CHAINING)
        candidate = self.no_match_builder(
            meta=self.runner.metadata(
                chaining_work.meta,
                "chaining_result",
                attempt_id=chaining_work.active_attempt_id,
            ),
            primitive_refs=primitive_index.primitive_refs,
        )
        call_ref, provider_ref = register_fake_llm_call(
            self.runtime,
            self.evidence,
            self._record_meta,
            self._artifact,
            self.clock.now(),
            self.provider_probe,
            runner=self.runner,
            work=chaining_work,
            scope=scope,
            orchestration_identity=orchestrator_ref,
            role="CHAINING",
            result_kind="chaining_result",
            context_refs=tuple(
                ref
                for ref in chaining_work.input_refs
                if isinstance(ref, StoredDataRef)
            ),
        )
        record, invocation = invoke_fake_provider(
            runtime=self.runtime,
            runner=self.runner,
            work=chaining_work,
            scope=scope,
            identity=chaining_identity,
            action_role=RequesterRole.CHAINING,
            action_type="CALL_LLM",
            call_spec_ref=call_ref,
            provider_profile_ref=provider_ref,
            artifact=self._stored_artifact,
            build_output=lambda _decision: candidate,
            provider_invoke=self.provider_invoke,
        )
        assert isinstance(record, ChainingResult)
        persist_fake_invocation(self.runtime, invocation)
        self.runner.complete(chaining_work, chaining_identity, "CHAINING", (record,))
        return ChainingOutcome(primitive_ref, stop_after_chaining)
