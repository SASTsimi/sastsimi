"""Deterministic policy preparation through exact fetch and parser boundaries."""

import asyncio
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.ids import LogicalRecordId, RecordId
from sastsimi.contracts.policy import (
    PolicyCacheRecord,
    PolicyCollectionResult,
    PolicyParserResult,
    PolicySourceCheck,
    ProgramPolicyRecord,
    RunPolicyState,
)
from sastsimi.contracts.records import PolicyCacheMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.dto import OfficialPolicyFetchRequest, OfficialPolicySource
from sastsimi.ports.fake_workflow import PolicyFetcher, ProviderInvoker, ProviderProber
from sastsimi.runtime.fake_llm_configuration import register_fake_llm_call
from sastsimi.runtime.fake_llm_invocation import (
    invoke_fake_provider,
    persist_fake_invocation,
)
from sastsimi.runtime.fake_support import (
    ANALYSIS_ID,
    PROGRAM_ID,
    FakeClock,
    FakeEvidence,
    FakeIds,
    FakeRecordFactory,
)
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner


@dataclass(frozen=True)
class PolicyDependencies:
    runtime: RuntimeServices
    runner: WorkflowRunner
    clock: FakeClock
    ids: FakeIds
    evidence: FakeEvidence
    records: FakeRecordFactory
    provider_invoke: ProviderInvoker
    provider_probe: ProviderProber
    policy_fetch: PolicyFetcher


class PolicyPreparationService:
    """Own policy work registration, official fetch, parse and frozen state."""

    def __init__(self, dependencies: PolicyDependencies) -> None:
        self.runtime = dependencies.runtime
        self.runner = dependencies.runner
        self.clock = dependencies.clock
        self.ids = dependencies.ids
        self.evidence = dependencies.evidence
        self.provider_invoke = dependencies.provider_invoke
        self.provider_probe = dependencies.provider_probe
        self.policy_fetch = dependencies.policy_fetch
        self._record_meta = dependencies.records.record_meta
        self._artifact = dependencies.records.artifact
        self._stored_artifact = dependencies.records.stored_artifact

    def _publish_parser_result(
        self,
        work: Any,
        record: PolicyParserResult,
    ) -> StoredDataRef:
        identity = self.evidence.identity(RequesterRole.POLICY_PARSER)
        candidate = self.runtime.unit_of_work.records.stage_record(record)
        action = self.runner.action(
            work,
            identity,
            "POLICY_PARSER",
            "SAVE_RESULT",
            result_kind="policy_parser_result",
            candidate_result_ref=candidate,
        )
        (published,) = self.runtime.intermediate.publish(
            str(work.work_id), self.runner.authorize(work, action), (record,)
        )
        assert isinstance(published, StoredDataRef)
        return published

    def start(self, scope: StoredDataRef, orchestrator_ref: StoredDataRef) -> Any:
        self.evidence.bind_identity(orchestrator_ref, RequesterRole.ORCHESTRATION)
        return self.runner.start(
            scope,
            self._record_meta("fake_policy_stage"),
            "POLICY_FETCH",
            "ANALYSIS",
            str(ANALYSIS_ID),
            orchestrator_ref,
        )

    def prepare(
        self,
        scope: StoredDataRef,
        orchestrator_ref: StoredDataRef,
        work: Any | None = None,
    ) -> RunPolicyState:
        if work is None:
            work = self.start(scope, orchestrator_ref)
        official = self._artifact("official_policy")
        source_config_ref = self._stored_artifact("policy_source_config")
        freshness = self._artifact("freshness_evidence")
        policy_identity = self.evidence.identity(RequesterRole.POLICY_COLLECTOR)
        fetch_action = self.runner.action(
            work,
            policy_identity,
            "POLICY_COLLECTOR",
            "FETCH_POLICY",
            input_refs=(official, source_config_ref),
        )
        fetch_units = self.runner.units(elapsed_ms=1, cost_minor_units=1)
        fetch_reservation = self.runner.reserve(work, scope, fetch_action, fetch_units)
        fetch_decision = self.runner.authorize(work, fetch_action, fetch_reservation)
        if not isinstance(official, StoredDataRef):
            raise ValueError("FAKE_POLICY_ARTIFACT_SCOPE_MISMATCH")
        with self.runtime.unit_of_work.artifacts.open_verified(official) as source:
            source_content = source.read()
        expected_source = OfficialPolicySource(
            PolicySourceCheck.model_validate(
                dict(
                    source_id="fake-official",
                    source_ref=official,
                    source_url="https://example.invalid/policy",
                    publisher="fixture",
                    status="VERIFIED",
                    evidence_refs=(freshness,),
                    checked_at=self.clock.now(),
                )
            ),
            source_content,
        )
        fetch_request = OfficialPolicyFetchRequest(
            fetch_action, PROGRAM_ID, source_config_ref
        )
        fetched_source = asyncio.run(
            self.runtime.external.invoke(
                str(work.work_id),
                fetch_decision,
                reference(fetch_reservation),
                lambda: self.policy_fetch(fetch_request, expected_source),
                idempotency_key=str(fetch_action.action_id),
            )
        )
        self.runner.account(fetch_reservation, fetch_units)
        if fetched_source != expected_source:
            raise ValueError("FAKE_POLICY_SOURCE_MISMATCH")
        criterion = self._artifact("freshness_criterion", record=True)
        parser_candidate = PolicyParserResult.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(
                        work.meta,
                        "policy_parser_result",
                        attempt_id=work.active_attempt_id,
                    ),
                    parser_result_id="fake-parser-result",
                    parser_name="fake-policy-parser",
                    parser_version="1",
                    source_ref=official,
                    llm_invocation_ref=official,
                    parsed_output_ref=self._artifact("parsed_policy"),
                    status="SUCCEEDED",
                    error_ids=(),
                    completed_at=self.clock.now(),
                )
            )
        )
        call_ref, provider_ref = register_fake_llm_call(
            self.runtime,
            self.evidence,
            self._record_meta,
            self._artifact,
            self.clock.now(),
            self.provider_probe,
            runner=self.runner,
            work=work,
            scope=scope,
            orchestration_identity=orchestrator_ref,
            role="POLICY_PARSER",
            result_kind="policy_parser_result",
            context_refs=(official,),
        )
        parser_identity = self.evidence.identity(RequesterRole.POLICY_PARSER)
        parser_record, parser_invocation = invoke_fake_provider(
            runtime=self.runtime,
            runner=self.runner,
            work=work,
            scope=scope,
            identity=parser_identity,
            action_role=RequesterRole.POLICY_PARSER,
            action_type="CALL_LLM",
            call_spec_ref=call_ref,
            provider_profile_ref=provider_ref,
            artifact=self._stored_artifact,
            build_output=lambda _decision: parser_candidate,
            provider_invoke=self.provider_invoke,
            bind_request=lambda record, request_ref: PolicyParserResult.model_validate(
                record
            ).model_copy(update={"llm_invocation_ref": request_ref}),
        )
        assert isinstance(parser_record, PolicyParserResult)
        persist_fake_invocation(self.runtime, parser_invocation)
        parser_ref = self._publish_parser_result(work, parser_record)
        checked = self.clock.now()
        policy = ProgramPolicyRecord.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(
                        work.meta,
                        "program_policy_record",
                        attempt_id=work.active_attempt_id,
                    ),
                    policy_record_id="fake-policy",
                    program_id=PROGRAM_ID,
                    preparation_source="COLLECTED",
                    source_cache_ref=None,
                    program_namespace="fake",
                    external_program_id="fake-program",
                    policy_version="1",
                    fetched_at=checked,
                    freshness_status="CURRENT",
                    freshness_checked_at=checked,
                    in_scope_assets=(),
                    out_of_scope_assets=(),
                    accepted_vulnerability_classes=(),
                    excluded_vulnerability_classes=(),
                    testing_restrictions=(),
                    reward_conditions=(),
                    impact_criteria=(),
                    disclosure_requirements=(),
                    parser_version="1",
                    source_refs=(official,),
                    source_checks=(fetched_source.source_check,),
                    parser_result_refs=(parser_ref,),
                    freshness_criterion_ref=criterion,
                    freshness_evidence_refs=(freshness,),
                    freshness_valid_until=checked + timedelta(days=1),
                    missing_information=(),
                    freshness_warning=None,
                )
            )
        )
        policy_ref = reference(policy)
        assert isinstance(policy_ref, StoredDataRef)
        collection = PolicyCollectionResult.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(
                        work.meta,
                        "policy_collection_result",
                        attempt_id=work.active_attempt_id,
                    ),
                    collection_result_id="fake-collection",
                    program_id=PROGRAM_ID,
                    preparation_source="COLLECTED",
                    source_cache_ref=None,
                    status="FOUND",
                    official_source_refs=(official,),
                    parser_result_refs=(parser_ref,),
                    policy_record_ref=policy_ref,
                    gap_ids=(),
                    error_ids=(),
                    completed_at=checked,
                )
            )
        )
        collection_ref = reference(collection)
        assert isinstance(collection_ref, StoredDataRef)
        cache_meta = PolicyCacheMeta(
            record_id=self.ids.new(RecordId),
            logical_record_id=LogicalRecordId("fake-policy-cache"),
            record_type="policy_cache_record",
            schema_version="1.0.0",
            revision_number=1,
            previous_record_id=None,
            created_at=checked,
            program_id=PROGRAM_ID,
        )
        cache = PolicyCacheRecord.model_validate_json(
            canonical_bytes(
                dict(
                    meta=cache_meta,
                    source_config_ref=scope,
                    parser_name="fake-policy-parser",
                    parser_version="1",
                    collection_status="FOUND",
                    collection_result_ref=collection_ref,
                    parser_result_refs=(parser_ref,),
                    policy_record_ref=policy_ref,
                    freshness_criterion_ref=criterion,
                    freshness_checked_at=checked,
                    freshness_evidence_refs=(freshness,),
                    freshness_valid_until=checked + timedelta(days=1),
                    published_at=checked,
                )
            )
        )
        cache_ref = reference(cache)
        state = RunPolicyState.model_validate_json(
            canonical_bytes(
                dict(
                    meta=self.runner.metadata(work.meta, "run_policy_state"),
                    program_id=PROGRAM_ID,
                    status="CURRENT",
                    preparation_source="COLLECTED",
                    source_config_ref=scope,
                    parser_name="fake-policy-parser",
                    parser_version="1",
                    policy_work_ref=reference(work),
                    policy_cache_ref=cache_ref,
                    collection_result_ref=collection_ref,
                    policy_record_ref=policy_ref,
                    freshness_criterion_ref=criterion,
                    freshness_checked_at=checked,
                    freshness_evidence_refs=(freshness,),
                    freshness_valid_until=checked + timedelta(days=1),
                )
            )
        )
        outputs = (collection, policy, cache, state, parser_record)
        self.runner.complete(work, policy_identity, "POLICY_COLLECTOR", outputs)
        return state
