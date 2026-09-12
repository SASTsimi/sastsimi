from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from uuid import uuid4

from sqlalchemy import insert, select

from sastsimi.bootstrap import (
    build_and_install_t13_application,
    build_fake_pipeline,
    build_runtime,
    build_t13_services,
    install_t13_services,
)
from sastsimi.chaining.service import ChainingCallRefs, chaining_input_hash
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.chaining import ChainingResult, Primitive, PrimitiveIndexState
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    HypothesisProposal,
    VulnerabilityHypothesis,
)
from sastsimi.contracts.ids import AnalysisId, AttemptId, RecordId, StoredDataId
from sastsimi.contracts.llm import LLMCallSpec, PromptPayload
from sastsimi.contracts.llm_closure import llm_action_input_refs
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.contracts.work import (
    TransitionCommit,
    WorkAttempt,
    WorkExecutionState,
    WorkType,
)
from sastsimi.orchestration.fake_setup import FakeSetupDependencies, FakeSetupStages
from sastsimi.ports.chaining import ChainingAgentInput, PinnedChainingUniverse
from sastsimi.ports.dto import CapabilityProbeResult, WorkContext
from sastsimi.providers.fake import FakeProviderAdapter
from sastsimi.runtime.fake_llm_configuration import register_fake_llm_call
from sastsimi.runtime.fake_support import ANALYSIS_ID, COMMIT_ID, WORKSPACE_ID
from sastsimi.runtime.work_handler_registry import WorkHandlerRegistry
from sastsimi.storage import models
from sastsimi.storage.artifact_store import LocalArtifactStore
from sastsimi.storage.chaining_registration import ChainingPoolHistoryStore
from sastsimi.storage.repositories import SQLiteRecordStore
from tests.contract.domain.canonical_fixtures import make
from tests.integration.chaining.test_true_hold_true_true import (
    _primitive,
    _primitive_with_exact_sources,
    _technical,
    _verification,
)
from tests.integration.providers.test_sqlite_output_artifact import (
    _ValidatedArtifactAdapter,
)


async def _probe(candidate: Any) -> CapabilityProbeResult:
    return await FakeProviderAdapter({}).probe(candidate)


def _current_attempt(runtime: Any, work: WorkExecutionState) -> WorkAttempt:
    assert work.active_attempt_id is not None
    records = cast(SQLiteRecordStore, runtime.unit_of_work.records)
    with records.database.engine.connect() as connection:
        payload = connection.execute(
            select(models.work_attempts.c.payload).where(
                models.work_attempts.c.attempt_id == str(work.active_attempt_id)
            )
        ).scalar_one()
    return WorkAttempt.model_validate_json(payload)


def _scope_json(value: object) -> bytes:
    data = json.dumps(cast(Any, value).model_dump(mode="json"))
    return (
        data.replace('"a1"', f'"{ANALYSIS_ID}"')
        .replace('"ws1"', f'"{WORKSPACE_ID}"')
        .replace('"c1"', f'"{COMMIT_ID}"')
        .encode()
    )


def _publish(runtime: Any, record: Any, *, current: bool = False) -> StoredDataRef:
    records = cast(SQLiteRecordStore, runtime.unit_of_work.records)
    ref = records.stage_record(record)
    assert isinstance(ref, StoredDataRef)
    with records.database.write() as connection:
        records.publish(connection, ref)
        if current:
            connection.execute(
                insert(models.current_records).values(
                    logical_record_id=str(record.meta.logical_record_id),
                    record_id=str(record.meta.record_id),
                    state_version=1,
                )
            )
    return ref


def _config_records(setup: FakeSetupStages) -> tuple[StoredDataRef, StoredDataRef]:
    assert setup.runtime is not None
    book_data = json.loads(
        json.dumps(make("VerificationPlaybook"))
        .replace('"a1"', f'"{ANALYSIS_ID}"')
        .replace('"ws1"', f'"{WORKSPACE_ID}"')
        .replace('"c1"', f'"{COMMIT_ID}"')
    )
    book_data["meta"]["created_at"] = setup.clock.now().isoformat()
    book_data["falsification_question_templates"] = [
        {"template_key": "path", "question": "Can the chain be blocked?"}
    ]
    book = VerificationPlaybook.model_validate_json(canonical_bytes(book_data))
    book_ref = _publish(setup.runtime, book, current=True)
    policy_data = json.loads(
        json.dumps(make("PlaybookPolicy"))
        .replace('"a1"', f'"{ANALYSIS_ID}"')
        .replace('"ws1"', f'"{WORKSPACE_ID}"')
        .replace('"c1"', f'"{COMMIT_ID}"')
    )
    policy_data["meta"]["created_at"] = setup.clock.now().isoformat()
    policy_data["common_playbook_ref"] = book_ref.model_dump(mode="json")
    policy = PlaybookPolicy.model_validate_json(canonical_bytes(policy_data))
    policy_ref = _publish(setup.runtime, policy, current=True)
    setup.evidence.playbook_approvals.update((content_hash(book), content_hash(policy)))
    return policy_ref, book_ref


def _initial_hypothesis(
    setup: FakeSetupStages, hypothesis_id: str
) -> VulnerabilityHypothesis:
    assert setup.runtime is not None
    shape = dict(
        origin="INITIAL",
        target_entities=(),
        target_locations=(
            {
                "workspace_id": str(WORKSPACE_ID),
                "commit_id": str(COMMIT_ID),
                "file_path": f"src/{hypothesis_id}.py",
                "start_line": 1,
                "end_line": 2,
                "start_column": None,
                "end_column": None,
            },
        ),
        suspected_path=(),
        falsification_questions=(
            {"question_id": f"question-{hypothesis_id}", "question": "Can it fail?"},
        ),
        validation_checks=(
            {
                "validation_id": f"validation-{hypothesis_id}",
                "instruction": "Validate the path",
            },
        ),
        parent_hypothesis_ids=(),
        source_primitive_match_id=None,
    )
    proposal = HypothesisProposal.model_validate(
        dict(
            meta=setup.records.record_meta(
                "hypothesis_proposal", hypothesis_id=None, attempt_id=None
            ),
            proposal_id=f"proposal-{hypothesis_id}",
            proposal_state="HYPOTHESIS_ONLY",
            assertion_mode="NON_FINAL",
            statement=f"Initial hypothesis {hypothesis_id}",
            vulnerability_type_candidates=(),
            observed_facts=(),
            assumptions=(),
            restrictions=(),
            **shape,
        )
    )
    proposal_ref = _publish(setup.runtime, proposal)
    hypothesis = VulnerabilityHypothesis.model_validate(
        dict(
            meta=setup.records.record_meta(
                "vulnerability_hypothesis",
                hypothesis_id=hypothesis_id,
                attempt_id=None,
            ),
            proposal_ref=proposal_ref,
            statement=proposal.statement,
            **shape,
        )
    )
    _publish(setup.runtime, hypothesis, current=True)
    return hypothesis


def _seed_primitive(
    setup: FakeSetupStages,
    name: str,
    *,
    inputs: tuple[str, ...],
    result: str | None,
) -> StoredDataRef:
    assert setup.runtime is not None
    base_verification = _verification(
        name,
        rationale=f"Verified capability and constraints for primitive {name}",
        final_true=result is not None,
    )
    base_verification_ref = reference(base_verification)
    assert isinstance(base_verification_ref, StoredDataRef)
    base_technical = (
        _technical(name, base_verification_ref) if result is not None else None
    )
    verification = type(base_verification).model_validate_json(
        _scope_json(base_verification)
    )
    verification = verification.model_copy(
        update={
            "meta": verification.meta.model_copy(
                update={"attempt_id": AttemptId(f"verification-hyp-{name}-attempt")}
            )
        }
    )
    verification_ref = reference(verification)
    assert isinstance(verification_ref, StoredDataRef)
    technical = None
    if base_technical is not None:
        technical_data = json.loads(_scope_json(base_technical))
        technical_data["verification_result_ref"] = verification_ref.model_dump(
            mode="json"
        )
        technical = type(base_technical).model_validate_json(
            canonical_bytes(technical_data)
        )
    primitive = Primitive.model_validate_json(
        _scope_json(_primitive(name, inputs=inputs, result=result))
    )
    primitive = _primitive_with_exact_sources(
        primitive, verification=verification, technical=technical
    )
    _commit_verification(setup, verification)
    if technical is not None:
        _publish(setup.runtime, technical)
    return _publish(setup.runtime, primitive)


def _commit_verification(setup: FakeSetupStages, verification: Any) -> None:
    """Seed one exact committed terminal parent without running unrelated stages."""

    assert setup.runtime is not None
    records = cast(SQLiteRecordStore, setup.runtime.unit_of_work.records)
    verification_ref = _publish(setup.runtime, verification)
    hypothesis_id = str(verification.meta.hypothesis_id)
    work_id = f"verification-{hypothesis_id}-work"
    assert verification.meta.attempt_id is not None
    attempt_id = str(verification.meta.attempt_id)
    transition_ref = StoredDataRef(
        stored_data_id=StoredDataId(f"transition-{hypothesis_id}"),
        data_kind="state_transition",
        content_hash=content_hash(["transition", hypothesis_id]),
        workspace_id=WORKSPACE_ID,
        commit_id=COMMIT_ID,
        record_id=RecordId(f"transition-{hypothesis_id}"),
    )
    commit = TransitionCommit.model_validate_json(
        canonical_bytes(
            dict(
                meta=setup.records.record_meta(
                    "transition_commit",
                    hypothesis_id=hypothesis_id,
                    attempt_id=attempt_id,
                ),
                transition_commit_id=f"commit-{hypothesis_id}",
                work_id=work_id,
                transition_ref=transition_ref,
                expected_state_version=1,
                target_state_version=2,
                attempt_id=attempt_id,
                target_status="SUCCEEDED",
                output_refs=(verification_ref,),
                gap_ids=(),
                error_ids=(),
                state="COMMITTED",
                prepared_at=setup.clock.now(),
                committed_at=setup.clock.now(),
                abort_reason=None,
            )
        )
    )
    commit_ref = _publish(setup.runtime, commit)
    input_hash = content_hash(["verification", hypothesis_id])
    work = WorkExecutionState.model_validate_json(
        canonical_bytes(
            dict(
                meta=setup.records.record_meta(
                    "work_execution_state",
                    hypothesis_id=hypothesis_id,
                    attempt_id=None,
                ),
                work_id=work_id,
                parent_work_ref=None,
                work_type="VERIFICATION",
                subject_type="HYPOTHESIS",
                subject_id=hypothesis_id,
                work_generation=1,
                status="SUCCEEDED",
                state_version=2,
                last_transition_ref=transition_ref,
                last_transition_commit_ref=commit_ref,
                active_attempt_id=None,
                input_hash=input_hash,
                dedupe_key=content_hash(["verification-work", hypothesis_id]),
                trigger_primitive_ref=None,
                input_refs=(),
                output_refs=(verification_ref,),
                gap_ids=(),
                error_ids=(),
                waiting_for=(),
                stop_reason="COMPLETED",
                started_at=setup.clock.now(),
                finished_at=setup.clock.now(),
                elapsed_ms=0,
            )
        )
    )
    attempt = WorkAttempt.model_validate_json(
        canonical_bytes(
            dict(
                meta=setup.records.record_meta(
                    "work_attempt",
                    hypothesis_id=hypothesis_id,
                    attempt_id=attempt_id,
                ),
                work_id=work_id,
                attempt_id=attempt_id,
                attempt_number=1,
                trigger="INITIAL",
                input_hash=input_hash,
                status="SUCCEEDED",
                output_refs=(verification_ref,),
                gap_ids=(),
                error_ids=(),
                started_at=setup.clock.now(),
                finished_at=setup.clock.now(),
                elapsed_ms=0,
            )
        )
    )
    process = HypothesisProcessState.model_validate_json(
        canonical_bytes(
            dict(
                meta=setup.records.record_meta(
                    "hypothesis_process_state",
                    hypothesis_id=hypothesis_id,
                    attempt_id=None,
                ),
                proposal_ref=next(
                    item.proposal_ref
                    for item in setup.runtime.queries.current_records(
                        str(ANALYSIS_ID), "vulnerability_hypothesis"
                    )
                    if isinstance(item, VulnerabilityHypothesis)
                    and str(item.meta.hypothesis_id) == hypothesis_id
                ),
                status="TERMINAL",
                verification_assignment_ref=StoredDataRef(
                    stored_data_id=StoredDataId(f"assignment-{hypothesis_id}"),
                    data_kind="verification_assignment",
                    content_hash=content_hash(["assignment", hypothesis_id]),
                    workspace_id=WORKSPACE_ID,
                    commit_id=COMMIT_ID,
                    record_id=RecordId(f"assignment-{hypothesis_id}"),
                ),
                verification_generation=1,
                verification_work_ref=None,
                verification_result_ref=verification_ref,
                started_at=setup.clock.now(),
                finished_at=setup.clock.now(),
                elapsed_ms=0,
            )
        )
    )
    with records.database.write() as connection:
        connection.execute(
            insert(models.work_states).values(
                work_id=work_id,
                analysis_id=str(ANALYSIS_ID),
                registration_key=f"verification-{hypothesis_id}",
                status="SUCCEEDED",
                state_version=2,
                active_attempt_id=None,
                payload=work.model_dump_json(),
            )
        )
        connection.execute(
            insert(models.work_attempts).values(
                attempt_id=attempt_id,
                work_id=work_id,
                attempt_number=1,
                status="SUCCEEDED",
                payload=attempt.model_dump_json(),
            )
        )
        connection.execute(
            insert(models.transition_commits).values(
                transition_commit_id=str(commit.transition_commit_id),
                work_id=work_id,
                expected_state_version=1,
                candidate_binding=f"verification-{hypothesis_id}",
                state="COMMITTED",
                payload=commit.model_dump_json(),
                request="{}",
            )
        )
    _publish(setup.runtime, process, current=True)


def _seed_pools(
    setup: FakeSetupStages,
    *,
    scope: StoredDataRef,
    primitive_refs: tuple[StoredDataRef, StoredDataRef],
) -> WorkExecutionState:
    assert setup.runtime is not None and setup.runner is not None
    indexes: list[StoredDataRef] = []
    for primitive_ref in primitive_refs:
        primitive = setup.runtime.unit_of_work.records.get_exact(primitive_ref)
        assert isinstance(primitive, Primitive)
        index_data = make("PrimitiveIndexState")
        index_data["meta"] = setup.records.record_meta(
            "primitive_index_state",
            hypothesis_id=str(primitive.source_hypothesis_id),
            attempt_id=None,
        ).model_dump(mode="json")
        index_data["current_verification_ref"] = (
            primitive.source_verification_ref.model_dump(mode="json")
        )
        index_data["primitive_refs"] = [primitive_ref.model_dump(mode="json")]
        index = PrimitiveIndexState.model_validate_json(canonical_bytes(index_data))
        indexes.append(_publish(setup.runtime, index, current=True))
    index_refs = tuple(indexes)
    identity = setup.evidence.stored_identity(RequesterRole.ORCHESTRATION)
    universe_refs = (*index_refs, *primitive_refs)
    analysis_meta = setup.records.record_meta(
        "chaining_work", hypothesis_id=None, attempt_id=None
    )
    works = tuple(
        setup.runner.start(
            scope,
            analysis_meta,
            "CHAINING",
            "ANALYSIS",
            str(ANALYSIS_ID),
            identity,
            inputs=universe_refs,
            trigger_primitive_ref=trigger,
        )
        for trigger in primitive_refs
    )
    records = cast(SQLiteRecordStore, setup.runtime.unit_of_work.records)
    with records.database.write() as connection:
        connection.execute(
            insert(models.chaining_cohorts).values(
                cohort_id="real-route-cohort",
                source_update_ref=canonical_bytes(index_refs[0]).decode(),
                analysis_id=str(ANALYSIS_ID),
                workspace_id=str(WORKSPACE_ID),
                commit_id=str(COMMIT_ID),
                member_count=2,
                status="READY",
            )
        )
        work_triggers = zip(works, primitive_refs, strict=True)
        for order, (work, trigger) in enumerate(work_triggers):
            work_ref = reference(work)
            assert isinstance(work_ref, StoredDataRef)
            universe = PinnedChainingUniverse(
                trigger_primitive_ref=trigger,
                index_refs=index_refs,
                considered_primitive_refs=primitive_refs,
            )
            connection.execute(
                insert(models.chaining_work_pools).values(
                    work_id=str(work.work_id),
                    cohort_id="real-route-cohort",
                    member_order=order,
                    analysis_id=str(ANALYSIS_ID),
                    workspace_id=str(WORKSPACE_ID),
                    commit_id=str(COMMIT_ID),
                    trigger_work_ref=canonical_bytes(work_ref).decode(),
                    work_generation=work.work_generation,
                    input_hash=work.input_hash,
                    trigger_primitive_ref=canonical_bytes(trigger).decode(),
                    index_refs=canonical_bytes(index_refs).decode(),
                    considered_primitive_refs=canonical_bytes(primitive_refs).decode(),
                    pool_hash=ChainingPoolHistoryStore._pool_hash(universe),
                )
            )
    return max(
        works,
        key=lambda work: str(cast(StoredDataRef, work.trigger_primitive_ref).record_id),
    )


def _match_output(content: ChainingAgentInput) -> bytes:
    assert content.comparisons and content.evidence
    return canonical_bytes(
        {
            "decisions": [
                {
                    "comparison_key": comparison.comparison_key,
                    "outcome": "MATCH" if index == 0 else "NO_MATCH",
                    "reason_code": None if index == 0 else "ENTITY_UNRELATED",
                    "detail": (
                        "The capabilities connect." if index == 0 else "Unrelated."
                    ),
                    "evidence_keys": [content.evidence[0].evidence_key]
                    if index == 0
                    else [],
                    "child": {
                        "statement": "Combined primitives may expose a larger impact.",
                        "vulnerability_type_candidates": ["CWE-20"],
                        "falsification_questions": [
                            "Can the required value reach the input?"
                        ],
                        "validation_checks": ["Verify the combined path end to end."],
                    }
                    if index == 0
                    else None,
                }
                for index, comparison in enumerate(content.comparisons)
            ]
        }
    )


def test_production_route_commits_child_and_replays_after_restart() -> None:
    root = Path("build") / f"t13-real-route-{uuid4()}"
    root.mkdir(parents=True)
    scenario = build_fake_pipeline(root)._scenario
    setup = FakeSetupStages(
        FakeSetupDependencies(
            data_dir=root,
            runtime_builder=build_runtime,
            database_upgrader=scenario.database_upgrader,
            provider_invoke=scenario.provider_invoke,
            provider_probe=scenario.provider_probe,
            policy_fetch=scenario.policy_fetch,
            clock=scenario.clock,
            ids=scenario.ids,
            evidence=scenario.evidence,
            records=scenario.records,
        )
    )
    scope, _owner, _orchestration = setup._bootstrap()
    assert setup.runtime is not None and setup.runner is not None
    runtime, runner = setup.runtime, setup.runner
    policy_ref, playbook_ref = _config_records(setup)
    recovery_profile = setup._work_profile(profile_key="t13-recovery-identity")
    setup.evidence.budget_approvals.add(content_hash(recovery_profile))
    recovery_identity = runtime.configuration.register_work_budget(recovery_profile)
    setup.evidence.bind_identity(recovery_identity, RequesterRole.RECOVERY)
    identities = {
        role: setup.evidence.stored_identity(role)
        for role in (
            RequesterRole.ORCHESTRATION,
            RequesterRole.CHAINING,
            RequesterRole.PRIMITIVE_ADMISSION_RUNTIME,
            RequesterRole.RECOVERY,
            RequesterRole.VERIFICATION,
        )
    }
    registry = WorkHandlerRegistry()
    resolver_state: dict[str, object] = {"calls": 0}

    def resolve_call(
        context: WorkContext, content: ChainingAgentInput
    ) -> tuple[ChainingCallRefs, str]:
        del context
        resolver_state["calls"] = cast(int, resolver_state["calls"]) + 1
        cast(
            _ValidatedArtifactAdapter, resolver_state["adapter"]
        )._raw_output = _match_output(content)
        return (
            cast(
                ChainingCallRefs,
                SimpleNamespace(
                    decision_ref=cast(StoredDataRef, resolver_state["decision_ref"]),
                    reservation_ref=cast(
                        StoredDataRef, resolver_state["reservation_ref"]
                    ),
                    call_spec_ref=cast(StoredDataRef, resolver_state["call_spec_ref"]),
                ),
            ),
            chaining_input_hash(content),
        )

    installation = build_and_install_t13_application(
        runtime=runtime,
        runner=runner,
        clock=setup.clock,
        ids=setup.ids,
        budget_scope_ref=scope,
        role_identity_refs=identities,
        chaining_call_resolver=resolve_call,
        verification_policy_ref=policy_ref,
        verification_playbook_ref=playbook_ref,
        registry=registry,
        active_analysis_ids=(AnalysisId(str(ANALYSIS_ID)),),
    )
    assert installation.registered_work_types == (
        WorkType.PRIMITIVE_UPDATE,
        WorkType.CHAINING,
        WorkType.HYPOTHESIS_PROPOSAL,
    )

    _initial_hypothesis(setup, "hyp-A")
    _initial_hypothesis(setup, "hyp-B")
    primitives = (
        _seed_primitive(setup, "A", inputs=(), result="capability"),
        _seed_primitive(setup, "B", inputs=("capability",), result=None),
    )
    running = _seed_pools(setup, scope=scope, primitive_refs=primitives)
    context = WorkContext(running, _current_attempt(runtime, running))
    call_spec_ref, provider_ref = register_fake_llm_call(
        runtime,
        setup.evidence,
        setup.records.record_meta,
        setup.records.artifact,
        setup.clock.now(),
        _probe,
        runner=runner,
        work=running,
        scope=scope,
        orchestration_identity=identities[RequesterRole.ORCHESTRATION],
        role="CHAINING",
        result_kind="chaining_result",
        task_kind="MATCH_PRIMITIVES",
        context_refs=cast(tuple[StoredDataRef, ...], running.input_refs),
    )
    spec = runtime.unit_of_work.records.get_exact(call_spec_ref)
    assert isinstance(spec, LLMCallSpec)
    payload = runtime.unit_of_work.records.get_exact(spec.prompt_payload_ref)
    assert isinstance(payload, PromptPayload)

    def invocation_meta(
        source: RecordMeta, record_type: str, attempt_id: AttemptId | None
    ) -> RecordMeta:
        return RecordMeta.model_validate(
            runner.metadata(source, record_type, attempt_id=attempt_id)
        )

    adapter = _ValidatedArtifactAdapter(
        records=cast(SQLiteRecordStore, runtime.unit_of_work.records),
        artifacts=cast(LocalArtifactStore, runtime.unit_of_work.artifacts),
        output_schema_ref=spec.output_schema_ref,
        semantic_validator_ref=spec.semantic_validator_ref,
        raw_output=b"{}",
        metadata_factory=invocation_meta,
        clock=setup.clock,
    )
    cast(Any, cast(Any, runtime.llm_calls)._adapters)._adapters[
        (provider_ref, spec.model)
    ] = adapter
    action = runner.action(
        running,
        identities[RequesterRole.CHAINING],
        RequesterRole.CHAINING.value,
        "CALL_LLM",
        llm_call_spec_ref=call_spec_ref,
        provider_profile_ref=provider_ref,
        session_mode="NEW",
        input_refs=llm_action_input_refs(call_spec_ref, spec, payload),
    )
    reservation = runner.reserve(
        running,
        scope,
        action,
        runner.units(elapsed_ms=1, llm_call_count=1, cost_minor_units=1),
    )
    resolver_state.update(
        adapter=adapter,
        decision_ref=runner.authorize(running, action, reservation),
        reservation_ref=runtime.unit_of_work.records.stage_record(reservation),
        call_spec_ref=call_spec_ref,
    )

    outcome = asyncio.run(registry.require(WorkType.CHAINING).execute(context))
    assert resolver_state["calls"] == 1
    result_ref = outcome.output_refs[0]
    result = runtime.unit_of_work.records.get_exact(result_ref)
    assert isinstance(result, ChainingResult)
    assert result.primitive_match_candidates and result.chained_hypothesis_proposals
    child = next(
        item
        for item in runtime.queries.current_records(
            str(ANALYSIS_ID), "work_execution_state"
        )
        if isinstance(item, WorkExecutionState)
        and item.work_type == WorkType.HYPOTHESIS_PROPOSAL
        and item.status == "READY"
        and item.input_refs == (result_ref,)
    )
    child_running = runner.activate(
        child, scope, identities[RequesterRole.ORCHESTRATION]
    )
    asyncio.run(
        registry.require(WorkType.HYPOTHESIS_PROPOSAL).execute(
            WorkContext(child_running, _current_attempt(runtime, child_running))
        )
    )
    verification = next(
        item
        for item in runtime.queries.current_records(
            str(ANALYSIS_ID), "work_execution_state"
        )
        if isinstance(item, WorkExecutionState)
        and item.work_type == WorkType.VERIFICATION
        and item.status == "READY"
        and any(ref.data_kind == "hypothesis_proposal" for ref in item.input_refs)
    )

    def forbidden_resolver(
        context: WorkContext, content: ChainingAgentInput
    ) -> tuple[ChainingCallRefs, str]:
        del context, content
        raise AssertionError("restart reconciliation must not call the Chaining Agent")

    restarted_services = build_t13_services(
        runtime=runtime,
        runner=runner,
        clock=setup.clock,
        ids=setup.ids,
        budget_scope_ref=scope,
        role_identity_refs=identities,
        chaining_call_resolver=forbidden_resolver,
        chaining_lineage=cast(Any, runtime.chaining_lineage),
        verification_policy_ref=policy_ref,
        verification_playbook_ref=playbook_ref,
    )
    replay = install_t13_services(
        restarted_services,
        registry=WorkHandlerRegistry(),
        active_analysis_ids=(AnalysisId(str(ANALYSIS_ID)),),
    )
    assert result_ref in replay.reconciliations[0].chaining_result_refs
    assert runtime.work.get(str(verification.work_id)) == verification
