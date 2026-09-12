import json
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest
from sqlalchemy import func, insert, select

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.budget import BudgetProfileBinding
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.chaining import (
    ChainingResult,
    Primitive,
    PrimitiveMatchCandidate,
)
from sastsimi.contracts.hypothesis import HypothesisProposal
from sastsimi.contracts.ids import (
    AttemptId,
    ProposalId,
    TransitionCommitId,
    WorkId,
)
from sastsimi.contracts.records import RecordMetadata
from sastsimi.contracts.refs import BudgetScopeRef, StoredDataRef, reference
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.contracts.work import (
    TransitionCommit,
    WorkAttempt,
    WorkExecutionState,
)
from sastsimi.ports.chaining import PinnedChainingUniverse
from sastsimi.ports.dto import Record, WorkContext
from sastsimi.runtime.workflow_runner import WorkflowRunner
from sastsimi.storage import models
from sastsimi.storage.chaining_child_registration import (
    ChainingChildRegistrationConfig,
    SQLiteChainingChildRegistration,
)
from sastsimi.storage.codec import encode
from sastsimi.storage.transition_service import TransitionService
from sastsimi.storage.verification_registration import (
    VerificationRegistrationService,
)
from sastsimi.storage.work_service import WorkService
from tests.contract.domain.canonical_fixtures import make
from tests.integration.runtime_support import Harness
from tests.integration.storage.test_intermediate_publication import (
    prepared_policy_parser,
)


class _NoAncestors:
    def ancestors(
        self,
        *,
        primitive_ref: StoredDataRef,
        universe: PinnedChainingUniverse,
    ) -> tuple[StoredDataRef, ...]:
        del primitive_ref, universe
        return ()


def _run_dir(name: str) -> Path:
    value = Path("build") / f"t13-child-{name}-{uuid4()}"
    value.mkdir(parents=True)
    return value


def _ref(kind: str, name: str) -> StoredDataRef:
    return StoredDataRef.model_validate(
        dict(
            stored_data_id=f"stored-{kind}-{name}",
            data_kind=kind,
            content_hash=content_hash([kind, name]),
            workspace_id="w1",
            commit_id="c1",
            record_id=f"{kind}-{name}",
        )
    )


def _count(works: WorkService, table: Any) -> int:
    with works.records.database.engine.connect() as connection:
        return connection.execute(select(func.count()).select_from(table)).scalar_one()


def _current_attempt(works: WorkService, work: WorkExecutionState) -> WorkAttempt:
    assert work.active_attempt_id is not None
    with works.records.database.engine.connect() as connection:
        payload = connection.execute(
            select(models.work_attempts.c.payload).where(
                models.work_attempts.c.attempt_id == str(work.active_attempt_id)
            )
        ).scalar_one()
    return WorkAttempt.model_validate_json(payload)


def _publish_current(harness: Harness, record: Record) -> StoredDataRef:
    ref = reference(record)
    assert isinstance(ref, StoredDataRef)
    harness.publish(record)
    with harness.database.write() as connection:
        connection.execute(
            insert(models.current_records).values(
                logical_record_id=str(record.meta.logical_record_id),
                record_id=str(record.meta.record_id),
                state_version=1,
            )
        )
    return ref


def _scope_primitive(
    name: str, *, inputs: tuple[str, ...], result: str | None
) -> Primitive:
    verification_ref = _ref("verification_result", f"{name}-verification")
    technical_ref = (
        _ref("technical_evidence_review", name) if result is not None else None
    )
    evidence_ref = _ref("code", name)

    def draft(value: str) -> dict[str, Any]:
        return {
            "draft_id": f"draft-{value}",
            "entity_refs": [
                {
                    "symbol_id": f"symbol-{value}",
                    "symbol_kind": "CALLABLE",
                    "native_kind": "function",
                    "name": value,
                    "location": {
                        "workspace_id": "w1",
                        "commit_id": "c1",
                        "file_path": f"src/{value}.py",
                        "start_line": 1,
                        "end_line": 2,
                        "start_column": None,
                        "end_column": None,
                    },
                }
            ],
            "privilege_level": None,
            "evidence_refs": [evidence_ref],
            "description": f"capability {value}",
        }

    data: dict[str, Any] = make("Primitive")
    data.update(
        meta=data["meta"]
        | {
            "record_id": f"primitive-{name}",
            "logical_record_id": f"primitive-logical-{name}",
            "workspace_id": "w1",
            "commit_id": "c1",
            "hypothesis_id": f"hyp-{name}",
        },
        primitive_id=f"primitive-{name}",
        workspace_id="w1",
        commit_id="c1",
        inputs=[draft(value) for value in inputs],
        result=draft(result) if result is not None else None,
        source_hypothesis_id=f"hyp-{name}",
        source_verification_ref=verification_ref,
        technical_review_ref=technical_ref,
        admission_decision_ref=(
            _ref("primitive_admission_decision", name)
            if result is not None
            else None
        ),
        evidence_refs=[evidence_ref],
        description=f"primitive {name}",
    )
    return Primitive.model_validate_json(canonical_bytes(data))


def _config_records(
    harness: Harness,
) -> tuple[StoredDataRef, StoredDataRef]:
    def data(name: str) -> dict[str, Any]:
        value = json.loads(json.dumps(make(name)).replace('"ws1"', '"w1"'))
        value["meta"]["created_at"] = harness.clock.now().isoformat()
        return cast(dict[str, Any], value)

    book_data = data("VerificationPlaybook")
    book_data["falsification_question_templates"] = [
        {"template_key": "path", "question": "Can the chain be blocked?"}
    ]
    book = VerificationPlaybook.model_validate_json(canonical_bytes(book_data))
    book_ref = _publish_current(harness, book)
    policy = PlaybookPolicy.model_validate_json(
        canonical_bytes(data("PlaybookPolicy") | {"common_playbook_ref": book_ref})
    )
    policy_ref = _publish_current(harness, policy)
    harness.evidence.playbook_approvals.update(
        (content_hash(book), content_hash(policy))
    )
    return policy_ref, book_ref


def _commit_source(
    harness: Harness,
    runner: WorkflowRunner,
    metadata: RecordMetadata,
) -> ChainingResult:
    upstream = _scope_primitive("upstream", inputs=(), result="capability")
    downstream = _scope_primitive("downstream", inputs=("capability",), result=None)
    upstream_ref = reference(upstream)
    downstream_ref = reference(downstream)
    assert isinstance(upstream_ref, StoredDataRef)
    assert isinstance(downstream_ref, StoredDataRef)
    harness.publish(upstream)
    harness.publish(downstream)
    attempt_id = harness.ids.new(AttemptId)
    match = PrimitiveMatchCandidate(
        primitive_match_id="match-child",
        upstream_result_ref=upstream_ref,
        downstream_input_ref=downstream_ref,
        matched_input_id=downstream.inputs[0].draft_id,
        parent_hypothesis_ids=(
            upstream.source_hypothesis_id,
            downstream.source_hypothesis_id,
        ),
        parent_verification_refs=(
            upstream.source_verification_ref,
            downstream.source_verification_ref,
        ),
        workspace_id=upstream.workspace_id,
        commit_id=upstream.commit_id,
        evidence_refs=(upstream.evidence_refs[0],),
        candidate_state="UNVALIDATED",
    )
    proposal = HypothesisProposal.model_validate(
        dict(
            meta=runner.metadata(
                metadata, "hypothesis_proposal", attempt_id=attempt_id
            ),
            proposal_id="chained-child",
            proposal_state="HYPOTHESIS_ONLY",
            assertion_mode="NON_FINAL",
            statement="The chained capability may expose a new path",
            origin="CHAINING",
            vulnerability_type_candidates=(),
            observed_facts=(),
            assumptions=(),
            target_entities=(),
            target_locations=(),
            suspected_path=(),
            falsification_questions=(
                {"question_id": "q-child", "question": "Can the join fail?"},
            ),
            validation_checks=(
                {"validation_id": "v-child", "instruction": "Test the join"},
            ),
            restrictions=(),
            parent_hypothesis_ids=match.parent_hypothesis_ids,
            source_primitive_match_id=match.primitive_match_id,
        )
    )
    source_refs = tuple(
        dict.fromkeys(
            (
                upstream.source_verification_ref,
                upstream.technical_review_ref,
                downstream.source_verification_ref,
            )
        )
    )
    assert all(isinstance(ref, StoredDataRef) for ref in source_refs)
    result = ChainingResult.model_validate(
        dict(
            meta=runner.metadata(
                metadata, "chaining_result", attempt_id=attempt_id
            ),
            source_result_refs=source_refs,
            considered_primitive_refs=(upstream_ref, downstream_ref),
            input_primitive_refs=(upstream_ref, downstream_ref),
            primitive_match_candidates=(match,),
            chained_hypothesis_proposals=(proposal,),
            excluded_lineage_refs=(),
            no_match_reasons=(),
            errors=(),
        )
    )
    result_ref = reference(result)
    assert isinstance(result_ref, StoredDataRef)
    work_id = harness.ids.new(WorkId)
    transition_ref = _ref("state_transition", "source")
    commit = TransitionCommit.model_validate_json(
        canonical_bytes(
            dict(
            meta=runner.metadata(
                metadata, "transition_commit", attempt_id=attempt_id
            ),
            transition_commit_id=harness.ids.new(TransitionCommitId),
            work_id=work_id,
            transition_ref=transition_ref,
            expected_state_version=2,
            target_state_version=3,
            attempt_id=attempt_id,
            target_status="SUCCEEDED",
            output_refs=(result_ref,),
            gap_ids=(),
            error_ids=(),
            state="COMMITTED",
            prepared_at=harness.clock.now(),
            committed_at=harness.clock.now(),
            abort_reason=None,
            )
        )
    )
    commit_ref = reference(commit)
    assert isinstance(commit_ref, StoredDataRef)
    inputs = (_ref("primitive_index_state", "pinned"), upstream_ref, downstream_ref)
    work = WorkExecutionState.model_validate_json(
        canonical_bytes(
            dict(
            meta=runner.metadata(
                metadata, "work_execution_state", attempt_id=None
            ),
            work_id=work_id,
            parent_work_ref=None,
            work_type="CHAINING",
            subject_type="ANALYSIS",
            subject_id="a1",
            work_generation=1,
            status="SUCCEEDED",
            state_version=3,
            last_transition_ref=transition_ref,
            last_transition_commit_ref=commit_ref,
            active_attempt_id=None,
            input_hash=content_hash(inputs),
            dedupe_key=content_hash(["source-chaining", inputs]),
            trigger_primitive_ref=upstream_ref,
            input_refs=inputs,
            output_refs=(result_ref,),
            gap_ids=(),
            error_ids=(),
            waiting_for=(),
            stop_reason="COMPLETED",
            started_at=harness.clock.now(),
            finished_at=harness.clock.now(),
            elapsed_ms=0,
            )
        )
    )
    attempt = WorkAttempt.model_validate_json(
        canonical_bytes(
            dict(
            meta=runner.metadata(
                metadata, "work_attempt", attempt_id=attempt_id
            ),
            work_id=work_id,
            attempt_id=attempt_id,
            attempt_number=1,
            trigger="INITIAL",
            input_hash=work.input_hash,
            status="SUCCEEDED",
            output_refs=(result_ref,),
            gap_ids=(),
            error_ids=(),
            started_at=harness.clock.now(),
            finished_at=harness.clock.now(),
            elapsed_ms=0,
            )
        )
    )
    with harness.database.write() as connection:
        for record in (result, commit, work, attempt):
            ref = harness.records.stage(connection, record)
            harness.records.publish(connection, ref)
        connection.execute(
            insert(models.current_records).values(
                logical_record_id=str(result.meta.logical_record_id),
                record_id=str(result.meta.record_id),
                state_version=1,
            )
        )
        connection.execute(
            insert(models.work_states).values(
                work_id=str(work_id),
                analysis_id="a1",
                registration_key=content_hash(["source", work_id]),
                status="SUCCEEDED",
                state_version=3,
                active_attempt_id=None,
                payload=encode(work),
            )
        )
        connection.execute(
            insert(models.work_attempts).values(
                attempt_id=str(attempt_id),
                work_id=str(work_id),
                attempt_number=1,
                status="SUCCEEDED",
                payload=encode(attempt),
            )
        )
        connection.execute(
            insert(models.transition_commits).values(
                transition_commit_id=str(commit.transition_commit_id),
                work_id=str(work_id),
                expected_state_version=2,
                candidate_binding=content_hash([commit, result_ref]),
                state="COMMITTED",
                payload=encode(commit),
                request=canonical_bytes({"source": result_ref}).decode(),
            )
        )
    return result


def _prepared(
    name: str,
) -> tuple[
    Harness,
    WorkflowRunner,
    SQLiteChainingChildRegistration,
    WorkService,
    StoredDataRef,
    BudgetScopeRef,
    ChainingResult,
]:
    harness, runtime, runner, policy_work, parser, _decision = (
        prepared_policy_parser(_run_dir(name))
    )
    requester = next(
        ref
        for ref, role in harness.evidence.identities.items()
        if role == RequesterRole.POLICY_PARSER
    )
    runner.complete(policy_work, requester, "POLICY_PARSER", (parser,))
    harness.evidence.identities[requester] = RequesterRole.ORCHESTRATION
    scope = runtime.budget_registry.current_state("a1").budget_binding_ref
    assert isinstance(scope, StoredDataRef)
    binding = harness.records.get_exact(scope)
    assert isinstance(binding, BudgetProfileBinding)
    owner = binding.work_budget_profile_ref
    harness.evidence.identities[owner] = RequesterRole.VERIFICATION
    policy_ref, book_ref = _config_records(harness)
    source = _commit_source(harness, runner, parser.meta)
    works = runtime.work.store
    verification = runtime.verification_registration.store
    transitions = verification.transitions
    assert isinstance(works, WorkService)
    assert isinstance(verification, VerificationRegistrationService)
    assert isinstance(transitions, TransitionService)
    lineage = _NoAncestors()
    service = SQLiteChainingChildRegistration(
        works=works,
        transitions=transitions,
        verification=verification,
        lineage=lineage,
        config=ChainingChildRegistrationConfig(
            budget_binding_ref=scope,
            verification_owner_identity_ref=owner,
            verification_policy_ref=policy_ref,
            verification_playbook_ref=book_ref,
        ),
    )
    return harness, runner, service, works, scope, requester, source


def test_child_registration_normal_and_lost_response_replay_are_idempotent() -> None:
    harness, runner, service, works, scope, requester, source = _prepared("normal")
    source_ref = reference(source)
    assert isinstance(source_ref, StoredDataRef)
    nested = source.chained_hypothesis_proposals[0]
    initial_ledger = _count(works, models.budget_ledger_entries)
    initial_work = _count(works, models.work_states)

    ready = service.enqueue_ready(
        source_result_ref=source_ref,
        proposal_id=nested.proposal_id,
        requester_identity_ref=requester,
    )
    assert ready.status == "READY"
    assert ready.input_refs == (source_ref,)
    assert ready.subject_id == nested.proposal_id
    assert _count(works, models.budget_ledger_entries) == initial_ledger + 1
    assert _count(works, models.work_states) == initial_work + 1
    replay_index = harness.ids.index
    assert (
        service.enqueue_ready(
            source_result_ref=source_ref,
            proposal_id=nested.proposal_id,
            requester_identity_ref=requester,
        )
        == ready
    )
    assert harness.ids.index == replay_index
    assert _count(works, models.budget_ledger_entries) == initial_ledger + 1

    running = runner.activate(ready, scope, requester)
    context = WorkContext(running, _current_attempt(works, running))
    phase_two_ledger = _count(works, models.budget_ledger_entries)
    phase_two_work = _count(works, models.work_states)
    registered = service.register_claimed(
        context=context,
        source_result_ref=source_ref,
        proposal_id=nested.proposal_id,
        requester_identity_ref=requester,
    )
    assert registered.proposal.model_dump(exclude={"meta"}) == nested.model_dump(
        exclude={"meta"}
    )
    assert registered.proposal.meta.attempt_id == running.active_attempt_id
    assert registered.verification_work.status == "READY"
    assert registered.proposal_ref in registered.verification_work.input_refs
    assert _count(works, models.budget_ledger_entries) == phase_two_ledger + 1
    assert _count(works, models.work_states) == phase_two_work + 1
    replay_index = harness.ids.index
    replay_ledger = _count(works, models.budget_ledger_entries)

    assert (
        service.register_claimed(
            context=context,
            source_result_ref=source_ref,
            proposal_id=nested.proposal_id,
            requester_identity_ref=requester,
        )
        == registered
    )
    assert harness.ids.index == replay_index
    assert _count(works, models.budget_ledger_entries) == replay_ledger
    assert _count(works, models.work_states) == phase_two_work + 1


def test_child_handoff_rejects_tampered_cross_scope_and_unknown_source_child() -> None:
    _harness, _runner, service, works, _scope, requester, source = _prepared(
        "tamper"
    )
    source_ref = reference(source)
    assert isinstance(source_ref, StoredDataRef)
    before_ledger = _count(works, models.budget_ledger_entries)
    before_work = _count(works, models.work_states)
    invalid_refs = (
        source_ref.model_copy(update={"content_hash": "f" * 64}),
        source_ref.model_copy(update={"workspace_id": "foreign-workspace"}),
    )
    for invalid_ref in invalid_refs:
        with pytest.raises(ValueError, match="RECORD_REVISION_MISMATCH"):
            service.enqueue_ready(
                source_result_ref=invalid_ref,
                proposal_id=source.chained_hypothesis_proposals[0].proposal_id,
                requester_identity_ref=requester,
            )
    with pytest.raises(ValueError, match="CHAINING_CHILD_SOURCE_MISMATCH"):
        service.enqueue_ready(
            source_result_ref=source_ref,
            proposal_id=ProposalId("not-in-source"),
            requester_identity_ref=requester,
        )
    assert _count(works, models.budget_ledger_entries) == before_ledger
    assert _count(works, models.work_states) == before_work
