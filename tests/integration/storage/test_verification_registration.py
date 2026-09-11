"""Registration mints work/application/questions together and deduplicates first."""

import json
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import func, insert, select, update

from sastsimi.bootstrap import build_fake_pipeline
from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.hypothesis import (
    HypothesisProcessState,
    HypothesisProposal,
    VulnerabilityHypothesis,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.verification import (
    PlaybookApplication,
    PlaybookPolicy,
    VerificationPlaybook,
)
from sastsimi.ports.verification_registration import VerificationRegistration
from sastsimi.storage import models
from sastsimi.storage.codec import reference
from tests.contract.domain.canonical_fixtures import make
from tests.integration.storage.test_intermediate_publication import (
    prepared_policy_parser,
)


@pytest.mark.parametrize(
    "invalid",
    [None, "owner", "requester", "book", "authorized", "before_commit", "committed"],
)
def test_registration_returns_same_work_application_and_questions_on_duplicate(
    tmp_path: Path, invalid: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    h, runtime, runner, policy_work, parser, _ = prepared_policy_parser(tmp_path)
    identity = next(
        ref
        for ref, role in h.evidence.identities.items()
        if role == RequesterRole.POLICY_PARSER
    )
    h.evidence.identities[identity] = RequesterRole.ORCHESTRATION
    scope = runtime.budget_registry.current_state("a1").budget_binding_ref
    assert scope is not None
    owner = h.records.get_exact(scope).work_budget_profile_ref
    h.evidence.identities[owner] = RequesterRole.VERIFICATION

    def data(name: str) -> dict[str, Any]:
        value: dict[str, Any] = json.loads(
            json.dumps(make(name)).replace('"ws1"', '"w1"')
        )
        value["meta"]["created_at"] = h.clock.now().isoformat()
        return value

    proposal = HypothesisProposal.model_validate_json(
        canonical_bytes(data("HypothesisProposal"))
    )
    h.publish(proposal)
    value = data("VulnerabilityHypothesis")
    for name in (
        "origin",
        "parent_hypothesis_ids",
        "source_primitive_match_id",
        "target_entities",
        "target_locations",
        "suspected_path",
        "falsification_questions",
        "validation_checks",
    ):
        value[name] = getattr(proposal, name)
    value.update(proposal_ref=reference(proposal))
    hypothesis = VulnerabilityHypothesis.model_validate_json(canonical_bytes(value))
    book_data = data("VerificationPlaybook")
    book_data["falsification_question_templates"] = [
        dict(template_key="path", question="Can the guard block this path?")
    ]
    book = VerificationPlaybook.model_validate_json(canonical_bytes(book_data))
    policy = PlaybookPolicy.model_validate_json(
        canonical_bytes(
            data("PlaybookPolicy") | dict(common_playbook_ref=reference(book))
        )
    )
    process = HypothesisProcessState.model_validate_json(
        canonical_bytes(
            data("HypothesisProcessState") | dict(proposal_ref=reference(proposal))
        )
    )
    for record in (hypothesis, book, policy, process):
        h.publish(record)
        with h.database.write() as connection:
            connection.execute(
                insert(models.current_records).values(
                    logical_record_id=str(record.meta.logical_record_id),
                    record_id=str(record.meta.record_id),
                    state_version=1,
                )
            )
    arguments = dict(
        hypothesis_ref=reference(hypothesis),
        proposal_ref=reference(proposal),
        policy_ref=reference(policy),
        playbook_ref=reference(book),
        owner_identity_ref=owner,
        requester_identity_ref=identity,
        budget_binding_ref=scope,
    )
    if invalid in {"owner", "requester"}:
        h.evidence.identities[owner if invalid == "owner" else identity] = (
            RequesterRole.PRO
        )
    if invalid == "book":
        alternate_data = book.model_dump(mode="json")
        alternate_data["meta"].update(
            record_id="alternate-book", logical_record_id="alternate-book"
        )
        alternate = VerificationPlaybook.model_validate_json(
            canonical_bytes(alternate_data)
        )
        h.publish(alternate)
        with h.database.write() as connection:
            connection.execute(
                insert(models.current_records).values(
                    logical_record_id=str(alternate.meta.logical_record_id),
                    record_id=str(alternate.meta.record_id),
                    state_version=1,
                )
            )
        arguments["playbook_ref"] = reference(alternate)
    if invalid in {"owner", "requester", "book"}:
        with pytest.raises(
            ValueError, match="AUTHORITY_DENIED|PLAYBOOK_SELECTION_MISMATCH"
        ):
            runtime.verification_registration.register(
                **arguments, expected_process_ref=reference(process)
            )
    elif invalid is not None:

        class Crash(BaseException):
            pass

        def crash(stage: str) -> None:
            if stage == invalid:
                raise Crash

        monkeypatch.setattr(
            runtime.verification_registration.store, "checkpoint", crash
        )
        with pytest.raises(Crash):
            runtime.verification_registration.register(
                **arguments, expected_process_ref=reference(process)
            )
    if invalid is not None:
        with h.database.engine.connect() as connection:
            for kind in ("playbook_application", "verification_assignment"):
                count = connection.execute(
                    select(func.count())
                    .select_from(models.records)
                    .join(
                        models.record_revisions,
                        models.record_revisions.c.record_id
                        == models.records.c.record_id,
                    )
                    .where(models.records.c.kind == kind)
                ).scalar_one()
                assert count == (1 if invalid == "committed" else 0)
        return
    result = runtime.verification_registration.register(
        **arguments, expected_process_ref=reference(process)
    )
    count = h.ids.index
    lost_response_retry = runtime.verification_registration.register(
        **arguments, expected_process_ref=reference(process)
    )
    assert lost_response_retry == result
    assert h.ids.index == count
    duplicate = runtime.verification_registration.register(
        **arguments, expected_process_ref=result.process_ref
    )
    assert duplicate == result
    assert h.ids.index == count
    assert len(result.application.questions) == 1
    assert result.work.input_refs == (
        reference(hypothesis),
        reference(proposal),
        reference(policy),
        reference(book),
        reference(result.application),
    )
    assert result.work.input_hash == content_hash(result.work.input_refs)
    assert h.records.get_exact(reference(result.application)) == result.application
    assert runtime.work.get(str(result.work.work_id)) == result.work
    h.evidence.identities[identity] = RequesterRole.POLICY_PARSER
    runner.complete(policy_work, identity, "POLICY_PARSER", (parser,))
    h.evidence.identities[identity] = RequesterRole.ORCHESTRATION
    running = runner.activate(result.work, scope, owner, role="VERIFICATION")
    (current_process,) = runtime.queries.current_records(
        "a1", "hypothesis_process_state"
    )
    assert current_process.verification_work_ref == reference(running)
    (dynamic,) = runtime.queries.current_records("a1", "dynamic_reproduction_state")
    assert dynamic.status == "NOT_REQUESTED" and dynamic.verification_generation == 1


def test_revise_registration_replays_after_ready_response_is_lost(
    tmp_path: Path,
) -> None:
    scenario = build_fake_pipeline(tmp_path)._scenario
    execution = scenario._verification("TRUE")
    verification = execution.result
    review = scenario._post_true(
        execution,
        technical_status="REVISE",
    )
    assert scenario.runtime is not None and scenario.runner is not None
    runtime = scenario.runtime
    state = runtime.budget_registry.current_state("fake-analysis")
    assert state.budget_binding_ref is not None
    budget_binding_ref = state.budget_binding_ref
    (hypothesis,) = runtime.queries.current_records(
        "fake-analysis", "vulnerability_hypothesis"
    )
    (process,) = runtime.queries.current_records(
        "fake-analysis", "hypothesis_process_state"
    )
    assert isinstance(hypothesis, VulnerabilityHypothesis)
    assert isinstance(process, HypothesisProcessState)
    application = runtime.unit_of_work.records.get_exact(
        verification.playbook_application_ref
    )
    assert isinstance(application, PlaybookApplication)
    owner_ref = next(
        ref
        for ref, role in scenario.evidence.identities.items()
        if role == RequesterRole.VERIFICATION
        and getattr(ref, "data_kind", None) == "work_budget_profile"
    )
    requester_ref = next(
        ref
        for ref in scenario.evidence.identities
        if getattr(ref, "data_kind", None) == "verification_budget_profile"
    )
    scenario.evidence.identities[requester_ref] = RequesterRole.ORCHESTRATION
    review_ref = reference(review)
    hypothesis_ref = reference(hypothesis)
    process_ref = reference(process)
    assert isinstance(review_ref, StoredDataRef)
    assert isinstance(hypothesis_ref, StoredDataRef)
    assert isinstance(process_ref, StoredDataRef)
    assert isinstance(owner_ref, StoredDataRef)
    assert isinstance(requester_ref, StoredDataRef)

    def revise() -> VerificationRegistration:
        return runtime.verification_registration.revise(
            technical_review_ref=review_ref,
            hypothesis_ref=hypothesis_ref,
            proposal_ref=hypothesis.proposal_ref,
            policy_ref=application.policy_ref,
            playbook_ref=application.playbook_ref,
            expected_process_ref=process_ref,
            owner_identity_ref=owner_ref,
            requester_identity_ref=requester_ref,
            budget_binding_ref=budget_binding_ref,
        )

    first = revise()
    ready = scenario.runner.enqueue_registered(
        first.work,
        budget_binding_ref,
        requester_ref,
        role="ORCHESTRATION",
    )
    registered_process = runtime.unit_of_work.records.get_exact(first.process_ref)
    assert isinstance(registered_process, HypothesisProcessState)
    with runtime.unit_of_work.records.database.write() as connection:
        connection.execute(
            update(models.current_records)
            .where(
                models.current_records.c.logical_record_id
                == str(registered_process.meta.logical_record_id)
            )
            .values(
                record_id=str(registered_process.meta.record_id),
                state_version=registered_process.meta.revision_number,
            )
        )
    id_index = scenario.ids.index
    replay = revise()

    assert replay.work == ready
    assert replay.application == first.application
    assert replay.assignment_ref == first.assignment_ref
    assert scenario.ids.index == id_index
