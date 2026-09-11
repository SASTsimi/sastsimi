"""Final Verification closes only its exact completed generation and evidence."""

from pathlib import Path

import pytest
from sqlalchemy import insert

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.verification import (
    ConEvidenceResult,
    PlaybookPolicy,
    ProEvidenceResult,
    VerificationInitialAssessment,
    VerificationPlaybook,
    VerificationResult,
)
from sastsimi.storage import models
from sastsimi.storage.codec import reference
from tests.contract.domain.canonical_fixtures import make
from tests.integration.storage.test_hypothesis_projection import prepared_hypothesis


@pytest.mark.parametrize(
    "invalid",
    [
        None,
        "questions",
        "assessment",
        "con_uncommitted",
        "pro_generation",
        "transaction_B",
    ],
)
def test_false_terminal_commit_projects_process_and_empty_primitive_index(
    tmp_path: Path, invalid: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    h, runtime, runner, orchestration, proposal, bundle = prepared_hypothesis(
        tmp_path, parallel=4
    )
    (initial_report_state,) = runtime.queries.current_records(
        "a1", "report_process_state"
    )
    (hypothesis,) = runtime.queries.current_records("a1", "vulnerability_hypothesis")
    (process,) = runtime.queries.current_records("a1", "hypothesis_process_state")
    scope = runtime.budget_registry.current_state("a1").budget_binding_ref
    assert scope is not None
    binding = h.records.get_exact(scope)
    owner = binding.work_budget_profile_ref
    h.evidence.identities[owner] = RequesterRole.VERIFICATION
    book = VerificationPlaybook.model_validate_json(
        canonical_bytes(
            make("VerificationPlaybook")
            | dict(
                meta=runner.metadata(bundle.meta, "verification_playbook"),
                falsification_question_templates=[
                    dict(
                        template_key="guard", question="Does the guard block the sink?"
                    )
                ],
            )
        )
    )
    policy = PlaybookPolicy.model_validate_json(
        canonical_bytes(
            make("PlaybookPolicy")
            | dict(
                meta=runner.metadata(bundle.meta, "playbook_policy"),
                common_playbook_ref=reference(book),
            )
        )
    )
    for record in (book, policy):
        h.publish(record)
        with h.database.write() as connection:
            connection.execute(
                insert(models.current_records).values(
                    logical_record_id=str(record.meta.logical_record_id),
                    record_id=str(record.meta.record_id),
                    state_version=1,
                )
            )
    registered = runtime.verification_registration.register(
        hypothesis_ref=reference(hypothesis),
        proposal_ref=reference(proposal),
        policy_ref=reference(policy),
        playbook_ref=reference(book),
        expected_process_ref=reference(process),
        owner_identity_ref=owner,
        requester_identity_ref=orchestration,
        budget_binding_ref=scope,
    )
    work = runner.activate(registered.work, scope, owner, role="VERIFICATION")
    evidence = []
    for role, model, identity in (
        ("PRO", ProEvidenceResult, binding.verification_budget_profile_ref),
        ("CON", ConEvidenceResult, binding.dynamic_lifecycle_profile_ref),
    ):
        h.evidence.identities[identity] = RequesterRole(role)
        child = runner.start(
            scope,
            work.meta,
            role + "_EVIDENCE",
            "HYPOTHESIS",
            str(hypothesis.meta.hypothesis_id),
            owner,
            role="VERIFICATION",
            inputs=(reference(bundle),),
            parent=reference(work),
        )
        value = model.model_validate_json(
            canonical_bytes(
                dict(
                    meta=runner.metadata(
                        work.meta,
                        role.lower() + "_evidence_result",
                        attempt_id=child.active_attempt_id,
                    ),
                    role=role,
                    parent_work_id=work.work_id,
                    evidence_work_id=child.work_id,
                    verification_generation=2
                    if invalid == "pro_generation" and role == "PRO"
                    else 1,
                    llm_call_id="fake-" + role,
                    debate_input_hash=content_hash((reference(bundle),)),
                    evidence=(),
                    summary="Reviewed exact guard path",
                    limitations=(),
                )
            )
        )
        if invalid == "con_uncommitted" and role == "CON":
            h.publish(value)
        else:
            runner.complete(child, identity, role, (value,))
        evidence.append(value)
    pro, con = evidence
    application = registered.application
    assessment = VerificationInitialAssessment.model_validate_json(
        canonical_bytes(
            dict(
                meta=runner.metadata(
                    work.meta,
                    "verification_initial_assessment",
                    attempt_id=work.active_attempt_id,
                ),
                verification_work_id=work.work_id,
                verification_generation=1,
                hypothesis_ref=reference(hypothesis),
                policy_ref=reference(policy),
                playbook_ref=reference(book),
                playbook_application_ref=reference(application),
                pro_evidence_ref=reference(pro),
                con_evidence_ref=reference(con),
                next_step="FINALIZE_WITHOUT_DYNAMIC",
                proposed_verdict="FALSE",
                rationale="The guard disproves the path",
                evidence_refs=(reference(bundle),),
                unresolved_conditions=(),
                llm_call_id="fake-initial",
            )
        )
    )
    action = runner.action(
        work,
        owner,
        "VERIFICATION",
        "SAVE_RESULT",
        result_kind="verification_initial_assessment",
        candidate_result_ref=h.records.stage_record(assessment),
    )
    if invalid != "assessment":
        runtime.intermediate.publish(
            str(work.work_id), runner.authorize(work, action), (assessment,)
        )
    final = VerificationResult.model_validate_json(
        canonical_bytes(
            make("VerificationResult")
            | dict(
                meta=runner.metadata(
                    work.meta, "verification_result", attempt_id=work.active_attempt_id
                ),
                playbook_ref=reference(book),
                playbook_application_ref=reference(application),
                verification_mode="ALWAYS_DEBATE",
                debate_input_hash=pro.debate_input_hash,
                pro_evidence_ref=reference(pro),
                con_evidence_ref=reference(con),
                initial_verdict="FALSE",
                verdict="FALSE",
                dynamic_request_ref=None,
                dynamic_result_ref=None,
                poc_ref=None,
                supporting_evidence=(),
                counter_evidence=(),
                falsification_results=tuple(
                    dict(
                        question_id=q.question_id,
                        outcome="DISPROVED",
                        evidence_refs=(reference(bundle),),
                        rationale="Guard blocks this path",
                    )
                    for q in (
                        *hypothesis.falsification_questions,
                        *application.questions,
                    )
                ),
                validation_results=tuple(
                    dict(
                        validation_id=v.validation_id,
                        completion="COMPLETE",
                        evidence_refs=(reference(bundle),),
                        summary="Guard checked",
                    )
                    for v in hypothesis.validation_checks
                ),
            )
        )
    )
    if invalid == "questions":
        data = final.model_dump(mode="json")
        data["falsification_results"] = data["falsification_results"][:1]
        final = VerificationResult.model_validate_json(canonical_bytes(data))
    if invalid == "transaction_B":

        class Crash(BaseException):
            pass

        def crash(stage: str) -> None:
            if stage == "transaction_B":
                raise Crash

        monkeypatch.setattr(runtime.intermediate.store.transitions, "checkpoint", crash)
        with pytest.raises(Crash):
            runner.complete(work, owner, "VERIFICATION", (final,))
    elif invalid is not None:
        with pytest.raises(ValueError):
            runner.complete(work, owner, "VERIFICATION", (final,))
    if invalid is not None:
        (current,) = runtime.queries.current_records("a1", "hypothesis_process_state")
        assert current.status == "VERIFYING" and current.verification_result_ref is None
        assert runtime.queries.current_records("a1", "primitive_index_state") == ()
        (report_state,) = runtime.queries.current_records(
            "a1", "report_process_state"
        )
        assert report_state == initial_report_state
        return
    completed = runner.complete(work, owner, "VERIFICATION", (final,))
    assert completed.status == "SUCCEEDED"
    (terminal,) = runtime.queries.current_records("a1", "hypothesis_process_state")
    assert (
        terminal.status == "TERMINAL"
        and terminal.verification_result_ref == reference(final)
    )
    assert terminal.verification_work_ref is None
    (index,) = runtime.queries.current_records("a1", "primitive_index_state")
    assert (
        index.current_verification_ref == reference(final)
        and index.primitive_refs == ()
    )
    (report_state,) = runtime.queries.current_records("a1", "report_process_state")
    assert report_state.status == "NOT_REQUESTED"
    assert report_state.report_draft_ref is None
    assert (
        report_state.meta.logical_record_id
        == initial_report_state.meta.logical_record_id
    )
    assert report_state.meta.revision_number == 2
