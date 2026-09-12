"""An initial proposal's terminal journal derives its registered hypothesis state."""

import json
from pathlib import Path
from typing import Any

import pytest

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.hypothesis import (
    HypothesisProposal,
    ProposalProcessState,
    validate_hypothesis_registration,
)
from sastsimi.contracts.refs import reference
from sastsimi.contracts.static import StaticFactBundle
from sastsimi.contracts.work import WorkStatus
from tests.contract.domain.canonical_fixtures import make
from tests.integration.storage.test_intermediate_publication import (
    prepared_policy_parser,
)


def prepared_hypothesis(tmp_path: Path, *, parallel: int = 1) -> tuple[Any, ...]:
    h, runtime, runner, policy_work, parser, _ = prepared_policy_parser(
        tmp_path, parallel=parallel
    )
    identity = next(
        ref
        for ref, role in h.evidence.identities.items()
        if role == RequesterRole.POLICY_PARSER
    )
    runner.complete(policy_work, identity, "POLICY_PARSER", (parser,))
    scope = runtime.budget_registry.current_state("a1").budget_binding_ref
    assert scope is not None
    h.evidence.identities[identity] = RequesterRole.ORCHESTRATION
    static_work = runner.start(
        scope, policy_work.meta, "STATIC_NORMALIZE", "ANALYSIS", "a1", identity
    )
    bundle_data = json.loads(
        json.dumps(make("StaticFactBundle")).replace('"ws1"', '"w1"')
    )
    bundle_data["meta"] = runner.metadata(static_work.meta, "static_fact_bundle")
    bundle = StaticFactBundle.model_validate_json(canonical_bytes(bundle_data))
    h.evidence.identities[identity] = RequesterRole.STATIC_ANALYSIS
    normalized = runner.complete(static_work, identity, "STATIC_ANALYSIS", (bundle,))
    h.evidence.identities[identity] = RequesterRole.ORCHESTRATION
    proposal_work = runner.start(
        scope,
        policy_work.meta,
        "HYPOTHESIS_PROPOSAL",
        "PROPOSAL",
        "p1",
        identity,
        inputs=normalized.output_refs,
    )
    proposal_data = json.loads(
        json.dumps(make("HypothesisProposal")).replace('"ws1"', '"w1"')
    )
    proposal_data["meta"] = runner.metadata(
        proposal_work.meta,
        "hypothesis_proposal",
        attempt_id=proposal_work.active_attempt_id,
    )
    proposal = HypothesisProposal.model_validate_json(canonical_bytes(proposal_data))
    runner.complete(proposal_work, identity, "ORCHESTRATION", (proposal,))
    return h, runtime, runner, identity, proposal, bundle


def test_initial_proposal_derives_hypothesis_process_and_empty_report_state(
    tmp_path: Path,
) -> None:
    _, runtime, _, _, proposal, _ = prepared_hypothesis(tmp_path)
    (hypothesis,) = runtime.queries.current_records("a1", "vulnerability_hypothesis")
    (process,) = runtime.queries.current_records("a1", "hypothesis_process_state")
    (index,) = runtime.queries.current_records("a1", "finding_index_state")
    (report_state,) = runtime.queries.current_records("a1", "report_process_state")
    (proposal_state,) = runtime.queries.current_records("a1", "proposal_process_state")
    validate_hypothesis_registration(hypothesis, proposal)
    assert process.status == "REGISTERED" and process.verification_generation == 0
    assert index.status == "EMPTY"
    assert report_state.status == "NOT_REQUESTED"
    assert report_state.report_draft_ref is None
    assert isinstance(proposal_state, ProposalProcessState)
    assert proposal_state.status == "SCHEMA_VALID"
    assert proposal_state.registration_reason == "NO_CANDIDATES"
    assert proposal_state.proposal_ref == reference(proposal)
    assert (
        hypothesis.meta.hypothesis_id
        == process.meta.hypothesis_id
        == index.meta.hypothesis_id
        == report_state.meta.hypothesis_id
    )


def test_initial_proposal_work_registers_every_candidate_in_one_batch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    h, runtime, runner, identity, _proposal, bundle = prepared_hypothesis(tmp_path)
    scope = runtime.budget_registry.current_state("a1").budget_binding_ref
    assert scope is not None
    bundle_ref = reference(bundle)
    work = runner.start(
        scope,
        bundle.meta,
        "HYPOTHESIS_PROPOSAL",
        "PROPOSAL",
        "proposal-batch",
        identity,
        inputs=(bundle_ref,),
    )
    proposals = []
    for number in (2, 3):
        data = json.loads(
            json.dumps(make("HypothesisProposal")).replace('"ws1"', '"w1"')
        )
        data["proposal_id"] = f"p{number}"
        data["meta"] = runner.metadata(
            work.meta,
            "hypothesis_proposal",
            attempt_id=work.active_attempt_id,
        )
        data["falsification_questions"][0]["question_id"] = f"q{number}"
        data["validation_checks"][0]["validation_id"] = f"v{number}"
        proposals.append(HypothesisProposal.model_validate_json(canonical_bytes(data)))

    proposal_refs = tuple(h.records.stage_record(item) for item in proposals)
    monkeypatch.setattr(h.evidence, "authorized_outputs", lambda _action: proposal_refs)
    completed = runner.complete(work, identity, "ORCHESTRATION", tuple(proposals))

    assert completed.status == WorkStatus.SUCCEEDED
    assert completed.output_refs == tuple(reference(item) for item in proposals)
    assert len(runtime.queries.current_records("a1", "vulnerability_hypothesis")) == 3


def test_initial_proposal_work_can_succeed_with_no_candidates(tmp_path: Path) -> None:
    _, runtime, runner, identity, _proposal, bundle = prepared_hypothesis(tmp_path)
    scope = runtime.budget_registry.current_state("a1").budget_binding_ref
    assert scope is not None
    work = runner.start(
        scope,
        bundle.meta,
        "HYPOTHESIS_PROPOSAL",
        "PROPOSAL",
        "empty-proposal-batch",
        identity,
        inputs=(reference(bundle),),
    )

    completed = runner.complete(work, identity, "ORCHESTRATION", ())

    assert completed.status == WorkStatus.SUCCEEDED
    assert completed.output_refs == ()
