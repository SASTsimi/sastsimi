"""An initial proposal's terminal journal derives its registered hypothesis state."""

import json
from pathlib import Path
from typing import Any

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.hypothesis import (
    HypothesisProposal,
    validate_hypothesis_registration,
)
from sastsimi.contracts.static import StaticFactBundle
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


def test_initial_proposal_derives_hypothesis_process_and_empty_finding_index(
    tmp_path: Path,
) -> None:
    _, runtime, _, _, proposal, _ = prepared_hypothesis(tmp_path)
    (hypothesis,) = runtime.queries.current_records("a1", "vulnerability_hypothesis")
    (process,) = runtime.queries.current_records("a1", "hypothesis_process_state")
    (index,) = runtime.queries.current_records("a1", "finding_index_state")
    validate_hypothesis_registration(hypothesis, proposal)
    assert process.status == "REGISTERED" and process.verification_generation == 0
    assert index.status == "EMPTY"
    assert (
        hypothesis.meta.hypothesis_id
        == process.meta.hypothesis_id
        == index.meta.hypothesis_id
    )
