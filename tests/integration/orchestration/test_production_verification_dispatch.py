"""Focused production handoff test: committed hypothesis becomes READY Verification."""

import json
from pathlib import Path

from sqlalchemy import insert

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.orchestration.production_verification_dispatch import (
    InitialVerificationDispatcher,
)
from sastsimi.storage import models
from sastsimi.storage.codec import reference
from tests.contract.domain.canonical_fixtures import make
from tests.integration.storage.test_hypothesis_projection import prepared_hypothesis


def test_committed_initial_proposal_registers_ready_verification(
    tmp_path: Path,
) -> None:
    h, runtime, runner, orchestration, proposal, bundle = prepared_hypothesis(tmp_path)
    scope = runtime.budget_registry.current_state("a1").budget_binding_ref
    assert scope is not None
    binding = h.records.get_exact(scope)
    verification_identity = binding.work_budget_profile_ref
    h.evidence.identities[verification_identity] = RequesterRole.VERIFICATION

    def data(kind: str) -> dict[str, object]:
        value = json.loads(json.dumps(make(kind)).replace('"ws1"', '"w1"'))
        value["meta"]["created_at"] = h.clock.now().isoformat()
        return value

    book = VerificationPlaybook.model_validate_json(
        canonical_bytes(data("VerificationPlaybook"))
    )
    policy = PlaybookPolicy.model_validate_json(
        canonical_bytes(
            data("PlaybookPolicy")
            | {"common_playbook_ref": reference(book), "type_playbooks": []}
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

    InitialVerificationDispatcher(
        records=h.records,
        current=runtime.queries,
        registrar=runtime.verification_registration,
        runner=runner,
        policy_ref=reference(policy),
        verification_identity_ref=verification_identity,
        orchestration_identity_ref=orchestration,
    )((reference(proposal),))

    works = runtime.work.store.work_for_run("a1")
    verification = tuple(item for item in works if item.work_type == "VERIFICATION")
    assert len(verification) == 1
    assert verification[0].status == "READY"
    assert reference(bundle) in verification[0].input_refs
