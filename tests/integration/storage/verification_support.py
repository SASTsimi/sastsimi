"""Test-only exact configuration for an actual registered Verification work."""

from pathlib import Path
from typing import Any

from sqlalchemy import insert

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.verification import PlaybookPolicy, VerificationPlaybook
from sastsimi.storage import models
from sastsimi.storage.codec import reference
from tests.contract.domain.canonical_fixtures import make
from tests.integration.storage.test_hypothesis_projection import prepared_hypothesis


def prepared_verification(tmp_path: Path) -> tuple[Any, ...]:
    h, runtime, runner, orchestrator, proposal, bundle = prepared_hypothesis(
        tmp_path, parallel=4
    )
    (hypothesis,) = runtime.queries.current_records("a1", "vulnerability_hypothesis")
    (process,) = runtime.queries.current_records("a1", "hypothesis_process_state")
    scope = runtime.budget_registry.current_state("a1").budget_binding_ref
    binding = h.records.get_exact(scope)
    owner = binding.work_budget_profile_ref
    h.evidence.identities[owner] = RequesterRole.VERIFICATION
    book = VerificationPlaybook.model_validate_json(
        canonical_bytes(
            make("VerificationPlaybook")
            | dict(meta=runner.metadata(bundle.meta, "verification_playbook"))
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
        requester_identity_ref=orchestrator,
        budget_binding_ref=scope,
    )
    work = runner.activate(registered.work, scope, owner, role="VERIFICATION")
    return h, runtime, runner, work, registered, owner, hypothesis, bundle
