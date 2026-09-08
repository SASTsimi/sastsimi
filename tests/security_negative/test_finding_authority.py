import pytest

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.reporting import Finding
from sastsimi.contracts.result_registry import validate_result_owner
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import meta, ref, wire
from tests.contract.domain.success_fixture import bound


def test_finding_service_requires_exact_active_assignment_and_owner() -> None:
    from sastsimi.contracts.hypothesis import VerificationAssignment

    finding = wire(Finding, make("Finding"))
    assignment = wire(
        VerificationAssignment,
        dict(
            meta=meta("verification_assignment", hypothesis="h1", attempt=None),
            assignment_id="assignment1",
            owner_identity_ref=ref("requester_identity"),
            assignment_generation=1,
            status="ACTIVE",
            previous_assignment_ref=None,
            assigned_at="2026-09-08T00:00:00Z",
        ),
    )
    identity = wire(StoredDataRef, ref("requester_identity"))
    with pytest.raises(ValueError, match="FINDING_NORMALIZER_AUTHORITY_REQUIRED"):
        validate_result_owner("finding", finding, RequesterRole.VERIFICATION)
    validate_result_owner(
        "finding",
        finding,
        RequesterRole.VERIFICATION,
        requester_identity_ref=identity,
        finding_service_identity_ref=identity,
        active_assignment_owner_ref=identity,
        finding_assignment=assignment,
        expected_assignment_ref=wire(StoredDataRef, bound(assignment)),
    )
    stale = wire(
        VerificationAssignment,
        assignment.model_dump(mode="json") | {"status": "SUPERSEDED"},
    )
    with pytest.raises(ValueError, match="FINDING_NORMALIZER_AUTHORITY_REQUIRED"):
        validate_result_owner(
            "finding",
            finding,
            RequesterRole.VERIFICATION,
            requester_identity_ref=identity,
            finding_service_identity_ref=identity,
            active_assignment_owner_ref=identity,
            finding_assignment=stale,
            expected_assignment_ref=wire(StoredDataRef, bound(stale)),
        )
