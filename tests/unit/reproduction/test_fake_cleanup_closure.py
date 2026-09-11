"""Exact resource closure at the deterministic fake cleanup seam."""

import pytest

from sastsimi.contracts.dynamic import CleanupResult
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.ports.dto import SandboxCleanupRequest
from sastsimi.reproduction.fake_closure import require_cleanup_result
from sastsimi.sandbox.cleanup import owned_container_resource_ref
from tests.contract.domain.fixtures import wire
from tests.contract.domain.success_fixture import dynamic_success


def _cleanup_with_resources(
    cleanup: CleanupResult,
    *,
    request_ref: StoredDataRef,
    environment_ref: StoredDataRef,
    resource_refs: tuple[StoredDataRef, ...],
) -> CleanupResult:
    return wire(
        CleanupResult,
        cleanup.model_dump(mode="json")
        | {
            "request_ref": request_ref.model_dump(mode="json"),
            "environment_refs": [environment_ref.model_dump(mode="json")],
            "resource_refs": [
                resource_ref.model_dump(mode="json") for resource_ref in resource_refs
            ],
        },
    )


def test_fake_cleanup_accepts_exact_attempt_owned_resource_refs() -> None:
    chain = dynamic_success()
    environment = chain["environment"]
    resource_ref = owned_container_resource_ref(
        container_id=environment.container_instance_id,
        meta=environment.meta,
    )
    request_ref = reference(chain["request"])
    environment_ref = reference(environment)
    assert isinstance(request_ref, StoredDataRef)
    assert isinstance(environment_ref, StoredDataRef)
    cleanup = _cleanup_with_resources(
        chain["cleanup"],
        request_ref=request_ref,
        environment_ref=environment_ref,
        resource_refs=(resource_ref,),
    )
    request = SandboxCleanupRequest(
        chain["request"],
        (environment,),
        (resource_ref,),
    )

    assert require_cleanup_result(request, cleanup, cleanup) is cleanup


@pytest.mark.parametrize("case", ["empty", "foreign_attempt"])
def test_fake_cleanup_rejects_missing_or_foreign_attempt_resources(case: str) -> None:
    chain = dynamic_success()
    environment = chain["environment"]
    if case == "empty":
        resource_refs: tuple[StoredDataRef, ...] = ()
    else:
        foreign_meta = RecordMeta.model_validate(
            environment.meta.model_dump() | {"attempt_id": "foreign-attempt"}
        )
        resource_refs = (
            owned_container_resource_ref(
                container_id=environment.container_instance_id,
                meta=foreign_meta,
            ),
        )
    request_ref = reference(chain["request"])
    environment_ref = reference(environment)
    assert isinstance(request_ref, StoredDataRef)
    assert isinstance(environment_ref, StoredDataRef)
    cleanup = _cleanup_with_resources(
        chain["cleanup"],
        request_ref=request_ref,
        environment_ref=environment_ref,
        resource_refs=resource_refs,
    )
    request = SandboxCleanupRequest(
        chain["request"],
        (environment,),
        resource_refs,
    )

    with pytest.raises(
        ValueError,
        match="FAKE_SANDBOX_CLEANUP_RESOURCE_MISMATCH",
    ):
        require_cleanup_result(request, cleanup, cleanup)
