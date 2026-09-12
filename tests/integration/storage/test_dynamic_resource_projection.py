"""Trusted reconstruction of resources owned by one dynamic attempt."""

from typing import Any

import pytest

from sastsimi.contracts.dynamic import CleanupResult, DynamicReproductionResult
from sastsimi.contracts.dynamic_resource import owned_container_resource_ref
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.sandbox.cleanup import OwnedResourceRegistry
from sastsimi.storage.dynamic_projection import resolve_attempt_resource_refs
from tests.contract.domain.fixtures import wire
from tests.contract.domain.success_fixture import bound, dynamic_success
from tests.contract.domain.test_success_closure import check_dynamic


def _cleanup_with_resources(
    chain: dict[str, Any], resources: tuple[StoredDataRef, ...]
) -> None:
    chain["cleanup"] = wire(
        CleanupResult,
        chain["cleanup"].model_dump(mode="json")
        | {"resource_refs": [item.model_dump(mode="json") for item in resources]},
    )
    chain["result"] = wire(
        DynamicReproductionResult,
        chain["result"].model_dump(mode="json")
        | {"cleanup_ref": bound(chain["cleanup"])},
    )


def test_projection_reconstructs_exact_owned_resource_from_environment() -> None:
    chain = dynamic_success()
    environment = chain["environment"]
    resource = owned_container_resource_ref(
        container_id=environment.container_instance_id,
        meta=environment.meta,
    )
    _cleanup_with_resources(chain, (resource,))

    resolved = resolve_attempt_resource_refs(
        chain["result"],
        chain["log"],
        chain["cleanup"],
        (environment,),
    )

    assert resolved == (resource,)
    chain["attempt_resource_refs"] = resolved
    check_dynamic(chain)


def test_registry_issues_the_attempt_scoped_resource_ref_projection_derives() -> None:
    environment = dynamic_success()["environment"]
    labels = {
        "sastsimi.owner": "reproduction-setup-automation",
        "sastsimi.attempt-id": str(environment.meta.attempt_id),
    }
    registry = OwnedResourceRegistry()

    registered = registry.register_container(
        container_id=environment.container_instance_id,
        labels=labels,
        meta=environment.meta,
    )
    foreign_meta = RecordMeta.model_validate(
        environment.meta.model_dump() | {"attempt_id": "foreign-attempt"}
    )

    assert registered == owned_container_resource_ref(
        container_id=environment.container_instance_id,
        meta=environment.meta,
    )
    assert registered != owned_container_resource_ref(
        container_id=environment.container_instance_id,
        meta=foreign_meta,
    )


@pytest.mark.parametrize("case", ["extra", "foreign_attempt"])
def test_projection_rejects_unowned_or_cross_attempt_resource(case: str) -> None:
    chain = dynamic_success()
    environment = chain["environment"]
    owned = owned_container_resource_ref(
        container_id=environment.container_instance_id,
        meta=environment.meta,
    )
    foreign_meta = RecordMeta.model_validate(
        environment.meta.model_dump() | {"attempt_id": "foreign-attempt"}
    )
    foreign = owned_container_resource_ref(
        container_id=environment.container_instance_id,
        meta=foreign_meta,
    )
    resources = (owned, foreign) if case == "extra" else (foreign,)
    _cleanup_with_resources(chain, resources)

    with pytest.raises(ValueError, match="CLEANUP_RESOURCE_PROVENANCE_MISMATCH"):
        resolve_attempt_resource_refs(
            chain["result"],
            chain["log"],
            chain["cleanup"],
            (environment,),
        )
