"""The authority artifact has a complete, ordered, non-substitutable role map."""

import json
from typing import cast

import pytest
from pydantic import ValidationError

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.refs import reference
from tests.unit.orchestration.test_production_operator_profiles import (
    _Clock,
    _Ids,
    _scope,
    _settings,
)


def catalog_payload() -> dict[str, object]:
    from sastsimi.orchestration.production_operator_profiles import (
        ProductionOperatorProfiles,
    )

    profiles = ProductionOperatorProfiles(
        scope=_scope(),
        program_id="program-one",
        settings=_settings(),
        clock=_Clock(),
        ids=_Ids(),
    )
    artifact = {
        "stored_data_id": "b" * 64,
        "data_kind": "artifact",
        "content_hash": "b" * 64,
        "analysis_id": "analysis-one",
        "record_id": None,
    }
    return cast(
        dict[str, object],
        json.loads(
            canonical_bytes(
                {
                    "schema_version": "1",
                    "artifact_scope": "ANALYSIS_OPERATOR_AUTHORITY",
                    "analysis_id": _scope().analysis_id,
                    "workspace_id": _scope().workspace_id,
                    "commit_id": _scope().commit_id,
                    "program_id": "program-one",
                    "purpose": "PRODUCTION",
                    "production_profile_ref": artifact,
                    "production_onboarding_ref": artifact,
                    "execution_budget_profile_ref": reference(
                        profiles.execution_profile
                    ),
                    "work_budget_profile_ref": reference(profiles.work_profile),
                    "verification_budget_profile_ref": reference(
                        profiles.verification_profile
                    ),
                    "dynamic_lifecycle_profile_ref": reference(
                        profiles.dynamic_profile
                    ),
                    "role_identities": [
                        {"role": role, "identity_ref": profiles.identity_ref(role)}
                        for role in RequesterRole
                    ],
                }
            )
        ),
    )


def test_catalog_preserves_every_role_including_unused_recovery() -> None:
    from sastsimi.contracts.production_authority import ProductionAuthorityCatalog

    catalog = ProductionAuthorityCatalog.model_validate_json(
        json.dumps(catalog_payload())
    )
    assert tuple(item.role for item in catalog.role_identities) == tuple(RequesterRole)
    assert catalog.role_identities[-1].role == RequesterRole.RECOVERY
    assert "budget_binding_ref" not in json.loads(canonical_bytes(catalog))
    assert "meta" not in json.loads(canonical_bytes(catalog))
    with pytest.raises(ValidationError):
        catalog.purpose = "EVALUATION"  # type: ignore[assignment]


def test_catalog_exports_as_configuration_without_a_result_owner() -> None:
    from sastsimi.contracts.production_authority import ProductionAuthorityCatalog
    from sastsimi.contracts.result_registry import RESULT_REGISTRY
    from sastsimi.contracts.schema_export import schema_documents
    from tests.contract.domain.test_inventory import canonical_fields

    assert "production_authority_catalog" not in RESULT_REGISTRY
    schema = json.loads(
        schema_documents()["production_authority_catalog/1.schema.json"]
    )
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(ProductionAuthorityCatalog.model_fields)
    assert set(ProductionAuthorityCatalog.model_fields) == set(
        canonical_fields()["ProductionAuthorityCatalog"]
    )


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "duplicate-role",
        "duplicate-identity",
        "reordered",
        "common",
        "loader",
        "foreign",
        "workspace",
        "purpose",
        "binding",
    ],
)
def test_catalog_rejects_ambiguous_or_foreign_authority(fault: str) -> None:
    from sastsimi.contracts.production_authority import ProductionAuthorityCatalog

    payload = catalog_payload()
    roles = payload["role_identities"]
    assert isinstance(roles, list)
    if fault == "missing":
        roles.pop()
    elif fault == "duplicate-role":
        roles[-1]["role"] = roles[0]["role"]
    elif fault == "duplicate-identity":
        roles[-1]["identity_ref"] = roles[0]["identity_ref"]
    elif fault == "reordered":
        roles.reverse()
    elif fault == "common":
        roles[0]["identity_ref"] = payload["work_budget_profile_ref"]
    elif fault == "loader":
        roles[10]["identity_ref"] = roles[0]["identity_ref"]
    elif fault == "foreign":
        payload["analysis_id"] = "foreign-analysis"
    elif fault == "workspace":
        roles[0]["identity_ref"]["workspace_id"] = "foreign-workspace"
    elif fault == "purpose":
        payload["purpose"] = "EVALUATION"
    else:
        payload["budget_binding_ref"] = payload["work_budget_profile_ref"]
    with pytest.raises(ValidationError):
        ProductionAuthorityCatalog.model_validate_json(json.dumps(payload))
