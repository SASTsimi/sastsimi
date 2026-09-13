"""Extending restart metadata must preserve immutable legacy input hashes."""

import json

import pytest

from sastsimi.contracts.analysis import AnalysisRunInput
from sastsimi.contracts.base import ContractModel
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from tests.unit.contracts.test_core_models import meta


def _legacy() -> dict[str, object]:
    return {
        "meta": meta(False, record_type="analysis_run_input"),
        "repository_ref": "repo",
        "requested_git_ref": "a" * 40,
        "program_id": "program",
        "purpose": "PRODUCTION",
    }


def test_legacy_input_keeps_exact_bytes_and_hash_with_missing_or_null_fields() -> None:
    original = AnalysisRunInput.model_validate_json(json.dumps(_legacy()))
    original_bytes = canonical_bytes(original)
    with_defaults = AnalysisRunInput.model_validate_json(
        json.dumps(
            _legacy()
            | {
                "workspace_id": None,
                "commit_id": None,
                "production_profile_ref": None,
                "production_onboarding_ref": None,
            }
        )
    )
    assert canonical_bytes(with_defaults) == original_bytes
    assert content_hash(with_defaults) == content_hash(original)
    assert content_hash(original) == (
        "b416b3ac24f7277b9897516167ec0a4f0d5f3282e2548bc9aa63df5d6dbcdfbb"
    )
    assert set(json.loads(original_bytes)) == set(_legacy())


@pytest.mark.parametrize(
    "field",
    [
        "workspace_id",
        "commit_id",
        "production_profile_ref",
        "production_onboarding_ref",
    ],
)
def test_non_null_restart_field_is_hashed(field: str) -> None:
    value: object = "workspace" if field == "workspace_id" else "a" * 40
    if field.endswith("_ref"):
        value = {
            "stored_data_id": "b" * 64,
            "data_kind": "artifact",
            "content_hash": "b" * 64,
            "analysis_id": "a1",
            "record_id": None,
        }
    legacy = AnalysisRunInput.model_validate_json(json.dumps(_legacy()))
    extended = AnalysisRunInput.model_validate_json(
        json.dumps(_legacy() | {field: value})
    )
    assert json.loads(canonical_bytes(extended))[field] == value
    assert content_hash(extended) != content_hash(legacy)


def test_other_nullable_contract_fields_remain_in_canonical_bytes() -> None:
    class OtherContract(ContractModel):
        workspace_id: str | None = None
        commit_id: str | None = None
        production_profile_ref: str | None = None
        production_onboarding_ref: str | None = None

    assert json.loads(canonical_bytes(OtherContract())) == {
        "workspace_id": None,
        "commit_id": None,
        "production_profile_ref": None,
        "production_onboarding_ref": None,
    }
    record = AnalysisRunInput.model_validate_json(json.dumps(_legacy()))
    assert json.loads(canonical_bytes(record))["meta"]["previous_record_id"] is None


def test_only_exact_analysis_input_declares_legacy_null_omission() -> None:
    from sastsimi.contracts.result_registry import RESULT_REGISTRY
    from sastsimi.contracts.schema_export import CORE_SCHEMAS

    expected = frozenset(
        {
            "workspace_id",
            "commit_id",
            "production_profile_ref",
            "production_onboarding_ref",
        }
    )
    models = {
        *CORE_SCHEMAS.values(),
        *(item.model for item in RESULT_REGISTRY.values()),
    }
    for model in models:
        if issubclass(model, ContractModel):
            assert model.canonical_omitted_null_fields() == (
                expected if model is AnalysisRunInput else frozenset()
            )

    class DerivedInput(AnalysisRunInput):
        pass

    derived = DerivedInput.model_validate_json(json.dumps(_legacy()))
    assert DerivedInput.canonical_omitted_null_fields() == frozenset()
    assert all(json.loads(canonical_bytes(derived))[name] is None for name in expected)
