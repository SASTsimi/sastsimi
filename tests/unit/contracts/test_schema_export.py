from pathlib import Path

import pytest

from sastsimi.contracts.schema_export import check_schemas, export_schemas

EXPECTED_KINDS = {
    "run_meta",
    "record_meta",
    "policy_cache_meta",
    "run_stored_data_ref",
    "stored_data_ref",
    "policy_cache_ref",
    "work_execution_state",
    "work_attempt",
    "state_transition",
    "transition_commit",
    "action_request",
    "action_check",
    "action_decision",
    "sandbox_profile",
    "execution_budget_profile",
    "work_budget_limit",
    "work_budget_profile",
    "verification_budget_profile",
    "dynamic_reproduction_lifecycle_profile",
    "budget_profile_binding",
    "budget_units",
    "budget_reservation",
    "budget_ledger_entry",
    "budget_remaining",
}


def test_full_budget_binding_schema_requires_workspace_metadata() -> None:
    from sastsimi.contracts.budget import BudgetProfileBinding

    schema = BudgetProfileBinding.model_json_schema()
    assert schema["properties"]["meta"] == {"$ref": "#/$defs/RecordMeta"}


def test_committed_schema_exports_have_no_drift() -> None:
    root = Path(__file__).resolve().parents[3] / "schemas" / "generated"
    check_schemas(root)
    from sastsimi.contracts.result_registry import RESULT_REGISTRY

    assert {
        path.parent.name for path in root.rglob("*.schema.json")
    } == EXPECTED_KINDS | set(RESULT_REGISTRY)


def test_transition_schemas_only_publish_valid_target_states() -> None:
    from sastsimi.contracts.work import StateTransition, TransitionCommit

    schema = StateTransition.model_json_schema()
    target = schema["properties"]["to_status"]["$ref"].split("/")[-1]
    assert set(schema["$defs"][target]["enum"]) == {
        "READY",
        "RUNNING",
        "BLOCKED",
        "SUCCEEDED",
        "PARTIAL",
        "FAILED",
        "CANCELLED",
    }
    schema = TransitionCommit.model_json_schema()
    target = schema["properties"]["target_status"]["$ref"].split("/")[-1]
    assert set(schema["$defs"][target]["enum"]) == {
        "BLOCKED",
        "SUCCEEDED",
        "PARTIAL",
        "FAILED",
        "CANCELLED",
    }


def test_regeneration_is_idempotent_and_missing_extra_modified_fail(
    tmp_path: Path,
) -> None:
    export_schemas(tmp_path)
    original = {
        str(path.relative_to(tmp_path)): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    export_schemas(tmp_path)
    assert original == {
        str(path.relative_to(tmp_path)): path.read_bytes()
        for path in tmp_path.rglob("*")
        if path.is_file()
    }
    check_schemas(tmp_path)
    path = tmp_path / "work_attempt" / "1.schema.json"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="drift"):
        check_schemas(tmp_path)
    export_schemas(tmp_path)
    path.unlink()
    with pytest.raises(ValueError, match="missing"):
        check_schemas(tmp_path)
    export_schemas(tmp_path)
    (tmp_path / "extra.json").write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="extra"):
        check_schemas(tmp_path)
