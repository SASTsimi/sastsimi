import json
from pathlib import Path
from typing import Any

import pytest

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.actions import ActionRequest, RequesterRole
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef
from sastsimi.contracts.work import WorkExecutionState
from tests.integration.runtime_support import Harness, metadata
from tests.unit.contracts.test_core_models import action, ref, work
from tests.unit.contracts.test_review_round1 import restart_data

# Literal §08 expectations, independent from the implementation's policy table.
ROLE_POLICY = {
    "REGISTER_WORK": "ORCHESTRATION VERIFICATION PRIMITIVE_ADMISSION_RUNTIME RECOVERY",
    "CHANGE_WORK_STATE": (
        "ORCHESTRATION VERIFICATION PRIMITIVE_ADMISSION_RUNTIME "
        "REPRODUCTION_SESSION_MANAGER RECOVERY"
    ),
    "START_ATTEMPT": (
        "ORCHESTRATION VERIFICATION PRIMITIVE_ADMISSION_RUNTIME "
        "REPRODUCTION_SESSION_MANAGER RECOVERY"
    ),
    "CANCEL_WORK": (
        "ORCHESTRATION VERIFICATION PRIMITIVE_ADMISSION_RUNTIME "
        "REPRODUCTION_SESSION_MANAGER RECOVERY"
    ),
    "RESTART_VERIFICATION_GENERATION": "VERIFICATION",
    "READ_CODE": "HYPOTHESIS PRO CON VERIFICATION CWE_LABELING TECHNICAL_GATE",
    "RUN_TOOL": "REPOSITORY_LOADER STATIC_ANALYSIS POLICY_COLLECTOR",
    "CALL_LLM": (
        "HYPOTHESIS PRO CON VERIFICATION CWE_LABELING CHAINING "
        "POLICY_PARSER DYNAMIC_REPRODUCTION"
    ),
    "FETCH_POLICY": "POLICY_COLLECTOR",
    "REQUEST_DYNAMIC_REPRO": "VERIFICATION",
    "RUN_SANDBOX": "REPRODUCTION_SETUP_AUTOMATION",
    "SAVE_RESULT": "REPOSITORY_LOADER",  # The selected result is code_workspace.
    "CALL_TECHNICAL_GATE": "VERIFICATION",
    "CALL_RULE_SCOPE_GATE": "VERIFICATION",
    "CREATE_REPORT_DRAFT": "VERIFICATION",
}


def action_shape(kind: str) -> dict[str, Any]:
    data = action(
        meta=metadata("action_request", "matrix", code=True), action_type=kind
    )
    if kind == "RESTART_VERIFICATION_GENERATION":
        data = restart_data("DYNAMIC_REQUEST_REPLACEMENT_REQUIRED")
        data["meta"] = metadata("action_request", "matrix", code=True) | {
            "hypothesis_id": "h1"
        }
    if kind in {"READ_CODE", "RUN_TOOL"}:
        data["file_paths"] = ["src/a.py"]
    if kind == "RUN_TOOL":
        data["tool_name"] = "approved-tool"
    if kind == "SAVE_RESULT":
        data.update(
            result_kind="code_workspace", candidate_result_ref=ref("code_workspace")
        )
    if kind in {
        "CALL_LLM",
        "CALL_TECHNICAL_GATE",
        "CALL_RULE_SCOPE_GATE",
        "CREATE_REPORT_DRAFT",
    }:
        data.update(
            llm_call_spec_ref=ref("llm_call_spec", True),
            provider_profile_ref=ref("provider_profile", True),
            session_mode="NEW",
            work_ref=ref(code=True),
            expected_state_version=1,
        )
    if kind in {"REQUEST_DYNAMIC_REPRO", "RUN_SANDBOX"}:
        data["dynamic_request_ref"] = ref("dynamic_reproduction_request", True)
    if kind == "RUN_SANDBOX":
        data.update(
            reproduction_plan_ref=ref("reproduction_plan", True),
            sandbox_profile_ref=ref("sandbox_profile", True),
            resource_profile_ref=ref("dynamic_reproduction_lifecycle_profile", True),
            run_policy_state_ref=ref("run_policy_state", True),
            input_refs=[
                ref(name, True)
                for name in (
                    "dynamic_reproduction_request",
                    "reproduction_plan",
                    "sandbox_profile",
                    "dynamic_reproduction_lifecycle_profile",
                    "environment_requirements",
                )
            ],
        )
    return data


@pytest.mark.parametrize("kind", ROLE_POLICY)
@pytest.mark.parametrize("role", list(RequesterRole))
def test_public_authority_policy_rejects_matching_identity_wrong_role(
    tmp_path: Path, kind: str, role: RequesterRole
) -> None:
    h = Harness(tmp_path)
    identity = h.records.stage_record(h.execution())
    assert isinstance(identity, (RunStoredDataRef, StoredDataRef))
    h.evidence.identities[identity] = role
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=h.evidence)
    data = action_shape(kind) | dict(
        requested_by=role.value, requester_identity_ref=identity.model_dump(mode="json")
    )
    if kind == "RESTART_VERIFICATION_GENERATION" and role != RequesterRole.VERIFICATION:
        # RECOVERY replays the existing exact Verification action, never authors one.
        with pytest.raises(ValueError):
            ActionRequest.model_validate_json(json.dumps(data))
        return
    approved = runtime.validator.authorize(
        ActionRequest.model_validate_json(json.dumps(data)),
        WorkExecutionState.model_validate_json(json.dumps(work())),
    )
    authority = next(
        check for check in approved.check_results if check.check_type == "AUTHORITY"
    )
    assert authority.result == (
        "PASS" if role.value in ROLE_POLICY[kind].split() else "FAIL"
    )
    if authority.result == "FAIL":
        assert approved.decision == "DENY"
