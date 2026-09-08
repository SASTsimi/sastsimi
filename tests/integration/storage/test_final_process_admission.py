import json
from pathlib import Path
from typing import cast

import pytest
from sqlalchemy import insert

from sastsimi.bootstrap import build_runtime
from sastsimi.contracts.actions import ActionRequest, RequesterRole
from sastsimi.contracts.hypothesis import HypothesisProcessState, VerificationAssignment
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.result_registry import RESULT_REGISTRY
from sastsimi.contracts.verification import VerificationResult
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import Record
from sastsimi.storage import models
from sastsimi.storage.codec import reference
from tests.contract.domain.canonical_fixtures import make
from tests.contract.domain.fixtures import meta
from tests.contract.domain.success_fixture import bound, dynamic_success
from tests.integration.runtime_support import Harness
from tests.integration.storage.restart_fixture import publish_current
from tests.unit.contracts.test_core_models import action, work


@pytest.mark.parametrize("terminal", [False, True])
@pytest.mark.parametrize(
    ("kind", "work_type", "role"),
    [
        ("cwe_label", "CWE_LABEL", "CWE_LABELING"),
        ("technical_evidence_review", "TECHNICAL_GATE", "TECHNICAL_GATE"),
        ("rule_scope_impact_review", "RULE_SCOPE_GATE", "RULE_SCOPE_GATE"),
        ("finding", "FINDING_NORMALIZE", "VERIFICATION"),
        ("report_draft", "REPORT_DRAFT", "REPORTER"),
    ],
)
def test_public_final_result_admission_requires_terminal_process(
    tmp_path: Path, terminal: bool, kind: str, work_type: str, role: str
) -> None:
    h = Harness(tmp_path)
    runtime = build_runtime(tmp_path, None, None, h.clock, h.ids, evidence=h.evidence)
    chain = dynamic_success()
    verification = VerificationResult.model_validate_json(
        json.dumps(
            make("VerificationResult")
            | dict(
                initial_verdict="TRUE",
                verdict="TRUE",
                dynamic_request_ref=bound(chain["request"]),
                dynamic_result_ref=bound(chain["result"]),
                poc_ref=bound(chain["poc"]),
            )
        )
    )
    h.publish(verification)
    binding = RESULT_REGISTRY[kind]
    label = binding.model.model_validate_json(
        json.dumps(
            make(binding.schema_name, kind)
            | (
                dict(
                    verification_result_ref=reference(verification).model_dump(
                        mode="json"
                    )
                )
                if "verification_result_ref" in binding.model.model_fields
                else {}
            )
        )
    )
    label_ref = h.records.stage_record(cast(Record, label))
    identity = reference(verification)
    assert isinstance(identity, StoredDataRef)
    h.evidence.identities[identity] = RequesterRole(role)
    assignment = VerificationAssignment.model_validate_json(
        json.dumps(
            make("VerificationAssignment")
            | dict(owner_identity_ref=identity.model_dump(mode="json"))
        )
    )
    publish_current(h, assignment)
    target = WorkExecutionState.model_validate_json(
        json.dumps(
            work(
                meta=meta("work_execution_state", hypothesis="h1", attempt=None),
                work_id="cwe-work",
                work_type=work_type,
                subject_type="HYPOTHESIS",
                subject_id="h1",
                parent_work_ref=chain["request"].verification_assignment_ref.model_dump(
                    mode="json"
                )
                | {"data_kind": "work_execution_state"}
                if work_type in {"CWE_LABEL", "FINDING_NORMALIZE"}
                else None,
                status="RUNNING",
                state_version=2,
                active_attempt_id="at1",
                started_at="2026-09-07T00:00:00Z",
                last_transition_ref=chain[
                    "request"
                ].verification_assignment_ref.model_dump(mode="json")
                | {"data_kind": "state_transition"},
            )
        )
    )
    publish_current(h, target)
    process_data = make("HypothesisProcessState") | dict(
        status="TERMINAL" if terminal else "VERIFYING",
        verification_generation=1,
        verification_assignment_ref=reference(assignment).model_dump(mode="json"),
        verification_work_ref=None
        if terminal
        else reference(target).model_dump(mode="json"),
        verification_result_ref=reference(verification).model_dump(mode="json"),
        finished_at="2026-09-08T00:00:00Z" if terminal else None,
    )
    publish_current(
        h, HypothesisProcessState.model_validate_json(json.dumps(process_data))
    )
    with h.database.write() as connection:
        connection.execute(
            insert(models.work_states).values(
                work_id="cwe-work",
                analysis_id="a1",
                registration_key=target.dedupe_key,
                state_version=2,
                status="RUNNING",
                active_attempt_id="at1",
                payload=target.model_dump_json(),
            )
        )
    request = ActionRequest.model_validate_json(
        json.dumps(
            action(
                meta=meta("action_request", hypothesis="h1"),
                requested_by=role,
                action_type="SAVE_RESULT",
                requester_identity_ref=identity.model_dump(mode="json"),
                work_ref=reference(target).model_dump(mode="json"),
                expected_state_version=2,
                input_refs=[reference(verification).model_dump(mode="json")],
                result_kind=kind,
                candidate_result_ref=label_ref.model_dump(mode="json"),
            )
        )
    )
    decision = runtime.validator.authorize(request)
    if kind == "finding":
        checks = {check.check_type.value: check for check in decision.check_results}
        assert checks["STATE"].result == ("PASS" if terminal else "FAIL")
        # T04's distinct trusted Finding service identity is not implemented in T06.
        assert checks["SCHEMA"].reason_code == "FINDING_NORMALIZER_AUTHORITY_REQUIRED"
        return
    assert decision.decision == ("ALLOW" if terminal else "DENY"), [
        (check.check_type.value, check.reason_code) for check in decision.check_results
    ]
