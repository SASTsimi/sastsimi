from __future__ import annotations

import hashlib
import inspect
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import pytest

from sastsimi.bootstrap import T11Services, build_t11_services
from sastsimi.contracts.canonical_json import canonical_bytes, content_hash
from sastsimi.contracts.dynamic import (
    AgentLogEvent,
    DynamicReproductionRequest,
    validate_boundary_binding,
)
from sastsimi.contracts.hypothesis import HypothesisProcessState
from sastsimi.contracts.ids import ActionId, RecordId
from sastsimi.contracts.refs import StoredDataRef, reference
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import WorkHandlerResult
from sastsimi.prompts.dynamic_reproduction import DYNAMIC_REPRODUCTION_PROMPTS
from sastsimi.prompts.registry import REQUIRED_TEMPLATE_SECTIONS
from sastsimi.reproduction.production import ProductionDynamicWorkflow
from sastsimi.reproduction.service import DynamicStageAuthorizations
from sastsimi.sandbox.session_manager import ReproductionSessionManager
from sastsimi.verification.completion import VerificationCompletionCoordinator
from tests.contract.domain.success_fixture import bound, dynamic_success
from tests.integration.runtime_support import TestClock, TestIds

NOW = "2026-09-08T00:00:00Z"


def _meta(kind: str, *, attempt_id: str | None) -> dict[str, object]:
    return {
        "record_id": f"{kind}-record",
        "logical_record_id": f"{kind}-logical",
        "record_type": kind,
        "schema_version": "1.0.0",
        "analysis_id": "a1",
        "revision_number": 1,
        "previous_record_id": None,
        "created_at": NOW,
        "workspace_id": "ws1",
        "commit_id": "c1",
        "hypothesis_id": "h1",
        "attempt_id": attempt_id,
    }


def _ref(kind: str, name: str) -> dict[str, object]:
    return {
        "stored_data_id": f"{name}-stored",
        "data_kind": kind,
        "content_hash": "a" * 64,
        "workspace_id": "ws1",
        "commit_id": "c1",
        "record_id": f"{name}-record",
    }


def _request() -> DynamicReproductionRequest:
    return DynamicReproductionRequest.model_validate_json(
        canonical_bytes(
            {
                "meta": _meta("dynamic_reproduction_request", attempt_id="r6-attempt"),
                "verification_assignment_ref": _ref(
                    "verification_assignment", "assignment"
                ),
                "verification_generation": 1,
                "hypothesis_ref": _ref("vulnerability_hypothesis", "hypothesis"),
                "purpose": "POC_CONFIRMATION",
                "initial_verdict": "TRUE",
                "goal": "Reproduce the path",
                "environment_needs": [],
                "sandbox_profile_ref": _ref("sandbox_profile", "sandbox-profile"),
                "code_refs": [],
                "static_evidence_refs": [],
                "pro_evidence_ref": _ref("pro_evidence_result", "pro"),
                "con_evidence_ref": _ref("con_evidence_result", "con"),
                "created_at": NOW,
            }
        )
    )


def _work(request_ref: StoredDataRef, *, generation: int = 1) -> WorkExecutionState:
    value = {
        "meta": _meta("work_execution_state", attempt_id=None),
        "work_id": "dynamic-work",
        "parent_work_ref": _ref("work_execution_state", "verification-work"),
        "work_type": "DYNAMIC_REPRO",
        "subject_type": "HYPOTHESIS",
        "subject_id": "h1",
        "work_generation": generation,
        "status": "RUNNING",
        "active_attempt_id": "dynamic-attempt",
        "input_refs": [request_ref.model_dump(mode="json")],
        "input_hash": content_hash((request_ref,)),
        "dedupe_key": "d" * 64,
        "trigger_primitive_ref": None,
        "output_refs": [],
        "gap_ids": [],
        "error_ids": [],
        "waiting_for": [],
        "stop_reason": None,
        "started_at": "2026-09-08T00:00:00Z",
        "finished_at": None,
        "elapsed_ms": 0,
        "state_version": 2,
        "last_transition_ref": _ref("state_transition", "started"),
        "last_transition_commit_ref": None,
    }
    return WorkExecutionState.model_validate_json(canonical_bytes(value))


def _process(request: DynamicReproductionRequest) -> HypothesisProcessState:
    value = {
        "meta": _meta("hypothesis_process_state", attempt_id=None),
        "proposal_ref": _ref("hypothesis_proposal", "proposal"),
        "status": "VERIFYING",
        "verification_assignment_ref": request.verification_assignment_ref.model_dump(
            mode="json"
        ),
        "verification_generation": request.verification_generation,
        "verification_work_ref": _ref("work_execution_state", "verification-work"),
        "verification_result_ref": None,
        "started_at": NOW,
        "finished_at": None,
        "elapsed_ms": 0,
    }
    return HypothesisProcessState.model_validate_json(canonical_bytes(value))


@dataclass
class _Executor:
    output_ref: StoredDataRef
    calls: int = 0

    async def __call__(self, **_: object) -> WorkHandlerResult:
        self.calls += 1
        return WorkHandlerResult((self.output_ref,))


def _output(kind: str) -> StoredDataRef:
    return StoredDataRef.model_validate(
        {
            "stored_data_id": f"{kind}-stored",
            "data_kind": kind,
            "content_hash": "c" * 64,
            "workspace_id": "ws1",
            "commit_id": "c1",
            "record_id": f"{kind}-record",
        }
    )


@pytest.mark.asyncio
async def test_t11_composition_runs_only_exact_current_dynamic_request() -> None:
    request = _request()
    request_ref = cast(StoredDataRef, reference(request))
    work = _work(request_ref)
    executor = _Executor(_output("dynamic_reproduction_result"))
    services = T11Services(
        execute_dynamic=executor,
        current_process=lambda _: _process(request),
        completion=cast(VerificationCompletionCoordinator, object()),
    )

    result = await services.execute(
        work=work,
        request=request,
        request_ref=request_ref,
        authorizations=cast(DynamicStageAuthorizations, object()),
    )

    assert result.output_refs == (executor.output_ref,)
    assert executor.calls == 1


def test_dynamic_prompt_seeds_are_exact_and_only_execute_can_use_tools() -> None:
    root = Path(__file__).resolve().parents[3]
    assert {item.task_kind for item in DYNAMIC_REPRODUCTION_PROMPTS} == {
        "DERIVE_ENVIRONMENT",
        "PLAN_REPRODUCTION",
        "CREATE_POC_CANDIDATE",
        "EXECUTE_REPRODUCTION",
        "INTERPRET_ATTEMPT",
    }
    assert [
        item.task_kind for item in DYNAMIC_REPRODUCTION_PROMPTS if item.sandbox_tools
    ] == ["EXECUTE_REPRODUCTION"]
    for seed in DYNAMIC_REPRODUCTION_PROMPTS:
        data = (root / seed.template_path).read_bytes()
        assert hashlib.sha256(data).hexdigest() == seed.template_sha256
        text = data.decode("utf-8")
        assert all(f"# {section}" in text for section in REQUIRED_TEMPLATE_SECTIONS)


def test_production_bootstrap_uses_real_sandbox_components() -> None:
    source = inspect.getsource(build_t11_services)
    for component in (
        "DockerAdapter",
        "SandboxController",
        "ReproductionSetupAutomation",
        "ReproductionSessionManager",
        "DynamicReproductionAgent",
    ):
        assert component in source
    assert "FakeSandboxAdapter" not in source
    assert "verification=verification" in source

    assert "completion=VerificationCompletionCoordinator(" in source
    assert "verification=verification" in source
    assert "repository_profile=repository_profile" in source
    assert "repository_profile=self._repository_profile" in inspect.getsource(
        ProductionDynamicWorkflow.open_session
    )
    assert "source.repository_profile_ref" in inspect.getsource(
        ProductionDynamicWorkflow.open_session
    )


def test_session_start_binds_the_exact_allow_policy_reference() -> None:
    chain = dynamic_success()
    request_ref = StoredDataRef.model_validate(bound(chain["request"]))
    policy_ref = StoredDataRef.model_validate(bound(chain["policy"]))
    manager = ReproductionSessionManager(clock=TestClock(), ids=TestIds())

    log = manager.start(
        request_ref=request_ref,
        meta=chain["log"].meta,
        policy_decision_ref=policy_ref,
    )

    assert log.events[0].input_refs == (request_ref, policy_ref)
    validate_boundary_binding(chain["result"], chain["request"], log, chain["policy"])


def test_recreate_event_binds_the_current_allow_policy_reference() -> None:
    chain = dynamic_success()
    request_ref = StoredDataRef.model_validate(bound(chain["request"]))
    initial_policy_ref = StoredDataRef.model_validate(bound(chain["policy"]))
    current_policy = chain["policy"].model_copy(
        update={"reason_codes": ("RECREATE_APPROVED",)}
    )
    current_policy_ref = cast(StoredDataRef, reference(current_policy))
    current_result = chain["result"].model_copy(
        update={"policy_decision_ref": current_policy_ref}
    )
    ids = TestIds()
    clock = TestClock()
    clock.wall_time = chain["log"].meta.created_at
    manager = ReproductionSessionManager(clock=clock, ids=ids)
    log = manager.start(
        request_ref=request_ref,
        meta=chain["log"].meta,
        policy_decision_ref=initial_policy_ref,
    )
    log = manager.append(
        previous=log,
        event=AgentLogEvent(
            event_id=str(ids.new(RecordId)),
            sequence=2,
            action_id=ids.new(ActionId),
            event_type="SANDBOX_RECREATE_REQUESTED",
            actor="DYNAMIC_REPRODUCTION",
            environment_ref=None,
            environment_recipe_ref=None,
            poc_candidate_ref=None,
            tool_request_ref=None,
            command_ref=None,
            command_digest=None,
            redaction_status=None,
            input_refs=(current_policy_ref,),
            output_refs=(),
            exit_code=None,
            timed_out=None,
            safe_message="STATE_UNCERTAIN",
            occurred_at=clock.now(),
        ),
    )

    validate_boundary_binding(current_result, chain["request"], log, current_policy)


@pytest.mark.parametrize("policy_mode", ["missing", "stale"])
def test_allow_policy_closure_rejects_missing_or_stale_session_binding(
    policy_mode: str,
) -> None:
    chain = dynamic_success()
    request_ref = StoredDataRef.model_validate(bound(chain["request"]))
    policy_ref = StoredDataRef.model_validate(bound(chain["policy"]))
    if policy_mode == "stale":
        policy_ref = policy_ref.model_copy(update={"content_hash": "f" * 64})
    manager = ReproductionSessionManager(clock=TestClock(), ids=TestIds())
    log = manager.start(
        request_ref=request_ref,
        meta=chain["log"].meta,
        policy_decision_ref=policy_ref if policy_mode == "stale" else None,
    )

    with pytest.raises(ValueError, match="SANDBOX_POLICY_LOG_MISMATCH"):
        validate_boundary_binding(
            chain["result"], chain["request"], log, chain["policy"]
        )


@pytest.mark.asyncio
async def test_t11_composition_rejects_stale_generation_and_r6_verdict_output() -> None:
    request = _request()
    request_ref = cast(StoredDataRef, reference(request))
    stale_work = _work(request_ref, generation=2)
    executor = _Executor(_output("verification_result"))
    services = T11Services(
        execute_dynamic=executor,
        current_process=lambda _: _process(request),
        completion=cast(VerificationCompletionCoordinator, object()),
    )

    with pytest.raises(ValueError, match="DYNAMIC_REQUEST_NOT_CURRENT"):
        await services.execute(
            work=stale_work,
            request=request,
            request_ref=request_ref,
            authorizations=cast(DynamicStageAuthorizations, object()),
        )
    assert executor.calls == 0

    with pytest.raises(ValueError, match="R7_OUTPUT_AUTHORITY_DENIED"):
        await services.execute(
            work=_work(request_ref),
            request=request,
            request_ref=request_ref,
            authorizations=cast(DynamicStageAuthorizations, object()),
        )
    assert executor.calls == 1
