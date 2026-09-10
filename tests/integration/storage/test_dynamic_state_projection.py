"""A dynamic work start must project the exact current request and generation."""

import json
from pathlib import Path

import pytest

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.dynamic import (
    AgentLog,
    DynamicReproductionRequest,
    DynamicReproductionResult,
)
from sastsimi.storage.codec import reference
from tests.contract.domain.canonical_fixtures import make
from tests.integration.storage.verification_support import prepared_verification


@pytest.mark.parametrize(
    "case",
    [
        "normal",
        "duplicate",
        "revoked",
        "claimed",
        "before_commit",
        "committed",
        "plan_failure",
    ],
)
def test_dynamic_start_projects_current_request_work_and_attempt(
    tmp_path: Path, case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    h, runtime, runner, work, registered, owner, hypothesis, bundle = (
        prepared_verification(tmp_path)
    )
    request = DynamicReproductionRequest.model_validate_json(
        canonical_bytes(
            json.loads(
                json.dumps(make("DynamicReproductionRequest")).replace('"ws1"', '"w1"')
            )
            | dict(
                meta=runner.metadata(
                    work.meta,
                    "dynamic_reproduction_request",
                    attempt_id=work.active_attempt_id,
                ),
                verification_assignment_ref=registered.assignment_ref,
                hypothesis_ref=reference(hypothesis),
                static_evidence_refs=(reference(bundle),),
            )
        )
    )
    action = runner.action(
        work,
        owner,
        "VERIFICATION",
        "SAVE_RESULT",
        result_kind="dynamic_reproduction_request",
        candidate_result_ref=h.records.stage_record(request),
    )
    runtime.intermediate.publish(
        str(work.work_id), runner.authorize(work, action), (request,)
    )
    scope = runtime.budget_registry.current_state("a1").budget_binding_ref
    action = runner.action(
        work,
        owner,
        "VERIFICATION",
        "REQUEST_DYNAMIC_REPRO",
        dynamic_request_ref=reference(request),
    )
    reservation = runner.reserve(work, scope, action, runner.units(work_count=1))
    decision = runner.authorize(work, action, reservation)
    service = getattr(runtime, "dynamic_registration", None)
    assert service is not None, "Exact dynamic handoff service is missing"
    if case == "revoked":
        h.evidence.identities[owner] = RequesterRole.PRO
        with pytest.raises(ValueError, match="AUTHORITY_DENIED"):
            service.register(str(work.work_id), decision, reference(reservation))
        (state,) = runtime.queries.current_records("a1", "dynamic_reproduction_state")
        assert state.status == "NOT_REQUESTED"
        return
    if case in {"claimed", "before_commit", "committed"}:

        class Crash(BaseException):
            pass

        def crash(stage: str) -> None:
            if stage == case:
                raise Crash

        monkeypatch.setattr(service.store, "checkpoint", crash)
        with pytest.raises(Crash):
            service.register(str(work.work_id), decision, reference(reservation))
        (state,) = runtime.queries.current_records("a1", "dynamic_reproduction_state")
        assert state.status == ("RUNNING" if case == "committed" else "NOT_REQUESTED")
        if case != "committed":
            assert not [
                r
                for r in runtime.queries.current_records("a1", "work_execution_state")
                if r.work_type == "DYNAMIC_REPRO"
            ]
        return
    pending = service.register(str(work.work_id), decision, reference(reservation))
    if case == "duplicate":
        counter = h.ids.index
        assert (
            service.register(str(work.work_id), decision, reference(reservation))
            == pending
        )
        assert h.ids.index == counter
    child = runner.activate(pending, scope, owner, role="VERIFICATION")
    (state,) = runtime.queries.current_records("a1", "dynamic_reproduction_state")
    assert state.status == "RUNNING"
    assert state.dynamic_work_ref == reference(child)
    assert state.request_ref == reference(request)
    assert state.verification_generation == 1 and state.dynamic_result_ref is None
    if case == "plan_failure":
        identity = h.records.get_exact(scope).dynamic_lifecycle_profile_ref
        h.evidence.identities[identity] = RequesterRole.REPRODUCTION_SESSION_MANAGER
        log = AgentLog.model_validate_json(
            canonical_bytes(
                dict(
                    meta=runner.metadata(
                        child.meta, "agent_log", attempt_id=child.active_attempt_id
                    ),
                    request_ref=reference(request),
                    events=(),
                )
            )
        )
        save = runner.action(
            child,
            identity,
            "REPRODUCTION_SESSION_MANAGER",
            "SAVE_RESULT",
            result_kind="agent_log",
            candidate_result_ref=h.records.stage_record(log),
        )
        runtime.intermediate.publish(
            str(child.work_id), runner.authorize(child, save), (log,)
        )
        result = DynamicReproductionResult.model_validate_json(
            canonical_bytes(
                make("DynamicReproductionResult")
                | dict(
                    meta=runner.metadata(
                        child.meta,
                        "dynamic_reproduction_result",
                        attempt_id=child.active_attempt_id,
                    ),
                    request_ref=reference(request),
                    agent_log_ref=reference(log),
                    started_at=h.clock.now(),
                    finished_at=h.clock.now(),
                    elapsed_ms=0,
                )
            )
        )
        finished = runner.complete(
            child,
            identity,
            "REPRODUCTION_SESSION_MANAGER",
            (result,),
            status="FAILED",
            cause="PLAN_FAILED",
            error_ids=("plan-error",),
        )
        (returned,) = runtime.queries.current_records(
            "a1", "dynamic_reproduction_state"
        )
        assert returned.status == "FAILED" and returned.dynamic_result_ref == reference(
            result
        )
        assert returned.dynamic_work_ref == reference(finished)
        (process,) = runtime.queries.current_records("a1", "hypothesis_process_state")
        assert process.status == "VERIFYING" and process.verification_result_ref is None
