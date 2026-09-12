from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any, cast

import pytest

from sastsimi.bootstrap import T12Services, build_t12_services
from sastsimi.contracts.canonical_json import content_hash
from sastsimi.contracts.ids import (
    AnalysisId,
    AttemptId,
    CommitId,
    HypothesisId,
    LogicalRecordId,
    RecordId,
    StoredDataId,
    WorkId,
    WorkspaceId,
)
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.work import (
    AttemptStatus,
    AttemptTrigger,
    SubjectType,
    WorkAttempt,
    WorkExecutionState,
    WorkStatus,
    WorkType,
)
from sastsimi.ports.dto import WorkContext
from sastsimi.reporting.rule_scope_gate_handler import (
    RuleScopeGateHandler,
    StoredRuleScopeInputResolver,
)
from sastsimi.reporting.rule_scope_gate_workflow import RuleScopeExecution
from sastsimi.reporting.work_handlers import StoredReporterInputResolver

NOW = datetime(2026, 9, 12, tzinfo=UTC)


def _ref(kind: str, suffix: str) -> StoredDataRef:
    return StoredDataRef(
        stored_data_id=StoredDataId(f"{kind}-{suffix}"),
        data_kind=kind,
        content_hash="a" * 64,
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
        record_id=RecordId(f"{kind}-{suffix}"),
    )


def _context(kind: WorkType, suffix: str = "current") -> WorkContext:
    attempt_id = AttemptId(f"attempt-{suffix}")
    refs = (_ref("verification_result", suffix),)
    work_meta = RecordMeta(
        record_id=RecordId(f"work-{suffix}-record"),
        logical_record_id=LogicalRecordId(f"work-{suffix}-logical"),
        record_type="work_execution_state",
        schema_version="1.0.0",
        revision_number=2,
        previous_record_id=RecordId(f"work-{suffix}-previous"),
        created_at=NOW,
        analysis_id=AnalysisId("analysis-1"),
        workspace_id=WorkspaceId("ws1"),
        commit_id=CommitId("c1"),
        hypothesis_id=HypothesisId("hypothesis-1"),
        attempt_id=None,
    )
    work = WorkExecutionState(
        meta=work_meta,
        work_id=WorkId(f"work-{suffix}"),
        parent_work_ref=None,
        work_type=kind,
        subject_type=SubjectType.HYPOTHESIS,
        subject_id=HypothesisId("hypothesis-1"),
        work_generation=1,
        status=WorkStatus.RUNNING,
        state_version=3,
        last_transition_ref=_ref("state_transition", suffix),
        last_transition_commit_ref=_ref("transition_commit", suffix),
        active_attempt_id=attempt_id,
        input_hash=content_hash(refs),
        dedupe_key="b" * 64,
        trigger_primitive_ref=None,
        input_refs=refs,
        output_refs=(),
        gap_ids=(),
        error_ids=(),
        waiting_for=(),
        stop_reason=None,
        started_at=NOW,
        finished_at=None,
        elapsed_ms=0,
    )
    attempt = WorkAttempt(
        meta=work_meta.model_copy(
            update={
                "record_id": RecordId(f"attempt-{suffix}-record"),
                "logical_record_id": LogicalRecordId(f"attempt-{suffix}-logical"),
                "record_type": "work_attempt",
                "revision_number": 1,
                "previous_record_id": None,
                "attempt_id": attempt_id,
            }
        ),
        work_id=work.work_id,
        attempt_id=attempt_id,
        attempt_number=1,
        trigger=AttemptTrigger.INITIAL,
        input_hash=work.input_hash,
        status=AttemptStatus.RUNNING,
        output_refs=(),
        gap_ids=(),
        error_ids=(),
        started_at=NOW,
        finished_at=None,
        elapsed_ms=0,
    )
    return WorkContext(work, attempt)


def test_compose_t12_services_wires_post_claim_resolvers_without_model() -> None:
    calls = SimpleNamespace(
        cwe=lambda _context: object(),
        technical=lambda _context: object(),
        rule_scope=lambda _context: object(),
        reporter=lambda _context: object(),
    )
    records = SimpleNamespace(get_exact=lambda _ref: object())
    runtime = SimpleNamespace(
        unit_of_work=SimpleNamespace(records=records, artifacts=object()),
        llm_calls=object(),
        queries=SimpleNamespace(
            current_records=lambda _analysis, _kind: (),
            published_records=lambda _analysis: (),
        ),
        budget_registry=SimpleNamespace(current_state=lambda _analysis: object()),
        work=object(),
    )
    identities = {
        role: _ref("agent_identity", role)
        for role in (
            "ORCHESTRATION",
            "CWE_LABELING",
            "TECHNICAL_GATE",
            "RULE_SCOPE_GATE",
            "REPORTER",
        )
    }
    primitive_handoff = object()
    t10_services = SimpleNamespace(
        revision=object(), primitive_handoff=primitive_handoff
    )

    services = build_t12_services(
        runtime=cast(Any, runtime),
        runner=cast(Any, object()),
        clock=cast(Any, object()),
        ids=cast(Any, object()),
        t10_services=cast(Any, t10_services),
        taxonomy_version="CWE-4.17",
        role_identity_refs=cast(Any, identities),
        cwe_call_resolver=cast(Any, calls.cwe),
        technical_call_resolver=cast(Any, calls.technical),
        rule_scope_call_resolver=cast(Any, calls.rule_scope),
        reporter_call_resolver=cast(Any, calls.reporter),
    )

    assert isinstance(services, T12Services)
    assert services.cwe.resolve_call is calls.cwe
    assert services.technical.resolve_call is calls.technical
    assert isinstance(services.rule_scope.resolve_inputs, StoredRuleScopeInputResolver)
    assert services.rule_scope.resolve_inputs.resolve_call is calls.rule_scope
    assert isinstance(services.reporter.resolve_inputs, StoredReporterInputResolver)
    assert services.reporter.resolve_inputs.resolve_call is calls.reporter
    assert services.primitive_handoff is primitive_handoff
    assert not hasattr(services, "provider")
    assert not hasattr(services, "model")


@pytest.mark.asyncio
async def test_rule_scope_handler_rejects_other_claimed_work() -> None:
    current = _context(WorkType.RULE_SCOPE_GATE)
    other = _context(WorkType.RULE_SCOPE_GATE, "other")
    execution = RuleScopeExecution(
        work=other.work,
        call=cast(Any, object()),
        owner_ref=_ref("agent_identity", "verification"),
        gate_identity_ref=_ref("agent_identity", "rule-scope"),
    )
    service = SimpleNamespace(review=lambda *_args, **_kwargs: None)

    class _Resolver:
        resolve_call = staticmethod(lambda _context: object())

        def __call__(self, _context: WorkContext) -> tuple[object, RuleScopeExecution]:
            return object(), execution

    resolver = _Resolver()
    handler = RuleScopeGateHandler(
        cast(Any, service), resolve_inputs=cast(Any, resolver)
    )

    with pytest.raises(ValueError, match="RULE_SCOPE_WORK_CONTEXT_MISMATCH"):
        await handler.execute(current)
