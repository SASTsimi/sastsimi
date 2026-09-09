"""Fake AST/SAST orchestration through real runtime boundaries."""

import asyncio

from sastsimi.contracts.actions import RequesterRole
from sastsimi.contracts.canonical_json import canonical_bytes
from sastsimi.contracts.records import RecordMeta
from sastsimi.contracts.refs import RunStoredDataRef, StoredDataRef, reference
from sastsimi.contracts.static import (
    CodeWorkspace,
    RuleExecutionRecord,
    ToolRunResult,
)
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.orchestration.fake_support import FakeEvidence
from sastsimi.ports.dto import StaticToolRequest
from sastsimi.runtime.services import RuntimeServices
from sastsimi.runtime.workflow_runner import WorkflowRunner

from .fake_base import StaticInvoker


def register_fake_static_works(
    *,
    runner: WorkflowRunner,
    evidence: FakeEvidence,
    scope: StoredDataRef,
    identity: StoredDataRef,
    workspace: CodeWorkspace,
    workspace_ref: RunStoredDataRef,
    metadata: RecordMeta,
) -> tuple[WorkExecutionState, WorkExecutionState]:
    evidence.identities[identity] = RequesterRole.ORCHESTRATION
    return tuple(
        runner.start(
            scope,
            metadata,
            "STATIC_TOOL",
            "ANALYSIS",
            str(workspace.analysis_id),
            identity,
            inputs=(workspace_ref,),
        )
        for _ in range(2)
    )  # type: ignore[return-value]


def execute_fake_static_work(
    *,
    runtime: RuntimeServices,
    runner: WorkflowRunner,
    evidence: FakeEvidence,
    scope: StoredDataRef,
    identity: StoredDataRef,
    work: WorkExecutionState,
    workspace: CodeWorkspace,
    analysis_config_ref: StoredDataRef,
    rule_catalog_ref: StoredDataRef,
    tool_name: str,
    tool_kind: str,
    raw_result_ref: StoredDataRef,
    static_invoke: StaticInvoker,
) -> tuple[ToolRunResult, StoredDataRef]:
    evidence.identities[identity] = RequesterRole.STATIC_ANALYSIS
    action = runner.action(
        work,
        identity,
        "STATIC_ANALYSIS",
        "RUN_TOOL",
        tool_name=tool_name,
        file_paths=("src/app.py",),
    )
    rule = None
    rule_ref = None
    if tool_kind == "RULE_BASED":
        rule = RuleExecutionRecord.model_validate_json(
            canonical_bytes(
                dict(
                    meta=runner.metadata(
                        work.meta,
                        "rule_execution_record",
                        attempt_id=work.active_attempt_id,
                    ),
                    tool_name=tool_name,
                    tool_version="1",
                    analysis_config_ref=analysis_config_ref,
                    rule_catalog_ref=rule_catalog_ref,
                    selected_rule_packs=("fake-security",),
                    rules=(
                        dict(
                            rule_id="fake-rule",
                            selection_status="SELECTED",
                            execution_status="EXECUTED",
                            hit_count=1,
                            reason=None,
                            detail=None,
                        ),
                    ),
                )
            )
        )
        rule_ref = reference(rule)
    result = ToolRunResult.model_validate_json(
        canonical_bytes(
            dict(
                meta=runner.metadata(
                    work.meta, "tool_run_result", attempt_id=work.active_attempt_id
                ),
                tool_name=tool_name,
                tool_version="1",
                tool_kind=tool_kind,
                status="SUCCEEDED",
                coverage=dict(
                    analyzed_paths=("src/app.py",),
                    skipped_paths=(),
                    analyzed_languages=("Python",),
                    skipped_languages=(),
                    notes=("Deterministic fake tool",),
                ),
                rule_execution_ref=rule_ref,
                raw_result_ref=raw_result_ref,
                gaps=(),
                errors=(),
                started_at=runner.clock.now(),
                finished_at=runner.clock.now(),
                elapsed_ms=1,
            )
        )
    )
    units = runner.units(elapsed_ms=1, cost_minor_units=1)
    reservation = runner.reserve(work, scope, action, units)
    decision = runner.authorize(work, action, reservation)
    request = StaticToolRequest(
        action, workspace, analysis_config_ref, rule_catalog_ref
    )
    returned = asyncio.run(
        runtime.external.invoke(
            str(work.work_id),
            decision,
            reference(reservation),
            lambda: static_invoke(request, result),
            idempotency_key=str(action.action_id),
        )
    )
    if returned != result:
        raise ValueError("FAKE_STATIC_RESULT_MISMATCH")
    runner.account(reservation, units)
    outputs = (result,) if rule is None else (result, rule)
    evidence.next_outputs = tuple(
        runtime.unit_of_work.records.stage_record(item) for item in outputs
    )
    try:
        completed = runner.complete(work, identity, "STATIC_ANALYSIS", outputs)
    finally:
        evidence.next_outputs = None
    result_ref = completed.output_refs[0]
    if not isinstance(result_ref, StoredDataRef):
        raise ValueError("FAKE_STATIC_OUTPUT_SCOPE_MISMATCH")
    return result, result_ref
