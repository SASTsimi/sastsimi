"""R7 return and state projection require the complete same-attempt closure."""

from sqlalchemy import Connection, select

from sastsimi.contracts.domain import DomainRecord, walk
from sastsimi.contracts.dynamic import (
    AgentLog,
    CleanupResult,
    DynamicReproductionConclusion,
    DynamicReproductionRequest,
    DynamicReproductionResult,
    DynamicReproductionState,
    DynamicReproductionToolRequest,
    EnvironmentRecipe,
    EnvironmentRequirements,
    PoCBundle,
    PoCCandidate,
    ReproductionPlan,
    SandboxCommandRecord,
    SandboxEnvironment,
    SandboxPolicyDecision,
    validate_dynamic_closure,
)
from sastsimi.contracts.refs import StoredDataRef
from sastsimi.contracts.work import WorkExecutionState
from sastsimi.ports.dto import Record

from . import models
from .codec import REF_ADAPTER, reference
from .dynamic_state import current_dynamic
from .intermediate_policy import prepublished_output
from .records import next_meta
from .stage_policy import resolved
from .work_service import WorkService


def dynamic_projection(
    works: WorkService,
    connection: Connection,
    work: WorkExecutionState,
    outputs: tuple[Record, ...],
    target_status: str,
    *,
    publish: bool,
) -> tuple[Record, ...]:
    results = [item for item in outputs if isinstance(item, DynamicReproductionResult)]
    if not results:
        return ()
    if len(results) != 1 or work.work_type != "DYNAMIC_REPRO":
        raise ValueError("DYNAMIC_RETURN_EXACT_RESULT_REQUIRED")
    result = results[0]
    closure_refs = {
        ref
        for ref in (
            result.reproduction_plan_ref,
            result.policy_decision_ref,
            result.agent_log_ref,
            result.agent_conclusion_ref,
            result.environment_recipe_ref,
            result.environment_ref,
            result.poc_candidate_ref,
            result.poc_ref,
            result.cleanup_ref,
        )
        if ref is not None
    }
    for output in outputs:
        if output is result:
            continue
        output_ref = reference(output)
        if output_ref not in closure_refs or not prepublished_output(
            works.records, connection, output_ref, work
        ):
            raise ValueError("DYNAMIC_RETURN_EXACT_RESULT_REQUIRED")
    state = current_dynamic(works.records, connection, work)
    if (
        state.dynamic_work_ref != reference(work)
        or state.status != "RUNNING"
        or result.status != target_status
        or result.request_ref != state.request_ref
        or result.meta.attempt_id != work.active_attempt_id
    ):
        raise ValueError("DYNAMIC_RETURN_STATE_MISMATCH")
    records = works.records
    request = resolved(
        records, connection, result.request_ref, DynamicReproductionRequest
    )

    def load[T: DomainRecord](ref: StoredDataRef | None, model: type[T]) -> T | None:
        if ref is None:
            return None
        value = resolved(records, connection, ref, model)
        if not prepublished_output(records, connection, ref, work):
            raise ValueError("DYNAMIC_INTERMEDIATE_RECEIPT_REQUIRED")
        return value

    log = load(result.agent_log_ref, AgentLog)
    assert log is not None
    plan = load(result.reproduction_plan_ref, ReproductionPlan)
    requirement = (
        load(plan.environment_requirements_ref, EnvironmentRequirements)
        if plan
        else None
    )
    evidence: dict[StoredDataRef, DomainRecord] = {}
    pending = list((*result.hypothesis_evidence_refs, *result.observation_refs))
    poc = load(result.poc_ref, PoCBundle)
    if poc:
        pending.extend(poc.evidence_refs)
    while pending:
        ref = pending.pop()
        if ref in evidence or ref.record_id is None:
            continue
        value = records.resolve(connection, ref)
        if not isinstance(value, DomainRecord):
            raise ValueError("DYNAMIC_EVIDENCE_RECORD_REQUIRED")
        evidence[ref] = value
        pending.extend(
            item
            for item in walk(value)
            if isinstance(item, StoredDataRef) and item not in evidence
        )
    all_attempt = []
    for wire in connection.execute(
        select(models.records.c.ref)
        .distinct()
        .join(
            models.record_revisions,
            models.record_revisions.c.record_id == models.records.c.record_id,
        )
        .where(
            models.records.c.kind.in_(
                (
                    "sandbox_command_record",
                    "dynamic_reproduction_tool_request",
                    "sandbox_environment",
                    "environment_recipe",
                )
            )
        )
    ).scalars():
        value = records.resolve(connection, REF_ADAPTER.validate_json(wire))
        if (
            isinstance(value, DomainRecord)
            and value.meta.attempt_id == work.active_attempt_id
            and value.meta.analysis_id == work.meta.analysis_id
        ):
            all_attempt.append(value)
    validate_dynamic_closure(
        result,
        request,
        log,
        generation=work.work_generation,
        plan=plan,
        recipe=load(result.environment_recipe_ref, EnvironmentRecipe),
        environment=load(result.environment_ref, SandboxEnvironment),
        candidate=load(result.poc_candidate_ref, PoCCandidate),
        poc=poc,
        conclusion=load(result.agent_conclusion_ref, DynamicReproductionConclusion),
        policy=load(result.policy_decision_ref, SandboxPolicyDecision),
        cleanup=load(result.cleanup_ref, CleanupResult),
        requirements=requirement,
        resolved_evidence=evidence,
        command_records=tuple(
            item for item in all_attempt if isinstance(item, SandboxCommandRecord)
        ),
        tool_requests=tuple(
            item
            for item in all_attempt
            if isinstance(item, DynamicReproductionToolRequest)
        ),
        attempt_environments=tuple(
            item
            for item in all_attempt
            if isinstance(item, SandboxEnvironment)
            and reference(item) != result.environment_ref
        ),
        attempt_recipes=tuple(
            item
            for item in all_attempt
            if isinstance(item, EnvironmentRecipe)
            and reference(item) != result.environment_recipe_ref
        ),
    )
    if not publish:
        return ()
    return (
        DynamicReproductionState.model_validate(
            state.model_dump()
            | dict(
                meta=next_meta(state.meta, works.clock, works.ids),
                status=result.status,
                dynamic_result_ref=reference(result),
                elapsed_ms=result.elapsed_ms,
                finished_at=None if result.status == "BLOCKED" else result.finished_at,
            )
        ),
    )
